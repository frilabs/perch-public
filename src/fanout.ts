import { createHash } from 'node:crypto';
import { PerchError, safeMessage } from './errors.js';
import type { CursorSeal } from './store/credentialStore.js';

/**
 * Runs one paginated query against several accounts/workspaces and merges the pages.
 * The opaque cursor holds each source's own upstream cursor; exhausted sources are dropped.
 * A failing source does not fail the whole call: it is reported in `errors`/`partial`, kept in
 * the cursor and retried from where it failed on the next page. After MAX_ATTEMPTS consecutive
 * failures it is given up, and every later page keeps reporting it, so incompleteness can
 * never disappear silently.
 */

export const MAX_ATTEMPTS = 3;

export interface Source {
  id: string;
  label: string;
}

export interface SourcePage<T> {
  items: T[];
  next?: string | null;
  /** Upstream signalled that its own result set is incomplete (e.g. Drive incompleteSearch). */
  incomplete?: boolean;
}

export interface SourceError {
  accountId: string;
  accountLabel: string;
  message: string;
}

export interface FanOutResult<T> {
  results: T[];
  nextCursor: string | null;
  hasMore: boolean;
  partial: boolean;
  errors: SourceError[];
  /** Sources whose upstream reported an incomplete result set. */
  incompleteSources: string[];
}

interface CursorState {
  k: string;
  h: string;
  /** source id -> upstream cursor ('' = start from the beginning) */
  t: Record<string, string>;
  /** source id -> consecutive failed attempts */
  f: Record<string, number>;
  /** sources given up on: id -> label */
  x: Record<string, string>;
}

const queryHash = (key: unknown) => createHash('sha256').update(JSON.stringify(key)).digest('base64url').slice(0, 16);

const isRecordOf = (v: unknown, type: 'string' | 'number'): v is Record<string, never> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.values(v).every((x) => typeof x === type);

function decodeCursor(seal: CursorSeal, cursor: string, kind: string, hash: string): CursorState {
  // The MAC check runs first: a cursor from another namespace (store) or an edited one never reaches
  // the per-source upstream cursors below, even when account ids collide.
  const payload = seal.openCursor(`fanout:${kind}`, cursor);
  let state: CursorState;
  try {
    state = JSON.parse(payload) as CursorState;
  } catch {
    throw new PerchError('Invalid cursor', 'bad_cursor');
  }
  if (!state || state.k !== kind || !isRecordOf(state.t, 'string') || !isRecordOf(state.f, 'number') || !isRecordOf(state.x, 'string')) {
    throw new PerchError('Invalid cursor', 'bad_cursor');
  }
  if (state.h !== hash) throw new PerchError('Cursor does not belong to this query; repeat the same arguments', 'bad_cursor');
  return state;
}

const gaveUpMessage = `Gave up after ${MAX_ATTEMPTS} failed attempts; results from this source are incomplete`;
const removedMessage = 'Account was removed during pagination; results are incomplete';
const REMOVED = '\u0000removed';

export async function fanOut<T>(opts: {
  kind: string;
  queryKey: unknown;
  sources: Source[];
  cursor?: string;
  /** The namespace's store: seals and verifies the opaque cursor. */
  seal: CursorSeal;
  fetchPage: (source: Source, upstreamCursor: string | undefined) => Promise<SourcePage<T>>;
}): Promise<FanOutResult<T & { accountId: string; accountLabel: string }>> {
  const hash = queryHash(opts.queryKey);
  const state: CursorState = opts.cursor
    ? decodeCursor(opts.seal, opts.cursor, opts.kind, hash)
    : { k: opts.kind, h: hash, t: Object.fromEntries(opts.sources.map((s) => [s.id, ''])), f: {}, x: {} };

  const next: CursorState = { k: opts.kind, h: hash, t: {}, f: {}, x: { ...state.x } };
  const errors: SourceError[] = [];
  const targets: Array<{ source: Source; token: string }> = [];
  for (const [id, token] of Object.entries(state.t)) {
    const source = opts.sources.find((s) => s.id === id);
    if (source) targets.push({ source, token });
    else next.x[id] = REMOVED;
  }

  const pages = await Promise.all(
    targets.map(async ({ source, token }) => {
      try {
        return { source, token, page: await opts.fetchPage(source, token || undefined) };
      } catch (err) {
        return { source, token, error: safeMessage(err) };
      }
    }),
  );

  const results: Array<T & { accountId: string; accountLabel: string }> = [];
  const incompleteSources: string[] = [];
  for (const p of pages) {
    if ('error' in p) {
      const attempts = (state.f[p.source.id] ?? 0) + 1;
      if (attempts >= MAX_ATTEMPTS) {
        next.x[p.source.id] = p.source.label;
        errors.push({ accountId: p.source.id, accountLabel: p.source.label, message: `${p.error!} (${gaveUpMessage})` });
      } else {
        next.t[p.source.id] = p.token; // retry the same page next time
        next.f[p.source.id] = attempts;
        errors.push({ accountId: p.source.id, accountLabel: p.source.label, message: `${p.error!} (will retry on the next page)` });
      }
      continue;
    }
    for (const item of p.page.items) results.push({ ...item, accountId: p.source.id, accountLabel: p.source.label });
    if (p.page.next) next.t[p.source.id] = p.page.next;
    if (p.page.incomplete) incompleteSources.push(p.source.id);
  }
  // Sources given up on earlier (or removed now/earlier) are reported on every page.
  for (const [id, label] of Object.entries(next.x)) {
    if (label === REMOVED) errors.push({ accountId: id, accountLabel: '', message: removedMessage });
    else if (id in state.x) errors.push({ accountId: id, accountLabel: label, message: gaveUpMessage });
  }

  const hasMore = Object.keys(next.t).length > 0;
  return {
    results,
    nextCursor: hasMore ? opts.seal.sealCursor(`fanout:${opts.kind}`, JSON.stringify(next)) : null,
    hasMore,
    partial: errors.length > 0 || incompleteSources.length > 0,
    errors,
    incompleteSources,
  };
}
