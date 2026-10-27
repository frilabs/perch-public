import { createHash } from 'node:crypto';
import { actorOf, type AuditLog } from '../audit/audit.js';
import { assertSlackCapability, currentPrincipal, type Principal } from '../auth/grants.js';
import { PerchError } from '../errors.js';
import { fanOut, type FanOutResult } from '../fanout.js';
import { newAccountId, validateLabel } from '../ids.js';
import { validateRequestId, type SendWorkflow } from '../mail/workflow.js';
import { messageSendStatus, sendMessageIdempotently, type MessageSendResult, type MessageSendView } from '../messaging/send.js';
import type { CredentialStore, SlackWorkspace } from '../store/credentialStore.js';
import { SLACK_CHANNEL_ID, SLACK_DOWNLOAD_PATH, SLACK_FILE_ID, SLACK_SESSION_COOKIE, SLACK_TS, SLACK_UPLOAD_PATH, UpstreamError, type Upstream } from '../upstream.js';

/**
 * Slack Web API with a user token (xoxp-…) per workspace. Each workspace uses its own internal app
 * (docs/slack-app-manifest.json): internal apps keep Slack's normal rate tiers for conversations.history
 * and conversations.replies, which commercially distributed non-Marketplace apps do not.
 *
 * Reads are plain allowlisted GETs. Posting (chat.postMessage) and scheduling (chat.scheduleMessage) need a
 * client grant with slack_send for the workspace and go through the idempotent send workflow
 * (src/messaging/send.ts).
 *
 * Session workspaces (docs/SLACK_SESSION_NOTION_GUIDE_SPEC.md §1, unofficial, opt-in) use the browser session
 * instead: token xoxc-… plus the cookie `d` (xoxd-…), sent only to slack.com and files.slack.com (see
 * Upstream's slackCookie). Same endpoints and grants; scope checks do not apply (session tokens report none).
 */

/** User-token scopes of the bundled manifest (docs/slack-app-manifest.json). */
export const SLACK_USER_SCOPES = [
  'channels:read',
  'channels:history',
  'groups:read',
  'groups:history',
  'im:read',
  'im:history',
  'mpim:read',
  'mpim:history',
  'users:read',
  'search:read',
  'chat:write',
  'reactions:read',
  'reactions:write',
  'files:read',
  'files:write',
  'im:write',
  'mpim:write',
] as const;

export const DEFAULT_SLACK_PAGE_SIZE = 50;
export const MAX_SLACK_PAGE_SIZE = 200;
export const MAX_SLACK_SEARCH_PAGE_SIZE = 100;
/** Slack truncates longer messages; Perch refuses instead. */
export const MAX_SLACK_TEXT = 40_000;
/** Upper bound for slack_upload_file (decoded bytes) and slack_get_file downloads. */
export const MAX_SLACK_FILE_BYTES = 10 * 1024 * 1024;
export const DEFAULT_SLACK_FILE_READ_BYTES = 48 * 1024;
export const MAX_SLACK_FILENAME = 255;
export const SLACK_EMOJI_NAME = /^[a-z0-9_+-]{1,100}$/;
/** conversations.open: 1 user = DM, 2-8 users = group DM (Slack's limit for multi-person DMs). */
export const MAX_SLACK_GROUP_DM_USERS = 8;
/** chat.scheduleMessage window enforced by Perch (Slack allows up to 120 days ahead). */
export const MIN_SCHEDULE_LEAD_SECONDS = 60;
export const MAX_SCHEDULE_AHEAD_SECONDS = 120 * 24 * 60 * 60;
export const DEFAULT_SCHEDULED_PAGE_SIZE = 50;
export const MAX_SCHEDULED_PAGE_SIZE = 100;
/** Slack scheduled message ids (Q…). */
export const SLACK_SCHEDULED_ID = /^Q[A-Z0-9]{2,30}$/;
export const CONVERSATION_TYPES = ['public_channel', 'private_channel', 'mpim', 'im'] as const;
export type ConversationType = (typeof CONVERSATION_TYPES)[number];

const MAX_RETRIES_PER_REQUEST = 3;
const MAX_RETRIES_PER_CALL = 6;
const MAX_RETRY_WAIT_MS = 10_000;
/** Upper bound on users.info lookups per tool call (names are cached per workspace afterwards). */
const MAX_USER_LOOKUPS_PER_CALL = 50;
const MAX_CACHED_USERS = 5000;
/** conversations.list pages scanned per result page when filtering by name. */
const MAX_FILTER_SCANS = 20;
const SLACK_ERROR = /^[a-z_]{1,64}$/;
const SLACK_USER = /^[UW][A-Z0-9]{2,30}$/;

export interface WorkspaceProvenance {
  workspaceId: string;
  workspaceLabel: string;
  team?: string;
}

const fingerprint = (s: string) => createHash('sha256').update(s).digest('hex');

export const isSlackSession = (ws: Pick<SlackWorkspace, 'authMode'>) => ws.authMode === 'session';

/**
 * Credentials of one Slack request: the bearer token, and for session workspaces the `d` cookie (Upstream only
 * attaches it for slack.com and files.slack.com).
 */
export function slackAuth(ws: Pick<SlackWorkspace, 'token' | 'authMode' | 'sessionCookie'>): { headers: Record<string, string>; slackCookie?: string } {
  return { headers: { authorization: `Bearer ${ws.token}` }, ...(isSlackSession(ws) && ws.sessionCookie ? { slackCookie: ws.sessionCookie } : {}) };
}

/** Session tokens report no scopes: every scope counts as present (Slack itself decides per call). */
const hasScope = (ws: SlackWorkspace, scope: string) => isSlackSession(ws) || ws.scopes.includes(scope);

const SAFE_ARG = /^[A-Za-z0-9_.@+:,/=-]+$/;
const quoteArg = (s: string) => (SAFE_ARG.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

/** The command that renews an expired session (updates the same workspace record). */
export const slackSessionAddCommand = (label: string) => `perch slack add --label ${quoteArg(label)} --session`;

const AUTH_FAILURES = ['invalid_auth', 'not_authed', 'token_revoked', 'token_expired', 'account_inactive'];
export const isSlackAuthFailure = (code: unknown) => typeof code === 'string' && AUTH_FAILURES.includes(code);

/** Message for a session workspace whose session Slack no longer accepts (never contains token or cookie). */
export const slackSessionExpired = (code: string, label: string) =>
  new PerchError(`Slack session expired (${code}): run ${slackSessionAddCommand(label)} again (updates the same workspace)`, 'slack_session_expired');

function slackFailure(code: unknown, ws?: Pick<SlackWorkspace, 'authMode' | 'label'>): PerchError {
  const c = typeof code === 'string' && SLACK_ERROR.test(code) ? code : 'unknown_error';
  if (c === 'missing_scope') {
    return new PerchError(`Slack token lacks a required scope. Reconnect: ${slackSessionAddCommand(ws?.label ?? 'NAME')}`, 'provider_scope_missing');
  }
  if (AUTH_FAILURES.includes(c)) {
    if (ws && isSlackSession(ws)) return slackSessionExpired(c, ws.label);
    return new PerchError(`Slack refused the token (${c}): it is invalid, revoked or the app was uninstalled; reconnect with perch slack add`, 'upstream_error');
  }
  if (c === 'ratelimited') return new PerchError('Slack rate limit reached; try again later', 'upstream_error');
  return new PerchError(`Slack request failed (${c})`, 'upstream_error');
}

function bounded(name: string, value: number | undefined, def: number, max: number): number {
  const n = value ?? def;
  if (!Number.isInteger(n) || n < 1 || n > max) throw new PerchError(`${name} must be between 1 and ${max}`, 'bad_argument');
  return n;
}

function channelIdOf(v: unknown): string {
  if (typeof v !== 'string' || !SLACK_CHANNEL_ID.test(v)) throw new PerchError('channelId must be a Slack conversation id (C…, G… or D…) from slack_list_conversations', 'bad_argument');
  return v;
}

function tsOf(v: unknown, what: string): string {
  if (typeof v !== 'string' || !SLACK_TS.test(v)) throw new PerchError(`${what} must be a Slack message timestamp like 1712345678.123456`, 'bad_argument');
  return v;
}

/** RFC 3339 (with offset) to a Slack epoch timestamp string. */
function epochOf(v: string | undefined, what: string): string | undefined {
  if (v === undefined) return undefined;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/.test(v)) {
    throw new PerchError(`${what} must be an RFC 3339 timestamp with offset, e.g. 2026-10-05T09:00:00+02:00`, 'bad_argument');
  }
  const ms = Date.parse(v);
  if (!Number.isFinite(ms)) throw new PerchError(`${what} is not a valid time`, 'bad_argument');
  return (ms / 1000).toFixed(6);
}

const isoOf = (ts: string | undefined) => {
  const n = Number(ts);
  return Number.isFinite(n) && n > 0 ? new Date(n * 1000).toISOString() : undefined;
};

/**
 * Slack ts is not a valid ledger provider id ('.'): stored as `<seconds>_<micros>`. The conversation id is
 * never stored (the ledger holds no recipients); the caller knows it from its own request.
 */
const encodeTs = (ts: string) => ts.replace('.', '_');
const decodeTs = (ref: string | undefined) => {
  const m = ref ? /^(\d{9,11})_(\d{6})$/.exec(ref) : null;
  return m ? `${m[1]}.${m[2]}` : undefined;
};

type Raw = Record<string, unknown>;

export interface SlackMessage {
  ts: string;
  time?: string;
  user?: string;
  userName?: string;
  botName?: string;
  subtype?: string;
  text: string;
  threadTs?: string;
  replyCount?: number;
  edited?: boolean;
  files?: Array<{ name?: string; mimetype?: string; size?: number }>;
}

function toMessage(m: Raw): SlackMessage {
  const files = Array.isArray(m.files)
    ? (m.files as Raw[]).map((f) => ({
        ...(typeof f.name === 'string' ? { name: f.name } : {}),
        ...(typeof f.mimetype === 'string' ? { mimetype: f.mimetype } : {}),
        ...(typeof f.size === 'number' ? { size: f.size } : {}),
      }))
    : undefined;
  const ts = String(m.ts ?? '');
  const time = isoOf(ts);
  return {
    ts,
    ...(time ? { time } : {}),
    ...(typeof m.user === 'string' ? { user: m.user } : {}),
    ...(typeof m.username === 'string' ? { botName: m.username } : {}),
    ...(typeof m.subtype === 'string' ? { subtype: m.subtype } : {}),
    text: typeof m.text === 'string' ? m.text : '',
    ...(typeof m.thread_ts === 'string' && m.thread_ts !== m.ts ? { threadTs: m.thread_ts } : {}),
    ...(typeof m.reply_count === 'number' ? { replyCount: m.reply_count } : {}),
    ...(m.edited ? { edited: true } : {}),
    ...(files?.length ? { files } : {}),
  };
}

function conversationType(c: Raw): ConversationType {
  if (c.is_im) return 'im';
  if (c.is_mpim) return 'mpim';
  if (c.is_private || c.is_group) return 'private_channel';
  return 'public_channel';
}

/** Session token of the Slack web client (xoxc-…). */
export const SLACK_SESSION_TOKEN = /^xoxc-[A-Za-z0-9-]{10,500}$/;

/**
 * Normalises a pasted value of the browser cookie `d`: an optional leading `d=`, surrounding quotes and a
 * trailing `;` are dropped. Browsers show the value URL-encoded (%2F, %2B, %3D) and Perch sends it as is; a
 * decoded copy (raw '/', '+', '=') is encoded the same way the browser sends it.
 */
export function normalizeSlackCookie(raw: string): string {
  let v = raw.trim();
  if (v.startsWith('d=')) v = v.slice(2).trim();
  v = v.replace(/;$/, '').trim();
  if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
  if (!v.includes('%') && /[/+=]/.test(v)) v = v.replace(/[/+=]/g, (ch) => encodeURIComponent(ch));
  if (!SLACK_SESSION_COOKIE.test(v)) {
    throw new PerchError('Expected the value of the Slack cookie "d" as shown in the browser (starts with xoxd-)', 'bad_argument');
  }
  return v;
}

/**
 * Validates a user token with auth.test and stores it under a user-assigned label. Bot tokens are refused:
 * they cannot read DMs or search, and would post as the app instead of the user.
 *
 * With `sessionCookie` (session mode, unofficial): the token must be a browser session token (xoxc-…) and
 * auth.test runs with token and cookie. A workspace with the same team id is updated in place (same id, client
 * grants stay); otherwise a new one is added. An app add for a team connected as a session switches that
 * record to the app the same way. Nothing is stored when Slack refuses.
 */
export async function addSlackWorkspace(
  store: CredentialStore,
  upstream: Upstream,
  input: { label: string; token: string; sessionCookie?: string },
): Promise<SlackWorkspace> {
  const label = validateLabel(input.label);
  const token = input.token.trim();
  if (!token) throw new PerchError('Empty token', 'bad_argument');
  const session = input.sessionCookie !== undefined;
  const cookie = session ? normalizeSlackCookie(input.sessionCookie!) : undefined;
  if (session) {
    if (!SLACK_SESSION_TOKEN.test(token)) throw new PerchError('Expected the Slack session token (xoxc-…, printed by the console line of the guide)', 'bad_argument');
  } else {
    if (SLACK_SESSION_TOKEN.test(token)) throw new PerchError('This is a browser session token (xoxc-…); connect it with perch slack add --label NAME --session', 'bad_argument');
    if (!/^xoxp-[A-Za-z0-9-]{10,500}$/.test(token)) {
      throw new PerchError('Expected a Slack user token (xoxp-…, "User OAuth Token" of the app). Bot (xoxb-), rotating (xoxe-) and app-level (xapp-) tokens are not supported', 'bad_argument');
    }
    const existing = (await store.read()).slack.find((w) => fingerprint(w.token) === fingerprint(token));
    if (existing) throw new PerchError(`This token is already connected as ${existing.id} ("${existing.label}")`, 'duplicate_account');
  }
  const creds = session ? { token, authMode: 'session' as const, sessionCookie: cookie! } : { token };
  const res = await upstream.raw('slack', { method: 'GET', path: '/api/auth.test', ...slackAuth(creds) });
  let body: Raw;
  try {
    body = JSON.parse(res.body.toString('utf8')) as Raw;
  } catch {
    throw new PerchError('Slack returned a malformed response', 'upstream_bad_response');
  }
  if (body.ok !== true) {
    if (session && isSlackAuthFailure(body.error)) {
      throw new PerchError(
        `Slack refused the session (${String(body.error)}): token and cookie must come from the same signed-in browser; copy both again. Nothing was stored`,
        'upstream_error',
      );
    }
    throw slackFailure(body.error);
  }
  const teamId = typeof body.team_id === 'string' ? body.team_id : '';
  const userId = typeof body.user_id === 'string' ? body.user_id : '';
  if (!/^[TE][A-Z0-9]{2,30}$/.test(teamId) || !SLACK_USER.test(userId)) throw new PerchError('Slack returned an unexpected identity', 'upstream_bad_response');
  // Session tokens report no x-oauth-scopes; their scopes are never checked.
  const scopes = session
    ? []
    : (res.headers['x-oauth-scopes'] ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter((s) => /^[a-z.:_-]{1,100}$/.test(s));
  return store.update((data) => {
    const now = new Date().toISOString();
    const fields = {
      label,
      token,
      teamId,
      ...(typeof body.team === 'string' ? { teamName: body.team.slice(0, 200) } : {}),
      ...(typeof body.url === 'string' ? { teamUrl: body.url.slice(0, 500) } : {}),
      userId,
      ...(typeof body.user === 'string' ? { userName: body.user.slice(0, 200) } : {}),
      scopes,
      ...(session ? { authMode: 'session' as const, sessionCookie: cookie! } : {}),
    };
    let replace: SlackWorkspace | undefined;
    if (session) {
      const sameTeam = data.slack.filter((w) => w.teamId === teamId);
      replace = sameTeam.find((w) => w.userId === userId) ?? sameTeam[0];
    } else {
      if (data.slack.some((w) => fingerprint(w.token) === fingerprint(token))) throw new PerchError('This token is already connected', 'duplicate_account');
      const dup = data.slack.find((w) => w.teamId === teamId && w.userId === userId && !isSlackSession(w));
      if (dup) throw new PerchError(`This Slack user in this workspace is already connected as ${dup.id} ("${dup.label}"); remove it first to replace the token`, 'duplicate_account');
      replace = data.slack.find((w) => w.teamId === teamId && isSlackSession(w));
    }
    if (replace) {
      const id = replace.id;
      const updated: SlackWorkspace = { id, ...fields, createdAt: replace.createdAt, updatedAt: now };
      data.slack = data.slack.map((w) => (w.id === id ? updated : w));
      return updated;
    }
    const ws: SlackWorkspace = { id: newAccountId('slack', data.slack.map((w) => w.id)), ...fields, createdAt: now, updatedAt: now };
    data.slack.push(ws);
    return ws;
  });
}

/** Local disconnect only. The token stays valid until the app is uninstalled or the token revoked in Slack. */
export async function removeSlackWorkspace(store: CredentialStore, id: string): Promise<void> {
  await store.update((data) => {
    if (!data.slack.some((w) => w.id === id)) throw new PerchError(`Unknown Slack workspace: ${id}`, 'unknown_account');
    data.slack = data.slack.filter((w) => w.id !== id);
  });
}

const bindingParts = (ws: SlackWorkspace) => ['slack', ws.id, ws.teamId, ws.userId, fingerprint(ws.token)];

/** Per tool call: 429 retries left and users.info lookups left (shared by every page and scan of the call). */
interface RetryBudget {
  remaining: number;
  lookups: number;
}

const newBudget = (): RetryBudget => ({ remaining: MAX_RETRIES_PER_CALL, lookups: MAX_USER_LOOKUPS_PER_CALL });

export interface SlackUploadRequest {
  workspaceId: string;
  channelId: string;
  filename: string;
  contentBase64: string;
  title?: string;
  initialComment?: string;
  threadTs?: string;
  requestId: string;
}

/** Standard base64 with padding (linear check; the length must also be a multiple of 4). */
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

function filenameOf(v: unknown): string {
  if (typeof v !== 'string' || !v.trim() || v.length > MAX_SLACK_FILENAME || /[\u0000-\u001f\u007f/\\]/.test(v) || v === '.' || v === '..') {
    throw new PerchError(`filename must be 1-${MAX_SLACK_FILENAME} characters without slashes or control characters`, 'bad_argument');
  }
  return v;
}

function optionalText(v: unknown, what: string, max: number): string | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'string' || !v.trim() || v.length > max) throw new PerchError(`${what} must be 1-${max} characters`, 'bad_argument');
  return v;
}

function emojiOf(v: unknown): string {
  if (typeof v !== 'string' || !SLACK_EMOJI_NAME.test(v)) throw new PerchError('emoji must be a Slack emoji name without colons, e.g. thumbsup or white_check_mark', 'bad_argument');
  return v;
}

function fileIdOf(v: unknown): string {
  if (typeof v !== 'string' || !SLACK_FILE_ID.test(v)) throw new PerchError('fileId must be a Slack file id (F…)', 'bad_argument');
  return v;
}

/** Decodes strict base64 and enforces the size limit (checked on the encoded length first, before decoding). */
function bytesOf(v: unknown): Buffer {
  if (typeof v !== 'string' || !v) throw new PerchError('contentBase64 must not be empty', 'bad_argument');
  if (v.length > Math.ceil(MAX_SLACK_FILE_BYTES / 3) * 4) throw new PerchError(`The file exceeds ${MAX_SLACK_FILE_BYTES} bytes`, 'bad_argument');
  if (v.length % 4 !== 0 || !BASE64.test(v)) throw new PerchError('contentBase64 must be standard base64', 'bad_argument');
  const bytes = Buffer.from(v, 'base64');
  if (bytes.length === 0) throw new PerchError('The file is empty', 'bad_argument');
  if (bytes.length > MAX_SLACK_FILE_BYTES) throw new PerchError(`The file exceeds ${MAX_SLACK_FILE_BYTES} bytes`, 'bad_argument');
  return bytes;
}

/** upload_url from files.getUploadURLExternal: exactly https://files.slack.com/upload/v1/<opaque segment>. */
function uploadPathOf(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || raw.length > 4096) return undefined;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:' || url.hostname !== 'files.slack.com' || url.port || url.username || url.password || url.search || url.hash) return undefined;
  return SLACK_UPLOAD_PATH.test(url.pathname) ? url.pathname : undefined;
}

/** url_private_download of file `fileId`: exactly https://files.slack.com/files-pri/<team>-<fileId>/…. */
function downloadPathOf(raw: unknown, fileId: string): string | undefined {
  if (typeof raw !== 'string' || raw.length > 2048) return undefined;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:' || url.hostname !== 'files.slack.com' || url.port || url.username || url.password || url.search || url.hash) return undefined;
  const m = SLACK_DOWNLOAD_PATH.exec(url.pathname);
  return m && m[1] === fileId ? url.pathname : undefined;
}

function fileMeta(f: Raw) {
  const str = (k: string, max = 500) => (typeof f[k] === 'string' ? { [k]: (f[k] as string).slice(0, max) } : {});
  const created = typeof f.created === 'number' ? new Date(f.created * 1000).toISOString() : undefined;
  return {
    fileId: String(f.id),
    ...(typeof f.name === 'string' ? { name: f.name.slice(0, 500) } : {}),
    ...str('title'),
    ...str('mimetype', 200),
    ...str('filetype', 50),
    ...(typeof f.size === 'number' ? { size: f.size } : {}),
    ...(created ? { created } : {}),
    ...(typeof f.user === 'string' ? { user: f.user } : {}),
    ...(typeof f.is_external === 'boolean' ? { isExternal: f.is_external } : {}),
    ...str('permalink', 1000),
  };
}

/** 1-8 distinct Slack user ids (U…/W…) for conversations.open. */
function usersOf(v: unknown): string[] {
  if (!Array.isArray(v) || v.length < 1 || v.length > MAX_SLACK_GROUP_DM_USERS) {
    throw new PerchError(`users must list 1 (DM) to ${MAX_SLACK_GROUP_DM_USERS} (group DM) Slack user ids`, 'bad_argument');
  }
  for (const u of v) if (typeof u !== 'string' || !SLACK_USER.test(u)) throw new PerchError('users must be Slack user ids (U… or W…), e.g. from slack_get_history', 'bad_argument');
  if (new Set(v).size !== v.length) throw new PerchError('users must not contain duplicates', 'bad_argument');
  return v as string[];
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/;

/** postAt as Unix seconds (integer) or RFC 3339 with offset, normalised to whole Unix seconds (format only). */
function postAtOf(v: unknown): number {
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || v <= 0) throw new PerchError('postAt must be whole Unix seconds or an RFC 3339 timestamp with offset', 'bad_argument');
    return v;
  }
  if (typeof v === 'string' && /^\d{9,11}$/.test(v)) return Number(v);
  if (typeof v !== 'string' || !RFC3339.test(v)) {
    throw new PerchError('postAt must be Unix seconds or an RFC 3339 timestamp with offset, e.g. 2026-10-21T09:00:00+02:00', 'bad_argument');
  }
  const ms = Date.parse(v);
  if (!Number.isFinite(ms)) throw new PerchError('postAt is not a valid time', 'bad_argument');
  return Math.floor(ms / 1000);
}

/** Throws unless postAt is at least 60 s and at most 120 days ahead of now. */
function assertScheduleWindow(postAt: number, nowMs: number): void {
  const now = Math.floor(nowMs / 1000);
  if (postAt < now + MIN_SCHEDULE_LEAD_SECONDS) throw new PerchError(`postAt must be at least ${MIN_SCHEDULE_LEAD_SECONDS} seconds in the future`, 'bad_argument');
  if (postAt > now + MAX_SCHEDULE_AHEAD_SECONDS) throw new PerchError('postAt must be at most 120 days in the future', 'bad_argument');
}

export interface SlackScheduleRequest {
  workspaceId: string;
  channelId: string;
  text: string;
  postAt: number | string;
  threadTs?: string;
  requestId: string;
}

export interface SlackSendRequest {
  workspaceId: string;
  channelId: string;
  text: string;
  threadTs?: string;
  replyBroadcast?: boolean;
  requestId: string;
}

export class SlackService {
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly guard?: () => Promise<void>;
  private readonly now: () => number;
  private readonly users = new Map<string, string>();

  constructor(
    private readonly store: CredentialStore,
    private readonly upstream: Upstream,
    private readonly workflow: SendWorkflow,
    private readonly audit: AuditLog,
    opts: { sleep?: (ms: number) => Promise<void>; guard?: () => Promise<void>; now?: () => number } = {},
  ) {
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.guard = opts.guard;
    this.now = opts.now ?? Date.now;
  }

  private async workspace(id: unknown): Promise<SlackWorkspace> {
    const ws = typeof id === 'string' ? (await this.store.read()).slack.find((w) => w.id === id) : undefined;
    if (!ws) throw new PerchError(`Unknown Slack workspace: ${String(id)}`, 'unknown_account');
    return ws;
  }

  private async readable(p: Principal, id: unknown): Promise<SlackWorkspace> {
    if (typeof id !== 'string') throw new PerchError('workspaceId is required', 'bad_argument');
    assertSlackCapability(p, id, 'slack_read');
    return this.workspace(id);
  }

  private async readableAll(p: Principal, id: string | undefined): Promise<SlackWorkspace[]> {
    if (id !== undefined) return [await this.readable(p, id)];
    if (!p.capabilities.has('slack_read')) throw new PerchError('Capability "slack_read" is not granted to this client', 'capability_denied');
    return (await this.store.read()).slack.filter((w) => p.slackAccounts === 'all' || p.slackAccounts.has(w.id));
  }

  private prov(ws: SlackWorkspace): WorkspaceProvenance {
    return { workspaceId: ws.id, workspaceLabel: ws.label, ...(ws.teamName ? { team: ws.teamName } : {}) };
  }

  private async call<T extends Raw>(budget: RetryBudget, ws: SlackWorkspace, method: string, query: Record<string, string | number | boolean | undefined>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      try {
        const body = await this.upstream.json<Raw>('slack', { method: 'GET', path: `/api/${method}`, query, ...slackAuth(ws) });
        if (body.ok !== true) throw slackFailure(body.error, ws);
        return body as T;
      } catch (err) {
        const limited = err instanceof UpstreamError && err.status === 429;
        if (!limited || attempt >= MAX_RETRIES_PER_REQUEST || budget.remaining <= 0) throw err;
        budget.remaining--;
        await this.sleep(Math.min((err.retryAfterSeconds ?? 1) * 1000, MAX_RETRY_WAIT_MS));
      }
    }
  }

  /** Adds userName to messages (users.info, cached per workspace, bounded per call; failures are ignored). */
  private async withNames<T extends { user?: string; userName?: string }>(budget: RetryBudget, ws: SlackWorkspace, items: T[]): Promise<T[]> {
    for (const id of new Set(items.map((m) => m.user).filter((u): u is string => typeof u === 'string' && SLACK_USER.test(u)))) {
      const key = `${ws.id}:${id}`;
      if (this.users.has(key) || budget.lookups <= 0) continue;
      budget.lookups--;
      try {
        const r = await this.call<{ user?: Raw }>(budget, ws, 'users.info', { user: id });
        const profile = (r.user?.profile ?? {}) as Raw;
        const name = [profile.display_name, profile.real_name, r.user?.real_name, r.user?.name].find((n) => typeof n === 'string' && n.trim());
        if (typeof name === 'string') {
          if (this.users.size >= MAX_CACHED_USERS) this.users.delete(this.users.keys().next().value!);
          this.users.set(key, name.slice(0, 200));
        }
      } catch {
        // Names are a convenience; the stable user id stays in the result.
      }
    }
    return items.map((m) => {
      const name = m.user ? this.users.get(`${ws.id}:${m.user}`) : undefined;
      return name ? { ...m, userName: name } : m;
    });
  }

  /** Channels, private channels, group DMs and DMs the token's user is in (or can see), across workspaces. */
  async listConversations(
    p: Principal,
    input: { workspaceId?: string; types?: ConversationType[]; query?: string; pageSize?: number; cursor?: string },
  ): Promise<FanOutResult<Raw & WorkspaceProvenance>> {
    const pageSize = bounded('pageSize', input.pageSize, DEFAULT_SLACK_PAGE_SIZE, MAX_SLACK_PAGE_SIZE);
    const types = input.types?.length ? [...new Set(input.types)] : [...CONVERSATION_TYPES];
    if (types.some((t) => !(CONVERSATION_TYPES as readonly string[]).includes(t))) throw new PerchError(`types must be of ${CONVERSATION_TYPES.join(', ')}`, 'bad_argument');
    const needle = input.query?.trim().toLowerCase();
    const workspaces = await this.readableAll(p, input.workspaceId);
    const budget = newBudget();
    const res = await fanOut<Raw>({
      kind: 'slack-conversations',
      queryKey: { ws: input.workspaceId ?? null, types, q: needle ?? null, pageSize },
      sources: workspaces,
      seal: this.store,
      cursor: input.cursor,
      fetchPage: async (source, start) => {
        const ws = workspaces.find((w) => w.id === source.id)!;
        const items: Raw[] = [];
        let cursor = start;
        for (let scans = 0; scans < (needle ? MAX_FILTER_SCANS : 1); scans++) {
          const r = await this.call<{ channels?: Raw[]; response_metadata?: { next_cursor?: string } }>(budget, ws, 'conversations.list', {
            types: types.join(','),
            exclude_archived: true,
            limit: needle ? MAX_SLACK_PAGE_SIZE : pageSize,
            cursor,
          });
          let rows = (r.channels ?? []).map((c) => ({
            channelId: String(c.id),
            type: conversationType(c),
            ...(typeof c.name === 'string' ? { name: c.name } : {}),
            ...(typeof c.user === 'string' ? { user: c.user } : {}),
            ...(typeof c.is_member === 'boolean' ? { isMember: c.is_member } : {}),
            ...(typeof c.num_members === 'number' ? { numMembers: c.num_members } : {}),
            ...((c.topic as Raw | undefined)?.value ? { topic: String((c.topic as Raw).value).slice(0, 500) } : {}),
          }));
          rows = await this.withNames(budget, ws, rows);
          if (needle) rows = rows.filter((c) => [c.name, (c as { userName?: string }).userName].some((n) => typeof n === 'string' && n.toLowerCase().includes(needle)));
          items.push(...rows);
          cursor = r.response_metadata?.next_cursor || undefined;
          if (!cursor || items.length >= pageSize) break;
        }
        return { items, next: cursor ?? null };
      },
    });
    return { ...res, results: res.results.map(({ accountId, accountLabel, ...c }) => ({ ...c, workspaceId: accountId, workspaceLabel: accountLabel })) };
  }

  /** Messages of one conversation, newest first. */
  async getHistory(p: Principal, input: { workspaceId: string; channelId: string; oldest?: string; latest?: string; pageSize?: number; cursor?: string }) {
    const ws = await this.readable(p, input.workspaceId);
    const channel = channelIdOf(input.channelId);
    const pageSize = bounded('pageSize', input.pageSize, DEFAULT_SLACK_PAGE_SIZE, MAX_SLACK_PAGE_SIZE);
    const kind = `slack-history:${ws.id}:${channel}:${input.oldest ?? ''}:${input.latest ?? ''}`;
    const budget = newBudget();
    const r = await this.call<{ messages?: Raw[]; has_more?: boolean; response_metadata?: { next_cursor?: string } }>(budget, ws, 'conversations.history', {
      channel,
      limit: pageSize,
      oldest: epochOf(input.oldest, 'oldest'),
      latest: epochOf(input.latest, 'latest'),
      cursor: input.cursor ? this.store.openCursor(kind, input.cursor) : undefined,
    });
    const next = r.response_metadata?.next_cursor;
    return {
      ...this.prov(ws),
      channelId: channel,
      messages: await this.withNames(budget, ws, (r.messages ?? []).map(toMessage)),
      nextCursor: next ? this.store.sealCursor(kind, next) : null,
      hasMore: Boolean(next),
    };
  }

  /** A thread: the parent message followed by its replies, oldest first. */
  async getThread(p: Principal, input: { workspaceId: string; channelId: string; threadTs: string; pageSize?: number; cursor?: string }) {
    const ws = await this.readable(p, input.workspaceId);
    const channel = channelIdOf(input.channelId);
    const ts = tsOf(input.threadTs, 'threadTs');
    const pageSize = bounded('pageSize', input.pageSize, DEFAULT_SLACK_PAGE_SIZE, MAX_SLACK_PAGE_SIZE);
    const kind = `slack-thread:${ws.id}:${channel}:${ts}`;
    const budget = newBudget();
    const r = await this.call<{ messages?: Raw[]; response_metadata?: { next_cursor?: string } }>(budget, ws, 'conversations.replies', {
      channel,
      ts,
      limit: pageSize,
      cursor: input.cursor ? this.store.openCursor(kind, input.cursor) : undefined,
    });
    const next = r.response_metadata?.next_cursor;
    return {
      ...this.prov(ws),
      channelId: channel,
      threadTs: ts,
      messages: await this.withNames(budget, ws, (r.messages ?? []).map(toMessage)),
      nextCursor: next ? this.store.sealCursor(kind, next) : null,
      hasMore: Boolean(next),
    };
  }

  /** Slack's message search (search.messages; supports in:#channel, from:@user, before:/after: modifiers), newest first. */
  async search(p: Principal, input: { query: string; workspaceId?: string; pageSize?: number; cursor?: string }): Promise<FanOutResult<Raw & WorkspaceProvenance>> {
    const query = input.query?.trim();
    if (!query) throw new PerchError('query is required', 'bad_argument');
    const pageSize = bounded('pageSize', input.pageSize, 20, MAX_SLACK_SEARCH_PAGE_SIZE);
    const workspaces = await this.readableAll(p, input.workspaceId);
    const budget = newBudget();
    const res = await fanOut<Raw>({
      kind: 'slack-search',
      queryKey: { q: query, ws: input.workspaceId ?? null, pageSize },
      sources: workspaces,
      seal: this.store,
      cursor: input.cursor,
      fetchPage: async (source, start) => {
        const ws = workspaces.find((w) => w.id === source.id)!;
        if (!hasScope(ws, 'search:read')) throw new PerchError(`Workspace ${ws.id} lacks search:read. Reconnect: ${slackSessionAddCommand(ws.label)}`, 'provider_scope_missing');
        const page = start ? Number(start) : 1;
        if (!Number.isInteger(page) || page < 1 || page > 100) throw new PerchError('Invalid cursor', 'bad_cursor');
        const r = await this.call<{ messages?: { matches?: Raw[]; paging?: { page?: number; pages?: number } } }>(budget, ws, 'search.messages', {
          query,
          count: pageSize,
          page,
          sort: 'timestamp',
          sort_dir: 'desc',
          highlight: false,
        });
        const matches = (r.messages?.matches ?? []).map((m) => {
          const ch = (m.channel ?? {}) as Raw;
          const msg = toMessage(m);
          return {
            ...msg,
            ...(typeof ch.id === 'string' ? { channelId: ch.id } : {}),
            ...(typeof ch.name === 'string' ? { channelName: ch.name } : {}),
            ...(typeof m.username === 'string' ? { userName: m.username } : {}),
            ...(typeof m.permalink === 'string' ? { permalink: m.permalink } : {}),
          };
        });
        const pages = r.messages?.paging?.pages ?? 1;
        return { items: matches, next: page < pages && page < 100 ? String(page + 1) : null };
      },
    });
    return { ...res, results: res.results.map(({ accountId, accountLabel, ...m }) => ({ ...m, workspaceId: accountId, workspaceLabel: accountLabel })) };
  }

  /** Re-checks the namespace guard and the stored grant (revocation applies before the provider call). */
  private async stillAllowed(stale: Principal, workspaceId: string): Promise<void> {
    await this.guard?.();
    assertSlackCapability(await currentPrincipal(this.store, stale), workspaceId, 'slack_send');
  }

  private assertCanPost(ws: SlackWorkspace): void {
    if (!hasScope(ws, 'chat:write')) {
      throw new PerchError(`Workspace ${ws.id} lacks chat:write. Reconnect: ${slackSessionAddCommand(ws.label)}`, 'provider_scope_missing');
    }
  }

  /** Posts a message as the token's user (idempotent per requestId; see src/messaging/send.ts). */
  async send(p: Principal, req: SlackSendRequest): Promise<Omit<MessageSendView, 'providerMessageId'> & WorkspaceProvenance & { channelId: string; messageTs?: string }> {
    let ws: SlackWorkspace | undefined;
    let channel = '';
    const view = await sendMessageIdempotently({
      workflow: this.workflow,
      audit: this.audit,
      actor: actorOf(p),
      provider: 'slack',
      accountId: req?.workspaceId,
      prepare: async () => {
        await this.guard?.();
        if (typeof req?.workspaceId !== 'string') throw new PerchError('workspaceId is required', 'bad_argument');
        assertSlackCapability(p, req.workspaceId, 'slack_send');
        ws = await this.workspace(req.workspaceId);
        this.assertCanPost(ws);
        channel = channelIdOf(req.channelId);
        if (typeof req.text !== 'string' || !req.text.trim()) throw new PerchError('text must not be empty', 'bad_argument');
        if (req.text.length > MAX_SLACK_TEXT) throw new PerchError(`text exceeds ${MAX_SLACK_TEXT} characters`, 'bad_argument');
        const threadTs = req.threadTs === undefined ? undefined : tsOf(req.threadTs, 'threadTs');
        if (req.replyBroadcast !== undefined && typeof req.replyBroadcast !== 'boolean') throw new PerchError('replyBroadcast must be a boolean', 'bad_argument');
        if (req.replyBroadcast && !threadTs) throw new PerchError('replyBroadcast requires threadTs', 'bad_argument');
        const canonical = JSON.stringify(['perch-slack-send-v1', ws.id, channel, req.text, threadTs ?? null, req.replyBroadcast ?? false]);
        return { accountId: ws.id, requestId: req.requestId, canonical, binding: bindingParts(ws) };
      },
      attempt: (binding) => this.attempt(p, req, channel, binding),
    });
    const ts = decodeTs(view.providerMessageId);
    const { providerMessageId: _ref, ...rest } = view;
    return { ...this.prov(ws!), ...rest, channelId: channel, ...(ts ? { messageTs: ts } : {}) };
  }

  private async attempt(p: Principal, req: SlackSendRequest, channel: string, binding: string): Promise<MessageSendResult> {
    const notSent = (detail: string, reason: MessageSendResult['reason']): MessageSendResult => ({ status: 'rejected', detail: `Not sent: ${detail}`, reason });
    try {
      await this.stillAllowed(p, req.workspaceId);
    } catch (err) {
      return notSent(err instanceof PerchError ? err.message : 'the request is no longer authorised', 'not_submitted_authorization');
    }
    const current = (await this.store.read()).slack.find((w) => w.id === req.workspaceId);
    if (!current || (await this.workflow.binding(bindingParts(current))) !== binding) {
      return notSent('the workspace was removed or reconnected since this requestId was first used', 'not_submitted_account_changed');
    }
    try {
      this.assertCanPost(current);
    } catch (err) {
      return notSent((err as PerchError).message, 'not_submitted_provider_precheck');
    }
    let body: Raw;
    try {
      body = await this.upstream.json<Raw>('slack', {
        method: 'POST',
        path: '/api/chat.postMessage',
        capability: 'slack_send',
        ...slackAuth(current),
        json: {
          channel,
          text: req.text,
          ...(req.threadTs ? { thread_ts: req.threadTs } : {}),
          ...(req.replyBroadcast ? { reply_broadcast: true } : {}),
        },
      });
    } catch (err) {
      // Slack answered with an error status: not processed (429 = rate limited before processing).
      if (err instanceof UpstreamError && err.status < 500) return notSent(`Slack refused the request (HTTP ${err.status})`, 'provider_rejected');
      if (err instanceof PerchError && err.code === 'route_not_allowed') return notSent(err.message, 'not_submitted_provider_precheck');
      return { status: 'indeterminate', detail: 'The request to Slack failed after it may have been processed; the outcome is unknown.', reason: 'provider_unknown' };
    }
    if (body.ok !== true) return notSent(slackFailure(body.error, current).message, 'provider_rejected');
    const ts = typeof body.ts === 'string' && SLACK_TS.test(body.ts) ? body.ts : undefined;
    return { status: 'accepted', detail: 'Posted.', ...(ts ? { providerMessageId: encodeTs(ts) } : {}), reason: 'provider_accepted' };
  }

  async sendStatus(p: Principal, input: { workspaceId: string; requestId: string }) {
    if (typeof input?.workspaceId !== 'string') throw new PerchError('workspaceId is required', 'bad_argument');
    assertSlackCapability(p, input.workspaceId, 'slack_send');
    const ws = await this.workspace(input.workspaceId);
    const view = await messageSendStatus(this.workflow, actorOf(p), ws.id, input.requestId, bindingParts(ws));
    const ts = decodeTs(view.providerMessageId);
    // slack_schedule_message shares this ledger: its record holds the scheduled message id (Q…), not a ts.
    const scheduled = view.providerMessageId && SLACK_SCHEDULED_ID.test(view.providerMessageId) ? view.providerMessageId : undefined;
    const { providerMessageId: _ref, ...rest } = view;
    return { ...this.prov(ws), ...rest, ...(ts ? { messageTs: ts } : {}), ...(scheduled ? { scheduledMessageId: scheduled } : {}) };
  }

  private assertScope(ws: SlackWorkspace, scope: (typeof SLACK_USER_SCOPES)[number]): void {
    if (!hasScope(ws, scope)) {
      throw new PerchError(
        `Workspace ${ws.id} lacks ${scope}. Reconnect: ${slackSessionAddCommand(ws.label)}`,
        'provider_scope_missing',
      );
    }
  }

  /**
   * One plain (non-idempotent, harmless to repeat) write: grant for slack_send, then right before the call
   * the grant, namespace guard and token scope are checked again against the stored state. No retries.
   */
  private async plainWrite(p: Principal, workspaceId: unknown, scope: (typeof SLACK_USER_SCOPES)[number], method: string, body: { json?: unknown; form?: Record<string, string> }): Promise<Raw> {
    await this.guard?.();
    if (typeof workspaceId !== 'string') throw new PerchError('workspaceId is required', 'bad_argument');
    assertSlackCapability(p, workspaceId, 'slack_send');
    this.assertScope(await this.workspace(workspaceId), scope);
    await this.stillAllowed(p, workspaceId);
    const ws = await this.workspace(workspaceId);
    this.assertScope(ws, scope);
    const res = await this.upstream.json<Raw>('slack', { method: 'POST', path: `/api/${method}`, capability: 'slack_send', ...slackAuth(ws), ...body });
    // An expired session is reported the same way for every write.
    if (res.ok !== true && isSlackAuthFailure(res.error)) throw slackFailure(res.error, ws);
    return res;
  }

  /** Adds an emoji reaction as the token's user; an existing reaction counts as success. */
  async addReaction(p: Principal, input: { workspaceId: string; channelId: string; ts: string; emoji: string }) {
    const channel = channelIdOf(input?.channelId);
    const ts = tsOf(input?.ts, 'ts');
    const name = emojiOf(input?.emoji);
    const body = await this.plainWrite(p, input?.workspaceId, 'reactions:write', 'reactions.add', { form: { channel, timestamp: ts, name } });
    if (body.ok !== true && body.error !== 'already_reacted') throw slackFailure(body.error);
    const ws = await this.workspace(input.workspaceId);
    return { ...this.prov(ws), channelId: channel, ts, emoji: name, status: body.ok === true ? 'added' : 'already_present' };
  }

  /** Removes the token user's own emoji reaction; a missing reaction counts as success. */
  async removeReaction(p: Principal, input: { workspaceId: string; channelId: string; ts: string; emoji: string }) {
    const channel = channelIdOf(input?.channelId);
    const ts = tsOf(input?.ts, 'ts');
    const name = emojiOf(input?.emoji);
    const body = await this.plainWrite(p, input?.workspaceId, 'reactions:write', 'reactions.remove', { form: { channel, timestamp: ts, name } });
    if (body.ok !== true && body.error !== 'no_reaction') throw slackFailure(body.error);
    const ws = await this.workspace(input.workspaceId);
    return { ...this.prov(ws), channelId: channel, ts, emoji: name, status: body.ok === true ? 'removed' : 'not_present' };
  }

  /** Edits a message (chat.update). Slack only allows the token user's own messages. */
  async editMessage(p: Principal, input: { workspaceId: string; channelId: string; ts: string; text: string }) {
    const channel = channelIdOf(input?.channelId);
    const ts = tsOf(input?.ts, 'ts');
    if (typeof input?.text !== 'string' || !input.text.trim()) throw new PerchError('text must not be empty', 'bad_argument');
    if (input.text.length > MAX_SLACK_TEXT) throw new PerchError(`text exceeds ${MAX_SLACK_TEXT} characters`, 'bad_argument');
    const body = await this.plainWrite(p, input.workspaceId, 'chat:write', 'chat.update', { json: { channel, ts, text: input.text } });
    if (body.ok !== true) {
      if (body.error === 'cant_update_message' || body.error === 'edit_window_closed') {
        throw new PerchError(
          body.error === 'cant_update_message'
            ? 'Slack refused the edit: only messages written by the connected user can be edited (cant_update_message)'
            : 'Slack refused the edit: the workspace no longer allows editing this message (edit_window_closed)',
          'provider_rejected',
        );
      }
      throw slackFailure(body.error);
    }
    const ws = await this.workspace(input.workspaceId);
    return { ...this.prov(ws), channelId: channel, ts, status: 'updated' };
  }

  /**
   * Uploads a file and shares it into a conversation (files.getUploadURLExternal, POST bytes to the
   * returned files.slack.com URL, files.completeUploadExternal). Idempotent per requestId like send().
   * The file only becomes visible with the final step, so every failure before it means "not shared".
   */
  async uploadFile(p: Principal, req: SlackUploadRequest) {
    let ws: SlackWorkspace | undefined;
    let channel = '';
    let bytes: Buffer = Buffer.alloc(0);
    let threadTs: string | undefined;
    let title: string | undefined;
    let comment: string | undefined;
    const view = await sendMessageIdempotently({
      workflow: this.workflow,
      audit: this.audit,
      actor: actorOf(p),
      provider: 'slack',
      accountId: req?.workspaceId,
      prepare: async () => {
        await this.guard?.();
        if (typeof req?.workspaceId !== 'string') throw new PerchError('workspaceId is required', 'bad_argument');
        assertSlackCapability(p, req.workspaceId, 'slack_send');
        ws = await this.workspace(req.workspaceId);
        this.assertScope(ws, 'files:write');
        channel = channelIdOf(req.channelId);
        const filename = filenameOf(req.filename);
        bytes = bytesOf(req.contentBase64);
        title = optionalText(req.title, 'title', MAX_SLACK_FILENAME);
        comment = optionalText(req.initialComment, 'initialComment', MAX_SLACK_TEXT);
        threadTs = req.threadTs === undefined ? undefined : tsOf(req.threadTs, 'threadTs');
        const digest = createHash('sha256').update(bytes).digest('hex');
        const canonical = JSON.stringify(['perch-slack-upload-v1', ws.id, channel, filename, digest, title ?? null, comment ?? null, threadTs ?? null]);
        return { accountId: ws.id, requestId: req.requestId, canonical, binding: bindingParts(ws) };
      },
      attempt: (binding) => this.uploadAttempt(p, req, { channel, bytes, threadTs, title, comment }, binding),
    });
    const { providerMessageId, ...rest } = view;
    return { ...this.prov(ws!), ...rest, channelId: channel, ...(providerMessageId && SLACK_FILE_ID.test(providerMessageId) ? { fileId: providerMessageId } : {}) };
  }

  private async uploadAttempt(
    p: Principal,
    req: SlackUploadRequest,
    f: { channel: string; bytes: Buffer; threadTs?: string; title?: string; comment?: string },
    binding: string,
  ): Promise<MessageSendResult> {
    const notShared = (detail: string, reason: MessageSendResult['reason']): MessageSendResult => ({ status: 'rejected', detail: `Not shared: ${detail}`, reason });
    try {
      await this.stillAllowed(p, req.workspaceId);
    } catch (err) {
      return notShared(err instanceof PerchError ? err.message : 'the request is no longer authorised', 'not_submitted_authorization');
    }
    const current = (await this.store.read()).slack.find((w) => w.id === req.workspaceId);
    if (!current || (await this.workflow.binding(bindingParts(current))) !== binding) {
      return notShared('the workspace was removed or reconnected since this requestId was first used', 'not_submitted_account_changed');
    }
    try {
      this.assertScope(current, 'files:write');
    } catch (err) {
      return notShared((err as PerchError).message, 'not_submitted_provider_precheck');
    }
    const failed = (step: string, err: unknown): MessageSendResult => {
      if (err instanceof PerchError && err.code === 'route_not_allowed') return notShared(err.message, 'not_submitted_provider_precheck');
      if (err instanceof UpstreamError) return notShared(`Slack refused ${step} (HTTP ${err.status})`, 'provider_rejected');
      return notShared(`${step} failed before the file was shared`, 'provider_rejected');
    };
    // 1. Reserve an upload URL.
    let fileId: string;
    let uploadPath: string;
    try {
      const r = await this.upstream.json<Raw>('slack', {
        method: 'POST',
        path: '/api/files.getUploadURLExternal',
        capability: 'slack_send',
        ...slackAuth(current),
        form: { filename: req.filename, length: String(f.bytes.length) },
      });
      if (r.ok !== true) return notShared(slackFailure(r.error, current).message, 'provider_rejected');
      const path = uploadPathOf(r.upload_url);
      if (!path || typeof r.file_id !== 'string' || !SLACK_FILE_ID.test(r.file_id)) {
        return notShared('Slack returned an upload URL outside https://files.slack.com/upload/v1/; refusing to send the file there', 'not_submitted_provider_precheck');
      }
      fileId = r.file_id;
      uploadPath = path;
    } catch (err) {
      return failed('the upload URL request', err);
    }
    // 2. Send the bytes (the pre-signed URL needs no token; the token never leaves slack.com).
    try {
      await this.upstream.raw('slackfiles', {
        method: 'POST',
        path: uploadPath,
        capability: 'slack_send',
        bytes: { contentType: 'application/octet-stream', data: f.bytes },
        maxBytes: 64 * 1024,
      });
    } catch (err) {
      return failed('the file upload', err);
    }
    // 3. Share it. From here on an unknown outcome is indeterminate.
    let body: Raw;
    try {
      body = await this.upstream.json<Raw>('slack', {
        method: 'POST',
        path: '/api/files.completeUploadExternal',
        capability: 'slack_send',
        ...slackAuth(current),
        form: {
          files: JSON.stringify([{ id: fileId, title: f.title ?? req.filename }]),
          channel_id: f.channel,
          ...(f.threadTs ? { thread_ts: f.threadTs } : {}),
          ...(f.comment ? { initial_comment: f.comment } : {}),
        },
      });
    } catch (err) {
      if (err instanceof UpstreamError && err.status < 500) return notShared(`Slack refused the request (HTTP ${err.status})`, 'provider_rejected');
      if (err instanceof PerchError && err.code === 'route_not_allowed') return notShared(err.message, 'not_submitted_provider_precheck');
      return { status: 'indeterminate', detail: 'The request to Slack failed after it may have been processed; the outcome is unknown.', reason: 'provider_unknown' };
    }
    if (body.ok !== true) return notShared(slackFailure(body.error, current).message, 'provider_rejected');
    return { status: 'accepted', detail: 'File shared.', providerMessageId: fileId, reason: 'provider_accepted' };
  }

  /** File metadata (files.info) and, within maxBytes, its content as base64. Never truncates. */
  async getFile(p: Principal, input: { workspaceId: string; fileId: string; maxBytes?: number }) {
    const ws = await this.readable(p, input?.workspaceId);
    this.assertScope(ws, 'files:read');
    const fileId = fileIdOf(input.fileId);
    const maxBytes = bounded('maxBytes', input.maxBytes, DEFAULT_SLACK_FILE_READ_BYTES, MAX_SLACK_FILE_BYTES);
    const r = await this.call<{ file?: Raw }>(newBudget(), ws, 'files.info', { file: fileId });
    const file = r.file ?? {};
    if (file.id !== fileId) throw new PerchError('Slack returned a different file', 'upstream_bad_response');
    const meta = fileMeta(file);
    if (file.is_external === true || file.mode === 'tombstone' || file.mode === 'external') {
      return { ...this.prov(ws), ...meta, content: null, note: 'This file has no downloadable content in Slack (external or deleted).' };
    }
    const path = downloadPathOf(file.url_private_download, fileId);
    if (!path) throw new PerchError('Slack returned a download URL outside https://files.slack.com/files-pri/<team>-<file>/; refusing to fetch it', 'upstream_bad_response');
    if (typeof file.size === 'number' && file.size > maxBytes) {
      throw new PerchError(`The file has ${file.size} bytes, more than maxBytes (${maxBytes}); raise maxBytes (up to ${MAX_SLACK_FILE_BYTES}) to download it`, 'response_too_large');
    }
    const credentials = slackAuth(ws);
    const res = await this.upstream.raw('slackfiles', { method: 'GET', path, ...credentials, headers: { ...credentials.headers, accept: '*/*' }, maxBytes });
    const type = res.headers['content-type'] ?? '';
    if (/^text\/html/i.test(type) && !/html/i.test(String(file.mimetype ?? ''))) {
      if (isSlackSession(ws)) {
        throw new PerchError(`Slack answered with a web page instead of the file: the session has probably expired; run ${slackSessionAddCommand(ws.label)} again`, 'slack_session_expired');
      }
      throw new PerchError('Slack answered with a web page instead of the file (token lacks files:read or was revoked)', 'upstream_bad_response');
    }
    return { ...this.prov(ws), ...meta, contentBase64: res.body.toString('base64'), bytes: res.body.length };
  }

  /**
   * Opens (or finds) a DM with one user or a group DM with 2-8 users (conversations.open) and returns its
   * id for slack_send_message / slack_schedule_message. Posts nothing; repeating it returns the same id.
   */
  async openConversation(p: Principal, input: { workspaceId: string; users: string[] }) {
    const users = usersOf(input?.users);
    const group = users.length > 1;
    const body = await this.plainWrite(p, input?.workspaceId, group ? 'mpim:write' : 'im:write', 'conversations.open', {
      form: { users: users.join(','), return_im: 'false' },
    });
    if (body.ok !== true) {
      if (body.error === 'user_not_found' || body.error === 'user_not_visible' || body.error === 'user_disabled') {
        throw new PerchError(`Slack refused: at least one user cannot be messaged (${String(body.error)})`, 'provider_rejected');
      }
      throw slackFailure(body.error);
    }
    const channel = (body.channel ?? {}) as Raw;
    if (typeof channel.id !== 'string' || !SLACK_CHANNEL_ID.test(channel.id)) throw new PerchError('Slack returned an unexpected conversation id', 'upstream_bad_response');
    const ws = await this.workspace(input.workspaceId);
    return {
      ...this.prov(ws),
      channelId: channel.id,
      type: group ? 'mpim' : 'im',
      users,
      alreadyOpen: body.already_open === true,
    };
  }

  /**
   * Schedules a message (chat.scheduleMessage) as the token's user, idempotent per requestId like send().
   * postAt must be 60 s to 120 days ahead; a replay of a stored requestId is answered from the ledger even
   * after that window has passed.
   */
  async scheduleMessage(p: Principal, req: SlackScheduleRequest) {
    let ws: SlackWorkspace | undefined;
    let channel = '';
    let postAt = 0;
    let threadTs: string | undefined;
    const actor = actorOf(p);
    const view = await sendMessageIdempotently({
      workflow: this.workflow,
      audit: this.audit,
      actor,
      provider: 'slack',
      accountId: req?.workspaceId,
      prepare: async () => {
        await this.guard?.();
        if (typeof req?.workspaceId !== 'string') throw new PerchError('workspaceId is required', 'bad_argument');
        assertSlackCapability(p, req.workspaceId, 'slack_send');
        ws = await this.workspace(req.workspaceId);
        this.assertCanPost(ws);
        channel = channelIdOf(req.channelId);
        if (typeof req.text !== 'string' || !req.text.trim()) throw new PerchError('text must not be empty', 'bad_argument');
        if (req.text.length > MAX_SLACK_TEXT) throw new PerchError(`text exceeds ${MAX_SLACK_TEXT} characters`, 'bad_argument');
        postAt = postAtOf(req.postAt);
        threadTs = req.threadTs === undefined ? undefined : tsOf(req.threadTs, 'threadTs');
        try {
          assertScheduleWindow(postAt, this.now());
        } catch (err) {
          // Outside the window: only a requestId that already has a record may continue (replay or conflict).
          const { key } = await this.workflow.ids(actor, ws.id, validateRequestId(req.requestId));
          if (!(await this.workflow.lookup(key))) throw err;
        }
        const canonical = JSON.stringify(['perch-slack-schedule-v1', ws.id, channel, req.text, postAt, threadTs ?? null]);
        return { accountId: ws.id, requestId: req.requestId, canonical, binding: bindingParts(ws) };
      },
      attempt: (binding) => this.scheduleAttempt(p, req, { channel, postAt, threadTs }, binding),
    });
    const { providerMessageId, ...rest } = view;
    return {
      ...this.prov(ws!),
      ...rest,
      channelId: channel,
      postAt: new Date(postAt * 1000).toISOString(),
      ...(providerMessageId && SLACK_SCHEDULED_ID.test(providerMessageId) ? { scheduledMessageId: providerMessageId } : {}),
    };
  }

  private async scheduleAttempt(p: Principal, req: SlackScheduleRequest, m: { channel: string; postAt: number; threadTs?: string }, binding: string): Promise<MessageSendResult> {
    const notScheduled = (detail: string, reason: MessageSendResult['reason']): MessageSendResult => ({ status: 'rejected', detail: `Not scheduled: ${detail}`, reason });
    try {
      await this.stillAllowed(p, req.workspaceId);
    } catch (err) {
      return notScheduled(err instanceof PerchError ? err.message : 'the request is no longer authorised', 'not_submitted_authorization');
    }
    const current = (await this.store.read()).slack.find((w) => w.id === req.workspaceId);
    if (!current || (await this.workflow.binding(bindingParts(current))) !== binding) {
      return notScheduled('the workspace was removed or reconnected since this requestId was first used', 'not_submitted_account_changed');
    }
    try {
      this.assertCanPost(current);
      assertScheduleWindow(m.postAt, this.now());
    } catch (err) {
      return notScheduled((err as PerchError).message, 'not_submitted_provider_precheck');
    }
    let body: Raw;
    try {
      body = await this.upstream.json<Raw>('slack', {
        method: 'POST',
        path: '/api/chat.scheduleMessage',
        capability: 'slack_send',
        ...slackAuth(current),
        form: { channel: m.channel, text: req.text, post_at: String(m.postAt), ...(m.threadTs ? { thread_ts: m.threadTs } : {}) },
      });
    } catch (err) {
      if (err instanceof UpstreamError && err.status < 500) return notScheduled(`Slack refused the request (HTTP ${err.status})`, 'provider_rejected');
      if (err instanceof PerchError && err.code === 'route_not_allowed') return notScheduled(err.message, 'not_submitted_provider_precheck');
      return { status: 'indeterminate', detail: 'The request to Slack failed after it may have been processed; the outcome is unknown.', reason: 'provider_unknown' };
    }
    if (body.ok !== true) return notScheduled(slackFailure(body.error, current).message, 'provider_rejected');
    const id = typeof body.scheduled_message_id === 'string' && SLACK_SCHEDULED_ID.test(body.scheduled_message_id) ? body.scheduled_message_id : undefined;
    return {
      status: 'accepted',
      detail: id ? 'Scheduled.' : 'Scheduled, but Slack returned no usable scheduled message id; find it with slack_list_scheduled_messages.',
      ...(id ? { providerMessageId: id } : {}),
      reason: 'provider_accepted',
    };
  }

  /** Messages scheduled by this workspace's app and user that Slack has not posted yet (chat.scheduledMessages.list). */
  async listScheduledMessages(p: Principal, input: { workspaceId: string; channelId?: string; pageSize?: number; cursor?: string }) {
    const ws = await this.readable(p, input?.workspaceId);
    const channel = input.channelId === undefined ? undefined : channelIdOf(input.channelId);
    const pageSize = bounded('pageSize', input.pageSize, DEFAULT_SCHEDULED_PAGE_SIZE, MAX_SCHEDULED_PAGE_SIZE);
    const kind = `slack-scheduled:${ws.id}:${channel ?? ''}`;
    const r = await this.call<{ scheduled_messages?: Raw[]; response_metadata?: { next_cursor?: string } }>(newBudget(), ws, 'chat.scheduledMessages.list', {
      channel,
      limit: pageSize,
      cursor: input.cursor ? this.store.openCursor(kind, input.cursor) : undefined,
    });
    const messages = (r.scheduled_messages ?? [])
      .filter((m) => typeof m.id === 'string' && SLACK_SCHEDULED_ID.test(m.id) && (!channel || m.channel_id === channel))
      .slice(0, pageSize)
      .map((m) => ({
        scheduledMessageId: String(m.id),
        ...(typeof m.channel_id === 'string' ? { channelId: m.channel_id } : {}),
        ...(typeof m.post_at === 'number' ? { postAt: new Date(m.post_at * 1000).toISOString() } : {}),
        ...(typeof m.date_created === 'number' ? { createdAt: new Date(m.date_created * 1000).toISOString() } : {}),
        text: typeof m.text === 'string' ? m.text : '',
      }));
    const next = r.response_metadata?.next_cursor;
    return { ...this.prov(ws), ...(channel ? { channelId: channel } : {}), messages, nextCursor: next ? this.store.sealCursor(kind, next) : null, hasMore: Boolean(next) };
  }

  /**
   * Withdraws a scheduled message Slack has not posted yet (chat.deleteScheduledMessage). Posted messages
   * are never deleted: chat.delete stays off the allowlist.
   */
  async cancelScheduledMessage(p: Principal, input: { workspaceId: string; channelId: string; scheduledMessageId: string }) {
    const channel = channelIdOf(input?.channelId);
    const id = input?.scheduledMessageId;
    if (typeof id !== 'string' || !SLACK_SCHEDULED_ID.test(id)) throw new PerchError('scheduledMessageId must be a Slack scheduled message id (Q…) from slack_list_scheduled_messages', 'bad_argument');
    const body = await this.plainWrite(p, input.workspaceId, 'chat:write', 'chat.deleteScheduledMessage', { form: { channel, scheduled_message_id: id } });
    if (body.ok !== true) {
      if (body.error === 'invalid_scheduled_message_id') {
        throw new PerchError('Slack has no pending scheduled message with this id in this conversation: it was already posted, cancelled or never existed (invalid_scheduled_message_id)', 'provider_rejected');
      }
      throw slackFailure(body.error);
    }
    const ws = await this.workspace(input.workspaceId);
    return { ...this.prov(ws), channelId: channel, scheduledMessageId: id, status: 'cancelled' };
  }

  /** Workspaces visible to this principal (never tokens). */
  async listWorkspaces(p: Principal) {
    const data = await this.store.read();
    return data.slack
      .filter((w) => p.slackAccounts === 'all' || p.slackAccounts.has(w.id))
      .map((w) => ({
        workspaceId: w.id,
        label: w.label,
        ...(w.teamName ? { team: w.teamName } : {}),
        ...(w.userName ? { user: w.userName } : {}),
        canSearch: hasScope(w, 'search:read'),
        canPost: hasScope(w, 'chat:write'),
        canReact: hasScope(w, 'reactions:write'),
        canReadFiles: hasScope(w, 'files:read'),
        canUploadFiles: hasScope(w, 'files:write'),
        canOpenDm: hasScope(w, 'im:write'),
        canOpenGroupDm: hasScope(w, 'mpim:write'),
        ...(isSlackSession(w) ? { connection: 'session (unofficial)' } : {}),
        granted: [...p.capabilities].filter((c) => c.startsWith('slack_')).sort(),
        connectedAt: w.createdAt,
      }));
  }
}
