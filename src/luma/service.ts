import { actorOf, type AuditLog } from '../audit/audit.js';
import { assertLumaCapability, currentPrincipal, type Principal } from '../auth/grants.js';
import { PerchError } from '../errors.js';
import { newAccountId, validateLabel } from '../ids.js';
import type { SendWorkflow } from '../mail/workflow.js';
import { messageSendStatus, sendMessageIdempotently, type MessageSendResult, type MessageSendView } from '../messaging/send.js';
import { RefreshingTokenProvider } from '../oauth/tokenProvider.js';
import type { CredentialStore, LumaAccount, LumaToolSnapshot } from '../store/credentialStore.js';
import type { Upstream } from '../upstream.js';
import { LumaMcp, type LumaCallResult, type LumaTool } from './client.js';
import { refreshLumaToken, revokeLumaToken, type LumaGrant } from './oauth.js';
import { callRules, GROUP_CAPABILITY, LUMA_TOOLS, schemaHash, unknownProps } from './policy.js';

/** Live tool lists are re-read at most this often per account. */
const LIVE_TTL_MS = 10 * 60 * 1000;
/** Blast check: at most this many guest pages (50 each) are counted. */
const MAX_COUNT_PAGES = 100;
const BLAST_STATUSES = new Set(['approved', 'pending_approval', 'waitlist', 'invited']);
/** Per account result handed to the MCP client (~1 MB of JSON text). */
const MAX_RESULT_CHARS = 1_000_000;

export interface LumaProvenance {
  accountId: string;
  accountLabel: string;
}

export type ToolState = 'ok' | 'changed' | 'new_fields' | 'missing' | 'not_approved';

export function createLumaTokenProvider(store: CredentialStore, upstream: Upstream): RefreshingTokenProvider<LumaAccount> {
  return new RefreshingTokenProvider<LumaAccount>(store, {
    name: 'Luma',
    list: (d) => d.luma,
    refresh: (a) => refreshLumaToken(upstream, a),
    reconnect: (id) => `\`perch luma remove ${id}\`, then \`perch luma add --label <label>\``,
  });
}

/** Snapshots of the allowlisted live tools that Perch can pass through (no unknown top-level fields). */
export function approveTools(live: readonly LumaTool[]): { approved: LumaToolSnapshot[]; blocked: Array<{ name: string; fields: string[] }> } {
  const approved: LumaToolSnapshot[] = [];
  const blocked: Array<{ name: string; fields: string[] }> = [];
  for (const t of live) {
    if (!LUMA_TOOLS[t.name]) continue;
    const extra = unknownProps(t.name, t.inputSchema);
    if (extra.length) blocked.push({ name: t.name, fields: extra });
    else approved.push({ name: t.name, hash: schemaHash(t.inputSchema), schema: t.inputSchema, ...(t.description ? { description: t.description } : {}) });
  }
  return { approved, blocked };
}

/** Best-effort identity from get_self (Luma's response shape is not documented; only plain strings are kept). */
function identityOf(data: unknown): { userId?: string; name?: string; email?: string } {
  const pick = (o: Record<string, unknown>, keys: string[]) => keys.map((k) => o[k]).find((v): v is string => typeof v === 'string' && v.length > 0 && v.length <= 200);
  const root = data && typeof data === 'object' ? (data as Record<string, unknown>) : {};
  const user = root.user && typeof root.user === 'object' ? (root.user as Record<string, unknown>) : root;
  const userId = pick(user, ['api_id', 'id', 'user_id']);
  const name = pick(user, ['name', 'username']);
  const email = pick(user, ['email']);
  return { ...(userId ? { userId } : {}), ...(name ? { name } : {}), ...(email ? { email } : {}) };
}

/** Stores a freshly authorised Luma account with its approved tool snapshots. */
export async function registerLumaAccount(
  store: CredentialStore,
  mcp: LumaMcp,
  input: { label: string; grant: LumaGrant },
): Promise<{ account: LumaAccount; blocked: Array<{ name: string; fields: string[] }>; missing: string[] }> {
  const label = validateLabel(input.label);
  const self = await mcp.callTool(input.grant.accessToken, 'get_self', {});
  if (self.isError) throw new PerchError('Luma did not return the signed-in account (get_self failed)', 'luma_identity');
  const identity = identityOf(self.data);
  const live = await mcp.listTools(input.grant.accessToken);
  const { approved, blocked } = approveTools(live);
  const missing = Object.keys(LUMA_TOOLS).filter((n) => !live.some((t) => t.name === n));
  const g = input.grant;
  const account = await store.update((data) => {
    if (identity.userId) {
      const dup = data.luma.find((a) => a.userId === identity.userId);
      if (dup) throw new PerchError(`This Luma account is already connected as ${dup.id} ("${dup.label}"). Remove it first to re-authorise.`, 'duplicate_account');
    }
    const now = new Date().toISOString();
    const acc: LumaAccount = {
      id: newAccountId('luma', data.luma.map((a) => a.id)),
      label,
      ...identity,
      clientId: g.clientId,
      registration: g.registration,
      issuer: g.server.issuer,
      tokenEndpoint: g.server.tokenEndpoint,
      ...(g.server.revocationEndpoint ? { revocationEndpoint: g.server.revocationEndpoint } : {}),
      resource: g.server.resource,
      refreshToken: g.refreshToken,
      scopes: g.scopes,
      tools: approved,
      toolsApprovedAt: now,
      createdAt: now,
      updatedAt: now,
    };
    data.luma.push(acc);
    return acc;
  });
  return { account, blocked, missing };
}

export async function removeLumaAccount(store: CredentialStore, upstream: Upstream, id: string, revoke: boolean): Promise<{ revoked: boolean; removedGrants: string[] }> {
  const account = (await store.read()).luma.find((a) => a.id === id);
  if (!account) throw new PerchError(`Unknown Luma account: ${id}`, 'unknown_account');
  let revoked = false;
  if (revoke) revoked = await revokeLumaToken(upstream, account).catch(() => false);
  const removedGrants: string[] = [];
  await store.update((data) => {
    data.luma = data.luma.filter((a) => a.id !== id);
    data.clients = data.clients
      .map((c) => ({ ...c, accountIds: c.accountIds.filter((x) => x !== id) }))
      .filter((c) => {
        const keep = c.full === true || c.readAll === true || c.accountIds.length > 0;
        if (!keep) removedGrants.push(c.id);
        return keep;
      });
  });
  return { revoked, removedGrants };
}

export class LumaService {
  private readonly live = new Map<string, { at: number; tools: Map<string, string> }>();
  /** Approved tools per account (from the store; refreshed before each MCP server is built). */
  private approved: Array<{ accountId: string; tools: LumaToolSnapshot[] }> = [];

  constructor(
    private readonly store: CredentialStore,
    private readonly workflow: SendWorkflow,
    private readonly audit: AuditLog,
    readonly tokens: RefreshingTokenProvider<LumaAccount>,
    readonly mcp: LumaMcp = new LumaMcp(),
    private readonly now: () => number = Date.now,
  ) {}

  /** Re-reads the approved tool schemas (call before building an MCP server). */
  async refresh(): Promise<void> {
    this.approved = (await this.store.read()).luma.map((a) => ({ accountId: a.id, tools: a.tools }));
  }

  /**
   * Tools to expose to `p` (synchronous for createMcpServer): approved for at least one account `p` may use.
   * If those accounts approved different schemas for a tool, it is not offered (one schema must fit all).
   */
  exposed(p: Principal): Array<{ name: string; schema: Record<string, unknown>; description?: string }> {
    const byName = new Map<string, LumaToolSnapshot | null>();
    for (const a of this.approved) {
      if (!(p.lumaAccounts === 'all' || p.lumaAccounts.has(a.accountId))) continue;
      for (const t of a.tools) {
        if (!LUMA_TOOLS[t.name]) continue;
        const seen = byName.get(t.name);
        if (seen === undefined) byName.set(t.name, t);
        else if (seen !== null && seen.hash !== t.hash) byName.set(t.name, null);
      }
    }
    return [...byName.values()].filter((t): t is LumaToolSnapshot => t !== null).map((t) => ({ name: t.name, schema: t.schema, ...(t.description ? { description: t.description } : {}) }));
  }

  private async account(id: unknown): Promise<LumaAccount> {
    const a = typeof id === 'string' ? (await this.store.read()).luma.find((x) => x.id === id) : undefined;
    if (!a) throw new PerchError(`Unknown Luma account: ${String(id)}`, 'unknown_account');
    return a;
  }

  private prov(a: LumaAccount): LumaProvenance {
    return { accountId: a.id, accountLabel: a.label };
  }

  /** Runs `fn` with an access token; a 401 from Luma drops the cached token and retries once (nothing was processed). */
  private async withToken<T>(a: LumaAccount, fn: (token: string) => Promise<T>): Promise<T> {
    try {
      return await fn(await this.tokens.getAccessToken(a.id));
    } catch (err) {
      if (!(err instanceof PerchError && err.code === 'luma_unauthorized')) throw err;
      this.tokens.invalidate(a.id);
      return fn(await this.tokens.getAccessToken(a.id));
    }
  }

  private async liveHashes(a: LumaAccount, token: string, force = false): Promise<Map<string, string>> {
    const hit = this.live.get(a.id);
    if (!force && hit && this.now() - hit.at < LIVE_TTL_MS) return hit.tools;
    const tools = new Map<string, string>();
    for (const t of await this.mcp.listTools(token)) if (LUMA_TOOLS[t.name]) tools.set(t.name, unknownProps(t.name, t.inputSchema).length ? 'new_fields' : schemaHash(t.inputSchema));
    this.live.set(a.id, { at: this.now(), tools });
    return tools;
  }

  /** The tool's live schema must still equal the approved one (trust on first use). */
  private async assertUsable(a: LumaAccount, name: string, token: string, fresh = false): Promise<void> {
    const approved = a.tools.find((t) => t.name === name);
    if (!approved) throw new PerchError(`Luma tool ${name} is not approved for ${a.id} (perch luma tools ${a.id})`, 'luma_tool_blocked');
    const live = (await this.liveHashes(a, token, fresh)).get(name);
    if (live !== approved.hash) {
      throw new PerchError(`Luma changed or removed the tool ${name}; it is blocked until the operator reviews it (perch luma tools ${a.id} --accept)`, 'luma_tool_changed');
    }
  }

  /** Splits Perch's own fields from the Luma arguments; only fields Perch knows for the tool are passed on. */
  private split(name: string, raw: Record<string, unknown>): { lumaArgs: Record<string, unknown> } {
    const policy = LUMA_TOOLS[name]!;
    const lumaArgs: Record<string, unknown> = {};
    for (const k of policy.props) if (raw[k] !== undefined) lumaArgs[k] = raw[k];
    return { lumaArgs };
  }

  async read(p: Principal, name: string, raw: Record<string, unknown>) {
    const policy = LUMA_TOOLS[name];
    if (!policy || policy.group !== 'read') throw new PerchError(`Unknown Luma read tool: ${name}`, 'bad_argument');
    const { lumaArgs } = this.split(name, raw);
    const accountId = raw.accountId;
    const one = async (a: LumaAccount) =>
      this.withToken(a, async (token) => {
        await this.assertUsable(a, name, token);
        return this.mcp.callTool(token, name, lumaArgs);
      });
    const shape = (a: LumaAccount, r: LumaCallResult) => {
      if (JSON.stringify(r.data ?? null).length > MAX_RESULT_CHARS) throw new PerchError('The Luma result is too large; narrow the request (limit, filters)', 'response_too_large');
      return { ...this.prov(a), ...(r.isError ? { isError: true } : {}), result: r.data };
    };
    if (accountId !== undefined) {
      if (typeof accountId !== 'string') throw new PerchError('accountId must be a string', 'bad_argument');
      assertLumaCapability(p, accountId, 'luma_read');
      const a = await this.account(accountId);
      return shape(a, await one(a));
    }
    if (!p.capabilities.has('luma_read')) throw new PerchError('Capability "luma_read" is not granted to this client', 'capability_denied');
    if (lumaArgs.cursor !== undefined) throw new PerchError('A cursor belongs to one Luma account: pass accountId with it', 'bad_argument');
    const accounts = (await this.store.read()).luma.filter((a) => (p.lumaAccounts === 'all' || p.lumaAccounts.has(a.id)) && a.tools.some((t) => t.name === name));
    if (!accounts.length) throw new PerchError('No Luma account offers this tool (perch luma list)', 'unknown_account');
    if (accounts.length === 1) return shape(accounts[0]!, await one(accounts[0]!));
    const results = await Promise.all(
      accounts.map(async (a) => {
        try {
          return shape(a, await one(a));
        } catch (err) {
          return { ...this.prov(a), error: err instanceof PerchError ? err.message : 'Luma request failed' };
        }
      }),
    );
    return { results, partial: results.some((r) => 'error' in r) };
  }

  private async stillAllowed(p: Principal, accountId: string, caps: string[]): Promise<void> {
    const cur = await currentPrincipal(this.store, p);
    for (const c of caps) assertLumaCapability(cur, accountId, c as Parameters<typeof assertLumaCapability>[2]);
  }

  /** Guests a blast with these recipient groups reaches (counted via list_guests, Spec §6 Gegenprobe). */
  private async countRecipients(a: LumaAccount, token: string, eventId: string, groups: unknown): Promise<number> {
    // The counting tool is pinned like any other (a renamed filter must not silently count everyone).
    await this.assertUsable(a, 'list_guests', token, true);
    const statuses = (groups as Array<{ status: string }>).map((g) => g.status);
    const seen = new Set<string>();
    let count = 0;
    for (const status of new Set(statuses)) {
      let cursor: string | undefined;
      for (let page = 0; page < MAX_COUNT_PAGES; page++) {
        const r = await this.mcp.callTool(token, 'list_guests', { event_id: eventId, approval_status: status, limit: 50, ...(cursor ? { cursor } : {}) });
        if (r.isError || !r.data || typeof r.data !== 'object') throw new PerchError('Could not count the guests', 'luma_count_failed');
        const d = r.data as Record<string, unknown>;
        const entries = [d.entries, d.guests, d.data, d.items].find(Array.isArray) as unknown[] | undefined;
        if (!entries) throw new PerchError('Could not count the guests (unknown list format)', 'luma_count_failed');
        for (const e of entries) {
          const g = e && typeof e === 'object' ? (e as Record<string, unknown>) : {};
          const inner = g.guest && typeof g.guest === 'object' ? (g.guest as Record<string, unknown>) : g;
          const id = [inner.api_id, inner.id, inner.email, inner.user_email].find((v): v is string => typeof v === 'string');
          if (id === undefined) count++;
          else if (!seen.has(id)) {
            seen.add(id);
            count++;
          }
        }
        const next = typeof d.next_cursor === 'string' && d.next_cursor ? d.next_cursor : undefined;
        if (d.has_more === false || (d.has_more === undefined && !next)) break;
        if (!next) throw new PerchError('Could not count the guests (more pages, but no cursor)', 'luma_count_failed');
        cursor = next;
        if (page === MAX_COUNT_PAGES - 1) throw new PerchError('Too many guests to verify the recipient count', 'luma_count_failed');
      }
    }
    return count;
  }

  /** Writes: idempotent per requestId (src/messaging/send.ts), one attempt, outcome accepted/rejected/indeterminate. */
  async write(p: Principal, name: string, raw: Record<string, unknown>): Promise<Omit<MessageSendView, 'providerMessageId'> & Partial<LumaProvenance> & { lumaTool: string; result?: unknown; lumaError?: string }> {
    const policy = LUMA_TOOLS[name];
    if (!policy || policy.group === 'read') throw new PerchError(`Unknown Luma write tool: ${name}`, 'bad_argument');
    const cap = GROUP_CAPABILITY[policy.group];
    const { lumaArgs } = this.split(name, raw);
    let account: LumaAccount | undefined;
    let caps: string[] = [cap];
    let result: unknown;
    let lumaError: string | undefined;
    const view = await sendMessageIdempotently({
      workflow: this.workflow,
      audit: this.audit,
      actor: actorOf(p),
      provider: 'luma',
      accountId: raw.accountId,
      prepare: async () => {
        if (typeof raw.accountId !== 'string') throw new PerchError('accountId is required for Luma writes', 'bad_argument');
        assertLumaCapability(p, raw.accountId, cap);
        const rule = callRules(name, lumaArgs);
        if (rule.refuse) throw new PerchError(rule.refuse, 'bad_argument');
        if (rule.alsoNeeds) {
          assertLumaCapability(p, raw.accountId, rule.alsoNeeds);
          caps = [cap, rule.alsoNeeds];
        }
        if (name === 'create_blast') this.checkBlastInput(raw, lumaArgs);
        account = await this.account(raw.accountId);
        if (!account.tools.some((t) => t.name === name)) throw new PerchError(`Luma tool ${name} is not approved for ${account.id} (perch luma tools ${account.id})`, 'luma_tool_blocked');
        const canonical = JSON.stringify(['perch-luma-write-v1', account.id, name, lumaArgs, name === 'create_blast' ? raw.confirmRecipientCount : null]);
        return { accountId: account.id, requestId: raw.requestId, canonical, binding: [account.id, account.userId ?? '', account.clientId] };
      },
      attempt: async (binding) => {
        const r = await this.attempt(p, name, raw, lumaArgs, caps, binding);
        result = r.result;
        lumaError = r.lumaError;
        return r.outcome;
      },
    });
    const { providerMessageId: _unused, ...rest } = view;
    return { ...(account ? this.prov(account) : {}), lumaTool: name, ...rest, ...(result !== undefined ? { result } : {}), ...(lumaError !== undefined ? { lumaError } : {}) };
  }

  private checkBlastInput(raw: Record<string, unknown>, lumaArgs: Record<string, unknown>): void {
    const n = raw.confirmRecipientCount;
    if (typeof n !== 'number' || !Number.isInteger(n) || n < 0) throw new PerchError('confirmRecipientCount is required: the number of guests the blast should reach', 'bad_argument');
    const groups = lumaArgs.recipient_groups;
    // Explicit audience only: Luma's default audience is not something Perch can verify.
    if (!Array.isArray(groups) || groups.length === 0) throw new PerchError('recipient_groups is required for blasts through Perch, e.g. [{"status": "approved"}]', 'bad_argument');
    for (const g of groups as Array<Record<string, unknown>>) {
      if (!g || typeof g !== 'object' || Object.keys(g).some((k) => k !== 'status' && k !== 'ticket_type_id')) throw new PerchError('Each recipient group may only name status (and no ticket filter)', 'bad_argument');
      if (typeof g.status !== 'string' || !BLAST_STATUSES.has(g.status)) {
        throw new PerchError('Perch can verify blasts to approved, pending_approval, waitlist or invited guests only', 'bad_argument');
      }
      if (g.ticket_type_id !== undefined && g.ticket_type_id !== null) throw new PerchError('Perch cannot verify blasts filtered by ticket type; send those in Luma itself', 'bad_argument');
    }
    if (typeof lumaArgs.event_id !== 'string') throw new PerchError('event_id is required', 'bad_argument');
  }

  private async attempt(
    p: Principal,
    name: string,
    raw: Record<string, unknown>,
    lumaArgs: Record<string, unknown>,
    caps: string[],
    binding: string,
  ): Promise<{ outcome: MessageSendResult; result?: unknown; lumaError?: string }> {
    const notSent = (detail: string, reason: MessageSendResult['reason']) => ({ outcome: { status: 'rejected' as const, detail: `Not done: ${detail}`, reason } });
    const accountId = raw.accountId as string;
    try {
      await this.stillAllowed(p, accountId, caps);
    } catch (err) {
      return notSent(err instanceof PerchError ? err.message : 'no longer authorised', 'not_submitted_authorization');
    }
    const a = (await this.store.read()).luma.find((x) => x.id === accountId);
    if (!a || (await this.workflow.binding([a.id, a.userId ?? '', a.clientId])) !== binding) {
      return notSent('the Luma account was removed or reconnected since this requestId was first used', 'not_submitted_account_changed');
    }
    let token: string;
    try {
      token = await this.tokens.getAccessToken(a.id);
      await this.assertUsable(a, name, token, true);
      if (name === 'create_blast') {
        const actual = await this.countRecipients(a, token, lumaArgs.event_id as string, lumaArgs.recipient_groups);
        if (actual !== raw.confirmRecipientCount) {
          return notSent(`the blast would reach ${actual} guest(s), not ${String(raw.confirmRecipientCount)} (confirmRecipientCount); check the audience`, 'not_submitted_provider_precheck');
        }
      }
    } catch (err) {
      if (err instanceof PerchError && err.code === 'luma_unauthorized') this.tokens.invalidate(a.id);
      return notSent(err instanceof PerchError ? err.message : 'precheck failed', 'not_submitted_provider_precheck');
    }
    let r: LumaCallResult;
    try {
      r = await this.mcp.callTool(token, name, lumaArgs);
    } catch (err) {
      if (err instanceof PerchError && err.code === 'luma_unauthorized') {
        this.tokens.invalidate(a.id);
        return notSent('Luma rejected the access token (nothing was processed); try again with a new requestId', 'provider_rejected');
      }
      if (err instanceof PerchError && err.code === 'luma_not_sent') return notSent('the Luma MCP server could not be reached; nothing was sent', 'not_submitted_provider_precheck');
      return { outcome: { status: 'indeterminate', detail: 'The request to Luma failed after it may have been processed; the outcome is unknown. Check in Luma.', reason: 'provider_unknown' } };
    }
    if (r.isError) {
      // Luma's own error text (untrusted) goes back to the caller as a separate field, never into the ledger.
      const text = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
      return { outcome: { status: 'rejected', detail: 'Luma refused it (see lumaError).', reason: 'provider_rejected' }, lumaError: text.slice(0, 300) };
    }
    return { outcome: { status: 'accepted', detail: 'Done in Luma.', reason: 'provider_accepted' }, result: r.data };
  }

  /** Outcome of one of this client's earlier Luma writes (same account and requestId), without doing anything. */
  async writeStatus(p: Principal, input: { accountId?: unknown; requestId?: unknown }) {
    if (typeof input?.accountId !== 'string') throw new PerchError('accountId is required', 'bad_argument');
    if (!['luma_events', 'luma_guests', 'luma_blast'].some((c) => p.capabilities.has(c as never))) throw new PerchError('This client has no Luma write capability', 'capability_denied');
    const a = await this.account(input.accountId);
    if (!(p.lumaAccounts === 'all' || p.lumaAccounts.has(a.id))) throw new PerchError(`Luma account ${a.id} is not granted to this client`, 'capability_denied');
    const view = await messageSendStatus(this.workflow, actorOf(p), a.id, input.requestId, [a.id, a.userId ?? '', a.clientId]);
    const { providerMessageId: _unused, ...rest } = view;
    return { ...this.prov(a), ...rest };
  }

  /** Accounts visible to this principal (never tokens). */
  async listAccounts(p: Principal) {
    return (await this.store.read()).luma
      .filter((a) => p.lumaAccounts === 'all' || p.lumaAccounts.has(a.id))
      .map((a) => ({
        accountId: a.id,
        label: a.label,
        ...(a.name ? { name: a.name } : {}),
        ...(a.email ? { email: a.email } : {}),
        tools: a.tools.map((t) => t.name).sort(),
        granted: [...p.capabilities].filter((c) => c.startsWith('luma_')).sort(),
        connectedAt: a.createdAt,
      }));
  }

  /** perch luma tools: state of every allowlisted tool for one account (live vs approved). */
  async toolStates(id: string): Promise<Array<{ name: string; group: string; state: ToolState }>> {
    const a = await this.account(id);
    const live = await this.withToken(a, (t) => this.liveHashes(a, t, true));
    return Object.entries(LUMA_TOOLS).map(([name, pol]) => {
      const approved = a.tools.find((t) => t.name === name);
      const l = live.get(name);
      const state: ToolState = l === undefined ? 'missing' : l === 'new_fields' ? 'new_fields' : !approved ? 'not_approved' : approved.hash === l ? 'ok' : 'changed';
      return { name, group: pol.group, state };
    });
  }

  /** perch luma tools --accept: approves the current live schemas (tools with unknown fields stay blocked). */
  async acceptTools(id: string): Promise<{ approved: string[]; blocked: Array<{ name: string; fields: string[] }> }> {
    const a = await this.account(id);
    const live = await this.withToken(a, (t) => this.mcp.listTools(t));
    const { approved, blocked } = approveTools(live);
    await this.store.update((d) => {
      const acc = d.luma.find((x) => x.id === id);
      if (!acc) throw new PerchError(`Unknown Luma account: ${id}`, 'unknown_account');
      acc.tools = approved;
      acc.toolsApprovedAt = new Date().toISOString();
      acc.updatedAt = acc.toolsApprovedAt;
    });
    this.live.delete(id);
    await this.refresh();
    return { approved: approved.map((t) => t.name), blocked };
  }

  /** Live check for perch status (get_self). */
  async check(id: string): Promise<void> {
    const a = await this.account(id);
    const r = await this.withToken(a, (t) => this.mcp.callTool(t, 'get_self', {}));
    if (r.isError) throw new PerchError('Luma answered get_self with an error', 'luma_failed');
    const blocked = (await this.toolStates(id)).filter((t) => t.state === 'changed' || t.state === 'new_fields' || (t.state === 'missing' && a.tools.some((x) => x.name === t.name)));
    if (blocked.length) throw new PerchError(`Luma changed ${blocked.length} approved tool(s) (${blocked.map((t) => t.name).join(', ')}); they are blocked: perch luma tools ${id}`, 'luma_tool_changed');
  }
}
