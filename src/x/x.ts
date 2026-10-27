import { actorOf, type AuditLog } from '../audit/audit.js';
import { assertXCapability, currentPrincipal, type Principal } from '../auth/grants.js';
import { PerchError } from '../errors.js';
import type { SendWorkflow } from '../mail/workflow.js';
import { messageSendStatus, sendMessageIdempotently, type MessageSendResult, type MessageSendView } from '../messaging/send.js';
import type { RefreshingTokenProvider } from '../oauth/tokenProvider.js';
import type { CredentialStore, XAccount } from '../store/credentialStore.js';
import { UpstreamError, type Upstream } from '../upstream.js';
import { fetchXMe, revokeXToken } from './oauth.js';
import { assertPostableXText } from './text.js';

/**
 * X posting (docs/X_SPEC.md): reads (x_status) for the read-only operator and x_read; posting only for
 * client grants with x_post for that account, idempotent per requestId on the shared send ledger
 * (src/messaging/send.ts). Only an unambiguous refusal (HTTP 4xx) is "rejected"; a timeout, network error or 5xx is
 * "indeterminate" and never retried. Errors and the audit trail never carry tokens or post texts.
 */
export const X_POST_ID = /^[0-9]{1,25}$/;
export const xPostUrl = (id: string) => `https://x.com/i/status/${id}`;

/** The send record's binding: the account and the X user it posts as (not the rotating refresh token). */
const bindingParts = (a: XAccount) => ['x', a.id, a.userId, a.clientId];

const reconnect = (a: XAccount) => `perch x add --label <label> (updates ${a.id})`;

function refusal(status: number, a: XAccount): string {
  if (status === 401) return `X refused the login (HTTP 401). Reconnect: ${reconnect(a)}`;
  if (status === 402) return 'X refused the post (HTTP 402): the developer account has no API credits left (developer.x.com → Billing)';
  if (status === 403) return 'X refused the post (HTTP 403): e.g. a duplicate of a recent post, app permissions not "Read and write", or the account is restricted';
  if (status === 429) return 'X refused the post (HTTP 429): rate limited or usage cap reached; try later with a new requestId';
  return `X refused the post (HTTP ${status})`;
}

export interface XPostRequest {
  accountId: string;
  text: string;
  requestId: string;
}

export class XService {
  private readonly guard?: () => Promise<void>;

  constructor(
    private readonly store: CredentialStore,
    private readonly upstream: Upstream,
    private readonly workflow: SendWorkflow,
    private readonly audit: AuditLog,
    readonly tokens: RefreshingTokenProvider<XAccount>,
    opts: { guard?: () => Promise<void> } = {},
  ) {
    this.guard = opts.guard;
  }

  private async account(id: unknown): Promise<XAccount> {
    if (typeof id !== 'string') throw new PerchError('accountId is required', 'bad_argument');
    const a = (await this.store.read()).x.find((x) => x.id === id);
    if (!a) throw new PerchError(`Unknown X account: ${id}`, 'unknown_account');
    return a;
  }

  private prov(a: XAccount) {
    return { accountId: a.id, accountLabel: a.label, username: a.username };
  }

  /** Accounts visible to this principal (never tokens or client secrets). */
  async listAccounts(p: Principal) {
    return (await this.store.read()).x
      .filter((a) => p.xAccounts === 'all' || p.xAccounts.has(a.id))
      .map((a) => ({
        accountId: a.id,
        label: a.label,
        username: `@${a.username}`,
        ...(a.name ? { name: a.name } : {}),
        canPost: a.scopes.includes('tweet.write'),
        granted: [...p.capabilities].filter((c) => c.startsWith('x_')).sort(),
        connectedAt: a.createdAt,
      }));
  }

  /** Stored state of one account (no X API call, so nothing is billed). */
  async status(p: Principal, input: { accountId: string }) {
    if (typeof input?.accountId !== 'string') throw new PerchError('accountId is required', 'bad_argument');
    assertXCapability(p, input.accountId, 'x_read');
    const a = await this.account(input.accountId);
    return {
      ...this.prov(a),
      username: `@${a.username}`,
      ...(a.name ? { name: a.name } : {}),
      userId: a.userId,
      profileUrl: `https://x.com/${a.username}`,
      canPost: a.scopes.includes('tweet.write'),
      connected: 'stays connected through refresh tokens (no expiry date); if X revokes the login, a call fails with a reconnect hint',
      connectedAt: a.createdAt,
      updatedAt: a.updatedAt,
    };
  }

  /** Live check for perch status: one GET /2/users/me with a fresh access token. */
  async check(id: string): Promise<void> {
    const a = await this.account(id);
    const token = await this.tokens.getAccessToken(a.id);
    try {
      const me = await fetchXMe(this.upstream, token);
      if (me.userId !== a.userId) throw new PerchError(`The stored login of ${a.id} now belongs to another X user; reconnect: ${reconnect(a)}`, 'account_changed');
    } catch (err) {
      if (err instanceof UpstreamError && err.status === 401) {
        this.tokens.invalidate(a.id);
        throw new PerchError(`X refused the login (HTTP 401). Reconnect: ${reconnect(a)}`, 'grant_invalid');
      }
      throw err;
    }
  }

  /** Posts on the connected account (idempotent per requestId; see src/messaging/send.ts). */
  async post(p: Principal, req: XPostRequest): Promise<Omit<MessageSendView, 'providerMessageId'> & ReturnType<XService['prov']> & { postId?: string; url?: string }> {
    let account: XAccount | undefined;
    const view = await sendMessageIdempotently({
      workflow: this.workflow,
      audit: this.audit,
      actor: actorOf(p),
      provider: 'x',
      accountId: req?.accountId,
      prepare: async () => {
        await this.guard?.();
        if (typeof req?.accountId !== 'string') throw new PerchError('accountId is required', 'bad_argument');
        assertXCapability(p, req.accountId, 'x_post');
        account = await this.account(req.accountId);
        const text = assertPostableXText(req.text);
        const canonical = JSON.stringify(['perch-x-post-v1', account.id, text]);
        return { accountId: account.id, requestId: req.requestId, canonical, binding: bindingParts(account) };
      },
      attempt: (binding) => this.attempt(p, req, binding),
    });
    const id = view.providerMessageId && X_POST_ID.test(view.providerMessageId) ? view.providerMessageId : undefined;
    const { providerMessageId: _ref, ...rest } = view;
    return { ...this.prov(account!), username: `@${account!.username}`, ...rest, ...(id ? { postId: id, url: xPostUrl(id) } : {}) };
  }

  private async attempt(p: Principal, req: XPostRequest, binding: string): Promise<MessageSendResult> {
    const notSent = (detail: string, reason: MessageSendResult['reason']): MessageSendResult => ({ status: 'rejected', detail: `Not posted: ${detail}`, reason });
    try {
      await this.guard?.();
      assertXCapability(await currentPrincipal(this.store, p), req.accountId, 'x_post');
    } catch (err) {
      return notSent(err instanceof PerchError ? err.message : 'the request is no longer authorised', 'not_submitted_authorization');
    }
    const current = (await this.store.read()).x.find((a) => a.id === req.accountId);
    if (!current || (await this.workflow.binding(bindingParts(current))) !== binding) {
      return notSent('the X account was removed or connected to another user since this requestId was first used', 'not_submitted_account_changed');
    }
    if (!current.scopes.includes('tweet.write')) return notSent(`the login lacks tweet.write; reconnect: ${reconnect(current)}`, 'not_submitted_provider_precheck');
    let token: string;
    try {
      token = await this.tokens.getAccessToken(current.id);
    } catch (err) {
      // Nothing was sent to the posting endpoint yet.
      return notSent(err instanceof PerchError ? err.message : 'no access token', 'not_submitted_provider_precheck');
    }
    let body: Buffer;
    try {
      const res = await this.upstream.raw('x', {
        method: 'POST',
        path: '/2/tweets',
        capability: 'x_post',
        headers: { authorization: `Bearer ${token}` },
        json: { text: req.text },
        maxBytes: 64 * 1024,
      });
      body = res.body;
    } catch (err) {
      if (err instanceof UpstreamError && err.status >= 400 && err.status < 500) {
        if (err.status === 401) this.tokens.invalidate(current.id);
        return notSent(refusal(err.status, current), 'provider_rejected');
      }
      if (err instanceof PerchError && err.code === 'route_not_allowed') return notSent(err.message, 'not_submitted_provider_precheck');
      // 5xx, timeout, network error, oversized answer: X may have posted it. Never retried.
      return { status: 'indeterminate', detail: 'The request to X failed after it may have been processed; the outcome is unknown. Check the profile before posting again with a new requestId.', reason: 'provider_unknown' };
    }
    // X answered 2xx: accepted. The id is read from the answer (the echoed text is never returned or stored).
    let id: string | undefined;
    try {
      const v = (JSON.parse(body.toString('utf8')) as { data?: { id?: unknown } }).data?.id;
      id = typeof v === 'string' && X_POST_ID.test(v) ? v : undefined;
    } catch {
      id = undefined;
    }
    return { status: 'accepted', detail: id ? 'Posted.' : 'Posted (X returned no post id).', ...(id ? { providerMessageId: id } : {}), reason: 'provider_accepted' };
  }

  async postStatus(p: Principal, input: { accountId: string; requestId: string }) {
    if (typeof input?.accountId !== 'string') throw new PerchError('accountId is required', 'bad_argument');
    assertXCapability(p, input.accountId, 'x_post');
    const a = await this.account(input.accountId);
    const view = await messageSendStatus(this.workflow, actorOf(p), a.id, input.requestId, bindingParts(a));
    const id = view.providerMessageId && X_POST_ID.test(view.providerMessageId) ? view.providerMessageId : undefined;
    const { providerMessageId: _ref, ...rest } = view;
    return { ...this.prov(a), username: `@${a.username}`, ...rest, ...(id ? { postId: id, url: xPostUrl(id) } : {}) };
  }
}

/** perch x remove: local removal; with revoke also ends the login at X (best effort). */
export async function removeXAccount(store: CredentialStore, upstream: Upstream, id: string, revoke: boolean): Promise<{ revoked: boolean }> {
  const account = (await store.read()).x.find((a) => a.id === id);
  if (!account) throw new PerchError(`Unknown X account: ${id}`, 'unknown_account');
  let revoked = false;
  if (revoke) revoked = await revokeXToken(upstream, account).then(() => true, () => false);
  await store.update((data) => {
    data.x = data.x.filter((a) => a.id !== id);
  });
  return { revoked };
}
