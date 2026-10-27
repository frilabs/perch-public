import { actorOf, auditCode, AuditLog, outcomeOf, safeAccountId } from '../audit/audit.js';
import { assertMailCapability, currentPrincipal, type Principal } from '../auth/grants.js';
import { PerchError } from '../errors.js';
import { fanOut, type FanOutResult } from '../fanout.js';
import type { Capability, CredentialStore, GmailAccount, ImapAccount, StoreData } from '../store/credentialStore.js';
import {
  composeForProvider,
  isMessageId,
  MAX_ATTACHMENT_TOTAL_BYTES,
  MAX_ATTACHMENTS,
  MAX_BODY_BYTES,
  validateOutgoing,
  type ComposeAttachment,
  type ComposeInput,
} from './compose.js';
import {
  addressKeys,
  deriveReplyRecipients,
  forwardBody,
  forwardSubject,
  htmlWithQuote,
  mergeRecipients,
  quoteReply,
  replySubject,
  safeContentType,
  safeFilename,
  threadingFor,
} from './replyForward.js';
import {
  ACCEPTED_NOTE,
  DEFAULT_MAIL_MAX_BYTES,
  DEFAULT_MAIL_PAGE_SIZE,
  HARD_MAIL_MAX_BYTES,
  MAX_MAIL_PAGE_SIZE,
  type MailDraftSummary,
  type MailFolder,
  type MailMessage,
  type MailProvider,
  type MailProviderKind,
  type MailSummary,
  type MoveTarget,
  type OrganizeResult,
  type ReplyContext,
  type SendResult,
} from './types.js';
import {
  accountChanged,
  canonicalDerivedPayload,
  canonicalSendDraftPayload,
  canonicalSendPayload,
  SendWorkflow,
  validateRequestId,
  viewOf,
  type SendView,
} from './workflow.js';
import { MailWorkflowLedger, newOperationId, type SendReason } from './workflowLedger.js';
import { sessionMailAccounts, type SessionMailAccount } from '../microsoft/session/model.js';

export interface MailProviders {
  gmail: MailProvider<GmailAccount>;
  imap: MailProvider<ImapAccount>;
  /** Optional to keep existing deployments and in-memory providers independent of browser sessions. */
  microsoftSession?: MailProvider<SessionMailAccount>;
}

type Entry =
  | { kind: 'gmail'; account: GmailAccount }
  | { kind: 'microsoftSession'; account: SessionMailAccount }
  | { kind: 'imap'; account: ImapAccount };

export interface MailProvenance {
  accountId: string;
  accountLabel: string;
  provider: MailProviderKind;
}

export interface OutgoingRequest extends Omit<ComposeInput, 'subject'> {
  accountId: string;
  /** Optional when replying (defaults to "Re: <original subject>"). */
  subject?: string;
  /** Perch message id (same account) being answered; sets In-Reply-To/References/thread. */
  replyToMessageId?: string;
}

/** A send always carries the caller's idempotency key (see src/mail/workflow.ts). */
export interface SendRequest extends OutgoingRequest {
  requestId: string;
}

/** mail_reply / mail_forward input (docs/MAIL_CALENDAR_SLACK_SPEC.md §1). Recipients come from the original's headers. */
export interface DerivedRequest {
  accountId: string;
  /** Perch message id (same account) of the original. */
  messageId: string;
  /** Plain-text body written by the caller; the quote / forward block is appended by Perch. */
  text?: string;
  html?: string;
  /** Forward: required recipients. Reply: optional additional recipients. */
  to?: string[];
  cc?: string[];
  bcc?: string[];
  /** Reply only: also answer the original To and Cc (without the own address). */
  replyAll?: boolean;
  /** Forward only: attach the original's (non-inline) attachments; default true. */
  includeAttachments?: boolean;
  /** false (default): create a draft (capability "draft"); true: send now ("send" and requestId). */
  send?: boolean;
  requestId?: string;
}

export type DerivedKind = 'reply' | 'forward';

/** What Perch derived from the original: returned so the user can check the recipients. */
export interface DerivedSummary {
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  /** Original header entries that were not one plain address and were left out. */
  skippedRecipients?: number;
  /** Forward: attachments taken over, and inline parts (embedded images of the HTML) that were not. */
  attachments?: number;
  omittedInlineAttachments?: number;
}

const FORWARD_ATTACHMENT_HINT = 'Forward without them (includeAttachments: false) or send them separately.';

export type SendOutcome = SendResult &
  MailProvenance & { from: string; operationId: string; requestState: SendView['requestState']; replayed: boolean; manualResolution?: 'sent' | 'not_sent' };

const FINALIZE_FAILED_NOTE =
  'The provider was called, but its outcome could not be recorded in the mail workflow ledger, so it must be treated as unknown. ' +
  'Perch will not send this requestId again. Check the Sent folder before sending with a new requestId.';
const USED_NOTE = ' This requestId is now used; to try again, use a new requestId.';

/** "accepted" always carries the fixed not-delivered note; a rejection says the key is used up. */
function liveDetail(r: SendResult): string {
  if (r.status === 'accepted') return r.detail.startsWith(ACCEPTED_NOTE) ? r.detail : ACCEPTED_NOTE;
  return r.status === 'rejected' ? r.detail + USED_NOTE : r.detail;
}

const RECONNECT: Record<MailProviderKind, (id: string, opt: string) => string> = {
  gmail: (id, opt) => `perch gmail remove ${id}, then perch gmail add --label <label> ${opt}`,
  microsoft: () => 'The standalone Microsoft OAuth connector is retired; reconnect with perch microsoft add --label NAME',
  microsoftSession: () => 'perch microsoft sessions, then perch microsoft reconnect GROUP_ID; enable mail writes for that session',
  imap: (id, opt) => `perch imap remove ${id}, then perch imap add ... ${opt}`,
};

/**
 * Identity of the sender account that a send record is bound to. Excludes rotating OAuth refresh
 * tokens; includes everything that changes when the account is removed and re-added or re-credentialed.
 */
function bindingParts(e: Entry): string[] {
  const base = [e.kind, e.account.id, e.account.email.toLowerCase(), e.account.createdAt];
  switch (e.kind) {
    case 'gmail':
      // Members of a Google account group are bound to their group (the group holds the OAuth client).
      return [...base, e.account.clientId ?? `group:${e.account.groupId ?? ''}`];
    case 'microsoftSession': {
      const a = e.account;
      return [...base, a.groupId, a.revision, a.identity.tenantId, a.identity.objectId, a.identity.mailboxId ?? '', a.identity.kind];
    }
    case 'imap': {
      const a = e.account;
      return [...base, a.username, a.password, a.imap.host, String(a.imap.port), a.smtp.host, String(a.smtp.port), a.smtp.security];
    }
  }
}

function sameBinding(a: Entry, b: Entry): boolean {
  const x = bindingParts(a);
  const y = bindingParts(b);
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

function entries(data: StoreData): Entry[] {
  return [
    ...data.gmail.map((account) => ({ kind: 'gmail' as const, account })),
    ...data.imap.map((account) => ({ kind: 'imap' as const, account })),
    ...sessionMailAccounts(data.microsoftSessions ?? []).map((account) => ({ kind: 'microsoftSession' as const, account })),
  ];
}

/** Ephemeral worker authorization context; never stored or included in public provenance. */
function withCaller(entry: Entry, principal: Principal): Entry {
  if (entry.kind !== 'microsoftSession') return entry;
  return { ...entry, account: { ...entry.account, caller: principal.kind === 'operator_readonly' ? { kind: 'operator_readonly' } : { kind: 'client', clientId: principal.clientId, tokenSha256: principal.tokenSha256 } } };
}

/** Worker errors can arrive after Microsoft accepted a write; only explicit pre-submit denials are certain. */
function sessionMayHaveWritten(entry: Entry, error: PerchError): boolean {
  return entry.kind === 'microsoftSession' && !new Set(['capability_denied', 'grant_revoked', 'account_changed', 'unknown_account', 'provider_scope_missing', 'bad_argument', 'identity_mismatch']).has(error.code);
}

function bounded(name: string, value: number | undefined, def: number, max: number): number {
  const n = value ?? def;
  if (!Number.isInteger(n) || n < 1 || n > max) throw new PerchError(`${name} must be between 1 and ${max}`, 'bad_argument');
  return n;
}

const provenance = (e: Entry): MailProvenance => ({ accountId: e.account.id, accountLabel: e.account.label, provider: e.kind });

export interface MailServiceOptions {
  /**
   * Optional service guard; runs on every call and again right before a provider write.
   */
  guard?: () => Promise<void>;
}

/**
 * Provider-neutral mail operations. Authorization happens here, before any provider call:
 * 0. the namespace guard runs and the principal is re-resolved from the store (a passed-in principal is
 * never trusted: a revoked, replaced or narrowed client grant fails closed on direct calls too),
 * 1. the principal must hold the capability for that account (client grant; replying also needs
 * "read"), 2. the account must exist, 3. the stored provider grant must allow it (OAuth scopes /
 * IMAP opt-in).
 * The sender is always the explicitly chosen account; adapters never pick a From address.
 */
export class MailService {
  private readonly workflow: SendWorkflow;
  private readonly audit: AuditLog;

  /** `ledger` defaults to this namespace's mail workflow ledger; every send goes through it. */
  constructor(
    private readonly store: CredentialStore,
    private readonly providers: MailProviders,
    ledger: MailWorkflowLedger = new MailWorkflowLedger(store),
    private readonly options: MailServiceOptions = {},
  ) {
    this.workflow = new SendWorkflow(ledger);
    this.audit = new AuditLog(ledger);
  }

  private provider(e: Entry): MailProvider<unknown> {
    const provider = this.providers[e.kind];
    if (!provider) throw new PerchError('Microsoft session mail runtime is not configured.', 'service_unavailable');
    return provider as MailProvider<unknown>;
  }

  /** Namespace guard, then the client grant as it is stored now. Every public method starts here. */
  private async caller(principal: Principal): Promise<Principal> {
    await this.options.guard?.();
    return currentPrincipal(this.store, principal);
  }

  /**
   * Body-free audit of one direct operation (the service is the audit boundary, also outside MCP; the MCP
   * runner does not record mail tools again). After the namespace guard (a failing guard is not recorded:
   * that namespace cannot be trusted to be written to) the grant is re-resolved from the store; a denial is
   * recorded. A draft write records its "attempt" durably BEFORE any provider I/O (missing, corrupt, full or
   * locked ledger: nothing is written). The outcome is recorded with fixed fields only (type, actor, Perch
   * account id/provider, outcome, Perch error code); never ids of messages/attachments/drafts, queries,
   * addresses or provider text. A read result is withheld if its record cannot be written.
   */
  private async audited<T>(type: string, stale: Principal, accountId: unknown, fn: (p: Principal) => Promise<T>, write = false): Promise<T> {
    await this.options.guard?.();
    let p: Principal;
    try {
      p = await currentPrincipal(this.store, stale);
    } catch (err) {
      await this.audit.record({ type, actor: actorOf(stale), accountId, outcome: outcomeOf(err), code: auditCode(err) });
      throw err;
    }
    const base = { type, actor: actorOf(p), accountId, operationId: newOperationId() };
    if (write) await this.audit.record({ ...base, outcome: 'attempt' });
    let result: T;
    try {
      result = await fn(p);
    } catch (err) {
      await this.audit.record({ ...base, outcome: outcomeOf(err), code: auditCode(err) });
      throw err;
    }
    try {
      await this.audit.record({ ...base, outcome: 'ok' });
    } catch (err) {
      // A completed write cannot be undone (its attempt record exists): report it. A read is withheld.
      if (write) process.stderr.write('perch: the outcome of a completed mail write could not be added to the audit ledger\n');
      else throw new PerchError(`The result was withheld because its audit record could not be written (${auditCode(err)})`, 'audit_unavailable');
    }
    return result;
  }

  /**
   * Re-validates a write right before its provider call (after awaits such as the reply lookup): namespace,
   * current grant, capability (+ read for replies) and the account as stored now.
   */
  private async stillAllowed(principal: Principal, req: OutgoingRequest, cap: 'draft' | 'send'): Promise<Entry> {
    const p = await this.caller(principal);
    const e = await this.authorised(p, req.accountId, cap);
    this.assertReplyReadable(p, req);
    return e;
  }

  private async entry(accountId: string, principal?: Principal): Promise<Entry> {
    const e = entries(await this.store.read()).find((x) => x.account.id === accountId);
    if (!e) {
      const message = accountId.startsWith('microsoft-')
        ? 'The standalone Microsoft OAuth connector is retired; reconnect with perch microsoft add --label NAME.'
        : `Unknown mail account: ${accountId}`;
      throw new PerchError(message, 'unknown_account');
    }
    return principal ? withCaller(e, principal) : e;
  }

  /**
   * The capability check comes first, so a client cannot tell an ungranted account id from a
   * nonexistent one. The read-only operator may read every account and still gets unknown_account.
   */
  private async authorised(principal: Principal, accountId: string, cap: Capability): Promise<Entry> {
    assertMailCapability(principal, accountId, cap);
    return this.entry(accountId, principal);
  }

  /** A client sees only the accounts named in its grant; the read-only operator sees all. */
  async listAccounts(stale: Principal) {
    return this.audited('mail_list_accounts', stale, undefined, async (principal) => this.visibleAccounts(principal));
  }

  private async visibleAccounts(principal: Principal) {
    const visible = (id: string) => principal.mailAccounts === 'all' || principal.mailAccounts.has(id);
    return entries(await this.store.read()).filter((e) => visible(e.account.id)).map((e) => withCaller(e, principal)).map((e) => {
      return {
        ...provenance(e),
        email: e.account.email,
        providerCapabilities: this.providerCaps(e),
        granted: [...principal.capabilities].filter((c) => c === 'read' || c === 'draft' || c === 'send' || c === 'modify').sort(),
      };
    });
  }

  async search(
    principal: Principal,
    opts: { query?: string; accountId?: string; folder?: string; pageSize?: number; cursor?: string },
  ): Promise<FanOutResult<MailSummary & { provider: MailProviderKind; accountId: string; accountLabel: string }>> {
    return this.audited('mail_search', principal, opts?.accountId, (p) => this.searchAs(p, opts));
  }

  private async searchAs(
    principal: Principal,
    opts: { query?: string; accountId?: string; folder?: string; pageSize?: number; cursor?: string },
  ): Promise<FanOutResult<MailSummary & { provider: MailProviderKind; accountId: string; accountLabel: string }>> {
    const pageSize = bounded('pageSize', opts.pageSize, DEFAULT_MAIL_PAGE_SIZE, MAX_MAIL_PAGE_SIZE);
    let targets: Entry[];
    if (opts.accountId) {
      targets = [await this.authorised(principal, opts.accountId, 'read')];
    } else {
      targets = entries(await this.store.read()).filter(
        (e) => principal.capabilities.has('read') && (principal.mailAccounts === 'all' || principal.mailAccounts.has(e.account.id)),
      ).map((e) => withCaller(e, principal));
    }
    const byId = new Map(targets.map((e) => [e.account.id, e]));
    return fanOut({
      kind: 'mail',
      queryKey: { q: opts.query ?? '', f: opts.folder ?? '', s: pageSize, a: opts.accountId ?? '*' },
      sources: targets.map((e) => ({ id: e.account.id, label: e.account.label })),
      seal: this.store,
      ...(opts.cursor ? { cursor: opts.cursor } : {}),
      fetchPage: async (source, cursor) => {
        const e = byId.get(source.id)!;
        const page = await this.provider(e).search(
          e.account,
          { ...(opts.query ? { query: opts.query } : {}), ...(opts.folder ? { folder: opts.folder } : {}), pageSize },
          cursor,
        );
        return { ...page, items: page.items.map((i) => ({ ...i, provider: e.kind })) };
      },
    });
  }

  async read(principal: Principal, opts: { accountId: string; messageId: string; maxBytes?: number }) {
    return this.audited('mail_read_message', principal, opts?.accountId, async (p) => {
      const e = await this.authorised(p, opts.accountId, 'read');
      const maxBytes = bounded('maxBytes', opts.maxBytes, DEFAULT_MAIL_MAX_BYTES, HARD_MAIL_MAX_BYTES);
      return { ...provenance(e), ...(await this.provider(e).read(e.account, opts.messageId, { maxBytes })) };
    });
  }

  async getAttachment(principal: Principal, opts: { accountId: string; messageId: string; attachmentId: string; maxBytes?: number }) {
    return this.audited('mail_get_attachment', principal, opts?.accountId, async (p) => {
      const e = await this.authorised(p, opts.accountId, 'read');
      const maxBytes = bounded('maxBytes', opts.maxBytes, DEFAULT_MAIL_MAX_BYTES, HARD_MAIL_MAX_BYTES);
      return { ...provenance(e), ...(await this.provider(e).getAttachment(e.account, opts.messageId, opts.attachmentId, { maxBytes })) };
    });
  }

  /** Fetches what a reply needs from the original (provider read I/O). */
  private async replyContext(e: Entry, req: OutgoingRequest): Promise<ReplyContext | undefined> {
    return req.replyToMessageId ? this.provider(e).replyContext(e.account, req.replyToMessageId) : undefined;
  }

  /**
   * Validates input, applies reply threading and builds the MIME message. `mode` 'api' keeps the
   * Bcc header (API sends and every stored draft need it); 'smtp' drops it (Bcc is envelope-only).
   */
  private async compose(e: Entry, req: OutgoingRequest, mode: 'api' | 'smtp', ctx: ReplyContext | undefined) {
    let { subject, inReplyTo, references } = req;
    let threadId: string | undefined;
    if (ctx) {
      threadId = ctx.threadId;
      // Upstream headers are untrusted and often malformed: keep only well-formed ids. Caller-supplied
      // inReplyTo/references are not filtered here; validateOutgoing rejects them if malformed.
      const original = isMessageId(ctx.internetMessageId) ? ctx.internetMessageId : undefined;
      const upstreamRefs = (ctx.references ?? []).filter((r) => isMessageId(r) && r !== original);
      if (original) inReplyTo ??= original;
      const threadRefs = [...upstreamRefs, ...(original ? [original] : [])].slice(-50);
      if (threadRefs.length) references ??= threadRefs;
      if (subject === undefined && ctx.subject !== undefined) subject = /^re:/i.test(ctx.subject) ? ctx.subject : `Re: ${ctx.subject}`;
    }
    if (subject === undefined) throw new PerchError('subject is required (or reply to a message)', 'bad_argument');
    const { accountId: _a, replyToMessageId: _r, requestId: _q, ...compose } = req as SendRequest;
    const validated = validateOutgoing(
      { ...compose, subject, ...(inReplyTo ? { inReplyTo } : {}), ...(references ? { references } : {}) },
      e.account.email,
    );
    return composeForProvider(validated, mode, threadId, req.replyToMessageId);
  }

  private async prepare(e: Entry, req: OutgoingRequest, mode: 'api' | 'smtp') {
    return this.compose(e, req, mode, await this.replyContext(e, req));
  }

  /** Local validation of everything the caller sent, before any ledger write or provider I/O. */
  private prevalidate(e: Entry, req: SendRequest): void {
    const { accountId: _a, replyToMessageId, requestId: _q, ...compose } = req;
    if (compose.subject === undefined && replyToMessageId === undefined) throw new PerchError('subject is required (or reply to a message)', 'bad_argument');
    validateOutgoing({ ...compose, subject: compose.subject ?? '' }, e.account.email);
  }

  /** What the stored provider grant allows, as reported to clients (read is always possible). */
  private providerCaps(e: Entry) {
    const p = this.provider(e);
    const caps = p.providerCapabilities(e.account);
    return { read: true, draft: caps.draft, send: caps.send, modify: caps.modify === true, sendDraft: p.canSendDraft?.(e.account) === true };
  }

  private assertProviderAllows(e: Entry, what: 'draft' | 'send' | 'modify' | 'send_draft') {
    const caps = this.providerCaps(e);
    if (what === 'send_draft' ? caps.sendDraft : caps[what]) return;
    const id = e.account.id;
    const groupId = e.kind === 'gmail' ? e.account.groupId : undefined;
    // A Google account group keeps its ids: re-adding the same Google account updates it in place.
    const reconnect = (opt: string) => (groupId ? `perch google add --label <label> --services gmail ${opt} (updates group ${groupId})` : RECONNECT[e.kind](id, opt));
    const message = {
      send: `Account ${id} was not authorised to send at the provider. Reconnect with send permission: ${reconnect('--allow-send')}`,
      draft: `Account ${id} was not authorised for drafts at the provider. Reconnect: ${reconnect('--allow-drafts')}`,
      modify: `Account ${id} was not authorised to organize mail at the provider. Reconnect: ${reconnect('--allow-modify')}`,
      send_draft:
        `Account ${id} was not authorised to send existing drafts at the provider. Reconnect: ` +
        reconnect(e.kind === 'gmail' ? '--allow-drafts' : '--allow-send'),
    }[what];
    throw new PerchError(message, 'provider_scope_missing');
  }

  /**
   * replyToMessageId reads the original (subject, Message-ID, References, thread), so it also needs
   * "read" on that account. Checked before any provider I/O; otherwise a send-only grant could copy
   * any message's subject into a mail it addresses to itself.
   */
  private assertReplyReadable(principal: Principal, req: OutgoingRequest) {
    if (req.replyToMessageId !== undefined) assertMailCapability(principal, req.accountId, 'read');
  }

  async createDraft(principal: Principal, req: OutgoingRequest) {
    return this.audited('mail_create_draft', principal, req?.accountId, (p) => this.draftAs(p, req), true);
  }

  private async draftAs(principal: Principal, req: OutgoingRequest) {
    const e = await this.stillAllowed(principal, req, 'draft');
    this.assertProviderAllows(e, 'draft');
    // Drafts keep Bcc for every provider (IMAP drafts are APPENDed as complete messages).
    const mail = await this.prepare(e, req, 'api');
    // The reply lookup awaited provider I/O: re-check everything before the provider write.
    const current = await this.stillAllowed(principal, req, 'draft');
    // The full sender identity (credentials, servers, re-added account), not just kind and address.
    if (!sameBinding(e, current)) throw accountChanged();
    this.assertProviderAllows(current, 'draft');
    return { ...provenance(current), from: current.account.email, ...(await this.provider(current).createDraft(current.account, mail)) };
  }

  /**
   * Idempotent send (src/mail/workflow.ts). Order, all before any provider I/O: capability (+ read for
   * replies), account, provider scope, requestId, local payload validation, then the atomic ledger claim.
   * A repeated key with the same payload replays the stored result (no reply lookup, no recompose, no
   * resubmission); a changed payload fails. Exactly one provider attempt per key, ever.
   */
  async send(stale: Principal, req: SendRequest): Promise<SendOutcome> {
    const actor = actorOf(stale);
    let principal: Principal;
    let e: Entry;
    let ids: { key: string; operationId: string };
    let fp: string;
    let binding: string;
    try {
      principal = await this.caller(stale);
      e = await this.authorised(principal, req?.accountId, 'send');
      this.assertReplyReadable(principal, req);
      this.assertProviderAllows(e, 'send');
      const requestId = validateRequestId(req.requestId);
      this.prevalidate(e, req);
      ids = await this.workflow.ids(actor, e.account.id, requestId);
      fp = await this.workflow.fingerprint(ids.key, canonicalSendPayload(req));
      binding = await this.workflow.binding(bindingParts(e));
    } catch (err) {
      const accountId = safeAccountId(req?.accountId);
      await this.audit.record({ type: 'mail_send', actor, accountId, outcome: outcomeOf(err), code: auditCode(err) });
      throw err;
    }
    const claim = await this.workflow.claim({ key: ids.key, fp, binding, operationId: ids.operationId, accountId: e.account.id, provider: e.kind, actor });
    const head = { ...provenance(e), from: e.account.email };
    if (claim.kind === 'existing') {
      const { createdAt: _c, finalizedAt: _f, ...view } = viewOf(claim.record);
      return { ...head, ...view, replayed: true };
    }

    // Claimed: the durable pending record exists. From here on nothing escapes without finalizing.
    const { result, reason } = await this.attempt(principal, e, req, binding).catch(
      (): { result: SendResult; reason: SendReason } => ({
        result: { status: 'indeterminate', detail: 'The send failed unexpectedly; the outcome is unknown.' },
        reason: 'adapter_error',
      }),
    );
    const finalState = result.status;
    const recorded = await this.workflow.finalize(ids.key, claim.attempt, finalState, reason, result.providerMessageId);
    if (!recorded) {
      return { ...head, status: 'indeterminate', detail: FINALIZE_FAILED_NOTE, operationId: ids.operationId, requestState: 'pending', replayed: false };
    }
    return {
      ...head,
      ...result,
      detail: liveDetail(result),
      operationId: ids.operationId,
      requestState: finalState,
      replayed: false,
    };
  }

  /**
   * The single attempt of a claimed send. Everything before the provider call that fails is "rejected"
   * (not submitted): reply lookup, composing, or a sender account whose identity changed since the claim.
   */
  private async attempt(principal: Principal, e: Entry, req: SendRequest, binding: string): Promise<{ result: SendResult; reason: SendReason }> {
    const notSent = (detail: string, reason: SendReason) => ({ result: { status: 'rejected' as const, detail: `Not sent: ${detail}` }, reason });
    const message = (err: unknown, fallback: string) => (err instanceof PerchError ? err.message : fallback);
    // Namespace, grant, capability (+ read for replies) as stored now; failing it is "not submitted".
    const authorization = async () => {
      try {
        await this.stillAllowed(principal, req, 'send');
        return undefined;
      } catch (err) {
        return notSent(message(err, 'the request is no longer authorised'), 'not_submitted_authorization');
      }
    };
    const denied = await authorization();
    if (denied) return denied;
    let ctx: ReplyContext | undefined;
    try {
      ctx = await this.replyContext(e, req);
    } catch (err) {
      return notSent(`the message to reply to could not be read (${message(err, 'error')})`, 'not_submitted_reply_context');
    }
    let mail: Awaited<ReturnType<MailService['compose']>>;
    try {
      mail = await this.compose(e, req, e.kind === 'imap' ? 'smtp' : 'api', ctx);
    } catch (err) {
      return notSent(message(err, 'the message could not be built'), 'not_submitted_compose');
    }
    // Immediately before submission (the reply lookup and composing awaited): authorization again, the
    // sender identity binding, and the provider grant of the account as stored now.
    const deniedNow = await authorization();
    if (deniedNow) return deniedNow;
    const current = await this.entry(e.account.id, principal).catch(() => undefined);
    if (!current || (await this.workflow.binding(bindingParts(current))) !== binding) {
      return notSent(accountChanged().message, 'not_submitted_account_changed');
    }
    try {
      this.assertProviderAllows(current, 'send');
    } catch (err) {
      return notSent(message(err, 'the provider grant no longer allows sending'), 'not_submitted_provider_precheck');
    }
    try {
      const result = await this.provider(current).send(current.account, mail);
      return { result, reason: result.status === 'accepted' ? 'provider_accepted' : result.status === 'rejected' ? 'provider_rejected' : 'provider_unknown' };
    } catch (err) {
      // Legacy adapters use PerchError for pre-submit checks. Session workers also return it
      // after dispatch, so only their explicit pre-submit denials are certain.
      if (err instanceof PerchError && !sessionMayHaveWritten(current, err)) return notSent(err.message, 'not_submitted_provider_precheck');
      if (err instanceof PerchError && err.code === 'partial_write') return { result: { status: 'indeterminate', detail: err.message }, reason: 'adapter_error' };
      return { result: { status: 'indeterminate', detail: 'The send failed unexpectedly after it may have reached the provider; the outcome is unknown.' }, reason: 'adapter_error' };
    }
  }

  /**
   * Current state of this client's own send (same actor, account and requestId). Re-checks the namespace,
   * the stored grant's "send" capability, the account, its provider send permission and its identity
   * binding before revealing anything; another client's or namespace's requests are simply not found
   * (they live under other keys or ledgers). The view holds no reply-derived data (no subject, thread or
   * message ids of the original), so "read" is not required.
   */
  async sendStatus(stale: Principal, opts: { accountId: string; requestId: string }): Promise<Omit<SendOutcome, 'replayed'> & { createdAt: string; finalizedAt?: string }> {
    return this.audited('mail_send_status', stale, opts?.accountId, (p) => this.statusAs(p, opts));
  }

  private async statusAs(principal: Principal, opts: { accountId: string; requestId: string }): Promise<Omit<SendOutcome, 'replayed'> & { createdAt: string; finalizedAt?: string }> {
    const e = await this.authorised(principal, opts?.accountId, 'send');
    this.assertProviderAllows(e, 'send');
    const requestId = validateRequestId(opts.requestId);
    const { key } = await this.workflow.ids(actorOf(principal), e.account.id, requestId);
    const record = await this.workflow.lookup(key);
    if (!record) throw new PerchError('No send with this requestId from this client and account', 'unknown_request');
    if (record.binding !== (await this.workflow.binding(bindingParts(e)))) throw accountChanged();
    return { ...provenance(e), from: e.account.email, ...viewOf(record) };
  }
  // ---- organizing (capability "modify") and sending existing drafts ("send") ---------------------------

  /** The adapter's optional organizer method, or a fixed refusal when this provider has none. */
  private org<K extends OrganizerMethod>(e: Entry, name: K): NonNullable<MailProvider<unknown>[K]> {
    const p = this.provider(e);
    const fn = p[name];
    if (typeof fn !== 'function') throw new PerchError(`This operation is not supported for ${e.kind} accounts`, 'unsupported');
    return (fn as (...args: never[]) => unknown).bind(p) as NonNullable<MailProvider<unknown>[K]>;
  }

  async listFolders(stale: Principal, opts: { accountId: string }): Promise<MailProvenance & { folders: MailFolder[] }> {
    return this.audited('mail_list_folders', stale, opts?.accountId, async (p) => {
      const e = await this.authorised(p, opts.accountId, 'read');
      return { ...provenance(e), folders: await this.org(e, 'listFolders')(e.account) };
    });
  }

  async listDrafts(
    stale: Principal,
    opts: { accountId: string; pageSize?: number; cursor?: string },
  ): Promise<MailProvenance & { drafts: MailDraftSummary[]; nextCursor: string | null; hasMore: boolean; incomplete?: boolean }> {
    return this.audited('mail_list_drafts', stale, opts?.accountId, async (p) => {
      const e = await this.authorised(p, opts.accountId, 'read');
      const pageSize = bounded('pageSize', opts.pageSize, DEFAULT_MAIL_PAGE_SIZE, MAX_MAIL_PAGE_SIZE);
      if (opts.cursor !== undefined && (typeof opts.cursor !== 'string' || !opts.cursor || opts.cursor.length > 16384)) {
        throw new PerchError('Invalid cursor', 'bad_cursor');
      }
      const page = await this.org(e, 'listDrafts')(e.account, { pageSize }, opts.cursor);
      const next = page.next ?? null;
      return { ...provenance(e), drafts: page.items, nextCursor: next, hasMore: next !== null, ...(page.incomplete ? { incomplete: true } : {}) };
    });
  }

  /**
   * One organizing write. Audited like a draft (attempt durably BEFORE the provider write, fail closed). Inside, right
   * before the provider call: namespace guard, the grant as stored now, "modify" on this account, the account as
   * stored now and its provider permission (gmail.modify, Mail.ReadWrite, IMAP allowModify).
   */
  private organize(
    type: string,
    stale: Principal,
    req: { accountId: string; messageId: string },
    write: (e: Entry) => Promise<OrganizeResult>,
  ): Promise<MailProvenance & OrganizeResult> {
    return this.audited(
      type,
      stale,
      req?.accountId,
      async (p) => {
        const now = await this.caller(p);
        const e = await this.authorised(now, req.accountId, 'modify');
        this.assertProviderAllows(e, 'modify');
        if (typeof req.messageId !== 'string' || !req.messageId || req.messageId.length > 2048) {
          throw new PerchError('messageId is required', 'bad_argument');
        }
        return { ...provenance(e), ...(await write(e)) };
      },
      true,
    );
  }

  async markMessage(stale: Principal, req: { accountId: string; messageId: string; read?: boolean; starred?: boolean }) {
    return this.organize('mail_mark_message', stale, req, (e) => {
      const change = {
        ...(typeof req.read === 'boolean' ? { read: req.read } : {}),
        ...(typeof req.starred === 'boolean' ? { starred: req.starred } : {}),
      };
      if (!Object.keys(change).length) throw new PerchError('Set read and/or starred', 'bad_argument');
      return this.org(e, 'markMessage')(e.account, req.messageId, change);
    });
  }

  async moveMessage(stale: Principal, req: { accountId: string; messageId: string; folderId?: string; archive?: boolean }) {
    return this.organize('mail_move_message', stale, req, (e) => {
      let target: MoveTarget;
      if (req.folderId !== undefined && (typeof req.folderId !== 'string' || !req.folderId || req.folderId.length > 1024)) {
        throw new PerchError('folderId must be a folder/label id from mail_list_folders', 'bad_argument');
      }
      if (req.archive === true) target = { archive: true, ...(req.folderId !== undefined ? { folderId: req.folderId } : {}) };
      else if (req.folderId !== undefined) target = { folderId: req.folderId };
      else throw new PerchError('Set folderId or archive: true', 'bad_argument');
      return this.org(e, 'moveMessage')(e.account, req.messageId, target);
    });
  }

  async trashMessage(stale: Principal, req: { accountId: string; messageId: string }) {
    return this.organize('mail_trash_message', stale, req, (e) => this.org(e, 'trashMessage')(e.account, req.messageId));
  }

  async restoreMessage(stale: Principal, req: { accountId: string; messageId: string }) {
    return this.organize('mail_restore_message', stale, req, (e) => this.org(e, 'restoreMessage')(e.account, req.messageId));
  }

  /**
   * Sends an existing draft through the same idempotent workflow as send(): capability "send", account, provider
   * permission for sending drafts, requestId and draft id, all before the atomic ledger claim; a repeated key with
   * the same draft replays the stored outcome, another draft (or a mail_send payload) under the same key conflicts.
   * Exactly one provider attempt per key.
   */
  async sendDraft(stale: Principal, req: { accountId: string; draftId: string; requestId: string }): Promise<SendOutcome> {
    const actor = actorOf(stale);
    let principal: Principal;
    let e: Entry;
    let ids: { key: string; operationId: string };
    let fp: string;
    let binding: string;
    try {
      principal = await this.caller(stale);
      e = await this.authorised(principal, req?.accountId, 'send');
      this.assertProviderAllows(e, 'send_draft');
      const requestId = validateRequestId(req.requestId);
      if (typeof req.draftId !== 'string' || !req.draftId || req.draftId.length > 2048 || /[\u0000-\u001f\u007f]/.test(req.draftId)) {
        throw new PerchError('draftId is required (from mail_list_drafts or mail_create_draft)', 'bad_argument');
      }
      ids = await this.workflow.ids(actor, e.account.id, requestId);
      fp = await this.workflow.fingerprint(ids.key, canonicalSendDraftPayload(e.account.id, req.draftId));
      binding = await this.workflow.binding(bindingParts(e));
    } catch (err) {
      await this.audit.record({ type: 'mail_send_draft', actor, accountId: safeAccountId(req?.accountId), outcome: outcomeOf(err), code: auditCode(err) });
      throw err;
    }
    const claim = await this.workflow.claim({ key: ids.key, fp, binding, operationId: ids.operationId, accountId: e.account.id, provider: e.kind, actor });
    const head = { ...provenance(e), from: e.account.email };
    if (claim.kind === 'existing') {
      const { createdAt: _c, finalizedAt: _f, ...view } = viewOf(claim.record);
      return { ...head, ...view, replayed: true };
    }
    const { result, reason } = await this.attemptDraft(principal, e, req, binding).catch(
      (): { result: SendResult; reason: SendReason } => ({
        result: { status: 'indeterminate', detail: 'The send failed unexpectedly; the outcome is unknown.' },
        reason: 'adapter_error',
      }),
    );
    const recorded = await this.workflow.finalize(ids.key, claim.attempt, result.status, reason, result.providerMessageId);
    if (!recorded) {
      return { ...head, status: 'indeterminate', detail: FINALIZE_FAILED_NOTE, operationId: ids.operationId, requestState: 'pending', replayed: false };
    }
    return { ...head, ...result, detail: liveDetail(result), operationId: ids.operationId, requestState: result.status, replayed: false };
  }

  /** The single attempt of a claimed draft send; everything that fails before the provider call is "rejected". */
  private async attemptDraft(
    principal: Principal,
    e: Entry,
    req: { accountId: string; draftId: string },
    binding: string,
  ): Promise<{ result: SendResult; reason: SendReason }> {
    const notSent = (detail: string, reason: SendReason) => ({ result: { status: 'rejected' as const, detail: `Not sent: ${detail}` }, reason });
    const message = (err: unknown, fallback: string) => (err instanceof PerchError ? err.message : fallback);
    // Immediately before submission: namespace, grant as stored now, "send" on this account, the sender identity
    // binding and the provider permission of the account as stored now.
    try {
      const now = await this.caller(principal);
      await this.authorised(now, req.accountId, 'send');
    } catch (err) {
      return notSent(message(err, 'the request is no longer authorised'), 'not_submitted_authorization');
    }
    const current = await this.entry(e.account.id, principal).catch(() => undefined);
    if (!current || (await this.workflow.binding(bindingParts(current))) !== binding) {
      return notSent(accountChanged().message, 'not_submitted_account_changed');
    }
    let submit: (account: unknown, draftId: string) => Promise<SendResult>;
    try {
      this.assertProviderAllows(current, 'send_draft');
      submit = this.org(current, 'sendDraft');
    } catch (err) {
      return notSent(message(err, 'the provider grant no longer allows sending drafts'), 'not_submitted_provider_precheck');
    }
    try {
      const result = await submit(current.account, req.draftId);
      return { result, reason: result.status === 'accepted' ? 'provider_accepted' : result.status === 'rejected' ? 'provider_rejected' : 'provider_unknown' };
    } catch (err) {
      // Session worker errors may arrive after submission; unknown outcomes are never retried.
      if (err instanceof PerchError && !sessionMayHaveWritten(current, err)) return notSent(err.message, 'not_submitted_provider_precheck');
      if (err instanceof PerchError && err.code === 'partial_write') return { result: { status: 'indeterminate', detail: err.message }, reason: 'adapter_error' };
      return { result: { status: 'indeterminate', detail: 'The send failed unexpectedly after it may have reached the provider; the outcome is unknown.' }, reason: 'adapter_error' };
    }
  }

  // ---- reply and forward (mail_reply / mail_forward) -----------------------------------------------------

  /** Reply (replyAll) to one message: a draft by default, or sent now with send: true (idempotent, needs requestId). */
  reply(stale: Principal, req: DerivedRequest) {
    return this.derived('reply', stale, req);
  }

  /** Forward one message with its attachments: a draft by default, or sent now with send: true. */
  forward(stale: Principal, req: DerivedRequest) {
    return this.derived('forward', stale, req);
  }

  private derived(kind: DerivedKind, stale: Principal, req: DerivedRequest) {
    return req?.send === true ? this.sendDerived(kind, stale, req) : this.draftDerived(kind, stale, req);
  }

  /** Current grant: the capability plus "read" (the original is read), the account, and its provider permission. */
  private async derivedAllowed(principal: Principal, accountId: string, cap: 'draft' | 'send'): Promise<Entry> {
    const p = await this.caller(principal);
    const e = await this.authorised(p, accountId, cap);
    assertMailCapability(p, accountId, 'read');
    this.assertProviderAllows(e, cap);
    return e;
  }

  /** Local checks of the caller's own input (before any ledger write or provider I/O). */
  private prevalidateDerived(kind: DerivedKind, e: Entry, req: DerivedRequest): void {
    const bad = (m: string) => new PerchError(m, 'bad_argument');
    if (typeof req.messageId !== 'string' || !req.messageId || req.messageId.length > 2048 || /[\u0000-\u001f\u007f]/.test(req.messageId)) {
      throw bad('messageId of the original message is required (from mail_search / mail_read_message)');
    }
    if (req.text !== undefined && typeof req.text !== 'string') throw bad('text must be a string');
    if (req.html !== undefined && typeof req.html !== 'string') throw bad('html must be a string');
    if (kind === 'reply' && (req.text === undefined || !req.text.trim())) throw bad('text is required for a reply');
    if (kind === 'forward' && !(Array.isArray(req.to) && req.to.length)) throw bad('to is required for a forward');
    if (kind === 'reply' && req.includeAttachments !== undefined) throw bad('includeAttachments applies to mail_forward only');
    if (kind === 'forward' && req.replyAll !== undefined) throw bad('replyAll applies to mail_reply only');
    // Caller addresses, body sizes and the sender, exactly as validateOutgoing checks them again on the derived message.
    validateOutgoing(
      {
        to: kind === 'forward' ? (req.to ?? []) : [...(req.to ?? []), e.account.email],
        ...(req.cc ? { cc: req.cc } : {}),
        ...(req.bcc ? { bcc: req.bcc } : {}),
        subject: '',
        text: req.text ?? '',
        ...(req.html !== undefined ? { html: req.html } : {}),
      },
      e.account.email,
    );
  }

  /**
   * Reads the original and derives the outgoing message: recipients (reply), subject, threading, quote or forward
   * block, and for a forward the original attachments within the outgoing limits (over the limits: an error, never
   * silently dropped). Only provider reads; nothing is written.
   */
  private async deriveOutgoing(kind: DerivedKind, e: Entry, req: DerivedRequest): Promise<{ request: OutgoingRequest; threadId?: string; sourceMessageId?: string; summary: DerivedSummary }> {
    const p = this.provider(e);
    const original: MailMessage = await p.read(e.account, req.messageId, { maxBytes: MAX_BODY_BYTES });
    const text = req.text ?? '';
    let to: string[];
    let cc: string[];
    let skipped = 0;
    if (kind === 'reply') {
      const r = deriveReplyRecipients(original, e.account.email, req.replyAll === true);
      const taken = addressKeys([...r.to, ...r.cc]);
      to = mergeRecipients(r.to, req.to, taken);
      cc = mergeRecipients(r.cc, req.cc, taken);
      skipped = r.skipped;
    } else {
      to = [...(req.to ?? [])];
      cc = [...(req.cc ?? [])];
    }
    // A caller bcc that is already a visible recipient would get the message twice: drop it (case-insensitive address).
    const bcc = mergeRecipients([], req.bcc, addressKeys([...to, ...cc]));
    const quote = kind === 'reply' ? quoteReply(original, '') : forwardBody(original, '');
    const body = kind === 'reply' ? quoteReply(original, text) : forwardBody(original, text);
    const subject = kind === 'reply' ? replySubject(original.subject) : forwardSubject(original.subject);
    const thread = threadingFor(original, kind === 'reply');

    const attachments: ComposeAttachment[] = [];
    let omittedInline = 0;
    if (kind === 'forward' && req.includeAttachments !== false) {
      const all = original.attachments ?? [];
      const files = all.filter((a) => a.inline !== true);
      omittedInline = all.length - files.length;
      if (files.length > MAX_ATTACHMENTS) {
        throw new PerchError(
          `The original has ${files.length} attachments, over the limit of ${MAX_ATTACHMENTS} per message. Nothing was created or sent. ${FORWARD_ATTACHMENT_HINT}`,
          'too_many_attachments',
        );
      }
      const tooLarge = () =>
        new PerchError(
          `The original's attachments are larger than ${MAX_ATTACHMENT_TOTAL_BYTES} bytes in total. Nothing was created or sent. ${FORWARD_ATTACHMENT_HINT}`,
          'attachments_too_large',
        );
      // Provider sizes are hints (IMAP reports the encoded size): refuse early only when clearly over the limit.
      const reported = files.reduce((n, a) => n + (typeof a.size === 'number' ? a.size : 0), 0);
      if (reported > Math.ceil((MAX_ATTACHMENT_TOTAL_BYTES * 4) / 3) + 64 * 1024) throw tooLarge();
      let total = 0;
      for (const [i, a] of files.entries()) {
        const remaining = MAX_ATTACHMENT_TOTAL_BYTES - total;
        if (remaining < 1) throw tooLarge();
        let content;
        try {
          content = await p.getAttachment(e.account, req.messageId, a.attachmentId, { maxBytes: remaining });
        } catch (err) {
          if (err instanceof PerchError && err.code === 'attachment_too_large') throw tooLarge();
          if (err instanceof PerchError && err.code === 'unsupported_attachment') {
            throw new PerchError(
              `Attachment ${i + 1} of the original cannot be forwarded (${err.message}). Nothing was created or sent. ${FORWARD_ATTACHMENT_HINT}`,
              'unsupported_attachment',
            );
          }
          throw err;
        }
        total += content.size;
        if (total > MAX_ATTACHMENT_TOTAL_BYTES) throw tooLarge();
        attachments.push({
          filename: safeFilename(content.filename ?? a.filename, i),
          contentType: safeContentType(content.contentType),
          contentBase64: content.contentBase64,
        });
      }
    }

    const request: OutgoingRequest = {
      accountId: e.account.id,
      to,
      ...(cc.length ? { cc } : {}),
      ...(bcc.length ? { bcc } : {}),
      subject,
      text: body,
      ...(req.html !== undefined ? { html: htmlWithQuote(req.html, quote.replace(/^\n+/, '')) } : {}),
      ...(attachments.length ? { attachments } : {}),
      ...(thread.inReplyTo ? { inReplyTo: thread.inReplyTo } : {}),
      ...(thread.references.length ? { references: thread.references } : {}),
    };
    const summary: DerivedSummary = {
      to,
      cc,
      bcc,
      subject,
      ...(skipped ? { skippedRecipients: skipped } : {}),
      ...(kind === 'forward' ? { attachments: attachments.length, omittedInlineAttachments: omittedInline } : {}),
    };
    // Gmail keeps the message in the original's thread with threadId (it must match the References/subject rules).
    return { request, ...(original.threadId && e.kind === 'gmail' ? { threadId: original.threadId } : {}), ...(kind === 'reply' ? { sourceMessageId: req.messageId } : {}), summary };
  }

  /** Validates the derived message like any caller input (headers, addresses, sizes) and builds the MIME. */
  private async composeDerived(e: Entry, d: { request: OutgoingRequest; threadId?: string; sourceMessageId?: string }, mode: 'api' | 'smtp') {
    const { accountId: _a, replyToMessageId: _r, subject, ...rest } = d.request;
    const validated = validateOutgoing({ ...rest, subject: subject ?? '' }, e.account.email);
    return composeForProvider(validated, mode, d.threadId, d.sourceMessageId);
  }

  /** Draft (default): audited like mail_create_draft, with the attempt recorded before the provider write. */
  private draftDerived(kind: DerivedKind, stale: Principal, req: DerivedRequest) {
    return this.audited(
      `mail_${kind}`,
      stale,
      req?.accountId,
      async (p) => {
        const e = await this.derivedAllowed(p, req.accountId, 'draft');
        this.prevalidateDerived(kind, e, req);
        if (req.requestId !== undefined) throw new PerchError('requestId is only used with send: true', 'bad_argument');
        const d = await this.deriveOutgoing(kind, e, req);
        const mail = await this.composeDerived(e, d, 'api');
        // The original was read (provider I/O): grant, account identity and provider permission again before the write.
        const current = await this.derivedAllowed(p, req.accountId, 'draft');
        if (!sameBinding(e, current)) throw accountChanged();
        const draft = await this.provider(current).createDraft(current.account, mail);
        return { ...provenance(current), from: current.account.email, ...draft, ...d.summary, sent: false as const };
      },
      true,
    );
  }

  /**
   * send: true goes through the idempotent send workflow like mail_send: capability "send" (+ "read"), account,
   * provider permission, requestId and the caller's input, all before the atomic ledger claim. The fingerprint covers
   * the CALLER's payload (original id, mode, text, extra recipients), not the derived message, so a retry with the
   * same requestId replays the stored outcome without reading the original again. Exactly one provider attempt per key.
   */
  private async sendDerived(kind: DerivedKind, stale: Principal, req: DerivedRequest): Promise<SendOutcome & Partial<DerivedSummary> & { sent: true }> {
    const actor = actorOf(stale);
    let principal: Principal;
    let e: Entry;
    let ids: { key: string; operationId: string };
    let fp: string;
    let binding: string;
    try {
      principal = await this.caller(stale);
      e = await this.authorised(principal, req?.accountId, 'send');
      assertMailCapability(principal, req.accountId, 'read');
      this.assertProviderAllows(e, 'send');
      const requestId = validateRequestId(req.requestId);
      this.prevalidateDerived(kind, e, req);
      ids = await this.workflow.ids(actor, e.account.id, requestId);
      fp = await this.workflow.fingerprint(ids.key, canonicalDerivedPayload(kind, req));
      binding = await this.workflow.binding(bindingParts(e));
    } catch (err) {
      await this.audit.record({ type: `mail_${kind}`, actor, accountId: safeAccountId(req?.accountId), outcome: outcomeOf(err), code: auditCode(err) });
      throw err;
    }
    const claim = await this.workflow.claim({ key: ids.key, fp, binding, operationId: ids.operationId, accountId: e.account.id, provider: e.kind, actor });
    const head = { ...provenance(e), from: e.account.email };
    if (claim.kind === 'existing') {
      const { createdAt: _c, finalizedAt: _f, ...view } = viewOf(claim.record);
      return { ...head, ...view, replayed: true, sent: true };
    }
    let summary: DerivedSummary | undefined;
    const { result, reason } = await this.attemptDerived(kind, principal, e, req, binding, (s) => {
      summary = s;
    }).catch(
      (): { result: SendResult; reason: SendReason } => ({
        result: { status: 'indeterminate', detail: 'The send failed unexpectedly; the outcome is unknown.' },
        reason: 'adapter_error',
      }),
    );
    const recorded = await this.workflow.finalize(ids.key, claim.attempt, result.status, reason, result.providerMessageId);
    if (!recorded) {
      return { ...head, status: 'indeterminate', detail: FINALIZE_FAILED_NOTE, operationId: ids.operationId, requestState: 'pending', replayed: false, sent: true };
    }
    return { ...head, ...result, detail: liveDetail(result), operationId: ids.operationId, requestState: result.status, replayed: false, ...(summary ?? {}), sent: true };
  }

  /** The single attempt of a claimed reply/forward send; everything that fails before the provider call is "rejected". */
  private async attemptDerived(
    kind: DerivedKind,
    principal: Principal,
    e: Entry,
    req: DerivedRequest,
    binding: string,
    report: (s: DerivedSummary) => void,
  ): Promise<{ result: SendResult; reason: SendReason }> {
    const notSent = (detail: string, reason: SendReason) => ({ result: { status: 'rejected' as const, detail: `Not sent: ${detail}` }, reason });
    const message = (err: unknown, fallback: string) => (err instanceof PerchError ? err.message : fallback);
    const authorization = async () => {
      try {
        await this.derivedAllowed(principal, req.accountId, 'send');
        return undefined;
      } catch (err) {
        return notSent(message(err, 'the request is no longer authorised'), 'not_submitted_authorization');
      }
    };
    const denied = await authorization();
    if (denied) return denied;
    let d: Awaited<ReturnType<MailService['deriveOutgoing']>>;
    try {
      d = await this.deriveOutgoing(kind, e, req);
    } catch (err) {
      return notSent(`the original message could not be used (${message(err, 'error')})`, 'not_submitted_reply_context');
    }
    let mail: Awaited<ReturnType<MailService['composeDerived']>>;
    try {
      mail = await this.composeDerived(e, d, e.kind === 'imap' ? 'smtp' : 'api');
    } catch (err) {
      return notSent(message(err, 'the message could not be built'), 'not_submitted_compose');
    }
    report(d.summary);
    // Immediately before submission: authorization, sender identity binding and provider grant as stored now.
    const deniedNow = await authorization();
    if (deniedNow) return deniedNow;
    const current = await this.entry(e.account.id, principal).catch(() => undefined);
    if (!current || (await this.workflow.binding(bindingParts(current))) !== binding) {
      return notSent(accountChanged().message, 'not_submitted_account_changed');
    }
    try {
      this.assertProviderAllows(current, 'send');
    } catch (err) {
      return notSent(message(err, 'the provider grant no longer allows sending'), 'not_submitted_provider_precheck');
    }
    try {
      const result = await this.provider(current).send(current.account, mail);
      return { result, reason: result.status === 'accepted' ? 'provider_accepted' : result.status === 'rejected' ? 'provider_rejected' : 'provider_unknown' };
    } catch (err) {
      if (err instanceof PerchError && !sessionMayHaveWritten(current, err)) return notSent(err.message, 'not_submitted_provider_precheck');
      if (err instanceof PerchError && err.code === 'partial_write') return { result: { status: 'indeterminate', detail: err.message }, reason: 'adapter_error' };
      return { result: { status: 'indeterminate', detail: 'The send failed unexpectedly after it may have reached the provider; the outcome is unknown.' }, reason: 'adapter_error' };
    }
  }
}

type OrganizerMethod = 'listFolders' | 'listDrafts' | 'markMessage' | 'moveMessage' | 'trashMessage' | 'restoreMessage' | 'sendDraft';

