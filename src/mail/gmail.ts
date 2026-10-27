import { PerchError } from '../errors.js';
import type { SourcePage } from '../fanout.js';
import type { GmailAccount } from '../store/credentialStore.js';
import { UpstreamError, type CallOptions, type Upstream } from '../upstream.js';
import { ACCEPTED_NOTE, HARD_MAIL_MAX_BYTES, INDETERMINATE_NOTE } from './types.js';
import { GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE, GMAIL_SEND_SCOPE } from './gmailAccounts.js';
import { htmlToText, truncateUtf8 } from './html.js';
import type {
  DraftResult,
  MailDraftSummary,
  MailFolder,
  MailFolderRole,
  MarkChange,
  MoveTarget,
  OrganizeResult,
  ProviderCapabilities,
  MailAttachmentContent,
  MailAttachmentMeta,
  MailMessage,
  MailProvider,
  MailSummary,
  OutgoingMime,
  ReadOptions,
  ReplyContext,
  SearchOptions,
  SendResult,
} from './types.js';

export interface GmailTokenSource {
  getAccessToken(id: string): Promise<string>;
  invalidate?(id: string): void;
}

interface GmailHeader {
  name?: string;
  value?: string;
}

interface GmailPart {
  partId?: string;
  mimeType?: string;
  filename?: string;
  headers?: GmailHeader[];
  body?: { size?: number; data?: string; attachmentId?: string };
  parts?: GmailPart[];
}

interface GmailMessageResource {
  id?: string;
  threadId?: string;
  snippet?: string;
  internalDate?: string;
  payload?: GmailPart;
}

interface GmailListResponse {
  messages?: Array<{ id?: string }>;
  nextPageToken?: string;
}

const BASE = '/gmail/v1/users/me';
/** Gmail message ids; validated before they are put into a path. */
const MESSAGE_ID = /^[A-Za-z0-9_-]{1,256}$/;
/** MIME part ids as Gmail numbers them ("0", "1.2", ...). */
const PART_ID = /^[0-9.]{1,64}$/;
/** Gmail's own (volatile) attachment ids, as allowlisted by Upstream. */
const ATTACHMENT_ID = /^[A-Za-z0-9_-]{1,4096}$/;
/** Gmail label ids (INBOX, Label_12, CATEGORY_SOCIAL, ...). */
const LABEL_ID = /^[A-Za-z0-9_-]{1,256}$/;
/** Gmail page tokens (opaque; digits in practice). */
const PAGE_TOKEN = /^[A-Za-z0-9_.~=-]{1,1024}$/;
const LABEL_ROLES: Record<string, MailFolderRole> = {
  INBOX: 'inbox',
  SENT: 'sent',
  DRAFT: 'drafts',
  TRASH: 'trash',
  SPAM: 'junk',
  STARRED: 'starred',
  IMPORTANT: 'important',
};
/** System labels a message cannot be moved to with labels.modify (or only through a dedicated tool). */
const UNMOVABLE_LABELS = new Set(['TRASH', 'DRAFT', 'SENT', 'UNREAD', 'STARRED', 'IMPORTANT', 'CHAT']);
/** Parallel messages.get calls per search page (Gmail enforces per-user concurrency limits). */
const METADATA_CONCURRENCY = 5;
/** Slack for the JSON envelope around a base64url body from the attachments endpoint. */
const ENVELOPE_SLACK = 64 * 1024;

/** Response cap for a base64url body of `size` decoded bytes wrapped in JSON. */
const encodedBound = (size: number) => Math.ceil((size * 4) / 3) + ENVELOPE_SLACK;

function header(headers: GmailHeader[] | undefined, name: string): string | undefined {
  const lower = name.toLowerCase();
  return headers?.find((h) => h.name?.toLowerCase() === lower)?.value;
}

/** Splits an address-list header on commas outside quotes, comments and angle brackets. */
export function splitAddresses(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  let depth = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value[i]!;
    if (c === '\\' && quoted) {
      cur += c + (value[i + 1] ?? '');
      i++;
      continue;
    }
    if (c === '"') quoted = !quoted;
    else if (!quoted && (c === '<' || c === '(')) depth++;
    else if (!quoted && (c === '>' || c === ')')) depth = Math.max(0, depth - 1);
    if (c === ',' && !quoted && depth === 0) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
    } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function isoFromInternalDate(ms: string | undefined): string | undefined {
  const n = Number(ms);
  return ms && Number.isFinite(n) ? new Date(n).toISOString() : undefined;
}

async function mapBounded<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

function checkMessageId(id: string): string {
  if (!MESSAGE_ID.test(id)) throw new PerchError('Invalid Gmail message id', 'bad_argument');
  return id;
}

/**
 * Gmail REST adapter. Gmail has no folders in the IMAP sense; `folder` is ignored and callers
 * use Gmail query syntax instead (e.g. `in:inbox`, `label:work`).
 */
export class GmailProvider implements MailProvider<GmailAccount> {
  readonly kind = 'gmail' as const;

  constructor(
    private readonly upstream: Upstream,
    private readonly tokens: GmailTokenSource,
  ) {}

  providerCapabilities(account: GmailAccount): ProviderCapabilities {
    const compose = account.scopes.includes(GMAIL_COMPOSE_SCOPE);
    return { draft: compose, send: !account.draftsOnly && (compose || account.scopes.includes(GMAIL_SEND_SCOPE)), modify: !account.draftsOnly && account.scopes.includes(GMAIL_MODIFY_SCOPE) };
  }

  /**
   * users.drafts.send accepts gmail.compose or gmail.modify, but Perch requires the compose opt-in
   * (--allow-drafts): an account connected only to organize mail (--allow-modify) must never gain a send path.
   */
  canSendDraft(account: GmailAccount): boolean {
    return !account.draftsOnly && account.scopes.includes(GMAIL_COMPOSE_SCOPE);
  }

  private async auth(account: GmailAccount): Promise<Record<string, string>> {
    return { authorization: `Bearer ${await this.tokens.getAccessToken(account.id)}` };
  }

  /** JSON call; a 401 drops the cached access token so the next call refreshes (never retried here). */
  private async call<T>(account: GmailAccount, opts: Omit<CallOptions, 'headers'>): Promise<T> {
    const headers = await this.auth(account);
    try {
      return await this.upstream.json<T>('gmail', { ...opts, headers });
    } catch (err) {
      if (err instanceof UpstreamError && err.status === 401) this.tokens.invalidate?.(account.id);
      throw err;
    }
  }

  private get<T>(account: GmailAccount, path: string, query?: Record<string, string | number | undefined>, maxBytes?: number): Promise<T> {
    return this.call<T>(account, {
      method: 'GET',
      path,
      ...(query ? { query } : {}),
      ...(maxBytes !== undefined ? { maxBytes } : {}),
    });
  }

  async search(account: GmailAccount, opts: SearchOptions, cursor: string | undefined): Promise<SourcePage<MailSummary>> {
    const list = await this.get<GmailListResponse>(account, `${BASE}/messages`, {
      q: opts.query || undefined,
      maxResults: opts.pageSize,
      pageToken: cursor,
    });
    const ids = (list.messages ?? []).map((m) => m.id).filter((id): id is string => typeof id === 'string' && MESSAGE_ID.test(id));
    // format=metadata without metadataHeaders returns all headers; Upstream.query cannot repeat a parameter.
    const items = await mapBounded(ids, METADATA_CONCURRENCY, async (id) =>
      toSummary(await this.get<GmailMessageResource>(account, `${BASE}/messages/${id}`, { format: 'metadata' })),
    );
    return { items, ...(list.nextPageToken ? { next: list.nextPageToken } : {}) };
  }

  private full(account: GmailAccount, messageId: string): Promise<GmailMessageResource> {
    return this.get<GmailMessageResource>(account, `${BASE}/messages/${checkMessageId(messageId)}`, { format: 'full' });
  }

  /** Decoded body of a leaf part: inline data, or a bounded fetch via the (volatile) attachment id. */
  private async partBody(account: GmailAccount, messageId: string, part: GmailPart, maxBytes: number): Promise<Buffer> {
    if (typeof part.body?.data === 'string') return Buffer.from(part.body.data, 'base64url');
    const aid = part.body?.attachmentId;
    if (!aid) return Buffer.alloc(0);
    if (!ATTACHMENT_ID.test(aid)) throw new PerchError('Gmail returned a malformed attachment id', 'upstream_bad_response');
    const res = await this.get<{ data?: string }>(
      account,
      `${BASE}/messages/${checkMessageId(messageId)}/attachments/${aid}`,
      undefined,
      encodedBound(maxBytes),
    );
    if (typeof res.data !== 'string') throw new PerchError('Gmail returned no attachment data', 'upstream_bad_response');
    return Buffer.from(res.data, 'base64url');
  }

  async read(account: GmailAccount, messageId: string, opts: ReadOptions): Promise<MailMessage> {
    const m = await this.full(account, messageId);
    const h = m.payload?.headers;
    const leaves = m.payload ? flatten(m.payload) : [];
    const msg: MailMessage = { ...toSummary(m), truncated: false, attachments: [] };
    const cc = splitAddresses(header(h, 'Cc'));
    if (cc) msg.cc = cc;
    const replyTo = splitAddresses(header(h, 'Reply-To'));
    if (replyTo) msg.replyTo = replyTo;
    Object.assign(msg, threading(h));

    const bodyPart =
      leaves.find((p) => !isAttachment(p) && mimeOf(p) === 'text/plain') ??
      leaves.find((p) => !isAttachment(p) && mimeOf(p) === 'text/html');
    if (bodyPart) {
      const size = bodyPart.body?.size ?? 0;
      // A body larger than the hard cap is not downloaded at all (bounded memory per read).
      if (size > HARD_MAIL_MAX_BYTES) msg.truncated = true;
      else {
        const raw = decodeCharset(await this.partBody(account, messageId, bodyPart, Math.max(size, 1)), bodyPart);
        const isHtml = mimeOf(bodyPart) === 'text/html';
        const { text, truncated } = isHtml ? htmlToText(raw, opts.maxBytes) : truncateUtf8(raw, opts.maxBytes);
        msg.text = text;
        msg.textSource = isHtml ? 'text/html' : 'text/plain';
        msg.truncated = truncated;
      }
    }
    for (const p of leaves) {
      if (!p.filename || p.partId === undefined) continue;
      const meta: MailAttachmentMeta = { attachmentId: p.partId, filename: p.filename, contentType: mimeOf(p) || 'application/octet-stream' };
      if (typeof p.body?.size === 'number') meta.size = p.body.size;
      if (/^\s*inline\b/i.test(header(p.headers, 'Content-Disposition') ?? '')) meta.inline = true;
      msg.attachments.push(meta);
    }
    msg.hasAttachments = msg.attachments.length > 0;
    return msg;
  }

  /**
   * `partId` is the MIME part id (stable), not Gmail's attachment id, which is re-issued on every
   * messages.get. The current attachment id is looked up right before the download.
   */
  async getAttachment(account: GmailAccount, messageId: string, partId: string, opts: ReadOptions): Promise<MailAttachmentContent> {
    checkMessageId(messageId);
    if (!PART_ID.test(partId)) throw new PerchError('Invalid Gmail attachment id', 'bad_argument');
    const m = await this.full(account, messageId);
    const part = (m.payload ? flatten(m.payload) : []).find((p) => p.partId === partId);
    if (!part) throw new PerchError(`Attachment ${partId} not found in message ${messageId}`, 'not_found');
    const size = part.body?.size ?? 0;
    const tooLarge = () =>
      new PerchError(`Attachment is ${size} bytes, over the ${opts.maxBytes} byte limit; raise maxBytes`, 'attachment_too_large');
    if (size > opts.maxBytes) throw tooLarge();
    const data = await this.partBody(account, messageId, part, size);
    // The reported size is not trusted: the decoded content is checked again.
    if (data.length > opts.maxBytes) throw tooLarge();
    const out: MailAttachmentContent = {
      attachmentId: partId,
      contentType: mimeOf(part) || 'application/octet-stream',
      size: data.length,
      contentBase64: data.toString('base64'),
    };
    if (part.filename) out.filename = part.filename;
    return out;
  }

  /** The answered message's own threading data; the MailService builds the reply's References. */
  async replyContext(account: GmailAccount, messageId: string): Promise<ReplyContext> {
    const m = await this.get<GmailMessageResource>(account, `${BASE}/messages/${checkMessageId(messageId)}`, { format: 'metadata' });
    const h = m.payload?.headers;
    const t = threading(h);
    const ctx: ReplyContext = { references: t.references ?? [] };
    if (t.internetMessageId) ctx.internetMessageId = t.internetMessageId;
    const subject = header(h, 'Subject');
    if (subject !== undefined) ctx.subject = subject;
    if (m.threadId) ctx.threadId = m.threadId;
    return ctx;
  }

  async createDraft(account: GmailAccount, mail: OutgoingMime): Promise<DraftResult> {
    // Defence in depth: the MailService checks too, and the grant could not do it anyway.
    if (!this.providerCapabilities(account).draft) {
      throw new PerchError(`Gmail account ${account.id} was not authorised for drafts (gmail.compose)`, 'capability_denied');
    }
    const message = outgoingMessage(mail);
    const res = await this.call<{ id?: string; message?: { id?: string; threadId?: string } }>(account, {
      method: 'POST',
      path: `${BASE}/drafts`,
      json: { message },
      capability: 'draft',
    });
    if (typeof res.id !== 'string' || !res.id) throw new PerchError('Gmail returned no draft id', 'upstream_bad_response');
    const out: DraftResult = { draftId: res.id };
    if (res.message?.id) out.messageId = res.message.id;
    if (res.message?.threadId) out.threadId = res.message.threadId;
    return out;
  }

  /**
   * Exactly one request, never retried: a retry after a lost response could send twice. Anything
   * that fails before the request reaches the transport (scope, token, validation) throws instead.
   */
  async send(account: GmailAccount, mail: OutgoingMime): Promise<SendResult> {
    if (!this.providerCapabilities(account).send) {
      throw new PerchError(`Gmail account ${account.id} was not authorised to send (gmail.send or gmail.compose)`, 'capability_denied');
    }
    return this.submit(account, `${BASE}/messages/send`, outgoingMessage(mail));
  }

  /**
   * One POST to a send route, never retried. 4xx = rejected (not sent); anything after the request may have
   * reached Google = indeterminate; failures before the transport (token, allowlist) throw.
   */
  private async submit(account: GmailAccount, path: string, json: unknown): Promise<SendResult> {
    const headers = await this.auth(account);
    let body: Buffer;
    try {
      ({ body } = await this.upstream.raw('gmail', { method: 'POST', path, headers, json, capability: 'send' }));
    } catch (err) {
      // Blocked by the allowlist: nothing left the process.
      if (err instanceof PerchError && err.code === 'route_not_allowed') throw err;
      if (err instanceof UpstreamError && err.status >= 400 && err.status < 500) {
        if (err.status === 401) this.tokens.invalidate?.(account.id);
        return { status: 'rejected', detail: `Not sent: ${err.message}` };
      }
      return { status: 'indeterminate', detail: INDETERMINATE_NOTE };
    }
    // 2xx means accepted even if the body cannot be parsed; the id is then simply unknown.
    let id: unknown;
    try {
      id = (JSON.parse(body.toString('utf8')) as { id?: unknown }).id;
    } catch {
      id = undefined;
    }
    return {
      status: 'accepted',
      ...(typeof id === 'string' && id ? { providerMessageId: id } : {}),
      detail: ACCEPTED_NOTE,
    };
  }

  // ---- organizing (gmail.modify) and sending existing drafts --------------------------------------------

  private requireModify(account: GmailAccount): void {
    if (this.providerCapabilities(account).modify) return;
    throw new PerchError(
      `Gmail account ${account.id} was not authorised to organize mail (gmail.modify). Reconnect it with --allow-modify: ` +
        `\`perch gmail remove ${account.id}\`, then \`perch gmail add --allow-modify --label <label>\`.`,
      'provider_scope_missing',
    );
  }

  /** labels.modify on one message (route tag mail_modify). */
  private async modify(account: GmailAccount, messageId: string, add: string[], remove: string[]): Promise<OrganizeResult> {
    this.requireModify(account);
    const id = checkMessageId(messageId);
    await this.call<unknown>(account, {
      method: 'POST',
      path: `${BASE}/messages/${id}/modify`,
      json: { ...(add.length ? { addLabelIds: add } : {}), ...(remove.length ? { removeLabelIds: remove } : {}) },
      capability: 'mail_modify',
    });
    return { messageId: id };
  }

  async listFolders(account: GmailAccount): Promise<MailFolder[]> {
    const res = await this.get<{ labels?: Array<{ id?: unknown; name?: unknown; type?: unknown }> }>(account, `${BASE}/labels`);
    return (res.labels ?? [])
      .filter((l): l is { id: string; name: unknown; type: unknown } => typeof l.id === 'string' && LABEL_ID.test(l.id))
      .map((l) => ({
        folderId: l.id,
        name: typeof l.name === 'string' ? l.name : l.id,
        role: LABEL_ROLES[l.id] ?? 'other',
        type: l.type === 'system' ? ('system' as const) : ('user' as const),
      }));
  }

  async listDrafts(account: GmailAccount, opts: { pageSize: number }, cursor: string | undefined): Promise<SourcePage<MailDraftSummary>> {
    if (cursor !== undefined && !PAGE_TOKEN.test(cursor)) throw new PerchError('Invalid cursor', 'bad_cursor');
    const list = await this.get<{ drafts?: Array<{ id?: unknown }>; nextPageToken?: unknown }>(account, `${BASE}/drafts`, {
      maxResults: opts.pageSize,
      pageToken: cursor,
    });
    const ids = (list.drafts ?? []).map((d) => d.id).filter((id): id is string => typeof id === 'string' && MESSAGE_ID.test(id));
    const items = await mapBounded(ids, METADATA_CONCURRENCY, async (draftId) => {
      const d = await this.get<{ message?: GmailMessageResource }>(account, `${BASE}/drafts/${draftId}`, { format: 'metadata' });
      const m = d.message ?? {};
      const h = m.payload?.headers;
      const out: MailDraftSummary = { draftId };
      if (m.id) out.messageId = m.id;
      const subject = header(h, 'Subject');
      if (subject !== undefined) out.subject = subject;
      const to = splitAddresses(header(h, 'To'));
      if (to) out.to = to;
      const date = isoFromInternalDate(m.internalDate);
      if (date) out.date = date;
      return out;
    });
    const next = typeof list.nextPageToken === 'string' && PAGE_TOKEN.test(list.nextPageToken) ? list.nextPageToken : null;
    return { items, next };
  }

  markMessage(account: GmailAccount, messageId: string, change: MarkChange): Promise<OrganizeResult> {
    const add: string[] = [];
    const remove: string[] = [];
    if (change.read !== undefined) (change.read ? remove : add).push('UNREAD');
    if (change.starred !== undefined) (change.starred ? add : remove).push('STARRED');
    return this.modify(account, messageId, add, remove);
  }

  /**
   * Gmail has labels, not folders: moving adds the target label and removes INBOX (what "Move to" does in Gmail);
   * moving to INBOX only adds INBOX; archiving only removes INBOX. TRASH is reached through trashMessage only.
   */
  async moveMessage(account: GmailAccount, messageId: string, target: MoveTarget): Promise<OrganizeResult> {
    if (target.archive) {
      if (target.folderId !== undefined) throw new PerchError('Gmail archive takes no folderId (it removes the INBOX label)', 'bad_argument');
      return { ...(await this.modify(account, messageId, [], ['INBOX'])), folderId: 'ARCHIVE' };
    }
    const label = target.folderId;
    if (typeof label !== 'string' || !LABEL_ID.test(label)) throw new PerchError('folderId must be a Gmail label id from mail_list_folders', 'bad_argument');
    if (UNMOVABLE_LABELS.has(label)) {
      throw new PerchError(`Cannot move to ${label}${label === 'TRASH' ? '; use mail_trash_message' : ''}`, 'bad_argument');
    }
    const res = label === 'INBOX' ? await this.modify(account, messageId, ['INBOX'], []) : await this.modify(account, messageId, [label], ['INBOX']);
    return { ...res, folderId: label };
  }

  async trashMessage(account: GmailAccount, messageId: string): Promise<OrganizeResult> {
    this.requireModify(account);
    const id = checkMessageId(messageId);
    await this.call<unknown>(account, { method: 'POST', path: `${BASE}/messages/${id}/trash`, capability: 'mail_modify' });
    return { messageId: id, folderId: 'TRASH' };
  }

  async restoreMessage(account: GmailAccount, messageId: string): Promise<OrganizeResult> {
    this.requireModify(account);
    const id = checkMessageId(messageId);
    await this.call<unknown>(account, { method: 'POST', path: `${BASE}/messages/${id}/untrash`, capability: 'mail_modify' });
    return { messageId: id };
  }

  /** users.drafts.send: Gmail sends the stored draft as is (Bcc handled by Gmail). Exactly one attempt. */
  async sendDraft(account: GmailAccount, draftId: string): Promise<SendResult> {
    if (!this.canSendDraft(account)) {
      throw new PerchError(`Gmail account ${account.id} was not authorised to send drafts (gmail.compose or gmail.modify)`, 'provider_scope_missing');
    }
    if (typeof draftId !== 'string' || !MESSAGE_ID.test(draftId)) throw new PerchError('Invalid Gmail draft id', 'bad_argument');
    return this.submit(account, `${BASE}/drafts/send`, { id: draftId });
  }
}

function toSummary(m: GmailMessageResource): MailSummary {
  const h = m.payload?.headers;
  const s: MailSummary = { messageId: m.id ?? '' };
  if (m.threadId) s.threadId = m.threadId;
  const from = header(h, 'From');
  if (from !== undefined) s.from = from;
  const to = splitAddresses(header(h, 'To'));
  if (to) s.to = to;
  const subject = header(h, 'Subject');
  if (subject !== undefined) s.subject = subject;
  const date = isoFromInternalDate(m.internalDate);
  if (date) s.date = date;
  if (m.snippet) s.snippet = m.snippet;
  return s;
}

/** Gmail's `raw` is the full RFC 5322 message, base64url-encoded; threadId keeps replies in the thread. */
function outgoingMessage(mail: OutgoingMime): { raw: string; threadId?: string } {
  if (mail.threadId !== undefined && !MESSAGE_ID.test(mail.threadId)) throw new PerchError('Invalid Gmail thread id', 'bad_argument');
  return { raw: mail.raw.toString('base64url'), ...(mail.threadId ? { threadId: mail.threadId } : {}) };
}

function flatten(part: GmailPart): GmailPart[] {
  return part.parts?.length ? part.parts.flatMap(flatten) : [part];
}

const mimeOf = (p: GmailPart) => (p.mimeType ?? '').toLowerCase();

/** Named parts (and explicit Content-Disposition: attachment) are attachments, never the body. */
function isAttachment(p: GmailPart): boolean {
  return !!p.filename || /^\s*attachment\b/i.test(header(p.headers, 'Content-Disposition') ?? '');
}

function threading(h: GmailHeader[] | undefined): Pick<MailMessage, 'internetMessageId' | 'inReplyTo' | 'references'> {
  const out: Pick<MailMessage, 'internetMessageId' | 'inReplyTo' | 'references'> = {};
  const id = header(h, 'Message-ID')?.trim();
  if (id) out.internetMessageId = id;
  const irt = header(h, 'In-Reply-To')?.trim();
  if (irt) out.inReplyTo = irt;
  const refs = header(h, 'References')?.split(/\s+/).filter(Boolean);
  if (refs?.length) out.references = refs;
  return out;
}

/** Gmail hands out body bytes in the part's declared charset; unknown charsets fall back to UTF-8. */
function decodeCharset(buf: Buffer, part: GmailPart): string {
  const charset = /charset\s*=\s*"?([A-Za-z0-9._:-]+)/i.exec(header(part.headers, 'Content-Type') ?? '')?.[1];
  if (charset) {
    try {
      return new TextDecoder(charset).decode(buf);
    } catch {
      // unsupported label: fall through
    }
  }
  return buf.toString('utf8');
}
