import { ImapFlow, type MessageEnvelopeObject, type MessageStructureObject } from 'imapflow';
import { PerchError } from '../errors.js';
import type { SourcePage } from '../fanout.js';
import type { ImapAccount } from '../store/credentialStore.js';
import { MAIL_TIMEOUTS, mailTlsOptions, validateHost, validatePort, type TestOnlyTlsTrust } from './imapPresets.js';
import { htmlToText } from './html.js';
import { SmtpSender } from './smtp.js';
import { prepareDraftForSmtp } from './draftMime.js';
import {
  ACCEPTED_NOTE,
  HARD_MAIL_MAX_BYTES,
  MAX_MAIL_PAGE_SIZE,
  type DraftResult,
  type MailDraftSummary,
  type MailFolder,
  type MailFolderRole,
  type MarkChange,
  type MoveTarget,
  type OrganizeResult,
  type ProviderCapabilities,
  type MailAttachmentContent,
  type MailAttachmentMeta,
  type MailMessage,
  type MailProvider,
  type MailSummary,
  type OutgoingMime,
  type ReadOptions,
  type ReplyContext,
  type SearchOptions,
  type SendResult,
} from './types.js';

/**
 * Generic IMAP (implicit TLS) adapter. Reading never changes mailbox state: every folder is
 * opened with EXAMINE (read-only lock), so \Seen flags are never set by Perch. Message ids are
 * bound to UIDVALIDITY because UIDs are only meaningful within one UIDVALIDITY epoch: if the
 * server rebuilds a mailbox, an old id could otherwise silently point at a different message.
 */

// ---- narrow session interface (unit-testable with a MOCK session) ----------------------------

export interface ImapMailboxLock {
  /** UIDVALIDITY of the opened mailbox as a decimal string. */
  uidValidity: string;
  release(): void;
}

/** One SEARCH criterion: everything, or IMAP TEXT (matches headers and body, server-side). */
export type ImapSearchQuery = { all: true } | { text: string };

export interface ImapFetchedMessage {
  uid: number;
  envelope?: MessageEnvelopeObject;
  internalDate?: Date | string;
  bodyStructure?: MessageStructureObject;
  size?: number;
  /** Raw header lines for Message-ID / In-Reply-To / References. */
  headers?: Buffer;
}

export interface ImapSession {
  /** EXAMINE the mailbox (read-only). Search/fetch/download act on it until release(). */
  openReadonly(mailbox: string): Promise<ImapMailboxLock>;
  /** UIDs matching the query in the open mailbox. */
  search(query: ImapSearchQuery): Promise<number[]>;
  /** envelope, internalDate, bodyStructure for the given UIDs. */
  fetchSummaries(uids: number[]): Promise<ImapFetchedMessage[]>;
  /** envelope, internalDate, bodyStructure, size and threading headers for one UID. */
  fetchMessage(uid: number): Promise<ImapFetchedMessage | undefined>;
  /** Decoded body part (text converted to UTF-8), at most maxBytes; undefined if absent. */
  download(uid: number, part: string, maxBytes: number): Promise<Buffer | undefined>;
  /** Path of the \Drafts special-use mailbox, if the server reports one. */
  draftsMailbox(): Promise<string | undefined>;
  append(mailbox: string, raw: Buffer, flags: string[]): Promise<{ uid?: number; uidValidity?: string }>;
  /** Every mailbox with its special-use flag (RFC 6154) and LIST flags. */
  listMailboxes(): Promise<ImapMailboxInfo[]>;
  /** SELECT the mailbox (read-write) for flag changes and moves until release(). */
  openWritable(mailbox: string): Promise<ImapMailboxLock>;
  /** UID STORE +FLAGS / -FLAGS on one message of the open (writable) mailbox. */
  setFlags(uid: number, add: string[], remove: string[]): Promise<void>;
  /**
   * Moves one message of the open (writable) mailbox. Only with MOVE (RFC 6851) or, as COPY + UID EXPUNGE of that
   * one UID, with UIDPLUS: a plain EXPUNGE could permanently remove other messages flagged \Deleted, so without
   * either extension it throws instead. Returns the new UID when the server reports it (COPYUID).
   */
  move(uid: number, destination: string): Promise<{ uid?: number; uidValidity?: string }>;
  /** Complete raw message source of one UID (open mailbox), at most maxBytes. */
  downloadSource(uid: number, maxBytes: number): Promise<Buffer | undefined>;
  logout(): Promise<void>;
}

export interface ImapMailboxInfo {
  path: string;
  name?: string;
  specialUse?: string;
  /** LIST flags such as \Noselect. */
  flags?: string[];
}

// ---- imapflow implementation -----------------------------------------------------------------

const SUMMARY_QUERY = { uid: true, envelope: true, internalDate: true, bodyStructure: true } as const;
const MESSAGE_QUERY = { ...SUMMARY_QUERY, size: true, headers: ['message-id', 'in-reply-to', 'references'] };

export class ImapflowSession implements ImapSession {
  constructor(private readonly client: ImapFlow) {}

  async openReadonly(mailbox: string): Promise<ImapMailboxLock> {
    const lock = await this.client.getMailboxLock(mailbox, { readOnly: true });
    const mb = this.client.mailbox;
    if (!mb || typeof mb !== 'object' || mb.uidValidity === undefined) {
      lock.release();
      throw new PerchError(`Could not open folder "${mailbox}"`, 'imap_error');
    }
    return { uidValidity: String(mb.uidValidity), release: () => lock.release() };
  }

  async search(query: ImapSearchQuery): Promise<number[]> {
    const uids = await this.client.search(query, { uid: true });
    if (!Array.isArray(uids)) throw new PerchError('IMAP search failed', 'imap_error');
    return uids;
  }

  async fetchSummaries(uids: number[]): Promise<ImapFetchedMessage[]> {
    if (!uids.length) return [];
    const out: ImapFetchedMessage[] = [];
    for await (const m of this.client.fetch(uids.join(','), { ...SUMMARY_QUERY }, { uid: true })) out.push(m);
    return out;
  }

  async fetchMessage(uid: number): Promise<ImapFetchedMessage | undefined> {
    return (await this.client.fetchOne(String(uid), { ...MESSAGE_QUERY }, { uid: true })) || undefined;
  }

  async download(uid: number, part: string, maxBytes: number): Promise<Buffer | undefined> {
    const res = await this.client.download(String(uid), part, { uid: true, maxBytes });
    if (!res.content) return undefined;
    const chunks: Buffer[] = [];
    let total = 0;
    // imapflow already caps the stream at maxBytes; the local cap is defence in depth.
    for await (const chunk of res.content as AsyncIterable<Buffer>) {
      chunks.push(chunk);
      total += chunk.length;
      if (total >= maxBytes) {
        res.content.destroy();
        break;
      }
    }
    return Buffer.concat(chunks).subarray(0, maxBytes);
  }

  async draftsMailbox(): Promise<string | undefined> {
    return (await this.client.list()).find((m) => m.specialUse === '\\Drafts')?.path;
  }

  async append(mailbox: string, raw: Buffer, flags: string[]): Promise<{ uid?: number; uidValidity?: string }> {
    const res = await this.client.append(mailbox, raw, flags);
    if (!res) throw new PerchError(`Could not save the draft to "${mailbox}"`, 'imap_error');
    return {
      ...(res.uid ? { uid: res.uid } : {}),
      ...(res.uidValidity !== undefined ? { uidValidity: String(res.uidValidity) } : {}),
    };
  }

  async listMailboxes(): Promise<ImapMailboxInfo[]> {
    return (await this.client.list()).map((m) => ({
      path: m.path,
      ...(m.name ? { name: m.name } : {}),
      ...(m.specialUse ? { specialUse: m.specialUse } : {}),
      ...(m.flags ? { flags: [...m.flags] } : {}),
    }));
  }

  async openWritable(mailbox: string): Promise<ImapMailboxLock> {
    const lock = await this.client.getMailboxLock(mailbox, { readOnly: false });
    const mb = this.client.mailbox;
    if (!mb || typeof mb !== 'object' || mb.uidValidity === undefined || mb.readOnly) {
      lock.release();
      throw new PerchError(`Could not open folder "${mailbox}" for changes`, 'imap_error');
    }
    return { uidValidity: String(mb.uidValidity), release: () => lock.release() };
  }

  async setFlags(uid: number, add: string[], remove: string[]): Promise<void> {
    if (add.length && !(await this.client.messageFlagsAdd(String(uid), add, { uid: true }))) {
      throw new PerchError('The server refused to change the message flags', 'imap_error');
    }
    if (remove.length && !(await this.client.messageFlagsRemove(String(uid), remove, { uid: true }))) {
      throw new PerchError('The server refused to change the message flags', 'imap_error');
    }
  }

  async move(uid: number, destination: string): Promise<{ uid?: number; uidValidity?: string }> {
    const caps = this.client.capabilities;
    if (!caps.has('MOVE') && !caps.has('UIDPLUS')) {
      throw new PerchError(
        'This IMAP server supports neither MOVE nor UIDPLUS; Perch does not move messages there (a plain EXPUNGE could delete other messages)',
        'imap_move_unsupported',
      );
    }
    const res = await this.client.messageMove(String(uid), destination, { uid: true });
    if (!res) throw new PerchError(`Could not move the message to "${destination}"`, 'imap_error');
    const newUid = res.uidMap?.get(uid);
    return {
      ...(newUid ? { uid: newUid } : {}),
      ...(res.uidValidity !== undefined ? { uidValidity: String(res.uidValidity) } : {}),
    };
  }

  async downloadSource(uid: number, maxBytes: number): Promise<Buffer | undefined> {
    const res = await this.client.download(String(uid), undefined, { uid: true, maxBytes });
    if (!res.content) return undefined;
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of res.content as AsyncIterable<Buffer>) {
      chunks.push(chunk);
      total += chunk.length;
      if (total >= maxBytes) {
        res.content.destroy();
        break;
      }
    }
    return Buffer.concat(chunks).subarray(0, maxBytes);
  }

  async logout(): Promise<void> {
    try {
      await this.client.logout();
    } catch {
      this.client.close();
    }
  }
}

const CERT_ERROR = /CERT|SELF_SIGNED|UNABLE_TO_(VERIFY|GET)|ALTNAME|HOSTNAME|ERR_SSL|ERR_TLS|EPROTO/;

/** Maps connect/login failures to messages that are useful but never echo credentials or server text. */
function connectError(err: unknown, host: string, port: number): PerchError {
  const e = err as { authenticationFailed?: boolean; code?: string; message?: string };
  if (e?.authenticationFailed) {
    return new PerchError('IMAP login failed (check app password / IMAP access enabled)', 'imap_auth');
  }
  if (CERT_ERROR.test(String(e?.code ?? '')) || /certificate|ssl|tls/i.test(String(e?.message ?? ''))) {
    return new PerchError(`TLS verification failed for IMAP server ${host}:${port} (certificate or TLS version not acceptable)`, 'imap_tls');
  }
  return new PerchError(`Could not connect to IMAP server ${host}:${port}`, 'imap_connect');
}

/** Opens an authenticated imapflow session: implicit TLS only, verified certificate, no logging. */
export async function openImapflowSession(account: ImapAccount, opts: { testOnlyTlsTrust?: TestOnlyTlsTrust } = {}): Promise<ImapSession> {
  const host = validateHost('imap host', account.imap.host);
  const port = validatePort('imap port', account.imap.port);
  const client = new ImapFlow({
    host,
    port,
    secure: true,
    servername: host,
    auth: { user: account.username, pass: account.password },
    tls: mailTlsOptions(host, opts.testOnlyTlsTrust),
    logger: false,
    emitLogs: false,
    disableAutoIdle: true,
    connectionTimeout: MAIL_TIMEOUTS.connectionMs,
    greetingTimeout: MAIL_TIMEOUTS.greetingMs,
    socketTimeout: MAIL_TIMEOUTS.socketMs,
    // Memory bounds against a hostile server; bodies are downloaded in bounded chunks anyway.
    maxLiteralSize: 16 * 1024 * 1024,
    maxResponseSize: 32 * 1024 * 1024,
  });
  // Failures surface through rejected promises; an unhandled 'error' event would crash the process.
  client.on('error', () => {});
  try {
    await client.connect();
  } catch (err) {
    client.close();
    throw connectError(err, host, port);
  }
  return new ImapflowSession(client);
}

// ---- ids, cursors, validation ----------------------------------------------------------------

const MAX_U32 = 4294967295;
const ID_RE = /^imap:([A-Za-z0-9_-]{1,400}):([1-9][0-9]{0,9}):([1-9][0-9]{0,9})$/;
const CURSOR_RE = /^([1-9][0-9]{0,9}):([1-9][0-9]{0,9})$/;
const PART_RE = /^[1-9][0-9]{0,4}(?:\.[1-9][0-9]{0,4}){0,20}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

export function validateFolder(folder: string): string {
  if (typeof folder !== 'string' || folder.length < 1 || folder.length > 200 || CONTROL.test(folder)) {
    throw new PerchError('folder must be 1-200 characters without control characters', 'bad_argument');
  }
  return folder;
}

export function encodeImapMessageId(mailbox: string, uidValidity: string, uid: number): string {
  return `imap:${Buffer.from(mailbox, 'utf8').toString('base64url')}:${uidValidity}:${uid}`;
}

export function decodeImapMessageId(id: string): { mailbox: string; uidValidity: string; uid: number } {
  const bad = () => new PerchError('Invalid IMAP message id', 'bad_message_id');
  const m = typeof id === 'string' ? ID_RE.exec(id) : null;
  if (!m) throw bad();
  const mailbox = Buffer.from(m[1]!, 'base64url').toString('utf8');
  // Canonical round trip only: one id per message, no smuggled bytes.
  if (Buffer.from(mailbox, 'utf8').toString('base64url') !== m[1]) throw bad();
  const uidValidity = Number(m[2]);
  const uid = Number(m[3]);
  if (uidValidity > MAX_U32 || uid > MAX_U32) throw bad();
  try {
    validateFolder(mailbox);
  } catch {
    throw bad();
  }
  return { mailbox, uidValidity: m[2]!, uid };
}

function decodeCursor(cursor: string, uidValidity: string): number {
  const m = CURSOR_RE.exec(cursor);
  if (!m || Number(m[2]) > MAX_U32) throw new PerchError('Invalid cursor', 'bad_cursor');
  if (m[1] !== uidValidity) {
    throw new PerchError('The folder was rebuilt on the server since the last page (UIDVALIDITY changed); search again', 'bad_cursor');
  }
  return Number(m[2]);
}

/** Largest stored draft Perch reads for sending (10 MiB attachments base64-encoded plus headers and text). */
const MAX_DRAFT_BYTES = 16 * 1024 * 1024;

const SPECIAL_USE_ROLES: Record<string, MailFolderRole> = {
  '\\sent': 'sent',
  '\\drafts': 'drafts',
  '\\trash': 'trash',
  '\\archive': 'archive',
  '\\all': 'all',
  '\\junk': 'junk',
  '\\flagged': 'starred',
  '\\important': 'important',
};

function checkMaxBytes(n: number): number {
  if (!Number.isInteger(n) || n < 1 || n > HARD_MAIL_MAX_BYTES) {
    throw new PerchError(`maxBytes must be between 1 and ${HARD_MAIL_MAX_BYTES}`, 'bad_argument');
  }
  return n;
}

// ---- message structure helpers ---------------------------------------------------------------

interface Leaf {
  part: string;
  node: MessageStructureObject;
}

/** Leaf parts in order; message/rfc822 is a leaf (an attached mail, not part of this body). */
function leaves(node: MessageStructureObject | undefined, out: Leaf[] = []): Leaf[] {
  if (!node) return out;
  const type = node.type.toLowerCase();
  if (type.startsWith('multipart/')) {
    for (const c of node.childNodes ?? []) leaves(c, out);
  } else {
    // A single-part message has no part number in BODYSTRUCTURE; its body is part "1".
    out.push({ part: node.part ?? '1', node });
  }
  return out;
}

const filenameOf = (n: MessageStructureObject) => n.dispositionParameters?.filename ?? n.parameters?.name;

function isAttachment(n: MessageStructureObject): boolean {
  return n.disposition?.toLowerCase() === 'attachment' || filenameOf(n) !== undefined || n.type.toLowerCase() === 'message/rfc822';
}

function attachmentsOf(structure: MessageStructureObject | undefined): MailAttachmentMeta[] {
  return leaves(structure)
    .filter((l) => isAttachment(l.node))
    .map(({ part, node }) => {
      const filename = filenameOf(node);
      return {
        attachmentId: part,
        ...(filename !== undefined ? { filename } : {}),
        contentType: node.type.toLowerCase(),
        ...(node.size !== undefined ? { size: node.size } : {}),
        inline: node.disposition?.toLowerCase() === 'inline',
      };
    });
}

function formatAddress(a: { name?: string; address?: string }): string | undefined {
  if (!a.address) return a.name || undefined;
  return a.name ? `${a.name} <${a.address}>` : a.address;
}

const addressList = (list: Array<{ name?: string; address?: string }> | undefined) =>
  (list ?? []).map(formatAddress).filter((x): x is string => !!x);

function isoDate(...candidates: Array<Date | string | undefined>): string | undefined {
  for (const c of candidates) {
    if (c === undefined) continue;
    const d = c instanceof Date ? c : new Date(c);
    if (!Number.isNaN(d.getTime())) return d.toISOString();
  }
  return undefined;
}

function parseHeaders(buf: Buffer | undefined): Map<string, string> {
  const map = new Map<string, string>();
  if (!buf) return map;
  const unfolded = buf.toString('utf8').replace(/\r?\n[ \t]+/g, ' ');
  for (const line of unfolded.split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i > 0) map.set(line.slice(0, i).trim().toLowerCase(), line.slice(i + 1).trim());
  }
  return map;
}

const msgIds = (v: string | undefined) => (v ? (v.match(/<[^<>\s]+>/g) ?? []) : []);

/** Cuts to at most maxBytes without splitting a UTF-8 sequence. */
export function cutUtf8(buf: Buffer, maxBytes: number): string {
  if (buf.length <= maxBytes) return buf.toString('utf8');
  let end = maxBytes;
  while (end > 0 && (buf[end]! & 0xc0) === 0x80) end--;
  return buf.subarray(0, end).toString('utf8');
}

// ---- Sent copy -------------------------------------------------------------------------------

/**
 * SMTP servers that file every submitted message in the account's Sent folder themselves (Gmail's SMTP, Microsoft
 * 365 / Outlook.com SMTP AUTH). An extra APPEND there would leave each sent mail twice, so the default for these
 * hosts is "no Sent copy". Everything else (e.g. GMX, which only files web-mail sends) gets a copy by default.
 */
const SMTP_HOSTS_FILING_SENT = new Set(['smtp.gmail.com', 'smtp.googlemail.com', 'smtp.office365.com', 'smtp-mail.outlook.com']);

/** Whether Perch APPENDs a copy of an accepted SMTP send to the Sent folder: explicit setting, else by SMTP host. */
export function imapSentCopyEnabled(account: Pick<ImapAccount, 'sentCopy' | 'smtp'>): boolean {
  if (typeof account.sentCopy === 'boolean') return account.sentCopy;
  return !SMTP_HOSTS_FILING_SENT.has(account.smtp.host.toLowerCase());
}

/** Common Sent folder names, tried in order when the server reports no \Sent special-use mailbox. */
const SENT_FALLBACK_NAMES = ['Sent', 'Sent Items', 'Sent Messages', 'Sent Mail', 'Gesendet', 'Gesendete Objekte', 'Gesendete Elemente', 'INBOX.Sent', 'INBOX/Sent', '[Gmail]/Sent Mail'];

/** The \Sent special-use mailbox, else the first selectable mailbox with a common Sent name (case-insensitive). */
export function sentMailboxOf(list: ImapMailboxInfo[]): string | undefined {
  const selectable = list.filter((m) => !(m.flags ?? []).some((f) => f.toLowerCase() === '\\noselect' || f.toLowerCase() === '\\nonexistent'));
  const special = selectable.find((m) => m.specialUse?.toLowerCase() === '\\sent');
  if (special) return special.path;
  for (const name of SENT_FALLBACK_NAMES) {
    const hit = selectable.find((m) => m.path.toLowerCase() === name.toLowerCase());
    if (hit) return hit.path;
  }
  return undefined;
}

const SENT_COPY_FILED = (box: string) => ` A copy was filed in "${box}".`;
const SENT_COPY_FAILED = ' The message was sent, but no copy could be filed in the Sent folder (sentCopy: false). It was NOT sent again; do not resend it.';
const SENT_COPY_OFF = ' No copy was filed in Sent: turned off for this account, or its SMTP server files sent mail itself (sentCopy: false).';

// ---- provider --------------------------------------------------------------------------------

export type ImapSessionFactory = (account: ImapAccount) => Promise<ImapSession>;

export class ImapMailProvider implements MailProvider<ImapAccount> {
  readonly kind = 'imap' as const;
  private readonly sessionFactory: ImapSessionFactory;
  private readonly smtp: SmtpSender;

  constructor(opts: { sessionFactory?: ImapSessionFactory; smtp?: SmtpSender } = {}) {
    this.sessionFactory = opts.sessionFactory ?? ((a) => openImapflowSession(a));
    this.smtp = opts.smtp ?? new SmtpSender();
  }

  providerCapabilities(account: ImapAccount): ProviderCapabilities {
    return { draft: account.allowDrafts, send: account.allowSend, modify: account.allowModify === true };
  }

  /** Sending a stored draft is sending: the allowSend opt-in (the draft is then moved to Sent). */
  canSendDraft(account: ImapAccount): boolean {
    return account.allowSend;
  }

  /** One connection per call, always logged out (also on error). */
  private async withSession<T>(account: ImapAccount, fn: (s: ImapSession) => Promise<T>): Promise<T> {
    const session = await this.sessionFactory(account);
    try {
      return await fn(session);
    } finally {
      await session.logout().catch(() => {});
    }
  }

  /** Opens the mailbox read-only for the duration of fn; the lock is always released. */
  private async withMailbox<T>(account: ImapAccount, mailbox: string, fn: (s: ImapSession, uidValidity: string) => Promise<T>): Promise<T> {
    return this.withSession(account, async (s) => {
      const lock = await s.openReadonly(mailbox);
      try {
        return await fn(s, lock.uidValidity);
      } finally {
        lock.release();
      }
    });
  }

  /** Opens the id's mailbox and refuses ids from another UIDVALIDITY epoch. */
  private withMessage<T>(account: ImapAccount, messageId: string, fn: (s: ImapSession, uid: number, mailbox: string) => Promise<T>) {
    const id = decodeImapMessageId(messageId);
    return this.withMailbox(account, id.mailbox, async (s, uidValidity) => {
      if (uidValidity !== id.uidValidity) {
        throw new PerchError(
          'This message id is no longer valid: the folder was rebuilt on the server (UIDVALIDITY changed). Search again to get current ids.',
          'stale_message_id',
        );
      }
      return fn(s, id.uid, id.mailbox);
    });
  }

  private static async fetchExisting(s: ImapSession, uid: number): Promise<ImapFetchedMessage> {
    const msg = await s.fetchMessage(uid);
    if (!msg) throw new PerchError('Message not found (it may have been moved or deleted)', 'not_found');
    return msg;
  }

  /**
   * Search uses IMAP SEARCH TEXT (header + body substring, evaluated by the server) or ALL.
   * Results are newest first by UID. The cursor is "<uidValidity>:<last uid returned>" so a page
   * continues strictly below the last UID and is refused if the folder was rebuilt meanwhile.
   */
  async search(account: ImapAccount, opts: SearchOptions, cursor: string | undefined): Promise<SourcePage<MailSummary>> {
    const folder = validateFolder(opts.folder ?? 'INBOX');
    const pageSize = Math.min(Math.max(1, Math.trunc(opts.pageSize) || 1), MAX_MAIL_PAGE_SIZE);
    const q = opts.query?.trim();
    if (q && (q.length > 500 || CONTROL.test(q))) throw new PerchError('query must be at most 500 characters without control characters', 'bad_argument');
    return this.withMailbox(account, folder, (s, uidValidity) => this.page(s, folder, uidValidity, q ? { text: q } : { all: true }, pageSize, cursor));
  }

  /** One page of the open mailbox, newest UID first (see search). */
  private async page(s: ImapSession, folder: string, uidValidity: string, query: ImapSearchQuery, pageSize: number, cursor: string | undefined) {
    const below = cursor ? decodeCursor(cursor, uidValidity) : Infinity;
    const uids = (await s.search(query)).filter((u) => u < below).sort((a, b) => b - a);
    const page = uids.slice(0, pageSize);
    const fetched = new Map((await s.fetchSummaries(page)).map((m) => [m.uid, m]));
    const items = page
      .map((uid) => fetched.get(uid))
      .filter((m): m is ImapFetchedMessage => !!m)
      .map((m) => this.summary(folder, uidValidity, m));
    return { items, next: uids.length > pageSize ? `${uidValidity}:${page[page.length - 1]}` : null };
  }

  private summary(folder: string, uidValidity: string, m: ImapFetchedMessage): MailSummary {
    const env = m.envelope ?? {};
    const from = addressList(env.from)[0];
    const date = isoDate(env.date, m.internalDate);
    return {
      messageId: encodeImapMessageId(folder, uidValidity, m.uid),
      folder,
      ...(from ? { from } : {}),
      to: addressList(env.to),
      ...(env.subject !== undefined ? { subject: env.subject } : {}),
      ...(date ? { date } : {}),
      hasAttachments: attachmentsOf(m.bodyStructure).length > 0,
    };
  }

  async read(account: ImapAccount, messageId: string, opts: ReadOptions): Promise<MailMessage> {
    const maxBytes = checkMaxBytes(opts.maxBytes);
    return this.withMessage(account, messageId, async (s, uid, mailbox) => {
      const msg = await ImapMailProvider.fetchExisting(s, uid);
      const env = msg.envelope ?? {};
      const headers = parseHeaders(msg.headers);
      const body = leaves(msg.bodyStructure).filter((l) => !isAttachment(l.node));
      const plain = body.find((l) => l.node.type.toLowerCase() === 'text/plain');
      const html = plain ? undefined : body.find((l) => l.node.type.toLowerCase() === 'text/html');
      let text: string | undefined;
      let truncated = false;
      // Parts are downloaded individually with maxBytes+1, so one extra byte reveals truncation
      // and the full message source is never pulled into memory.
      if (plain) {
        const buf = (await s.download(uid, plain.part, maxBytes + 1)) ?? Buffer.alloc(0);
        truncated = buf.length > maxBytes;
        text = cutUtf8(buf, maxBytes);
      } else if (html) {
        const buf = (await s.download(uid, html.part, maxBytes + 1)) ?? Buffer.alloc(0);
        const derived = htmlToText(cutUtf8(buf, maxBytes), maxBytes);
        truncated = buf.length > maxBytes || derived.truncated;
        text = derived.text;
      }
      const internetMessageId = msgIds(headers.get('message-id'))[0] ?? env.messageId;
      const inReplyTo = msgIds(headers.get('in-reply-to'))[0] ?? env.inReplyTo;
      const cc = addressList(env.cc);
      const replyTo = addressList(env.replyTo);
      return {
        ...this.summary(mailbox, decodeImapMessageId(messageId).uidValidity, msg),
        ...(cc.length ? { cc } : {}),
        ...(replyTo.length ? { replyTo } : {}),
        ...(internetMessageId ? { internetMessageId } : {}),
        ...(inReplyTo ? { inReplyTo } : {}),
        references: msgIds(headers.get('references')),
        ...(text !== undefined ? { text, textSource: plain ? ('text/plain' as const) : ('text/html' as const) } : {}),
        truncated,
        attachments: attachmentsOf(msg.bodyStructure),
      };
    });
  }

  async getAttachment(account: ImapAccount, messageId: string, attachmentId: string, opts: ReadOptions): Promise<MailAttachmentContent> {
    const maxBytes = checkMaxBytes(opts.maxBytes);
    if (typeof attachmentId !== 'string' || !PART_RE.test(attachmentId)) throw new PerchError('Invalid attachment id', 'bad_argument');
    return this.withMessage(account, messageId, async (s, uid) => {
      const msg = await ImapMailProvider.fetchExisting(s, uid);
      const leaf = leaves(msg.bodyStructure).find((l) => l.part === attachmentId && isAttachment(l.node));
      if (!leaf) throw new PerchError('Attachment not found in this message', 'not_found');
      const tooLarge = () =>
        new PerchError(`Attachment is larger than maxBytes (${maxBytes}); it is never returned truncated`, 'attachment_too_large');
      // Refuse before downloading: BODYSTRUCTURE reports the encoded size (base64 = 4/3 of decoded).
      const encoded = leaf.node.size ?? 0;
      const estimate = leaf.node.encoding?.toLowerCase() === 'base64' ? Math.floor((encoded * 3) / 4) : encoded;
      if (estimate > maxBytes) throw tooLarge();
      const content = await s.download(uid, leaf.part, maxBytes + 1);
      if (!content) throw new PerchError('Attachment not found in this message', 'not_found');
      if (content.length > maxBytes) throw tooLarge();
      const filename = filenameOf(leaf.node);
      return {
        attachmentId,
        ...(filename !== undefined ? { filename } : {}),
        contentType: leaf.node.type.toLowerCase(),
        size: content.length,
        contentBase64: content.toString('base64'),
      };
    });
  }

  async replyContext(account: ImapAccount, messageId: string): Promise<ReplyContext> {
    return this.withMessage(account, messageId, async (s, uid) => {
      const msg = await ImapMailProvider.fetchExisting(s, uid);
      const headers = parseHeaders(msg.headers);
      const internetMessageId = msgIds(headers.get('message-id'))[0] ?? msg.envelope?.messageId;
      return {
        ...(internetMessageId ? { internetMessageId } : {}),
        references: msgIds(headers.get('references')),
        ...(msg.envelope?.subject !== undefined ? { subject: msg.envelope.subject } : {}),
      };
    });
  }

  /** Saves the message (Bcc kept) to the drafts folder with \Draft and \Seen; nothing is sent. */
  async createDraft(account: ImapAccount, mail: OutgoingMime): Promise<DraftResult> {
    if (!account.allowDrafts) {
      throw new PerchError(`Drafts are not enabled for ${account.id}. Re-add the account with drafts allowed.`, 'not_permitted');
    }
    return this.withSession(account, async (s) => {
      const mailbox = validateFolder(account.draftsMailbox ?? (await s.draftsMailbox()) ?? 'Drafts');
      const res = await s.append(mailbox, mail.raw, ['\\Draft', '\\Seen']);
      // Without UIDPLUS the server reports no APPENDUID, so there is no stable id to return.
      return { draftId: res.uid && res.uidValidity ? encodeImapMessageId(mailbox, res.uidValidity, res.uid) : 'appended' };
    });
  }

  /**
   * One SMTP submission (never retried). Only after SMTP accepted it, a copy (with Bcc, the sender's own record) is
   * APPENDed to the Sent folder with \Seen, when the account files Sent copies. A failing APPEND never changes the
   * outcome and never causes a second submission: the result stays accepted with sentCopy: false.
   */
  async send(account: ImapAccount, mail: OutgoingMime): Promise<SendResult> {
    if (!account.allowSend) {
      throw new PerchError(`Sending is not enabled for ${account.id}. Re-add the account with sending allowed.`, 'not_permitted');
    }
    const result = await this.smtp.send(account, mail.raw, mail.envelope);
    if (result.status !== 'accepted') return result;
    const detail = result.detail.startsWith(ACCEPTED_NOTE) ? result.detail : ACCEPTED_NOTE;
    if (!imapSentCopyEnabled(account)) return { ...result, detail: detail + SENT_COPY_OFF, sentCopy: false };
    try {
      const box = await this.withSession(account, async (s) => {
        const sent = sentMailboxOf(await s.listMailboxes());
        if (!sent) return undefined;
        await s.append(validateFolder(sent), mail.sentCopy ?? mail.raw, ['\\Seen']);
        return sent;
      });
      if (box) return { ...result, detail: detail + SENT_COPY_FILED(box), sentCopy: true };
    } catch {
      // fall through: reported below, never retried over SMTP
    }
    return { ...result, detail: detail + SENT_COPY_FAILED, sentCopy: false };
  }
  // ---- organizing (allowModify opt-in) and sending existing drafts (allowSend) ---------------------------

  private requireModify(account: ImapAccount): void {
    if (account.allowModify === true) return;
    throw new PerchError(
      `Organizing mail is not enabled for ${account.id}. Re-add the account with --allow-modify: ` +
        `\`perch imap remove ${account.id}\`, then \`perch imap add ... --allow-modify\`.`,
      'provider_scope_missing',
    );
  }

  /** Opens the id's mailbox read-write and refuses ids from another UIDVALIDITY epoch. */
  private withWritableMessage<T>(account: ImapAccount, messageId: string, fn: (s: ImapSession, uid: number, mailbox: string) => Promise<T>) {
    const id = decodeImapMessageId(messageId);
    return this.withSession(account, async (s) => {
      const lock = await s.openWritable(id.mailbox);
      try {
        if (lock.uidValidity !== id.uidValidity) {
          throw new PerchError(
            'This message id is no longer valid: the folder was rebuilt on the server (UIDVALIDITY changed). Search again to get current ids.',
            'stale_message_id',
          );
        }
        await ImapMailProvider.fetchExisting(s, id.uid);
        return await fn(s, id.uid, id.mailbox);
      } finally {
        lock.release();
      }
    });
  }

  private static selectable(list: ImapMailboxInfo[]): ImapMailboxInfo[] {
    return list.filter((m) => !(m.flags ?? []).some((f) => f.toLowerCase() === '\\noselect' || f.toLowerCase() === '\\nonexistent'));
  }

  private static special(list: ImapMailboxInfo[], use: string): string | undefined {
    return ImapMailProvider.selectable(list).find((m) => m.specialUse?.toLowerCase() === use.toLowerCase())?.path;
  }

  private async draftsPath(account: ImapAccount, s: ImapSession): Promise<string> {
    return validateFolder(account.draftsMailbox ?? (await s.draftsMailbox()) ?? 'Drafts');
  }

  /** Moves within one session; the destination must be an existing selectable mailbox other than the source. */
  private async moveIn(s: ImapSession, uid: number, from: string, to: string, list: ImapMailboxInfo[]): Promise<OrganizeResult> {
    if (!ImapMailProvider.selectable(list).some((m) => m.path === to)) throw new PerchError(`Unknown folder "${to}"`, 'bad_folder');
    if (to === from) throw new PerchError('The message is already in that folder', 'bad_argument');
    const res = await s.move(uid, to);
    if (res.uid && res.uidValidity) return { messageId: encodeImapMessageId(to, res.uidValidity, res.uid), folderId: to };
    return { folderId: to, note: 'The server did not report the new message id (no UIDPLUS); search the folder again.' };
  }

  async listFolders(account: ImapAccount): Promise<MailFolder[]> {
    return this.withSession(account, async (s) =>
      ImapMailProvider.selectable(await s.listMailboxes()).map((m) => ({
        folderId: m.path,
        name: m.name ?? m.path,
        role: m.path.toUpperCase() === 'INBOX' ? 'inbox' : (SPECIAL_USE_ROLES[m.specialUse?.toLowerCase() ?? ''] ?? 'other'),
        ...(m.specialUse ? { specialUse: m.specialUse } : {}),
      })),
    );
  }

  async listDrafts(account: ImapAccount, opts: { pageSize: number }, cursor: string | undefined): Promise<SourcePage<MailDraftSummary>> {
    const pageSize = Math.min(Math.max(1, Math.trunc(opts.pageSize) || 1), MAX_MAIL_PAGE_SIZE);
    return this.withSession(account, async (s) => {
      const mailbox = await this.draftsPath(account, s);
      const lock = await s.openReadonly(mailbox);
      try {
        const page = await this.page(s, mailbox, lock.uidValidity, { all: true }, pageSize, cursor);
        return {
          items: page.items.map((m) => ({
            draftId: m.messageId,
            ...(m.subject !== undefined ? { subject: m.subject } : {}),
            ...(m.to ? { to: m.to } : {}),
            ...(m.date ? { date: m.date } : {}),
          })),
          next: page.next,
        };
      } finally {
        lock.release();
      }
    });
  }

  async markMessage(account: ImapAccount, messageId: string, change: MarkChange): Promise<OrganizeResult> {
    this.requireModify(account);
    const add: string[] = [];
    const remove: string[] = [];
    if (change.read !== undefined) (change.read ? add : remove).push('\\Seen');
    if (change.starred !== undefined) (change.starred ? add : remove).push('\\Flagged');
    return this.withWritableMessage(account, messageId, async (s, uid) => {
      await s.setFlags(uid, add, remove);
      return { messageId };
    });
  }

  async moveMessage(account: ImapAccount, messageId: string, target: MoveTarget): Promise<OrganizeResult> {
    this.requireModify(account);
    if (target.folderId !== undefined) validateFolder(target.folderId);
    return this.withWritableMessage(account, messageId, async (s, uid, mailbox) => {
      const list = await s.listMailboxes();
      let to = target.folderId;
      if (target.archive && to === undefined) {
        to = ImapMailProvider.special(list, '\\Archive');
        if (!to) throw new PerchError('This server reports no \\Archive folder; pass folderId with archive: true', 'no_archive_folder');
      }
      if (to === undefined) throw new PerchError('folderId is required (or archive: true)', 'bad_argument');
      // A message moved into Drafts could then be re-sent with mail_send_draft (e.g. an old mail from Sent).
      if (to === (await this.draftsPath(account, s))) throw new PerchError('Perch does not move messages into the drafts folder', 'not_permitted');
      return this.moveIn(s, uid, mailbox, to, list);
    });
  }

  /** MOVE to the \Trash special-use mailbox (recoverable). Never \Deleted + EXPUNGE of the message itself. */
  async trashMessage(account: ImapAccount, messageId: string): Promise<OrganizeResult> {
    this.requireModify(account);
    return this.withWritableMessage(account, messageId, async (s, uid, mailbox) => {
      const list = await s.listMailboxes();
      const trash = ImapMailProvider.special(list, '\\Trash');
      if (!trash) throw new PerchError('This server reports no \\Trash folder; Perch does not guess one', 'no_trash_folder');
      if (trash === mailbox) throw new PerchError('The message is already in the trash', 'bad_argument');
      return this.moveIn(s, uid, mailbox, trash, list);
    });
  }

  /** Only a message in the \Trash mailbox is moved back, to INBOX. */
  async restoreMessage(account: ImapAccount, messageId: string): Promise<OrganizeResult> {
    this.requireModify(account);
    return this.withWritableMessage(account, messageId, async (s, uid, mailbox) => {
      const list = await s.listMailboxes();
      if (ImapMailProvider.special(list, '\\Trash') !== mailbox) throw new PerchError('This message is not in the trash', 'not_in_trash');
      return this.moveIn(s, uid, mailbox, 'INBOX', list);
    });
  }

  /**
   * Sends a stored draft: reads its raw MIME from the drafts mailbox, submits it over SMTP with the envelope from
   * its To/Cc/Bcc and WITHOUT the Bcc header, then (only when accepted) clears \Draft and moves it to the Sent
   * mailbox (\Sent special-use, else a common name). Without MOVE/UIDPLUS a copy is APPENDed to Sent instead (the
   * draft stays). Moving is done regardless of the sentCopy setting (it takes the sent draft out of Drafts so it is
   * not sent twice); the APPEND fallback follows the setting. Exactly one SMTP attempt; filing never changes the outcome.
   */
  async sendDraft(account: ImapAccount, draftId: string): Promise<SendResult> {
    if (!account.allowSend) {
      throw new PerchError(`Sending is not enabled for ${account.id}. Re-add the account with sending allowed.`, 'not_permitted');
    }
    const id = decodeImapMessageId(draftId);
    // Everything before SMTP throws a PerchError (nothing was submitted), also for unexpected IMAP failures.
    const raw = await this.withSession(account, async (s) => {
      if ((await this.draftsPath(account, s)) !== id.mailbox) throw new PerchError('This message is not in the drafts folder', 'not_a_draft');
      const lock = await s.openReadonly(id.mailbox);
      try {
        if (lock.uidValidity !== id.uidValidity) throw new PerchError('This draft id is no longer valid (UIDVALIDITY changed); list the drafts again', 'stale_message_id');
        await ImapMailProvider.fetchExisting(s, id.uid);
        const source = await s.downloadSource(id.uid, MAX_DRAFT_BYTES + 1);
        if (!source?.length) throw new PerchError('The draft could not be read', 'not_found');
        if (source.length > MAX_DRAFT_BYTES) throw new PerchError(`The draft is larger than ${MAX_DRAFT_BYTES} bytes`, 'message_too_large');
        return source;
      } finally {
        lock.release();
      }
    }).catch((err: unknown) => {
      if (err instanceof PerchError) throw err;
      throw new PerchError('The draft could not be read from the IMAP server', 'imap_error');
    });
    const ready = prepareDraftForSmtp(raw, account.email);
    const result = await this.smtp.send(account, ready.raw, ready.envelope);
    if (result.status !== 'accepted') return result;
    let filed: { note: string; sentCopy: boolean };
    try {
      filed = await this.withSession(account, async (s) => {
        const sent = sentMailboxOf(await s.listMailboxes());
        if (!sent) return { note: ' The server reports no Sent folder; the draft stays in the drafts folder. Do not send it again.', sentCopy: false };
        const lock = await s.openWritable(id.mailbox);
        let moveError: unknown;
        try {
          if (lock.uidValidity !== id.uidValidity) throw new Error('uidvalidity changed');
          await s.setFlags(id.uid, ['\\Seen'], ['\\Draft']);
          try {
            await s.move(id.uid, sent);
            return { note: ` The draft was moved to "${sent}".`, sentCopy: true };
          } catch (err) {
            moveError = err;
          }
        } finally {
          lock.release();
        }
        // No MOVE/UIDPLUS (or the move failed): file a copy instead when the account files Sent copies.
        if (!imapSentCopyEnabled(account)) throw moveError;
        await s.append(validateFolder(sent), raw, ['\\Seen']);
        return { note: ` A copy was filed in "${sent}"; the draft could not be moved and is still in the drafts folder. Do not send it again.`, sentCopy: true };
      });
    } catch {
      filed = { note: ' The draft could not be moved to the Sent folder and is still in the drafts folder. Do not send it again.', sentCopy: false };
    }
    const detail = result.detail.startsWith(ACCEPTED_NOTE) ? result.detail : ACCEPTED_NOTE;
    return { ...result, detail: `${detail}${filed.note}`, sentCopy: filed.sentCopy };
  }
}

