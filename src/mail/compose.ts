import MailComposer from 'nodemailer/lib/mail-composer';
import { PerchError } from '../errors.js';
import { stripBcc } from './draftMime.js';
import type { OutgoingMime } from './types.js';

/**
 * Validates outbound mail input and builds the RFC 5322 message. Every header value is checked
 * here (no CR/LF/control characters, one address per entry, strict Message-ID syntax), so no
 * provider adapter ever sees attacker-controlled header structure. Attachments are inline base64
 * only: no file paths, no URLs (nodemailer file/URL access is additionally disabled).
 */

export const MAX_RECIPIENTS = 100;
export const MAX_ATTACHMENTS = 10;
export const MAX_ATTACHMENT_TOTAL_BYTES = 10 * 1024 * 1024;
export const MAX_BODY_BYTES = 1024 * 1024;
const MAX_SUBJECT = 998;

export interface ComposeAttachment {
  filename: string;
  contentType?: string;
  contentBase64: string;
}

export interface ComposeInput {
  from?: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  text: string;
  html?: string;
  attachments?: ComposeAttachment[];
  inReplyTo?: string;
  references?: string[];
}

export interface Mailbox {
  name?: string;
  address: string;
}

export interface ValidatedMail {
  from: string;
  to: Mailbox[];
  cc: Mailbox[];
  bcc: Mailbox[];
  subject: string;
  text: string;
  html?: string;
  attachments: Array<{ filename: string; contentType: string; content: Buffer }>;
  inReplyTo?: string;
  references: string[];
}

const CONTROL = /[\u0000-\u0008\u000a-\u001f\u007f]/;
// Pragmatic addr-spec: no whitespace, quotes, angle brackets, commas or semicolons.
const ADDR = /^[^\s@<>()",;:\\[\]]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$/;
const MSG_ID = /^<[^<>\s]{1,995}>$/;

/** True for exactly one well-formed `<id@host>` Message-ID (the form outgoing headers accept). */
export const isMessageId = (v: unknown): v is string => typeof v === 'string' && MSG_ID.test(v);
const MIME_TYPE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/;

const bad = (msg: string) => new PerchError(msg, 'bad_argument');

function noControl(field: string, v: string, allowTab = true): string {
  if (CONTROL.test(v) || (!allowTab && v.includes('\t'))) throw bad(`${field} must not contain line breaks or control characters`);
  return v;
}

export function isAddress(s: string): boolean {
  return s.length <= 254 && ADDR.test(s);
}

/** Parses "addr@x.y" or "Display Name <addr@x.y>"; exactly one mailbox per entry. */
export function parseMailbox(field: string, raw: string): Mailbox {
  noControl(field, raw);
  const s = raw.trim();
  const m = /^([^<>",;]{0,100}?)\s*<([^<>\s]+)>$/.exec(s);
  const address = m ? m[2]! : s;
  const name = m?.[1]?.trim();
  if (!isAddress(address)) throw bad(`${field}: invalid address (one plain address per entry)`);
  return name ? { name, address } : { address };
}

function mailboxes(field: string, list: string[] | undefined): Mailbox[] {
  return (list ?? []).map((v) => parseMailbox(field, v));
}

function strictBase64(s: string): Buffer | null {
  // Linear checks only (an anchored repetition regex overflows the stack on multi-MB input).
  const t = s.replace(/[\r\n]/g, '');
  if (t.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(t)) return null;
  const buf = Buffer.from(t, 'base64');
  return buf.toString('base64') === t ? buf : null;
}

function messageId(field: string, v: string): string {
  if (!MSG_ID.test(v)) throw bad(`${field} must be a single Message-ID like <id@host>`);
  return v;
}

/**
 * `accountEmail` is the address of the explicitly chosen sender account. An explicit `from`
 * must be the same address; the stored account address is always what is used.
 */
export function validateOutgoing(input: ComposeInput, accountEmail: string): ValidatedMail {
  if (input.from !== undefined) {
    const f = parseMailbox('from', input.from);
    if (f.address.toLowerCase() !== accountEmail.toLowerCase()) {
      throw bad('from must match the address of the chosen sender account');
    }
  }
  const to = mailboxes('to', input.to);
  const cc = mailboxes('cc', input.cc);
  const bcc = mailboxes('bcc', input.bcc);
  const count = to.length + cc.length + bcc.length;
  if (count === 0) throw bad('At least one recipient (to/cc/bcc) is required');
  if (count > MAX_RECIPIENTS) throw bad(`Too many recipients (max ${MAX_RECIPIENTS})`);

  const subject = noControl('subject', input.subject ?? '');
  if (subject.length > MAX_SUBJECT) throw bad(`subject is longer than ${MAX_SUBJECT} characters`);
  const text = input.text ?? '';
  if (Buffer.byteLength(text) > MAX_BODY_BYTES || Buffer.byteLength(input.html ?? '') > MAX_BODY_BYTES) {
    throw bad(`Body is larger than ${MAX_BODY_BYTES} bytes`);
  }

  const atts = input.attachments ?? [];
  if (atts.length > MAX_ATTACHMENTS) throw bad(`Too many attachments (max ${MAX_ATTACHMENTS})`);
  let total = 0;
  const attachments = atts.map((a) => {
    const extra = Object.keys(a).filter((k) => !['filename', 'contentType', 'contentBase64'].includes(k));
    if (extra.length) throw bad(`Unsupported attachment field(s): ${extra.join(', ')} (only inline base64 content is accepted)`);
    if (typeof a.filename !== 'string' || !a.filename.trim() || a.filename.length > 255) throw bad('Attachment filename is required (max 255)');
    noControl('attachment filename', a.filename, false);
    const contentType = a.contentType ?? 'application/octet-stream';
    if (!MIME_TYPE.test(contentType)) throw bad('Attachment contentType must be a plain MIME type like application/pdf');
    if (typeof a.contentBase64 !== 'string') throw bad('Attachment contentBase64 is required');
    // Bound before decoding: base64 is 4/3 of the decoded size.
    if (a.contentBase64.length > Math.ceil((MAX_ATTACHMENT_TOTAL_BYTES * 4) / 3) + 4096) {
      throw bad(`Attachments are too large (max ${MAX_ATTACHMENT_TOTAL_BYTES} bytes in total)`);
    }
    const content = strictBase64(a.contentBase64);
    if (!content) throw bad('Attachment contentBase64 is not valid base64');
    total += content.length;
    if (total > MAX_ATTACHMENT_TOTAL_BYTES) throw bad(`Attachments are too large (max ${MAX_ATTACHMENT_TOTAL_BYTES} bytes in total)`);
    return { filename: a.filename, contentType, content };
  });

  const references = (input.references ?? []).map((r) => messageId('references', r));
  if (references.length > 100) throw bad('Too many references');
  return {
    from: accountEmail,
    to,
    cc,
    bcc,
    subject,
    text,
    ...(input.html !== undefined ? { html: input.html } : {}),
    attachments,
    ...(input.inReplyTo !== undefined ? { inReplyTo: messageId('inReplyTo', input.inReplyTo) } : {}),
    references,
  };
}

/** Bare envelope recipients (To + Cc + Bcc), deduplicated case-insensitively. */
export function envelopeRecipients(v: ValidatedMail): string[] {
  const seen = new Map<string, string>();
  for (const m of [...v.to, ...v.cc, ...v.bcc]) if (!seen.has(m.address.toLowerCase())) seen.set(m.address.toLowerCase(), m.address);
  return [...seen.values()];
}

/** Builds the RFC 5322 message. keepBcc=true for API drafts/sends (the provider strips it). */
export async function buildMime(v: ValidatedMail, opts: { keepBcc: boolean }): Promise<Buffer> {
  const composer = new MailComposer({
    from: v.from,
    to: v.to,
    ...(v.cc.length ? { cc: v.cc } : {}),
    ...(v.bcc.length ? { bcc: v.bcc } : {}),
    subject: v.subject,
    text: v.text,
    ...(v.html !== undefined ? { html: v.html } : {}),
    ...(v.inReplyTo ? { inReplyTo: v.inReplyTo } : {}),
    ...(v.references.length ? { references: v.references } : {}),
    attachments: v.attachments.map((a) => ({ filename: a.filename, contentType: a.contentType, content: a.content })),
    disableFileAccess: true,
    disableUrlAccess: true,
  });
  const node = composer.compile();
  node.keepBcc = opts.keepBcc;
  return node.build();
}

/**
 * Builds the complete outbound message for a provider (Bcc kept for API providers, envelope for SMTP). For SMTP the
 * message is built once WITH Bcc (`sentCopy`, the copy an IMAP account files in its Sent folder, private to the sender)
 * and `raw` is that same message with the Bcc header removed, so both copies share one Message-ID and Date.
 */
export async function composeForProvider(v: ValidatedMail, kind: 'api' | 'smtp', threadId?: string, sourceMessageId?: string): Promise<OutgoingMime> {
  const full = await buildMime(v, { keepBcc: true });
  return {
    raw: kind === 'api' ? full : stripBcc(full),
    envelope: { from: v.from, to: envelopeRecipients(v) },
    ...(kind === 'smtp' ? { sentCopy: full } : {}),
    ...(threadId ? { threadId } : {}),
    ...(sourceMessageId ? { sourceMessageId } : {}),
    structured: {
      subject: v.subject, text: v.text, ...(v.html !== undefined ? { html: v.html } : {}),
      to: v.to.map((m) => m.address), cc: v.cc.map((m) => m.address), bcc: v.bcc.map((m) => m.address),
      attachments: v.attachments.map((a) => ({ filename: a.filename, contentType: a.contentType, contentBase64: a.content.toString('base64') })),
      ...(v.inReplyTo ? { inReplyTo: v.inReplyTo } : {}), references: [...v.references],
    },
  };
}
