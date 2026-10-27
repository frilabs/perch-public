import addressparser from 'nodemailer/lib/addressparser';
import { PerchError } from '../errors.js';
import { isAddress, isMessageId, MAX_BODY_BYTES, MAX_RECIPIENTS } from './compose.js';
import type { MailMessage } from './types.js';

/**
 * Pure helpers for mail_reply / mail_forward (docs/MAIL_CALENDAR_SLACK_SPEC.md §1). Everything read from the
 * original message is untrusted: addresses are re-parsed and must be plain addr-specs (malformed entries are
 * skipped and counted), display names lose every character the outgoing header grammar rejects, header values
 * quoted into the body lose control characters, and the result still goes through validateOutgoing (compose.ts)
 * like any caller input. The original's Bcc is never read or used.
 */

const CONTROL_ALL = /[\u0000-\u001f\u007f]/g;
/** Characters parseMailbox (compose.ts) does not accept in a display name, plus backslash. */
const NAME_UNSAFE = /[<>",;\\\u0000-\u001f\u007f]/g;
const MAX_NAME = 100;
/** Same budget as compose.ts MAX_SUBJECT. */
const MAX_SUBJECT = 998;

export interface DerivedRecipients {
  to: string[];
  cc: string[];
  /** Original header entries that were not a single plain address and were left out. */
  skipped: number;
}

interface Box {
  name?: string;
  address: string;
}

/** Parses untrusted header entries into plain mailboxes; anything else is counted as skipped. */
function parseEntries(entries: readonly string[] | undefined, skipped: { n: number }): Box[] {
  const out: Box[] = [];
  for (const raw of entries ?? []) {
    if (typeof raw !== 'string') continue;
    let parsed: Array<{ name?: string; address?: string }>;
    try {
      parsed = addressparser(raw.replace(CONTROL_ALL, ' '), { flatten: true });
    } catch {
      skipped.n++;
      continue;
    }
    for (const a of parsed) {
      const address = a.address?.trim();
      if (!address || !isAddress(address)) {
        skipped.n++;
        continue;
      }
      const name = (a.name ?? '').replace(NAME_UNSAFE, ' ').replace(/\s+/g, ' ').trim().slice(0, MAX_NAME).trim();
      out.push(name && name.toLowerCase() !== address.toLowerCase() ? { name, address } : { address });
    }
  }
  return out;
}

const format = (b: Box) => (b.name ? `${b.name} <${b.address}>` : b.address);

/**
 * Reply recipients from the original's headers: Reply-To, else From (a reply to one's own message goes to the
 * original To). replyAll adds the original To (to "to") and Cc (to "cc"). The own address is removed, duplicates
 * are removed case-insensitively, and more than MAX_RECIPIENTS is refused (never cut silently).
 */
export function deriveReplyRecipients(original: Pick<MailMessage, 'from' | 'replyTo' | 'to' | 'cc'>, ownAddress: string, replyAll: boolean): DerivedRecipients {
  const skipped = { n: 0 };
  const own = ownAddress.toLowerCase();
  const isOwn = (b: Box) => b.address.toLowerCase() === own;
  const replyTo = parseEntries(original.replyTo, skipped);
  let target = replyTo.length ? replyTo : parseEntries(original.from !== undefined ? [original.from] : [], skipped);
  const origTo = parseEntries(original.to, skipped);
  const origCc = replyAll ? parseEntries(original.cc, skipped) : [];
  if (target.length && target.every(isOwn)) target = origTo;
  const seen = new Set<string>();
  const take = (list: Box[]) =>
    list.filter((b) => {
      const k = b.address.toLowerCase();
      if (k === own || seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  const to = take(replyAll ? [...target, ...origTo] : target);
  const cc = take(origCc);
  if (!to.length && !cc.length) {
    throw new PerchError('The original message has no usable sender or reply address to answer (only your own or malformed addresses)', 'no_recipients');
  }
  if (to.length + cc.length > MAX_RECIPIENTS) {
    throw new PerchError(`Replying to all would address ${to.length + cc.length} recipients, over the limit of ${MAX_RECIPIENTS}. Nothing was created or sent.`, 'too_many_recipients');
  }
  return { to: to.map(format), cc: cc.map(format), skipped: skipped.n };
}

/** Appends caller entries to a derived list, skipping addresses already present (case-insensitive). */
export function mergeRecipients(base: string[], extra: readonly string[] | undefined, taken: Set<string>): string[] {
  const out = [...base];
  for (const e of extra ?? []) {
    const m = /<([^<>\s]+)>\s*$/.exec(e);
    const key = (m ? m[1]! : e.trim()).toLowerCase();
    if (taken.has(key)) continue;
    taken.add(key);
    out.push(e);
  }
  return out;
}

/** Lower-cased bare addresses of formatted entries ("Name <a@b>" or "a@b"). */
export function addressKeys(list: readonly string[]): Set<string> {
  return new Set(list.map((e) => (/<([^<>\s]+)>\s*$/.exec(e)?.[1] ?? e.trim()).toLowerCase()));
}

const cleanSubject = (s: string | undefined) => (s ?? '').replace(CONTROL_ALL, ' ').trim();

function prefixed(prefix: string, already: RegExp, subject: string | undefined): string {
  const s = cleanSubject(subject);
  const out = already.test(s) ? s : s ? `${prefix} ${s}` : prefix;
  return out.slice(0, MAX_SUBJECT);
}

/** "Re: <subject>" unless it already starts with Re:/AW: (no "Re: Re:"). */
export const replySubject = (subject: string | undefined) => prefixed('Re:', /^(re|aw)\s*:/i, subject);
/** "Fwd: <subject>" unless it already starts with Fwd:/Fw:/WG:. */
export const forwardSubject = (subject: string | undefined) => prefixed('Fwd:', /^(fwd?|wg)\s*:/i, subject);

/** In-Reply-To (replies only) and References (original References + its Message-ID, last 50), well-formed ids only. */
export function threadingFor(original: Pick<MailMessage, 'internetMessageId' | 'references'>, reply: boolean): { inReplyTo?: string; references: string[] } {
  const id = isMessageId(original.internetMessageId) ? original.internetMessageId : undefined;
  const refs = [...(original.references ?? []).filter((r) => isMessageId(r) && r !== id), ...(id ? [id] : [])].slice(-50);
  return { ...(reply && id ? { inReplyTo: id } : {}), references: refs };
}

/** Cuts a string to at most maxBytes of UTF-8 without splitting a character. */
function cutBytes(s: string, maxBytes: number): string {
  const buf = Buffer.from(s, 'utf8');
  if (buf.length <= maxBytes) return s;
  let end = Math.max(0, maxBytes);
  while (end > 0 && (buf[end]! & 0xc0) === 0x80) end--;
  return buf.subarray(0, end).toString('utf8');
}

const TRUNCATED = '[… quoted text truncated]';
const headerValue = (v: string | undefined) => (v ?? '').replace(CONTROL_ALL, ' ').trim();
const dateLine = (iso: string | undefined) => {
  const d = iso ? new Date(iso) : undefined;
  return d && !Number.isNaN(d.getTime()) ? d.toUTCString() : 'an unknown date';
};

/** Fits `head + quoted` into the remaining body budget; a cut quote ends with a visible marker. */
function fit(own: string, quoted: string, truncatedAlready: boolean): string {
  const budget = MAX_BODY_BYTES - Buffer.byteLength(own) - Buffer.byteLength(TRUNCATED) - 8;
  if (budget <= 0) return own;
  const marker = truncatedAlready ? `\n${TRUNCATED}` : '';
  if (Buffer.byteLength(quoted) + Buffer.byteLength(marker) <= budget) return own + quoted + marker;
  return `${own}${cutBytes(quoted, budget)}\n${TRUNCATED}`;
}

/** Caller text followed by "On <date>, <from> wrote:" and the original text quoted with "> ", within MAX_BODY_BYTES. */
export function quoteReply(original: Pick<MailMessage, 'from' | 'date' | 'text' | 'truncated'>, text: string): string {
  const own = `${text}\n\nOn ${dateLine(original.date)}, ${headerValue(original.from) || 'the sender'} wrote:\n`;
  const body = (original.text ?? '').replace(/\r\n?/g, '\n');
  const quoted = body.split('\n').map((l) => (l.startsWith('>') ? `>${l}` : `> ${l}`)).join('\n');
  return fit(own, quoted, original.truncated === true);
}

/** Caller text followed by a forward block (From/Date/Subject/To/Cc of the original) and its text, within MAX_BODY_BYTES. */
export function forwardBody(original: Pick<MailMessage, 'from' | 'date' | 'subject' | 'to' | 'cc' | 'text' | 'truncated'>, text: string): string {
  const lines = [
    '---------- Forwarded message ---------',
    `From: ${headerValue(original.from)}`,
    `Date: ${dateLine(original.date)}`,
    `Subject: ${headerValue(original.subject)}`,
    `To: ${headerValue((original.to ?? []).join(', '))}`,
    ...(original.cc?.length ? [`Cc: ${headerValue(original.cc.join(', '))}`] : []),
  ];
  const own = `${text ? `${text}\n\n` : ''}${lines.join('\n')}\n\n`;
  return fit(own, (original.text ?? '').replace(/\r\n?/g, '\n'), original.truncated === true);
}

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/**
 * HTML alternative: the caller's HTML followed by the plain-text quote/forward block, escaped, in a blockquote
 * (the original's own HTML is never copied: it is untrusted markup). Within MAX_BODY_BYTES.
 */
export function htmlWithQuote(html: string, plainQuote: string): string {
  const close = '</blockquote>';
  const open = '<br><blockquote type="cite" style="margin:0 0 0 .8ex;border-left:1px solid #ccc;padding-left:1ex">';
  const budget = MAX_BODY_BYTES - Buffer.byteLength(html) - open.length - close.length - 64;
  if (budget <= 0) return html;
  let inner = escapeHtml(plainQuote).replace(/\n/g, '<br>\n');
  if (Buffer.byteLength(inner) > budget) inner = `${cutBytes(inner, budget).replace(/&[a-z#0-9]*$/i, '').replace(/<[^>]*$/, '')}<br>\n${escapeHtml(TRUNCATED)}`;
  return `${html}${open}${inner}${close}`;
}

/** Filenames of forwarded attachments: no control characters, at most 255 characters, never empty. */
export function safeFilename(name: string | undefined, index: number): string {
  const n = (name ?? '').replace(CONTROL_ALL, '_').trim().slice(0, 255);
  return n || `attachment-${index + 1}`;
}

const MIME_TYPE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/;
export const safeContentType = (t: string | undefined) => (t && MIME_TYPE.test(t) ? t : 'application/octet-stream');
