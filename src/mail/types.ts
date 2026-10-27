import type { SourcePage } from '../fanout.js';

/** Provider-neutral shapes shared by the Gmail, Microsoft browser-session and IMAP/SMTP adapters. */

/** `microsoft` remains only for historical encrypted send/audit records. */
export type MailProviderKind = 'gmail' | 'microsoft' | 'microsoftSession' | 'imap';

/** Default and hard caps for message text and attachment content returned to MCP clients. */
export const DEFAULT_MAIL_MAX_BYTES = 48 * 1024;
export const HARD_MAIL_MAX_BYTES = 10 * 1024 * 1024;
export const DEFAULT_MAIL_PAGE_SIZE = 20;
export const MAX_MAIL_PAGE_SIZE = 50;

export interface MailSummary {
  /** Perch message id, opaque and provider-specific (IMAP ids are bound to UIDVALIDITY). */
  messageId: string;
  threadId?: string;
  folder?: string;
  from?: string;
  to?: string[];
  subject?: string;
  /** ISO 8601 */
  date?: string;
  snippet?: string;
  hasAttachments?: boolean;
}

export interface MailAttachmentMeta {
  attachmentId: string;
  filename?: string;
  contentType: string;
  /** Provider-reported size in bytes (IMAP reports the encoded size). */
  size?: number;
  inline?: boolean;
}

export interface MailMessage extends MailSummary {
  cc?: string[];
  replyTo?: string[];
  /** RFC 5322 threading headers of this message. */
  internetMessageId?: string;
  inReplyTo?: string;
  references?: string[];
  /** Plain-text body (from text/plain, or derived from HTML when no text part exists). */
  text?: string;
  /** "text/plain", or "text/html" when the text was derived from HTML. */
  textSource?: 'text/plain' | 'text/html';
  /** True when `text` was cut at maxBytes. */
  truncated: boolean;
  attachments: MailAttachmentMeta[];
}

export interface MailAttachmentContent {
  attachmentId: string;
  filename?: string;
  contentType: string;
  size: number;
  contentBase64: string;
}

/** What a reply needs from the message being answered. */
export interface ReplyContext {
  internetMessageId?: string;
  references: string[];
  subject?: string;
  /** Provider thread id (Gmail threadId), passed back when drafting/sending. */
  threadId?: string;
}

export interface SearchOptions {
  query?: string;
  /** IMAP mailbox path or Outlook well-known folder name; Gmail ignores it (use the query, e.g. in:inbox). */
  folder?: string;
  pageSize: number;
}

export interface ReadOptions {
  maxBytes: number;
}

export interface OutgoingMime {
  /** Full RFC 5322 message (Bcc header included for API providers, excluded for SMTP). */
  raw: Buffer;
  /** SMTP envelope: account address and every To/Cc/Bcc recipient (bare addresses). */
  envelope: { from: string; to: string[] };
  threadId?: string;
  /** Validated fields for JSON-based providers; never reconstructed by parsing raw MIME. */
  structured?: StructuredOutgoingMail;
  /** Original provider message id used for Outlook's native reply-draft operation. */
  sourceMessageId?: string;
  /** SMTP only: the same message WITH its Bcc header, filed in the IMAP Sent folder after an accepted send. */
  sentCopy?: Buffer;
}

export interface StructuredOutgoingMail {
  subject: string;
  text: string;
  html?: string;
  to: string[];
  cc: string[];
  bcc: string[];
  attachments: Array<{ filename: string; contentType: string; contentBase64: string }>;
  inReplyTo?: string;
  references: string[];
}

export interface DraftResult {
  draftId: string;
  messageId?: string;
  threadId?: string;
}

/**
 * accepted: the provider accepted the message for delivery (NOT proof of delivery).
 * rejected: the provider refused it before accepting; it was not sent.
 * indeterminate: the outcome is unknown (network loss/timeout/5xx after the request left);
 *   Perch never retries automatically. Check the Sent folder before sending again.
 */
export interface SendResult {
  status: 'accepted' | 'rejected' | 'indeterminate';
  providerMessageId?: string;
  detail: string;
  /**
   * IMAP only, after an accepted send: whether a copy was filed in the Sent folder. false when filing failed or is
   * turned off for the account (the detail says which); the send outcome is never changed by it.
   */
  sentCopy?: boolean;
}

/**
 * One adapter per provider. `A` is the stored account type. Adapters never decide
 * authorization: the MailService checks the client grant and provider capability first.
 */
export interface MailProvider<A> {
  readonly kind: MailProviderKind;
  /** What this stored account is able to do at the provider (OAuth scopes / IMAP opt-ins). */
  providerCapabilities(account: A): ProviderCapabilities;
  search(account: A, opts: SearchOptions, cursor: string | undefined): Promise<SourcePage<MailSummary>>;
  read(account: A, messageId: string, opts: ReadOptions): Promise<MailMessage>;
  getAttachment(account: A, messageId: string, attachmentId: string, opts: ReadOptions): Promise<MailAttachmentContent>;
  replyContext(account: A, messageId: string): Promise<ReplyContext>;
  createDraft(account: A, mail: OutgoingMime): Promise<DraftResult>;
  send(account: A, mail: OutgoingMime): Promise<SendResult>;
  // ---- organizing and sending existing drafts (mail_* organize tools, src/mcp/tools/mailExtra.ts) -------------
  // Optional so that minimal MOCK providers in older tests stay valid; every production adapter implements them.
  /** Whether the stored grant can send an EXISTING draft (Gmail compose/modify, Microsoft session write access, IMAP allowSend). */
  canSendDraft?(account: A): boolean;
  listFolders?(account: A): Promise<MailFolder[]>;
  listDrafts?(account: A, opts: { pageSize: number }, cursor: string | undefined): Promise<SourcePage<MailDraftSummary>>;
  markMessage?(account: A, messageId: string, change: MarkChange): Promise<OrganizeResult>;
  moveMessage?(account: A, messageId: string, target: MoveTarget): Promise<OrganizeResult>;
  /** Moves to the provider's trash (recoverable). Never a permanent delete. */
  trashMessage?(account: A, messageId: string): Promise<OrganizeResult>;
  /** Moves a trashed message back (Gmail untrash, Outlook/IMAP back to the inbox). */
  restoreMessage?(account: A, messageId: string): Promise<OrganizeResult>;
  /** Exactly one provider attempt, never retried (same outcome classes as send). */
  sendDraft?(account: A, draftId: string): Promise<SendResult>;
}

/** What a stored account is able to do at the provider (OAuth scopes / IMAP opt-ins). */
export interface ProviderCapabilities {
  draft: boolean;
  send: boolean;
  /** Organizing: flags, move/archive, trash/restore (Gmail gmail.modify, Microsoft session write access, IMAP allowModify). */
  modify?: boolean;
}

export type MailFolderRole = 'inbox' | 'sent' | 'drafts' | 'trash' | 'archive' | 'junk' | 'starred' | 'important' | 'all' | 'other';

export interface MailFolder {
  /** Gmail label id, Outlook folder id (or well-known name) or IMAP mailbox path; use it as folderId when moving. */
  folderId: string;
  name: string;
  role: MailFolderRole;
  /** Gmail: system or user label. */
  type?: 'system' | 'user';
  /** IMAP special-use flag as reported by the server (e.g. \Trash). */
  specialUse?: string;
  total?: number;
  unread?: number;
}

export interface MailDraftSummary {
  /** Id to pass to mail_send_draft (Gmail draft id, Outlook message id, Perch IMAP message id). */
  draftId: string;
  messageId?: string;
  subject?: string;
  to?: string[];
  /** ISO 8601 */
  date?: string;
}

export interface MarkChange {
  read?: boolean;
  /** Gmail STARRED label, Outlook follow-up flag, IMAP \Flagged. */
  starred?: boolean;
}

/** A folder/label id, or archive (Gmail: remove INBOX; Outlook: archive folder; IMAP: \Archive or folderId). */
export type MoveTarget = { folderId: string; archive?: false } | { archive: true; folderId?: string };

export interface OrganizeResult {
  /** The message's id after the operation (Outlook and IMAP ids change when a message moves); absent when unknown. */
  messageId?: string;
  /** Present when the provider did not report the new id (IMAP without UIDPLUS): search the folder again. */
  note?: string;
  folderId?: string;
}

export const ACCEPTED_NOTE =
  'Accepted by the provider for delivery. This is not proof of delivery to the recipient.';
export const INDETERMINATE_NOTE =
  'The outcome is unknown (connection lost or provider error after the request was sent). Perch did not retry. ' +
  'Check the Sent folder before sending again to avoid a duplicate.';
