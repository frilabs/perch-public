import { randomBytes } from 'node:crypto';
import { PerchError } from '../errors.js';
import type { ComposeAttachment } from './compose.js';
import { ACCEPTED_NOTE } from './types.js';
import {
  MAX_SEND_RECORDS,
  PROVIDER_MESSAGE_ID_PATTERN,
  type Actor,
  type MailWorkflowLedger,
  type SendReason,
  type SendProvider,
  type SendRecord,
  type SendState,
} from './workflowLedger.js';

/** Audit operation type of a send record, derived from its provider (never caller text). */
export function sendTypeOf(provider: SendProvider): string {
  if (provider === 'slack') return 'slack_send_message';
  if (provider === 'whatsapp') return 'whatsapp_send_message';
  if (provider === 'luma') return 'luma_write';
  if (provider === 'drive') return 'drive_write';
  if (provider === 'notion') return 'notion_write';
  if (provider === 'microsoftSessionWrite') return 'microsoft_session_write';
  if (provider === 'x') return 'x_post';
  return 'mail_send';
}

/**
 * Durable idempotent send workflow. One send record per (namespace, actor, account, requestId):
 *
 *   claim (atomic, under mail-workflow.lock): new key -> "pending" persisted BEFORE any provider I/O;
 *     same key + same payload fingerprint -> the stored record is replayed (never resubmitted);
 *     same key + different fingerprint -> idempotency_conflict (no provider I/O).
 *   one provider attempt (no lock held across the network).
 *   finalize: pending -> accepted | rejected | indeterminate, only by the attempt that claimed it.
 *
 * A record that stays "pending" (crash, kill, finalization write failure) is reported as unknown forever
 * and never sent again; only the local admin can record a human-verified outcome (resolveSend), which
 * still never sends. Rejected and indeterminate keys are never retried automatically: a new attempt
 * needs a new requestId. "accepted" means accepted by the provider, not delivered.
 *
 * Provider-native idempotency: Gmail users.messages.send, Microsoft session sendMail and SMTP have no idempotency
 * key, so this ledger is the only duplicate protection; it cannot detect a message sent outside Perch.
 */

export const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;

export function validateRequestId(v: unknown): string {
  if (typeof v !== 'string' || !REQUEST_ID_PATTERN.test(v)) {
    throw new PerchError(
      'requestId is required: 8-128 characters of A-Z a-z 0-9 . _ : - (a stable id you generate per message and reuse only to retry that same message)',
      'bad_argument',
    );
  }
  return v;
}

export interface SendPayload {
  accountId: string;
  from?: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject?: string;
  text: string;
  html?: string;
  attachments?: ComposeAttachment[];
  replyToMessageId?: string;
  inReplyTo?: string;
  references?: string[];
}

/**
 * Canonical form of the CALLER's payload (before reply context is fetched or MIME is built), so the
 * fingerprint is deterministic: no generated Message-ID, Date or boundary is involved.
 */
export function canonicalSendPayload(req: SendPayload): string {
  const attachments = (req.attachments ?? []).map((a) => [a.filename, a.contentType ?? null, a.contentBase64]);
  return JSON.stringify([
    'perch-send-v1',
    req.accountId,
    req.from ?? null,
    req.to ?? [],
    req.cc ?? [],
    req.bcc ?? [],
    req.subject ?? null,
    req.text ?? '',
    req.html ?? null,
    attachments,
    req.replyToMessageId ?? null,
    req.inReplyTo ?? null,
    req.references ?? [],
  ]);
}

/**
 * Canonical CALLER payload of mail_reply / mail_forward with send: true (one domain per kind, never equal to a
 * mail_send or send-draft payload). The derived recipients and quote are not part of it: they are derived only on
 * the one attempt.
 */
export function canonicalDerivedPayload(
  kind: 'reply' | 'forward',
  req: { accountId: string; messageId: string; text?: string; html?: string; to?: string[]; cc?: string[]; bcc?: string[]; replyAll?: boolean; includeAttachments?: boolean },
): string {
  return JSON.stringify([
    `perch-${kind}-v1`,
    req.accountId,
    req.messageId,
    req.replyAll === true,
    req.includeAttachments !== false,
    req.text ?? '',
    req.html ?? null,
    req.to ?? [],
    req.cc ?? [],
    req.bcc ?? [],
  ]);
}

/** Canonical payload of sending an existing draft: a distinct domain, so it never equals a mail_send payload. */
export function canonicalSendDraftPayload(accountId: string, draftId: string): string {
  return JSON.stringify(['perch-send-draft-v1', accountId, draftId]);
}

export interface SendView {
  status: 'accepted' | 'rejected' | 'indeterminate';
  requestState: SendState;
  operationId: string;
  detail: string;
  providerMessageId?: string;
  manualResolution?: 'sent' | 'not_sent';
  createdAt: string;
  finalizedAt?: string;
}

const STORED_DETAIL: Record<SendState, string> = {
  pending:
    'An earlier request with this requestId is still running or was interrupted; its outcome is unknown. Perch did not send it again and ' +
    'never will for this requestId. Check the Sent folder; the local admin can record the verified outcome (perch mail-workflow resolve).',
  accepted: `Already accepted earlier; not sent again. ${ACCEPTED_NOTE}`,
  rejected: 'Rejected earlier: it was not sent and is not sent again. Fix the cause and use a new requestId.',
  indeterminate:
    'The earlier attempt has an unknown outcome; Perch did not send it again and never retries it. Check the Sent folder before sending with a new requestId.',
};

/** Reports a stored record with fixed texts only. Pending is reported as indeterminate. */
export function viewOf(record: SendRecord): SendView {
  const resolved = record.resolution ? ` The local admin recorded after checking: ${record.resolution.outcome === 'sent' ? 'sent' : 'not sent'}.` : '';
  return {
    status: record.state === 'pending' ? 'indeterminate' : record.state,
    requestState: record.state,
    operationId: record.operationId,
    detail: STORED_DETAIL[record.state] + resolved,
    ...(record.providerMessageId ? { providerMessageId: record.providerMessageId } : {}),
    ...(record.resolution ? { manualResolution: record.resolution.outcome } : {}),
    createdAt: record.createdAt,
    ...(record.finalizedAt ? { finalizedAt: record.finalizedAt } : {}),
  };
}

export type ClaimResult = { kind: 'new'; attempt: string } | { kind: 'existing'; record: SendRecord };

export interface ClaimInput {
  key: string;
  fp: string;
  binding: string;
  operationId: string;
  accountId: string;
  provider: SendProvider;
  actor: Actor;
}

export class SendWorkflow {
  constructor(readonly ledger: MailWorkflowLedger) {}

  /** Storage key and stable operation id of (namespace, actor, account, requestId). */
  async ids(actor: Actor, accountId: string, requestId: string): Promise<{ key: string; operationId: string }> {
    const key = await this.ledger.mac('send-key', [this.ledger.namespace, actor.kind, actor.kind === 'client' ? actor.clientId : '', accountId, requestId]);
    const operationId = `op-${(await this.ledger.mac('send-operation', [key])).slice(0, 24)}`;
    return { key, operationId };
  }

  fingerprint(key: string, canonical: string): Promise<string> {
    return this.ledger.mac('send-payload', [key, canonical]);
  }

  binding(parts: readonly string[]): Promise<string> {
    return this.ledger.mac('account-binding', parts);
  }

  /** Atomic claim (see class comment). Conflicts and changed accounts are audited, then thrown. */
  async claim(c: ClaimInput): Promise<ClaimResult> {
    const base = { ns: this.ledger.namespace, actor: c.actor, operationId: c.operationId, type: sendTypeOf(c.provider), accountId: c.accountId, provider: c.provider };
    const at = () => new Date().toISOString();
    const r = await this.ledger.transact((d) => {
      const existing = d.sends.find((s) => s.key === c.key);
      if (existing) {
        if (existing.fp !== c.fp) {
          this.ledger.appendAudit(d, { ...base, at: at(), outcome: 'conflict', code: 'idempotency_conflict' });
          return { kind: 'conflict' as const };
        }
        if (existing.binding !== c.binding) {
          this.ledger.appendAudit(d, { ...base, at: at(), outcome: 'denied', code: 'account_changed' });
          return { kind: 'changed' as const };
        }
        this.ledger.appendAudit(d, { ...base, at: at(), outcome: 'replayed', code: existing.state });
        return { kind: 'existing' as const, record: structuredClone(existing) };
      }
      if (d.sends.length >= MAX_SEND_RECORDS) {
        this.ledger.appendAudit(d, { ...base, at: at(), outcome: 'error', code: 'ledger_full' });
        return { kind: 'full' as const };
      }
      const attempt = randomBytes(16).toString('hex');
      d.sends.push({
        key: c.key,
        fp: c.fp,
        binding: c.binding,
        operationId: c.operationId,
        accountId: c.accountId,
        provider: c.provider,
        actor: c.actor,
        state: 'pending',
        attempt,
        createdAt: at(),
      });
      this.ledger.appendAudit(d, { ...base, at: at(), outcome: 'pending' });
      return { kind: 'new' as const, attempt };
    });
    if (r.kind === 'conflict') {
      throw new PerchError(
        'This requestId was already used for a different message (from this client and account). Nothing was sent. Use a new requestId for a new message.',
        'idempotency_conflict',
      );
    }
    if (r.kind === 'changed') throw accountChanged();
    if (r.kind === 'full') {
      throw new PerchError(
        `Mail workflow ledger is full (${MAX_SEND_RECORDS} send records). Nothing was sent. Used requestIds are never forgotten, so this namespace cannot send again until a ledger rollover exists (docs/MAIL_WORKFLOW_MILESTONE.md).`,
        'ledger_full',
      );
    }
    return r;
  }

  /**
   * pending -> terminal, only for the attempt that claimed the record. Returns false if the outcome could
   * not be persisted (the durable pending record then keeps reporting "unknown").
   */
  async finalize(key: string, attempt: string, state: Exclude<SendState, 'pending'>, reason: SendReason, providerMessageId?: string): Promise<boolean> {
    const pmid = providerMessageId !== undefined && PROVIDER_MESSAGE_ID_PATTERN.test(providerMessageId) ? providerMessageId : undefined;
    try {
      return await this.ledger.transact((d) => {
        const rec = d.sends.find((s) => s.key === key);
        if (!rec || rec.state !== 'pending' || rec.attempt !== attempt) return false;
        rec.state = state;
        rec.reason = reason;
        rec.finalizedAt = new Date().toISOString();
        if (pmid) rec.providerMessageId = pmid;
        this.ledger.appendAudit(d, {
          at: rec.finalizedAt,
          ns: this.ledger.namespace,
          actor: rec.actor,
          operationId: rec.operationId,
          type: sendTypeOf(rec.provider),
          accountId: rec.accountId,
          provider: rec.provider,
          outcome: state,
          code: reason,
        });
        return true;
      });
    } catch {
      return false;
    }
  }

  async lookup(key: string): Promise<SendRecord | undefined> {
    return (await this.ledger.read()).sends.find((s) => s.key === key);
  }
}

export const accountChanged = () =>
  new PerchError(
    'The sender account changed (removed, replaced or re-credentialed) since this requestId was first used; refusing to replay or send. Nothing was sent.',
    'account_changed',
  );

/**
 * Local admin only (perch mail-workflow resolve): records a human-verified outcome of a pending or
 * indeterminate send after checking the Sent folder. It never sends and never frees the requestId.
 */
export async function resolveSend(ledger: MailWorkflowLedger, operationId: string, outcome: 'sent' | 'not_sent'): Promise<SendRecord> {
  return ledger.transact((d) => {
    const rec = d.sends.find((s) => s.operationId === operationId);
    if (!rec) throw new PerchError(`Unknown operation id: ${operationId}`, 'unknown_request');
    if (rec.state !== 'pending' && rec.state !== 'indeterminate') {
      throw new PerchError(`Operation ${operationId} is ${rec.state}; only pending or indeterminate sends can be resolved`, 'bad_argument');
    }
    if (rec.resolution) throw new PerchError(`Operation ${operationId} was already resolved (${rec.resolution.outcome})`, 'bad_argument');
    rec.resolution = { outcome, at: new Date().toISOString() };
    ledger.appendAudit(d, {
      at: rec.resolution.at,
      ns: ledger.namespace,
      actor: { kind: 'local_admin' },
      operationId: rec.operationId,
      type: 'workflow_resolve',
      accountId: rec.accountId,
      provider: rec.provider,
      outcome: 'resolved',
      code: outcome,
    });
    return structuredClone(rec);
  });
}

/**
 * Removed: forgetting finished send records would let a reused requestId be sent again, which breaks the
 * exactly-once promise. Kept as an explicit refusal so old callers (and `perch mail-workflow prune`) fail
 * closed instead of silently doing nothing. Finished keys stay in the ledger forever; at MAX_SEND_RECORDS
 * new sends fail closed (ledger_full).
 */
export async function pruneSends(_ledger: MailWorkflowLedger, _before: Date): Promise<never> {
  throw new PerchError(PRUNE_REFUSED, 'prune_unsupported');
}

export const PRUNE_REFUSED =
  'Pruning the mail workflow ledger is not supported: used requestIds are never forgotten (otherwise a reused requestId ' +
  'would be sent again). Nothing was changed.';
