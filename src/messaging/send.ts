import { auditCode, outcomeOf, safeAccountId, type AuditLog } from '../audit/audit.js';
import { PerchError } from '../errors.js';
import { accountChanged, sendTypeOf, validateRequestId, type SendWorkflow } from '../mail/workflow.js';
import type { Actor, SendProvider, SendReason, SendRecord, SendState } from '../mail/workflowLedger.js';

/**
 * Idempotent chat-message send (Slack, WhatsApp) on top of the namespace's mail workflow ledger
 * (src/mail/workflow.ts): the same claim / one attempt / finalize protocol, the same send-record limits
 * and the same audit trail. One record per (namespace, actor, account, requestId); a repeated requestId
 * with identical content replays the stored outcome, different content fails before any I/O, and an
 * attempt whose outcome is unknown is never retried.
 */

export interface MessageSendResult {
  status: 'accepted' | 'rejected' | 'indeterminate';
  /** Fixed or Perch-generated text (never provider response bodies). */
  detail: string;
  /** Opaque provider id ([A-Za-z0-9_-], e.g. a WhatsApp message id or an encoded Slack ts). */
  providerMessageId?: string;
  reason: SendReason;
}

export interface MessageSendView {
  status: 'accepted' | 'rejected' | 'indeterminate';
  requestState: SendState;
  operationId: string;
  detail: string;
  providerMessageId?: string;
  manualResolution?: 'sent' | 'not_sent';
  replayed: boolean;
}

const ACCEPTED = 'Accepted by the service for delivery (not proof that anyone has read it).';
const STORED_DETAIL: Record<SendState, string> = {
  pending:
    'An earlier request with this requestId is still running or was interrupted; its outcome is unknown. Perch did not send it again and never ' +
    'will for this requestId. Check the conversation; the local admin can record the verified outcome (perch mail-workflow resolve).',
  accepted: `Already accepted earlier; not sent again. ${ACCEPTED}`,
  rejected: 'Rejected earlier: it was not sent and is not sent again. Fix the cause and use a new requestId.',
  indeterminate:
    'The earlier attempt has an unknown outcome; Perch did not send it again and never retries it. Check the conversation before sending with a new requestId.',
};
const FINALIZE_FAILED =
  'The outcome could not be recorded; it is unknown. Perch will not send this requestId again. Check the conversation before sending with a new requestId.';

export function messageViewOf(record: SendRecord): Omit<MessageSendView, 'replayed'> {
  const resolved = record.resolution ? ` The local admin recorded after checking: ${record.resolution.outcome === 'sent' ? 'sent' : 'not sent'}.` : '';
  return {
    status: record.state === 'pending' ? 'indeterminate' : record.state,
    requestState: record.state,
    operationId: record.operationId,
    detail: STORED_DETAIL[record.state] + resolved,
    ...(record.providerMessageId ? { providerMessageId: record.providerMessageId } : {}),
    ...(record.resolution ? { manualResolution: record.resolution.outcome } : {}),
  };
}

export interface MessageSendInput {
  workflow: SendWorkflow;
  audit: AuditLog;
  actor: Actor;
  provider: SendProvider;
  accountId: unknown;
  /**
   * Authorisation, account lookup and local validation, all before any provider I/O. Returns the caller's
   * requestId, the canonical caller payload (fingerprinted) and the sender identity (bound to the record).
   */
  prepare: () => Promise<{ accountId: string; requestId: unknown; canonical: string; binding: readonly string[] }>;
  /**
   * The single provider attempt, given the binding HMAC from the claim. It must re-check authorisation and
   * the sender identity itself immediately before submitting, and return "rejected" for anything that fails
   * before submission. A throw is treated as an unknown outcome.
   */
  attempt: (binding: string) => Promise<MessageSendResult>;
}

export async function sendMessageIdempotently(input: MessageSendInput): Promise<MessageSendView> {
  const { workflow } = input;
  const type = sendTypeOf(input.provider);
  let accountId: string;
  let ids: { key: string; operationId: string };
  let fp: string;
  let binding: string;
  try {
    const prepared = await input.prepare();
    accountId = prepared.accountId;
    const requestId = validateRequestId(prepared.requestId);
    ids = await workflow.ids(input.actor, accountId, requestId);
    fp = await workflow.fingerprint(ids.key, prepared.canonical);
    binding = await workflow.binding(prepared.binding);
  } catch (err) {
    await input.audit.record({ type, actor: input.actor, accountId: safeAccountId(input.accountId), outcome: outcomeOf(err), code: auditCode(err) });
    throw err;
  }
  const claim = await workflow.claim({ key: ids.key, fp, binding, operationId: ids.operationId, accountId, provider: input.provider, actor: input.actor });
  if (claim.kind === 'existing') return { ...messageViewOf(claim.record), replayed: true };

  // Claimed: the durable pending record exists. Nothing escapes from here without finalizing.
  const result = await input.attempt(binding).catch(
    (): MessageSendResult => ({ status: 'indeterminate', detail: 'The send failed unexpectedly; the outcome is unknown.', reason: 'adapter_error' }),
  );
  const recorded = await workflow.finalize(ids.key, claim.attempt, result.status, result.reason, result.providerMessageId);
  if (!recorded) return { status: 'indeterminate', requestState: 'pending', operationId: ids.operationId, detail: FINALIZE_FAILED, replayed: false };
  return {
    status: result.status,
    requestState: result.status,
    operationId: ids.operationId,
    detail: result.status === 'accepted' ? `${result.detail} ${ACCEPTED}`.trim() : result.detail,
    ...(result.providerMessageId ? { providerMessageId: result.providerMessageId } : {}),
    replayed: false,
  };
}

/** Status of one of this actor's earlier sends; the binding must still match the account as stored now. */
export async function messageSendStatus(
  workflow: SendWorkflow,
  actor: Actor,
  accountId: string,
  requestId: unknown,
  bindingParts: readonly string[],
): Promise<Omit<MessageSendView, 'replayed'> & { createdAt: string; finalizedAt?: string }> {
  const { key } = await workflow.ids(actor, accountId, validateRequestId(requestId));
  const record = await workflow.lookup(key);
  if (!record) throw new PerchError('No send with this requestId from this client and account', 'unknown_request');
  if (record.binding !== (await workflow.binding(bindingParts))) throw accountChanged();
  return { ...messageViewOf(record), createdAt: record.createdAt, ...(record.finalizedAt ? { finalizedAt: record.finalizedAt } : {}) };
}
