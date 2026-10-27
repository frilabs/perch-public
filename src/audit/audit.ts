import type { Principal } from '../auth/grants.js';
import { PerchError } from '../errors.js';
import {
  ACCOUNT_ID_PATTERN,
  newOperationId,
  type Actor,
  type AuditEvent,
  type AuditOutcome,
  type AuditProvider,
  type MailWorkflowLedger,
} from '../mail/workflowLedger.js';

/**
 * Body-free audit trail, stored in the namespace's encrypted mail workflow ledger (see workflowLedger.ts).
 * An event holds only: timestamp, namespace, actor (principal kind and client id), operation id, operation
 * type (tool name), the Perch account id and provider (only when the account id has Perch's own generated
 * shape), a fixed outcome and a Perch error code. Never labels, addresses, subjects, bodies, recipients,
 * attachment names or bytes, queries, ids of messages/files, tokens, request ids or provider error text.
 */

export interface AuditInput {
  type: string;
  actor: Actor;
  outcome: AuditOutcome;
  operationId?: string;
  accountId?: unknown;
  code?: string;
}

const SAFE_CODE = /^[a-z][a-z0-9_]{0,47}$/;

const PROVIDER_BY_PREFIX: Record<string, AuditProvider> = {
  google: 'drive',
  notion: 'notion',
  gmail: 'gmail',
  microsoft: 'microsoft',
  imap: 'imap',
  gprod: 'google_productivity',
  slack: 'slack',
  whatsapp: 'whatsapp',
  luma: 'luma',
  x: 'x',
};

export function actorOf(p: Principal): Actor {
  return p.kind === 'client' && p.clientId ? { kind: 'client', clientId: p.clientId } : { kind: 'operator_readonly' };
}

/** A caller-supplied account id is recorded only if it has the exact shape of a Perch-generated id. */
export function safeAccountId(v: unknown): string | undefined {
  return typeof v === 'string' && ACCOUNT_ID_PATTERN.test(v) ? v : undefined;
}

export function providerOf(accountId: string | undefined): AuditProvider | undefined {
  return accountId ? PROVIDER_BY_PREFIX[accountId.slice(0, accountId.indexOf('-'))] : undefined;
}

/** Perch error code (fixed vocabulary set by code), or "internal" for anything else. */
export function auditCode(err: unknown): string {
  return err instanceof PerchError && SAFE_CODE.test(err.code) ? err.code : 'internal';
}

const DENIED = new Set([
  'capability_denied',
  'grant_revoked',
  'provider_scope_missing',
  'not_permitted',
  'unknown_account',
  'account_changed',
  'user_inactive',
  'unknown_user',
  'namespace_unavailable',
]);
const INVALID = new Set(['bad_argument', 'bad_cursor', 'unknown_request']);

export function outcomeOf(err: unknown): AuditOutcome {
  const code = auditCode(err);
  if (DENIED.has(code)) return 'denied';
  if (INVALID.has(code)) return 'invalid';
  return 'error';
}

export interface AuditFilter {
  clientId?: string;
  accountId?: string;
  limit?: number;
}

export class AuditLog {
  constructor(readonly ledger: MailWorkflowLedger) {}

  /** Builds a validated-shape event (the ledger schema re-validates every field on write). */
  event(input: AuditInput): AuditEvent {
    const accountId = safeAccountId(input.accountId);
    const provider = providerOf(accountId);
    return {
      at: new Date().toISOString(),
      ns: this.ledger.namespace,
      actor: input.actor,
      operationId: input.operationId ?? newOperationId(),
      type: input.type,
      ...(accountId ? { accountId } : {}),
      ...(provider ? { provider } : {}),
      outcome: input.outcome,
      ...(input.code !== undefined ? { code: SAFE_CODE.test(input.code) ? input.code : 'internal' } : {}),
    };
  }

  /** Persists one event durably (fails closed: throws if the ledger cannot be written). */
  async record(input: AuditInput): Promise<string> {
    const ev = this.event(input);
    await this.ledger.transact((d) => this.ledger.appendAudit(d, ev));
    return ev.operationId;
  }

  /** Local inspection (newest last), optionally filtered by client id and account id. */
  async list(filter: AuditFilter = {}): Promise<{ events: AuditEvent[]; dropped: number; total: number }> {
    const data = await this.ledger.read();
    let events = data.audit;
    if (filter.clientId !== undefined) events = events.filter((e) => e.actor.kind === 'client' && e.actor.clientId === filter.clientId);
    if (filter.accountId !== undefined) events = events.filter((e) => e.accountId === filter.accountId);
    const total = events.length;
    if (filter.limit !== undefined) events = events.slice(-filter.limit);
    return { events, dropped: data.auditDropped, total };
  }
}
