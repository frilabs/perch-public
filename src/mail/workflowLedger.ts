import { createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import { PerchError } from '../errors.js';
import { assertPrivateDir, readPrivateFile, writePrivateFileAtomic, writePrivateFileExclusive } from '../secureFs.js';
import type { CredentialStore } from '../store/credentialStore.js';
import { decryptEnvelope, encryptEnvelope, parseKey } from '../store/crypto.js';
import { withFileLock } from '../store/lock.js';

/**
 * Per-namespace mail workflow and audit ledger. Shared storage contract (also used by the operations
 * backup tooling, which copies the raw encrypted file):
 * - file `mail-workflow.enc` and cross-process lock directory `mail-workflow.lock`, both directly in the
 *   namespace's store data directory (next to `store.enc`); no other files;
 * - the same envelope as the credential store (AES-256-GCM, fresh 12-byte IV per write, 16-byte tag),
 *   but encrypted with a domain-separated subkey HKDF-SHA256(owner store key read from
 *   `store.storePaths.keyFile`, salt "perch-mail-workflow-v1", info "enc\0<namespace>") and its own AAD
 *   bound to the namespace, so it can never be confused with `store.enc` or another namespace's ledger;
 * - plaintext: JSON `{format:"perch-mail-workflow", version:1, namespace, createdAt, sends[], audit[],
 *   auditDropped}`, strictly validated on every read and write. Records hold only ids, HMACs, fixed enums
 *   and timestamps: never credentials, bodies, subjects, recipients, attachment names/content, labels,
 *   addresses, raw request ids or provider error text.
 *
 * Missing, corrupt, foreign, future-version or symlinked ledgers fail closed and are never recreated or
 * overwritten implicitly; only `initStore` (new namespaces) and the explicit `perch mail-workflow init`
 * (namespaces created before this ledger existed) create one, and only if no file exists.
 */

export const LEDGER_FILE = 'mail-workflow.enc';
export const LEDGER_LOCK = 'mail-workflow.lock';
export const LEDGER_FORMAT = 'perch-mail-workflow';
export const LEDGER_VERSION = 1;
/** Send records are never evicted automatically (that would reopen a request id): full = fail closed. */
export const MAX_SEND_RECORDS = 1000;
/** Audit events form a ring: the oldest are dropped and counted in `auditDropped`. */
export const MAX_AUDIT_EVENTS = 2000;
export const MAX_LEDGER_FILE_BYTES = 4 * 1024 * 1024;
const MAX_LEDGER_PLAINTEXT_BYTES = 2 * 1024 * 1024;

const HEX64 = /^[a-f0-9]{64}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
export const OPERATION_ID_PATTERN = /^op-[a-f0-9]{24}$/;
/** Ids of accounts Perch itself generated (provider prefix + 8 hex). Caller text never matches by accident. */
export const ACCOUNT_ID_PATTERN = /^(google|notion|gmail|microsoft|imap|gprod|slack|whatsapp|luma|linkedin|x|msmail|msteams|mscalendar|msfiles)-[a-f0-9]{8}$/;
/** Accounts that can send through the idempotent workflow (mail, Slack, WhatsApp). */
const SEND_ACCOUNT_ID = /^(gmail|microsoft|imap|slack|whatsapp|luma|google|notion|linkedin|x|msmail|msteams|mscalendar|msfiles)-[a-f0-9]{8}$/;
export const SEND_PROVIDERS = ['gmail', 'microsoft', 'imap', 'slack', 'whatsapp', 'luma', 'drive', 'notion', 'linkedin', 'x', 'microsoftSession', 'microsoftSessionWrite'] as const;
const NAMESPACE = /^(root|user-[a-f0-9]{16})$/;
const SAFE_TOKEN = /^[a-z][a-z0-9_]{0,47}$/;
/** Provider message ids are kept only in this opaque form (Gmail ids); anything with an address/host is dropped. */
export const PROVIDER_MESSAGE_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

const ActorSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('operator_readonly') }),
  z.strictObject({ kind: z.literal('client'), clientId: z.string().regex(/^client-[a-f0-9]{8}$/) }),
  z.strictObject({ kind: z.literal('local_admin') }),
  // Public access lifecycle events (pairing, tokens, revocation); the device id when one exists.
  // origin: listener of the event (private = tailnet, public = internet); absent in events before it existed.
  z.strictObject({ kind: z.literal('oauth'), deviceId: z.string().regex(/^oc-[a-f0-9]{16}$/).optional(), origin: z.enum(['private', 'public']).optional() }),
]);

export const SEND_STATES = ['pending', 'accepted', 'rejected', 'indeterminate'] as const;
/** Fixed reasons for a terminal state (never provider text). */
export const SEND_REASONS = [
  'provider_accepted',
  'provider_rejected',
  'provider_unknown',
  'adapter_error',
  'not_submitted_reply_context',
  'not_submitted_compose',
  'not_submitted_account_changed',
  'not_submitted_provider_precheck',
  'not_submitted_authorization',
] as const;

const SendRecordSchema = z.strictObject({
  /** HMAC of namespace, actor, account and the caller's request id (the raw id is never stored). */
  key: z.string().regex(HEX64),
  /** HMAC of the canonical caller payload (never returned or logged). */
  fp: z.string().regex(HEX64),
  /** HMAC of the sender account identity at claim time. */
  binding: z.string().regex(HEX64),
  operationId: z.string().regex(OPERATION_ID_PATTERN),
  accountId: z.string().regex(SEND_ACCOUNT_ID),
  provider: z.enum(SEND_PROVIDERS),
  actor: ActorSchema,
  state: z.enum(SEND_STATES),
  /** Random id of the one attempt allowed to finalize this record. */
  attempt: z.string().regex(/^[a-f0-9]{32}$/),
  createdAt: z.string().regex(ISO),
  finalizedAt: z.string().regex(ISO).optional(),
  reason: z.enum(SEND_REASONS).optional(),
  providerMessageId: z.string().regex(PROVIDER_MESSAGE_ID_PATTERN).optional(),
  /** Human verification by the local admin (perch mail-workflow resolve); never triggers a send. */
  resolution: z.strictObject({ outcome: z.enum(['sent', 'not_sent']), at: z.string().regex(ISO) }).optional(),
});

export const AUDIT_OUTCOMES = [
  'ok',
  'denied',
  'invalid',
  'error',
  'attempt',
  'pending',
  'accepted',
  'rejected',
  'indeterminate',
  'replayed',
  'conflict',
  'resolved',
  'pruned',
] as const;

export const AUDIT_PROVIDERS = ['drive', 'notion', 'gmail', 'microsoft', 'imap', 'google_productivity', 'slack', 'whatsapp', 'luma', 'linkedin', 'x', 'microsoftSession', 'microsoftSessionWrite'] as const;

const AuditEventSchema = z.strictObject({
  at: z.string().regex(ISO),
  ns: z.string().regex(NAMESPACE),
  actor: ActorSchema,
  operationId: z.string().regex(OPERATION_ID_PATTERN),
  /** Tool or operation name (fixed by code, never caller text). */
  type: z.string().regex(SAFE_TOKEN),
  accountId: z.string().regex(ACCOUNT_ID_PATTERN).optional(),
  provider: z.enum(AUDIT_PROVIDERS).optional(),
  outcome: z.enum(AUDIT_OUTCOMES),
  /** Perch error code or fixed reason (never a message). */
  code: z.string().regex(SAFE_TOKEN).optional(),
});

const LedgerSchema = z.strictObject({
  format: z.literal(LEDGER_FORMAT),
  version: z.literal(LEDGER_VERSION),
  namespace: z.string().regex(NAMESPACE),
  createdAt: z.string().regex(ISO),
  sends: z.array(SendRecordSchema).max(MAX_SEND_RECORDS),
  audit: z.array(AuditEventSchema).max(MAX_AUDIT_EVENTS),
  auditDropped: z.number().int().min(0),
});

export type Actor = z.infer<typeof ActorSchema>;
export type SendRecord = z.infer<typeof SendRecordSchema>;
export type SendState = SendRecord['state'];
export type SendReason = (typeof SEND_REASONS)[number];
export type SendProvider = (typeof SEND_PROVIDERS)[number];
export type AuditEvent = z.infer<typeof AuditEventSchema>;
export type AuditOutcome = (typeof AUDIT_OUTCOMES)[number];
export type AuditProvider = (typeof AUDIT_PROVIDERS)[number];
export type LedgerData = z.infer<typeof LedgerSchema>;

export interface LedgerKeys {
  enc: Buffer;
  mac: Buffer;
}

const SALT = Buffer.from('perch-mail-workflow-v1');
const aadFor = (namespace: string) => Buffer.from(`perch-mail-workflow|v${LEDGER_VERSION}|AES-256-GCM|${namespace}`);

/** Domain-separated subkeys of the owner's store key (never the store key itself). */
export function deriveLedgerKeys(storeKey: Buffer, namespace: string): LedgerKeys {
  const sub = (label: string) => Buffer.from(hkdfSync('sha256', storeKey, SALT, Buffer.from(`${label}\u0000${namespace}`), 32));
  return { enc: sub('enc'), mac: sub('mac') };
}

/** Encrypts ledger plaintext with the ledger subkey and namespace-bound AAD. */
export function sealLedger(keys: LedgerKeys, namespace: string, plaintext: Buffer): string {
  return encryptEnvelope(keys.enc, plaintext, aadFor(namespace));
}

const corrupt = (why: string) =>
  new PerchError(
    `Mail workflow ledger is unreadable (${why}). Perch fails closed and never resets it: restore ${LEDGER_FILE} from backup.`,
    'ledger_corrupt',
  );

function openLedger(keys: LedgerKeys, namespace: string, raw: string): LedgerData {
  let plain: Buffer;
  try {
    plain = decryptEnvelope(keys.enc, raw, aadFor(namespace));
  } catch (err) {
    if (err instanceof PerchError && err.code === 'store_wrong_key') {
      throw new PerchError(`Mail workflow ledger was encrypted with a different key or namespace; restore ${LEDGER_FILE} from backup`, 'ledger_wrong_key');
    }
    throw corrupt('format or integrity check failed');
  }
  let json: unknown;
  try {
    json = JSON.parse(plain.toString('utf8'));
  } catch {
    throw corrupt('not JSON');
  }
  const head = json as { format?: unknown; version?: unknown; namespace?: unknown } | null;
  if (!head || head.format !== LEDGER_FORMAT) throw corrupt('unknown format');
  if (head.version !== LEDGER_VERSION) throw corrupt(`unsupported version ${JSON.stringify(head.version)}`);
  if (head.namespace !== namespace) throw corrupt('it belongs to another namespace');
  const parsed = LedgerSchema.safeParse(json);
  if (!parsed.success) throw corrupt('schema mismatch');
  return parsed.data;
}

function emptyLedger(namespace: string): LedgerData {
  return { format: LEDGER_FORMAT, version: LEDGER_VERSION, namespace, createdAt: new Date().toISOString(), sends: [], audit: [], auditDropped: 0 };
}

function encode(keys: LedgerKeys, data: LedgerData): string {
  if (data.sends.length > MAX_SEND_RECORDS || data.audit.length > MAX_AUDIT_EVENTS) {
    throw new PerchError(
      `Mail workflow ledger is full (${MAX_SEND_RECORDS} send records). Nothing was sent. Used requestIds are never forgotten, ` +
        'so this namespace cannot send again until a ledger rollover exists (docs/MAIL_WORKFLOW_MILESTONE.md).',
      'ledger_full',
    );
  }
  const parsed = LedgerSchema.safeParse(data);
  if (!parsed.success) throw new PerchError('Refusing to write a mail workflow record that does not match the ledger schema', 'ledger_schema');
  const plain = Buffer.from(JSON.stringify(parsed.data));
  if (plain.length > MAX_LEDGER_PLAINTEXT_BYTES) throw new PerchError('Mail workflow ledger would exceed its size limit; nothing was written', 'ledger_full');
  return sealLedger(keys, data.namespace, plain);
}

export const ledgerFilePath = (dataDir: string) => path.join(dataDir, LEDGER_FILE);
const ledgerLockPath = (dataDir: string) => path.join(dataDir, LEDGER_LOCK);

/**
 * Creates an empty ledger only if none exists (temp file + link, EEXIST instead of overwrite).
 * Returns false when a ledger file already existed (its content is not touched or checked here).
 */
export async function createLedgerFile(dataDir: string, storeKey: Buffer, namespace: string): Promise<boolean> {
  const keys = deriveLedgerKeys(storeKey, namespace);
  return writePrivateFileExclusive(ledgerFilePath(dataDir), Buffer.from(encode(keys, emptyLedger(namespace))));
}

const lostLedger = (file: string, since: string) =>
  new PerchError(
    `Mail workflow ledger ${file} is missing, but this namespace has had one since ${since}. Perch never re-initialises it ` +
      '(that would forget used requestIds and allow duplicate sends): restore it from backup.',
    'ledger_missing',
  );

/**
 * Explicit initialisation for a namespace created before the ledger existed (perch mail-workflow init).
 * Runs under the store lock. The store's `mailWorkflowLedger` marker decides:
 * - marker set: the namespace had a ledger. Missing now = lost: refused (restore from backup), never reset;
 * - no marker, no file: creates the ledger, THEN writes the marker (a crash in between leaves a valid ledger
 *   without marker, which the next init or first ledger write marks);
 * - no marker, file exists: the file must open (key, namespace, schema) before it is marked; never rewritten.
 * Returns true only if a ledger file was created.
 */
export async function initMailWorkflowLedger(store: CredentialStore): Promise<boolean> {
  await store.assertKeyUnchanged();
  const paths = store.storePaths;
  await assertPrivateDir(paths.dataDir);
  const file = ledgerFilePath(paths.dataDir);
  return store.update(async (d) => {
    const exists = await lstat(file).then(
      () => true,
      (err: NodeJS.ErrnoException) => {
        if (err.code === 'ENOENT') return false;
        throw err;
      },
    );
    if (d.mailWorkflowLedger) {
      if (!exists) throw lostLedger(file, d.mailWorkflowLedger.createdAt);
      await new MailWorkflowLedger(store).read();
      return false;
    }
    const created = !exists && (await createLedgerFile(paths.dataDir, parseKey(await readPrivateFile(paths.keyFile)), store.namespace));
    if (!created) await new MailWorkflowLedger(store).read();
    d.mailWorkflowLedger = { createdAt: new Date().toISOString() };
    return created;
  });
}

export class MailWorkflowLedger {
  private derived: LedgerKeys | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(readonly store: CredentialStore) {}

  get namespace(): string {
    return this.store.namespace;
  }

  private get dataDir(): string {
    return this.store.storePaths.dataDir;
  }

  /** The owner's key must still be the one the store was opened with (missing/replaced: fail closed). */
  private async keys(): Promise<LedgerKeys> {
    await this.store.assertKeyUnchanged();
    if (!this.derived) this.derived = deriveLedgerKeys(parseKey(await readPrivateFile(this.store.storePaths.keyFile)), this.namespace);
    return this.derived;
  }

  private async load(keys: LedgerKeys): Promise<LedgerData> {
    await assertPrivateDir(this.dataDir);
    const file = ledgerFilePath(this.dataDir);
    let st;
    try {
      st = await lstat(file);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new PerchError(
          `Mail workflow ledger ${file} is missing. Perch fails closed: restore it from backup. Only if this namespace never had ` +
            'one (created before this version), run perch mail-workflow init.',
          'ledger_missing',
        );
      }
      throw err;
    }
    if (st.isSymbolicLink()) throw new PerchError(`Refusing symlinked file: ${file}`, 'insecure_path');
    if (!st.isFile()) throw new PerchError(`Not a regular file: ${file}`, 'insecure_path');
    if (st.size > MAX_LEDGER_FILE_BYTES) throw corrupt('file too large');
    const raw = await readPrivateFile(file);
    if (raw.length > MAX_LEDGER_FILE_BYTES) throw corrupt('file too large');
    return openLedger(keys, this.namespace, raw.toString('utf8'));
  }

  /** Current ledger (no lock needed: writes replace the file atomically). Fails closed. */
  async read(): Promise<LedgerData> {
    return this.load(await this.keys());
  }

  /**
   * Read-modify-write under an in-process queue and the cross-process `mail-workflow.lock` (held for the
   * local read/encrypt/write only, never across provider I/O; bounded wait, stale locks fail closed and
   * are never taken over). Nothing is written if `fn` throws or the result fails validation. Before the
   * ledger lock is taken, the store's `mailWorkflowLedger` marker must be durably persisted (ensureMarked):
   * no ledger write (audit event, send claim, finalization, resolution) happens without it.
   */
  transact<T>(fn: (data: LedgerData) => T | Promise<T>): Promise<T> {
    const run = async () => {
      await this.ensureMarked();
      return withFileLock(ledgerLockPath(this.dataDir), async () => {
        const keys = await this.keys();
        const data = await this.load(keys);
        const result = await fn(data);
        await writePrivateFileAtomic(ledgerFilePath(this.dataDir), Buffer.from(encode(keys, data)));
        return result;
      });
    };
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => {});
    return p;
  }

  /**
   * A ledger that is written to must be recorded in the store (`mailWorkflowLedger` marker) FIRST, so a later
   * loss of the ledger can never be "fixed" by perch mail-workflow init (which would forget used requestIds).
   * Checked against the persisted store on every write (never an in-memory flag: a marker removed on disk is
   * noticed). Only stores from before the marker lack it; then the existing ledger must open (key, namespace,
   * schema) and the marker is written under the store lock, or the write is refused: a failed marker write
   * is never swallowed. A missing or corrupt ledger is never marked (init stays possible for a namespace that
   * never had one). Lock order: store lock, then (after it is released) the ledger lock; never the reverse.
   */
  private async ensureMarked(): Promise<void> {
    if ((await this.store.read()).mailWorkflowLedger) return;
    await this.store.update(async (d) => {
      if (d.mailWorkflowLedger) return;
      await this.read();
      d.mailWorkflowLedger = { createdAt: new Date().toISOString() };
    });
  }

  /** Appends an audit event; the oldest events are dropped (and counted) beyond MAX_AUDIT_EVENTS. */
  appendAudit(data: LedgerData, event: AuditEvent): void {
    data.audit.push(event);
    while (data.audit.length > MAX_AUDIT_EVENTS) {
      data.audit.shift();
      data.auditDropped += 1;
    }
  }

  /** Keyed, domain-separated, length-prefixed HMAC-SHA256 (hex) under the namespace's ledger MAC subkey. */
  async mac(domain: string, parts: readonly string[]): Promise<string> {
    const h = createHmac('sha256', (await this.keys()).mac).update(`perch-mail-workflow-v1\u0000${domain}\u0000`);
    for (const p of parts) h.update(`${Buffer.byteLength(p, 'utf8')}:`).update(p, 'utf8');
    return h.digest('hex');
  }
}

/** Random operation id for audited calls that have no idempotency key. */
export const newOperationId = () => `op-${randomBytes(12).toString('hex')}`;
