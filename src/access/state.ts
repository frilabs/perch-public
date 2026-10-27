import { createHash, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import { PerchError } from '../errors.js';
import { assertPrivateDir, readPrivateFile, writePrivateFileAtomic, writePrivateFileExclusive } from '../secureFs.js';
import type { CredentialStore } from '../store/credentialStore.js';
import { decryptEnvelope, encryptEnvelope, parseKey } from '../store/crypto.js';
import { withFileLock } from '../store/lock.js';
import { base32Encode } from './base32.js';

/**
 * Encrypted state of the public access (docs/PUBLIC_ACCESS_SPEC.md §7). Storage contract:
 * - file `oauth.enc` and lock directory `oauth.lock` next to `store.enc`;
 * - the credential-store envelope (AES-256-GCM, fresh IV per write) under a domain-separated subkey
 *   HKDF-SHA256(store key, salt "perch-oauth-v1", info "enc") and its own AAD;
 * - plaintext strictly validated on every read and write; tokens, codes and recovery codes only as hashes.
 *
 * A missing file means "public access never set up" (read returns the empty state; the first write creates
 * it exclusively). A corrupt, foreign, future-version or symlinked file fails closed and is never reset.
 */

export const OAUTH_FILE = 'oauth.enc';
export const OAUTH_LOCK = 'oauth.lock';
const FORMAT = 'perch-oauth';
const VERSION = 1;
const MAX_FILE_BYTES = 1024 * 1024;

/** Feste Obergrenzen (Spec §7). */
export const MAX_ACTIVE_DEVICES = 50;
/** Revoked/expired device records kept for the device list and audit context. */
export const MAX_DEVICE_RECORDS = 200;
export const MAX_LOGIN_ALLOW = 10;
export const MAX_PREREGISTERED_CLIENTS = 20;
export const MAX_CIMD_URLS = 20;
export const RECOVERY_CODE_COUNT = 10;
/** Rotated refresh-token hashes remembered per device for reuse detection. */
const MAX_PREVIOUS_REFRESH = 100;

export const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000;
export const REFRESH_IDLE_MS = 14 * 24 * 60 * 60 * 1000;
export const DEVICE_ABSOLUTE_MS = 90 * 24 * 60 * 60 * 1000;
/** A paired device whose authorization code was never exchanged expires after this. */
export const UNUSED_DEVICE_MS = 10 * 60 * 1000;

const HEX64 = /^[a-f0-9]{64}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
export const DEVICE_ID_PATTERN = /^oc-[a-f0-9]{16}$/;
export const PRECLIENT_ID_PATTERN = /^pc-[a-f0-9]{16}$/;
export const DCR_CLIENT_ID_PATTERN = /^dcr-[a-f0-9]{16}$/;
const EMAIL = z.string().min(3).max(254).regex(/^[^\s@]+@[^\s@]+$/);

const LoginAllowSchema = z.strictObject({
  email: EMAIL,
  /** Google `sub`, pinned at the first successful login. */
  sub: z.string().regex(/^[0-9]{1,64}$/).optional(),
  addedAt: z.string().regex(ISO),
});

const RecoveryCodeSchema = z.strictObject({
  salt: z.string().regex(/^[a-f0-9]{32}$/),
  hash: z.string().regex(HEX64),
  usedAt: z.string().regex(ISO).optional(),
});

const TotpSchema = z.strictObject({
  /** base64 of the 20-byte secret. */
  secret: z.string().regex(/^[A-Za-z0-9+/]{27}=$/),
  /** Last accepted 30-second step (each step is accepted once). */
  lastStep: z.number().int().min(0).optional(),
  createdAt: z.string().regex(ISO),
  recovery: z.array(RecoveryCodeSchema).max(RECOVERY_CODE_COUNT),
});

export const REGISTRATIONS = ['cimd', 'dcr', 'preregistered'] as const;

const FamilySchema = z.strictObject({
  accessHash: z.string().regex(HEX64).optional(),
  accessExpiresAt: z.string().regex(ISO).optional(),
  refreshHash: z.string().regex(HEX64).optional(),
  refreshedAt: z.string().regex(ISO).optional(),
  previousRefresh: z.array(z.string().regex(HEX64)).max(MAX_PREVIOUS_REFRESH),
});

const DeviceSchema = z.strictObject({
  id: z.string().regex(DEVICE_ID_PATTERN),
  clientId: z.string().min(1).max(512),
  clientName: z.string().max(100),
  registration: z.enum(REGISTRATIONS),
  redirectHost: z.string().max(253),
  /**
   * Listener the device was paired on and the only one its tokens work on (docs/SIMPLE_CONNECT_SPEC.md §1).
   * Records written before the private listener had OAuth have no origin: they are public.
   */
  origin: z.enum(['private', 'public']).optional(),
  /** Google account of the sign-in (public pairing only; the private listener does not ask for one). */
  googleEmail: EMAIL.optional(),
  userAgent: z.string().max(200).optional(),
  ip: z.string().max(64).optional(),
  pairedAt: z.string().regex(ISO),
  expiresAt: z.string().regex(ISO),
  lastSeenAt: z.string().regex(ISO).optional(),
  /**
   * `pending`: confirmed by the operator, authorization code issued, not yet exchanged. Only the first
   * successful code exchange makes it `active`; a pending device has no tokens and is removed when its code
   * expires or its window closes first (docs/SIMPLE_CONNECT_SPEC.md §5).
   */
  status: z.enum(['pending', 'active', 'revoked', 'expired']),
  endedAt: z.string().regex(ISO).optional(),
  endedReason: z.enum(['revoked', 'refresh_reuse', 'idle', 'absolute', 'kill_switch', 'totp_changed', 'unused', 'code_reuse']).optional(),
  /** Client grant (store.enc) with write capabilities; without one the device reads like the global token. */
  grantClientId: z.string().regex(/^client-[a-f0-9]{8}$/).optional(),
  family: FamilySchema,
});

const PreClientSchema = z.strictObject({
  id: z.string().regex(PRECLIENT_ID_PATTERN),
  name: z.string().min(1).max(100),
  redirectUris: z.array(z.string().max(512)).min(1).max(5),
  createdAt: z.string().regex(ISO),
});

const OAuthStateSchema = z.strictObject({
  format: z.literal(FORMAT),
  version: z.literal(VERSION),
  createdAt: z.string().regex(ISO),
  loginAllow: z.array(LoginAllowSchema).max(MAX_LOGIN_ALLOW),
  totp: TotpSchema.optional(),
  preClients: z.array(PreClientSchema).max(MAX_PREREGISTERED_CLIENTS),
  cimdUrls: z.array(z.string().max(512)).max(MAX_CIMD_URLS),
  devices: z.array(DeviceSchema).max(MAX_DEVICE_RECORDS),
  /** Kill switch marker (perch public off): the public listener answers 503 while set. */
  publicLocked: z.strictObject({ since: z.string().regex(ISO) }).optional(),
  /** Wrong Perch codes (timestamps) and the resulting pairing lockout (Spec §9). */
  totpFailures: z.array(z.string().regex(ISO)).max(50),
  pairLock: z.strictObject({ until: z.string().regex(ISO), level: z.number().int().min(1).max(20) }).optional(),
  /** Local pairing page (/local/pair): SHA-256 of its own password; absent = page disabled. */
  localPage: z.strictObject({ passwordHash: z.string().regex(HEX64), createdAt: z.string().regex(ISO) }).optional(),
});

export type OAuthState = z.infer<typeof OAuthStateSchema>;
export type Device = z.infer<typeof DeviceSchema>;
export type Registration = (typeof REGISTRATIONS)[number];

const SALT = Buffer.from('perch-oauth-v1');
const AAD = Buffer.from(`perch-oauth|v${VERSION}|AES-256-GCM`);

const corrupt = (why: string) =>
  new PerchError(`Public access state is unreadable (${why}). Perch fails closed and never resets it: restore ${OAUTH_FILE} from backup.`, 'oauth_state_corrupt');

export function emptyOAuthState(): OAuthState {
  return { format: FORMAT, version: VERSION, createdAt: new Date().toISOString(), loginAllow: [], preClients: [], cimdUrls: [], devices: [], totpFailures: [] };
}

export const sha256Hex = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
export const newToken = () => randomBytes(32).toString('base64url');
export const newDeviceId = () => `oc-${randomBytes(8).toString('hex')}`;

/** Constant-time comparison of two hex digests of equal length. */
export function hexEqual(a: string, b: string): boolean {
  return a.length === b.length && timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/** 10 recovery codes (10 base32 characters = 50 bits each): returns the codes once and their salted hashes. */
export function newRecoveryCodes(): { codes: string[]; records: Array<{ salt: string; hash: string }> } {
  const codes: string[] = [];
  const records: Array<{ salt: string; hash: string }> = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const code = base32Encode(randomBytes(7), { pad: false }).slice(0, 10);
    const salt = randomBytes(16).toString('hex');
    codes.push(code);
    records.push({ salt, hash: sha256Hex(`${salt}:${code}`) });
  }
  return { codes, records };
}

/** Normalises user input of a recovery code (case, spaces, dashes). */
export const normaliseRecoveryCode = (s: string) => s.replace(/[\s-]/g, '').toUpperCase();

export class OAuthStore {
  private derived: Buffer | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(readonly store: CredentialStore) {}

  private get dataDir() {
    return this.store.storePaths.dataDir;
  }
  get file() {
    return path.join(this.dataDir, OAUTH_FILE);
  }

  private async key(): Promise<Buffer> {
    await this.store.assertKeyUnchanged();
    if (!this.derived) {
      const storeKey = parseKey(await readPrivateFile(this.store.storePaths.keyFile));
      this.derived = Buffer.from(hkdfSync('sha256', storeKey, SALT, Buffer.from('enc'), 32));
    }
    return this.derived;
  }

  private decode(key: Buffer, raw: string): OAuthState {
    let plain: Buffer;
    try {
      plain = decryptEnvelope(key, raw, AAD);
    } catch {
      throw corrupt('format, key or integrity check failed');
    }
    let json: unknown;
    try {
      json = JSON.parse(plain.toString('utf8'));
    } catch {
      throw corrupt('not JSON');
    }
    const head = json as { format?: unknown; version?: unknown } | null;
    if (!head || head.format !== FORMAT) throw corrupt('unknown format');
    if (head.version !== VERSION) throw corrupt(`unsupported version ${JSON.stringify(head.version)}`);
    const parsed = OAuthStateSchema.safeParse(json);
    if (!parsed.success) throw corrupt('schema mismatch');
    return parsed.data;
  }

  private encode(key: Buffer, data: OAuthState): Buffer {
    if (data.devices.filter((d) => d.status === 'active' || d.status === 'pending').length > MAX_ACTIVE_DEVICES) {
      throw new PerchError(`At most ${MAX_ACTIVE_DEVICES} active devices; revoke some first (perch oauth devices)`, 'too_many_devices');
    }
    // Keep the newest records when old revoked/expired ones exceed the bound.
    while (data.devices.length > MAX_DEVICE_RECORDS) {
      const i = data.devices.findIndex((d) => d.status !== 'active' && d.status !== 'pending');
      if (i < 0) break;
      data.devices.splice(i, 1);
    }
    const parsed = OAuthStateSchema.safeParse(data);
    if (!parsed.success) throw new PerchError('Refusing to write public access state that does not match its schema', 'oauth_state_schema');
    return Buffer.from(encryptEnvelope(key, Buffer.from(JSON.stringify(parsed.data)), AAD));
  }

  private async load(key: Buffer): Promise<OAuthState | null> {
    await assertPrivateDir(this.dataDir);
    let st;
    try {
      st = await lstat(this.file);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw err;
    }
    if (st.isSymbolicLink()) throw new PerchError(`Refusing symlinked file: ${this.file}`, 'insecure_path');
    if (!st.isFile()) throw new PerchError(`Not a regular file: ${this.file}`, 'insecure_path');
    if (st.size > MAX_FILE_BYTES) throw corrupt('file too large');
    return this.decode(key, (await readPrivateFile(this.file)).toString('utf8'));
  }

  /** Current state; the empty state if public access was never set up. Fails closed on damage. */
  async read(): Promise<OAuthState> {
    return (await this.load(await this.key())) ?? emptyOAuthState();
  }

  /**
   * Read-modify-write under an in-process queue and the cross-process lock. Nothing is written if `fn`
   * throws. The first write creates the file exclusively (a concurrent creator wins; we then retry once).
   */
  transact<T>(fn: (data: OAuthState) => T | Promise<T>): Promise<T> {
    const run = () =>
      withFileLock(path.join(this.dataDir, OAUTH_LOCK), async () => {
        const key = await this.key();
        const existing = await this.load(key);
        const data = existing ?? emptyOAuthState();
        const result = await fn(data);
        const bytes = this.encode(key, data);
        if (existing) await writePrivateFileAtomic(this.file, bytes);
        else if (!(await writePrivateFileExclusive(this.file, bytes))) throw new PerchError('Public access state was created concurrently; retry', 'oauth_state_race');
        return result;
      });
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => {});
    return p;
  }
}

/** Ends an active or pending device (no tokens work afterwards). */
export function endDevice(d: Device, reason: NonNullable<Device['endedReason']>, now = new Date()): void {
  if (d.status !== 'active' && d.status !== 'pending') return;
  d.status = reason === 'idle' || reason === 'absolute' || reason === 'unused' ? 'expired' : 'revoked';
  d.endedAt = now.toISOString();
  d.endedReason = reason;
  d.family = { previousRefresh: d.family.previousRefresh };
}

/** Marks devices expired by idle time or absolute lifetime. Returns true if anything changed. */
export function expireDevices(data: OAuthState, now = new Date()): boolean {
  let changed = false;
  for (const d of data.devices) {
    if (d.status !== 'active' && d.status !== 'pending') continue;
    // Pending devices are removed when their code expires; this is the fallback (e.g. a crash in between).
    if ((d.status === 'pending' || !d.family.refreshHash) && Date.parse(d.pairedAt) + UNUSED_DEVICE_MS <= now.getTime()) {
      endDevice(d, 'unused', now);
      changed = true;
    } else if (Date.parse(d.expiresAt) <= now.getTime()) {
      endDevice(d, 'absolute', now);
      changed = true;
    } else if (Date.parse(d.family.refreshedAt ?? d.pairedAt) + REFRESH_IDLE_MS <= now.getTime()) {
      endDevice(d, 'idle', now);
      changed = true;
    }
  }
  return changed;
}

/**
 * Removes pending devices matching `pred` (default: all) from the records. Returns the grant ids they held,
 * which the caller removes from the credential store.
 */
export function removePendingDevices(data: OAuthState, pred: (d: Device) => boolean = () => true): string[] {
  const grants: string[] = [];
  data.devices = data.devices.filter((d) => {
    if (d.status !== 'pending' || !pred(d)) return true;
    if (d.grantClientId) grants.push(d.grantClientId);
    return false;
  });
  return grants;
}

export const isPublicLocked = (s: OAuthState) => s.publicLocked !== undefined;

export type ListenerKind = 'private' | 'public';
/** Old device records (no origin) are public. */
export const deviceOrigin = (d: Pick<Device, 'origin'>): ListenerKind => d.origin ?? 'public';
