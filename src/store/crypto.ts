import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { PerchError } from '../errors.js';

export const KEY_BYTES = 32;
const VERSION = 1;
const ALG = 'AES-256-GCM';
const AAD = Buffer.from(`perch-store|v${VERSION}|${ALG}`);
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** Decodes canonical, padded base64 only (Buffer.from silently skips junk and truncates). */
function strictBase64(s: string): Buffer | null {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) return null;
  const buf = Buffer.from(s, 'base64');
  return buf.toString('base64') === s ? buf : null;
}

interface Envelope {
  v: number;
  alg: string;
  kid: string;
  iv: string;
  tag: string;
  ct: string;
}

/** Non-reversible key fingerprint, used only to tell "wrong key" apart from "tampered data". */
export function keyId(key: Buffer): string {
  return createHash('sha256').update('perch-kid').update(key).digest('hex').slice(0, 16);
}

/**
 * `aad` defaults to the credential store's associated data. Other files encrypted with the same envelope
 * (the mail workflow ledger) pass their own AAD so one file can never be decrypted as the other.
 */
export function encryptEnvelope(key: Buffer, plaintext: Buffer, aad: Buffer = AAD): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const env: Envelope = {
    v: VERSION,
    alg: ALG,
    kid: keyId(key),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: ct.toString('base64'),
  };
  return JSON.stringify(env);
}

export function decryptEnvelope(key: Buffer, raw: string, aad: Buffer = AAD): Buffer {
  let env: Envelope;
  try {
    env = JSON.parse(raw) as Envelope;
  } catch {
    throw new PerchError('Credential store has an unknown format', 'store_format');
  }
  if (
    !env ||
    env.v !== VERSION ||
    env.alg !== ALG ||
    typeof env.kid !== 'string' ||
    typeof env.iv !== 'string' ||
    typeof env.tag !== 'string' ||
    typeof env.ct !== 'string'
  ) {
    throw new PerchError('Credential store has an unknown format', 'store_format');
  }
  const iv = strictBase64(env.iv);
  const tag = strictBase64(env.tag);
  const ct = strictBase64(env.ct);
  if (!iv || !tag || !ct || iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new PerchError('Credential store has an unknown format', 'store_format');
  }
  const expected = Buffer.from(keyId(key));
  const actual = Buffer.from(env.kid);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    throw new PerchError('Credential store was encrypted with a different key (wrong key file)', 'store_wrong_key');
  }
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new PerchError('Credential store failed its integrity check (tampered or corrupted)', 'store_integrity');
  }
}

export function parseKey(contents: Buffer): Buffer {
  const key = Buffer.from(contents.toString('utf8').trim(), 'base64');
  if (key.length !== KEY_BYTES) throw new PerchError(`Key file must contain ${KEY_BYTES} bytes (base64)`, 'bad_key');
  return key;
}

export function generateKeyFileContents(): Buffer {
  return Buffer.from(`${randomBytes(KEY_BYTES).toString('base64')}\n`);
}
