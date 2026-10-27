import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { base32Encode } from './base32.js';

/**
 * TOTP (RFC 6238) on HOTP (RFC 4226) with the parameters every common authenticator app supports:
 * HMAC-SHA1, 6 digits, 30-second steps. Built on node:crypto only.
 */
export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
/** 160-bit secrets (RFC 4226 §4 recommends at least 128 bits; 160 matches the SHA-1 block output). */
export const TOTP_SECRET_BYTES = 20;
/** Accepted clock drift in steps on either side of "now". */
export const TOTP_WINDOW = 1;

export const newTotpSecret = (): Buffer => randomBytes(TOTP_SECRET_BYTES);

/** HOTP value of `counter` (RFC 4226 §5.3 dynamic truncation), zero-padded to `digits`. */
export function hotp(secret: Buffer, counter: number, digits = TOTP_DIGITS): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(msg).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export const totpStep = (nowMs: number) => Math.floor(nowMs / 1000 / TOTP_PERIOD_SECONDS);

export function totp(secret: Buffer, nowMs: number, digits = TOTP_DIGITS): string {
  return hotp(secret, totpStep(nowMs), digits);
}

/**
 * Checks `code` against the steps now-1 … now+1 that are LATER than `lastUsedStep` (each step is accepted
 * at most once, so an observed code cannot be replayed). Returns the matched step, or null. Every candidate
 * is compared in constant time; malformed input never matches.
 */
export function verifyTotp(secret: Buffer, code: string, nowMs: number, lastUsedStep: number | undefined): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const now = totpStep(nowMs);
  let matched: number | null = null;
  for (let step = now - TOTP_WINDOW; step <= now + TOTP_WINDOW; step++) {
    const ok = timingSafeEqual(Buffer.from(hotp(secret, step)), Buffer.from(code));
    if (ok && (lastUsedStep === undefined || step > lastUsedStep) && matched === null) matched = step;
  }
  return matched;
}

/** Key URI for authenticator apps (de-facto otpauth format): label and issuer are fixed, plain ASCII. */
export function otpauthUri(secret: Buffer, account: string): string {
  const label = encodeURIComponent(`Perch:${account}`);
  return `otpauth://totp/${label}?secret=${base32Encode(secret, { pad: false })}&issuer=Perch&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD_SECONDS}`;
}
