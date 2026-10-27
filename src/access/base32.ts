import { PerchError } from '../errors.js';

/** RFC 4648 base32 alphabet (upper case). */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 §6 base32. `pad: false` drops the trailing '=' (otpauth URIs and pairing codes). */
export function base32Encode(data: Uint8Array, opts: { pad?: boolean } = {}): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31];
  if (opts.pad !== false) while (out.length % 8 !== 0) out += '=';
  return out;
}

/**
 * Strict decoder: upper or lower case, optional '=' padding, no other characters. Bits left over after the
 * last full byte must be zero (canonical encoding only).
 */
export function base32Decode(text: string): Buffer {
  const s = text.replace(/=+$/, '').toUpperCase();
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of s) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new PerchError('Invalid base32 text', 'bad_base32');
    buffer = ((buffer << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (bits >= 5 || (buffer & ((1 << bits) - 1)) !== 0) throw new PerchError('Invalid base32 text', 'bad_base32');
  return Buffer.from(out);
}
