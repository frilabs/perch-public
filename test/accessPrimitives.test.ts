// Self-built primitives of the public access milestone, checked against reference values: RFC 4648 base32
// vectors, RFC 6238 TOTP vectors (SHA-1) and QR module matrices generated offline by an independent encoder
// (test/support/qrReference.json; dev-only fixture, not a dependency).
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { base32Decode, base32Encode } from '../src/access/base32.js';
import { encodeQr, penalty, renderQrSvg, renderQrTerminal } from '../src/access/qr.js';
import { hotp, otpauthUri, totp, totpStep, verifyTotp } from '../src/access/totp.js';

describe('base32 (RFC 4648 §10 vectors)', () => {
  const vectors: Array<[string, string]> = [
    ['', ''],
    ['f', 'MY======'],
    ['fo', 'MZXQ===='],
    ['foo', 'MZXW6==='],
    ['foob', 'MZXW6YQ='],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI======'],
  ];
  it('encodes and decodes the vectors', () => {
    for (const [plain, enc] of vectors) {
      expect(base32Encode(Buffer.from(plain))).toBe(enc);
      expect(base32Decode(enc).toString()).toBe(plain);
      expect(base32Decode(enc.replace(/=/g, '').toLowerCase()).toString()).toBe(plain);
    }
    expect(base32Encode(Buffer.from('foobar'), { pad: false })).toBe('MZXW6YTBOI');
  });
  it('rejects foreign characters and non-canonical trailing bits', () => {
    for (const bad of ['MZXW6YT1', 'MZ XW', 'MZXW6YTBOJ', 'M']) expect(() => base32Decode(bad)).toThrow(/base32/);
  });
});

describe('TOTP (RFC 6238 Appendix B, SHA-1)', () => {
  const secret = Buffer.from('12345678901234567890');
  const vectors: Array<[number, string]> = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];
  it('matches the 8-digit vectors', () => {
    for (const [t, code] of vectors) expect(totp(secret, t * 1000, 8)).toBe(code);
  });
  it('matches RFC 4226 Appendix D HOTP values', () => {
    expect([0, 1, 2, 9].map((c) => hotp(secret, c))).toEqual(['755224', '287082', '359152', '520489']);
  });
  it('accepts ±1 step once, never a replay or an older step, and rejects malformed codes', () => {
    const now = 1_700_000_000_000;
    const step = totpStep(now);
    expect(verifyTotp(secret, hotp(secret, step), now, undefined)).toBe(step);
    expect(verifyTotp(secret, hotp(secret, step - 1), now, undefined)).toBe(step - 1);
    expect(verifyTotp(secret, hotp(secret, step + 1), now, undefined)).toBe(step + 1);
    expect(verifyTotp(secret, hotp(secret, step + 2), now, undefined)).toBeNull();
    expect(verifyTotp(secret, hotp(secret, step - 2), now, undefined)).toBeNull();
    expect(verifyTotp(secret, hotp(secret, step), now, step)).toBeNull(); // replay
    expect(verifyTotp(secret, hotp(secret, step - 1), now, step - 1)).toBeNull();
    expect(verifyTotp(secret, hotp(secret, step), now, step - 1)).toBe(step);
    for (const bad of ['', '12345', '1234567', 'abcdef', ' 12345']) expect(verifyTotp(secret, bad, now, undefined)).toBeNull();
  });
  it('builds an otpauth URI without padding', () => {
    expect(otpauthUri(Buffer.from('foobar'), 'host.example')).toBe(
      'otpauth://totp/Perch%3Ahost.example?secret=MZXW6YTBOI&issuer=Perch&algorithm=SHA1&digits=6&period=30',
    );
  });
});

interface QrCase {
  text: string;
  mask: number | null;
  version: number;
  chosenMask: number;
  rows: string[];
  auto?: boolean;
}
const reference = JSON.parse(readFileSync(new URL('./support/qrReference.json', import.meta.url), 'utf8')) as { cases: QrCase[] };
const rowsOf = (m: boolean[][]) => m.map((r) => r.map((d) => (d ? '1' : '0')).join(''));

describe('QR encoder (level M, byte mode) against reference matrices', () => {
  it('produces identical matrices for every reference case with the reference mask', () => {
    for (const c of reference.cases) {
      const qr = encodeQr(c.text, { mask: c.chosenMask });
      expect(qr.version, c.text).toBe(c.version);
      expect(rowsOf(qr.modules), `${c.text.slice(0, 20)} mask ${c.chosenMask}`).toEqual(c.rows);
    }
  });
  it('picks a mask with the lowest penalty', () => {
    for (const c of reference.cases.filter((x) => x.auto)) {
      const auto = encodeQr(c.text);
      const scores = [0, 1, 2, 3, 4, 5, 6, 7].map((m) => penalty(encodeQr(c.text, { mask: m }).modules));
      expect(penalty(auto.modules)).toBe(Math.min(...scores));
    }
  });
  it('rejects too long text and bad masks', () => {
    expect(() => encodeQr('x'.repeat(700))).toThrow(/too long/);
    expect(() => encodeQr('x', { mask: 8 })).toThrow(/mask/);
  });
  it('renders for the terminal and as SVG', () => {
    const qr = encodeQr('perch');
    const lines = renderQrTerminal(qr).trimEnd().split('\n');
    expect(lines).toHaveLength(Math.ceil((qr.size + 4) / 2));
    expect(lines.every((l) => [...l].length === qr.size + 4)).toBe(true);
    const svg = renderQrSvg(qr);
    expect(svg).toMatch(/^<svg xmlns="http:\/\/www.w3.org\/2000\/svg"/);
    expect(svg).not.toMatch(/<script/);
  });
});
