import { PerchError } from '../errors.js';

/**
 * Minimal QR Code encoder (ISO/IEC 18004) for showing an otpauth:// URI: byte mode, error correction level
 * M, versions 1–20, automatic or fixed mask. Built without dependencies; tests compare the module matrix
 * with reference matrices.
 */
export const MAX_QR_VERSION = 20;

/** Level M: [EC codewords per block, group 1 blocks, data codewords per block in group 1, group 2 blocks]. */
const EC_M: ReadonlyArray<readonly [number, number, number, number]> = [
  [10, 1, 16, 0],
  [16, 1, 28, 0],
  [26, 1, 44, 0],
  [18, 2, 32, 0],
  [24, 2, 43, 0],
  [16, 4, 27, 0],
  [18, 4, 31, 0],
  [22, 2, 38, 2],
  [22, 3, 36, 2],
  [26, 4, 43, 1],
  [30, 1, 50, 4],
  [22, 6, 36, 2],
  [22, 8, 37, 1],
  [24, 4, 40, 5],
  [24, 5, 41, 5],
  [28, 7, 45, 3],
  [28, 10, 46, 1],
  [26, 9, 43, 4],
  [26, 3, 44, 11],
  [26, 3, 41, 13],
];

const ALIGNMENT: ReadonlyArray<readonly number[]> = [
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
  [6, 30, 54],
  [6, 32, 58],
  [6, 34, 62],
  [6, 26, 46, 66],
  [6, 26, 48, 70],
  [6, 26, 50, 74],
  [6, 30, 54, 78],
  [6, 30, 56, 82],
  [6, 30, 58, 86],
  [6, 34, 62, 90],
];

const dataCodewords = (v: number) => {
  const [, g1, d1, g2] = EC_M[v - 1]!;
  return g1 * d1 + g2 * (d1 + 1);
};
const countBits = (v: number) => (v <= 9 ? 8 : 16);
const capacityBytes = (v: number) => Math.floor((dataCodewords(v) * 8 - 4 - countBits(v)) / 8);

// GF(256) with the QR primitive polynomial x^8 + x^4 + x^3 + x^2 + 1.
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
}
const gfMul = (a: number, b: number) => (a === 0 || b === 0 ? 0 : EXP[LOG[a]! + LOG[b]!]!);

/** Generator polynomial of degree n (coefficients without the leading 1), roots α^0 … α^(n-1). */
function rsGenerator(n: number): number[] {
  const g = new Array<number>(n).fill(0);
  g[n - 1] = 1;
  let root = 1;
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      g[j] = gfMul(g[j]!, root);
      if (j + 1 < n) g[j] = g[j]! ^ g[j + 1]!;
    }
    root = gfMul(root, 2);
  }
  return g;
}

function rsRemainder(data: readonly number[], gen: readonly number[]): number[] {
  const r = new Array<number>(gen.length).fill(0);
  for (const b of data) {
    const factor = b ^ r.shift()!;
    r.push(0);
    for (let i = 0; i < gen.length; i++) r[i] = r[i]! ^ gfMul(gen[i]!, factor);
  }
  return r;
}

/** Data and error correction codewords of `data` at version `v`, interleaved as placed in the symbol. */
function codewords(data: Uint8Array, v: number): number[] {
  const bits: number[] = [];
  const put = (value: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  put(0b0100, 4);
  put(data.length, countBits(v));
  for (const b of data) put(b, 8);
  const total = dataCodewords(v) * 8;
  put(0, Math.min(4, total - bits.length));
  while (bits.length % 8) bits.push(0);
  const bytes: number[] = [];
  for (let i = 0; i < bits.length; i += 8) bytes.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  for (let pad = 0xec; bytes.length < dataCodewords(v); pad ^= 0xec ^ 0x11) bytes.push(pad);

  const [ec, g1, d1, g2] = EC_M[v - 1]!;
  const gen = rsGenerator(ec);
  const blocks: number[][] = [];
  const ecBlocks: number[][] = [];
  let k = 0;
  for (let i = 0; i < g1 + g2; i++) {
    const len = i < g1 ? d1 : d1 + 1;
    const block = bytes.slice(k, k + len);
    k += len;
    blocks.push(block);
    ecBlocks.push(rsRemainder(block, gen));
  }
  const out: number[] = [];
  for (let i = 0; i < d1 + 1; i++) for (const b of blocks) if (i < b.length) out.push(b[i]!);
  for (let i = 0; i < ec; i++) for (const b of ecBlocks) out.push(b[i]!);
  return out;
}

export interface QrCode {
  version: number;
  mask: number;
  size: number;
  /** modules[row][col]: true = dark. */
  modules: boolean[][];
}

const MASKS: ReadonlyArray<(r: number, c: number) => boolean> = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

class Matrix {
  readonly m: boolean[][];
  readonly fn: boolean[][];
  constructor(readonly size: number) {
    this.m = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
    this.fn = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  }
  set(r: number, c: number, dark: boolean) {
    this.m[r]![c] = dark;
    this.fn[r]![c] = true;
  }
}

function drawFunctionPatterns(q: Matrix, v: number) {
  const n = q.size;
  for (let i = 0; i < n; i++) {
    q.set(6, i, i % 2 === 0);
    q.set(i, 6, i % 2 === 0);
  }
  for (const [cr, cc] of [
    [3, 3],
    [3, n - 4],
    [n - 4, 3],
  ] as const) {
    for (let dr = -4; dr <= 4; dr++) {
      for (let dc = -4; dc <= 4; dc++) {
        const r = cr + dr;
        const c = cc + dc;
        if (r < 0 || r >= n || c < 0 || c >= n) continue;
        const d = Math.max(Math.abs(dr), Math.abs(dc));
        q.set(r, c, d !== 2 && d !== 4);
      }
    }
  }
  const pos = ALIGNMENT[v - 1]!;
  const last = pos.length - 1;
  for (let i = 0; i < pos.length; i++) {
    for (let j = 0; j < pos.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
      for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) q.set(pos[i]! + dr, pos[j]! + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
    }
  }
  drawFormat(q, 0); // reserve; overwritten after masking
  if (v >= 7) {
    let rem = v;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (v << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = n - 11 + (i % 3);
      const b = Math.floor(i / 3);
      q.set(b, a, dark);
      q.set(a, b, dark);
    }
  }
}

/** Format information for level M (bits 00) and `mask`, both copies plus the dark module. */
function drawFormat(q: Matrix, mask: number) {
  const n = q.size;
  const data = mask; // (level M = 0b00) << 3 | mask
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i: number) => ((bits >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) q.set(i, 8, bit(i));
  q.set(7, 8, bit(6));
  q.set(8, 8, bit(7));
  q.set(8, 7, bit(8));
  for (let i = 9; i < 15; i++) q.set(8, 14 - i, bit(i));
  for (let i = 0; i < 8; i++) q.set(8, n - 1 - i, bit(i));
  for (let i = 8; i < 15; i++) q.set(n - 15 + i, 8, bit(i));
  q.set(n - 8, 8, true);
}

function drawCodewords(q: Matrix, data: readonly number[]) {
  const n = q.size;
  let i = 0;
  for (let right = n - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < n; vert++) {
      for (let j = 0; j < 2; j++) {
        const c = right - j;
        const upward = ((right + 1) & 2) === 0;
        const r = upward ? n - 1 - vert : vert;
        if (!q.fn[r]![c] && i < data.length * 8) {
          q.m[r]![c] = ((data[i >>> 3]! >>> (7 - (i & 7))) & 1) === 1;
          i++;
        }
      }
    }
  }
}

function applyMask(q: Matrix, mask: number) {
  const f = MASKS[mask]!;
  for (let r = 0; r < q.size; r++) for (let c = 0; c < q.size; c++) if (!q.fn[r]![c] && f(r, c)) q.m[r]![c] = !q.m[r]![c];
}

/** ISO/IEC 18004 §7.8.3 penalty (N1 = 3, N2 = 3, N3 = 40, N4 = 10). */
export function penalty(m: readonly boolean[][]): number {
  const n = m.length;
  let score = 0;
  const at = (r: number, c: number, byRow: boolean) => (byRow ? m[r]![c]! : m[c]![r]!);
  for (const byRow of [true, false]) {
    for (let r = 0; r < n; r++) {
      let run = 1;
      for (let c = 1; c <= n; c++) {
        if (c < n && at(r, c, byRow) === at(r, c - 1, byRow)) run++;
        else {
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
        }
      }
      // 1:1:3:1:1 finder-like pattern with 4 light modules on one side.
      for (let c = 0; c + 6 < n; c++) {
        const p = [true, false, true, true, true, false, true].every((d, k) => at(r, c + k, byRow) === d);
        if (!p) continue;
        const lightBefore = c >= 4 && [1, 2, 3, 4].every((k) => !at(r, c - k, byRow));
        const lightAfter = c + 10 < n && [7, 8, 9, 10].every((k) => !at(r, c + k, byRow));
        if (lightBefore || lightAfter) score += 40;
      }
    }
  }
  for (let r = 0; r + 1 < n; r++) {
    for (let c = 0; c + 1 < n; c++) {
      const v = m[r]![c];
      if (m[r]![c + 1] === v && m[r + 1]![c] === v && m[r + 1]![c + 1] === v) score += 3;
    }
  }
  let dark = 0;
  for (const row of m) for (const d of row) if (d) dark++;
  score += Math.floor(Math.abs(dark * 20 - n * n * 10) / (n * n)) * 10;
  return score;
}

/** Encodes `text` (UTF-8 bytes) at level M in the smallest version that fits. */
export function encodeQr(text: string, opts: { mask?: number; minVersion?: number } = {}): QrCode {
  const data = new TextEncoder().encode(text);
  let v = Math.max(1, opts.minVersion ?? 1);
  while (v <= MAX_QR_VERSION && capacityBytes(v) < data.length) v++;
  if (v > MAX_QR_VERSION) throw new PerchError(`Text too long for a QR code (at most ${capacityBytes(MAX_QR_VERSION)} bytes)`, 'qr_too_long');
  const cw = codewords(data, v);
  const build = (mask: number) => {
    const q = new Matrix(17 + 4 * v);
    drawFunctionPatterns(q, v);
    drawCodewords(q, cw);
    applyMask(q, mask);
    drawFormat(q, mask);
    return q;
  };
  if (opts.mask !== undefined) {
    if (!Number.isInteger(opts.mask) || opts.mask < 0 || opts.mask > 7) throw new PerchError('QR mask must be 0-7', 'qr_mask');
    const q = build(opts.mask);
    return { version: v, mask: opts.mask, size: q.size, modules: q.m };
  }
  let best: { q: Matrix; mask: number; score: number } | undefined;
  for (let mask = 0; mask < 8; mask++) {
    const q = build(mask);
    const score = penalty(q.m);
    if (!best || score < best.score) best = { q, mask, score };
  }
  return { version: v, mask: best!.mask, size: best!.q.size, modules: best!.q.m };
}

/**
 * Terminal rendering with Unicode half blocks (two module rows per line) and a 2-module quiet zone, drawn
 * as dark-on-light so it scans on both dark and light terminal themes.
 */
export function renderQrTerminal(qr: QrCode): string {
  const quiet = 2;
  const n = qr.size + quiet * 2;
  const dark = (r: number, c: number) => {
    const rr = r - quiet;
    const cc = c - quiet;
    return rr >= 0 && rr < qr.size && cc >= 0 && cc < qr.size && qr.modules[rr]![cc]!;
  };
  const lines: string[] = [];
  for (let r = 0; r < n; r += 2) {
    let line = '';
    for (let c = 0; c < n; c++) {
      const top = dark(r, c);
      const bottom = r + 1 < n && dark(r + 1, c);
      // Light modules are printed as the block, dark ones as space (inverse video of the terminal background).
      line += top ? (bottom ? ' ' : '▄') : bottom ? '▀' : '█';
    }
    lines.push(line);
  }
  return `${lines.join('\n')}\n`;
}

/** SVG rendering (for the local setup page); 4-module quiet zone, crisp edges. */
export function renderQrSvg(qr: QrCode, scale = 6): string {
  const quiet = 4;
  const n = qr.size + quiet * 2;
  let path = '';
  for (let r = 0; r < qr.size; r++) for (let c = 0; c < qr.size; c++) if (qr.modules[r]![c]) path += `M${c + quiet} ${r + quiet}h1v1h-1z`;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n} ${n}" width="${n * scale}" height="${n * scale}" shape-rendering="crispEdges">` +
    `<rect width="${n}" height="${n}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`
  );
}
