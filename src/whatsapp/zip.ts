import { crc32, inflateRawSync } from 'node:zlib';
import { PerchError } from '../errors.js';

/**
 * Minimal ZIP reader for `perch whatsapp install` (docs/WHATSAPP_INSTALL_SPEC.md): reads the central
 * directory and extracts exactly one top-level entry by name (stored or deflate). No ZIP64, no
 * encryption, no multi-disk archives. The archive is rejected as a whole if any entry name is absolute,
 * contains a ".." segment, a backslash or a drive letter, so a hostile archive never gets half-used.
 */

const EOCD_SIG = 0x06054b50;
const CEN_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;
const EOCD_MIN = 22;
const MAX_COMMENT = 0xffff;
const MAX_ENTRIES = 1000;

const bad = (why: string) => new PerchError(`The downloaded archive is not usable: ${why}`, 'bad_archive');

interface CentralEntry {
  name: string;
  flags: number;
  method: number;
  crc: number;
  compressedSize: number;
  size: number;
  localOffset: number;
}

function unsafeName(name: string): boolean {
  if (!name || name.includes('\\') || name.includes('\0') || name.startsWith('/') || /^[A-Za-z]:/.test(name)) return true;
  return name.split('/').some((seg) => seg === '..');
}

function readCentralDirectory(zip: Buffer): CentralEntry[] {
  if (zip.length < EOCD_MIN) throw bad('too short');
  let eocd = -1;
  for (let i = zip.length - EOCD_MIN; i >= Math.max(0, zip.length - EOCD_MIN - MAX_COMMENT); i--) {
    if (zip.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw bad('no end of central directory');
  const disk = zip.readUInt16LE(eocd + 4);
  const cdDisk = zip.readUInt16LE(eocd + 6);
  const countDisk = zip.readUInt16LE(eocd + 8);
  const count = zip.readUInt16LE(eocd + 10);
  const cdSize = zip.readUInt32LE(eocd + 12);
  const cdOffset = zip.readUInt32LE(eocd + 16);
  if (disk !== 0 || cdDisk !== 0 || countDisk !== count) throw bad('multi-disk archives are not supported');
  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) throw bad('ZIP64 is not supported');
  if (count > MAX_ENTRIES) throw bad('too many entries');
  if (cdOffset + cdSize > eocd) throw bad('central directory out of bounds');
  const entries: CentralEntry[] = [];
  let p = cdOffset;
  for (let n = 0; n < count; n++) {
    if (p + 46 > cdOffset + cdSize || zip.readUInt32LE(p) !== CEN_SIG) throw bad('corrupt central directory');
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const end = p + 46 + nameLen + extraLen + commentLen;
    if (end > cdOffset + cdSize) throw bad('corrupt central directory');
    const name = zip.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    if (unsafeName(name)) throw bad(`unsafe entry name ${JSON.stringify(name.slice(0, 80))}`);
    entries.push({
      name,
      flags: zip.readUInt16LE(p + 8),
      method: zip.readUInt16LE(p + 10),
      crc: zip.readUInt32LE(p + 16),
      compressedSize: zip.readUInt32LE(p + 20),
      size: zip.readUInt32LE(p + 24),
      localOffset: zip.readUInt32LE(p + 42),
    });
    p = end;
  }
  return entries;
}

/** Lists the entry names (after the same safety checks as extraction). */
export function listZipEntries(zip: Buffer): string[] {
  return readCentralDirectory(zip).map((e) => e.name);
}

/**
 * Extracts the single top-level entry `name` from `zip`, refusing anything larger than `maxBytes`
 * (declared or actual) and verifying the CRC-32.
 */
export function extractZipEntry(zip: Buffer, name: string, maxBytes: number): Buffer {
  if (name.includes('/') || unsafeName(name)) throw new PerchError('Internal error: entry name must be a plain top-level name', 'internal');
  const entries = readCentralDirectory(zip);
  const matches = entries.filter((e) => e.name === name);
  if (matches.length !== 1) throw bad(matches.length ? `entry "${name}" appears more than once` : `entry "${name}" is missing`);
  const e = matches[0]!;
  if (e.flags & 0x1) throw bad('encrypted entries are not supported');
  if (e.size > maxBytes || e.compressedSize > maxBytes) throw bad(`entry "${name}" exceeds the ${maxBytes} byte limit`);
  const l = e.localOffset;
  if (l + 30 > zip.length || zip.readUInt32LE(l) !== LOC_SIG) throw bad('corrupt local header');
  const localName = zip.subarray(l + 30, l + 30 + zip.readUInt16LE(l + 26)).toString('utf8');
  if (localName !== name) throw bad('local header does not match the central directory');
  const start = l + 30 + zip.readUInt16LE(l + 26) + zip.readUInt16LE(l + 28);
  if (start + e.compressedSize > zip.length) throw bad('entry data out of bounds');
  const raw = zip.subarray(start, start + e.compressedSize);
  let data: Buffer;
  if (e.method === 0) {
    if (e.compressedSize !== e.size) throw bad('stored entry with mismatching sizes');
    data = Buffer.from(raw);
  } else if (e.method === 8) {
    try {
      data = inflateRawSync(raw, { maxOutputLength: maxBytes });
    } catch {
      throw bad(`entry "${name}" could not be decompressed (corrupt or over the ${maxBytes} byte limit)`);
    }
  } else {
    throw bad(`compression method ${e.method} is not supported`);
  }
  if (data.length !== e.size) throw bad('entry size does not match the central directory');
  if (crc32(data) !== e.crc) throw bad('CRC-32 mismatch');
  return data;
}
