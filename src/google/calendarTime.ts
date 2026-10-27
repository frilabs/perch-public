import { PerchError } from '../errors.js';

/**
 * Date/time validation for the Calendar API (https://developers.google.com/workspace/calendar/api/v3/reference/events):
 * - all-day: `date` "yyyy-mm-dd", end date exclusive;
 * - timed: `dateTime` RFC 3339; "A time zone offset is required unless a time zone is explicitly
 *   specified in timeZone"; `timeZone` is an IANA name such as "Europe/Zurich".
 * events.list `timeMin`/`timeMax` need an RFC 3339 timestamp with a mandatory offset.
 */

const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})?$/;
const IANA = /^(?:UTC|[A-Za-z][A-Za-z_+-]{0,30}(?:\/[A-Za-z0-9][A-Za-z0-9_+-]{0,30}){1,2})$/;

/**
 * UTC epoch ms of a proleptic Gregorian date/time with a full year. Date.UTC alone maps years 0-99 to
 * 1900-1999 (ECMAScript MakeFullYear), so the year is set separately with setUTCFullYear.
 */
export function utcMs(y: number, mo: number, d: number, h = 0, mi = 0, s = 0, ms = 0): number {
  const t = new Date(Date.UTC(2000, mo - 1, d, h, mi, s, ms));
  t.setUTCFullYear(y, mo - 1, d);
  return t.getTime();
}

function validYmd(y: number, m: number, d: number): boolean {
  if (y < 1 || m < 1 || m > 12 || d < 1) return false;
  return d <= new Date(utcMs(y, m + 1, 0)).getUTCDate();
}

export function isValidDate(s: string): boolean {
  const m = DATE.exec(s);
  return !!m && validYmd(Number(m[1]), Number(m[2]), Number(m[3]));
}

interface ParsedDateTime {
  y: number;
  mo: number;
  d: number;
  h: number;
  mi: number;
  s: number;
  ms: number;
  offset?: string;
}

export function parseDateTime(s: string): ParsedDateTime | undefined {
  const m = DATE_TIME.exec(s);
  if (!m) return undefined;
  const [y, mo, d, h, mi, sec] = [1, 2, 3, 4, 5, 6].map((i) => Number(m[i]));
  if (!validYmd(y!, mo!, d!) || h! > 23 || mi! > 59 || sec! > 59) return undefined;
  if (m[8] && m[8] !== 'Z') {
    const [oh, om] = m[8].slice(1).split(':').map(Number);
    if (oh! > 23 || om! > 59) return undefined;
  }
  return { y: y!, mo: mo!, d: d!, h: h!, mi: mi!, s: sec!, ms: m[7] ? Math.floor(Number(`0${m[7]}`) * 1000) : 0, ...(m[8] ? { offset: m[8] } : {}) };
}

/** RFC 3339 timestamp with offset (Z or ±hh:mm), as events.list timeMin/timeMax require. */
export function assertTimestamp(name: string, s: string): number {
  const p = parseDateTime(s);
  if (!p || !p.offset) throw new PerchError(`${name} must be an RFC 3339 timestamp with offset, e.g. 2026-10-05T09:00:00+02:00 or ...Z`, 'bad_argument');
  return instantOf(p, undefined);
}

export function isValidTimeZone(tz: string): boolean {
  if (!IANA.test(tz)) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

export function assertTimeZone(name: string, tz: string): string {
  if (!isValidTimeZone(tz)) throw new PerchError(`${name} must be an IANA time zone name such as Europe/Vienna`, 'bad_argument');
  return tz;
}

/** Offset of `tz` at instant `epochMs`, in ms (local = UTC + offset). */
function tzOffsetMs(epochMs: number, tz: string): number {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    era: 'short',
  }).formatToParts(new Date(epochMs));
  const get = (t: string) => Number(parts.find((p) => p.type === t)!.value);
  // Era-aware year (1 BC = year 0), so wall times right after 0001-01-01 still compare correctly.
  const bc = parts.find((p) => p.type === 'era')?.value === 'BC';
  const year = bc ? 1 - get('year') : get('year');
  return utcMs(year, get('month'), get('day'), get('hour'), get('minute'), get('second')) - Math.floor(epochMs / 1000) * 1000;
}

/** Instant of a dateTime: its own offset if present, else local wall time in `tz`. */
export function instantOf(p: ParsedDateTime, tz: string | undefined): number {
  const local = utcMs(p.y, p.mo, p.d, p.h, p.mi, p.s, p.ms);
  if (p.offset === 'Z') return local;
  if (p.offset) {
    const sign = p.offset[0] === '-' ? -1 : 1;
    const [oh, om] = p.offset.slice(1).split(':').map(Number);
    return local - sign * (oh! * 60 + om!) * 60_000;
  }
  if (!tz) throw new PerchError('A dateTime without offset needs a timeZone', 'bad_argument');
  // Two passes settle DST transitions to a well-defined instant.
  let guess = local - tzOffsetMs(local, tz);
  guess = local - tzOffsetMs(guess, tz);
  return guess;
}
