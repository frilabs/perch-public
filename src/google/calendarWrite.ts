import { createHash } from 'node:crypto';
import { z } from 'zod';
import { PerchError } from '../errors.js';
import { checkCalendarId, checkEventId, type EventTime, type GoogleEvent } from './calendar.js';
import { instantOf, isValidDate, isValidTimeZone, parseDateTime, utcMs } from './calendarTime.js';

/**
 * The calendar write subset (docs/MAIL_CALENDAR_SLACK_SPEC.md §2). Events on the user's own calendars:
 * - fields: summary, description, location, start, end, transparency, visibility (default, public,
 *   private, confidential), reminders (up to 5 popup overrides, never the calendar defaults), attendees
 *   (up to 50 email addresses, optional flag), guest permissions (guestsCanModify, guestsCanInviteOthers,
 *   guestsCanSeeOtherGuests), recurrence (up to 5 strictly validated RRULE/EXDATE/RDATE lines, whole series
 *   only), addMeet (a Google Meet link via conferenceData.createRequest and conferenceDataVersion=1, the
 *   conference request id derived from requestId), sendUpdates (all, externalOnly, none);
 * - defaults: without guests an event stays private and silent: create sends visibility "private" unless
 *   given, an update of a guest-less event whose visibility is default/unset adds visibility "private" to
 *   the same PATCH, and the write uses sendUpdates=none. With guests the default visibility is "default"
 *   (as in Google Calendar) and sendUpdates defaults to "all". Reminders are always popup-only
 *   ({useDefault:false}), because calendar default reminders may be email;
 * - capabilities: calendar_write for every write; additionally calendar_invite as soon as a write adds or
 *   changes guests, or notifies guests (sendUpdates other than none on an event with guests). Decided by the
 *   service (src/google/calendar.ts), which knows the existing event;
 * - never: organizer, attachments, source URLs, extended properties, caller-chosen ids, event types,
 *   status, anyoneCanAddSelf, conference data other than a new Meet request, and single occurrences of a
 *   series (instance ids `<id>_<timestamp>` and events with recurringEventId are refused).
 * Field semantics: https://developers.google.com/workspace/calendar/api/v3/reference/events/insert
 */

export const MAX_SUMMARY_LENGTH = 1024;
export const MAX_DESCRIPTION_LENGTH = 8192;
export const MAX_LOCATION_LENGTH = 1024;
export const MAX_EVENT_BODY_BYTES = 32 * 1024;
export const MAX_EVENT_DAYS = 366;
export const MAX_ATTENDEES = 50;
export const MAX_RECURRENCE_LINES = 5;
const MAX_RECURRENCE_LINE = 1000;
/** Google: "The maximum number of override reminders is 5"; minutes "between 0 and 40320". */
const MAX_REMINDERS = 5;
const MAX_REMINDER_MINUTES = 40320;
const DAY_MS = 86_400_000;

export const VISIBILITIES = ['default', 'public', 'private', 'confidential'] as const;
export const SEND_UPDATES = ['all', 'externalOnly', 'none'] as const;
export const RESPONSES = ['accepted', 'declined', 'tentative'] as const;
export type SendUpdates = (typeof SEND_UPDATES)[number];

/** Fields that would reach beyond what Perch offers (organizer changes, attachments, special events, ...). */
const FORBIDDEN: Record<string, string> = {
  organizer: 'the organizer is always the calendar owner',
  creator: 'set by Google',
  conferenceData: 'use addMeet: true for a Google Meet link; other conference data is not supported',
  hangoutLink: 'use addMeet: true for a Google Meet link',
  attachments: 'no attachment URLs',
  recurringEventId: 'single occurrences of a series are not supported; change the whole series',
  originalStartTime: 'single occurrences of a series are not supported; change the whole series',
  anyoneCanAddSelf: 'guests are invited explicitly with attendees',
  sendNotifications: 'use sendUpdates',
  source: 'no source URLs',
  extendedProperties: 'not part of this subset',
  gadget: 'not part of this subset',
  id: 'the event id is derived from requestId',
  iCalUID: 'the event id is derived from requestId',
  eventType: 'only default events',
  status: 'use calendar_delete_event to delete an event',
  sequence: 'managed by Google',
  acl: 'calendar sharing is never changed',
  attendeesOmitted: 'attendees is always the full guest list',
  workingLocationProperties: 'only default events',
  outOfOfficeProperties: 'only default events',
  focusTimeProperties: 'only default events',
  birthdayProperties: 'only default events',
};

const REQUEST_ID = /^[A-Za-z0-9._:-]{8,128}$/;
/** HTTP entity tag as returned by Calendar ("…" or W/"…"), printable ASCII only. */
const ETAG = /^(?:W\/)?"[\x21\x23-\x7e]{1,200}"$/;
/** Pragmatic addr-spec: no whitespace, quotes, brackets, separators or control characters; a dotted domain. */
const EMAIL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

const text = (name: string, max: number, min = 0) =>
  z
    .string({ error: `${name} must be a string` })
    .min(min, `${name} must not be empty`)
    .max(max, `${name} must be at most ${max} characters`)
    .refine((s) => !CONTROL.test(s), `${name} must not contain control characters`);

const TimeSchema = z.strictObject({ date: z.string().optional(), dateTime: z.string().optional(), timeZone: z.string().optional() });

const RemindersSchema = z.strictObject({
  useDefault: z.literal(false, { error: 'reminders.useDefault must be false: calendar default reminders may send email; give popup overrides instead' }),
  overrides: z
    .array(
      z.strictObject({
        method: z.literal('popup', { error: 'Only popup reminders are supported (email reminders send mail)' }),
        minutes: z.number().int().min(0).max(MAX_REMINDER_MINUTES, `Reminder minutes must be between 0 and ${MAX_REMINDER_MINUTES}`),
      }),
    )
    .max(MAX_REMINDERS, `At most ${MAX_REMINDERS} reminder overrides`)
    .optional(),
});

const EmailSchema = z
  .string({ error: 'attendee email must be a string' })
  .max(254, 'attendee email must be at most 254 characters')
  .regex(EMAIL, 'attendee email must be a plain address such as name@example.com');
const AttendeeSchema = z.union([EmailSchema, z.strictObject({ email: EmailSchema, optional: z.boolean().optional() })], {
  error: 'each attendee is an email address or {email, optional}',
});
const AttendeesSchema = z.array(AttendeeSchema).max(MAX_ATTENDEES, `At most ${MAX_ATTENDEES} attendees`);

const RecurrenceSchema = z
  .array(z.string({ error: 'recurrence lines must be strings' }).max(MAX_RECURRENCE_LINE, `recurrence lines must be at most ${MAX_RECURRENCE_LINE} characters`))
  .min(1, 'recurrence needs at least one RRULE line')
  .max(MAX_RECURRENCE_LINES, `At most ${MAX_RECURRENCE_LINES} recurrence lines`);

const sendUpdatesField = z.enum(SEND_UPDATES, { error: `sendUpdates must be one of ${SEND_UPDATES.join(', ')}` }).optional();

const fields = {
  summary: text('summary', MAX_SUMMARY_LENGTH, 1),
  description: text('description', MAX_DESCRIPTION_LENGTH).optional(),
  location: text('location', MAX_LOCATION_LENGTH).optional(),
  transparency: z.enum(['opaque', 'transparent']).optional(),
  visibility: z.enum(VISIBILITIES, { error: `visibility must be one of ${VISIBILITIES.join(', ')}` }).optional(),
  reminders: RemindersSchema.optional(),
  attendees: AttendeesSchema.optional(),
  guestsCanModify: z.boolean().optional(),
  guestsCanInviteOthers: z.boolean().optional(),
  guestsCanSeeOtherGuests: z.boolean().optional(),
  sendUpdates: sendUpdatesField,
  recurrence: RecurrenceSchema.optional(),
  addMeet: z.boolean().optional(),
};

const CreateSchema = z.strictObject({
  accountId: z.string().max(64),
  calendarId: z.string().max(255).optional(),
  requestId: z.string({ error: 'requestId is required (a stable id you reuse when retrying)' }).regex(REQUEST_ID, 'requestId must be 8-128 characters of A-Z a-z 0-9 . _ : -'),
  ...fields,
  start: TimeSchema,
  end: TimeSchema,
});

const etagField = z
  .string({ error: 'etag is required (from calendar_get_event or calendar_list_events)' })
  .regex(ETAG, 'etag must be the event etag returned by Perch, e.g. "3181161784712000"');

const UpdateSchema = z.strictObject({
  accountId: z.string().max(64),
  calendarId: z.string().max(255),
  eventId: z.string().max(1100),
  etag: etagField,
  ...fields,
  summary: fields.summary.optional(),
  start: TimeSchema.optional(),
  end: TimeSchema.optional(),
});

const DeleteSchema = z.strictObject({
  accountId: z.string().max(64),
  calendarId: z.string().max(255),
  eventId: z.string().max(1100),
  etag: etagField.optional(),
  sendUpdates: sendUpdatesField,
});

const RespondSchema = z.strictObject({
  accountId: z.string().max(64),
  calendarId: z.string().max(255),
  eventId: z.string().max(1100),
  response: z.enum(RESPONSES, { error: `response must be one of ${RESPONSES.join(', ')}` }),
  etag: etagField.optional(),
  sendUpdates: sendUpdatesField,
});

type Reminders = { useDefault: false; overrides: Array<{ method: 'popup'; minutes: number }> };
export interface Attendee {
  email: string;
  optional?: true;
}
export type CreateInput = Omit<z.infer<typeof CreateSchema>, 'visibility' | 'sendUpdates' | 'reminders' | 'attendees'> & {
  calendarId: string;
  visibility: (typeof VISIBILITIES)[number];
  reminders: Reminders;
  attendees: Attendee[];
  /** Resolved: "none" without guests, otherwise the caller's value or "all". */
  sendUpdates: SendUpdates;
};
export type UpdateInput = Omit<z.infer<typeof UpdateSchema>, 'reminders' | 'attendees'> & { reminders?: Reminders; attendees?: Attendee[] };
export type DeleteInput = z.infer<typeof DeleteSchema>;
export type RespondInput = z.infer<typeof RespondSchema>;

/** Overrides are always explicit: a PATCH merges nested objects, so an omitted array would keep old (email) overrides. */
const reminders = (r: { useDefault: false; overrides?: Reminders['overrides'] } | undefined): Reminders | undefined =>
  r && { useDefault: false, overrides: r.overrides ?? [] };

/** Normalised guest list: {email[, optional]}, duplicates (case-insensitive) refused. */
function attendees(list: z.infer<typeof AttendeesSchema> | undefined): Attendee[] | undefined {
  if (!list) return undefined;
  const seen = new Set<string>();
  return list.map((a) => {
    const email = typeof a === 'string' ? a : a.email;
    const key = email.toLowerCase();
    if (seen.has(key)) throw new PerchError(`attendees: ${email} is listed twice`, 'bad_argument');
    seen.add(key);
    return { email, ...(typeof a !== 'string' && a.optional === true ? { optional: true as const } : {}) };
  });
}

const RRULE_KEYS = new Set(['FREQ', 'UNTIL', 'COUNT', 'INTERVAL', 'BYSECOND', 'BYMINUTE', 'BYHOUR', 'BYDAY', 'BYMONTHDAY', 'BYYEARDAY', 'BYWEEKNO', 'BYMONTH', 'BYSETPOS', 'WKST']);
const FREQS = new Set(['DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY']);
const DATE_VALUE = /^[0-9]{8}(?:T[0-9]{6}Z?)?$/;

const recurrenceError = (why: string, line: string) => new PerchError(`recurrence: ${why} (${JSON.stringify(line.slice(0, 80))})`, 'bad_argument');

function rruleLine(value: string, line: string): void {
  const seen = new Map<string, string>();
  for (const part of value.split(';')) {
    const m = /^([A-Z]{2,10})=([A-Z0-9,+-]{1,200})$/.exec(part);
    if (!m) throw recurrenceError('RRULE parts are KEY=VALUE separated by ";"', line);
    if (!RRULE_KEYS.has(m[1]!)) throw recurrenceError(`unknown RRULE part ${m[1]}`, line);
    if (seen.has(m[1]!)) throw recurrenceError(`RRULE part ${m[1]} is given twice`, line);
    seen.set(m[1]!, m[2]!);
  }
  const freq = seen.get('FREQ');
  if (!freq) throw recurrenceError('RRULE needs FREQ', line);
  if (!FREQS.has(freq)) throw recurrenceError('FREQ must be DAILY, WEEKLY, MONTHLY or YEARLY', line);
  if (seen.has('COUNT') && seen.has('UNTIL')) throw recurrenceError('RRULE may have COUNT or UNTIL, not both', line);
  const count = seen.get('COUNT');
  if (count !== undefined && !/^[1-9][0-9]{0,3}$/.test(count)) throw recurrenceError('COUNT must be 1-9999', line);
  const interval = seen.get('INTERVAL');
  if (interval !== undefined && !/^[1-9][0-9]{0,2}$/.test(interval)) throw recurrenceError('INTERVAL must be 1-999', line);
  const until = seen.get('UNTIL');
  if (until !== undefined && !DATE_VALUE.test(until)) throw recurrenceError('UNTIL must be yyyymmdd or yyyymmddThhmmssZ', line);
}

function dateListLine(name: string, params: string, value: string, line: string): void {
  for (const p of params ? params.split(';') : []) {
    const m = /^(VALUE|TZID)=(.{1,64})$/.exec(p);
    if (!m) throw recurrenceError(`${name} parameters may only be VALUE or TZID`, line);
    if (m[1] === 'VALUE' && m[2] !== 'DATE' && m[2] !== 'DATE-TIME') throw recurrenceError(`${name};VALUE must be DATE or DATE-TIME`, line);
    if (m[1] === 'TZID' && !isValidTimeZone(m[2]!)) throw recurrenceError(`${name};TZID must be an IANA time zone`, line);
  }
  const dates = value.split(',');
  if (dates.length > 100 || !dates.every((d) => DATE_VALUE.test(d))) throw recurrenceError(`${name} values must be yyyymmdd or yyyymmddThhmmss[Z], comma separated`, line);
}

/**
 * RFC 5545 recurrence lines as Google accepts them in events.recurrence: exactly one RRULE (with FREQ),
 * optional EXDATE/RDATE lines; no control characters, no whitespace or line folding, no other properties.
 */
export function validateRecurrence(lines: string[]): string[] {
  let rrules = 0;
  for (const line of lines) {
    if (CONTROL.test(line) || /\s/.test(line)) throw new PerchError('recurrence lines must not contain whitespace or control characters', 'bad_argument');
    const m = /^(RRULE|EXDATE|RDATE)((?:;[A-Z-]+=[^;:]+)*):(.+)$/.exec(line);
    if (!m) throw new PerchError('recurrence lines must start with RRULE:, EXDATE: or RDATE:', 'bad_argument');
    if (m[1] === 'RRULE') {
      if (m[2]) throw recurrenceError('RRULE takes no parameters', line);
      rruleLine(m[3]!, line);
      rrules++;
    } else dateListLine(m[1]!, m[2]!.slice(1), m[3]!, line);
  }
  if (rrules !== 1) throw new PerchError('recurrence needs exactly one RRULE line (with FREQ)', 'bad_argument');
  return lines;
}

function rejectForbidden(raw: Record<string, unknown>): void {
  for (const [k, v] of Object.entries(raw)) {
    if (v !== undefined && k in FORBIDDEN) throw new PerchError(`${k} is not supported: ${FORBIDDEN[k]}`, 'bad_argument');
  }
}

function parse<S extends z.ZodType>(schema: S, raw: unknown): z.infer<S> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new PerchError('Expected an object', 'bad_argument');
  // Undefined optional keys (e.g. from the MCP layer) are not "present".
  const clean = Object.fromEntries(Object.entries(raw as Record<string, unknown>).filter(([, v]) => v !== undefined));
  rejectForbidden(clean);
  const r = schema.safeParse(clean);
  if (r.success) return r.data;
  const issue = r.error.issues[0]!;
  if (issue.code === 'unrecognized_keys') throw new PerchError(`Unsupported field: ${issue.keys.join(', ')}`, 'bad_argument');
  const where = issue.path.length ? `${issue.path.join('.')}: ` : '';
  throw new PerchError(`${where}${issue.message}`, 'bad_argument');
}

type Point = { allDay: true; day: number } | { allDay: false; at: number };

function point(name: string, t: EventTime): Point {
  if (t.date !== undefined) {
    if (t.dateTime !== undefined || t.timeZone !== undefined) throw new PerchError(`${name}: an all-day time has only date (no dateTime/timeZone)`, 'bad_argument');
    if (!isValidDate(t.date)) throw new PerchError(`${name}.date must be a valid yyyy-mm-dd date`, 'bad_argument');
    const [y, mo, d] = t.date.split('-').map(Number);
    return { allDay: true, day: utcMs(y!, mo!, d!) };
  }
  if (t.dateTime === undefined) throw new PerchError(`${name} needs date (all-day) or dateTime`, 'bad_argument');
  const p = parseDateTime(t.dateTime);
  if (!p) throw new PerchError(`${name}.dateTime must be RFC 3339, e.g. 2026-10-06T09:00:00+02:00`, 'bad_argument');
  if (t.timeZone !== undefined && !isValidTimeZone(t.timeZone)) throw new PerchError(`${name}.timeZone must be an IANA time zone name such as Europe/Vienna`, 'bad_argument');
  if (!p.offset && t.timeZone === undefined) throw new PerchError(`${name}.dateTime needs an offset (Z or ±hh:mm) or a timeZone`, 'bad_argument');
  return { allDay: false, at: instantOf(p, t.timeZone) };
}

/** Both all-day or both timed; end strictly after start; at most MAX_EVENT_DAYS long. */
export function validateTimes(start: EventTime, end: EventTime): void {
  const s = point('start', start);
  const e = point('end', end);
  if (s.allDay !== e.allDay) throw new PerchError('start and end must be both all-day (date) or both timed (dateTime)', 'bad_argument');
  const a = s.allDay ? s.day : s.at;
  const b = e.allDay ? (e as { day: number }).day : (e as { at: number }).at;
  if (b <= a) throw new PerchError(s.allDay ? 'end must be after start (all-day end dates are exclusive: the day after the last day)' : 'end must be after start', 'bad_argument');
  if (b - a > MAX_EVENT_DAYS * DAY_MS) throw new PerchError(`Events may be at most ${MAX_EVENT_DAYS} days long`, 'bad_argument');
}

/** Google: for recurring events start/end.timeZone "is required and specifies the time zone in which the recurrence is expanded". */
function assertRecurringTimes(start: EventTime | undefined, end: EventTime | undefined): void {
  for (const [name, t] of [['start', start], ['end', end]] as const) {
    if (t?.dateTime !== undefined && t.timeZone === undefined) throw new PerchError(`${name}.timeZone is required for a recurring timed event`, 'bad_argument');
  }
}

/** Instance ids (`<series id>_<yyyymmdd[Thhmmssz]>`) address one occurrence of a series. */
export function isInstanceId(eventId: string): boolean {
  return eventId.includes('_');
}

export const SINGLE_OCCURRENCE_REFUSED =
  'Single occurrences of a recurring series are not supported; nothing was changed. To change or delete the whole series, use its series id (recurringEventId of the occurrence).';

function checkSeriesOrEventId(eventId: string): string {
  checkEventId(eventId);
  if (isInstanceId(eventId)) throw new PerchError(SINGLE_OCCURRENCE_REFUSED, 'unsupported_event');
  return eventId;
}

export function parseCreateInput(raw: unknown): CreateInput {
  const v = parse(CreateSchema, raw);
  const calendarId = checkCalendarId(v.calendarId ?? 'primary');
  validateTimes(v.start, v.end);
  if (v.recurrence) {
    validateRecurrence(v.recurrence);
    assertRecurringTimes(v.start, v.end);
  }
  const guests = attendees(v.attendees) ?? [];
  const hasGuests = guests.length > 0;
  return {
    ...v,
    calendarId,
    attendees: guests,
    // Without guests: private and silent (visibility "default" inherits the calendar sharing, which may be public).
    visibility: v.visibility ?? (hasGuests ? 'default' : 'private'),
    sendUpdates: hasGuests ? (v.sendUpdates ?? 'all') : 'none',
    reminders: reminders(v.reminders) ?? { useDefault: false, overrides: [] },
  };
}

const UPDATE_FIELDS = [
  'summary',
  'description',
  'location',
  'transparency',
  'visibility',
  'reminders',
  'start',
  'end',
  'attendees',
  'guestsCanModify',
  'guestsCanInviteOthers',
  'guestsCanSeeOtherGuests',
  'recurrence',
  'addMeet',
] as const;

export function parseUpdateInput(raw: unknown): UpdateInput {
  const v = parse(UpdateSchema, raw);
  checkCalendarId(v.calendarId);
  checkSeriesOrEventId(v.eventId);
  if (!UPDATE_FIELDS.some((k) => v[k] !== undefined && !(k === 'addMeet' && v[k] === false))) {
    throw new PerchError(`Give at least one field to change (${UPDATE_FIELDS.join(', ')})`, 'bad_argument');
  }
  if (v.recurrence) validateRecurrence(v.recurrence);
  const { reminders: r, attendees: a, ...rest } = v;
  const guests = attendees(a);
  return { ...rest, ...(r ? { reminders: reminders(r) } : {}), ...(guests ? { attendees: guests } : {}) };
}

export function parseDeleteInput(raw: unknown): DeleteInput {
  const v = parse(DeleteSchema, raw);
  checkCalendarId(v.calendarId);
  checkSeriesOrEventId(v.eventId);
  return v;
}

export function parseRespondInput(raw: unknown): RespondInput {
  const v = parse(RespondSchema, raw);
  checkCalendarId(v.calendarId);
  checkSeriesOrEventId(v.eventId);
  return v;
}

/** base32hex (RFC 4648 §7) in lowercase: exactly the documented Calendar event id alphabet a-v, 0-9. */
function base32hex(buf: Buffer): string {
  const alphabet = '0123456789abcdefghijklmnopqrstuv';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

/**
 * Deterministic event id for create: the same (account, calendarId as given, requestId) always maps to
 * the same id, so a retry after an unknown outcome cannot create a second event (Google answers 409).
 */
export function eventIdForRequest(accountId: string, calendarId: string, requestId: string): string {
  const digest = createHash('sha256').update(`perch-calendar-create\u0000${accountId}\u0000${calendarId}\u0000${requestId}`).digest();
  return `perch${base32hex(digest)}`;
}

/**
 * conferenceData.createRequest.requestId: derived like the event id, so a retried create asks for the same
 * conference. For an update it is derived from the event and the etag the change is based on.
 */
export function meetRequestId(...parts: string[]): string {
  return `perch-meet-${createHash('sha256').update(['perch-calendar-meet', ...parts].join('\u0000')).digest('hex').slice(0, 40)}`;
}

const meetRequest = (requestId: string) => ({ createRequest: { requestId, conferenceSolutionKey: { type: 'hangoutsMeet' } } });

function sizeChecked<T>(body: T): T {
  if (Buffer.byteLength(JSON.stringify(body)) > MAX_EVENT_BODY_BYTES) throw new PerchError(`Event exceeds ${MAX_EVENT_BODY_BYTES} bytes`, 'bad_argument');
  return body;
}

const PLAIN_FIELDS = [
  'summary',
  'description',
  'location',
  'start',
  'end',
  'transparency',
  'visibility',
  'reminders',
  'guestsCanModify',
  'guestsCanInviteOthers',
  'guestsCanSeeOtherGuests',
  'recurrence',
] as const;

function pick(v: Partial<CreateInput & UpdateInput>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of PLAIN_FIELDS) if (v[k] !== undefined) out[k] = v[k];
  return out;
}

export function buildCreateBody(v: CreateInput): Record<string, unknown> & { id: string } {
  const id = eventIdForRequest(v.accountId, v.calendarId, v.requestId);
  return sizeChecked({
    id,
    ...pick(v),
    ...(v.attendees.length ? { attendees: v.attendees } : {}),
    ...(v.addMeet ? { conferenceData: meetRequest(meetRequestId(v.accountId, v.calendarId, v.requestId)) } : {}),
  });
}

const isPrivate = (visibility: unknown) => visibility === 'private' || visibility === 'confidential';

/** Guests: every attendee that is not the calendar owner (rooms count as guests: they answer invitations too). */
export function guestsOf(e: Pick<GoogleEvent, 'attendees'>): NonNullable<GoogleEvent['attendees']> {
  return Array.isArray(e.attendees) ? e.attendees.filter((a) => a && a.self !== true) : [];
}

/** The existing event's valid popup overrides; anything else (email, malformed) is dropped. */
function popupOverrides(r: GoogleEvent['reminders']): Reminders['overrides'] {
  const list = Array.isArray(r?.overrides) ? r.overrides : [];
  return list
    .filter((o) => o?.method === 'popup' && Number.isInteger(o.minutes) && o.minutes! >= 0 && o.minutes! <= MAX_REMINDER_MINUTES)
    .slice(0, MAX_REMINDERS)
    .map((o) => ({ method: 'popup', minutes: o.minutes! }));
}

/** Only an explicit useDefault:false with popup overrides only is silent; missing or default reminders may be email. */
function remindersAreSafe(r: GoogleEvent['reminders']): boolean {
  if (!r || typeof r !== 'object' || r.useDefault !== false) return false;
  const list = r.overrides ?? [];
  return Array.isArray(list) && list.length === popupOverrides(r).length;
}

/** What an existing attendee entry keeps through a guest-list PATCH: their answer, note, extra guests and name. */
function kept(a: NonNullable<GoogleEvent['attendees']>[number] | undefined): Record<string, unknown> {
  if (!a) return {};
  return {
    ...(typeof a.responseStatus === 'string' ? { responseStatus: a.responseStatus } : {}),
    ...(typeof a.comment === 'string' ? { comment: a.comment } : {}),
    ...(Number.isInteger(a.additionalGuests) ? { additionalGuests: a.additionalGuests } : {}),
    ...(typeof a.displayName === 'string' ? { displayName: a.displayName } : {}),
  };
}

/**
 * The new guest list for a PATCH (arrays are replaced): the owner's own entries are kept as they are, and a
 * guest who stays keeps their response, comment, additionalGuests and displayName, so changing the list
 * never resets answers or notes.
 */
function mergedAttendees(given: Attendee[], existing: GoogleEvent): { list: Array<Record<string, unknown>>; guests: number } {
  const current = Array.isArray(existing.attendees) ? existing.attendees : [];
  const own = current.filter((a) => a?.self === true && typeof a.email === 'string');
  const ownEmails = new Set(own.map((a) => a.email!.toLowerCase()));
  const byEmail = new Map(current.filter((a) => typeof a?.email === 'string').map((a) => [a.email!.toLowerCase(), a]));
  const list: Array<Record<string, unknown>> = own.map((a) => ({ email: a.email, ...kept(a) }));
  let guests = 0;
  for (const g of given) {
    if (ownEmails.has(g.email.toLowerCase())) continue;
    list.push({ email: g.email, ...(g.optional ? { optional: true } : {}), ...kept(byEmail.get(g.email.toLowerCase())) });
    guests++;
  }
  return { list, guests };
}

export interface PatchPlan {
  body: Record<string, unknown>;
  /** The update touches the guest list of an event that has (or gets, or loses) guests. */
  changesGuests: boolean;
  /** Guests are involved before or after the change: calendar_invite is needed (sendUpdates would notify them). */
  guestsInvolved: boolean;
  /** conferenceDataVersion=1 is needed (a Meet link is requested). */
  addsMeet: boolean;
}

/**
 * PATCH plan: the changed fields, a single changed time validated against the existing event, plus
 * - without guests (after the change): visibility "private" unless the caller sets one or the event already
 *   has an explicit visibility (private, confidential or public); default/unset inherits the calendar's
 *   sharing, which may be public;
 * - reminders {useDefault:false, overrides:[existing popup overrides]} unless the caller sets them or
 *   the event already uses only popup overrides (default reminders and email overrides send mail).
 * Both go in the same PATCH as the change.
 */
export function planPatch(v: UpdateInput, existing: GoogleEvent): PatchPlan {
  const start = v.start ?? existing.start;
  const end = v.end ?? existing.end;
  if (v.start || v.end) {
    if (!start || !end) throw new PerchError('The existing event has no start/end; give both', 'bad_argument');
    validateTimes(start, end);
  }
  const recurring = v.recurrence !== undefined || (Array.isArray(existing.recurrence) && existing.recurrence.length > 0);
  if (recurring && (v.recurrence || v.start || v.end)) assertRecurringTimes(start, end);
  const body = pick(v);
  const before = guestsOf(existing).length > 0;
  let after = before;
  if (v.attendees) {
    const merged = mergedAttendees(v.attendees, existing);
    after = merged.guests > 0;
    // Only your own entry on an event without guests: nothing to change (and no guest-list write).
    if (before || after) body.attendees = merged.list;
  }
  const addsMeet = v.addMeet === true;
  if (addsMeet) {
    if (existing.hangoutLink || existing.conferenceData) throw new PerchError('This event already has a conference; nothing was changed', 'bad_argument');
    body.conferenceData = meetRequest(meetRequestId(v.accountId, v.calendarId, v.eventId, v.etag));
  }
  if (!after && body.visibility === undefined && !isPrivate(existing.visibility) && existing.visibility !== 'public') body.visibility = 'private';
  if (body.reminders === undefined && !remindersAreSafe(existing.reminders)) body.reminders = { useDefault: false, overrides: popupOverrides(existing.reminders) };
  return { body: sizeChecked(body), changesGuests: v.attendees !== undefined && (before || after), guestsInvolved: before || after, addsMeet };
}

/** Only the PATCH body of planPatch. */
export function buildPatchBody(v: UpdateInput, existing: GoogleEvent): Record<string, unknown> {
  return planPatch(v, existing).body;
}

/**
 * Updates and deletes are limited to events the calendar owner organises: not organised by someone else,
 * not a single occurrence of a series, default event type, not cancelled. Guests and whole series are
 * allowed; whether guests need calendar_invite is decided by the caller.
 */
export function assertOwnEvent(e: GoogleEvent): void {
  const no = (why: string) => new PerchError(`This event cannot be changed by Perch: ${why}. Nothing was changed.`, 'unsupported_event');
  if (e.status === 'cancelled') throw no('it is cancelled');
  if (!e.organizer) throw no('the event has no organizer, so Perch cannot confirm you organize it');
  if (e.organizer.self !== true) throw no('it is organized by someone else (or the organizer is not confirmed as you); answer invitations with calendar_respond_event');
  if (e.recurringEventId !== undefined) throw new PerchError(SINGLE_OCCURRENCE_REFUSED, 'unsupported_event');
  if (e.eventType !== undefined && e.eventType !== 'default') throw no(`its type is ${e.eventType}`);
}
