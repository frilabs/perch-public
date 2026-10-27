// Calendar write subset: schema, forbidden fields, guests/recurrence/visibility/Meet validation, dates and
// time zones, size bounds, deterministic ids from requestId, and the "own event, no single occurrence" check.
// Pure functions; no upstream.
import { describe, expect, it } from 'vitest';
import {
  assertOwnEvent,
  buildCreateBody,
  buildPatchBody,
  eventIdForRequest,
  MAX_DESCRIPTION_LENGTH,
  meetRequestId,
  parseCreateInput,
  parseDeleteInput,
  parseRespondInput,
  parseUpdateInput,
  planPatch,
  validateRecurrence,
  validateTimes,
} from '../src/google/calendarWrite.js';
import { assertTimestamp, instantOf, parseDateTime } from '../src/google/calendarTime.js';

const base = {
  accountId: 'gprod-0000000a',
  requestId: 'req-2026-10-05-0001',
  summary: 'Dentist',
  start: { dateTime: '2026-10-06T09:00:00', timeZone: 'Europe/Vienna' },
  end: { dateTime: '2026-10-06T10:00:00', timeZone: 'Europe/Vienna' },
};

describe('parseCreateInput', () => {
  it('accepts the documented subset and defaults calendarId to primary', () => {
    const v = parseCreateInput({
      ...base,
      description: 'Bring card',
      location: 'Vienna',
      transparency: 'transparent',
      visibility: 'private',
      reminders: { useDefault: false, overrides: [{ method: 'popup', minutes: 30 }] },
    });
    expect(v.calendarId).toBe('primary');
    expect(v.summary).toBe('Dentist');
  });

  it('rejects organizer, conference data, attachments, special types and other forbidden fields with an explicit reason', () => {
    for (const field of ['organizer', 'conferenceData', 'hangoutLink', 'attachments', 'anyoneCanAddSelf', 'source', 'extendedProperties', 'id', 'iCalUID', 'acl', 'recurringEventId', 'status', 'eventType', 'attendeesOmitted']) {
      expect(() => parseCreateInput({ ...base, [field]: 'x' }), field).toThrow(
        new RegExp(`${field}.*not supported`, 'i'),
      );
    }
    expect(() => parseCreateInput({ ...base, colour: 'red' })).toThrow(/unsupported field.*colour/i);
  });

  it('rejects email reminders (they send mail) and more than five overrides', () => {
    expect(() => parseCreateInput({ ...base, reminders: { useDefault: false, overrides: [{ method: 'email', minutes: 10 }] } })).toThrow(/popup/i);
    expect(() =>
      parseCreateInput({ ...base, reminders: { useDefault: false, overrides: Array.from({ length: 6 }, () => ({ method: 'popup', minutes: 5 })) } }),
    ).toThrow(/5/);
    expect(() => parseCreateInput({ ...base, reminders: { useDefault: false, overrides: [{ method: 'popup', minutes: 40321 }] } })).toThrow(/40320/);
  });

  it('accepts every documented visibility and nothing else', () => {
    for (const visibility of ['default', 'public', 'private', 'confidential']) expect(parseCreateInput({ ...base, visibility }).visibility).toBe(visibility);
    expect(() => parseCreateInput({ ...base, visibility: 'secret' })).toThrow(/visibility must be one of/i);
  });

  it('validates all-day and timed dates and time zones', () => {
    const bad: Array<[Record<string, unknown>, RegExp]> = [
      [{ start: { date: '2026-10-06' }, end: { dateTime: '2026-10-07T00:00:00Z' } }, /both all-day/i],
      [{ start: { date: '2026-10-06' }, end: { date: '2026-10-06' } }, /end.*after/i],
      [{ start: { date: '2026-02-29' }, end: { date: '2026-03-01' } }, /date/i],
      [{ start: { date: '2026-10-06', timeZone: 'Europe/Vienna' }, end: { date: '2026-10-07' } }, /timeZone/i],
      [{ start: { dateTime: '2026-10-06T09:00:00' }, end: { dateTime: '2026-10-06T10:00:00' } }, /offset.*timeZone/i],
      [{ start: { dateTime: '2026-10-06T09:00:00Z', timeZone: 'Mars/Base' }, end: { dateTime: '2026-10-06T10:00:00Z' } }, /time ?zone/i],
      [{ start: { dateTime: '2026-10-06T10:00:00+02:00' }, end: { dateTime: '2026-10-06T08:00:00Z' } }, /end.*after/i],
      [{ start: { dateTime: '2026-10-06T25:00:00Z' }, end: { dateTime: '2026-10-07T00:00:00Z' } }, /dateTime/i],
      [{ start: { date: '2026-01-01' }, end: { date: '2027-01-03' } }, /366/],
    ];
    for (const [times, re] of bad) expect(() => parseCreateInput({ ...base, ...times }), JSON.stringify(times)).toThrow(re);
    // Wall time in different zones: 09:30 Vienna (07:30Z) ends after 08:00 London (07:00Z)? No: it starts later.
    expect(() =>
      parseCreateInput({ ...base, start: { dateTime: '2026-10-06T09:30:00', timeZone: 'Europe/Vienna' }, end: { dateTime: '2026-10-06T08:00:00', timeZone: 'Europe/London' } }),
    ).toThrow(/end.*after/i);
    expect(() =>
      parseCreateInput({ ...base, start: { dateTime: '2026-10-06T09:30:00', timeZone: 'Europe/Vienna' }, end: { dateTime: '2026-10-06T09:00:00', timeZone: 'Europe/London' } }),
    ).not.toThrow();
    expect(() => parseCreateInput({ ...base, start: { date: '2026-10-06' }, end: { date: '2026-10-07' } })).not.toThrow();
  });

  it('bounds text lengths and requires a stable requestId', () => {
    expect(() => parseCreateInput({ ...base, summary: '' })).toThrow(/summary/i);
    expect(() => parseCreateInput({ ...base, summary: 'x'.repeat(1025) })).toThrow(/summary/i);
    expect(() => parseCreateInput({ ...base, description: 'x'.repeat(MAX_DESCRIPTION_LENGTH + 1) })).toThrow(/description/i);
    expect(() => parseCreateInput({ ...base, summary: 'a\u0000b' })).toThrow(/control/i);
    for (const requestId of [undefined, 'short', 'has space here', 'x'.repeat(129)]) {
      expect(() => parseCreateInput({ ...base, requestId }), String(requestId)).toThrow(/requestId/i);
    }
  });
});

describe('create: private and silent by construction (review blockers)', () => {
  it('sends visibility=private when none is given, so the event never inherits public calendar sharing', () => {
    expect(buildCreateBody(parseCreateInput(base)).visibility).toBe('private');
    expect(buildCreateBody(parseCreateInput({ ...base, visibility: 'private' })).visibility).toBe('private');
    // Google: "confidential: The event is private. This value is provided for compatibility reasons."
    expect(buildCreateBody(parseCreateInput({ ...base, visibility: 'confidential' })).visibility).toBe('confidential');
  });

  it('defaults to visibility "default" and sendUpdates all only when guests are invited', () => {
    const v = parseCreateInput({ ...base, attendees: ['guest@example.test'] });
    expect(v).toMatchObject({ visibility: 'default', sendUpdates: 'all' });
    expect(parseCreateInput({ ...base, attendees: ['guest@example.test'], sendUpdates: 'none', visibility: 'private' })).toMatchObject({ visibility: 'private', sendUpdates: 'none' });
    // Without guests nobody can be notified: always none.
    expect(parseCreateInput({ ...base, sendUpdates: 'all' }).sendUpdates).toBe('none');
    expect(parseCreateInput({ ...base, attendees: [] })).toMatchObject({ visibility: 'private', sendUpdates: 'none', attendees: [] });
  });

  it('never inherits calendar default reminders (they may be email): absent -> {useDefault:false, overrides:[]}', () => {
    expect(buildCreateBody(parseCreateInput(base)).reminders).toEqual({ useDefault: false, overrides: [] });
    expect(buildCreateBody(parseCreateInput({ ...base, reminders: { useDefault: false } })).reminders).toEqual({ useDefault: false, overrides: [] });
    const popup = { useDefault: false, overrides: [{ method: 'popup', minutes: 15 }] };
    expect(buildCreateBody(parseCreateInput({ ...base, reminders: popup })).reminders).toEqual(popup);
  });

  it('rejects reminders.useDefault=true (calendar defaults may send email), also together with overrides', () => {
    expect(() => parseCreateInput({ ...base, reminders: { useDefault: true } })).toThrow(/useDefault.*false/i);
    expect(() => parseCreateInput({ ...base, reminders: { useDefault: true, overrides: [{ method: 'popup', minutes: 5 }] } })).toThrow(/useDefault.*false/i);
  });
});

describe('timed values in years 0001-0099 (Date.UTC maps 0-99 to 1900-1999)', () => {
  it('computes the real instant for full years below 100', () => {
    for (const s of ['0099-12-31T00:00:00Z', '0001-01-01T00:00:00Z', '0050-06-15T12:30:00+02:00']) {
      expect(instantOf(parseDateTime(s)!, undefined), s).toBe(Date.parse(s));
    }
    expect(assertTimestamp('timeMin', '0099-12-31T00:00:00Z')).toBe(Date.parse('0099-12-31T00:00:00Z'));
  });

  it('keeps the ordering and the 366-day maximum for such years', () => {
    expect(() => validateTimes({ dateTime: '0099-12-31T00:00:00Z' }, { dateTime: '1999-12-31T12:00:00Z' })).toThrow(/366/);
    expect(() => validateTimes({ dateTime: '1999-01-01T00:00:00Z' }, { dateTime: '0099-01-02T00:00:00Z' })).toThrow(/end.*after/i);
    expect(() => validateTimes({ dateTime: '0099-01-01T09:00:00Z' }, { dateTime: '0099-01-01T10:00:00Z' })).not.toThrow();
    // Wall time in a zone: two hours after a Z start in the same year 0050 (Vienna LMT is about +01:05).
    expect(() => validateTimes({ dateTime: '0050-03-01T10:00:00Z' }, { dateTime: '0050-03-01T09:00:00', timeZone: 'Europe/Vienna' })).toThrow(/end.*after/i);
    expect(() => validateTimes({ dateTime: '0050-03-01T10:00:00Z' }, { dateTime: '0050-03-01T13:00:00', timeZone: 'Europe/Vienna' })).not.toThrow();
    expect(() => validateTimes({ date: '0099-12-31' }, { date: '0100-01-01' })).not.toThrow();
  });
});

describe('deterministic event ids', () => {
  it('maps (account, calendar, requestId) to a legal, stable base32hex id', () => {
    const id = eventIdForRequest('gprod-0000000a', 'primary', 'req-2026-10-05-0001');
    expect(id).toMatch(/^[a-v0-9]{5,1024}$/);
    expect(id).toBe(eventIdForRequest('gprod-0000000a', 'primary', 'req-2026-10-05-0001'));
    expect(id).not.toBe(eventIdForRequest('gprod-0000000a', 'primary', 'req-2026-10-05-0002'));
    expect(id).not.toBe(eventIdForRequest('gprod-0000000b', 'primary', 'req-2026-10-05-0001'));
  });

  it('builds a create body with only allowed fields plus the derived id', () => {
    const body = buildCreateBody(parseCreateInput({ ...base, description: 'd' }));
    expect(Object.keys(body).sort()).toEqual(['description', 'end', 'id', 'reminders', 'start', 'summary', 'visibility']);
    expect(body.id).toBe(eventIdForRequest('gprod-0000000a', 'primary', base.requestId));
  });
});

describe('updates', () => {
  const existing = {
    id: 'evt0timed002',
    etag: '"2"',
    status: 'confirmed',
    organizer: { email: 'dummy.a@example.test', self: true },
    start: { dateTime: '2026-10-06T09:00:00+02:00', timeZone: 'Europe/Vienna' },
    end: { dateTime: '2026-10-06T10:00:00+02:00', timeZone: 'Europe/Vienna' },
  };

  it('requires the etag and at least one change, and forbids the same fields as create', () => {
    const ok = { accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"', summary: 'New' };
    expect(parseUpdateInput(ok).etag).toBe('"2"');
    expect(() => parseUpdateInput({ ...ok, etag: undefined })).toThrow(/etag/i);
    expect(() => parseUpdateInput({ ...ok, etag: 'W/"x"\r\n' })).toThrow(/etag/i);
    expect(() => parseUpdateInput({ accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"' })).toThrow(/at least one/i);
    expect(() => parseUpdateInput({ ...ok, organizer: { email: 'x@example.test' } })).toThrow(/organizer.*not supported/i);
    expect(parseUpdateInput({ ...ok, summary: undefined, attendees: [] }).attendees).toEqual([]);
    expect(() => parseUpdateInput({ ...ok, summary: undefined, addMeet: false })).toThrow(/at least one/i);
    expect(() => parseUpdateInput({ ...ok, eventId: '../x' })).toThrow(/event id/i);
  });

  it('validates a partial time change against the existing event', () => {
    const later = parseUpdateInput({ accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"', start: { dateTime: '2026-10-06T11:00:00+02:00' } });
    expect(() => buildPatchBody(later, existing)).toThrow(/end.*after/i);
    const allDayStartOnly = parseUpdateInput({ accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"', start: { date: '2026-10-06' } });
    expect(() => buildPatchBody(allDayStartOnly, existing)).toThrow(/both all-day/i);
    const fine = parseUpdateInput({ accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"', summary: 'Moved', location: 'Graz' });
    expect(buildPatchBody(fine, { ...existing, visibility: 'private', reminders: { useDefault: false, overrides: [] } })).toEqual({ summary: 'Moved', location: 'Graz' });
  });

  it('only touches events you organise: guests and whole series are fine, occurrences, other organisers and special types are not', () => {
    expect(() => assertOwnEvent(existing)).not.toThrow();
    expect(() => assertOwnEvent({ ...existing, attendees: [{ email: 'guest@example.test' }] })).not.toThrow();
    expect(() => assertOwnEvent({ ...existing, recurrence: ['RRULE:FREQ=WEEKLY'] })).not.toThrow();
    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ organizer: { email: 'boss@example.test' } }, /organi[sz]ed by someone else/i],
      [{ recurringEventId: 'abcde12345' }, /single occurrences/i],
      [{ eventType: 'outOfOffice' }, /type/i],
      [{ status: 'cancelled' }, /cancelled/i],
    ];
    for (const [change, re] of cases) {
      expect(() => assertOwnEvent({ ...existing, ...change }), JSON.stringify(change)).toThrow(re);
    }
  });

  it('fails closed when the existing event has no organizer or no organizer.self', () => {
    const { organizer: _o, ...noOrganizer } = existing;
    expect(() => assertOwnEvent(noOrganizer)).toThrow(/organizer/i);
    expect(() => assertOwnEvent({ status: 'confirmed' })).toThrow(/organizer/i);
    expect(() => assertOwnEvent({ ...existing, organizer: { email: 'dummy.a@example.test' } })).toThrow(/organi[sz]e/i);
  });

  const safe = { visibility: 'private', reminders: { useDefault: false, overrides: [{ method: 'popup', minutes: 10 }] } };
  const summaryOnly = () => parseUpdateInput({ accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"', summary: 'S' });

  it('makes a guest-less result private in the same PATCH when the existing visibility is default or unset (public stays a deliberate choice)', () => {
    expect(buildPatchBody(summaryOnly(), { ...existing, ...safe, visibility: 'public' })).toEqual({ summary: 'S' });
    for (const visibility of ['default', undefined]) {
      expect(buildPatchBody(summaryOnly(), { ...existing, ...safe, visibility }), String(visibility)).toEqual({ summary: 'S', visibility: 'private' });
    }
    expect(buildPatchBody(summaryOnly(), { ...existing, ...safe })).toEqual({ summary: 'S' });
    expect(buildPatchBody(summaryOnly(), { ...existing, ...safe, visibility: 'confidential' })).toEqual({ summary: 'S' });
    const conf = parseUpdateInput({ accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"', visibility: 'confidential' });
    expect(buildPatchBody(conf, { ...existing, ...safe, visibility: 'public' })).toEqual({ visibility: 'confidential' });
  });

  it('accepts every update visibility but rejects reminders.useDefault=true', () => {
    const ok = { accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"' };
    expect(parseUpdateInput({ ...ok, visibility: 'public' }).visibility).toBe('public');
    expect(buildPatchBody(parseUpdateInput({ ...ok, visibility: 'default' }), { ...existing, ...safe })).toEqual({ visibility: 'default' });
    expect(() => parseUpdateInput({ ...ok, reminders: { useDefault: true } })).toThrow(/useDefault.*false/i);
  });

  it('disables inherited/default and email reminders in the same PATCH, keeping only popup overrides', () => {
    const vis = { visibility: 'private' };
    const cases: Array<[unknown, unknown]> = [
      [undefined, { useDefault: false, overrides: [] }],
      [{ useDefault: true }, { useDefault: false, overrides: [] }],
      [{}, { useDefault: false, overrides: [] }],
      [{ useDefault: false, overrides: [{ method: 'email', minutes: 30 }, { method: 'popup', minutes: 5 }] }, { useDefault: false, overrides: [{ method: 'popup', minutes: 5 }] }],
      [{ useDefault: false, overrides: [{ method: 'popup', minutes: 'x' }] }, { useDefault: false, overrides: [] }],
    ];
    for (const [reminders, expected] of cases) {
      expect(buildPatchBody(summaryOnly(), { ...existing, ...vis, reminders } as never), JSON.stringify(reminders)).toEqual({ summary: 'S', reminders: expected });
    }
    // Already safe: untouched.
    expect(buildPatchBody(summaryOnly(), { ...existing, ...safe })).toEqual({ summary: 'S' });
    expect(buildPatchBody(summaryOnly(), { ...existing, ...vis, reminders: { useDefault: false } })).toEqual({ summary: 'S' });
    // An explicit popup array replaces everything; overrides are always sent so a PATCH merge cannot keep old email overrides.
    const explicit = parseUpdateInput({ accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"', reminders: { useDefault: false } });
    expect(buildPatchBody(explicit, { ...existing, ...vis, reminders: { useDefault: false, overrides: [{ method: 'email', minutes: 1 }] } })).toEqual({
      reminders: { useDefault: false, overrides: [] },
    });
  });
});

describe('guests, recurrence, Meet and occurrences (MAIL_CALENDAR_SLACK_SPEC §2)', () => {
  const emails = (n: number) => Array.from({ length: n }, (_, i) => `guest${i}@example.test`);

  it('accepts up to 50 attendees as addresses or {email, optional} and refuses more, duplicates and non-addresses', () => {
    const v = parseCreateInput({ ...base, attendees: ['a@example.test', { email: 'b@example.test', optional: true }, { email: 'c@example.test', optional: false }] });
    expect(v.attendees).toEqual([{ email: 'a@example.test' }, { email: 'b@example.test', optional: true }, { email: 'c@example.test' }]);
    expect(parseCreateInput({ ...base, attendees: emails(50) }).attendees).toHaveLength(50);
    expect(() => parseCreateInput({ ...base, attendees: emails(51) })).toThrow(/at most 50/i);
    expect(() => parseCreateInput({ ...base, attendees: ['a@example.test', 'A@Example.test'] })).toThrow(/twice/i);
    for (const bad of ['no-at-sign', 'a@b', 'Name <a@example.test>', 'a b@example.test', 'a@example.test\r\nBcc: x@example.test', 'a,b@example.test', 'x'.repeat(65) + '@example.test']) {
      expect(() => parseCreateInput({ ...base, attendees: [bad] }), bad).toThrow(/attendee/i);
    }
    expect(() => parseCreateInput({ ...base, attendees: [{ email: 'a@example.test', responseStatus: 'accepted' }] })).toThrow(/responseStatus/);
  });

  it('puts attendees, guest permissions, recurrence and a requestId-derived Meet request into the create body', () => {
    const v = parseCreateInput({
      ...base,
      attendees: ['a@example.test'],
      guestsCanModify: true,
      guestsCanInviteOthers: false,
      guestsCanSeeOtherGuests: false,
      recurrence: ['RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=10', 'EXDATE;TZID=Europe/Vienna:20261012T090000'],
      addMeet: true,
    });
    const body = buildCreateBody(v);
    expect(body).toMatchObject({
      attendees: [{ email: 'a@example.test' }],
      guestsCanModify: true,
      guestsCanInviteOthers: false,
      guestsCanSeeOtherGuests: false,
      recurrence: ['RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=10', 'EXDATE;TZID=Europe/Vienna:20261012T090000'],
      visibility: 'default',
      conferenceData: { createRequest: { requestId: meetRequestId('gprod-0000000a', 'primary', base.requestId), conferenceSolutionKey: { type: 'hangoutsMeet' } } },
    });
    expect(buildCreateBody(parseCreateInput({ ...base, addMeet: true })).conferenceData).toEqual(body.conferenceData);
    expect(meetRequestId('gprod-0000000a', 'primary', 'req-other-0001')).not.toBe(meetRequestId('gprod-0000000a', 'primary', base.requestId));
    expect(buildCreateBody(parseCreateInput(base))).not.toHaveProperty('conferenceData');
    expect(buildCreateBody(parseCreateInput(base))).not.toHaveProperty('attendees');
  });

  it('validates recurrence strictly', () => {
    const ok = [
      ['RRULE:FREQ=DAILY'],
      ['RRULE:FREQ=MONTHLY;BYMONTHDAY=1;UNTIL=20271231T235959Z'],
      ['RRULE:FREQ=YEARLY;INTERVAL=2', 'RDATE;VALUE=DATE:20261224,20261231', 'EXDATE:20261225T090000Z'],
    ];
    for (const recurrence of ok) expect(validateRecurrence(recurrence), recurrence.join('|')).toEqual(recurrence);
    const bad: Array<[string[], RegExp]> = [
      [['RRULE:INTERVAL=2'], /FREQ/],
      [['RRULE:FREQ=HOURLY'], /FREQ must be/],
      [['RRULE:FREQ=WEEKLY;FREQ=DAILY'], /twice/],
      [['RRULE:FREQ=WEEKLY;COUNT=3;UNTIL=20270101'], /COUNT or UNTIL/],
      [['RRULE:FREQ=WEEKLY;COUNT=0'], /COUNT/],
      [['RRULE:FREQ=WEEKLY;X-NAME=1'], /RRULE parts|unknown RRULE part/],
      [['RRULE:FREQ=WEEKLY;BYWHAT=1'], /unknown RRULE part/],
      [['RRULE:FREQ=WEEKLY\r\nATTENDEE:mailto:x@example.test'], /whitespace or control/],
      [['RRULE:FREQ=WEEKLY;BYDAY=MO TU'], /whitespace/],
      [['RRULE;X=1:FREQ=WEEKLY'], /no parameters/],
      [['EXDATE:20261012'], /exactly one RRULE/],
      [['RRULE:FREQ=DAILY', 'RRULE:FREQ=WEEKLY'], /exactly one RRULE/],
      [['EXRULE:FREQ=DAILY'], /start with RRULE/],
      [['rrule:freq=daily'], /start with RRULE/],
      [['RRULE:FREQ=DAILY', 'EXDATE;TZID=Mars/Base:20261012T090000'], /TZID/],
      [['RRULE:FREQ=DAILY', 'RDATE;VALUE=PERIOD:20261012T090000Z/PT1H'], /VALUE/],
      [['RRULE:FREQ=DAILY', 'EXDATE:2026-10-12'], /yyyymmdd/],
    ];
    for (const [recurrence, re] of bad) expect(() => validateRecurrence(recurrence), recurrence.join('|')).toThrow(re);
    expect(() =>
      parseCreateInput({ ...base, recurrence: ['RRULE:FREQ=DAILY', 'EXDATE:20261012', 'EXDATE:20261013', 'EXDATE:20261014', 'EXDATE:20261015', 'EXDATE:20261016'] }),
    ).toThrow(/at most 5/i);
    expect(() => parseCreateInput({ ...base, recurrence: [] })).toThrow(/at least one/i);
    // Google expands timed series in start/end.timeZone, which is then required.
    expect(() => parseCreateInput({ ...base, start: { dateTime: '2026-10-06T09:00:00Z' }, end: { dateTime: '2026-10-06T10:00:00Z' }, recurrence: ['RRULE:FREQ=DAILY'] })).toThrow(
      /timeZone is required/,
    );
    expect(() => parseCreateInput({ ...base, start: { date: '2026-10-06' }, end: { date: '2026-10-07' }, recurrence: ['RRULE:FREQ=DAILY'] })).not.toThrow();
  });

  it('refuses single occurrences (instance ids) for update, delete and respond before any I/O', () => {
    const id = { accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'abcde12345_20261012T090000Z' };
    expect(() => parseUpdateInput({ ...id, etag: '"2"', summary: 'x' })).toThrow(/single occurrences .*not supported/i);
    expect(() => parseDeleteInput(id)).toThrow(/single occurrences .*not supported/i);
    expect(() => parseRespondInput({ ...id, response: 'accepted' })).toThrow(/single occurrences .*not supported/i);
    expect(() => parseRespondInput({ ...id, eventId: 'abcde12345', response: 'maybe' })).toThrow(/response must be one of/i);
    expect(() => parseDeleteInput({ ...id, eventId: 'abcde12345', sendUpdates: 'everyone' })).toThrow(/sendUpdates/i);
  });

  const existing = {
    id: 'evt0guests03',
    etag: '"3"',
    status: 'confirmed',
    organizer: { email: 'dummy.a@example.test', self: true },
    start: { dateTime: '2026-10-07T15:00:00Z' },
    end: { dateTime: '2026-10-07T16:00:00Z' },
    visibility: 'default',
    reminders: { useDefault: false, overrides: [] },
    attendees: [
      { email: 'dummy.a@example.test', self: true, responseStatus: 'accepted' },
      { email: 'guest@example.test', responseStatus: 'accepted' },
    ],
  };
  const upd = (extra: Record<string, unknown>) => parseUpdateInput({ accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0guests03', etag: '"3"', ...extra });

  it('plans guest changes: full new list, own entry and existing answers kept, no forced privacy with guests', () => {
    const plan = planPatch(upd({ attendees: ['guest@example.test', { email: 'new@example.test', optional: true }] }), existing);
    expect(plan).toMatchObject({ changesGuests: true, guestsInvolved: true, addsMeet: false });
    expect(plan.body).toEqual({
      attendees: [
        { email: 'dummy.a@example.test', responseStatus: 'accepted' },
        { email: 'guest@example.test', responseStatus: 'accepted' },
        { email: 'new@example.test', optional: true },
      ],
    });
    // A summary change of a guest event: guests involved (notification decision), the guest list untouched, visibility not forced.
    expect(planPatch(upd({ summary: 'S' }), existing)).toMatchObject({ body: { summary: 'S' }, changesGuests: false, guestsInvolved: true });
    // Removing every guest is a guest change; the event then is guest-less and becomes private.
    expect(planPatch(upd({ attendees: [] }), existing)).toMatchObject({
      body: { attendees: [{ email: 'dummy.a@example.test', responseStatus: 'accepted' }], visibility: 'private' },
      changesGuests: true,
      guestsInvolved: true,
    });
    // Listing only yourself on a guest-less event is not a guest change.
    const solo = { ...existing, attendees: [existing.attendees[0]!] };
    const soloPlan = planPatch(upd({ attendees: ['dummy.a@example.test'] }), { ...solo, visibility: 'private' });
    expect(soloPlan).toMatchObject({ changesGuests: false, guestsInvolved: false });
    expect(soloPlan.body).not.toHaveProperty('attendees');
  });

  it('plans a Meet link from the event and the etag, and refuses a second conference', () => {
    const plan = planPatch(upd({ addMeet: true }), existing);
    expect(plan.addsMeet).toBe(true);
    expect(plan.body.conferenceData).toEqual({
      createRequest: { requestId: meetRequestId('gprod-0000000a', 'primary', 'evt0guests03', '"3"'), conferenceSolutionKey: { type: 'hangoutsMeet' } },
    });
    expect(() => planPatch(upd({ addMeet: true }), { ...existing, hangoutLink: 'https://meet.google.com/x' })).toThrow(/already has a conference/i);
  });

  it('requires a time zone when a timed series is created or retimed by an update', () => {
    expect(() => planPatch(upd({ recurrence: ['RRULE:FREQ=WEEKLY'] }), existing)).toThrow(/timeZone is required/);
    const zoned = { ...existing, start: { dateTime: '2026-10-07T15:00:00Z', timeZone: 'UTC' }, end: { dateTime: '2026-10-07T16:00:00Z', timeZone: 'UTC' } };
    expect(planPatch(upd({ recurrence: ['RRULE:FREQ=WEEKLY'] }), zoned).body).toEqual({ recurrence: ['RRULE:FREQ=WEEKLY'] });
    expect(() => planPatch(upd({ start: { dateTime: '2026-10-07T14:00:00Z' } }), { ...existing, recurrence: ['RRULE:FREQ=WEEKLY'] })).toThrow(/timeZone is required/);
  });
});
