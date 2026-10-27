// Calendar invitations, series, Meet links, permanent delete and responses (MAIL_CALENDAR_SLACK_SPEC §2)
// against the MOCK Google upstream: calendar_write vs calendar_invite gating, sendUpdates defaults, If-Match,
// occurrence refusal and the narrowed allowlist. No live event is ever written.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { principalFromGrant, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { PerchError } from '../src/errors.js';
import { CalendarService } from '../src/google/calendar.js';
import { meetRequestId } from '../src/google/calendarWrite.js';
import { createProductivityTokenProvider } from '../src/google/productivity.js';
import { CAPABILITIES, CredentialStore, initStore, PRODUCTIVITY_CAPABILITIES, type Capability } from '../src/store/credentialStore.js';
import { Upstream, type UpstreamRequest } from '../src/upstream.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGoogleProductivity, sampleEvents, type MockProdAccount } from './support/mockProductivity.js';
import { addDummyProductivity } from './support/productivityFixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
let google: MockGoogleProductivity;
let service: CalendarService;
let acct: MockProdAccount;

const client = (capabilities: Capability[], accountIds = ['gprod-0000000a']): Principal =>
  principalFromGrant({ id: 'client-0000000a', label: 'T', tokenSha256: '0'.repeat(64), capabilities, accountIds, createdAt: '' });
const writer = () => client(['calendar_read', 'calendar_write']);
const inviter = () => client(['calendar_read', 'calendar_write', 'calendar_invite']);
const full = () => principalFromGrant({ id: 'client-0000000f', label: 'F', tokenSha256: '1'.repeat(64), capabilities: ['read'], accountIds: [], full: true, createdAt: '' });

const createArgs = (extra: Record<string, unknown> = {}) => ({
  accountId: 'gprod-0000000a',
  requestId: 'req-2026-10-20-0001',
  summary: 'Dummy sync',
  start: { dateTime: '2026-10-21T09:00:00', timeZone: 'Europe/Vienna' },
  end: { dateTime: '2026-10-21T10:00:00', timeZone: 'Europe/Vienna' },
  ...extra,
});
const at = { accountId: 'gprod-0000000a', calendarId: 'primary' };

const writes = () => google.calendarWrites();
const events = () => acct.calendars[0]!.events;
const ev = (id: string) => events().find((e) => e.id === id);
const query = (r: UpstreamRequest) => Object.fromEntries(r.url.searchParams);

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  google = new MockGoogleProductivity();
  acct = google.addAccount('dummy.a@example.test');
  acct.calendars[0]!.events = sampleEvents();
  await addDummyProductivity(store, 'gprod-0000000a', { refreshToken: acct.refreshToken, email: acct.email, allowCalendarWrite: true });
  const upstream = new Upstream(google.transport);
  service = new CalendarService(store, upstream, createProductivityTokenProvider(store, upstream));
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('calendar_invite capability', () => {
  it('is a productivity capability and part of full grants', () => {
    expect(PRODUCTIVITY_CAPABILITIES).toContain('calendar_invite');
    expect(CAPABILITIES).toContain('calendar_invite');
    expect(full().capabilities.has('calendar_invite')).toBe(true);
    expect(READONLY_PRINCIPAL.capabilities.has('calendar_invite')).toBe(false);
  });
});

describe('create with guests, series and Meet [MOCK Google]', () => {
  it('needs calendar_invite for attendees, denied before any I/O', async () => {
    const r = await rejection(service.createEvent(writer(), createArgs({ attendees: ['guest@example.test'] })));
    expect(r.message).toMatch(/calendar_invite.*not granted.*invitations/i);
    expect(google.calls).toEqual([]);
    expect((await rejection(service.createEvent(READONLY_PRINCIPAL, createArgs({ attendees: ['guest@example.test'] })))).message).toMatch(/read-only/i);
  });

  it('invites with sendUpdates=all and visibility default, and reports what Google was asked to send', async () => {
    const r = await service.createEvent(inviter(), createArgs({ attendees: ['guest@example.test', { email: 'opt@example.test', optional: true }], guestsCanSeeOtherGuests: false }));
    expect(r).toMatchObject({ status: 'created', sendUpdates: 'all' });
    expect(r.detail).toMatch(/email all guests/i);
    const req = writes()[0]!;
    expect(query(req)).toEqual({ sendUpdates: 'all' });
    const body = JSON.parse(req.body!);
    expect(body).toMatchObject({ visibility: 'default', guestsCanSeeOtherGuests: false, attendees: [{ email: 'guest@example.test' }, { email: 'opt@example.test', optional: true }] });
    expect(r.event!.attendees).toHaveLength(2);
  });

  it('honours sendUpdates none/externalOnly with guests', async () => {
    const silent = await service.createEvent(inviter(), createArgs({ attendees: ['guest@example.test'], sendUpdates: 'none' }));
    expect(silent.detail).toMatch(/NOT notified/);
    await service.createEvent(inviter(), createArgs({ requestId: 'req-2026-10-20-0002', attendees: ['guest@example.test'], sendUpdates: 'externalOnly' }));
    expect(writes().map((w) => w.url.searchParams.get('sendUpdates'))).toEqual(['none', 'externalOnly']);
  });

  it('creates a private series with calendar_write only', async () => {
    const r = await service.createEvent(writer(), createArgs({ recurrence: ['RRULE:FREQ=WEEKLY;BYDAY=TU;COUNT=5'] }));
    expect(r.status).toBe('created');
    expect(r.event!.recurrence).toEqual(['RRULE:FREQ=WEEKLY;BYDAY=TU;COUNT=5']);
    expect(JSON.parse(writes()[0]!.body!)).toMatchObject({ visibility: 'private', recurrence: ['RRULE:FREQ=WEEKLY;BYDAY=TU;COUNT=5'] });
    expect(query(writes()[0]!)).toEqual({ sendUpdates: 'none' });
  });

  it('adds a Meet link with conferenceDataVersion=1 and a requestId-derived conference request id', async () => {
    const r = await service.createEvent(writer(), createArgs({ addMeet: true }));
    expect(query(writes()[0]!)).toEqual({ sendUpdates: 'none', conferenceDataVersion: '1' });
    expect(JSON.parse(writes()[0]!.body!).conferenceData.createRequest.requestId).toBe(meetRequestId('gprod-0000000a', 'primary', 'req-2026-10-20-0001'));
    expect(r.event!.hangoutLink).toMatch(/^https:\/\/meet\.google\.com\//);
  });
});

describe('update with guests [MOCK Google]', () => {
  const upd = (extra: Record<string, unknown> = {}) => ({ ...at, eventId: 'evt0guests03', etag: '"3"', summary: 'Moved', ...extra });

  it('a change to a guest event notifies by default and then needs calendar_invite (denied before any write)', async () => {
    const r = await rejection(service.updateEvent(writer(), upd()));
    expect(r.message).toMatch(/event that has guests needs calendar_invite/i);
    expect(writes()).toEqual([]);
    const ok = await service.updateEvent(inviter(), upd());
    expect(ok).toMatchObject({ status: 'updated', sendUpdates: 'all' });
    expect(query(writes()[0]!)).toEqual({ sendUpdates: 'all' });
    // No forced privacy for an event with guests; reminders are still made popup-only.
    expect(JSON.parse(writes()[0]!.body!)).toEqual({ summary: 'Moved', reminders: { useDefault: false, overrides: [] } });
  });

  it('any change to a guest event needs calendar_invite, also silent ones (time, recurrence, Meet, guest permissions)', async () => {
    const changes: Array<Record<string, unknown>> = [
      { sendUpdates: 'none' },
      { summary: undefined, guestsCanModify: true, sendUpdates: 'none' },
      { summary: undefined, guestsCanInviteOthers: true },
      { summary: undefined, guestsCanSeeOtherGuests: false, sendUpdates: 'none' },
      { summary: undefined, start: { dateTime: '2026-10-07T17:00:00Z' }, end: { dateTime: '2026-10-07T18:00:00Z' }, sendUpdates: 'none' },
      {
        summary: undefined,
        recurrence: ['RRULE:FREQ=WEEKLY;COUNT=3'],
        start: { dateTime: '2026-10-07T15:00:00', timeZone: 'Europe/Vienna' },
        end: { dateTime: '2026-10-07T16:00:00', timeZone: 'Europe/Vienna' },
        sendUpdates: 'none',
      },
      { summary: undefined, addMeet: true, sendUpdates: 'none' },
    ];
    for (const c of changes) {
      const r = await rejection(service.updateEvent(writer(), upd(c)));
      expect((r as PerchError).code, JSON.stringify(c)).toBe('capability_denied');
      expect(r.message).toMatch(/guests needs calendar_invite.*calendar_write alone only covers events without guests/i);
    }
    expect(writes()).toEqual([]);
    const r = await service.updateEvent(inviter(), upd({ sendUpdates: 'none' }));
    expect(r).toMatchObject({ status: 'updated', sendUpdates: 'none' });
    expect(r.detail).toMatch(/NOT notified/);
    expect(query(writes()[0]!)).toEqual({ sendUpdates: 'none' });
    // An event without guests stays calendar_write only, guest permissions included.
    const ok = await service.updateEvent(writer(), { ...at, eventId: 'evt0timed002', etag: '"2"', guestsCanModify: true, start: { dateTime: '2026-10-06T11:00:00+02:00', timeZone: 'Europe/Vienna' }, end: { dateTime: '2026-10-06T12:00:00+02:00', timeZone: 'Europe/Vienna' } });
    expect(ok).toMatchObject({ status: 'updated', sendUpdates: 'none' });
  });

  it('keeps comment, additionalGuests and displayName of guests who stay on the list', async () => {
    (ev('evt0guests03')!.attendees as Array<Record<string, unknown>>)[1] = {
      email: 'guest@example.test', responseStatus: 'accepted', comment: 'bringing slides', additionalGuests: 2, displayName: 'Gina Guest',
    };
    await service.updateEvent(inviter(), upd({ summary: undefined, attendees: ['GUEST@example.test', 'new@example.test'] }));
    expect(JSON.parse(writes()[0]!.body!).attendees).toEqual([
      { email: 'dummy.a@example.test', responseStatus: 'accepted' },
      { email: 'GUEST@example.test', responseStatus: 'accepted', comment: 'bringing slides', additionalGuests: 2, displayName: 'Gina Guest' },
      { email: 'new@example.test' },
    ]);
  });

  it('changing the guest list always needs calendar_invite, even silently, and keeps existing answers', async () => {
    const r = await rejection(service.updateEvent(writer(), upd({ summary: undefined, attendees: ['guest@example.test', 'new@example.test'], sendUpdates: 'none' })));
    expect(r.message).toMatch(/guest list needs calendar_invite/i);
    expect(writes()).toEqual([]);
    await service.updateEvent(inviter(), upd({ summary: undefined, attendees: ['guest@example.test', 'new@example.test'] }));
    expect(JSON.parse(writes()[0]!.body!).attendees).toEqual([
      { email: 'dummy.a@example.test', responseStatus: 'accepted' },
      { email: 'guest@example.test', responseStatus: 'needsAction' },
      { email: 'new@example.test' },
    ]);
    // Inviting guests to a guest-less event is a guest change too.
    expect((await rejection(service.updateEvent(writer(), { ...at, eventId: 'evt0timed002', etag: '"2"', attendees: ['x@example.test'] }))).message).toMatch(/calendar_invite/);
  });

  it('turns a single event into a series and adds a Meet link to an existing event', async () => {
    Object.assign(ev('evt0timed002')!, { visibility: 'private', reminders: { useDefault: false, overrides: [] } });
    const r = await service.updateEvent(writer(), { ...at, eventId: 'evt0timed002', etag: '"2"', recurrence: ['RRULE:FREQ=DAILY;COUNT=3'], addMeet: true });
    expect(r.status).toBe('updated');
    expect(query(writes()[0]!)).toEqual({ sendUpdates: 'none', conferenceDataVersion: '1' });
    expect(JSON.parse(writes()[0]!.body!)).toEqual({
      recurrence: ['RRULE:FREQ=DAILY;COUNT=3'],
      conferenceData: { createRequest: { requestId: meetRequestId('gprod-0000000a', 'primary', 'evt0timed002', '"2"'), conferenceSolutionKey: { type: 'hangoutsMeet' } } },
    });
    expect(ev('evt0timed002')!.hangoutLink).toMatch(/meet\.google\.com/);
  });
});

describe('calendar_delete_event [MOCK Google]', () => {
  it('permanently deletes a guest-less event with calendar_write, sendUpdates=none and If-Match', async () => {
    const r = await service.deleteEvent(writer(), { ...at, eventId: 'evt0timed002', etag: '"2"' });
    expect(r).toMatchObject({ status: 'deleted', sendUpdates: 'none' });
    expect(r.detail).toMatch(/permanently deleted.*cannot be undone/i);
    const req = writes()[0]!;
    expect(req.method).toBe('DELETE');
    expect(req.url.pathname).toBe('/calendar/v3/calendars/primary/events/evt0timed002');
    expect(req.headers['if-match']).toBe('"2"');
    expect(query(req)).toEqual({ sendUpdates: 'none' });
    expect(ev('evt0timed002')).toBeUndefined();
  });

  it('sends the current etag as If-Match even without a caller etag, and refuses a stale caller etag without deleting', async () => {
    const stale = await service.deleteEvent(writer(), { ...at, eventId: 'evt0timed002', etag: '"1"' });
    expect(stale).toMatchObject({ status: 'precondition_failed', currentEtag: '"2"' });
    expect(writes()).toEqual([]);
    google.faults.push({ match: (q) => q.method === 'DELETE', mode: 'status', status: 412, body: { error: { code: 412, errors: [{ reason: 'conditionNotMet' }] } } });
    expect((await service.deleteEvent(writer(), { ...at, eventId: 'evt0timed002' })).status).toBe('precondition_failed');
    expect(writes()[0]!.headers['if-match']).toBe('"2"');
    expect(ev('evt0timed002')).toBeDefined();
  });

  it('needs calendar_invite for events with guests (cancellations default to all)', async () => {
    expect((await rejection(service.deleteEvent(writer(), { ...at, eventId: 'evt0guests03' }))).message).toMatch(/guests needs calendar_invite/i);
    expect(writes()).toEqual([]);
    const r = await service.deleteEvent(inviter(), { ...at, eventId: 'evt0guests03' });
    expect(r).toMatchObject({ status: 'deleted', sendUpdates: 'all' });
    expect(r.detail).toMatch(/cancellations/i);
    await service.deleteEvent(inviter(), { ...at, eventId: 'evt0timed002', sendUpdates: 'all' });
    expect(writes().map((w) => w.url.searchParams.get('sendUpdates'))).toEqual(['all', 'none']);
  });

  it('deletes a whole series by its series id and refuses occurrences', async () => {
    events().push({
      id: 'evt0series05',
      etag: '"5"',
      status: 'confirmed',
      summary: 'Series',
      recurrence: ['RRULE:FREQ=WEEKLY'],
      organizer: { email: 'dummy.a@example.test', self: true },
      start: { date: '2026-10-08' },
      end: { date: '2026-10-09' },
    });
    events().push({ id: 'evt0inst0006', etag: '"6"', status: 'confirmed', recurringEventId: 'evt0series05', organizer: { email: 'dummy.a@example.test', self: true }, start: { date: '2026-10-15' }, end: { date: '2026-10-16' } });
    expect((await rejection(service.deleteEvent(writer(), { ...at, eventId: 'evt0series05_20261015' }))).message).toMatch(/single occurrences .*not supported/i);
    expect((await rejection(service.deleteEvent(writer(), { ...at, eventId: 'evt0inst0006' }))).message).toMatch(/single occurrences .*not supported/i);
    expect(writes()).toEqual([]);
    const r = await service.deleteEvent(writer(), { ...at, eventId: 'evt0series05' });
    expect(r.detail).toMatch(/whole series/);
  });

  it('reports a fetched event with status "cancelled" as not_found without writing', async () => {
    Object.assign(ev('evt0timed002')!, { status: 'cancelled' });
    const r = await service.deleteEvent(writer(), { ...at, eventId: 'evt0timed002' });
    expect(r.status).toBe('not_found');
    expect(r.detail).toMatch(/already deleted/i);
    expect(writes()).toEqual([]);
  });

  it('refuses events organised by others; reports already-deleted, indeterminate and denials honestly', async () => {
    events().push({ id: 'evt0other08', etag: '"8"', status: 'confirmed', organizer: { email: 'boss@example.test' }, start: { date: '2026-10-08' }, end: { date: '2026-10-09' } });
    expect((await rejection(service.deleteEvent(writer(), { ...at, eventId: 'evt0other08' }))).message).toMatch(/organized by someone else.*calendar_respond_event/i);
    google.faults.push({ match: (q) => q.method === 'DELETE', mode: 'status', status: 410, body: { error: { code: 410, errors: [{ reason: 'deleted' }] } } });
    expect((await service.deleteEvent(writer(), { ...at, eventId: 'evt0timed002' })).status).toBe('not_found');
    google.faults.push({ match: (q) => q.method === 'DELETE', mode: 'network', commitFirst: true });
    expect((await service.deleteEvent(writer(), { ...at, eventId: 'evt0timed002' })).status).toBe('indeterminate');
    expect(writes().filter((w) => w.method === 'DELETE')).toHaveLength(2);
    const before = google.calls.length;
    expect((await rejection(service.deleteEvent(READONLY_PRINCIPAL, { ...at, eventId: 'evt0guests03' }))).message).toMatch(/read-only/i);
    expect((await rejection(service.deleteEvent(client(['calendar_write']), { ...at, eventId: 'evt0guests03' }))).message).toMatch(/calendar_read.*not granted/i);
    expect(google.calls.length).toBe(before);
  });
});

describe('calendar_respond_event [MOCK Google]', () => {
  const invitation = () => {
    events().push({
      id: 'evt0invite07',
      etag: '"7"',
      status: 'confirmed',
      summary: 'Invitation',
      organizer: { email: 'boss@example.test' },
      start: { dateTime: '2026-10-22T09:00:00Z' },
      end: { dateTime: '2026-10-22T10:00:00Z' },
      attendees: [
        { email: 'boss@example.test', organizer: true, responseStatus: 'accepted' },
        { email: 'dummy.a@example.test', self: true, responseStatus: 'needsAction', comment: 'hi' },
        { email: 'other@example.test', responseStatus: 'needsAction' },
      ],
    });
  };

  it('patches only the own entry with attendeesOmitted, If-Match and sendUpdates=all by default', async () => {
    invitation();
    const r = await service.respondEvent(client(['calendar_read', 'calendar_invite']), { ...at, eventId: 'evt0invite07', response: 'accepted' });
    expect(r).toMatchObject({ status: 'responded', response: 'accepted', sendUpdates: 'all' });
    const req = writes()[0]!;
    expect(req.method).toBe('PATCH');
    expect(req.headers['if-match']).toBe('"7"');
    expect(query(req)).toEqual({ sendUpdates: 'all' });
    expect(JSON.parse(req.body!)).toEqual({ attendees: [{ email: 'dummy.a@example.test', responseStatus: 'accepted', comment: 'hi' }], attendeesOmitted: true });
    const list = ev('evt0invite07')!.attendees as Array<{ email: string; responseStatus: string }>;
    expect(list.map((a) => a.responseStatus)).toEqual(['accepted', 'accepted', 'needsAction']);
  });

  it('needs calendar_invite and refuses events without an own entry, occurrences and stale etags', async () => {
    invitation();
    expect((await rejection(service.respondEvent(writer(), { ...at, eventId: 'evt0invite07', response: 'declined' }))).message).toMatch(/calendar_invite.*not granted/i);
    expect(google.calls).toEqual([]);
    events().push({ id: 'evt0noself09', etag: '"9"', status: 'confirmed', organizer: { email: 'boss@example.test' }, start: { date: '2026-10-08' }, end: { date: '2026-10-09' } });
    expect((await rejection(service.respondEvent(inviter(), { ...at, eventId: 'evt0noself09', response: 'declined' }))).message).toMatch(/not on the guest list/i);
    expect((await rejection(service.respondEvent(inviter(), { ...at, eventId: 'evt0invite07_20261022T090000Z', response: 'declined' }))).message).toMatch(/single occurrences/i);
    expect(await service.respondEvent(inviter(), { ...at, eventId: 'evt0invite07', response: 'declined', etag: '"1"' })).toMatchObject({ status: 'precondition_failed' });
    expect(writes()).toEqual([]);
    await service.respondEvent(inviter(), { ...at, eventId: 'evt0invite07', response: 'tentative', sendUpdates: 'none' });
    expect(query(writes()[0]!)).toEqual({ sendUpdates: 'none' });
  });

  it('refuses to answer an event the account organizes (use calendar_update_event)', async () => {
    const r = await rejection(service.respondEvent(inviter(), { ...at, eventId: 'evt0guests03', response: 'declined' }));
    expect((r as PerchError).code).toBe('unsupported_event');
    expect(r.message).toMatch(/you organize this event.*calendar_update_event/i);
    expect(writes()).toEqual([]);
  });

  it('finds the own entry by the account email when Google omits self', async () => {
    invitation();
    const e = ev('evt0invite07')!;
    (e.attendees as Array<Record<string, unknown>>)[1] = { email: 'Dummy.A@example.test', responseStatus: 'needsAction' };
    expect((await service.respondEvent(inviter(), { ...at, eventId: 'evt0invite07', response: 'declined' })).status).toBe('responded');
    expect(JSON.parse(writes()[0]!.body!).attendees).toEqual([{ email: 'Dummy.A@example.test', responseStatus: 'declined' }]);
  });
});

describe('Calendar write allowlist [MOCK transport]', () => {
  const rec = () => {
    const calls: UpstreamRequest[] = [];
    const upstream = new Upstream(async (req) => {
      calls.push(req);
      return { status: 200, headers: {}, body: Buffer.from('{}') };
    });
    return { calls, upstream };
  };
  const EV = '/calendar/v3/calendars/primary/events';

  it('reaches DELETE of one event or series only with a calendar tag, never whole calendars, clear, ACLs or occurrences', async () => {
    const { calls, upstream } = rec();
    await upstream.raw('calendar', { method: 'DELETE', path: `${EV}/abcde12345`, capability: 'calendar_write', query: { sendUpdates: 'none' } });
    await upstream.raw('calendar', { method: 'DELETE', path: `${EV}/abcde12345`, capability: 'calendar_invite', query: { sendUpdates: 'all' } });
    expect(calls).toHaveLength(2);
    const blocked: Array<[string, string]> = [
      ['DELETE', '/calendar/v3/calendars/primary'],
      ['DELETE', '/calendar/v3/calendars/dummy%40example.test'],
      ['POST', '/calendar/v3/calendars/primary/clear'],
      ['DELETE', '/calendar/v3/users/me/calendarList/primary'],
      ['DELETE', '/calendar/v3/calendars/primary/acl/user%3Ax%40example.test'],
      ['DELETE', `${EV}/abcde12345_20261012T090000Z`],
      ['PATCH', `${EV}/abcde12345_20261012`],
      ['DELETE', `${EV}`],
      ['POST', `${EV}/abcde12345/move`],
    ];
    for (const capability of ['calendar_write', 'calendar_invite', 'read', 'admin'] as const) {
      for (const [method, path] of blocked) {
        expect((await rejection(upstream.raw('calendar', { method: method as 'DELETE', path, capability }))).message, `${capability} ${method} ${path}`).toMatch(/non-allowlisted/i);
      }
    }
    expect((await rejection(upstream.raw('calendar', { method: 'DELETE', path: `${EV}/abcde12345` }))).message).toMatch(/non-allowlisted/i);
    expect(calls).toHaveLength(2);
  });

  it('allows only sendUpdates/conferenceDataVersion on writes, and no notifications or attendees under calendar_write', async () => {
    const { calls, upstream } = rec();
    const bad: Array<[Record<string, unknown>, 'calendar_write' | 'calendar_invite', RegExp]> = [
      [{ query: { sendUpdates: 'all' } }, 'calendar_write', /calendar_invite/],
      [{ query: { sendUpdates: 'externalOnly' } }, 'calendar_write', /calendar_invite/],
      [{ json: { attendees: [] } }, 'calendar_write', /attendees need calendar_invite/],
      [{ json: { attendeesOmitted: true } }, 'calendar_write', /attendees need calendar_invite/],
      [{ query: { sendUpdates: 'everyone' } }, 'calendar_invite', /sendUpdates/],
      [{ query: { conferenceDataVersion: 2 } }, 'calendar_invite', /conferenceDataVersion/],
      [{ query: { supportsAttachments: true } }, 'calendar_invite', /supportsAttachments/],
      [{ query: { sendNotifications: true } }, 'calendar_invite', /sendNotifications/],
    ];
    for (const [extra, capability, re] of bad) {
      expect((await rejection(upstream.raw('calendar', { method: 'POST', path: EV, capability, ...extra }))).message, JSON.stringify(extra)).toMatch(re);
    }
    expect((await rejection(upstream.raw('calendar', { method: 'DELETE', path: `${EV}/abcde12345`, capability: 'calendar_write', query: { conferenceDataVersion: 1 } }))).message).toMatch(
      /conferenceDataVersion/,
    );
    expect(calls).toEqual([]);
    await upstream.raw('calendar', { method: 'POST', path: EV, capability: 'calendar_invite', query: { sendUpdates: 'all', conferenceDataVersion: 1 }, json: { attendees: [{ email: 'x@example.test' }] } });
    await upstream.raw('calendar', { method: 'PATCH', path: `${EV}/abcde12345`, capability: 'calendar_write', query: { sendUpdates: 'none', conferenceDataVersion: 1 }, json: { summary: 'x' } });
    expect(calls).toHaveLength(2);
  });
});
