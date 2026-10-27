// Calendar read operations (calendarList.list, events.list/get) with multi-account provenance, cursor
// pagination, all-day vs dateTime handling and authorization before I/O. MOCK Google upstream only.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { principalFromGrant, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { CalendarService } from '../src/google/calendar.js';
import { createProductivityTokenProvider } from '../src/google/productivity.js';
import { CredentialStore, initStore, type Capability } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGoogleProductivity, sampleEvents, SCOPE, type MockProdAccount } from './support/mockProductivity.js';
import { addDummyProductivity } from './support/productivityFixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
let google: MockGoogleProductivity;
let service: CalendarService;
let a: MockProdAccount;
let b: MockProdAccount;

const client = (capabilities: Capability[], accountIds: string[]): Principal =>
  principalFromGrant({ id: 'client-0000000a', label: 'T', tokenSha256: '0'.repeat(64), capabilities, accountIds, createdAt: '' });

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  google = new MockGoogleProductivity();
  a = google.addAccount('dummy.a@example.test');
  a.calendars[0]!.events = sampleEvents();
  a.calendars.push(
    { id: 'team+x@group.calendar.google.com', summary: 'Team', timeZone: 'UTC', accessRole: 'writer', events: [] },
    { id: 'en.austrian#holiday@group.v.calendar.google.com', summary: 'Holidays', timeZone: 'Europe/Vienna', accessRole: 'reader', events: [] },
  );
  b = google.addAccount('dummy.b@example.test');
  b.calendars[0]!.events = [
    { id: 'bbb0event01', etag: '"9"', status: 'confirmed', summary: 'B event', start: { dateTime: '2026-10-08T08:00:00Z' }, end: { dateTime: '2026-10-08T09:00:00Z' } },
  ];
  await addDummyProductivity(store, 'gprod-0000000a', { refreshToken: a.refreshToken, email: a.email });
  await addDummyProductivity(store, 'gprod-0000000b', { refreshToken: b.refreshToken, email: b.email });
  const upstream = new Upstream(google.transport);
  service = new CalendarService(store, upstream, createProductivityTokenProvider(store, upstream));
});
afterEach(async () => {
  await dirs.cleanup();
});

const calendarCalls = () => google.calls.filter((c) => c.url.pathname.startsWith('/calendar/'));

describe('calendar_list_calendars [MOCK Google]', () => {
  it('fans out over all readable accounts with provenance and a resumable cursor', async () => {
    const p1 = await service.listCalendars(READONLY_PRINCIPAL, {});
    expect(p1.results.map((c) => [c.accountId, c.calendarId])).toEqual([
      ['gprod-0000000a', 'dummy.a@example.test'],
      ['gprod-0000000a', 'team+x@group.calendar.google.com'],
      ['gprod-0000000b', 'dummy.b@example.test'],
    ]);
    expect(p1.results[0]).toMatchObject({ accountLabel: 'Productivity gprod-0000000a', email: 'dummy.a@example.test', primary: true, accessRole: 'owner', timeZone: 'Europe/Vienna' });
    expect(p1.hasMore).toBe(true);
    const p2 = await service.listCalendars(READONLY_PRINCIPAL, { cursor: p1.nextCursor! });
    expect(p2.results.map((c) => c.calendarId)).toEqual(['en.austrian#holiday@group.v.calendar.google.com']);
    expect(p2.hasMore).toBe(false);
  });
});

describe('calendar_list_events [MOCK Google]', () => {
  it('expands single events ordered by start time and keeps all-day vs dateTime/timeZone exactly', async () => {
    const page1 = await service.listEvents(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', timeMin: '2026-10-01T00:00:00Z' });
    const req = calendarCalls().at(-1)!;
    expect(req.url.pathname).toBe('/calendar/v3/calendars/primary/events');
    expect(req.url.searchParams.get('singleEvents')).toBe('true');
    expect(req.url.searchParams.get('orderBy')).toBe('startTime');
    expect(req.url.searchParams.get('timeMin')).toBe('2026-10-01T00:00:00Z');
    const [allDay, timed] = page1.results;
    expect(allDay).toMatchObject({
      accountId: 'gprod-0000000a',
      calendarId: 'primary',
      eventId: 'evt0allday01',
      allDay: true,
      start: { date: '2026-10-06' },
      end: { date: '2026-10-07' },
      endExclusive: true,
      calendarTimeZone: 'Europe/Vienna',
      etag: '"1"',
    });
    expect(timed).toMatchObject({
      allDay: false,
      start: { dateTime: '2026-10-06T09:00:00+02:00', timeZone: 'Europe/Vienna' },
      end: { dateTime: '2026-10-06T10:00:00+02:00', timeZone: 'Europe/Vienna' },
    });
    expect(timed).not.toHaveProperty('endExclusive');
    expect(page1.hasMore).toBe(true);
    const page2 = await service.listEvents(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', timeMin: '2026-10-01T00:00:00Z', cursor: page1.nextCursor! });
    expect(page2.results.map((e) => e.eventId)).toEqual(['evt0guests03']);
    expect(page2.results[0]!.attendees).toEqual([
      { email: 'dummy.a@example.test', self: true, responseStatus: 'accepted' },
      { email: 'guest@example.test', responseStatus: 'needsAction' },
    ]);
    expect(page2.hasMore).toBe(false);
    // A cursor is bound to its query (and carries timeMin, so a later page keeps the same window).
    expect((await rejection(service.listEvents(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', query: 'other', cursor: page1.nextCursor! }))).message).toMatch(/cursor/i);
    expect(
      (await rejection(service.listEvents(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', timeMin: '2026-10-02T00:00:00Z', cursor: page1.nextCursor! }))).message,
    ).toMatch(/cursor/i);
    const again = await service.listEvents(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', cursor: page1.nextCursor! });
    expect(again.results.map((e) => e.eventId)).toEqual(['evt0guests03']);
    expect(calendarCalls().at(-1)!.url.searchParams.get('timeMin')).toBe('2026-10-01T00:00:00Z');
  });

  it('defaults timeMin to now and fans out across accounts, reporting a failing account as partial', async () => {
    google.faults = [{ match: (r) => r.url.pathname === '/calendar/v3/calendars/primary/events' && google.accessTokens.get(r.headers.authorization!.slice(7))?.account === b, mode: 'status', status: 500 }];
    const before = Date.now();
    const res = await service.listEvents(READONLY_PRINCIPAL, { timeMax: '2030-01-01T00:00:00Z' });
    const timeMin = Date.parse(calendarCalls().at(-1)!.url.searchParams.get('timeMin')!);
    expect(timeMin).toBeGreaterThanOrEqual(before - 1000);
    expect(res.partial).toBe(true);
    expect(res.errors).toEqual([expect.objectContaining({ accountId: 'gprod-0000000b' })]);
    expect(res.errors[0]!.message).toMatch(/HTTP 500/);
  });

  it('skips accounts connected without the calendar service and filters q/timeMax', async () => {
    await store.update((d) => {
      d.googleProductivity.find((x) => x.id === 'gprod-0000000b')!.services = ['contacts'];
    });
    const res = await service.listEvents(READONLY_PRINCIPAL, { timeMin: '2026-10-01T00:00:00Z', query: 'timed', timeMax: '2026-10-07T00:00:00Z' });
    expect(res.results.map((e) => [e.accountId, e.eventId])).toEqual([['gprod-0000000a', 'evt0timed002']]);
    expect(res.errors).toEqual([]);
    expect(calendarCalls().at(-1)!.url.searchParams.get('q')).toBe('timed');
  });

  it('validates arguments before any I/O', async () => {
    const bad: Array<[Record<string, unknown>, RegExp]> = [
      [{ timeMin: '2026-10-01T00:00:00' }, /timeMin.*offset/i],
      [{ timeMin: '2026-02-30T00:00:00Z' }, /timeMin/i],
      [{ timeMin: '2026-10-02T00:00:00Z', timeMax: '2026-10-01T00:00:00Z' }, /timeMax.*after/i],
      [{ timeZone: 'Mars/Olympus' }, /time ?zone/i],
      [{ calendarId: 'team+x@group.calendar.google.com' }, /accountId/i],
      [{ accountId: 'gprod-0000000a', calendarId: 'a/../b' }, /calendar id/i],
      [{ pageSize: 101 }, /pageSize/i],
    ];
    for (const [args, re] of bad) expect((await rejection(service.listEvents(READONLY_PRINCIPAL, args))).message, JSON.stringify(args)).toMatch(re);
    expect(google.calls).toEqual([]);
  });
});

describe('calendar_get_event [MOCK Google]', () => {
  it('reads one event with encoded calendar id and strict event id', async () => {
    a.calendars[1]!.events.push({ id: 'teamevent01', etag: '"5"', status: 'confirmed', summary: 'Team', start: { date: '2026-12-24' }, end: { date: '2026-12-25' } });
    const ev = await service.getEvent(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', calendarId: 'team+x@group.calendar.google.com', eventId: 'teamevent01' });
    expect(calendarCalls().at(-1)!.url.pathname).toBe('/calendar/v3/calendars/team%2Bx%40group.calendar.google.com/events/teamevent01');
    expect(ev).toMatchObject({ accountId: 'gprod-0000000a', calendarId: 'team+x@group.calendar.google.com', eventId: 'teamevent01', allDay: true, etag: '"5"' });
    expect((await rejection(service.getEvent(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'nothere0' }))).message).toMatch(/404/);
    const calls = google.calls.length;
    for (const eventId of ['../x', 'ABC', 'import', 'a b', '']) {
      expect((await rejection(service.getEvent(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', calendarId: 'primary', eventId }))).message).toMatch(/event id/i);
    }
    expect(google.calls.length).toBe(calls);
  });
});

describe('calendar read authorization (before any I/O)', () => {
  it('denies clients without calendar_read or without the account, with no existence oracle', async () => {
    const contactsOnly = client(['contacts_read'], ['gprod-0000000a']);
    const otherAccount = client(['calendar_read'], ['gprod-0000000b']);
    for (const p of [contactsOnly, otherAccount]) {
      expect((await rejection(service.getEvent(p, { accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002' }))).message).toMatch(/not granted/i);
    }
    const unknown = await rejection(service.getEvent(otherAccount, { accountId: 'gprod-000000ff', calendarId: 'primary', eventId: 'evt0timed002' }));
    expect(unknown.message).toMatch(/not granted/i);
    // A fan-out only covers the granted accounts.
    const res = await service.listCalendars(otherAccount, {});
    expect(new Set(res.results.map((c) => c.accountId))).toEqual(new Set(['gprod-0000000b']));
    expect(google.calls.some((c) => google.accessTokens.get((c.headers.authorization ?? '').slice(7))?.account === a)).toBe(false);
    expect((await service.listCalendars(contactsOnly, {})).results).toEqual([]);
  });

  it('requires the stored calendar scope and fails closed when Google stops reporting it on refresh', async () => {
    await store.update((d) => {
      d.googleProductivity.find((x) => x.id === 'gprod-0000000a')!.services = ['contacts'];
    });
    expect((await rejection(service.getEvent(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002' }))).message).toMatch(
      /not connected for calendar/i,
    );
    expect(google.calls).toEqual([]);
    google.refreshScopeOverride = `openid ${SCOPE.email} ${SCOPE.contactsRead}`;
    const err = await rejection(service.getEvent(READONLY_PRINCIPAL, { accountId: 'gprod-0000000b', calendarId: 'primary', eventId: 'bbb0event01' }));
    expect(err.message).toMatch(/no longer reports/i);
    expect(calendarCalls()).toEqual([]);
  });
});
