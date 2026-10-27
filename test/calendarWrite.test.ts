// Calendar create/update against the MOCK Google upstream: idempotent create via requestId-derived ids,
// ETag If-Match PATCH, no notifications, honest conflict/indeterminate outcomes and no blind retries.
// No live event is ever written.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { principalFromGrant, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { CalendarService } from '../src/google/calendar.js';
import { eventIdForRequest } from '../src/google/calendarWrite.js';
import { createProductivityTokenProvider } from '../src/google/productivity.js';
import { CredentialStore, initStore, type Capability } from '../src/store/credentialStore.js';
import { Upstream, type UpstreamRequest } from '../src/upstream.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGoogleProductivity, sampleEvents, SCOPE, type MockProdAccount } from './support/mockProductivity.js';
import { addDummyProductivity } from './support/productivityFixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
let google: MockGoogleProductivity;
let service: CalendarService;
let acct: MockProdAccount;

const client = (capabilities: Capability[], accountIds = ['gprod-0000000a']): Principal =>
  principalFromGrant({ id: 'client-0000000a', label: 'T', tokenSha256: '0'.repeat(64), capabilities, accountIds, createdAt: '' });
const writer = () => client(['calendar_read', 'calendar_write']);

const createArgs = (requestId = 'req-2026-10-05-0001') => ({
  accountId: 'gprod-0000000a',
  requestId,
  summary: 'Dummy dentist',
  start: { dateTime: '2026-10-06T09:00:00', timeZone: 'Europe/Vienna' },
  end: { dateTime: '2026-10-06T10:00:00', timeZone: 'Europe/Vienna' },
});

const isInsert = (r: UpstreamRequest) => r.method === 'POST' && r.url.pathname.endsWith('/events');
const isPatch = (r: UpstreamRequest) => r.method === 'PATCH';
const events = () => acct.calendars[0]!.events;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  google = new MockGoogleProductivity();
  acct = google.addAccount('dummy.a@example.test');
  acct.calendars[0]!.events = sampleEvents();
  await addDummyProductivity(store, 'gprod-0000000a', { refreshToken: acct.refreshToken, email: acct.email, allowCalendarWrite: true });
  await addDummyProductivity(store, 'gprod-0000000b', { allowCalendarWrite: true });
  const upstream = new Upstream(google.transport);
  service = new CalendarService(store, upstream, createProductivityTokenProvider(store, upstream));
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('calendar_create_event [MOCK Google]', () => {
  it('creates a private event with the requestId-derived id, sendUpdates=none and only allowed fields', async () => {
    const res = await service.createEvent(writer(), createArgs());
    expect(res).toMatchObject({
      status: 'created',
      accountId: 'gprod-0000000a',
      email: 'dummy.a@example.test',
      requestId: 'req-2026-10-05-0001',
      event: { eventId: eventIdForRequest('gprod-0000000a', 'primary', 'req-2026-10-05-0001'), summary: 'Dummy dentist', calendarId: 'primary' },
    });
    expect(res.detail).toMatch(/no invitations or updates were sent to anyone/i);
    const req = google.calls.find(isInsert)!;
    expect(req.url.pathname).toBe('/calendar/v3/calendars/primary/events');
    expect(req.url.searchParams.get('sendUpdates')).toBe('none');
    expect(req.url.searchParams.has('conferenceDataVersion')).toBe(false);
    expect(req.url.searchParams.has('supportsAttachments')).toBe(false);
    const sent = JSON.parse(req.body!);
    expect(Object.keys(sent).sort()).toEqual(['end', 'id', 'reminders', 'start', 'summary', 'visibility']);
    // Never inherit calendar sharing (may be public) or calendar default reminders (may be email).
    expect(sent.visibility).toBe('private');
    expect(sent.reminders).toEqual({ useDefault: false, overrides: [] });
    expect(res.event).toMatchObject({ visibility: 'private', reminders: { useDefault: false, overrides: [] } });
  });

  it('a retry with the same requestId never creates a second event: conflict', async () => {
    await service.createEvent(writer(), createArgs());
    const again = await service.createEvent(writer(), createArgs());
    expect(again).toMatchObject({ status: 'conflict', eventId: eventIdForRequest('gprod-0000000a', 'primary', 'req-2026-10-05-0001') });
    expect(again.detail).toMatch(/already exists/i);
    expect(events().filter((e) => e.summary === 'Dummy dentist')).toHaveLength(1);
  });

  it('reports indeterminate on a lost response, never retries, and a manual retry with the same requestId resolves it', async () => {
    // Response lost AFTER Google committed the event.
    google.faults.push({ match: isInsert, mode: 'network', commitFirst: true });
    const lost = await service.createEvent(writer(), createArgs());
    expect(lost).toMatchObject({ status: 'indeterminate', eventId: eventIdForRequest('gprod-0000000a', 'primary', 'req-2026-10-05-0001') });
    expect(lost.detail).toMatch(/same requestId/i);
    expect(google.calls.filter(isInsert)).toHaveLength(1);
    expect((await service.createEvent(writer(), createArgs())).status).toBe('conflict');
    // Lost BEFORE commit: the manual retry creates it exactly once.
    google.faults.push({ match: isInsert, mode: 'status', status: 503 });
    expect((await service.createEvent(writer(), createArgs('req-2026-10-05-0002'))).status).toBe('indeterminate');
    expect((await service.createEvent(writer(), createArgs('req-2026-10-05-0002'))).status).toBe('created');
    expect(events().filter((e) => e.summary === 'Dummy dentist')).toHaveLength(2);
  });

  it('maps other 4xx to rejected (nothing created)', async () => {
    google.faults.push({ match: isInsert, mode: 'status', status: 400, body: { error: { code: 400, errors: [{ reason: 'timeRangeEmpty' }] } } });
    const r = await service.createEvent(writer(), createArgs());
    expect(r).toMatchObject({ status: 'rejected' });
    expect(r.detail).toMatch(/not created.*400/i);
  });

  it('denies before any I/O: operator, missing calendar_write, other account, no provider write grant, scope revoked', async () => {
    const attempts: Array<[Principal, string]> = [
      [READONLY_PRINCIPAL, 'read-only'],
      [client(['calendar_read']), 'not granted'],
      [client(['calendar_read', 'calendar_write'], ['gprod-0000000b']), 'not granted'],
    ];
    for (const [p, re] of attempts) expect((await rejection(service.createEvent(p, createArgs()))).message).toMatch(new RegExp(re, 'i'));
    await store.update((d) => {
      d.googleProductivity.find((a) => a.id === 'gprod-0000000a')!.allowCalendarWrite = false;
    });
    expect((await rejection(service.createEvent(writer(), createArgs()))).message).toMatch(/not authorised for calendar writes/i);
    expect(google.calls).toEqual([]);
    await store.update((d) => {
      d.googleProductivity.find((a) => a.id === 'gprod-0000000a')!.allowCalendarWrite = true;
    });
    google.refreshScopeOverride = `openid ${SCOPE.email} ${SCOPE.calendarRead}`;
    expect((await rejection(service.createEvent(writer(), createArgs()))).message).toMatch(/no longer reports.*calendar\.events\.owned/i);
    expect(google.calls.filter((c) => c.url.pathname.startsWith('/calendar/'))).toEqual([]);
  });

  it('rejects conference data and other forbidden fields before any I/O; sendUpdates without guests stays none', async () => {
    for (const extra of [{ conferenceData: {} }, { organizer: { email: 'x@example.test' } }, { attachments: [] }]) {
      expect((await rejection(service.createEvent(writer(), { ...createArgs(), ...extra }))).message).toMatch(/not supported/i);
    }
    expect(google.calls).toEqual([]);
    const r = await service.createEvent(writer(), { ...createArgs(), sendUpdates: 'all' });
    expect(r).toMatchObject({ status: 'created', sendUpdates: 'none' });
    expect(google.calls.find(isInsert)!.url.searchParams.get('sendUpdates')).toBe('none');
  });
});

describe('calendar_update_event [MOCK Google]', () => {
  const upd = (extra: Record<string, unknown> = {}) => ({ accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"', summary: 'Moved', ...extra });

  it('PATCHes with If-Match and sendUpdates=none and returns the new etag', async () => {
    const res = await service.updateEvent(writer(), upd());
    expect(res).toMatchObject({ status: 'updated', event: { eventId: 'evt0timed002', summary: 'Moved' } });
    expect(res.event!.etag).not.toBe('"2"');
    const req = google.calls.find(isPatch)!;
    expect(req.url.pathname).toBe('/calendar/v3/calendars/primary/events/evt0timed002');
    expect(req.headers['if-match']).toBe('"2"');
    expect(req.url.searchParams.get('sendUpdates')).toBe('none');
    // The sample event has Google's defaults (no visibility = "default", inherited reminders): the same PATCH makes it private and silent.
    expect(JSON.parse(req.body!)).toEqual({ summary: 'Moved', visibility: 'private', reminders: { useDefault: false, overrides: [] } });
    expect(res.event).toMatchObject({ visibility: 'private', reminders: { useDefault: false, overrides: [] } });
  });

  it('turns an existing guest-less event with default visibility and email reminders private and popup-only in the same PATCH', async () => {
    const ev = events().find((e) => e.id === 'evt0timed002')!;
    Object.assign(ev, { visibility: 'default', reminders: { useDefault: false, overrides: [{ method: 'email', minutes: 60 }, { method: 'popup', minutes: 10 }] } });
    const res = await service.updateEvent(writer(), upd({ description: 'secret' }));
    expect(res.status).toBe('updated');
    expect(google.calls.filter(isPatch)).toHaveLength(1);
    expect(JSON.parse(google.calls.find(isPatch)!.body!)).toEqual({
      summary: 'Moved',
      description: 'secret',
      visibility: 'private',
      reminders: { useDefault: false, overrides: [{ method: 'popup', minutes: 10 }] },
    });
    expect(ev).toMatchObject({ visibility: 'private', reminders: { useDefault: false, overrides: [{ method: 'popup', minutes: 10 }] } });
  });

  it('sends only the change for an already private, popup-only event', async () => {
    Object.assign(events().find((e) => e.id === 'evt0timed002')!, { visibility: 'private', reminders: { useDefault: false, overrides: [{ method: 'popup', minutes: 10 }] } });
    await service.updateEvent(writer(), upd());
    expect(JSON.parse(google.calls.find(isPatch)!.body!)).toEqual({ summary: 'Moved' });
  });

  it('refuses an existing event without organizer (fail closed), without writing', async () => {
    delete (events().find((e) => e.id === 'evt0timed002') as { organizer?: unknown }).organizer;
    const r = await rejection(service.updateEvent(writer(), upd()));
    expect(r.message).toMatch(/organizer/i);
    expect(google.calls.filter(isPatch)).toEqual([]);
  });

  it('reports precondition_failed for a stale etag without writing, and for a race at PATCH time', async () => {
    const stale = await service.updateEvent(writer(), upd({ etag: '"1"' }));
    expect(stale).toMatchObject({ status: 'precondition_failed', currentEtag: '"2"' });
    expect(google.calls.filter(isPatch)).toEqual([]);
    google.faults.push({ match: isPatch, mode: 'status', status: 412, body: { error: { code: 412, errors: [{ reason: 'conditionNotMet' }] } } });
    const raced = await service.updateEvent(writer(), upd());
    expect(raced.status).toBe('precondition_failed');
    expect(google.calls.filter(isPatch)).toHaveLength(1);
  });

  it('refuses events organised by others and single occurrences, without writing', async () => {
    Object.assign(events().find((e) => e.id === 'evt0timed002')!, { organizer: { email: 'boss@example.test' } });
    expect((await rejection(service.updateEvent(writer(), upd()))).message).toMatch(/organized by someone else/i);
    expect((await rejection(service.updateEvent(writer(), upd({ eventId: 'evt0timed002_20261006T070000Z' })))).message).toMatch(/single occurrences .*not supported/i);
    events().push({ id: 'evt0inst0004', etag: '"4"', status: 'confirmed', recurringEventId: 'evt0series05', organizer: { email: 'dummy.a@example.test', self: true }, start: { date: '2026-10-08' }, end: { date: '2026-10-09' } });
    expect((await rejection(service.updateEvent(writer(), upd({ eventId: 'evt0inst0004', etag: '"4"' })))).message).toMatch(/single occurrences .*not supported/i);
    expect(google.calls.filter(isPatch)).toEqual([]);
  });

  it('reports indeterminate on a lost PATCH response and never retries', async () => {
    google.faults.push({ match: isPatch, mode: 'network', commitFirst: true });
    const r = await service.updateEvent(writer(), upd());
    expect(r.status).toBe('indeterminate');
    expect(r.detail).toMatch(/calendar_get_event/);
    expect(google.calls.filter(isPatch)).toHaveLength(1);
  });

  it('needs calendar_read as well (the update returns the event) and validates time changes against the event', async () => {
    expect((await rejection(service.updateEvent(client(['calendar_write']), upd()))).message).toMatch(/calendar_read.*not granted/i);
    expect(google.calls).toEqual([]);
    expect((await rejection(service.updateEvent(writer(), upd({ start: { dateTime: '2026-10-06T11:00:00+02:00' } })))).message).toMatch(/end.*after/i);
    expect(google.calls.filter(isPatch)).toEqual([]);
  });
});
