// Fixed origins and path allowlist for Google Calendar, People (Contacts) and the OpenID Connect
// userinfo endpoint. MOCK transport only: nothing leaves the process.
import { describe, expect, it } from 'vitest';
import { Upstream, type UpstreamRequest } from '../src/upstream.js';
import { rejection } from './support/fixtures.js';

function recorder(status = 200, body: unknown = {}) {
  const calls: UpstreamRequest[] = [];
  const upstream = new Upstream(async (req) => {
    calls.push(req);
    return { status, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(body)) };
  });
  return { calls, upstream };
}

const CAL = '/calendar/v3/calendars/dummy%40example.test/events';

describe('Calendar / People / userinfo allowlist [MOCK transport]', () => {
  it('uses fixed origins', async () => {
    const { calls, upstream } = recorder();
    await upstream.json('calendar', { method: 'GET', path: '/calendar/v3/users/me/calendarList' });
    await upstream.json('people', { method: 'GET', path: '/v1/people/me/connections' });
    await upstream.json('openid', { method: 'GET', path: '/v1/userinfo' });
    expect(calls.map((c) => c.url.origin)).toEqual([
      'https://www.googleapis.com',
      'https://people.googleapis.com',
      'https://openidconnect.googleapis.com',
    ]);
  });

  it('allows the read routes with strictly shaped ids', async () => {
    const { calls, upstream } = recorder();
    await upstream.json('calendar', { method: 'GET', path: CAL });
    await upstream.json('calendar', { method: 'GET', path: '/calendar/v3/calendars/primary/events/abc123_20261005T090000Z' });
    await upstream.json('calendar', { method: 'GET', path: '/calendar/v3/calendars/team%2Bx%40group.calendar.google.com/events' });
    await upstream.json('people', { method: 'GET', path: '/v1/people/c1234567890' });
    expect(calls).toHaveLength(4);
  });

  it('reaches create (POST) and update (PATCH) only with the calendar_write tag, passing If-Match through', async () => {
    const { calls, upstream } = recorder();
    const create = { method: 'POST' as const, path: CAL, json: { summary: 'x' } };
    expect((await rejection(upstream.json('calendar', create))).message).toMatch(/non-allowlisted/i);
    expect((await rejection(upstream.json('calendar', { ...create, capability: 'send' }))).message).toMatch(/non-allowlisted/i);
    await upstream.json('calendar', { ...create, capability: 'calendar_write' });
    const patch = { method: 'PATCH' as const, path: `${CAL}/abc123`, json: { summary: 'y' }, headers: { 'if-match': '"3181161784712000"' } };
    expect((await rejection(upstream.json('calendar', patch))).message).toMatch(/non-allowlisted/i);
    await upstream.json('calendar', { ...patch, capability: 'calendar_write' });
    expect(calls.map((c) => c.method)).toEqual(['POST', 'PATCH']);
    expect(calls[1]!.headers['if-match']).toBe('"3181161784712000"');
    expect(calls[1]!.body).toBe(JSON.stringify({ summary: 'y' }));
    // Read routes cannot be "upgraded" with a write tag.
    expect((await rejection(upstream.json('calendar', { method: 'GET', path: CAL, capability: 'calendar_write' }))).message).toMatch(/non-allowlisted/i);
  });

  it('blocks ACLs, moves, imports, other users, deletes, profile lookups and encoded traversal before any I/O', async () => {
    const { calls, upstream } = recorder();
    const blocked: Array<[import('../src/upstream.js').Service, string, string]> = [
      ['calendar', 'GET', '/calendar/v3/calendars/primary/acl'],
      ['calendar', 'GET', '/calendar/v3/users/victim%40example.test/calendarList'],
      ['calendar', 'GET', '/calendar/v3/calendars/a%2Fb/events'],
      ['calendar', 'GET', '/calendar/v3/calendars/a%2e%2e/events'],
      ['calendar', 'GET', '/calendar/v3/calendars/primary/events/abc/instances'],
      ['calendar', 'GET', '/drive/v3/files'],
      ['drive', 'GET', '/calendar/v3/users/me/calendarList'],
      ['people', 'GET', '/v1/people/me'],
      ['people', 'GET', '/v1/people/1234567890'],
      ['people', 'GET', '/v1/people:searchContacts'],
      ['openid', 'GET', '/v1/userinfo/../x'],
    ];
    for (const [service, method, path] of blocked) {
      expect((await rejection(upstream.json(service, { method: method as 'GET', path }))).message, path).toMatch(/non-allowlisted/i);
    }
    for (const [path, capability] of [
      [`${CAL}/abc/move`, 'calendar_write'],
      ['/calendar/v3/calendars/primary/events/import', 'calendar_write'],
      ['/calendar/v3/calendars/primary/events/quickAdd', 'calendar_write'],
    ] as const) {
      expect((await rejection(upstream.json('calendar', { method: 'POST', path, capability }))).message, path).toMatch(/non-allowlisted/i);
    }
    // DELETE exists only for one event or a whole series (calendarInvite.test.ts); never for calendars, untagged or as PUT.
    for (const [method, path, capability] of [
      ['DELETE', '/calendar/v3/calendars/dummy%40example.test', 'calendar_write'],
      ['DELETE', `${CAL}/abcde12345`, 'read'],
      ['PUT', `${CAL}/abcde12345`, 'calendar_write'],
    ] as const) {
      expect((await rejection(upstream.json('calendar', { method: method as 'GET', path, capability }))).message, `${method} ${path}`).toMatch(/non-allowlisted/i);
    }
    expect(calls).toHaveLength(0);
  });

  it('extracts the sanitised Calendar error reason (duplicate, conditionNotMet)', async () => {
    const { upstream } = recorder(409, { error: { code: 409, errors: [{ reason: 'duplicate', message: 'secret' }], message: 'secret' } });
    const err = await rejection(upstream.json('calendar', { method: 'POST', path: CAL, json: {}, capability: 'calendar_write' }));
    expect(err.message).toContain('duplicate');
    expect(err.message).not.toContain('secret');
  });
});
