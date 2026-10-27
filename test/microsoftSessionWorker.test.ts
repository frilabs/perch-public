import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDeviceGrant } from '../src/auth/grants.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { MicrosoftSessionGroupSchema } from '../src/microsoft/session/model.js';
import { findSessionBrowser, launchSessionBrowser, openSessionProfile, sessionProfileId, type BrowserEvent, type SessionProtocol } from '../src/microsoft/sessionBrowser.js';
import { runSessionJob } from '../src/microsoft/session/worker.js';
import { makeTempDirs } from './support/fixtures.js';

vi.mock('../src/microsoft/sessionBrowser.js', async (importOriginal) => ({
  ...await importOriginal<typeof import('../src/microsoft/sessionBrowser.js')>(),
  findSessionBrowser: vi.fn(), launchSessionBrowser: vi.fn(), openSessionProfile: vi.fn(),
}));
const cleanupDirs: Array<() => Promise<void>> = [];
beforeEach(() => { vi.clearAllMocks(); });
afterEach(async () => { for (const cleanup of cleanupDirs.splice(0)) await cleanup(); });
const identity = { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', mailboxId: 'mailbox-1', kind: 'organization' as const };
const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const bearer = `${encode({ alg: 'RS256' })}.${encode({ tid: identity.tenantId, oid: identity.objectId, exp: Math.floor(Date.now() / 1000) + 3600, aud: 'https://outlook.office.com' })}.dummySignature`;
interface Request { url: string; method: string; body?: unknown }
async function fixture(options: { mailboxId?: string; beforeResponse?: (request: Request, number: number, store: CredentialStore) => Promise<void>; response?: (request: Request, number: number) => { status?: number; body: unknown } } = {}) {
  const dirs = await makeTempDirs(); cleanupDirs.push(dirs.cleanup); await initStore(dirs); const store = await CredentialStore.open(dirs);
  const group = MicrosoftSessionGroupSchema.parse({
    id: 'mgroup-12345678', label: 'Worker Test', email: 'dummy@example.test', profileId: sessionProfileId('Worker Test'), identity,
    members: { mail: 'msmail-12345678', teams: 'msteams-12345678', calendar: 'mscalendar-12345678', files: 'msfiles-12345678' },
    services: Object.fromEntries(['mail', 'teams', 'calendar', 'files'].map((service) => [service, { enabled: true, write: true, invite: false, status: 'ready' }])),
    sites: [], createdAt: '2026-10-26T00:00:00.000Z', updatedAt: '2026-10-26T00:00:00.000Z', revision: '12345678',
  });
  await store.update((data) => { data.microsoftSessions = [group]; });
  const grant = await createDeviceGrant(store, { label: 'Worker test client', capabilities: ['read', 'modify'], accountIds: [group.members.mail] });
  const trace: string[] = [], requests: Request[] = []; const observers=new Set<(event:BrowserEvent)=>void>();const observer=(event:BrowserEvent)=>{for(const fn of observers)fn(event);};
  const protocol: SessionProtocol = {
    onEvent(listener) { const first=observers.size===0;observers.add(listener); return () => { if(first)trace.push('transport.close'); observers.delete(listener); }; },
    async call(method, params, sessionId) {
      if (method === 'Target.createTarget') { observer({ method: 'Target.attachedToTarget', params: { sessionId: 'page1', targetInfo: { targetId: 'target1', type: 'page' }, waitingForDebugger: true } }); return { targetId: 'target1' }; }
      if (method === 'Target.attachToTarget') return { sessionId: 'page1' };
      if (method === 'Page.navigate') observer({ method: 'Network.requestWillBeSent', sessionId, params: { requestId: 'auth', request: { url: 'https://outlook.office.com/owa/service.svc', headers: { Authorization: `Bearer ${bearer}` } } } });
      if (method === 'Runtime.evaluate') {
        if (String(params?.expression).includes('PerchDisabledChannel')) return { result: { value: true } };
        const request = JSON.parse(String(params?.expression).match(/\}\)\((\{[\s\S]*\})\)$/)![1]!) as Request;
        const guardedUrl=new URL(request.url);guardedUrl.searchParams.delete('__perch_request');request.url=guardedUrl.href;
        requests.push(request);
        await options.beforeResponse?.(request, requests.length, store);
        const response = options.response?.(request, requests.length) ?? { body: new URL(request.url).pathname === '/api/v2.0/me' ? { Id: options.mailboxId ?? 'mailbox-1', EmailAddress: 'dummy@example.test' } : request.method === 'PATCH' ? {} : { IsRead: true } };
        return { result: { value: { status: response.status ?? 200, headers: {}, body: Buffer.from(JSON.stringify(response.body)).toString('base64') } } };
      }
      return {};
    },
  };
  const release = vi.fn(async () => { trace.push('profile.release'); });
  const close = vi.fn(async () => { trace.push('browser.close'); });
  vi.mocked(findSessionBrowser).mockResolvedValue('/DUMMY/chromium');
  vi.mocked(openSessionProfile).mockResolvedValue({ path: '/DUMMY/profile', id: group.profileId, release });
  vi.mocked(launchSessionBrowser).mockResolvedValue({ protocol, mainSessionId: 'main', close, snapshot: async () => ({ image: '', host: 'outlook.office.com' }), action: async () => {} });
  const job = (operation = 'mail.mark', args: unknown = { messageId: 'message1', read: true }) => ({ kind: 'execute', paths: dirs, accountId: group.members.mail, operation, args, revision: group.revision, allowInvites: false, caller: operation === 'mail.profile' ? { kind: 'operator_readonly' } : { kind: 'client', clientId: grant.id, tokenSha256: grant.tokenSha256 } });
  return { dirs, store, group, grant, trace, requests, release, close, job };
}

describe('real Microsoft worker orchestration with fake browser protocol', () => {
  it('runs the actual mailbox adapter and closes transport, browser, then profile exactly once', async () => {
    const f = await fixture();
    const signals = ['SIGTERM', 'SIGINT', 'disconnect'] as const;
    const listeners = signals.map((signal) => process.listenerCount(signal));
    expect(await runSessionJob(f.job())).toEqual({ messageId: 'message1' });
    expect(f.requests.filter((r) => r.method === 'PATCH')).toEqual([expect.objectContaining({ url: 'https://outlook.office.com/api/v2.0/me/messages/message1', body: { IsRead: true } })]);
    expect(f.trace).toEqual(['transport.close', 'browser.close', 'profile.release']);
    expect(f.close).toHaveBeenCalledTimes(1); expect(f.release).toHaveBeenCalledTimes(1);
    expect(signals.map((signal) => process.listenerCount(signal))).toEqual(listeners);
  });
  it.each(['removed', 'revised', 'disabled', 'grant-revoked'] as const)('rechecks %s state after browser identity preflight and never writes', async (change) => {
    const f = await fixture({ beforeResponse: async (_request, count, store) => {
      if (count !== 1) return;
      await store.update((data) => {
        if (change === 'removed') data.microsoftSessions = [];
        if (change === 'revised') data.microsoftSessions![0]!.revision = '87654321';
        if (change === 'disabled') data.microsoftSessions![0]!.services.mail.enabled = false;
        if (change === 'grant-revoked') data.clients = [];
      });
    } });
    await expect(runSessionJob(f.job())).rejects.toThrow();
    expect(f.requests).toHaveLength(1);
    expect(f.requests.every((r) => r.method === 'GET')).toBe(true);
    expect(f.trace).toEqual(['transport.close', 'browser.close', 'profile.release']);
  });
  it('rechecks the client again after the final transport identity probe', async () => {
    const f = await fixture({ beforeResponse: async (_request, count, store) => {
      if (count === 2) await store.update((data) => { data.clients = []; });
    } });
    await expect(runSessionJob(f.job())).rejects.toMatchObject({ code: 'grant_revoked' });
    expect(f.requests).toHaveLength(2);
    expect(f.requests.every((request) => request.method === 'GET')).toBe(true);
    expect(f.trace).toEqual(['transport.close', 'browser.close', 'profile.release']);
  });
  it('stops an invitation if its grant is revoked during the final identity probe', async () => {
    const f = await fixture({ beforeResponse: async (_request, count, store) => {
      if (count === 2) await store.update((data) => { for (const grant of data.clients) grant.capabilities = grant.capabilities.filter((cap) => cap !== 'microsoft_calendar_invite'); });
    } });
    await f.store.update((data) => { data.microsoftSessions![0]!.services.calendar.invite = true; });
    const grant = await createDeviceGrant(f.store, { label: 'Calendar test client', capabilities: ['microsoft_calendar_write', 'microsoft_calendar_invite'], accountIds: [f.group.members.calendar] });
    const job = { ...f.job(), accountId: f.group.members.calendar, operation: 'calendar.createEvent', allowInvites: true, caller: { kind: 'client', clientId: grant.id, tokenSha256: grant.tokenSha256 }, args: { subject: 'Test meeting', start: { dateTime: '2026-10-28T10:00:00', timeZone: 'UTC' }, end: { dateTime: '2026-10-28T11:00:00', timeZone: 'UTC' }, attendees: [{ email: 'dummy@example.test' }] } };
    await expect(runSessionJob(job)).rejects.toMatchObject({ code: 'capability_denied' });
    expect(f.requests).toHaveLength(2);
    expect(f.requests.every((request) => request.method === 'GET')).toBe(true);
    expect((await f.store.read()).clients.find((client) => client.id === grant.id)?.capabilities).toContain('microsoft_calendar_write');
    expect(f.trace).toEqual(['transport.close', 'browser.close', 'profile.release']);
  });
  it('rejects writes lacking a serialized caller before opening the browser', async () => {
    const f = await fixture(); const { caller: _caller, ...job } = f.job();
    await expect(runSessionJob(job)).rejects.toThrow();
    expect(launchSessionBrowser).not.toHaveBeenCalled(); expect(openSessionProfile).not.toHaveBeenCalled();
  });
  it('rejects a changed immutable mailbox before dispatching the requested operation', async () => {
    const f = await fixture({ mailboxId: 'other-mailbox' });
    await expect(runSessionJob(f.job())).rejects.toMatchObject({ code: 'identity_mismatch' });
    expect(f.requests).toHaveLength(1); expect(f.requests[0]!.url).toBe('https://outlook.office.com/api/v2.0/me');
    expect(f.trace).toEqual(['transport.close', 'browser.close', 'profile.release']);
  });
  it.each(['browser.fetch', 'files.probeSite', 'toString'])('rejects invalid/internal operation %s before opening a browser', async (operation) => {
    const f = await fixture();
    await expect(runSessionJob(f.job(operation, {}))).rejects.toMatchObject({ code: 'bad_argument' });
    expect(findSessionBrowser).not.toHaveBeenCalled(); expect(openSessionProfile).not.toHaveBeenCalled(); expect(launchSessionBrowser).not.toHaveBeenCalled();
  });
  it('allows a read-only caller to read a mailbox profile but never to write', async () => {
    const f = await fixture();
    expect(await runSessionJob(f.job('mail.profile', {}))).toMatchObject({ id: 'mailbox-1' });
    const before = f.requests.length;
    await expect(runSessionJob({ ...f.job(), caller: { kind: 'operator_readonly' } })).rejects.toThrow();
    expect(f.requests).toHaveLength(before);
  });
  it('cleans up once when the requested upstream operation fails after identity probes', async () => {
    const f = await fixture({ response: (request) => request.method === 'PATCH' ? { status: 403, body: { error: { message: 'DUMMY-PRIVATE-UPSTREAM' } } } : { body: { Id: 'mailbox-1' } } });
    await expect(runSessionJob(f.job())).rejects.toMatchObject({ code: 'access_denied' });
    expect(f.requests.filter((r) => r.method === 'PATCH')).toHaveLength(1);
    expect(f.trace).toEqual(['transport.close', 'browser.close', 'profile.release']);
    expect(f.release).toHaveBeenCalledTimes(1);
  });
  it('releases the profile exactly once when browser launch rejects', async () => {
    const f = await fixture(); vi.mocked(launchSessionBrowser).mockRejectedValueOnce(new Error('DUMMY launch failure'));
    await expect(runSessionJob(f.job())).rejects.toThrow('DUMMY launch failure');
    expect(f.trace).toEqual(['profile.release']); expect(f.release).toHaveBeenCalledTimes(1); expect(f.close).not.toHaveBeenCalled();
  });
});
