import { beforeEach, expect, it, vi } from 'vitest';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { makeTempDirs } from './support/fixtures.js';
import { runSessionJob } from '../src/microsoft/session/worker.js';
const fixture = vi.hoisted(() => ({
  identity: { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', kind: 'organization' },
  hosts: [] as string[], requests: [] as any[], denied: false, mailFailed: false, csaFailed: false,
}));
beforeEach(() => { fixture.hosts = []; fixture.requests = []; fixture.denied = false; fixture.mailFailed = false; fixture.csaFailed = false; });
vi.mock('../src/microsoft/sessionBrowser.js', async original => ({ ...await original<any>(),
  findSessionBrowser: async () => '/mock/chrome',
  openSessionProfile: async () => ({ path: '/mock/profile', release: async () => {} }),
  launchSessionBrowser: async () => ({ protocol: {}, close: async () => {}, allowDiscoveredSite: (url: string) => { fixture.hosts.push(url); } }),
}));
vi.mock('../src/microsoft/session/browserTransport.js', () => ({ BrowserSessionTransport: class {
  identity: typeof fixture.identity | undefined;
  metadata = { email: 'self@example.test' };
  open = async () => {};
  close() {}
  async request(r: any) {
    fixture.requests.push(r);
    if ((r.resource === 'outlook' && fixture.mailFailed) || (r.resource === 'csa' && fixture.csaFailed)) return { status: 401, headers: {}, body: Buffer.from('{}') };
    if (['outlook', 'csa', 'graph'].includes(r.resource)) this.identity = fixture.identity;
    let body: any = { value: [] };
    if (r.resource === 'chat') body = { conversations: [] };
    if (r.path === '/api/v2.0/me') body = { Id: 'mailbox', EmailAddress: 'self@example.test' };
    if (r.path === '/v1.0/me') body = { id: fixture.identity.objectId, mail: 'self@example.test' };
    if (r.path === '/v1.0/me/drives') body = { value: [{ sharepointIds: { siteUrl: 'https://tenant-my.sharepoint.com/personal/self_example_test' } }] };
    if (r.path === '/v1.0/me/followedSites') body = { value: [{ webUrl: 'https://tenant.sharepoint.com/sites/Team' }] };
    if (r.path === '/_api/web/currentuser') body = { AadObjectId: { NameId: fixture.identity.objectId } };
    if (r.path === '/_api/v2.0/drives') body = { value: [{ id: 'drive-1', name: 'Documents' }] };
    const status = fixture.denied && r.resource === 'graph' && r.path !== '/v1.0/me' ? 403 : 200;
    return { status, headers: {}, body: Buffer.from(JSON.stringify(body)) };
  }
} }));

it('discovers and verifies file sites after a single login using exact temporary egress hosts', async () => {
  const dirs = await makeTempDirs();
  try {
    await initStore(dirs); fixture.hosts = []; fixture.requests = []; fixture.denied = false;
    const result: any = await runSessionJob({ kind: 'probe', paths: dirs, label: 'Test', sites: [], discover: true });
    expect(result.sites).toHaveLength(2);
    expect(result.libraries).toHaveLength(2);
    expect(result.services.files).toMatchObject({ enabled: true, status: 'ready' });
    expect(fixture.hosts).toEqual(result.sites.map((s: any) => s.url));
    expect(fixture.requests.findIndex(r => r.path === '/v1.0/me')).toBeLessThan(fixture.requests.findIndex(r => r.path === '/v1.0/me/drives'));
    expect((await (await CredentialStore.open(dirs)).read()).microsoftSessions ?? []).toEqual([]); // confirmation belongs to CLI
  } finally { await dirs.cleanup(); }
});
it('keeps working services when session discovery is denied and reports incomplete files', async () => {
  const dirs = await makeTempDirs();
  try {
    await initStore(dirs); fixture.hosts = []; fixture.requests = []; fixture.denied = true;
    const result: any = await runSessionJob({ kind: 'probe', paths: dirs, label: 'Test', sites: [], discover: true });
    expect(result.services.mail.status).toBe('ready');
    expect(result.sites).toEqual([]);
    expect(result.discovery.every((s: any) => s.status === 'unavailable')).toBe(true);
    expect(fixture.hosts).toEqual([]);
  } finally { await dirs.cleanup(); }
});

it('skips unavailable optional CSA identity bootstrap after this transport verifies mail', async () => {
  const dirs = await makeTempDirs();
  try {
    await initStore(dirs); fixture.csaFailed = true;
    const result: any = await runSessionJob({ kind: 'probe', paths: dirs, label: 'Test', sites: [] });
    expect(result.services.mail.status).toBe('ready');
    expect(result.services.teams.status).toBe('ready');
    expect(fixture.requests.filter(r => r.resource === 'csa')).toEqual([]);
    expect(fixture.requests.some(r => r.resource === 'chat')).toBe(true);
  } finally { await dirs.cleanup(); }
});

it.each([false, true])('keeps CSA identity bootstrap when mail fails, including saved identity=%s', async saved => {
  const dirs = await makeTempDirs();
  try {
    await initStore(dirs); fixture.mailFailed = true;
    const result: any = await runSessionJob({ kind: 'probe', paths: dirs, label: 'Test', sites: [], ...(saved ? { expected: fixture.identity } : {}) });
    expect(result.services.mail.status).toBe('reauth_required');
    expect(result.services.teams.status).toBe('ready');
    const csaIndex = fixture.requests.findIndex(r => r.resource === 'csa');
    const chatIndex = fixture.requests.findIndex(r => r.resource === 'chat');
    expect(csaIndex).toBeGreaterThan(-1);
    expect(chatIndex).toBeGreaterThan(csaIndex);
  } finally { await dirs.cleanup(); }
});

it('never attempts Skype-only chat for a new account when mail and CSA identity probes fail', async () => {
  const dirs = await makeTempDirs();
  try {
    await initStore(dirs); fixture.mailFailed = true; fixture.csaFailed = true;
    const result: any = await runSessionJob({ kind: 'probe', paths: dirs, label: 'Test', sites: [] });
    expect(result.services.teams.status).toBe('unavailable');
    expect(fixture.requests.filter(r => r.resource === 'csa')).toHaveLength(1);
    expect(fixture.requests.some(r => r.resource === 'chat')).toBe(false);
  } finally { await dirs.cleanup(); }
});
