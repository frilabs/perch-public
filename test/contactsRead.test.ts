// Contacts read operations (people.connections.list, people.get) with bounded personFields, multi-account
// provenance and authorization before I/O. MOCK Google upstream only.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { principalFromGrant, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { ContactsService, DEFAULT_PERSON_FIELDS } from '../src/google/contacts.js';
import { createProductivityTokenProvider } from '../src/google/productivity.js';
import { CredentialStore, initStore, type Capability } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGoogleProductivity, type MockPerson } from './support/mockProductivity.js';
import { addDummyProductivity } from './support/productivityFixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
let google: MockGoogleProductivity;
let service: ContactsService;

const client = (capabilities: Capability[], accountIds: string[]): Principal =>
  principalFromGrant({ id: 'client-0000000a', label: 'T', tokenSha256: '0'.repeat(64), capabilities, accountIds, createdAt: '' });

const person = (n: number): MockPerson => ({
  resourceName: `people/c${1000 + n}`,
  etag: `%E${n}`,
  names: [{ displayName: `Dummy Person ${n}` }],
  emailAddresses: [{ value: `person${n}@example.test` }],
  phoneNumbers: [{ value: `+43 1 000 ${n}` }],
  biographies: [{ value: 'Dummy notes' }],
});

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  google = new MockGoogleProductivity();
  const a = google.addAccount('dummy.a@example.test', { contacts: [person(1), person(2), person(3)] });
  const b = google.addAccount('dummy.b@example.test', { contacts: [person(9)] });
  await addDummyProductivity(store, 'gprod-0000000a', { refreshToken: a.refreshToken, email: a.email });
  await addDummyProductivity(store, 'gprod-0000000b', { refreshToken: b.refreshToken, email: b.email });
  const upstream = new Upstream(google.transport);
  service = new ContactsService(store, upstream, createProductivityTokenProvider(store, upstream));
});
afterEach(async () => {
  await dirs.cleanup();
});

const peopleCalls = () => google.calls.filter((c) => c.url.origin === 'https://people.googleapis.com');

describe('contacts_list [MOCK Google]', () => {
  it('pages through all contacts of all accounts with explicit bounded personFields and provenance', async () => {
    const seen: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await service.list(READONLY_PRINCIPAL, { ...(cursor ? { cursor } : {}) });
      for (const p of page.results) seen.push(`${p.accountId}:${p.resourceName}`);
      expect(page.partial).toBe(false);
      cursor = page.nextCursor ?? undefined;
    } while (cursor);
    expect(seen.sort()).toEqual(['gprod-0000000a:people/c1001', 'gprod-0000000a:people/c1002', 'gprod-0000000a:people/c1003', 'gprod-0000000b:people/c1009']);
    const req = peopleCalls()[0]!;
    expect(req.url.pathname).toBe('/v1/people/me/connections');
    expect(req.url.searchParams.get('personFields')).toBe(DEFAULT_PERSON_FIELDS.join(','));
    expect(req.url.searchParams.get('sources')).toBe('READ_SOURCE_TYPE_CONTACT');
  });

  it('returns only the requested allowlisted fields', async () => {
    const page = await service.list(READONLY_PRINCIPAL, { accountId: 'gprod-0000000b', personFields: ['names', 'biographies'] });
    expect(page.results[0]).toEqual({
      accountId: 'gprod-0000000b',
      accountLabel: 'Productivity gprod-0000000b',
      email: 'dummy.b@example.test',
      provider: 'google',
      resourceName: 'people/c1009',
      etag: '%E9',
      names: [{ displayName: 'Dummy Person 9' }],
      biographies: [{ value: 'Dummy notes' }],
    });
    expect(peopleCalls()[0]!.url.searchParams.get('personFields')).toBe('names,biographies');
  });

  it('rejects unknown/unbounded personFields, bad sort orders and page sizes before I/O', async () => {
    for (const args of [{ personFields: ['names', 'coverPhotos'] }, { personFields: [] }, { sortOrder: 'RANDOM' }, { pageSize: 0 }, { pageSize: 101 }]) {
      await expect(service.list(READONLY_PRINCIPAL, args as never), JSON.stringify(args)).rejects.toThrow(/personFields|sortOrder|pageSize/);
    }
    expect(google.calls).toEqual([]);
  });
});

describe('contacts_get [MOCK Google]', () => {
  it('reads one contact by contact resource name only', async () => {
    const p = await service.get(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', resourceName: 'people/c1002' });
    expect(p).toMatchObject({ accountId: 'gprod-0000000a', resourceName: 'people/c1002', names: [{ displayName: 'Dummy Person 2' }] });
    expect(peopleCalls()[0]!.url.pathname).toBe('/v1/people/c1002');
    const before = google.calls.length;
    for (const resourceName of ['people/me', 'people/1234567890', 'people/c12/../me', 'contactGroups/all', 'people/c']) {
      expect((await rejection(service.get(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', resourceName }))).message, resourceName).toMatch(/resourceName/i);
    }
    expect(google.calls.length).toBe(before);
    expect((await rejection(service.get(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', resourceName: 'people/c1009' }))).message).toMatch(/404/);
  });
});

describe('contacts authorization (before any I/O)', () => {
  it('needs contacts_read on the account and a contacts-connected account', async () => {
    const calOnly = client(['calendar_read'], ['gprod-0000000a']);
    expect((await rejection(service.get(calOnly, { accountId: 'gprod-0000000a', resourceName: 'people/c1001' }))).message).toMatch(/not granted/i);
    expect((await service.list(calOnly, {})).results).toEqual([]);
    const bOnly = client(['contacts_read'], ['gprod-0000000b']);
    expect((await rejection(service.get(bOnly, { accountId: 'gprod-0000000a', resourceName: 'people/c1001' }))).message).toMatch(/not granted/i);
    expect(google.calls).toEqual([]);
    await store.update((d) => {
      d.googleProductivity.find((x) => x.id === 'gprod-0000000a')!.services = ['calendar'];
    });
    expect((await rejection(service.get(READONLY_PRINCIPAL, { accountId: 'gprod-0000000a', resourceName: 'people/c1001' }))).message).toMatch(
      /not connected for contacts/i,
    );
    const page = await service.list(READONLY_PRINCIPAL, {});
    expect(new Set(page.results.map((p) => p.accountId))).toEqual(new Set(['gprod-0000000b']));
  });
});
