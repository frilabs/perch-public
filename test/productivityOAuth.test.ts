// Separate Google productivity (Calendar/Contacts) OAuth grant: explicit scope selection, verified
// identity via the fixed OpenID Connect userinfo endpoint, encrypted storage and token refresh.
// MOCK Google upstream only (test/support/mockProductivity.ts); no live Google calls.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  CALENDAR_EVENTS_OWNED_SCOPE,
  CALENDAR_READONLY_SCOPE,
  CONTACTS_READONLY_SCOPE,
  createProductivityTokenProvider,
  parseServices,
  productivityCapabilities,
  productivityScopesFor,
  registerProductivityAccount,
  removeProductivityAccount,
  runProductivityAuthorization,
} from '../src/google/productivity.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGoogleProductivity, SCOPE, type MockProdAccount } from './support/mockProductivity.js';

let dirs: TempDirs;
let store: CredentialStore;
let google: MockGoogleProductivity;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  google = new MockGoogleProductivity();
});
afterEach(async () => {
  await dirs.cleanup();
});

const client = { clientId: `${dummySecret('CLIENT')}.apps.googleusercontent.com`, clientSecret: dummySecret('CLIENT-SECRET') };

/** Drives the real loopback flow: the "browser" approves and hits the redirect URI with code + state. */
async function authorize(acct: MockProdAccount, services: Array<'calendar' | 'contacts'>, allowCalendarWrite = false) {
  let authUrl = '';
  const flow = runProductivityAuthorization({
    client,
    upstream: new Upstream(google.transport),
    services,
    allowCalendarWrite,
    port: 0,
    timeoutMs: 5000,
    onAuthUrl: (u) => {
      authUrl = u;
      const url = new URL(u);
      const code = google.approve(u, acct);
      void fetch(`${url.searchParams.get('redirect_uri')}?code=${code}&state=${url.searchParams.get('state')}`);
    },
  });
  const grant = await flow;
  return { grant, authUrl: new URL(authUrl) };
}

describe('scope selection', () => {
  it('requests only identity + the explicitly selected read-only services', () => {
    expect(productivityScopesFor({ services: ['calendar'], allowCalendarWrite: false })).toEqual(['openid', 'email', CALENDAR_READONLY_SCOPE]);
    expect(productivityScopesFor({ services: ['contacts'], allowCalendarWrite: false })).toEqual(['openid', 'email', CONTACTS_READONLY_SCOPE]);
    expect(productivityScopesFor({ services: ['calendar', 'contacts'], allowCalendarWrite: true })).toEqual([
      'openid',
      'email',
      CALENDAR_READONLY_SCOPE,
      CONTACTS_READONLY_SCOPE,
      CALENDAR_EVENTS_OWNED_SCOPE,
    ]);
    for (const s of productivityScopesFor({ services: ['calendar', 'contacts'], allowCalendarWrite: true })) {
      expect(s).not.toMatch(/drive|gmail|auth\/calendar$|auth\/contacts$/);
    }
  });

  it('requires an explicit service selection and calendar for --allow-calendar-write', () => {
    expect(() => parseServices([])).toThrow(/at least one/i);
    expect(() => parseServices(['calendar', 'drive'])).toThrow(/unknown service/i);
    expect(parseServices(['contacts', 'calendar', 'calendar'])).toEqual(['calendar', 'contacts']);
    expect(() => productivityScopesFor({ services: ['contacts'], allowCalendarWrite: true })).toThrow(/calendar/i);
  });
});

describe('runProductivityAuthorization [MOCK Google]', () => {
  it('uses PKCE S256, offline access and a separate grant (include_granted_scopes=false)', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const { grant, authUrl } = await authorize(acct, ['calendar']);
    expect(authUrl.origin + authUrl.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(authUrl.searchParams.get('scope')).toBe(`openid email ${CALENDAR_READONLY_SCOPE}`);
    expect(authUrl.searchParams.get('include_granted_scopes')).toBe('false');
    expect(authUrl.searchParams.get('access_type')).toBe('offline');
    expect(authUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(grant.scopes).toContain(CALENDAR_READONLY_SCOPE);
    expect(grant.refreshToken).toBe(acct.refreshToken);
  });

  it('fails closed when a selected service scope, the write scope or the email scope was not granted', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    google.grantedScopeOverride = `openid ${SCOPE.email} ${SCOPE.calendarRead}`;
    expect((await rejection(authorize(acct, ['calendar', 'contacts']))).message).toMatch(/contacts\.readonly.*not granted/);
    expect((await rejection(authorize(acct, ['calendar'], true))).message).toMatch(/calendar\.events\.owned.*not granted/);
    google.grantedScopeOverride = `openid ${SCOPE.calendarRead}`;
    expect((await rejection(authorize(acct, ['calendar']))).message).toMatch(/email.*not granted/);
    google.grantedScopeOverride = undefined;
    google.omitRefreshToken = true;
    expect((await rejection(authorize(acct, ['calendar']))).message).toMatch(/refresh token/i);
  });
});

describe('registerProductivityAccount [MOCK Google]', () => {
  it('stores the account with a verified email from the fixed userinfo endpoint, without Drive or Gmail calls', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const { grant } = await authorize(acct, ['calendar', 'contacts'], true);
    const account = await registerProductivityAccount(store, new Upstream(google.transport), {
      label: 'Private',
      client,
      grant,
      services: ['calendar', 'contacts'],
      allowCalendarWrite: true,
    });
    expect(account).toMatchObject({ label: 'Private', email: 'dummy.a@example.test', sub: acct.sub, services: ['calendar', 'contacts'], allowCalendarWrite: true });
    expect(account.id).toMatch(/^gprod-[a-f0-9]{8}$/);
    expect((await store.read()).googleProductivity).toHaveLength(1);
    const origins = new Set(google.calls.map((c) => c.url.origin));
    expect([...origins].sort()).toEqual(['https://oauth2.googleapis.com', 'https://openidconnect.googleapis.com']);
    expect(google.calls.find((c) => c.url.origin === 'https://openidconnect.googleapis.com')!.url.pathname).toBe('/v1/userinfo');
    expect(productivityCapabilities(account)).toEqual({ calendarRead: true, contactsRead: true, calendarWrite: true });
  });

  it('refuses an unverified email and a second grant for the same Google account (sub)', async () => {
    const unverified = google.addAccount('dummy.u@example.test', { emailVerified: false });
    const { grant: g1 } = await authorize(unverified, ['calendar']);
    const up = new Upstream(google.transport);
    expect((await rejection(registerProductivityAccount(store, up, { label: 'U', client, grant: g1, services: ['calendar'], allowCalendarWrite: false }))).message).toMatch(
      /verified email/i,
    );
    const acct = google.addAccount('dummy.a@example.test');
    const { grant: g2 } = await authorize(acct, ['calendar']);
    await registerProductivityAccount(store, up, { label: 'A', client, grant: g2, services: ['calendar'], allowCalendarWrite: false });
    const { grant: g3 } = await authorize(acct, ['contacts']);
    expect((await rejection(registerProductivityAccount(store, up, { label: 'B', client, grant: g3, services: ['contacts'], allowCalendarWrite: false }))).message).toMatch(
      /already connected/i,
    );
    expect((await store.read()).googleProductivity).toHaveLength(1);
  });

  it('never derives provider capabilities from stored flags alone', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const { grant } = await authorize(acct, ['calendar']);
    const account = await registerProductivityAccount(store, new Upstream(google.transport), {
      label: 'A',
      client,
      grant,
      services: ['calendar'],
      allowCalendarWrite: false,
    });
    // Flag tampered on disk without the scope: still no write.
    expect(productivityCapabilities({ ...account, allowCalendarWrite: true })).toMatchObject({ calendarWrite: false, contactsRead: false });
    // Scope present but no opt-in flag: no write either.
    expect(productivityCapabilities({ ...account, scopes: [...account.scopes, CALENDAR_EVENTS_OWNED_SCOPE] })).toMatchObject({ calendarWrite: false });
    // Live refresh reports the scope as gone: no write, even with flag + stored scope.
    const both = { ...account, allowCalendarWrite: true, scopes: [...account.scopes, CALENDAR_EVENTS_OWNED_SCOPE] };
    expect(productivityCapabilities(both).calendarWrite).toBe(true);
    expect(productivityCapabilities(both, [CALENDAR_READONLY_SCOPE]).calendarWrite).toBe(false);
  });

  it('removes locally and optionally revokes at Google', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const { grant } = await authorize(acct, ['calendar']);
    const up = new Upstream(google.transport);
    const account = await registerProductivityAccount(store, up, { label: 'A', client, grant, services: ['calendar'], allowCalendarWrite: false });
    expect(await removeProductivityAccount(store, up, account.id, { revoke: true })).toEqual({ revoked: true });
    expect(google.revoked).toEqual([acct.refreshToken]);
    expect((await store.read()).googleProductivity).toEqual([]);
    expect((await rejection(removeProductivityAccount(store, up, account.id, {}))).message).toMatch(/unknown/i);
  });
});

describe('productivity token provider [MOCK Google]', () => {
  async function connected() {
    const acct = google.addAccount('dummy.a@example.test');
    const { grant } = await authorize(acct, ['calendar'], true);
    const up = new Upstream(google.transport);
    const account = await registerProductivityAccount(store, up, { label: 'A', client, grant, services: ['calendar'], allowCalendarWrite: true });
    return { acct, account, tokens: createProductivityTokenProvider(store, up) };
  }

  it('refreshes single-flight and records the scopes Google reports on refresh', async () => {
    const { account, tokens } = await connected();
    google.refreshScopeOverride = `openid ${SCOPE.email} ${SCOPE.calendarRead}`;
    const before = google.calls.length;
    const [a, b] = await Promise.all([tokens.getAccessToken(account.id), tokens.getAccessToken(account.id)]);
    expect(a).toBe(b);
    expect(google.calls.slice(before).filter((c) => c.url.pathname === '/token')).toHaveLength(1);
    expect(tokens.lastGrantedScopes(account.id)).toEqual(['openid', SCOPE.email, SCOPE.calendarRead]);
  });

  it('fails closed with a reconnect hint naming only the id when the grant was revoked', async () => {
    const { acct, account, tokens } = await connected();
    acct.refreshToken = dummySecret('ROTATED-ELSEWHERE');
    const err = await rejection(tokens.getAccessToken(account.id));
    expect(err.message).toMatch(new RegExp(`perch google-productivity remove ${account.id}`));
    expect(err.message).not.toContain('"A"');
  });
});
