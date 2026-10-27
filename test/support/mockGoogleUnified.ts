/**
 * MOCK Google upstream for the unified Google login (docs/GOOGLE_UNIFIED_SPEC.md), for tests only: ONE OAuth
 * token endpoint and OpenID userinfo in front of the existing Drive (MockGoogle), Gmail (MockGmail) and
 * Calendar/People (MockGoogleProductivity) fakes. An access token issued here is valid at all three, like a real
 * Google access token covering several APIs. Granular consent is simulated with `untick` (scopes the "user"
 * deselects on the consent screen). In-memory fake of the documented HTTP API shapes; nothing here talks to
 * Google, and passing tests that use it are NOT evidence of a live integration.
 */
import { createHash } from 'node:crypto';
import type { UpstreamRequest, UpstreamResponse, UpstreamTransport } from '../../src/upstream.js';
import { dummySecret } from './fixtures.js';
import { MockGoogle, type MockGoogleAccount } from './mockGoogle.js';
import { MockGmail, type MockGmailAccount } from './mockGmail.js';
import { MockGoogleProductivity, SCOPE, type MockProdAccount } from './mockProductivity.js';

export interface MockGooglePerson {
  email: string;
  sub: string;
  /** The refresh token of the person's current grant (shared by every service). */
  refreshToken: string;
  drive: MockGoogleAccount;
  gmail: MockGmailAccount;
  prod: MockProdAccount;
}

const json = (status: number, body: unknown): UpstreamResponse => ({
  status,
  headers: { 'content-type': 'application/json' },
  body: Buffer.from(JSON.stringify(body)),
});

export class MockGoogleUnified {
  readonly drive = new MockGoogle();
  readonly gmail = new MockGmail();
  readonly prod = new MockGoogleProductivity();
  readonly people: MockGooglePerson[] = [];
  readonly calls: UpstreamRequest[] = [];
  readonly revoked: string[] = [];
  /** authorization_code and refresh_token requests that reached the token endpoint. */
  tokenRequests: Array<'authorization_code' | 'refresh_token'> = [];
  /** Scopes the consent screen "user" deselects in the next approvals (granular consent). */
  untick: string[] = [];
  /** Scopes granted earlier to the same OAuth client (reported back with include_granted_scopes=true). */
  readonly earlier = new Map<string, Set<string>>();
  /** Last authorization URL parameters seen by approve(). */
  lastAuthParams?: URLSearchParams;
  /** Runs while a refresh_token grant is "in flight" (concurrency tests). */
  beforeRefreshResponse?: () => Promise<void>;
  private readonly codes = new Map<string, { challenge: string; redirectUri: string; person: MockGooglePerson; scope: string }>();
  /** Scope string of each person's current grant. */
  private readonly grantScope = new Map<string, string>();

  addPerson(email: string): MockGooglePerson {
    const refreshToken = dummySecret('UNIFIED-REFRESH');
    const drive = this.drive.addAccount(email);
    const gmail = this.gmail.addAccount(email);
    const prod = this.prod.addAccount(email, { refreshToken });
    drive.refreshToken = refreshToken;
    gmail.refreshToken = refreshToken;
    const person: MockGooglePerson = { email, sub: prod.sub, refreshToken, drive, gmail, prod };
    this.people.push(person);
    return person;
  }

  /** Simulates consent for `person` in the browser; returns the code for the loopback redirect. */
  approve(authUrl: string, person: MockGooglePerson): string {
    const u = new URL(authUrl);
    this.lastAuthParams = u.searchParams;
    const code = dummySecret('AUTHCODE');
    const requested = u.searchParams.get('scope')!.split(' ').map((s) => (s === 'email' ? SCOPE.email : s));
    const granted = requested.filter((s) => !this.untick.includes(s));
    const include = u.searchParams.get('include_granted_scopes') === 'true' ? [...(this.earlier.get(person.email) ?? [])] : [];
    const scope = [...new Set([...include, ...granted])].join(' ');
    this.codes.set(code, { challenge: u.searchParams.get('code_challenge')!, redirectUri: u.searchParams.get('redirect_uri')!, person, scope });
    return code;
  }

  /** Revokes the person's grant at "Google" (e.g. from myaccount.google.com). */
  revokeGrant(person: MockGooglePerson): void {
    this.setRefreshToken(person, dummySecret('REVOKED'));
  }

  private setRefreshToken(person: MockGooglePerson, rt: string) {
    person.refreshToken = rt;
    person.drive.refreshToken = rt;
    person.gmail.refreshToken = rt;
    person.prod.refreshToken = rt;
  }

  private issue(person: MockGooglePerson, scope: string): string {
    const t = dummySecret('UNIFIED-ACCESS');
    this.drive.accessTokens.set(t, person.drive);
    this.gmail.accessTokens.set(t, person.gmail);
    this.prod.accessTokens.set(t, { account: person.prod, scope });
    return t;
  }

  transport: UpstreamTransport = async (req) => {
    this.calls.push(req);
    const { origin, pathname } = req.url;
    if (origin === 'https://oauth2.googleapis.com') {
      if (pathname === '/token' && new URLSearchParams(req.body ?? '').get('grant_type') === 'refresh_token') await this.beforeRefreshResponse?.();
      return this.oauth(req, pathname);
    }
    if (origin === 'https://gmail.googleapis.com') return this.gmail.transport(req);
    if (origin === 'https://www.googleapis.com' && pathname.startsWith('/drive/')) return this.drive.transport(req);
    if (origin === 'https://www.googleapis.com' && pathname.startsWith('/upload/drive/')) return this.drive.transport(req);
    return this.prod.transport(req);
  };

  private oauth(req: UpstreamRequest, pathname: string): UpstreamResponse {
    const form = new URLSearchParams(req.body ?? '');
    if (pathname === '/revoke') {
      const token = form.get('token') ?? '';
      this.revoked.push(token);
      const person = this.people.find((p) => p.refreshToken === token);
      if (person) this.setRefreshToken(person, dummySecret('REVOKED'));
      return json(200, {});
    }
    const type = form.get('grant_type');
    if (type === 'authorization_code') {
      this.tokenRequests.push('authorization_code');
      const pending = this.codes.get(form.get('code') ?? '');
      if (!pending) return json(400, { error: 'invalid_grant' });
      this.codes.delete(form.get('code')!);
      if (createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url') !== pending.challenge) return json(400, { error: 'invalid_grant' });
      if (form.get('redirect_uri') !== pending.redirectUri) return json(400, { error: 'redirect_uri_mismatch' });
      const person = pending.person;
      // Every authorization issues a new refresh token for the (incrementally extended) grant.
      this.setRefreshToken(person, dummySecret('UNIFIED-REFRESH'));
      this.grantScope.set(person.email, pending.scope);
      this.earlier.set(person.email, new Set(pending.scope.split(' ')));
      return json(200, { access_token: this.issue(person, pending.scope), expires_in: 3599, scope: pending.scope, token_type: 'Bearer', refresh_token: person.refreshToken });
    }
    if (type === 'refresh_token') {
      this.tokenRequests.push('refresh_token');
      const person = this.people.find((p) => p.refreshToken === form.get('refresh_token'));
      if (!person) return json(400, { error: 'invalid_grant', error_description: 'Token has been expired or revoked.' });
      const scope = this.grantScope.get(person.email) ?? '';
      return json(200, { access_token: this.issue(person, scope), expires_in: 3599, scope, token_type: 'Bearer' });
    }
    return json(400, { error: 'unsupported_grant_type' });
  }
}
