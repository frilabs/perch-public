// Google OAuth flow against the MOCK Google upstream (test/support/mockGoogle.ts). No live Google calls.
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  DRIVE_READONLY_SCOPE,
  parseClientFile,
  runLoopbackAuthorization,
  type GoogleClientCredentials,
} from '../src/google/oauth.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret } from './support/fixtures.js';
import { MockGoogle, type MockGoogleOptions } from './support/mockGoogle.js';

const client = (): GoogleClientCredentials => ({
  clientId: `${dummySecret('CLIENT')}.apps.googleusercontent.com`,
  clientSecret: dummySecret('CLIENT-SECRET'),
});

function setup(opts: MockGoogleOptions = {}, timeoutMs = 5000) {
  const google = new MockGoogle(opts);
  const acct = google.addAccount('dummy.one@example.test');
  let resolveUrl!: (u: string) => void;
  const authUrl = new Promise<string>((r) => (resolveUrl = r));
  const flow = runLoopbackAuthorization({
    client: client(),
    upstream: new Upstream(google.transport),
    port: 0,
    timeoutMs,
    onAuthUrl: resolveUrl,
  });
  flow.catch(() => {});
  return { google, acct, authUrl, flow };
}

describe('parseClientFile', () => {
  it('reads a Desktop ("installed") client and rejects web clients', () => {
    const c = client();
    expect(parseClientFile(JSON.stringify({ installed: { client_id: c.clientId, client_secret: c.clientSecret } }))).toEqual(c);
    expect(() => parseClientFile(JSON.stringify({ web: { client_id: 'x', client_secret: 'y' } }))).toThrow(/desktop/i);
    expect(() => parseClientFile('nope')).toThrow(/desktop/i);
  });
});

describe('runLoopbackAuthorization [mock Google]', () => {
  it('builds a PKCE S256, offline, drive.readonly auth URL with a random state', async () => {
    const { authUrl } = setup();
    const u = new URL(await authUrl);
    expect(u.origin + u.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(u.searchParams.get('response_type')).toBe('code');
    expect(u.searchParams.get('scope')).toBe(DRIVE_READONLY_SCOPE);
    expect(u.searchParams.get('access_type')).toBe('offline');
    expect(u.searchParams.get('prompt')).toBe('consent');
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(u.searchParams.get('state')!.length).toBeGreaterThanOrEqual(43);
    expect(new URL(u.searchParams.get('redirect_uri')!).hostname).toBe('127.0.0.1');
    expect(new URL(u.searchParams.get('redirect_uri')!).pathname).toBe('/oauth2/callback');
  });

  it('rejects wrong path and wrong state without exchanging, then completes with PKCE', async () => {
    const { google, acct, authUrl, flow } = setup();
    const u = new URL(await authUrl);
    const redirect = new URL(u.searchParams.get('redirect_uri')!);
    const code = google.approve(u.toString(), acct);

    const wrongPath = await fetch(`${redirect.origin}/other?code=${code}&state=${u.searchParams.get('state')}`);
    expect(wrongPath.status).toBe(404);
    const wrongState = await fetch(`${redirect}?code=${code}&state=${'A'.repeat(43)}`);
    expect(wrongState.status).toBe(400);
    const noState = await fetch(`${redirect}?code=${code}`);
    expect(noState.status).toBe(400);
    expect(google.tokenCalls).toBe(0);

    const ok = await fetch(`${redirect}?code=${code}&state=${u.searchParams.get('state')}&scope=x`);
    expect(ok.status).toBe(200);
    expect(await ok.text()).not.toContain(code);
    const result = await flow;
    expect(result.refreshToken).toBe(acct.refreshToken);
    expect(result.scopes).toContain(DRIVE_READONLY_SCOPE);
    expect(google.tokenCalls).toBe(1);
    const tokenReq = new URLSearchParams(google.calls.find((c) => c.url.pathname === '/token')!.body);
    expect(createHash('sha256').update(tokenReq.get('code_verifier')!).digest('base64url')).toBe(
      u.searchParams.get('code_challenge'),
    );
  });

  it('fails when the PKCE verifier does not match (mock token endpoint verifies S256)', async () => {
    const { google, acct, authUrl, flow } = setup();
    const u = new URL(await authUrl);
    const code = google.approve(u.toString(), acct);
    google.codes.get(code)!.challenge = 'tampered-challenge-value-tampered-challenge-v';
    await fetch(`${u.searchParams.get('redirect_uri')}?code=${code}&state=${u.searchParams.get('state')}`);
    const err = await flow.catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/invalid_grant/);
    expect((err as Error).message).not.toContain(code);
  });

  it('times out and closes the callback listener', async () => {
    const { authUrl, flow } = setup({}, 300);
    const redirect = new URL(new URL(await authUrl).searchParams.get('redirect_uri')!);
    await expect(flow).rejects.toThrow(/timed out/i);
    await expect(fetch(redirect)).rejects.toThrow();
  });

  it('rejects timeouts beyond one hour (setTimeout overflow) before opening a port', async () => {
    const google = new MockGoogle();
    let urlShown = false;
    await expect(
      runLoopbackAuthorization({
        client: client(),
        upstream: new Upstream(google.transport),
        timeoutMs: 3_000_000_000,
        onAuthUrl: () => (urlShown = true),
      }),
    ).rejects.toThrow(/timeout/i);
    expect(urlShown).toBe(false);
  });

  it('aborts when Google reports an error for a valid state', async () => {
    const { authUrl, flow } = setup();
    const u = new URL(await authUrl);
    const res = await fetch(`${u.searchParams.get('redirect_uri')}?error=access_denied&state=${u.searchParams.get('state')}`);
    expect(res.status).toBe(400);
    await expect(flow).rejects.toThrow(/access_denied/);
  });

  it('requires a refresh token', async () => {
    const { google, acct, authUrl, flow } = setup({ omitRefreshToken: true });
    const u = new URL(await authUrl);
    const code = google.approve(u.toString(), acct);
    await fetch(`${u.searchParams.get('redirect_uri')}?code=${code}&state=${u.searchParams.get('state')}`);
    await expect(flow).rejects.toThrow(/refresh token/i);
  });

  it('requires the drive.readonly scope to actually be granted (drive.file is not enough)', async () => {
    const { google, acct, authUrl, flow } = setup({ grantedScope: 'https://www.googleapis.com/auth/drive.file' });
    const u = new URL(await authUrl);
    const code = google.approve(u.toString(), acct);
    await fetch(`${u.searchParams.get('redirect_uri')}?code=${code}&state=${u.searchParams.get('state')}`);
    await expect(flow).rejects.toThrow(/drive\.readonly/);
  });
});
