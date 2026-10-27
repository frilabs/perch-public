// Generic PKCE loopback receiver (shared by Google/Gmail and Microsoft). Local only; the code
// exchange is a MOCK callback.
import { createHash } from 'node:crypto';
import { request } from 'node:http';
import { describe, expect, it } from 'vitest';
import { runPkceLoopback } from '../src/oauth/loopback.js';

function get(url: string) {
  return new Promise<number>((resolve, reject) => {
    const u = new URL(url);
    // Always connect to 127.0.0.1 (the listener), whatever host name the redirect URI uses.
    const req = request({ host: '127.0.0.1', port: u.port, path: u.pathname + u.search, method: 'GET' }, (res) => {
      res.resume();
      resolve(res.statusCode!);
    });
    req.on('error', reject);
    req.end();
  });
}

describe('runPkceLoopback', () => {
  it('supports a localhost redirect URI with a custom callback path and verifies state before exchanging', async () => {
    let exchanged: { code: string; verifier: string; redirectUri: string } | undefined;
    let resolveUrl!: (u: string) => void;
    const authUrl = new Promise<string>((r) => (resolveUrl = r));
    const flow = runPkceLoopback({
      provider: 'Microsoft',
      authEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      authParams: { client_id: 'dummy-client', scope: 'offline_access User.Read Mail.Read' },
      redirectHost: 'localhost',
      callbackPath: '/',
      port: 0,
      timeoutMs: 5000,
      onAuthUrl: resolveUrl,
      exchange: async (code, verifier, redirectUri) => {
        exchanged = { code, verifier, redirectUri };
        return 'ok';
      },
    });
    const u = new URL(await authUrl);
    expect(u.origin + u.pathname).toBe('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
    const redirect = new URL(u.searchParams.get('redirect_uri')!);
    expect(redirect.hostname).toBe('localhost');
    expect(redirect.pathname).toBe('/');
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('response_type')).toBe('code');

    expect(await get(`${redirect.origin}/?state=wrong&code=X`)).toBe(400);
    expect(exchanged).toBeUndefined();
    expect(await get(`${redirect.origin}/?state=${u.searchParams.get('state')}&code=GOOD`)).toBe(200);
    expect(await flow).toBe('ok');
    expect(exchanged!.code).toBe('GOOD');
    expect(createHash('sha256').update(exchanged!.verifier).digest('base64url')).toBe(u.searchParams.get('code_challenge'));
    expect(exchanged!.redirectUri).toBe(redirect.toString());
  });

  it('reports provider errors with a sanitised code', async () => {
    let resolveUrl!: (u: string) => void;
    const authUrl = new Promise<string>((r) => (resolveUrl = r));
    const flow = runPkceLoopback({
      provider: 'Microsoft',
      authEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      authParams: { client_id: 'c', scope: 's' },
      redirectHost: '127.0.0.1',
      callbackPath: '/cb',
      timeoutMs: 5000,
      onAuthUrl: resolveUrl,
      exchange: async () => 'never',
    });
    flow.catch(() => {});
    const u = new URL(await authUrl);
    const redirect = new URL(u.searchParams.get('redirect_uri')!);
    await get(`${redirect.origin}/cb?state=${u.searchParams.get('state')}&error=access_denied&error_description=<script>`);
    await expect(flow).rejects.toThrow(/Microsoft authorization failed: access_denied/);
  });
});
