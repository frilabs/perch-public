// Acceptance criteria of docs/PUBLIC_ACCESS_SPEC.md §12 against the real public listener (127.0.0.1) with
// MOCK Google and MOCK client metadata documents. Numbers in the test names refer to §12. Nothing reaches a
// real provider; every secret is generated dummy data.
import { readFile, writeFile } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, createDeviceGrant } from '../src/auth/grants.js';
import { checkIdTokenClaims } from '../src/access/google.js';
import { noticeText } from '../src/access/notify.js';
import { AUTH_CODE_TTL_MS } from '../src/access/pairing.js';
import { DEVICE_ABSOLUTE_MS, endDevice, REFRESH_IDLE_MS, sha256Hex } from '../src/access/state.js';
import { hotp, totpStep } from '../src/access/totp.js';
import {
  authorizeUrl,
  BASE,
  CLAUDE_CALLBACK,
  CLAUDE_CODE_CIMD,
  cookieFrom,
  csrfOf,
  exchange,
  form,
  GOOGLE,
  mcpCall,
  openWindow,
  OPERATOR,
  pairAndExchange,
  pkce,
  runBrowserFlow,
  startHarness,
  waitFor,
  type Harness,
} from './support/publicAccessFixtures.js';

let h: Harness;
beforeEach(async () => {
  h = await startHarness();
});
afterEach(async () => {
  await h.close();
});

const listAccounts = (token: string) => mcpCall(h, token, 'tools/call', { name: 'perch_list_accounts', arguments: {} });

/** Starts a session and passes the pairing code; returns the cookie and the Google redirect. */
async function throughCode(code: string, o: { clientId?: string; redirectUri?: string } = {}) {
  const { verifier, challenge } = pkce();
  const a = await h.http('GET', authorizeUrl({ challenge, ...o }));
  const cookie = cookieFrom(a)!;
  const p = await h.http('GET', '/oauth/pair', { cookie });
  const g = await h.http('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code }) });
  return { cookie, verifier, google: g };
}

async function throughGoogle(code: string) {
  const r = await throughCode(code);
  const gu = new URL(r.google.location!);
  h.google.nonce = gu.searchParams.get('nonce')!;
  const cb = await h.http('GET', `/oauth/google/callback?state=${encodeURIComponent(gu.searchParams.get('state')!)}&code=google-code-0123456789`, { cookie: r.cookie });
  return { ...r, cb };
}

describe('public listener routing and discovery', () => {
  it('bounds tool arguments on the OAuth listener before validation or provider I/O', async () => {
    const { tokens } = await pairAndExchange(h);
    const calls = h.upstreamCalls.length;
    const response = await mcpCall(h, tokens.access_token!, 'tools/call', {
      name: 'perch_list_accounts', arguments: { extra: Array.from({ length: 10_001 }, () => null) },
    });
    expect(response.status).toBe(200);
    const result = JSON.parse(response.body).result;
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('maximum of 10000 elements');
    expect(response.body.length).toBeLessThan(1000);
    expect(h.upstreamCalls).toHaveLength(calls);
    const normal = await listAccounts(tokens.access_token!);
    expect(normal.status).toBe(200);
    expect(JSON.parse(normal.body).result.isError).not.toBe(true);
  });

  it('1: has no status page, local pages or other routes, even with a valid token', async () => {
    const { tokens } = await pairAndExchange(h);
    for (const path of ['/status', '/local/pair', '/', '/admin', '/oauth/unknown']) {
      const r = await h.http('GET', path, { headers: { authorization: `Bearer ${tokens.access_token}` } });
      expect(r.status, path).toBe(404);
    }
  });

  it('2: rejects client-grant tokens (and any static token) on /mcp', async () => {
    const now = new Date().toISOString();
    await h.store.update((d) => {
      d.imap.push({ id: 'imap-0000000a', label: 'GMX', email: 'me@example.test', username: 'me@example.test', password: 'DUMMY-PW', imap: { host: 'imap.invalid.example', port: 993 }, smtp: { host: 'smtp.invalid.example', port: 465, security: 'tls' }, allowDrafts: false, allowSend: false, createdAt: now, updatedAt: now });
    });
    const tokenFile = `${h.dirs.root}/config/clients/c.token`;
    await createClientGrant(h.store, { label: 'Laptop', capabilities: ['read'], accountIds: ['imap-0000000a'], tokenFile });
    const clientToken = (await readFile(tokenFile, 'utf8')).trim();
    expect((await listAccounts(clientToken)).status).toBe(401);
    expect((await listAccounts('A'.repeat(43))).status).toBe(401);
  });

  it('3: serves the discovery documents and answers 401 with resource_metadata', async () => {
    const prm = JSON.parse((await h.http('GET', '/.well-known/oauth-protected-resource/mcp')).body);
    expect(prm).toMatchObject({ resource: `${BASE}/mcp`, authorization_servers: [BASE] });
    const as = JSON.parse((await h.http('GET', '/.well-known/oauth-authorization-server')).body);
    expect(as).toMatchObject({
      issuer: BASE,
      code_challenge_methods_supported: ['S256'],
      client_id_metadata_document_supported: true,
      token_endpoint_auth_methods_supported: ['none'],
      registration_endpoint: `${BASE}/oauth/register`,
    });
    const r = await h.http('POST', '/mcp', { type: 'application/json', body: '{}' });
    expect(r.status).toBe(401);
    expect(r.headers['www-authenticate']).toBe(`Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource", scope="perch.read"`);
  });

  it('rejects a foreign Host header', async () => {
    expect((await h.http('GET', '/.well-known/oauth-authorization-server', { host: 'evil.example' })).status).toBe(403);
  });
});

describe('pairing window', () => {
  it('4: without a window, authorize shows a fixed page (no Google redirect, no metadata fetch) and register is closed', async () => {
    const { challenge } = pkce();
    const r = await h.http('GET', authorizeUrl({ challenge }));
    expect(r.status).toBe(403);
    expect(r.body).toContain('No pairing window is open');
    expect(r.headers['content-security-policy']).toMatch(/default-src 'none'/);
    const reg = await h.http('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ redirect_uris: ['http://127.0.0.1/cb'] }) });
    expect(reg.status).toBe(403);
    expect(h.upstreamCalls).toEqual([]);
  });

  it('5: no code without PKCE S256, with a wrong resource, an unknown client or an unregistered redirect; unlisted CIMD URLs are never fetched', async () => {
    openWindow(h);
    const { challenge } = pkce();
    const noPkce = await h.http('GET', authorizeUrl({ challenge, method: 'plain' }));
    expect(new URL(noPkce.location!).searchParams.get('error')).toBe('invalid_request');
    const wrongResource = await h.http('GET', authorizeUrl({ challenge, resource: 'https://other.example/mcp' }));
    expect(new URL(wrongResource.location!).searchParams.get('error')).toBe('invalid_target');
    const unknown = await h.http('GET', authorizeUrl({ challenge, clientId: 'https://evil.example/client.json' }));
    expect(unknown.status).toBe(400);
    const badRedirect = await h.http('GET', authorizeUrl({ challenge, redirectUri: 'https://evil.example/cb' }));
    expect(badRedirect.status).toBe(400); // listed in the document, but not on Claude's site: filtered out
    expect(h.upstreamCalls.some((c) => c.includes('evil.example'))).toBe(false);
    expect(h.events.some((e) => e.type === 'paired')).toBe(false);
  });

  it('6: a wrong pairing code does not advance; the third closes the window', async () => {
    openWindow(h);
    const { cookie, google } = await throughCode('WRONGCOD');
    expect(google.status).toBe(200);
    expect(google.body).toContain('Wrong pairing code');
    const csrf = csrfOf(google.body);
    await h.http('POST', '/oauth/pair', { cookie, body: form({ csrf, code: 'WRONG002' }) });
    const third = await h.http('POST', '/oauth/pair', { cookie, body: form({ csrf, code: 'WRONG003' }) });
    expect(third.body).toContain('pairing window was closed');
    expect(h.pairing.isOpen).toBe(false);
    expect(h.notices.filter((n) => n.kind === 'pairing_code_wrong')).toHaveLength(3);
  });

  it('7: a second browser session in the same window closes it for both, with an alarm', async () => {
    const code = openWindow(h);
    const first = await throughCode(code);
    expect(first.google.status).toBe(303);
    const { challenge } = pkce();
    const second = await h.http('GET', authorizeUrl({ challenge }));
    expect(second.status).toBe(403);
    expect(second.body).toContain('second sign-in attempt');
    expect(h.pairing.isOpen).toBe(false);
    expect(h.notices.map((n) => n.kind)).toContain('second_pairing_attempt');
    expect(h.events).toContainEqual({ type: 'closed', reason: 'second_attempt' });
    // The first session cannot continue either.
    const gu = new URL(first.google.location!);
    const cb = await h.http('GET', `/oauth/google/callback?state=${gu.searchParams.get('state')}&code=google-code-0123456789`, { cookie: first.cookie });
    expect(cb.status).toBe(403);
  });

  it('8: Google: an account outside the allowlist, a changed sub or e-mail, a bad nonce, an unverified e-mail or a stale sign-in give no code', async () => {
    for (const claims of [
      (b: Record<string, unknown>) => ({ ...b, email: 'stranger@example.test', sub: '999' }),
      (b: Record<string, unknown>) => ({ ...b, nonce: 'other' }),
      (b: Record<string, unknown>) => ({ ...b, email_verified: false }),
      (b: Record<string, unknown>) => ({ ...b, auth_time: (b.iat as number) - 3600 }),
      (b: Record<string, unknown>) => ({ ...b, aud: 'someone-else.apps.googleusercontent.com' }),
    ]) {
      h.google.claims = claims;
      const code = openWindow(h);
      const { cb } = await throughGoogle(code);
      expect(cb.status).toBe(403);
      expect(h.pairing.isOpen).toBe(false);
    }
    // Pin the sub with a good login, then a different sub with the same e-mail is refused.
    h.google.claims = undefined;
    const ok = await throughGoogle(openWindow(h));
    expect(ok.cb.location).toBe('/oauth/totp');
    expect((await h.oauth.read()).loginAllow[0]!.sub).toBe(OPERATOR.sub);
    h.pairing.close('aborted');
    h.google.claims = (b) => ({ ...b, sub: '111' });
    expect((await throughGoogle(openWindow(h))).cb.status).toBe(403);
  });

  it('9: wrong and replayed Perch codes are refused; a recovery code works once and never replaces the pairing code; five failures lock pairing', async () => {
    const code = openWindow(h, 'manual');
    const { cookie, cb } = await throughGoogle(code);
    expect(cb.location).toBe('/oauth/totp');
    const page = await h.http('GET', '/oauth/totp', { cookie });
    const csrf = csrfOf(page.body);
    const step = totpStep(h.clock.now);
    await h.oauth.transact((d) => void (d.totp!.lastStep = step));
    const replay = await h.http('POST', '/oauth/totp', { cookie, body: form({ csrf, code: hotp(h.secret, step) }) });
    expect(replay.body).toContain('Wrong or already used code');
    const far = await h.http('POST', '/oauth/totp', { cookie, body: form({ csrf, code: hotp(h.secret, step + 3) }) });
    expect(far.body).toContain('Wrong or already used code');
    for (let i = 0; i < 2; i++) await h.http('POST', '/oauth/totp', { cookie, body: form({ csrf, code: '000000' }) });
    const fifth = await h.http('POST', '/oauth/totp', { cookie, body: form({ csrf, code: '000001' }) });
    expect(fifth.body).toContain('Pairing locked');
    expect(h.pairing.isOpen).toBe(false);
    const s = await h.oauth.read();
    expect(Date.parse(s.pairLock!.until)).toBeGreaterThan(h.clock.now);
    expect(h.notices.map((n) => n.kind)).toContain('pairing_locked');
  });

  it('9b: a recovery code is accepted exactly once', async () => {
    await h.oauth.transact((d) => {
      d.totp!.recovery = [{ salt: '00112233445566778899aabbccddeeff', hash: sha256Hex('00112233445566778899aabbccddeeff:ABCDE23456') }];
    });
    const code = openWindow(h);
    const { cookie } = await throughGoogle(code);
    const page = await h.http('GET', '/oauth/totp', { cookie });
    const ok = await h.http('POST', '/oauth/totp', { cookie, body: form({ csrf: csrfOf(page.body), code: 'abcde-23456' }) });
    expect(ok.location).toBe('/oauth/wait');
    expect((await h.oauth.read()).totp!.recovery[0]!.usedAt).toBeDefined();
    expect(h.notices.map((n) => n.kind)).toContain('recovery_code_used');
    await waitFor(() => h.events.some((e) => e.type === 'paired'));
    await h.http('GET', '/oauth/wait', { cookie }); // the browser picks up its redirect: window consumed
    // A second use in a new window fails.
    const again = await throughGoogle(openWindow(h));
    const p2 = await h.http('GET', '/oauth/totp', { cookie: again.cookie });
    const no = await h.http('POST', '/oauth/totp', { cookie: again.cookie, body: form({ csrf: csrfOf(p2.body), code: 'ABCDE23456' }) });
    expect(no.body).toContain('Wrong or already used code');
  });

  it('10: without the local "y" there is no code (rejected, or the window expires)', async () => {
    const code = openWindow(h, 'reject');
    const { cookie } = await throughGoogle(code);
    const page = await h.http('GET', '/oauth/totp', { cookie });
    await h.http('POST', '/oauth/totp', { cookie, body: form({ csrf: csrfOf(page.body), code: h.nextTotp() }) });
    await waitFor(() => h.events.some((e) => e.type === 'closed'));
    const w = await h.http('GET', '/oauth/wait', { cookie });
    expect(w.status).toBe(403);
    expect(w.body).toContain('not confirmed');
    expect((await h.oauth.read()).devices).toEqual([]);
  });

  it('10b: while waiting for the terminal, the browser only sees the wait page', async () => {
    const code = openWindow(h, 'manual');
    const { cookie } = await throughGoogle(code);
    const page = await h.http('GET', '/oauth/totp', { cookie });
    await h.http('POST', '/oauth/totp', { cookie, body: form({ csrf: csrfOf(page.body), code: h.nextTotp() }) });
    const confirm = h.events.find((e) => e.type === 'confirm') as { details: unknown };
    expect(confirm.details).toMatchObject({ clientDisplay: 'claude.ai', redirectHost: 'claude.ai', googleEmail: OPERATOR.email, ip: 'unknown' });
    const w = await h.http('GET', '/oauth/wait', { cookie });
    expect(w.status).toBe(200);
    expect(w.body).toContain('Confirm this sign-in in your terminal');
    expect(w.body).toContain('http-equiv="refresh"');
    h.pairing.answer(true, h.pairing.windowId!, (h.events.find((e) => e.type === 'confirm') as { confirmId: string }).confirmId);
    await waitFor(() => h.events.some((e) => e.type === 'paired'));
    const done = await h.http('GET', '/oauth/wait', { cookie });
    const u = new URL(done.location!);
    expect(`${u.origin}${u.pathname}`).toBe(CLAUDE_CALLBACK);
    expect(u.searchParams.get('state')).toBe('state-123');
    expect(u.searchParams.get('iss')).toBe(BASE);
  });

  it('11: one window pairs at most one device; a DCR client id from an earlier window is worthless', async () => {
    const code = openWindow(h);
    const reg = await h.http('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ client_name: 'Codex', redirect_uris: ['http://127.0.0.1/callback'] }) });
    expect(reg.status).toBe(201);
    const clientId = JSON.parse(reg.body).client_id as string;
    const r = await runBrowserFlow(h, code, { clientId, redirectUri: 'http://127.0.0.1:43123/callback' });
    expect(h.pairing.isOpen).toBe(false); // consumed
    expect((await exchange(h, r, { clientId, redirectUri: 'http://127.0.0.1:43123/callback' })).status).toBe(200);
    // New window: the old DCR id is unknown there.
    openWindow(h);
    const { challenge } = pkce();
    const stale = await h.http('GET', authorizeUrl({ challenge, clientId, redirectUri: 'http://127.0.0.1:43123/callback' }));
    expect(stale.status).toBe(400);
    const dev = (await h.oauth.read()).devices;
    expect(dev).toHaveLength(1);
    expect(dev[0]).toMatchObject({ registration: 'dcr', clientName: 'Codex', redirectHost: '127.0.0.1' });
  });

  it('11b: DCR is bounded per window and can be switched off', async () => {
    openWindow(h);
    for (let i = 0; i < 3; i++) {
      const r = await h.http('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ redirect_uris: [`https://app${i}.example/cb`] }) });
      expect(r.status).toBe(201);
    }
    expect((await h.http('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ redirect_uris: ['https://x.example/cb'] }) })).status).toBe(429);
    expect((await h.http('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ redirect_uris: ['ftp://x'] }) })).status).toBe(400);
    const off = await startHarness({ dcrEnabled: false });
    try {
      expect((await off.http('POST', '/oauth/register', { type: 'application/json', body: '{}' })).status).toBe(404);
      expect(JSON.parse((await off.http('GET', '/.well-known/oauth-authorization-server')).body).registration_endpoint).toBeUndefined();
    } finally {
      await off.close();
    }
  });

  it('accepts Claude Code (CIMD, loopback redirect on any port)', async () => {
    const code = openWindow(h);
    const r = await runBrowserFlow(h, code, { clientId: CLAUDE_CODE_CIMD, redirectUri: 'http://localhost:51234/callback' });
    expect(r.redirect.origin).toBe('http://localhost:51234');
    const t = await exchange(h, r, { clientId: CLAUDE_CODE_CIMD, redirectUri: 'http://localhost:51234/callback' });
    expect(t.status).toBe(200);
  });
});

describe('tokens', () => {
  it('13: the authorization code is single-use and expires after 60 s', async () => {
    const code = openWindow(h);
    const r = await runBrowserFlow(h, code);
    const first = await exchange(h, r);
    expect(first.status).toBe(200);
    expect(first.json).toMatchObject({ token_type: 'Bearer', expires_in: 3600, scope: 'perch.read' });
    expect((await exchange(h, r)).json.error).toBe('invalid_grant');
    const code2 = openWindow(h);
    const r2 = await runBrowserFlow(h, code2);
    h.clock.now += AUTH_CODE_TTL_MS + 1000;
    expect((await exchange(h, r2)).json.error).toBe('invalid_grant');
  });

  it('13b: a wrong PKCE verifier, client id or redirect uri gives no token', async () => {
    const code = openWindow(h);
    const r = await runBrowserFlow(h, code);
    const bad = await h.http('POST', '/oauth/token', {
      body: form({ grant_type: 'authorization_code', code: r.code, redirect_uri: CLAUDE_CALLBACK, client_id: 'https://claude.ai/oauth/claude-code-client-metadata', code_verifier: r.verifier }),
    });
    expect(JSON.parse(bad.body).error).toBe('invalid_grant');
  });

  it('14: refresh rotates; reusing an old refresh token signs the device out, including its current access token', async () => {
    const { tokens } = await pairAndExchange(h);
    expect((await listAccounts(tokens.access_token!)).status).toBe(200);
    const r1 = JSON.parse((await h.http('POST', '/oauth/token', { body: form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: 'https://claude.ai/oauth/mcp-oauth-client-metadata' }) })).body);
    expect(r1.refresh_token).toBeDefined();
    expect(r1.refresh_token).not.toBe(tokens.refresh_token);
    expect((await listAccounts(tokens.access_token!)).status).toBe(401); // replaced
    expect((await listAccounts(r1.access_token)).status).toBe(200);
    const reuse = await h.http('POST', '/oauth/token', { body: form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token! }) });
    expect(JSON.parse(reuse.body).error).toBe('invalid_grant');
    expect((await listAccounts(r1.access_token)).status).toBe(401);
    expect((await h.oauth.read()).devices[0]).toMatchObject({ status: 'revoked', endedReason: 'refresh_reuse' });
    expect(h.notices.map((n) => n.kind)).toContain('refresh_reuse');
  });

  it('12: an expired device (14 days idle, 90 days absolute) cannot refresh; only a new pairing helps', async () => {
    const a = await pairAndExchange(h);
    h.clock.now += REFRESH_IDLE_MS + 1000;
    const idle = await h.http('POST', '/oauth/token', { body: form({ grant_type: 'refresh_token', refresh_token: a.tokens.refresh_token! }) });
    expect(JSON.parse(idle.body).error).toBe('invalid_grant');
    expect((await h.oauth.read()).devices[0]).toMatchObject({ status: 'expired', endedReason: 'idle' });
    const b = await pairAndExchange(h);
    for (let i = 0; i < 7; i++) {
      h.clock.now += 13 * 24 * 3600 * 1000;
      const cur = (await h.oauth.read()).devices.find((d) => d.id === b.deviceId)!;
      if (cur.status !== 'active') break;
      const last = JSON.parse((await h.http('POST', '/oauth/token', { body: form({ grant_type: 'refresh_token', refresh_token: b.tokens.refresh_token! }) })).body);
      if (last.refresh_token) b.tokens.refresh_token = last.refresh_token;
    }
    expect((await h.oauth.read()).devices.find((d) => d.id === b.deviceId)).toMatchObject({ status: 'expired', endedReason: 'absolute' });
    expect(DEVICE_ABSOLUTE_MS).toBe(90 * 24 * 3600 * 1000);
  });

  it('client revocation (RFC 7009) signs the device out', async () => {
    const { tokens } = await pairAndExchange(h);
    expect((await h.http('POST', '/oauth/revoke', { body: form({ token: tokens.access_token! }) })).status).toBe(200);
    expect((await listAccounts(tokens.access_token!)).status).toBe(401);
  });
});

describe('revocation, kill switch and rights', () => {
  it('15: revoking a device, changing the Perch code and the kill switch apply to running tokens', async () => {
    const a = await pairAndExchange(h);
    await h.oauth.transact((d) => endDevice(d.devices.find((x) => x.id === a.deviceId)!, 'revoked'));
    expect((await listAccounts(a.tokens.access_token!)).status).toBe(401);
    const b = await pairAndExchange(h);
    await h.oauth.transact((d) => endDevice(d.devices.find((x) => x.id === b.deviceId)!, 'totp_changed'));
    expect((await listAccounts(b.tokens.access_token!)).status).toBe(401);
    const c = await pairAndExchange(h);
    await h.oauth.transact((d) => void (d.publicLocked = { since: new Date().toISOString() }));
    expect((await listAccounts(c.tokens.access_token!)).status).toBe(503);
    expect((await h.http('GET', '/.well-known/oauth-protected-resource')).status).toBe(200); // static discovery stays
    expect((await h.http('POST', '/oauth/token', { body: form({ grant_type: 'refresh_token', refresh_token: c.tokens.refresh_token! }) })).status).toBe(503);
  });

  it('16: without a grant a device reads like the global token and has no write tools; with a grant it is a client grant', async () => {
    const a = await pairAndExchange(h);
    const tools = JSON.parse((await mcpCall(h, a.tokens.access_token!, 'tools/list')).body).result.tools.map((t: { name: string }) => t.name);
    expect(tools).toContain('drive_search');
    expect(tools).not.toContain('mail_send');
    // An IMAP account so a send grant is possible.
    const now = new Date().toISOString();
    await h.store.update((d) => {
      d.imap.push({ id: 'imap-0000000a', label: 'GMX', email: 'me@example.test', username: 'me@example.test', password: 'DUMMY-PW', imap: { host: 'imap.invalid.example', port: 993 }, smtp: { host: 'smtp.invalid.example', port: 465, security: 'tls' }, allowDrafts: false, allowSend: true, createdAt: now, updatedAt: now });
    });
    const g = await createDeviceGrant(h.store, { label: 'OAuth dev', capabilities: ['read', 'send'], accountIds: ['imap-0000000a'] });
    await h.oauth.transact((d) => void (d.devices[0]!.grantClientId = g.id));
    const granted = JSON.parse((await mcpCall(h, a.tokens.access_token!, 'tools/list')).body).result.tools.map((t: { name: string }) => t.name);
    expect(granted).toContain('mail_send');
    expect(granted).not.toContain('drive_search');
    // Its grant token hash has no known preimage: no bearer token can use the grant directly.
    await h.store.update((d) => void (d.clients = d.clients.filter((c) => c.id !== g.id)));
    expect((await mcpCall(h, a.tokens.access_token!, 'tools/list')).status).toBe(401);
  });

  it('17: rate limits and the invalid-bearer block (known devices keep working)', async () => {
    // Without a window the fixed page costs nothing: nobody can exhaust the limit in advance.
    for (let i = 0; i < 30; i++) expect((await h.http('GET', authorizeUrl({ challenge: 'x'.repeat(43) }))).status).toBe(403);
    openWindow(h, 'manual');
    for (let i = 0; i < 10; i++) await h.http('GET', authorizeUrl({ challenge: 'x'.repeat(43) }));
    expect((await h.http('GET', authorizeUrl({ challenge: 'x'.repeat(43) }))).status).toBe(429);
    h.pairing.close('aborted');
    const { tokens } = await (async () => {
      h.clock.now += 120_000; // refill
      return pairAndExchange(h);
    })();
    expect((await listAccounts(tokens.access_token!)).status).toBe(200); // now known
    for (let i = 0; i < 20; i++) await listAccounts('B'.repeat(43));
    expect((await listAccounts('D'.repeat(43))).status).toBe(401); // blocked for 5 minutes
    expect((await listAccounts(tokens.access_token!)).status).toBe(200); // a known device is not locked out
  });

  it('17d: a token issued during the invalid-bearer block (refresh, before its first use) still passes', async () => {
    const { tokens } = await pairAndExchange(h);
    for (let i = 0; i < 20; i++) await listAccounts('B'.repeat(43));
    expect((await listAccounts('D'.repeat(43))).status).toBe(401); // blocked
    const refreshed = JSON.parse(
      (await h.http('POST', '/oauth/token', { body: form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: 'https://claude.ai/oauth/mcp-oauth-client-metadata' }) })).body,
    );
    expect(refreshed.access_token).toBeTruthy();
    expect((await listAccounts(refreshed.access_token)).status).toBe(200); // never used before, but issued by Perch
    expect((await listAccounts(tokens.access_token!)).status).toBe(401); // the replaced token stays invalid
  });

  it('17b: every pairing step leaves a secret-free audit trail; notifications carry no links or secrets', async () => {
    const a = await pairAndExchange(h);
    const ledger = await h.context.audit.list({ limit: 100 });
    const types = ledger.events.map((e) => e.type);
    expect(types).toEqual(expect.arrayContaining(['oauth_pair_started', 'oauth_totp', 'oauth_device_paired', 'oauth_token_issued']));
    const raw = JSON.stringify(ledger);
    for (const secret of [a.tokens.access_token!, a.tokens.refresh_token!, a.code, OPERATOR.email, GOOGLE.clientSecret]) expect(raw).not.toContain(secret);
    for (const kind of ['window_opened', 'device_paired', 'second_pairing_attempt', 'refresh_reuse'] as const) expect(noticeText(kind)).not.toMatch(/https?:\/\//);
  });

  it('17c: a failing notification channel never blocks a pairing', async () => {
    const failing = await startHarness({ notifierFails: true });
    try {
      const a = await pairAndExchange(failing);
      expect(a.tokens.access_token).toBeDefined();
    } finally {
      await failing.close();
    }
  });

  it('19: a damaged oauth.enc fails closed (503) on the public listener', async () => {
    const file = `${h.dirs.dataDir}/oauth.enc`;
    const raw = await readFile(file, 'utf8');
    await writeFile(file, raw.replace(/"ct":"(.)/, (_m, c: string) => `"ct":"${c === 'A' ? 'B' : 'A'}`));
    openWindow(h);
    const { challenge } = pkce();
    expect((await h.http('GET', authorizeUrl({ challenge }))).status).toBe(503);
    expect((await listAccounts('C'.repeat(43))).status).toBe(503);
  });
});

describe('ID token claims (unit)', () => {
  const now = 1_800_000_000;
  const base = { iss: 'https://accounts.google.com', aud: GOOGLE.clientId, sub: '42', email: 'A@Example.test', email_verified: true, iat: now, exp: now + 3600, nonce: 'n' };
  it('accepts a valid token and lower-cases the e-mail', () => {
    expect(checkIdTokenClaims(base, GOOGLE, 'n', now)).toEqual({ sub: '42', email: 'a@example.test' });
  });
  it('rejects wrong issuer, audience, azp, expiry and age', () => {
    for (const bad of [
      { ...base, iss: 'https://evil.example' },
      { ...base, aud: 'x' },
      { ...base, aud: [GOOGLE.clientId, 'x'], azp: 'x' },
      { ...base, exp: now - 120 },
      { ...base, iat: now - 3600 },
      { ...base, email_verified: undefined },
    ]) {
      expect(() => checkIdTokenClaims(bad, GOOGLE, 'n', now)).toThrow(/Google sign-in rejected/);
    }
  });
});

describe('regressions from the independent review', () => {
  it('the browser that passed the pairing code cannot restart and let another browser join', async () => {
    const code = openWindow(h, 'manual');
    const a = await throughCode(code);
    expect(a.google.status).toBe(303);
    const { challenge } = pkce();
    const restart = await h.http('GET', authorizeUrl({ challenge }), { cookie: a.cookie });
    expect(restart.status).toBe(403);
    expect(h.pairing.isOpen).toBe(false);
    expect(h.events).toContainEqual({ type: 'closed', reason: 'replaced' });
  });

  it('an answer only applies to the confirmation that was shown', async () => {
    const code = openWindow(h, 'manual');
    const { cookie } = await throughGoogle(code);
    const page = await h.http('GET', '/oauth/totp', { cookie });
    await h.http('POST', '/oauth/totp', { cookie, body: form({ csrf: csrfOf(page.body), code: h.nextTotp() }) });
    expect(() => h.pairing.answer(true, h.pairing.windowId!, 'not-the-shown-one')).toThrow(/Nothing is waiting/);
    expect(() => h.pairing.answer(true, 'other-window', (h.events.find((e) => e.type === 'confirm') as { confirmId: string }).confirmId)).toThrow(/Nothing is waiting/);
    expect((await h.oauth.read()).devices).toEqual([]);
  });

  it('reusing an exchanged authorization code signs the device out', async () => {
    const code = openWindow(h);
    const r = await runBrowserFlow(h, code);
    const t = await exchange(h, r);
    expect(t.status).toBe(200);
    expect((await exchange(h, r)).json.error).toBe('invalid_grant');
    expect((await listAccounts(t.json.access_token!)).status).toBe(401);
    expect((await h.oauth.read()).devices[0]).toMatchObject({ status: 'revoked', endedReason: 'code_reuse' });
  });

  it('a self-registered client never gets an error redirect (no open redirect)', async () => {
    openWindow(h, 'manual');
    const reg = await h.http('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ redirect_uris: ['https://attacker.example/cb'] }) });
    const clientId = JSON.parse(reg.body).client_id as string;
    const { challenge } = pkce();
    const r = await h.http('GET', authorizeUrl({ challenge, clientId, redirectUri: 'https://attacker.example/cb', responseType: 'token' }));
    expect(r.status).toBe(400);
    expect(r.location).toBeUndefined();
  });

  it('an authorization code that expires unused removes its pending device and grant (L3)', async () => {
    const code = openWindow(h, 'manual');
    const run = runBrowserFlow(h, code);
    await waitFor(() => h.events.some((e) => e.type === 'confirm'));
    const c = h.events.find((e) => e.type === 'confirm') as { confirmId: string };
    h.pairing.answer(true, h.pairing.windowId!, c.confirmId, 'full');
    const r = await run;
    const dev = (await h.oauth.read()).devices[0]!;
    expect(dev.status).toBe('pending');
    expect((await h.store.read()).clients.some((x) => x.id === dev.grantClientId)).toBe(true);
    h.clock.now += AUTH_CODE_TTL_MS + 1000;
    h.pairing.sweepCodes();
    const gone = async () => !(await h.oauth.read()).devices.length && !(await h.store.read()).clients.some((x) => x.id === dev.grantClientId);
    for (let i = 0; i < 200 && !(await gone()); i++) await new Promise((res) => setTimeout(res, 10));
    expect((await h.oauth.read()).devices).toEqual([]);
    expect((await h.store.read()).clients.some((x) => x.id === dev.grantClientId)).toBe(false);
    expect((await exchange(h, r)).json.error).toBe('invalid_grant');
  });

  it('a paired device whose code is never exchanged expires after 10 minutes', async () => {
    const code = openWindow(h);
    await runBrowserFlow(h, code);
    h.clock.now += 11 * 60 * 1000;
    const { tokens } = await pairAndExchange(h); // any state write expires the unused one
    expect(tokens.access_token).toBeDefined();
    const devs = (await h.oauth.read()).devices;
    expect(devs[0]).toMatchObject({ status: 'expired', endedReason: 'unused' });
    expect(devs[1]!.status).toBe('active');
  });
});
