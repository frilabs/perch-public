// OAuth on the private (tailnet) listener and perch connect (docs/SIMPLE_CONNECT_SPEC.md §1–§4): private
// discovery and issuer, pairing without Google and Perch code only on the private listener, token binding in
// both directions, window binding to the first listener, 401 with WWW-Authenticate, the rights choice,
// compatibility of old tokens and devices, and perch connect for every target. Real listeners on 127.0.0.1,
// MOCK Google and MOCK client metadata only; nothing leaves the machine and every secret is dummy data.
import { auth, type OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { readFile, stat } from 'node:fs/promises';
import { ClientResolver } from '../src/access/clients.js';
import { connectControl } from '../src/access/control.js';
import { request } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { derivePrivateBaseUrl } from '../src/access/baseUrl.js';
import type { PairEvent } from '../src/access/pairing.js';
import { startAccess, type Access } from '../src/access/runtime.js';
import { OAuthStore, type ListenerKind } from '../src/access/state.js';
import { hotp, totpStep } from '../src/access/totp.js';
import { createClientGrant, createDeviceGrant } from '../src/auth/grants.js';
import { confirmText } from '../src/cli/oauth.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { resolveConfig } from '../src/config.js';
import { createPerchContext, type PerchContext } from '../src/context.js';
import { generateHttpToken, startHttpServer, type RunningHttpServer } from '../src/mcp/http.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream, type UpstreamTransport } from '../src/upstream.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';
import { authorizeUrl, BASE, CLAUDE_CALLBACK, CLAUDE_CODE_CIMD, cookieFrom, csrfOf, form, GOOGLE, HOST, HOSTED_CIMD, idToken, OPERATOR, pkce, waitFor, writeWebClientFile } from './support/publicAccessFixtures.js';

const CODEX_CIMD = 'https://chatgpt.com/oauth/codex/client.json';
const PRIV_HOST = 'homeserver.tailnet-test.ts.net';
const PRIV = `https://${PRIV_HOST}`;
const CC_REDIRECT = 'http://localhost:53682/callback';

let dirs: TempDirs;
let store: CredentialStore;
let context: PerchContext;
let transport: UpstreamTransport;
let upstreamCalls: string[];
let google: { nonce?: string };
let access: Access;
let local: RunningHttpServer;
let globalToken: string;
let events: PairEvent[];
let logs: string[];

interface Res {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  location?: string;
}

function http(port: number, method: string, p: string, o: { body?: string; cookie?: string; headers?: Record<string, string>; host: string; type?: string }): Promise<Res> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { host: o.host, ...(o.headers ?? {}) };
    if (o.cookie) headers.cookie = o.cookie;
    if (o.body !== undefined) {
      headers['content-type'] ??= o.type ?? 'application/x-www-form-urlencoded';
      headers['content-length'] = String(Buffer.byteLength(o.body));
    }
    const req = request({ host: '127.0.0.1', port, method, path: p, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), ...(res.headers.location ? { location: res.headers.location } : {}) }));
    });
    req.on('error', reject);
    if (o.body !== undefined) req.write(o.body);
    req.end();
  });
}
/** The private listener as reached through Tailscale Serve (Host = the tailnet name). */
const priv = (method: string, p: string, o: { body?: string; cookie?: string; headers?: Record<string, string>; host?: string; type?: string } = {}) =>
  http(local.port, method, p, { host: PRIV_HOST, ...o });
const pub = (method: string, p: string, o: { body?: string; cookie?: string; headers?: Record<string, string>; type?: string } = {}) => http(access.publicServer!.port, method, p, { host: HOST, ...o });

const privAuthorize = (challenge: string, o: { clientId?: string; redirectUri?: string } = {}) =>
  authorizeUrl({ challenge, clientId: o.clientId ?? CLAUDE_CODE_CIMD, redirectUri: o.redirectUri ?? CC_REDIRECT, resource: `${PRIV}/mcp` });

/** Opens a window for ONE listener (default private); `answer` decides the confirmation (manual: the test answers). */
function openWindow(answer: { approve: boolean; access?: 'read' | 'full' } | 'manual' = { approve: true }, listener: ListenerKind = 'private'): string {
  events = [];
  const { code } = access.pairing.open(
    (ev) => {
      events.push(ev);
      if (ev.type === 'confirm' && answer !== 'manual') queueMicrotask(() => access.pairing.answer(answer.approve, access.pairing.windowId!, ev.confirmId, answer.access ?? 'read'));
    },
    listener,
  );
  return code;
}

/** Private browser flow: authorize, pairing code, wait for the confirmation, redirect with the code. */
async function privateFlow(pairCode: string, o: { clientId?: string; redirectUri?: string } = {}) {
  const { verifier, challenge } = pkce();
  const a = await priv('GET', privAuthorize(challenge, o), { headers: { 'user-agent': 'Claude-Code-Test/1.0' } });
  expect(a.status, a.body).toBe(303);
  expect(a.location).toBe('/oauth/pair');
  const cookie = cookieFrom(a)!;
  const p = await priv('GET', '/oauth/pair', { cookie });
  expect(p.body).toContain('No Google sign-in');
  const c = await priv('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code: pairCode }), headers: { origin: PRIV } });
  return { cookie, verifier, codeStep: c };
}

async function privateExchange(cookie: string, verifier: string, o: { clientId?: string; redirectUri?: string } = {}) {
  await waitFor(() => events.some((e) => e.type === 'paired' || e.type === 'closed'));
  const w = await priv('GET', '/oauth/wait', { cookie });
  expect(w.status).toBe(303);
  const redirect = new URL(w.location!);
  expect(redirect.searchParams.get('iss')).toBe(PRIV);
  const tok = await priv('POST', '/oauth/token', {
    body: form({ grant_type: 'authorization_code', code: redirect.searchParams.get('code')!, redirect_uri: o.redirectUri ?? CC_REDIRECT, client_id: o.clientId ?? CLAUDE_CODE_CIMD, code_verifier: verifier }),
  });
  expect(tok.status, tok.body).toBe(200);
  return JSON.parse(tok.body) as Record<string, string>;
}

async function pairPrivate(answer: { approve: boolean; access?: 'read' | 'full' } = { approve: true }) {
  const code = openWindow(answer);
  const r = await privateFlow(code);
  expect(r.codeStep.location).toBe('/oauth/wait');
  const tokens = await privateExchange(r.cookie, r.verifier);
  const paired = events.find((e) => e.type === 'paired') as Extract<PairEvent, { type: 'paired' }>;
  return { tokens, deviceId: paired.deviceId };
}

/** Public browser flow (pairing code, MOCK Google, Perch code), confirmation approved by openWindow. */
async function pairPublic() {
  const code = openWindow({ approve: true }, 'public');
  const { verifier, challenge } = pkce();
  const a = await pub('GET', authorizeUrl({ challenge }));
  const cookie = cookieFrom(a)!;
  const p = await pub('GET', '/oauth/pair', { cookie });
  const g = await pub('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code }) });
  const gu = new URL(g.location!);
  google.nonce = gu.searchParams.get('nonce')!;
  await pub('GET', `/oauth/google/callback?state=${encodeURIComponent(gu.searchParams.get('state')!)}&code=google-code-0123456789`, { cookie });
  const t = await pub('GET', '/oauth/totp', { cookie });
  const secret = Buffer.from((await new OAuthStore(store).read()).totp!.secret, 'base64');
  await pub('POST', '/oauth/totp', { cookie, body: form({ csrf: csrfOf(t.body), code: hotp(secret, totpStep(Date.now()) + 1) }) });
  await waitFor(() => events.some((e) => e.type === 'paired' || e.type === 'closed'));
  const w = await pub('GET', '/oauth/wait', { cookie });
  const tok = await pub('POST', '/oauth/token', {
    body: form({ grant_type: 'authorization_code', code: new URL(w.location!).searchParams.get('code')!, redirect_uri: CLAUDE_CALLBACK, client_id: HOSTED_CIMD, code_verifier: verifier }),
  });
  return JSON.parse(tok.body) as Record<string, string>;
}

const rpc = (method: string) => JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: {} });
const mcpHeaders = (token: string) => ({ 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${token}` });
const toolsOf = (r: Res) => (JSON.parse(r.body) as { result: { tools: Array<{ name: string }> } }).result.tools.map((t) => t.name);

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  google = {};
  upstreamCalls = [];
  logs = [];
  transport = async (req) => {
    upstreamCalls.push(`${req.method} ${req.url.origin}${req.url.pathname}`);
    const json = (status: number, body: unknown) => ({ status, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(body)) });
    if (req.url.origin === 'https://oauth2.googleapis.com') {
      const t = Math.floor(Date.now() / 1000);
      return json(200, { id_token: idToken({ iss: 'https://accounts.google.com', aud: GOOGLE.clientId, sub: OPERATOR.sub, email: OPERATOR.email, email_verified: true, iat: t, exp: t + 3600, nonce: google.nonce }) });
    }
    const url = `${req.url.origin}${req.url.pathname}`;
    if (url === CODEX_CIMD) return json(200, { client_id: CODEX_CIMD, client_name: 'Codex', redirect_uris: ['http://127.0.0.1/callback', 'http://localhost/callback'], token_endpoint_auth_method: 'none' });
    if (url === HOSTED_CIMD) return json(200, { client_id: HOSTED_CIMD, client_name: 'Claude', redirect_uris: [CLAUDE_CALLBACK] });
    if (url === CLAUDE_CODE_CIMD) return json(200, { client_id: CLAUDE_CODE_CIMD, client_name: 'Claude Code', redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'], token_endpoint_auth_method: 'none' });
    return json(404, {});
  };
  // Public access set up (Google allowlist + Perch code), so both listeners can pair.
  const oauth = new OAuthStore(store);
  await oauth.transact((d) => {
    d.loginAllow.push({ email: OPERATOR.email, addedAt: new Date().toISOString() });
    d.totp = { secret: Buffer.alloc(20, 7).toString('base64'), createdAt: new Date().toISOString(), recovery: [] };
  });
  context = createPerchContext(store, transport);
  access = await startAccess({
    context,
    upstream: new Upstream(transport),
    privateBaseUrl: PRIV,
    public: { baseUrl: BASE, port: 0, googleClient: GOOGLE },
    dcrEnabled: true,
    trustForwarded: false,
    log: (l) => logs.push(l),
  });
  globalToken = generateHttpToken();
  local = await startHttpServer({ host: '127.0.0.1', port: 0, token: globalToken, context, oauth: access.privateOAuth!, localPair: access.localPair, allowedHosts: [PRIV_HOST], log: (l) => logs.push(l) });
});
afterEach(async () => {
  await local.close();
  await access.close();
  await dirs.cleanup();
});

describe('private OAuth: discovery and issuer', () => {
  it('serves its own issuer and resource, separate from the public one', async () => {
    const prm = JSON.parse((await priv('GET', '/.well-known/oauth-protected-resource')).body);
    expect(prm).toMatchObject({ resource: `${PRIV}/mcp`, authorization_servers: [PRIV] });
    const as = JSON.parse((await priv('GET', '/.well-known/oauth-authorization-server')).body);
    expect(as).toMatchObject({ issuer: PRIV, authorization_endpoint: `${PRIV}/oauth/authorize`, token_endpoint: `${PRIV}/oauth/token`, registration_endpoint: `${PRIV}/oauth/register`, client_id_metadata_document_supported: true });
    const pubAs = JSON.parse((await pub('GET', '/.well-known/oauth-authorization-server')).body);
    expect(pubAs.issuer).toBe(BASE);
    expect(pubAs.issuer).not.toBe(as.issuer);
  });

  it('answers 401 on /mcp with WWW-Authenticate pointing at the private resource metadata', async () => {
    const r = await priv('POST', '/mcp', { body: rpc('tools/list'), type: 'application/json' });
    expect(r.status).toBe(401);
    expect(r.headers['www-authenticate']).toBe(`Bearer realm="perch", resource_metadata="${PRIV}/.well-known/oauth-protected-resource", scope="perch.read"`);
    const bad = await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders('Z'.repeat(43)) });
    expect(bad.status).toBe(401);
    expect(bad.headers['www-authenticate']).toMatch(/error="invalid_token"/);
  });

  it('has no Google or Perch-code routes, and no OAuth on a loopback Host name', async () => {
    expect((await priv('GET', '/oauth/google/callback?state=x&code=y')).status).not.toBe(200);
    expect((await priv('GET', '/oauth/totp')).status).not.toBe(200);
    const loop = await priv('GET', '/.well-known/oauth-authorization-server', { host: `127.0.0.1:${local.port}` });
    expect(loop.status).toBe(404);
    // A Host outside the allowlist is still refused before anything else.
    expect((await priv('GET', '/.well-known/oauth-authorization-server', { host: 'evil.example' })).status).toBe(403);
  });

  it('without a window: the fixed page, no metadata fetch, registration closed', async () => {
    const { challenge } = pkce();
    const r = await priv('GET', privAuthorize(challenge));
    expect(r.status).toBe(403);
    expect(r.body).toContain('No pairing window is open');
    expect((await priv('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ redirect_uris: ['http://127.0.0.1/cb'] }) })).status).toBe(403);
    expect(upstreamCalls).toEqual([]);
  });
});

describe('private pairing', () => {
  it('pairs without Google and without a Perch code, after the terminal confirmation, with details', async () => {
    const { tokens, deviceId } = await pairPrivate();
    expect(upstreamCalls.some((c) => c.includes('googleapis'))).toBe(false);
    const confirm = events.find((e) => e.type === 'confirm') as Extract<PairEvent, { type: 'confirm' }>;
    expect(confirm.details).toMatchObject({ origin: 'private', clientName: 'Claude Code', redirectHost: 'localhost:53682', userAgent: 'Claude-Code-Test/1.0', ip: '127.0.0.1' });
    expect(confirm.details.googleEmail).toBeUndefined();
    const dev = (await new OAuthStore(store).read()).devices.find((d) => d.id === deviceId)!;
    expect(dev).toMatchObject({ origin: 'private', status: 'active' });
    expect(dev.googleEmail).toBeUndefined();
    const list = await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(tokens.access_token!) });
    expect(list.status).toBe(200);
    expect(toolsOf(list)).toContain('drive_search');
    expect(events.some((e) => e.type === 'first_use')).toBe(true);
    // Refresh works on the private issuer.
    const ref = await priv('POST', '/oauth/token', { body: form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: CLAUDE_CODE_CIMD }) });
    expect(ref.status).toBe(200);
  });

  it('gives no code without the operator\'s yes; a no closes the window', async () => {
    const code = openWindow('manual');
    const r = await privateFlow(code);
    expect(r.codeStep.location).toBe('/oauth/wait');
    await waitFor(() => events.some((e) => e.type === 'confirm'));
    const waiting = await priv('GET', '/oauth/wait', { cookie: r.cookie });
    expect(waiting.status).toBe(200);
    expect(waiting.body).toContain('Confirm in your terminal');
    const c = events.find((e) => e.type === 'confirm') as Extract<PairEvent, { type: 'confirm' }>;
    access.pairing.answer(false, access.pairing.windowId!, c.confirmId);
    expect(access.pairing.isOpen).toBe(false);
    expect((await priv('GET', '/oauth/wait', { cookie: r.cookie })).status).toBe(403);
    expect((await new OAuthStore(store).read()).devices).toEqual([]);
  });

  it('keeps the pairing code, its failure lock and the one-browser rule', async () => {
    openWindow();
    const { verifier: _v, challenge } = pkce();
    const a = await priv('GET', privAuthorize(challenge));
    const cookie = cookieFrom(a)!;
    const p = await priv('GET', '/oauth/pair', { cookie });
    for (const wrong of ['WRONG001', 'WRONG002']) {
      const r = await priv('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code: wrong }), headers: { origin: PRIV } });
      expect(r.body).toContain('Wrong pairing code');
    }
    const third = await priv('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code: 'WRONG003' }), headers: { origin: PRIV } });
    expect(third.body).toContain('pairing window was closed');
    expect(access.pairing.isOpen).toBe(false);
    // Second browser after the code: window closed, alarm.
    const code = openWindow();
    await privateFlow(code).catch(() => undefined);
    const { challenge: c2 } = pkce();
    const second = await priv('GET', privAuthorize(c2));
    expect(second.status).toBe(403);
    expect(events).toContainEqual({ type: 'alarm', kind: 'second_pairing_attempt' });
  });

  it('accepts its own origin on the sign-in forms but not a foreign one', async () => {
    const code = openWindow();
    const { challenge } = pkce();
    const a = await priv('GET', privAuthorize(challenge));
    const cookie = cookieFrom(a)!;
    const p = await priv('GET', '/oauth/pair', { cookie });
    const evil = await priv('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code }), headers: { origin: 'https://evil.example' } });
    expect(evil.status).toBe(403);
    // The issuer origin is accepted on /oauth/* only, never on /mcp.
    const m = await priv('POST', '/mcp', { body: rpc('tools/list'), headers: { ...mcpHeaders(globalToken), origin: PRIV } });
    expect(m.status).toBe(403);
  });

  it('applies the rights chosen at the confirmation: full access gets a full grant before the code', async () => {
    const read = await pairPrivate({ approve: true, access: 'read' });
    const readTools = toolsOf(await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(read.tokens.access_token!) }));
    const full = await pairPrivate({ approve: true, access: 'full' });
    const dev = (await new OAuthStore(store).read()).devices.find((d) => d.id === full.deviceId)!;
    expect(dev.grantClientId).toMatch(/^client-[a-f0-9]{8}$/);
    expect((await store.read()).clients.find((c) => c.id === dev.grantClientId)).toMatchObject({ full: true });
    const fullTools = toolsOf(await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(full.tokens.access_token!) }));
    expect(fullTools.length).toBeGreaterThan(readTools.length);
    expect(events.find((e) => e.type === 'paired')).toMatchObject({ origin: 'private', access: 'full' });
  });

  it('the local pairing page pairs a private device read only and shows the terminal command for full access', async () => {
    const env = { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root };
    let out = '';
    expect(await runCli(['oauth', 'local-page', 'enable'], { env, stdout: (s) => (out += s), stderr: () => {}, readSecret: async () => '' })).toBe(0);
    const password = /Password \(any user name; shown once, a new enable replaces it\): (\S+)/.exec(out)![1]!;
    const lp = { host: `127.0.0.1:${local.port}`, headers: { authorization: `Basic ${Buffer.from(`perch:${password}`).toString('base64')}` } };
    const post = (csrf: string, action: string) =>
      http(local.port, 'POST', '/local/pair', { ...lp, body: form({ csrf, action }), headers: { ...lp.headers, origin: `http://127.0.0.1:${local.port}` } });
    const idle = await http(local.port, 'GET', '/local/pair', lp);
    expect(idle.body).toContain('Open a window for the private address (tailnet)');
    expect(idle.body).toContain('Open a window for the public address (internet)');
    expect((await post(csrfOf(idle.body), 'open_private')).status).toBe(303);
    const open = await http(local.port, 'GET', '/local/pair', lp);
    const code = /class="mono code">([A-Z2-7]{8})</.exec(open.body)![1]!;
    expect(open.body).toContain(`${PRIV}/mcp`);
    expect(open.body).toContain('Only for the private address (tailnet)');
    expect(open.body).not.toContain(`${BASE}/mcp`);
    events = [];
    const r = await privateFlow(code);
    expect(r.codeStep.location).toBe('/oauth/wait');
    let confirm = '';
    for (let i = 0; i < 100 && !confirm.includes('Pair: read only'); i++) {
      confirm = (await http(local.port, 'GET', '/local/pair', lp)).body;
      if (!confirm.includes('Pair: read only')) await new Promise((res) => setTimeout(res, 20));
    }
    expect(confirm).toContain('Pair: read only');
    expect(confirm).not.toContain('Pair: full access');
    expect(confirm).toContain('private (tailnet)');
    expect(confirm).not.toContain('Google account');
    // Full access is never approved on the page (its password is only a pairing credential).
    expect((await post(csrfOf(confirm), 'approve_full')).status).toBe(303);
    expect(access.pairing.isOpen).toBe(true);
    expect((await new OAuthStore(store).read()).devices).toEqual([]);
    const again = (await http(local.port, 'GET', '/local/pair', lp)).body;
    expect(again).toContain('Full access cannot be approved on this page');
    expect((await post(csrfOf(again), 'approve')).status).toBe(303);
    let w = await priv('GET', '/oauth/wait', { cookie: r.cookie });
    for (let i = 0; i < 100 && w.status !== 303; i++) {
      await new Promise((res) => setTimeout(res, 20));
      w = await priv('GET', '/oauth/wait', { cookie: r.cookie });
    }
    expect(w.status).toBe(303);
    const dev = (await new OAuthStore(store).read()).devices.at(-1)!;
    expect(dev.origin).toBe('private');
    expect(dev.grantClientId).toBeUndefined();
    const done = (await http(local.port, 'GET', '/local/pair', lp)).body;
    expect(done).toContain(`Paired ${dev.id} (read only)`);
    expect(done).toContain(`perch oauth grant ${dev.id} --full`);
  });

  it('audits the pairing steps with their origin and without secrets', async () => {
    const { tokens } = await pairPrivate();
    const ledger = (await context.audit.list()).events;
    const paired = ledger.find((e) => e.type === 'oauth_device_paired')!;
    expect(paired.actor).toMatchObject({ kind: 'oauth', origin: 'private' });
    expect(ledger.find((e) => e.type === 'oauth_pair_code')!.actor).toMatchObject({ origin: 'private' });
    expect(JSON.stringify(ledger)).not.toContain(tokens.access_token!);
    expect(JSON.stringify(ledger)).not.toContain(tokens.refresh_token!);
  });
});

describe('token and window binding', () => {
  it('a private token works only on the private /mcp, a public token only on the public /mcp', async () => {
    const p = await pairPrivate();
    const q = await pairPublic();
    expect(q.access_token).toBeDefined();
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(p.tokens.access_token!) })).status).toBe(200);
    expect((await pub('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(q.access_token!) })).status).toBe(200);
    // Crossed: refused in both directions.
    expect((await pub('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(p.tokens.access_token!) })).status).toBe(401);
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(q.access_token!) })).status).toBe(401);
    // Refresh tokens cannot cross either.
    expect((await pub('POST', '/oauth/token', { body: form({ grant_type: 'refresh_token', refresh_token: p.tokens.refresh_token! }) })).body).toContain('invalid_grant');
    expect((await priv('POST', '/oauth/token', { body: form({ grant_type: 'refresh_token', refresh_token: q.refresh_token! }) })).body).toContain('invalid_grant');
    // Both devices are still active (a crossed token is not a reuse).
    expect((await new OAuthStore(store).read()).devices.every((d) => d.status === 'active')).toBe(true);
  });

  it('an authorization code of the private issuer is refused by the public token endpoint (without burning it)', async () => {
    const code = openWindow();
    const r = await privateFlow(code);
    await waitFor(() => events.some((e) => e.type === 'paired'));
    const w = await priv('GET', '/oauth/wait', { cookie: r.cookie });
    const authCode = new URL(w.location!).searchParams.get('code')!;
    const exchangeAt = (send: typeof pub) => send('POST', '/oauth/token', { body: form({ grant_type: 'authorization_code', code: authCode, redirect_uri: CC_REDIRECT, client_id: CLAUDE_CODE_CIMD, code_verifier: r.verifier }) });
    expect((await exchangeAt(pub)).body).toContain('invalid_grant');
    expect((await exchangeAt(priv)).status).toBe(200);
  });

  it('a private window serves the private listener only: no sign-in, no registration over the public one', async () => {
    openWindow();
    expect(access.pairing.isOpenFor('private')).toBe(true);
    expect(access.pairing.isOpenFor('public')).toBe(false);
    const { challenge } = pkce();
    const r = await pub('GET', authorizeUrl({ challenge }));
    expect(r.status).toBe(403);
    expect(r.body).toContain('No pairing window is open');
    expect((await pub('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ redirect_uris: ['http://127.0.0.1/cb'] }) })).status).toBe(403);
  });

  it('a public window serves the public listener only', async () => {
    openWindow({ approve: true }, 'public');
    expect(access.pairing.isOpenFor('private')).toBe(false);
    const { challenge } = pkce();
    const r = await priv('GET', privAuthorize(challenge));
    expect(r.status).toBe(403);
    expect(r.body).toContain('No pairing window is open');
    expect((await priv('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ redirect_uris: ['http://127.0.0.1/cb'] }) })).status).toBe(403);
  });
});

describe('compatibility', () => {
  it('the global token and client tokens keep working on the private /mcp', async () => {
    const g = await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(globalToken) });
    expect(g.status).toBe(200);
    const loop = await http(local.port, 'POST', '/mcp', { host: `127.0.0.1:${local.port}`, body: rpc('tools/list'), headers: mcpHeaders(globalToken) });
    expect(loop.status).toBe(200);
    const tokenFile = `${dirs.root}/config/clients/agent.token`;
    await createClientGrant(store, { label: 'Agent', capabilities: [], accountIds: [], tokenFile, readAll: true });
    const clientToken = (await readFile(tokenFile, 'utf8')).trim();
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(clientToken) })).status).toBe(200);
  });

  it('an old device record without origin is public: it works on the public /mcp only', async () => {
    const q = await pairPublic();
    await new OAuthStore(store).transact((d) => {
      for (const dev of d.devices) delete dev.origin;
    });
    expect((await new OAuthStore(store).read()).devices[0]!.origin).toBeUndefined();
    expect((await pub('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(q.access_token!) })).status).toBe(200);
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(q.access_token!) })).status).toBe(401);
  });

  it('perch public off signs out public devices only; revoke --private-all the private ones', async () => {
    const p = await pairPrivate();
    const q = await pairPublic();
    const env = { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, PERCH_PUBLIC_BASE_URL: BASE, HOME: dirs.root };
    const io = (): CliIo & { out: () => string } => {
      let out = '';
      return { env, stdout: (s) => (out += s), stderr: (s) => (out += s), readSecret: async () => '', out: () => out };
    };
    const off = io();
    expect(await runCli(['public', 'off'], off)).toBe(0);
    expect(off.out()).toMatch(/1 public device\(s\) were signed out/);
    expect((await pub('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(q.access_token!) })).status).toBe(503);
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(p.tokens.access_token!) })).status).toBe(200);
    // The kill switch does not block private pairing.
    const devices = io();
    await runCli(['oauth', 'devices'], devices);
    expect(devices.out()).toMatch(/oc-[a-f0-9]{16} {2}active {2}private {2}read only/);
    expect(devices.out()).toMatch(/oc-[a-f0-9]{16} {2}revoked \(kill_switch\) {2}public/);
    const rev = io();
    expect(await runCli(['oauth', 'revoke', '--private-all'], rev)).toBe(0);
    expect(rev.out()).toMatch(/Revoked 1 private device/);
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(p.tokens.access_token!) })).status).toBe(401);
  });

  it('the kill switch closes a public window but never a private one; private pairing still works', async () => {
    openWindow({ approve: true }, 'public');
    access.pairing.lockout('kill_switch');
    expect(access.pairing.isOpen).toBe(false);
    await new OAuthStore(store).transact((d) => void (d.publicLocked = { since: new Date().toISOString() }));
    const code = openWindow();
    access.pairing.lockout('kill_switch');
    access.pairing.lockout('totp_lockout');
    expect(access.pairing.isOpenFor('private')).toBe(true);
    const r = await privateFlow(code);
    expect(r.codeStep.location).toBe('/oauth/wait');
    await privateExchange(r.cookie, r.verifier);
  });
});

describe('configuration', () => {
  it('derives the private base URL from the first tailnet name in PERCH_ALLOWED_HOSTS', () => {
    expect(derivePrivateBaseUrl(undefined, ['127.0.0.1:8765', '100.101.102.103', 'homeserver.tail1.ts.net:8443'])).toEqual({ url: 'https://homeserver.tail1.ts.net:8443', source: 'allowed_hosts' });
    expect(derivePrivateBaseUrl(undefined, ['localhost:8765'])).toBeNull();
    expect(derivePrivateBaseUrl('https://perch.tail1.ts.net', [])).toEqual({ url: 'https://perch.tail1.ts.net', source: 'env' });
    expect(() => derivePrivateBaseUrl('http://perch.tail1.ts.net', [])).toThrow(/PERCH_PRIVATE_BASE_URL/);
    const c = resolveConfig({ HOME: '/nonexistent', PERCH_ALLOWED_HOSTS: 'homeserver.tail1.ts.net' });
    expect(c.privateBaseUrl).toBe('https://homeserver.tail1.ts.net');
    expect(() => resolveConfig({ HOME: '/nonexistent', PERCH_PRIVATE_BASE_URL: BASE, PERCH_PUBLIC_BASE_URL: BASE })).toThrow(/must differ/);
    expect(resolveConfig({ HOME: '/nonexistent', PERCH_ALLOWED_HOSTS: HOST, PERCH_PUBLIC_BASE_URL: BASE }).privateBaseUrl).toBeUndefined();
  });
});

// ------------------------------------------------------------------ perch connect

/** Lines over 80 columns are allowed only when they carry a URL or a command to copy. */
const overlong = (text: string) =>
  text
    .split('\n')
    .filter((l) => l.length > 80)
    .filter((l) => !/:\/\//.test(l) && !/^\s+(sudo|perch|claude|codex|url =|"perch")/.test(l) && !/^\s+\/\S+$/.test(l));

describe('perch connect', () => {
  const connectEnv = (extra: Record<string, string> = {}) => ({
    PERCH_DATA_DIR: dirs.dataDir,
    PERCH_KEY_FILE: dirs.keyFile,
    PERCH_HTTP_TOKEN_FILE: dirs.tokenFile,
    PERCH_ALLOWED_HOSTS: PRIV_HOST,
    HOME: dirs.root,
    ...extra,
  });
  const cio = (env: Record<string, string>, answers: (prompt: string) => string = () => ''): CliIo & { out: () => string; prompts: string[] } => {
    let out = '';
    const prompts: string[] = [];
    return {
      env,
      stdout: (s) => (out += s),
      stderr: (s) => (out += s),
      readSecret: async () => '',
      readLine: async (p) => {
        prompts.push(p);
        out += p;
        return answers(p);
      },
      out: () => out,
      prompts,
    };
  };

  it('prints the private address and the exact commands for Claude Code and Codex', async () => {
    const cc = cio(connectEnv());
    expect(await runCli(['connect', '--target', 'claude-code', '--no-pair'], cc)).toBe(0);
    expect(cc.out()).toContain(`claude mcp add --scope user --transport http perch ${PRIV}/mcp`);
    expect(cc.out()).toContain('/mcp');
    expect(cc.out()).toContain('perch oauth pair');
    expect(overlong(cc.out())).toEqual([]);
    const cx = cio(connectEnv());
    expect(await runCli(['connect', '--target', 'codex', '--no-pair'], cx)).toBe(0);
    expect(cx.out()).toContain(`codex mcp add perch --url ${PRIV}/mcp`);
    expect(cx.out()).toContain('codex mcp login perch');
    expect(cx.out()).toContain(`url = "${PRIV}/mcp"`);
    expect(overlong(cx.out())).toEqual([]);
  });

  it('claude.ai and ChatGPT need the public access: a hint when it is missing, the public address when it is ready', async () => {
    for (const target of ['claude-ai', 'chatgpt']) {
      const missing = cio(connectEnv(), () => 'n');
      expect(await runCli(['connect', '--target', target, '--no-pair'], missing)).toBe(1);
      expect(missing.prompts).toEqual(['Set it up now? [Y/n] ']);
      expect(missing.out()).toContain('perch public setup');
      expect(overlong(missing.out())).toEqual([]);
      const ready = cio(connectEnv({ PERCH_PUBLIC_BASE_URL: BASE, PERCH_GOOGLE_LOGIN_CLIENT_FILE: await writeWebClientFile(`${dirs.root}/google-login.json`) }));
      expect(await runCli(['connect', '--target', target, '--no-pair'], ready)).toBe(0);
      expect(ready.out()).toContain(`${BASE}/mcp`);
      expect(ready.out()).not.toContain(PRIV);
      expect(overlong(ready.out())).toEqual([]);
    }
  });

  it('desktop and other clients get the private address and the fallbacks', async () => {
    const d = cio(connectEnv());
    expect(await runCli(['connect', '--target', 'desktop', '--no-pair'], d)).toBe(0);
    expect(d.out()).toContain(`"args": ["mcp-remote", "${PRIV}/mcp"]`);
    expect(overlong(d.out())).toEqual([]);
    const o = cio(connectEnv());
    expect(await runCli(['connect', '--target', 'other', '--no-pair'], o)).toBe(0);
    expect(o.out()).toContain(`${PRIV}/mcp`);
    expect(o.out()).toContain('perch client add --label NAME --read-all');
    expect(overlong(o.out())).toEqual([]);
  });

  it('without a private address it says how to set one (Claude Code)', async () => {
    const io = cio(connectEnv({ PERCH_ALLOWED_HOSTS: '' }));
    expect(await runCli(['connect', '--target', 'claude-code', '--no-pair'], io)).toBe(1);
    expect(io.out()).toContain('PERCH_ALLOWED_HOSTS');
    expect(overlong(io.out())).toEqual([]);
  });

  it('server agent: a client grant with a 0600 token file and generic connection instructions; the token is never printed', async () => {
    const io = cio(connectEnv(), (p) => (/\[f\]ull/.test(p) ? 'r' : ''));
    expect(await runCli(['connect', '--target', 'server-agent'], io)).toBe(0);
    const file = /Token file[^\n]*\n {2}(\S+)/.exec(io.out())![1]!;
    expect((await stat(file)).mode & 0o777).toBe(0o600);
    const token = (await readFile(file, 'utf8')).trim();
    expect(token.length).toBeGreaterThanOrEqual(43);
    expect(io.out()).not.toContain(token);
    expect(io.out()).toContain('PERCH_CLIENT_TOKEN_FILE');
    expect(io.out()).not.toContain('/home/example-agent/');
    const client = (await store.read()).clients.at(-1)!;
    expect(client).toMatchObject({ readAll: true });
    expect(client.full).toBeUndefined();
    expect(overlong(io.out())).toEqual([]);
    // --full without a prompt.
    const full = cio(connectEnv());
    expect(await runCli(['connect', '--target', 'server-agent', '--full', '--label', 'friagent'], full)).toBe(0);
    expect((await store.read()).clients.at(-1)).toMatchObject({ label: 'friagent', full: true });
    expect(full.prompts).toEqual([]);
  });

  it('asks interactively for the AI and rejects an unknown target', async () => {
    const io = cio(connectEnv(), (p) => (p.startsWith('Choice') ? '2' : 'n'));
    expect(await runCli(['connect'], io)).toBe(0);
    expect(io.out()).toContain('Which AI do you want to connect to Perch?');
    expect(io.out()).toContain('codex mcp add');
    expect(io.prompts.some((p) => /Open a pairing window now\? \[Y\/n\]/.test(p))).toBe(true);
    expect(io.out()).toContain('Pairing address: private.');
    expect(overlong(io.out())).toEqual([]);
    expect(await runCli(['connect', '--target', 'nope'], cio(connectEnv()))).not.toBe(0);
  });

  it('pairs Claude Code end to end: connect opens the window, the browser pairs privately, the terminal confirms', async () => {
    const io = cio(connectEnv(), (p) => (/Pair this device/.test(p) ? 'y' : /\[f\]ull/.test(p) ? 'r' : ''));
    const run = runCli(['connect', '--target', 'claude-code'], io);
    await waitFor(() => /Pairing code: {2}([A-Z2-7]{8})/.test(io.out()));
    const code = /Pairing code: {2}([A-Z2-7]{8})/.exec(io.out())![1]!;
    expect(io.out()).toContain(`private (tailnet):  ${PRIV}/mcp`);
    expect(io.out()).toContain('Pairing window for the PRIVATE address (tailnet)');
    expect(io.out()).not.toContain(`${BASE}/mcp`);
    // The control socket opened the window; the test drives the browser side.
    events = [];
    const { verifier, challenge } = pkce();
    const a = await priv('GET', privAuthorize(challenge));
    const cookie = cookieFrom(a)!;
    const p = await priv('GET', '/oauth/pair', { cookie });
    expect((await priv('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code }), headers: { origin: PRIV } })).location).toBe('/oauth/wait');
    await waitFor(() => io.out().includes('Paired device'));
    expect(io.out()).toContain('A device wants to pair over the PRIVATE address (tailnet)');
    expect(io.out()).toMatch(/Source: {10}127\.0\.0\.1 \(loopback/);
    expect(io.out()).not.toContain('Google account:');
    const w = await priv('GET', '/oauth/wait', { cookie });
    const tok = await priv('POST', '/oauth/token', {
      body: form({ grant_type: 'authorization_code', code: new URL(w.location!).searchParams.get('code')!, redirect_uri: CC_REDIRECT, client_id: CLAUDE_CODE_CIMD, code_verifier: verifier }),
    });
    const access_token = (JSON.parse(tok.body) as { access_token: string }).access_token;
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(access_token) })).status).toBe(200);
    expect(await run).toBe(0);
    expect(io.out()).toMatch(/First request from oc-[a-f0-9]{16} received/);
    expect(overlong(io.out())).toEqual([]);
  });
});

// ------------------------------------------------------------------ security review (M1, M2, L1–L5, L7)

describe('security review fixes', () => {
  const cliEnv = (extra: Record<string, string> = {}) => ({
    PERCH_DATA_DIR: dirs.dataDir,
    PERCH_KEY_FILE: dirs.keyFile,
    PERCH_HTTP_TOKEN_FILE: dirs.tokenFile,
    PERCH_ALLOWED_HOSTS: PRIV_HOST,
    HOME: dirs.root,
    ...extra,
  });
  const cio = (env: Record<string, string>, answers: (prompt: string) => string = () => ''): CliIo & { out: () => string } => {
    let out = '';
    return { env, stdout: (s) => (out += s), stderr: (s) => (out += s), readSecret: async () => '', readLine: async (p) => ((out += p), answers(p)), out: () => out };
  };
  /** Opens a window over the control socket (as perch oauth pair does) and returns the first answer. */
  async function controlOpen(listener?: ListenerKind): Promise<{ msg: Record<string, unknown>; close: () => void }> {
    const ctl = await connectControl(dirs.dataDir);
    const msgs: Array<Record<string, unknown>> = [];
    ctl.onMessage((m) => msgs.push(m));
    ctl.send({ op: 'open', ...(listener ? { listener } : {}) });
    await waitFor(() => msgs.length > 0);
    return { msg: msgs[0]!, close: () => ctl.socket.end() };
  }
  const closedNow = async () => waitFor(() => !access.pairing.isOpen);

  // M1 ------------------------------------------------------------
  it('M1: a window serves exactly one listener; default private, --public on request', async () => {
    const def = await controlOpen();
    expect(def.msg).toMatchObject({ type: 'opened', listener: 'private', url: `${PRIV}/mcp` });
    expect(def.msg.urls).toBeUndefined();
    expect(String((def.msg.notes as string[])[0])).toContain('perch oauth pair --public');
    expect(access.pairing.isOpenFor('public')).toBe(false);
    def.close();
    await closedNow();
    const pubWin = await controlOpen('public');
    expect(pubWin.msg).toMatchObject({ type: 'opened', listener: 'public', url: `${BASE}/mcp` });
    expect(access.pairing.isOpenFor('private')).toBe(false);
    pubWin.close();
    await closedNow();
  });

  it('M1: only the listener that can pair is used; a requested listener that cannot pair is refused', async () => {
    await new OAuthStore(store).transact((d) => void (d.publicLocked = { since: new Date().toISOString() }));
    const refused = await controlOpen('public');
    expect(refused.msg.type).toBe('error');
    expect(String(refused.msg.message)).toMatch(/Public address.*switched off/);
    refused.close();
    const def = await controlOpen();
    expect(def.msg).toMatchObject({ type: 'opened', listener: 'private' });
    expect(def.msg.notes).toEqual([]);
    def.close();
    await closedNow();
  });

  it('M1: code failures, sessions and registrations count per window (= per listener)', async () => {
    const code = openWindow({ approve: true }, 'public');
    // Wrong codes on the private listener are impossible: no window there, nothing counts.
    const { challenge } = pkce();
    expect((await priv('GET', privAuthorize(challenge))).status).toBe(403);
    // Three registrations on the public window; the private listener has none.
    for (let i = 0; i < 3; i++) expect((await pub('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ redirect_uris: ['http://127.0.0.1/cb'] }) })).status).toBe(201);
    expect(access.pairing.dcrRegistrations('private').size).toBe(0);
    expect(access.pairing.dcrRegistrations('public').size).toBe(3);
    access.pairing.close('aborted');
    expect(code).toMatch(/^[A-Z2-7]{8}$/);
    // Two wrong codes in a private window do not count against the next (public) window.
    const wrongTwice = async (send: typeof priv, url: string, headers: Record<string, string>) => {
      const a = await send('GET', url);
      const cookie = cookieFrom(a)!;
      const p = await send('GET', '/oauth/pair', { cookie });
      for (const wrong of ['WRONG001', 'WRONG002']) await send('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code: wrong }), headers });
    };
    openWindow();
    await wrongTwice(priv, privAuthorize(pkce().challenge), { origin: PRIV });
    expect(access.pairing.isOpen).toBe(true);
    access.pairing.close('aborted');
    openWindow({ approve: true }, 'public');
    await wrongTwice(pub, authorizeUrl({ challenge: pkce().challenge }), {});
    expect(access.pairing.isOpen).toBe(true);
    access.pairing.close('aborted');
  });

  it('M1: perch oauth pair shows the listener and refuses --private together with --public', async () => {
    const both = cio(cliEnv());
    expect(await runCli(['oauth', 'pair', '--private', '--public'], both)).not.toBe(0);
    expect(both.out()).toMatch(/either --private or --public/);
    const io = cio(cliEnv());
    const run = runCli(['oauth', 'pair', '--public'], io);
    await waitFor(() => io.out().includes('Pairing code:'));
    expect(io.out()).toContain('Pairing window for the PUBLIC address (internet)');
    expect(io.out()).toContain(`public (internet):  ${BASE}/mcp`);
    expect(io.out()).not.toContain(`${PRIV}/mcp`);
    expect(access.pairing.openListener).toBe('public');
    access.pairing.close('aborted');
    expect(await run).toBe(1);
  });

  it('M1: perch connect opens the window for the listener its target needs', async () => {
    const env = cliEnv({ PERCH_PUBLIC_BASE_URL: BASE, PERCH_GOOGLE_LOGIN_CLIENT_FILE: await writeWebClientFile(`${dirs.root}/google-login.json`) });
    for (const [target, want] of [['claude-ai', 'public'], ['chatgpt', 'public'], ['codex', 'private'], ['desktop', 'private'], ['other', 'private'], ['claude-code', 'private']] as const) {
      const io = cio(env);
      const run = runCli(['connect', '--target', target], io);
      await waitFor(() => access.pairing.isOpen || /perch: /.test(io.out()));
      expect(access.pairing.openListener, `${target}: ${io.out()}`).toBe(want);
      access.pairing.close('aborted');
      await run;
    }
    const later = cio(env);
    expect(await runCli(['connect', '--target', 'claude-ai', '--no-pair'], later)).toBe(0);
    expect(later.out()).toContain('perch oauth pair --public');
  });

  it('M1: the local page opens a window for the chosen listener only', async () => {
    let out = '';
    await runCli(['oauth', 'local-page', 'enable'], { env: cliEnv(), stdout: (s) => (out += s), stderr: () => {}, readSecret: async () => '' });
    const password = /replaces it\): (\S+)/.exec(out)![1]!;
    const lp = { host: `127.0.0.1:${local.port}`, headers: { authorization: `Basic ${Buffer.from(`x:${password}`).toString('base64')}` } };
    const idle = await http(local.port, 'GET', '/local/pair', lp);
    // Private is the default (first, primary button).
    expect(idle.body.indexOf('open_private')).toBeLessThan(idle.body.indexOf('open_public'));
    await http(local.port, 'POST', '/local/pair', { ...lp, body: form({ csrf: csrfOf(idle.body), action: 'open_public' }), headers: { ...lp.headers, origin: `http://127.0.0.1:${local.port}` } });
    expect(access.pairing.openListener).toBe('public');
    const shown = await http(local.port, 'GET', '/local/pair', lp);
    expect(shown.body).toContain('Only for the public address (internet)');
    expect(shown.body).not.toContain(`${PRIV}/mcp`);
  });

  // M2 ------------------------------------------------------------
  it('M2: the local-page password is documented as a pairing credential', async () => {
    const io = cio(cliEnv());
    expect(await runCli(['oauth', 'local-page', 'enable'], io)).toBe(0);
    expect(io.out()).toMatch(/pairing credential/);
    expect(io.out()).toMatch(/full access only in the terminal/);
  });

  // L1 ------------------------------------------------------------
  it('L1: requests with the Funnel marker never reach private OAuth, private-device tokens or the local page', async () => {
    const { tokens } = await pairPrivate();
    const funnel = { 'tailscale-funnel-request': '?1' };
    expect((await priv('GET', '/.well-known/oauth-authorization-server', { headers: funnel })).status).toBe(404);
    expect((await priv('GET', '/.well-known/oauth-protected-resource', { headers: funnel })).status).toBe(404);
    expect((await priv('POST', '/oauth/token', { headers: funnel, body: form({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token! }) })).status).toBe(404);
    const { challenge } = pkce();
    openWindow();
    expect((await priv('GET', privAuthorize(challenge), { headers: funnel })).status).toBe(404);
    access.pairing.close('aborted');
    expect((await http(local.port, 'GET', '/local/pair', { host: `127.0.0.1:${local.port}`, headers: funnel })).status).toBe(404);
    const viaFunnel = await priv('POST', '/mcp', { body: rpc('tools/list'), headers: { ...mcpHeaders(tokens.access_token!), ...funnel } });
    expect(viaFunnel.status).toBe(401);
    expect(viaFunnel.headers['www-authenticate']).toBe('Bearer realm="perch"');
    // Without the marker the same token works.
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(tokens.access_token!) })).status).toBe(200);
    expect(logs.some((l) => /Tailscale Funnel request/.test(l))).toBe(true);
  });

  it('L1: PERCH_PRIVATE_OAUTH=off switches private OAuth off; the startup logs the private issuer once', () => {
    expect(resolveConfig({ HOME: '/nonexistent', PERCH_ALLOWED_HOSTS: PRIV_HOST }).privateOAuth).toBe(true);
    const off = resolveConfig({ HOME: '/nonexistent', PERCH_ALLOWED_HOSTS: PRIV_HOST, PERCH_PRIVATE_OAUTH: 'off' });
    expect(off.privateOAuth).toBe(false);
    expect(off.privateBaseUrl).toBeUndefined();
    expect(resolveConfig({ HOME: '/nonexistent', PERCH_PRIVATE_BASE_URL: PRIV, PERCH_PRIVATE_OAUTH: 'off' }).privateBaseUrl).toBeUndefined();
    expect(() => resolveConfig({ HOME: '/nonexistent', PERCH_PRIVATE_OAUTH: 'maybe' })).toThrow(/PERCH_PRIVATE_OAUTH must be on or off/);
    expect(logs.filter((l) => l.includes(`private OAuth issuer ${PRIV}`))).toHaveLength(1);
  });

  it('L1: with PERCH_PRIVATE_OAUTH=off, perch connect says so and falls back to the public address', async () => {
    const io = cio(cliEnv({ PERCH_PRIVATE_OAUTH: 'off' }));
    expect(await runCli(['connect', '--target', 'claude-code', '--no-pair'], io)).toBe(1);
    expect(io.out()).toContain('PERCH_PRIVATE_OAUTH=off');
  });

  // L2 ------------------------------------------------------------
  it('L2: a client-set Tailscale-User-Login header is never shown as an identity', async () => {
    const code = openWindow('manual');
    const { challenge } = pkce();
    const a = await priv('GET', privAuthorize(challenge), { headers: { 'tailscale-user-login': 'boss@example.test' } });
    const cookie = cookieFrom(a)!;
    const p = await priv('GET', '/oauth/pair', { cookie });
    await priv('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code }), headers: { origin: PRIV } });
    await waitFor(() => events.some((e) => e.type === 'confirm'));
    const c = events.find((e) => e.type === 'confirm') as Extract<PairEvent, { type: 'confirm' }>;
    expect(JSON.stringify(c.details)).not.toContain('boss@example.test');
    expect(confirmText(c.details as unknown as Record<string, unknown>)).not.toMatch(/Tailnet user|boss@/);
    access.pairing.close('aborted');
  });

  // L3 ------------------------------------------------------------
  it('L3: the device is pending until the first code exchange; perch oauth devices shows it', async () => {
    const code = openWindow({ approve: true, access: 'full' });
    const r = await privateFlow(code);
    await waitFor(() => events.some((e) => e.type === 'paired'));
    const before = (await new OAuthStore(store).read()).devices[0]!;
    expect(before.status).toBe('pending');
    expect(before.grantClientId).toBeDefined();
    const list = cio(cliEnv());
    await runCli(['oauth', 'devices'], list);
    expect(list.out()).toMatch(/oc-[a-f0-9]{16} {2}pending \(code not exchanged yet\) {2}private/);
    await privateExchange(r.cookie, r.verifier);
    expect((await new OAuthStore(store).read()).devices[0]!.status).toBe('active');
  });

  it('L3: a window closed before the browser picked its code up removes the pending device and its grant', async () => {
    const code = openWindow({ approve: true, access: 'full' });
    const r = await privateFlow(code);
    await waitFor(() => events.some((e) => e.type === 'paired'));
    const grantId = (await new OAuthStore(store).read()).devices[0]!.grantClientId!;
    expect((await store.read()).clients.some((c) => c.id === grantId)).toBe(true);
    access.pairing.close('aborted');
    const gone = async () => !(await new OAuthStore(store).read()).devices.length && !(await store.read()).clients.some((c) => c.id === grantId);
    for (let i = 0; i < 100 && !(await gone()); i++) await new Promise((res) => setTimeout(res, 10));
    expect((await new OAuthStore(store).read()).devices).toEqual([]);
    expect((await store.read()).clients.some((c) => c.id === grantId)).toBe(false);
    expect((await priv('GET', '/oauth/wait', { cookie: r.cookie })).status).toBe(403);
  });

  it('L3: a failed audit write removes the pending device (and its grant); nothing is issued', async () => {
    const record = context.audit.record.bind(context.audit);
    context.audit.record = async (e) => {
      if (e.type === 'oauth_device_paired') throw new Error('MOCK: audit disk full');
      return record(e);
    };
    const code = openWindow({ approve: true, access: 'full' });
    const r = await privateFlow(code);
    await waitFor(() => events.some((e) => e.type === 'closed'));
    expect(events.some((e) => e.type === 'paired')).toBe(false);
    expect((await new OAuthStore(store).read()).devices).toEqual([]);
    expect((await store.read()).clients.filter((c) => c.full)).toEqual([]);
    expect((await priv('GET', '/oauth/wait', { cookie: r.cookie })).status).toBe(403);
  });

  it('L3: pending devices of an earlier run are removed at startup', async () => {
    // A crash between the confirmation and the code exchange leaves a pending device (with a full grant).
    await access.close();
    const grantId = (await createDeviceGrant(store, { label: 'OAuth oc-0123456789abcdef', capabilities: [], accountIds: [], full: true })).id;
    const t = new Date().toISOString();
    await new OAuthStore(store).transact((d) => {
      d.devices.push({ id: 'oc-0123456789abcdef', clientId: CLAUDE_CODE_CIMD, clientName: 'Claude Code', registration: 'cimd', redirectHost: 'localhost:1', origin: 'private', pairedAt: t, expiresAt: t, status: 'pending', grantClientId: grantId, family: { previousRefresh: [] } });
    });
    access = await startAccess({ context, upstream: new Upstream(transport), privateBaseUrl: PRIV, dcrEnabled: true, trustForwarded: false, log: () => {} });
    expect((await new OAuthStore(store).read()).devices).toEqual([]);
    expect((await store.read()).clients.some((c) => c.id === grantId)).toBe(false);
  });

  // L4 ------------------------------------------------------------
  it('L4: a flood without a session cannot drain the pairing step of the real browser (private)', async () => {
    const code = openWindow();
    const { verifier, challenge } = pkce();
    const a = await priv('GET', privAuthorize(challenge));
    const cookie = cookieFrom(a)!;
    let limited = false;
    for (let i = 0; i < 15; i++) if ((await priv('GET', '/oauth/pair')).status === 429) limited = true;
    expect(limited).toBe(true);
    const p = await priv('GET', '/oauth/pair', { cookie });
    expect(p.status).toBe(200);
    const c = await priv('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code }), headers: { origin: PRIV } });
    expect(c.location).toBe('/oauth/wait');
    await privateExchange(cookie, verifier);
  });

  it('L4: invalid bearer tokens on the private /mcp are throttled; static and known tokens keep working', async () => {
    const { tokens } = await pairPrivate();
    const tokenFile = `${dirs.root}/config/clients/agent.token`;
    await createClientGrant(store, { label: 'Agent', capabilities: [], accountIds: [], tokenFile, readAll: true });
    const clientToken = (await readFile(tokenFile, 'utf8')).trim();
    for (let i = 0; i < 21; i++) await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(`${'Q'.repeat(42)}${i % 10}`) });
    expect(logs.some((l) => /too many invalid bearer tokens on the private \/mcp/.test(l))).toBe(true);
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(globalToken) })).status).toBe(200);
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(clientToken) })).status).toBe(200);
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(tokens.access_token!) })).status).toBe(200);
  });

  // L5 ------------------------------------------------------------
  it('L5: a mismatching exchange does not burn the code; repeated mismatches do', async () => {
    const code = openWindow();
    const r = await privateFlow(code);
    await waitFor(() => events.some((e) => e.type === 'paired'));
    const w = await priv('GET', '/oauth/wait', { cookie: r.cookie });
    const authCode = new URL(w.location!).searchParams.get('code')!;
    const ex = (o: Record<string, string>) =>
      priv('POST', '/oauth/token', { body: form({ grant_type: 'authorization_code', code: authCode, redirect_uri: CC_REDIRECT, client_id: CLAUDE_CODE_CIMD, code_verifier: r.verifier, ...o }) });
    expect((await ex({ code_verifier: pkce().verifier })).body).toContain('invalid_grant');
    expect((await ex({ client_id: HOSTED_CIMD })).body).toContain('invalid_grant');
    expect((await ex({ redirect_uri: 'http://localhost:1/callback' })).body).toContain('invalid_grant');
    expect((await ex({ resource: `${BASE}/mcp` })).body).toContain('invalid_grant');
    expect((await new OAuthStore(store).read()).devices[0]!.status).toBe('pending');
    expect((await ex({})).status).toBe(200);
    expect((await new OAuthStore(store).read()).devices[0]!.status).toBe('active');
    // Second window: five mismatches burn the code and remove its pending device.
    const code2 = openWindow();
    const r2 = await privateFlow(code2);
    await waitFor(() => events.some((e) => e.type === 'paired'));
    const authCode2 = new URL((await priv('GET', '/oauth/wait', { cookie: r2.cookie })).location!).searchParams.get('code')!;
    const ex2 = (verifier: string) => priv('POST', '/oauth/token', { body: form({ grant_type: 'authorization_code', code: authCode2, redirect_uri: CC_REDIRECT, client_id: CLAUDE_CODE_CIMD, code_verifier: verifier }) });
    for (let i = 0; i < 5; i++) await ex2(pkce().verifier);
    expect((await ex2(r2.verifier)).body).toContain('invalid_grant');
    let devs = (await new OAuthStore(store).read()).devices;
    for (let i = 0; i < 100 && devs.length > 1; i++) {
      await new Promise((res) => setTimeout(res, 10));
      devs = (await new OAuthStore(store).read()).devices;
    }
    expect(devs).toHaveLength(1);
  });

  // L7 ------------------------------------------------------------
  it('L7: the TOTP pair lock does not apply to private windows', async () => {
    await new OAuthStore(store).transact((d) => void (d.pairLock = { until: new Date(Date.now() + 60 * 60 * 1000).toISOString(), level: 1 }));
    const pubTry = await controlOpen('public');
    expect(pubTry.msg.type).toBe('error');
    expect(String(pubTry.msg.message)).toMatch(/locked/);
    pubTry.close();
    const privTry = await controlOpen('private');
    expect(privTry.msg).toMatchObject({ type: 'opened', listener: 'private' });
    privTry.close();
    await closedNow();
    const code = openWindow();
    const r = await privateFlow(code);
    expect(r.codeStep.location).toBe('/oauth/wait');
    await privateExchange(r.cookie, r.verifier);
  });
});


describe('native OAuth refresh compatibility', () => {
  it.each([CODEX_CIMD, CLAUDE_CODE_CIMD, 'dynamic-client'])('SDK automatically refreshes %s after access expiry and server restart without pairing', async (clientId) => {
    const code = openWindow();
    if (clientId === 'dynamic-client') {
      const registered = await priv('POST', '/oauth/register', { type: 'application/json', body: JSON.stringify({ client_name: 'Other MCP client', redirect_uris: [CC_REDIRECT] }) });
      expect(registered.status).toBe(201);
      clientId = JSON.parse(registered.body).client_id;
    }
    const flow = await privateFlow(code, { clientId });
    const issued = await privateExchange(flow.cookie, flow.verifier, { clientId });
    let saved = { ...issued, token_type: 'Bearer', issuer: PRIV } as OAuthTokens;
    const oauth = new OAuthStore(store);
    await oauth.transact(d => { d.devices[0]!.family.accessExpiresAt = new Date(Date.now() - 1000).toISOString(); });
    const expired = await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(issued.access_token!) });
    expect(expired.status).toBe(401);
    expect(expired.headers['www-authenticate']).toContain('invalid_token');
    await local.close();
    await access.close();
    access = await startAccess({ context, upstream: new Upstream(transport), privateBaseUrl: PRIV, dcrEnabled: true, trustForwarded: false, log: l => logs.push(l) });
    local = await startHttpServer({ host: '127.0.0.1', port: 0, token: globalToken, context, oauth: access.privateOAuth!, allowedHosts: [PRIV_HOST] });
    expect(access.pairing.isOpen).toBe(false);
    const paths: string[] = [];
    const provider: OAuthClientProvider = {
      redirectUrl: CC_REDIRECT,
      clientMetadata: { redirect_uris: [CC_REDIRECT], token_endpoint_auth_method: 'none' },
      clientInformation: () => ({ client_id: clientId, issuer: PRIV }),
      tokens: () => saved,
      saveTokens: value => { saved = value; },
      redirectToAuthorization: () => { throw new Error('Refresh must not request pairing'); },
      saveCodeVerifier: () => { throw new Error('Refresh must not start PKCE'); },
      codeVerifier: () => { throw new Error('Refresh must not need a verifier'); },
    };
    const fetchFn: typeof fetch = async (input, init) => {
      const u = new URL(input instanceof Request ? input.url : String(input));
      expect(u.origin).toBe(PRIV);
      paths.push(u.pathname);
      const result = await priv(init?.method ?? 'GET', u.pathname + u.search, {
        ...(init?.body ? { body: String(init.body) } : {}),
        headers: Object.fromEntries(new Headers(init?.headers).entries()),
      });
      return new Response(result.body, { status: result.status, headers: Object.fromEntries(Object.entries(result.headers).filter((e): e is [string, string] => typeof e[1] === 'string')) });
    };
    expect(await auth(provider, { serverUrl: `${PRIV}/mcp`, fetchFn })).toBe('AUTHORIZED');
    expect(saved.issuer).toBe(PRIV);
    expect(saved.refresh_token).not.toBe(issued.refresh_token);
    expect(paths).toContain('/oauth/token');
    expect(paths).not.toContain('/oauth/authorize');
    expect((await priv('POST', '/mcp', { body: rpc('tools/list'), headers: mcpHeaders(saved.access_token) })).status).toBe(200);
    expect((await oauth.read()).devices[0]!.family.previousRefresh).toHaveLength(1);
  });
});


describe('Codex built-in client restrictions', () => {
  it('does not fetch lookalike or alternative Codex metadata URLs', async () => {
    const resolver = new ClientResolver(new Upstream(transport));
    const state = await new OAuthStore(store).read();
    for (const id of [CODEX_CIMD + '?x=1', CODEX_CIMD + '#x', CODEX_CIMD + '/extra', 'https://chatgpt.com/oauth/other.json', 'https://chatgpt.com.evil.test/oauth/codex/client.json']) {
      await expect(resolver.resolve(id, state, new Map())).rejects.toMatchObject({ code: 'unknown_oauth_client' });
    }
    expect(upstreamCalls).toEqual([]);
  });
  it('does not inherit Claude hosted redirects for Codex metadata', async () => {
    const resolver = new ClientResolver(new Upstream(async () => ({ status: 200, headers: {}, body: Buffer.from(JSON.stringify({ client_id: CODEX_CIMD, redirect_uris: ['https://claude.ai/callback'] })) })));
    await expect(resolver.resolve(CODEX_CIMD, await new OAuthStore(store).read(), new Map())).rejects.toMatchObject({ code: 'client_metadata_invalid' });
  });
});
