// Harness for the public access tests: a real public listener on 127.0.0.1 with MOCK Google (token endpoint)
// and MOCK client metadata documents behind the Upstream transport, a controllable clock, and a tiny HTTP
// client that sets the Host header and keeps the pairing cookie. No request leaves the machine; every secret
// is generated dummy data.
import { createHash, randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { ClientResolver } from '../../src/access/clients.js';
import type { GoogleLoginClient } from '../../src/access/google.js';
import type { NoticeKind, Notifier } from '../../src/access/notify.js';
import { PairingManager, type PairEvent } from '../../src/access/pairing.js';
import { startPublicServer, type RunningPublicServer } from '../../src/access/server.js';
import { OAuthStore } from '../../src/access/state.js';
import { hotp, totpStep } from '../../src/access/totp.js';
import { createPerchContext, type PerchContext } from '../../src/context.js';
import { CredentialStore, initStore } from '../../src/store/credentialStore.js';
import { Upstream, type UpstreamRequest, type UpstreamResponse, type UpstreamTransport } from '../../src/upstream.js';
import { makeTempDirs, type TempDirs } from './fixtures.js';

export const BASE = 'https://perch.example.test';
export const HOST = 'perch.example.test';
export const CLAUDE_CODE_CIMD = 'https://claude.ai/oauth/claude-code-client-metadata';
export const HOSTED_CIMD = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
export const CLAUDE_CALLBACK = 'https://claude.ai/api/mcp/auth_callback';
export const GOOGLE: GoogleLoginClient = { clientId: '123456789012-abcdef.apps.googleusercontent.com', clientSecret: `DUMMY-${randomBytes(8).toString('hex')}` };
export const OPERATOR = { email: 'operator@example.test', sub: '1098765432101234567890' };

/** The JSON Google offers as download for a "Web application" client (dummy secret). */
export function webClientJson(base = BASE, redirects = [`${base}/oauth/google/callback`]): string {
  return JSON.stringify({ web: { client_id: GOOGLE.clientId, project_id: 'perch-test', client_secret: GOOGLE.clientSecret, redirect_uris: redirects } });
}

/** Writes a valid sign-in client file (0600) for `base`. */
export async function writeWebClientFile(file: string, base = BASE): Promise<string> {
  await writeFile(file, webClientJson(base), { mode: 0o600 });
  return file;
}

export interface HttpResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  location?: string;
}

export const b64url = (b: Buffer) => b.toString('base64url');
export const pkce = () => {
  const verifier = b64url(randomBytes(48));
  return { verifier, challenge: b64url(createHash('sha256').update(verifier).digest()) };
};

/** Unsigned JWT with the given claims (the server never checks signatures; see src/access/google.ts). */
export function idToken(claims: Record<string, unknown>): string {
  return `${b64url(Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })))}.${b64url(Buffer.from(JSON.stringify(claims)))}.${b64url(randomBytes(32))}`;
}

export interface Harness {
  dirs: TempDirs;
  store: CredentialStore;
  context: PerchContext;
  oauth: OAuthStore;
  pairing: PairingManager;
  server: RunningPublicServer;
  clock: { now: number };
  secret: Buffer;
  upstreamCalls: string[];
  notices: Array<{ kind: NoticeKind; detail?: string }>;
  events: PairEvent[];
  google: { nonce?: string; claims?: (base: Record<string, unknown>) => Record<string, unknown> };
  cimdDocs: Map<string, unknown>;
  http(method: string, path: string, opts?: { body?: string; type?: string; headers?: Record<string, string>; cookie?: string; host?: string }): Promise<HttpResult>;
  /** A fresh TOTP code (never reused within one test). */
  nextTotp(): string;
  close(): Promise<void>;
}

export async function startHarness(opts: { dcrEnabled?: boolean; notifierFails?: boolean } = {}): Promise<Harness> {
  const dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  const upstreamCalls: string[] = [];
  const clock = { now: Date.UTC(2026, 9, 14, 12, 0, 0) };
  const google: Harness['google'] = {};
  const cimdDocs = new Map<string, unknown>([
    [CLAUDE_CODE_CIMD, { client_id: CLAUDE_CODE_CIMD, client_name: 'Claude Code', redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'], token_endpoint_auth_method: 'none' }],
    [HOSTED_CIMD, { client_id: HOSTED_CIMD, client_name: 'Claude', redirect_uris: [CLAUDE_CALLBACK, 'https://evil.example/cb'], token_endpoint_auth_method: 'none' }],
  ]);
  const json = (status: number, body: unknown): UpstreamResponse => ({ status, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(body)) });
  const transport: UpstreamTransport = async (req: UpstreamRequest) => {
    upstreamCalls.push(`${req.method} ${req.url.origin}${req.url.pathname}`);
    if (req.url.origin === 'https://oauth2.googleapis.com' && req.url.pathname === '/token') {
      const form = new URLSearchParams(req.body ?? '');
      if (form.get('client_id') !== GOOGLE.clientId || form.get('client_secret') !== GOOGLE.clientSecret || !form.get('code_verifier')) return json(400, { error: 'invalid_grant' });
      const t = Math.floor(clock.now / 1000);
      const base = { iss: 'https://accounts.google.com', aud: GOOGLE.clientId, sub: OPERATOR.sub, email: OPERATOR.email, email_verified: true, iat: t, exp: t + 3600, nonce: google.nonce, auth_time: t };
      return json(200, { access_token: 'ya29.DUMMY', id_token: idToken(google.claims ? google.claims(base) : base), token_type: 'Bearer' });
    }
    const doc = cimdDocs.get(`${req.url.origin}${req.url.pathname}`);
    if (doc && req.method === 'GET') return json(200, doc);
    return json(404, { error: 'not_found' });
  };
  const upstream = new Upstream(transport);
  const context = createPerchContext(store, transport);
  const oauth = new OAuthStore(store);
  const secret = randomBytes(20);
  await oauth.transact((d) => {
    d.loginAllow.push({ email: OPERATOR.email, addedAt: new Date(clock.now).toISOString() });
    d.totp = { secret: secret.toString('base64'), createdAt: new Date(clock.now).toISOString(), recovery: [] };
  });
  const pairing = new PairingManager(() => clock.now);
  const notices: Harness['notices'] = [];
  const notifier: Notifier = {
    notify: async (kind, detail) => {
      notices.push({ kind, ...(detail ? { detail } : {}) });
      if (opts.notifierFails) throw new Error('MOCK: telegram down');
    },
  };
  const server = await startPublicServer({
    baseUrl: BASE,
    port: 0,
    context,
    oauth,
    pairing,
    clients: new ClientResolver(upstream),
    upstream,
    google: GOOGLE,
    notifier,
    dcrEnabled: opts.dcrEnabled ?? true,
    trustForwarded: false,
    log: () => {},
    now: () => clock.now,
  });
  let step = totpStep(clock.now) - 1;
  const h: Harness = {
    dirs,
    store,
    context,
    oauth,
    pairing,
    server,
    clock,
    secret,
    upstreamCalls,
    notices,
    events: [],
    google,
    cimdDocs,
    http: (method, path, o = {}) =>
      new Promise((resolve, reject) => {
        const headers: Record<string, string> = { host: o.host ?? HOST, ...(o.headers ?? {}) };
        if (o.cookie) headers.cookie = o.cookie;
        if (o.body !== undefined) {
          headers['content-type'] = o.type ?? 'application/x-www-form-urlencoded';
          headers['content-length'] = String(Buffer.byteLength(o.body));
        }
        const req = request({ host: '127.0.0.1', port: server.port, method, path, headers }, (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () =>
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              body: Buffer.concat(chunks).toString('utf8'),
              ...(res.headers.location ? { location: res.headers.location } : {}),
            }),
          );
        });
        req.on('error', reject);
        if (o.body !== undefined) req.write(o.body);
        req.end();
      }),
    nextTotp: () => {
      // Steps within ±1 of "now" are accepted once each; advance the clock when they run out.
      step = Math.max(step + 1, totpStep(clock.now) - 1);
      if (step > totpStep(clock.now) + 1) {
        clock.now += 30_000;
        step = totpStep(clock.now);
      }
      return hotp(secret, step);
    },
    close: async () => {
      pairing.close('aborted');
      await server.close();
      await dirs.cleanup();
    },
  };
  return h;
}

export const csrfOf = (html: string) => /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? '';
export const cookieFrom = (r: HttpResult) => {
  const raw = r.headers['set-cookie'];
  const first = Array.isArray(raw) ? raw[0] : raw;
  return first ? first.split(';')[0]! : undefined;
};
export const form = (o: Record<string, string>) => new URLSearchParams(o).toString();

export function authorizeUrl(o: { clientId?: string; redirectUri?: string; challenge: string; state?: string; resource?: string | null; method?: string; responseType?: string }) {
  const q = new URLSearchParams({
    response_type: o.responseType ?? 'code',
    client_id: o.clientId ?? HOSTED_CIMD,
    redirect_uri: o.redirectUri ?? CLAUDE_CALLBACK,
    code_challenge: o.challenge,
    code_challenge_method: o.method ?? 'S256',
    state: o.state ?? 'state-123',
    scope: 'perch.read offline_access',
  });
  if (o.resource !== null) q.set('resource', o.resource ?? `${BASE}/mcp`);
  return `/oauth/authorize?${q.toString()}`;
}

/** Opens a window as the operator (recording events). Returns the pairing code. */
export function openWindow(h: Harness, onConfirm: 'approve' | 'reject' | 'manual' = 'approve'): string {
  h.events.length = 0;
  // A real operator needs about a minute per pairing; this also refills the page rate limit (10/min).
  h.clock.now += 60_000;
  const { code } = h.pairing.open((ev) => {
    h.events.push(ev);
    if (ev.type === 'confirm' && onConfirm !== 'manual') queueMicrotask(() => h.pairing.answer(onConfirm === 'approve', h.pairing.windowId!, ev.confirmId));
  });
  return code;
}

export const waitFor = async (pred: () => boolean, ms = 2000) => {
  const start = Date.now();
  while (!pred()) {
    if (Date.now() - start > ms) throw new Error('timeout waiting for condition');
    await new Promise((r) => setTimeout(r, 5));
  }
};

export interface PairResult {
  cookie: string;
  verifier: string;
  code: string;
  redirect: URL;
  deviceId: string;
}

/** Full browser flow through to the authorization code redirect (window already open). */
export async function runBrowserFlow(h: Harness, pairCode: string, o: { clientId?: string; redirectUri?: string } = {}): Promise<PairResult> {
  const { verifier, challenge } = pkce();
  const a = await h.http('GET', authorizeUrl({ challenge, ...o }));
  if (a.status !== 303 || a.location !== '/oauth/pair') throw new Error(`authorize: ${a.status} ${a.body.slice(0, 200)}`);
  const cookie = cookieFrom(a)!;
  const p = await h.http('GET', '/oauth/pair', { cookie });
  const g = await h.http('POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code: pairCode }) });
  if (g.status !== 303 || !g.location?.startsWith('https://accounts.google.com/')) throw new Error(`pair: ${g.status} ${g.body.slice(0, 200)}`);
  const gu = new URL(g.location);
  h.google.nonce = gu.searchParams.get('nonce')!;
  const cb = await h.http('GET', `/oauth/google/callback?state=${encodeURIComponent(gu.searchParams.get('state')!)}&code=google-code-0123456789`, { cookie });
  if (cb.status !== 303 || cb.location !== '/oauth/totp') throw new Error(`callback: ${cb.status} ${cb.body.slice(0, 200)}`);
  const t = await h.http('GET', '/oauth/totp', { cookie });
  const w = await h.http('POST', '/oauth/totp', { cookie, body: form({ csrf: csrfOf(t.body), code: h.nextTotp() }) });
  if (w.status !== 303 || w.location !== '/oauth/wait') throw new Error(`totp: ${w.status} ${w.body.slice(0, 200)}`);
  await waitFor(() => h.events.some((e) => e.type === 'paired' || e.type === 'closed'));
  const done = await h.http('GET', '/oauth/wait', { cookie });
  if (done.status !== 303) throw new Error(`wait: ${done.status} ${done.body.slice(0, 200)}`);
  const redirect = new URL(done.location!);
  const paired = h.events.find((e) => e.type === 'paired') as { deviceId: string };
  return { cookie, verifier, code: redirect.searchParams.get('code')!, redirect, deviceId: paired.deviceId };
}

export async function exchange(h: Harness, r: PairResult, o: { clientId?: string; redirectUri?: string } = {}) {
  const res = await h.http('POST', '/oauth/token', {
    body: form({ grant_type: 'authorization_code', code: r.code, redirect_uri: o.redirectUri ?? CLAUDE_CALLBACK, client_id: o.clientId ?? HOSTED_CIMD, code_verifier: r.verifier }),
  });
  return { status: res.status, json: JSON.parse(res.body || '{}') as Record<string, string> };
}

export async function mcpCall(h: Harness, token: string, method: string, params: Record<string, unknown> = {}) {
  const res = await h.http('POST', '/mcp', {
    type: 'application/json',
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    headers: { authorization: `Bearer ${token}`, accept: 'application/json, text/event-stream' },
  });
  return { status: res.status, body: res.body, headers: res.headers };
}

export async function pairAndExchange(h: Harness) {
  const code = openWindow(h);
  const r = await runBrowserFlow(h, code);
  const t = await exchange(h, r);
  return { ...r, tokens: t.json };
}
