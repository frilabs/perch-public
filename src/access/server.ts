import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createDeviceGrant, hasWriteCapability, principalForGrantId, READONLY_PRINCIPAL, removeClientGrant, type Principal } from '../auth/grants.js';
import type { PerchContext } from '../context.js';
import { PerchError } from '../errors.js';
import { validateBindHost } from '../mcp/http.js';
import { createMcpServer } from '../mcp/server.js';
import type { Upstream } from '../upstream.js';
import { parseBaseUrl } from './baseUrl.js';
import { ClientResolver, newDcrClientId, parseDcrRequest, redirectHost, redirectMatches, type ResolvedClient } from './clients.js';
import { exchangeGoogleCode, googleAuthRequest, type GoogleLoginClient } from './google.js';
import type { Notifier, NoticeKind } from './notify.js';
import { errorPage, noWindowPage, notConfirmedPage, pageHeaders, pairCodePage, totpPage, waitPage, type ClientView } from './pages.js';
import type { PairingManager, PairSession } from './pairing.js';
import {
  ACCESS_TOKEN_TTL_MS,
  DEVICE_ABSOLUTE_MS,
  deviceOrigin,
  endDevice,
  expireDevices,
  hexEqual,
  isPublicLocked,
  newDeviceId,
  newToken,
  normaliseRecoveryCode,
  removePendingDevices,
  sha256Hex,
  type Device,
  type ListenerKind,
  type OAuthState,
  type OAuthStore,
} from './state.js';
import { verifyTotp } from './totp.js';

export { parseBaseUrl } from './baseUrl.js';

/**
 * OAuth for one listener (PUBLIC_ACCESS_SPEC §1, §3–§9; SIMPLE_CONNECT_SPEC §1). Each listener is its own
 * issuer: the public listener (internet, behind Funnel) and the private listener (the local listener, in the
 * tailnet behind Tailscale Serve). A device belongs to the listener it was paired on, and its tokens are
 * accepted there only (device origin, resource and issuer all differ).
 *
 * Public pairing: pairing code, Google sign-in, Perch code, terminal confirmation. Private pairing: pairing
 * code, terminal confirmation (the tailnet already authenticated the device; window, code, locks and the
 * operator's confirmation with details stay mandatory).
 *
 * The public listener's routing table is fixed: /mcp, /.well-known/oauth-*, /oauth/*. Everything else is 404
 * without any authentication attempt. Only OAuth access tokens are accepted on its /mcp.
 */

export const MCP_SCOPE = 'perch.read';
const MAX_FORM_BYTES = 16 * 1024;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_WRITE_BODY_BYTES = 16 * 1024 * 1024;
const COOKIE = '__Host-perch_pair';
/** Spec §9. */
export const TOTP_MAX_FAILURES = 5;
const TOTP_FAILURE_WINDOW_MS = 15 * 60 * 1000;
const PAIR_LOCK_BASE_MS = 15 * 60 * 1000;
const INVALID_BEARER_LIMIT = 20;
const INVALID_BEARER_BLOCK_MS = 5 * 60 * 1000;
const LAST_SEEN_EVERY_MS = 5 * 60 * 1000;
/** OAuth access tokens: 32 random bytes, base64url. */
export const OAUTH_BEARER = /^Bearer\s+([A-Za-z0-9_-]{43,64})\s*$/i;

export interface OAuthAppOptions {
  /** Which listener this issuer serves. Default public. */
  listener?: ListenerKind;
  baseUrl: string;
  context: PerchContext;
  oauth: OAuthStore;
  pairing: PairingManager;
  clients: ClientResolver;
  /** Upstream for the Google token exchange (fixed origin). */
  upstream: Upstream;
  /** Public listener only. */
  google: GoogleLoginClient | null;
  notifier: Notifier;
  dcrEnabled: boolean;
  /** Public listener only: X-Forwarded-For of a loopback proxy. */
  trustForwarded: boolean;
  log?: (line: string) => void;
  now?: () => number;
}

export interface PublicServerOptions extends OAuthAppOptions {
  host?: string;
  port: number;
}

export interface RunningPublicServer {
  port: number;
  close(): Promise<void>;
}

export type DeviceAuth =
  | { kind: 'ok'; principal: Principal; guard: () => Promise<void>; deviceId: string }
  | { kind: 'unauthorized' }
  | { kind: 'unavailable' }
  | { kind: 'limited' };

export interface OAuthApp {
  listener: ListenerKind;
  /** Issuer origin, e.g. https://homeserver.tailnet-xyz.ts.net */
  origin: string;
  host: string;
  resource: string;
  /** Discovery and /oauth/* paths of this listener. */
  isOAuthPath(path: string): boolean;
  /** Handles a discovery or /oauth/* request (404 for anything else). */
  route(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void>;
  /** Device of an OAuth access token issued on THIS listener. */
  authenticate(authorization: string | undefined): Promise<DeviceAuth>;
  /** WWW-Authenticate value of a 401 on /mcp (RFC 9728 resource_metadata). */
  wwwAuthenticate(expired: boolean, realm?: string): string;
  /**
   * authenticate() behind the invalid-bearer throttle (both listeners): 20 invalid bearer headers per minute
   * block unknown tokens for 5 minutes; tokens of this listener seen valid recently still pass. The local
   * listener checks its static tokens BEFORE this, so a block never touches them.
   */
  authenticateThrottled(authorization: string | undefined): Promise<DeviceAuth>;
  /** Full /mcp handling of the public listener (bearer block, per-device limit, transport). */
  mcp(req: IncomingMessage, res: ServerResponse): Promise<void>;
  /** Marks the current access tokens of this listener's devices as known (after a restart). */
  warm(devices: Device[]): void;
  /** Overall limit of the unauthenticated routes (per client IP when trusted). */
  takeAll(req: IncomingMessage): boolean;
}

/** Token bucket: `perMinute` requests, refilled continuously. */
class Bucket {
  private tokens: number;
  private at: number;
  constructor(
    private readonly perMinute: number,
    private readonly now: () => number,
  ) {
    this.tokens = perMinute;
    this.at = now();
  }
  take(): boolean {
    const t = this.now();
    this.tokens = Math.min(this.perMinute, this.tokens + ((t - this.at) / 60_000) * this.perMinute);
    this.at = t;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}

const pkceS256 = (verifier: string) => createHash('sha256').update(verifier).digest('base64url');

function constEq(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function readBody(req: IncomingMessage, limit: number): Promise<Buffer | 'too_large'> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let tooLarge = Number(req.headers['content-length'] ?? 0) > limit;
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > limit) tooLarge = true;
      if (!tooLarge) chunks.push(c);
    });
    req.on('end', () => resolve(tooLarge ? 'too_large' : Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function cookieOf(req: IncomingMessage): string | undefined {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === COOKIE) return v.join('=');
  }
  return undefined;
}

const isLoopbackRemote = (remote: string) => remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';

const DISCOVERY_PATHS = new Set([
  '/.well-known/oauth-protected-resource',
  '/.well-known/oauth-protected-resource/mcp',
  '/.well-known/oauth-authorization-server',
  '/.well-known/oauth-authorization-server/mcp',
]);
const PUBLIC_OAUTH_PATHS = new Set(['/oauth/authorize', '/oauth/pair', '/oauth/google/callback', '/oauth/totp', '/oauth/wait', '/oauth/token', '/oauth/revoke', '/oauth/register']);
/** No Google and no Perch code on the private listener. */
const PRIVATE_OAUTH_PATHS = new Set(['/oauth/authorize', '/oauth/pair', '/oauth/wait', '/oauth/token', '/oauth/revoke', '/oauth/register']);

export function createOAuthApp(opts: OAuthAppOptions): OAuthApp {
  const listener: ListenerKind = opts.listener ?? 'public';
  const isPublic = listener === 'public';
  const base = parseBaseUrl(opts.baseUrl, isPublic ? 'PERCH_PUBLIC_BASE_URL' : 'PERCH_PRIVATE_BASE_URL');
  const origin = base.origin;
  const resource = `${origin}/mcp`;
  const now = opts.now ?? Date.now;
  const log = opts.log ?? ((l: string) => process.stderr.write(`${l}\n`));
  const { oauth, pairing, context } = opts;
  const oauthPaths = isPublic ? PUBLIC_OAUTH_PATHS : PRIVATE_OAUTH_PATHS;

  // Per client IP when the proxy's X-Forwarded-For is trusted, otherwise global (Spec §9).
  const LIMITS = { pages: 10, wait: 60, register: 5, token: 30, all: 300 } as const;
  type Kind = keyof typeof LIMITS;
  const bucketMap = new Map<string, Bucket>();
  const take = (kind: Kind, req: IncomingMessage): boolean => takeKey(kind, clientIp(req) ?? '*');
  const takeKey = (kind: Kind, who: string): boolean => {
    const key = `${kind}|${who}`;
    let b = bucketMap.get(key);
    if (!b) {
      if (bucketMap.size > 5000) bucketMap.clear();
      bucketMap.set(key, (b = new Bucket(LIMITS[kind], now)));
    }
    return b.take();
  };
  /** Access-token hashes seen valid recently: known devices pass the invalid-bearer block. */
  const knownAccess = new Map<string, number>();
  const rememberAccess = (hash: string, until: number) => {
    if (knownAccess.size > 500) knownAccess.clear();
    knownAccess.set(hash, until);
  };
  const deviceBuckets = new Map<string, Bucket>();
  let invalidBearer: number[] = [];
  let bearerBlockedUntil = 0;
  const lastSeenWritten = new Map<string, number>();

  const audit = async (type: string, outcome: 'ok' | 'denied' | 'invalid' | 'error', deviceId?: string, code?: string) => {
    try {
      await context.audit.record({ type, actor: { kind: 'oauth', ...(deviceId ? { deviceId } : {}), origin: listener }, outcome, ...(code ? { code } : {}) });
    } catch {
      log(`perch: could not write a ${listener} access audit event`);
      if (outcome === 'ok') throw new PerchError('The audit trail could not be written; nothing was issued', 'audit_unavailable');
    }
  };
  const notify = (kind: NoticeKind, detail?: string) => {
    opts.notifier.notify(kind, detail).catch(() => log(`perch: notification ${kind} could not be delivered`));
  };

  const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
    if (res.headersSent) return;
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', pragma: 'no-cache', ...headers });
    res.end(JSON.stringify(body));
  };
  const html = (res: ServerResponse, status: number, page: string, headers: Record<string, string> = {}) => {
    if (res.headersSent) return;
    res.writeHead(status, pageHeaders(headers));
    res.end(page);
  };
  const redirect = (res: ServerResponse, location: string, headers: Record<string, string> = {}) => {
    res.writeHead(303, { location, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', ...headers });
    res.end();
  };
  const tooMany = (res: ServerResponse) => json(res, 429, { error: 'rate_limited' }, { 'retry-after': '60' });
  const wwwAuthenticate = (expired: boolean, realm?: string) =>
    `Bearer ${realm ? `realm="${realm}", ` : ''}resource_metadata="${origin}/.well-known/oauth-protected-resource", scope="${MCP_SCOPE}"${expired ? ', error="invalid_token"' : ''}`;
  const unauthorized = (res: ServerResponse, expired = false) => json(res, 401, { error: 'invalid_token' }, { 'www-authenticate': wwwAuthenticate(expired) });
  const oauthError = (res: ServerResponse, error: string, status = 400) => json(res, status, { error });

  /** Public: the trusted proxy's client IP. Private: the peer address (loopback = Tailscale Serve or this server). */
  const clientIp = (req: IncomingMessage): string | undefined => {
    const remote = req.socket.remoteAddress ?? '';
    if (!isPublic) return remote ? remote.replace(/^::ffff:/, '') : undefined;
    if (!opts.trustForwarded || !isLoopbackRemote(remote)) return undefined;
    const xff = String(req.headers['x-forwarded-for'] ?? '');
    const last = xff.split(',').pop()?.trim();
    return last && /^[0-9a-fA-F:.]{2,45}$/.test(last) ? last : undefined;
  };
  /**
   * Bucket of the sign-in steps. Public: per client IP (trusted proxy) or global. Private: every request comes
   * from 127.0.0.1 (Tailscale Serve), so a per-IP bucket would be one global bucket that any local process
   * could drain; there the bucket belongs to the browser session (cookie), plus one shared bucket for
   * requests without a valid session.
   */
  const takeStep = (kind: 'pages' | 'wait', req: IncomingMessage): boolean => {
    if (isPublic) return take(kind, req);
    const s = session(req);
    return takeKey(kind, s ? `session:${s.id}` : 'no-session');
  };
  const userAgent = (req: IncomingMessage) => {
    const ua = String(req.headers['user-agent'] ?? '').replace(/[^\x20-\x7e]/g, '').slice(0, 200);
    return ua || undefined;
  };

  const clientView = (c: ResolvedClient, redirectUri: string): ClientView => ({
    clientDisplay: c.displayName,
    clientName: c.clientName,
    registration: c.registration === 'cimd' ? 'metadata document' : c.registration === 'dcr' ? 'self-registered' : 'pre-registered',
    redirectHost: redirectHost(redirectUri),
    loopbackOnly: c.redirectUris.every((u) => u.startsWith('http://')),
  });

  /**
   * Reads the state; a damaged state closes the window and answers 503 (fail closed). The kill switch of the
   * public access (perch public off) applies to the public listener only.
   */
  const readState = async (res: ServerResponse): Promise<OAuthState | null> => {
    let s: OAuthState;
    try {
      s = await oauth.read();
    } catch {
      log(`perch: OAuth state is unreadable; the ${listener} OAuth endpoints fail closed (503)`);
      pairing.close('aborted');
      json(res, 503, { error: 'temporarily_unavailable' });
      return null;
    }
    if (isPublic && isPublicLocked(s)) {
      pairing.lockout('kill_switch');
      json(res, 503, { error: 'temporarily_unavailable' });
      return null;
    }
    return s;
  };

  const session = (req: IncomingMessage): PairSession | null => pairing.session(cookieOf(req), listener);
  const secondAttemptPage = async (res: ServerResponse) => {
    notify('second_pairing_attempt');
    await audit('oauth_pair_second_attempt', 'denied', undefined, 'second_pairing_attempt');
    return html(res, 403, errorPage(origin, 'Pairing closed', 'A second sign-in attempt was made in the same pairing window. Both were discarded and the window was closed.'));
  };

  // ---------------------------------------------------------------- discovery
  const protectedResource = () => ({ resource, authorization_servers: [origin], scopes_supported: [MCP_SCOPE], bearer_methods_supported: ['header'] });
  const authServer = () => ({
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    revocation_endpoint: `${origin}/oauth/revoke`,
    ...(opts.dcrEnabled ? { registration_endpoint: `${origin}/oauth/register` } : {}),
    code_challenge_methods_supported: ['S256'],
    client_id_metadata_document_supported: true,
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    response_types_supported: ['code'],
    scopes_supported: [MCP_SCOPE, 'offline_access'],
    authorization_response_iss_parameter_supported: true,
  });

  // ---------------------------------------------------------------- authorize flow
  async function authorize(req: IncomingMessage, res: ServerResponse, url: URL) {
    // No window (for this listener): a fixed page, no Google redirect, no metadata fetch, no state access
    // (Spec §3), and no rate-limit cost (otherwise anyone could keep the limit exhausted).
    if (!pairing.isOpenFor(listener)) return html(res, 403, noWindowPage(origin));
    if (!take('pages', req)) return tooMany(res);
    const state = await readState(res);
    if (!state) return;
    const q = url.searchParams;
    const clientId = q.get('client_id') ?? '';
    const redirectUri = q.get('redirect_uri') ?? '';
    let client: ResolvedClient;
    try {
      client = await opts.clients.resolve(clientId, state, pairing.dcrRegistrations(listener));
    } catch {
      return html(res, 400, errorPage(origin, 'Unknown client', 'This client is not known to Perch. Nothing was connected.'));
    }
    if (!client.redirectUris.some((r) => redirectMatches(r, redirectUri))) {
      return html(res, 400, errorPage(origin, 'Invalid request', 'The return address of this client is not registered. Nothing was connected.'));
    }
    const back = (error: string) => {
      // Self-registered clients may name any https redirect: never redirect them with an error (no open redirect).
      if (client.registration === 'dcr') return html(res, 400, errorPage(origin, 'Invalid request', `The sign-in request is invalid (${error}). Nothing was connected.`));
      const u = new URL(redirectUri);
      u.searchParams.set('error', error);
      if (q.get('state')) u.searchParams.set('state', q.get('state')!);
      u.searchParams.set('iss', origin);
      return redirect(res, u.toString());
    };
    if (q.get('response_type') !== 'code') return back('unsupported_response_type');
    const challenge = q.get('code_challenge') ?? '';
    if (q.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) return back('invalid_request');
    const requested = q.get('resource');
    if (requested !== null && requested !== resource) return back('invalid_target');
    const stateParam = q.get('state') ?? undefined;
    if (stateParam !== undefined && stateParam.length > 1024) return back('invalid_request');
    let s: PairSession;
    try {
      const ua = userAgent(req);
      const ip = clientIp(req);
      s = pairing.startSession(cookieOf(req), {
        origin: listener,
        auth: { clientId: client.clientId, redirectUri, ...(stateParam !== undefined ? { state: stateParam } : {}), codeChallenge: challenge, resource },
        client,
        ...(ua ? { userAgent: ua } : {}),
        ...(ip ? { ip } : {}),
      });
    } catch (err) {
      if (err instanceof PerchError && err.code === 'second_pairing_attempt') return secondAttemptPage(res);
      if (err instanceof PerchError && err.code === 'no_pairing_window') return html(res, 403, noWindowPage(origin));
      return html(res, 403, errorPage(origin, 'Pairing not possible', err instanceof PerchError ? err.message : 'Pairing not possible'));
    }
    await audit('oauth_pair_started', 'ok');
    redirect(res, '/oauth/pair', { 'set-cookie': `${COOKIE}=${s.id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600` });
  }

  async function readForm(req: IncomingMessage, res: ServerResponse): Promise<URLSearchParams | null> {
    const type = String(req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
    if (type !== 'application/x-www-form-urlencoded') {
      json(res, 415, { error: 'invalid_request' });
      return null;
    }
    const body = await readBody(req, MAX_FORM_BYTES);
    if (body === 'too_large') {
      json(res, 413, { error: 'invalid_request' });
      return null;
    }
    return new URLSearchParams(body.toString('utf8'));
  }

  /** Same-origin form post with the session's CSRF token. */
  async function sessionForm(req: IncomingMessage, res: ServerResponse): Promise<{ s: PairSession; form: URLSearchParams } | null> {
    const o = req.headers.origin;
    if (o !== undefined && o !== origin) {
      html(res, 403, errorPage(origin, 'Forbidden', 'This form must be sent from the Perch sign-in page.'));
      return null;
    }
    const form = await readForm(req, res);
    if (!form) return null;
    const s = session(req);
    if (!s || !constEq(form.get('csrf') ?? '', s.csrf)) {
      html(res, 403, notConfirmedPage(origin));
      return null;
    }
    return { s, form };
  }

  async function pairCode(req: IncomingMessage, res: ServerResponse) {
    if (!takeStep('pages', req)) return tooMany(res);
    const next = isPublic ? 'google' : 'confirm';
    if (req.method === 'GET') {
      const s = session(req);
      if (!s || s.step !== 'code') return html(res, 403, notConfirmedPage(origin));
      return html(res, 200, pairCodePage(origin, s.csrf, clientView(s.client, s.auth.redirectUri), undefined, next));
    }
    const state = await readState(res);
    if (!state) return;
    const r = await sessionForm(req, res);
    if (!r) return;
    const { s, form } = r;
    if (isPublic && !opts.google) return html(res, 503, errorPage(origin, 'Not set up', 'Google sign-in is not configured on this server.'));
    let ok: boolean;
    try {
      ok = pairing.submitPairingCode(s, form.get('code') ?? '');
    } catch (err) {
      if (err instanceof PerchError && err.code === 'second_pairing_attempt') return secondAttemptPage(res);
      return html(res, 403, notConfirmedPage(origin));
    }
    if (!ok) {
      notify('pairing_code_wrong');
      await audit('oauth_pair_code', 'denied', undefined, 'pairing_code_wrong');
      if (!pairing.session(s.id, listener)) return html(res, 403, errorPage(origin, 'Pairing closed', 'Too many wrong pairing codes. The pairing window was closed.'));
      return html(res, 200, pairCodePage(origin, s.csrf, clientView(s.client, s.auth.redirectUri), 'Wrong pairing code.', next));
    }
    await audit('oauth_pair_code', 'ok');
    if (!isPublic) {
      // Private listener: no Google sign-in and no Perch code; the operator confirms in the terminal.
      try {
        pairing.privateCodeDone(s, (sess) => createDevice(sess), (deviceId) => void dropPending([deviceId]));
      } catch (err) {
        if (err instanceof PerchError && err.code === 'second_pairing_attempt') return secondAttemptPage(res);
        return html(res, 403, notConfirmedPage(origin));
      }
      return redirect(res, '/oauth/wait');
    }
    const g = googleAuthRequest(opts.google!, `${origin}/oauth/google/callback`);
    pairing.googleStarted(s, { state: g.state, nonce: g.nonce, verifier: g.verifier });
    redirect(res, g.url);
  }

  async function googleCallback(req: IncomingMessage, res: ServerResponse, url: URL) {
    if (!take('pages', req)) return tooMany(res);
    const state = await readState(res);
    if (!state) return;
    const s = session(req);
    const q = url.searchParams;
    if (!s || s.step !== 'google' || !s.google || !opts.google || !constEq(q.get('state') ?? '', s.google.state)) return html(res, 403, notConfirmedPage(origin));
    const code = q.get('code');
    if (!code) {
      pairing.close('rejected');
      await audit('oauth_google', 'denied', undefined, 'google_cancelled');
      return html(res, 403, errorPage(origin, 'Not connected', 'Google sign-in was cancelled. The pairing window was closed.'));
    }
    let identity;
    try {
      identity = await exchangeGoogleCode(opts.upstream, opts.google, { code, redirectUri: `${origin}/oauth/google/callback`, verifier: s.google.verifier, nonce: s.google.nonce, nowSeconds: now() / 1000 });
    } catch {
      pairing.close('rejected');
      await audit('oauth_google', 'denied', undefined, 'google_login_failed');
      return html(res, 403, errorPage(origin, 'Not connected', 'Google sign-in failed. The pairing window was closed.'));
    }
    // Allowlist: the pinned sub decides; the first successful login pins it.
    let allowed = false;
    await oauth.transact((d) => {
      const bySub = d.loginAllow.find((e) => e.sub === identity.sub);
      if (bySub) {
        allowed = bySub.email.toLowerCase() === identity.email;
        return;
      }
      const byEmail = d.loginAllow.find((e) => e.email.toLowerCase() === identity.email && e.sub === undefined);
      if (byEmail) {
        byEmail.sub = identity.sub;
        allowed = true;
      }
    });
    if (!allowed) {
      pairing.close('rejected');
      await audit('oauth_google', 'denied', undefined, 'google_account_not_allowed');
      return html(res, 403, errorPage(origin, 'Not connected', 'This Google account is not allowed for this Perch. The pairing window was closed.'));
    }
    pairing.googleDone(s, identity);
    redirect(res, '/oauth/totp');
  }

  async function totpStep(req: IncomingMessage, res: ServerResponse) {
    if (!take('pages', req)) return tooMany(res);
    if (req.method === 'GET') {
      const s = session(req);
      if (!s || s.step !== 'totp' || !s.identity) return html(res, 403, notConfirmedPage(origin));
      return html(res, 200, totpPage(origin, s.csrf, s.identity.email));
    }
    const state = await readState(res);
    if (!state) return;
    const r = await sessionForm(req, res);
    if (!r) return;
    const { s, form } = r;
    if (s.step !== 'totp' || !s.identity) return html(res, 403, notConfirmedPage(origin));
    const input = (form.get('code') ?? '').trim();
    const t = now();
    let result = 'wrong' as 'ok' | 'recovery' | 'wrong' | 'locked';
    await oauth.transact((d) => {
      if (!d.totp) {
        result = 'locked';
        return;
      }
      if (/^\d{6}$/.test(input.replace(/\s/g, ''))) {
        const step = verifyTotp(Buffer.from(d.totp.secret, 'base64'), input.replace(/\s/g, ''), t, d.totp.lastStep);
        if (step !== null) {
          d.totp.lastStep = step;
          result = 'ok';
        }
      } else {
        const code = normaliseRecoveryCode(input);
        const rec = /^[A-Z2-7]{10}$/.test(code) ? d.totp.recovery.find((x) => !x.usedAt && hexEqual(x.hash, sha256Hex(`${x.salt}:${code}`))) : undefined;
        if (rec) {
          rec.usedAt = new Date(t).toISOString();
          result = 'recovery';
        }
      }
      if (result === 'wrong') {
        d.totpFailures = [...d.totpFailures.filter((x) => t - Date.parse(x) < TOTP_FAILURE_WINDOW_MS), new Date(t).toISOString()].slice(-50);
        if (d.totpFailures.length >= TOTP_MAX_FAILURES) {
          const level = Math.min(20, d.pairLock && Date.parse(d.pairLock.until) > t - PAIR_LOCK_BASE_MS * 4 ? d.pairLock.level + 1 : 1);
          d.pairLock = { until: new Date(t + PAIR_LOCK_BASE_MS * 2 ** (level - 1)).toISOString(), level };
          d.totpFailures = [];
          result = 'locked';
        }
      } else if (result !== 'locked') {
        d.totpFailures = [];
      }
    });
    if (result === 'locked') {
      pairing.lockout('totp_lockout');
      notify('pairing_locked');
      await audit('oauth_totp', 'denied', undefined, 'pairing_locked');
      return html(res, 403, errorPage(origin, 'Pairing locked', 'Too many wrong Perch codes. Pairing is locked for a while; the window was closed.'));
    }
    if (result === 'wrong') {
      await audit('oauth_totp', 'denied', undefined, 'totp_wrong');
      return html(res, 200, totpPage(origin, s.csrf, s.identity.email, 'Wrong or already used code.'));
    }
    if (result === 'recovery') notify('recovery_code_used');
    await audit('oauth_totp', 'ok', undefined, result === 'recovery' ? 'recovery_code' : undefined);
    try {
      pairing.totpDone(s, result === 'recovery', (sess) => createDevice(sess), (deviceId) => void dropPending([deviceId]));
    } catch (err) {
      if (err instanceof PerchError && err.code === 'second_pairing_attempt') return secondAttemptPage(res);
      return html(res, 403, notConfirmedPage(origin));
    }
    redirect(res, '/oauth/wait');
  }

  /** Removes the client grants of devices that are no longer active (they fail closed anyway). */
  async function releaseGrants(): Promise<void> {
    const grants: string[] = [];
    await oauth.transact((d) => {
      for (const dev of d.devices) {
        if (dev.status !== 'active' && dev.grantClientId) {
          grants.push(dev.grantClientId);
          dev.grantClientId = undefined;
        }
      }
    });
    for (const g of grants) await removeClientGrant(context.store, g).catch(() => {});
  }

  async function endDevices(ids: string[], reason: NonNullable<Device['endedReason']>): Promise<void> {
    try {
      await oauth.transact((d) => {
        for (const dev of d.devices) if (ids.includes(dev.id)) endDevice(dev, reason, new Date(now()));
      });
      await releaseGrants();
    } catch {
      log('perch: could not end a device');
    }
  }

  /**
   * Removes PENDING devices (their code expired, was burnt, the window closed before pick-up, or the audit
   * write failed) and their grants. Active devices are never touched here.
   */
  async function dropPending(ids: string[]): Promise<void> {
    try {
      const grants = await oauth.transact((d) => removePendingDevices(d, (x) => ids.includes(x.id)));
      for (const g of grants) await removeClientGrant(context.store, g).catch(() => {});
    } catch {
      log('perch: could not remove a pending device');
    }
  }

  /**
   * After the operator's "y": the device record (bound to this listener, status `pending`) and, for full
   * access, its grant. Both exist before the authorization code is issued; the device becomes active only
   * with the first successful code exchange.
   */
  async function createDevice(s: PairSession): Promise<string> {
    const id = newDeviceId();
    const t = new Date(now());
    const grant = s.access === 'full' ? await createDeviceGrant(context.store, { label: `OAuth ${id}`, capabilities: [], accountIds: [], full: true }) : undefined;
    try {
      await oauth.transact((d) => {
        if (isPublic && isPublicLocked(d)) throw new PerchError('Public access is switched off', 'public_locked');
        expireDevices(d, t);
        const device: Device = {
          id,
          clientId: s.auth.clientId,
          clientName: s.client.clientName,
          registration: s.client.registration,
          redirectHost: redirectHost(s.auth.redirectUri),
          origin: listener,
          ...(s.identity ? { googleEmail: s.identity.email } : {}),
          ...(s.userAgent ? { userAgent: s.userAgent } : {}),
          ...(s.ip ? { ip: s.ip } : {}),
          pairedAt: t.toISOString(),
          expiresAt: new Date(t.getTime() + DEVICE_ABSOLUTE_MS).toISOString(),
          status: 'pending',
          ...(grant ? { grantClientId: grant.id } : {}),
          family: { previousRefresh: [] },
        };
        d.devices.push(device);
      });
    } catch (err) {
      if (grant) await removeClientGrant(context.store, grant.id).catch(() => {});
      throw err;
    }
    try {
      await audit('oauth_device_paired', 'ok', id, s.access === 'full' ? 'full_access' : 'read_only');
    } catch (err) {
      await dropPending([id]); // no audit trail, no device (and no grant)
      throw err;
    }
    notify('device_paired', id);
    return id;
  }

  async function wait(req: IncomingMessage, res: ServerResponse) {
    if (!takeStep('wait', req)) return tooMany(res);
    const s = session(req);
    if (!s) return html(res, 403, notConfirmedPage(origin));
    if (s.step === 'confirm') return html(res, 200, waitPage(origin, clientView(s.client, s.auth.redirectUri)));
    if (s.step !== 'approved' || !s.authCode) return html(res, 403, notConfirmedPage(origin));
    const u = new URL(s.auth.redirectUri);
    u.searchParams.set('code', s.authCode);
    if (s.auth.state !== undefined) u.searchParams.set('state', s.auth.state);
    u.searchParams.set('iss', origin);
    pairing.finish(s);
    redirect(res, u.toString(), { 'set-cookie': `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0` });
  }

  // ---------------------------------------------------------------- DCR
  async function register(req: IncomingMessage, res: ServerResponse) {
    if (!take('register', req)) return tooMany(res);
    if (!opts.dcrEnabled) return json(res, 404, { error: 'not_found' });
    // Closed outside a pairing window (Spec §4).
    if (!pairing.isOpenFor(listener)) return json(res, 403, { error: 'access_denied', error_description: 'Registration is only possible while a pairing window is open' });
    const state = await readState(res);
    if (!state) return;
    const type = String(req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
    if (type !== 'application/json') return json(res, 400, { error: 'invalid_client_metadata' });
    const body = await readBody(req, MAX_FORM_BYTES);
    if (body === 'too_large') return json(res, 400, { error: 'invalid_client_metadata' });
    let reg;
    try {
      reg = parseDcrRequest(JSON.parse(body.toString('utf8')));
    } catch (err) {
      return json(res, 400, { error: err instanceof PerchError && err.code === 'invalid_client_metadata' ? 'invalid_redirect_uri' : 'invalid_client_metadata' });
    }
    const clientId = newDcrClientId();
    try {
      pairing.addDcr({ clientId, clientName: reg.clientName, redirectUris: reg.redirectUris, createdAt: now() }, listener);
    } catch {
      return json(res, 429, { error: 'too_many_registrations' }, { 'retry-after': '60' });
    }
    await audit('oauth_register', 'ok');
    json(res, 201, {
      client_id: clientId,
      client_id_issued_at: Math.floor(now() / 1000),
      client_name: reg.clientName,
      redirect_uris: reg.redirectUris,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    });
  }

  // ---------------------------------------------------------------- token + revoke
  const issueTokens = (d: Device, t: number) => {
    const access = newToken();
    const refresh = newToken();
    if (d.family.refreshHash) d.family.previousRefresh = [...d.family.previousRefresh, d.family.refreshHash].slice(-100);
    d.family.accessHash = sha256Hex(access);
    d.family.accessExpiresAt = new Date(t + ACCESS_TOKEN_TTL_MS).toISOString();
    // A freshly issued token must pass a running invalid-bearer block (spec §15.9: valid tokens are exempt).
    rememberAccess(d.family.accessHash, t + ACCESS_TOKEN_TTL_MS);
    d.family.refreshHash = sha256Hex(refresh);
    d.family.refreshedAt = new Date(t).toISOString();
    d.lastSeenAt = new Date(t).toISOString();
    return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TOKEN_TTL_MS / 1000, refresh_token: refresh, scope: MCP_SCOPE };
  };
  /** Devices of this listener only: a token never crosses to the other listener. */
  const mine = (d: Device) => deviceOrigin(d) === listener;

  async function token(req: IncomingMessage, res: ServerResponse) {
    if (!take('token', req)) return tooMany(res);
    const state = await readState(res);
    if (!state) return;
    const form = await readForm(req, res);
    if (!form) return;
    const grant = form.get('grant_type');
    const t = now();
    if (grant === 'authorization_code') {
      const presented = form.get('code') ?? '';
      const peeked = pairing.peekCode(presented);
      if (peeked && 'reused' in peeked) {
        // A second use of an exchanged code: the tokens issued for it are no longer trustworthy.
        await endDevices([peeked.reused], 'code_reuse');
        await audit('oauth_code_reuse', 'denied', peeked.reused, 'code_reuse');
        return oauthError(res, 'invalid_grant');
      }
      // Everything is checked BEFORE the code is consumed: a mismatching request does not burn it.
      const issued = peeked;
      const verifier = form.get('code_verifier') ?? '';
      const requested = form.get('resource');
      if (
        !issued ||
        issued.origin !== listener ||
        issued.resource !== resource ||
        form.get('client_id') !== issued.clientId ||
        form.get('redirect_uri') !== issued.redirectUri ||
        !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) ||
        !constEq(pkceS256(verifier), issued.codeChallenge) ||
        (requested !== null && requested !== resource)
      ) {
        if (issued) pairing.codeMismatch(presented);
        await audit('oauth_token', 'denied', issued?.deviceId, 'invalid_grant');
        return oauthError(res, 'invalid_grant');
      }
      const taken = pairing.takeCode(presented);
      if (!taken || 'reused' in taken || taken.deviceId !== issued.deviceId) return oauthError(res, 'invalid_grant');
      let body = null as ReturnType<typeof issueTokens> | null;
      await oauth.transact((d) => {
        // The first successful exchange activates the pending device.
        const dev = d.devices.find((x) => x.id === issued.deviceId && x.status === 'pending' && mine(x));
        if (!dev || dev.family.refreshHash) return; // removed, revoked or already exchanged
        dev.status = 'active';
        body = issueTokens(dev, t);
      });
      if (!body) return oauthError(res, 'invalid_grant');
      await audit('oauth_token_issued', 'ok', issued.deviceId);
      return json(res, 200, body);
    }
    if (grant === 'refresh_token') {
      const presented = form.get('refresh_token') ?? '';
      const clientId = form.get('client_id');
      if (presented.length < 43 || presented.length > 64) return oauthError(res, 'invalid_grant');
      const h = sha256Hex(presented);
      type RefreshOutcome = { kind: 'ok'; body: ReturnType<typeof issueTokens>; id: string } | { kind: 'reuse'; id: string } | { kind: 'invalid'; id?: string };
      let outcome = { kind: 'invalid' } as RefreshOutcome;
      await oauth.transact((d) => {
        expireDevices(d, new Date(t));
        const dev = d.devices.find((x) => x.status === 'active' && mine(x) && x.family.refreshHash !== undefined && hexEqual(x.family.refreshHash, h));
        if (dev) {
          if (clientId !== null && clientId !== dev.clientId) {
            outcome = { kind: 'invalid', id: dev.id };
            return;
          }
          outcome = { kind: 'ok', body: issueTokens(dev, t), id: dev.id };
          return;
        }
        const reused = d.devices.find((x) => mine(x) && x.family.previousRefresh.some((p) => hexEqual(p, h)));
        if (reused) {
          if (reused.status === 'active') endDevice(reused, 'refresh_reuse', new Date(t));
          outcome = { kind: 'reuse', id: reused.id };
        }
      });
      const o = outcome as RefreshOutcome;
      if (o.kind === 'reuse') {
        await releaseGrants();
        notify('refresh_reuse', o.id);
        await audit('oauth_refresh_reuse', 'denied', o.id, 'refresh_reuse');
        return oauthError(res, 'invalid_grant');
      }
      if (o.kind === 'invalid') {
        await audit('oauth_token', 'denied', o.id, 'invalid_grant');
        return oauthError(res, 'invalid_grant');
      }
      await audit('oauth_token_refreshed', 'ok', o.id);
      return json(res, 200, o.body);
    }
    return oauthError(res, 'unsupported_grant_type');
  }

  async function revoke(req: IncomingMessage, res: ServerResponse) {
    if (!take('token', req)) return tooMany(res);
    const state = await readState(res);
    if (!state) return;
    const form = await readForm(req, res);
    if (!form) return;
    const presented = form.get('token') ?? '';
    if (presented.length >= 43 && presented.length <= 64) {
      const h = sha256Hex(presented);
      let ended: string | undefined;
      await oauth.transact((d) => {
        const dev = d.devices.find(
          (x) => x.status === 'active' && mine(x) && ((x.family.accessHash && hexEqual(x.family.accessHash, h)) || (x.family.refreshHash && hexEqual(x.family.refreshHash, h))),
        );
        if (dev) {
          endDevice(dev, 'revoked', new Date(now()));
          ended = dev.id;
        }
      });
      if (ended) {
        await releaseGrants();
        await audit('oauth_device_revoked', 'ok', ended, 'client_revocation');
      }
    }
    res.writeHead(200, { 'cache-control': 'no-store' });
    res.end();
  }

  // ---------------------------------------------------------------- bearer authentication
  /** The device of this listener whose current access token is `h`, if it is active and unexpired. */
  const deviceForAccess = (s: OAuthState, h: string, t: number) =>
    s.devices.find(
      (x) =>
        x.status === 'active' &&
        mine(x) &&
        x.family.accessHash !== undefined &&
        hexEqual(x.family.accessHash, h) &&
        Date.parse(x.family.accessExpiresAt ?? '') > t &&
        Date.parse(x.expiresAt) > t,
    );

  async function authenticate(authorization: string | undefined): Promise<DeviceAuth> {
    const m = OAUTH_BEARER.exec(String(authorization ?? ''));
    if (!m) return { kind: 'unauthorized' };
    const h = sha256Hex(m[1]!);
    const t = now();
    let state: OAuthState;
    try {
      state = await oauth.read();
    } catch {
      log(`perch: OAuth state is unreadable; OAuth tokens on the ${listener} /mcp fail closed (503)`);
      pairing.close('aborted');
      return { kind: 'unavailable' };
    }
    if (isPublic && isPublicLocked(state)) {
      pairing.lockout('kill_switch');
      return { kind: 'unavailable' };
    }
    const device = deviceForAccess(state, h, t);
    if (!device) {
      knownAccess.delete(h);
      return { kind: 'unauthorized' };
    }
    rememberAccess(h, Date.parse(device.family.accessExpiresAt!));
    let bucket = deviceBuckets.get(device.id);
    if (!bucket) deviceBuckets.set(device.id, (bucket = new Bucket(120, now)));
    if (!bucket.take()) return { kind: 'limited' };
    let principal: Principal = READONLY_PRINCIPAL;
    if (device.grantClientId) {
      const p = await principalForGrantId(context.store, device.grantClientId);
      if (!p) return { kind: 'unauthorized' };
      principal = p;
    }
    pairing.firstUse(device.id);
    if (t - (lastSeenWritten.get(device.id) ?? 0) > LAST_SEEN_EVERY_MS) {
      lastSeenWritten.set(device.id, t);
      oauth
        .transact((d) => {
          const dev = d.devices.find((x) => x.id === device.id && x.status === 'active');
          if (dev) dev.lastSeenAt = new Date(t).toISOString();
        })
        .catch(() => log('perch: could not record a device as seen'));
    }
    // Before every tool call: this access token is still current and its device active (revocation, kill switch).
    const guard = async () => {
      const s = await oauth.read();
      if ((isPublic && isPublicLocked(s)) || !deviceForAccess(s, h, now())) throw new PerchError('This device was signed out or its token expired; no request was made', 'grant_revoked');
    };
    return { kind: 'ok', principal, guard, deviceId: device.id };
  }

  // ---------------------------------------------------------------- invalid-bearer throttle
  async function authenticateThrottled(authorization: string | undefined): Promise<DeviceAuth> {
    const t = now();
    const m = OAUTH_BEARER.exec(String(authorization ?? ''));
    // While blocked, unknown tokens get 401 without any state access; recently valid tokens still pass.
    if (t < bearerBlockedUntil && !(m && (knownAccess.get(sha256Hex(m[1]!)) ?? 0) > t)) return { kind: 'unauthorized' };
    const countInvalid = () => {
      invalidBearer = [...invalidBearer.filter((x) => t - x < 60_000), t];
      if (invalidBearer.length >= INVALID_BEARER_LIMIT) {
        bearerBlockedUntil = t + INVALID_BEARER_BLOCK_MS;
        invalidBearer = [];
        log(`perch: too many invalid bearer tokens on the ${listener} /mcp; unknown OAuth tokens get 401 for 5 minutes`);
      }
    };
    if (!m) {
      if (authorization !== undefined) countInvalid();
      return { kind: 'unauthorized' };
    }
    const a = await authenticate(authorization);
    if (a.kind === 'unauthorized') countInvalid();
    return a;
  }

  // ---------------------------------------------------------------- /mcp (public listener)
  async function mcp(req: IncomingMessage, res: ServerResponse) {
    if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed' }, { allow: 'POST' });
    const o = req.headers.origin;
    if (o !== undefined && o !== origin) return json(res, 403, { error: 'forbidden_origin' });
    const a = await authenticateThrottled(req.headers.authorization);
    if (a.kind === 'unavailable') return json(res, 503, { error: 'temporarily_unavailable' });
    if (a.kind === 'limited') return tooMany(res);
    if (a.kind === 'unauthorized') return unauthorized(res, OAUTH_BEARER.test(String(req.headers.authorization ?? '')));
    const { principal, guard } = a;
    const body = await readBody(req, hasWriteCapability(principal) ? MAX_WRITE_BODY_BYTES : MAX_BODY_BYTES);
    if (body === 'too_large') return json(res, 413, { jsonrpc: '2.0', error: { code: -32000, message: 'Request body too large' }, id: null });
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.toString('utf8'));
    } catch {
      return json(res, 400, { jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' }, id: null });
    }
    await context.luma.refresh();
    const server = createMcpServer(context, principal, { guard });
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
      enableDnsRebindingProtection: true,
      allowedHosts: [base.host],
    });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, parsed);
  }

  // ---------------------------------------------------------------- routing (discovery and /oauth/*)
  const isOAuthPath = (path: string) => DISCOVERY_PATHS.has(path) || oauthPaths.has(path);

  async function route(req: IncomingMessage, res: ServerResponse, url: URL) {
    const path = url.pathname;
    // The private listener also answers loopback Host names: OAuth lives only on its issuer name.
    if (!isPublic && String(req.headers.host ?? '').toLowerCase() !== base.host) return json(res, 404, { error: 'not_found' });
    const get = req.method === 'GET' || req.method === 'HEAD';
    if (path === '/.well-known/oauth-protected-resource' || path === '/.well-known/oauth-protected-resource/mcp') {
      return get ? json(res, 200, protectedResource(), { 'cache-control': 'public, max-age=300' }) : json(res, 405, { error: 'method_not_allowed' });
    }
    if (path === '/.well-known/oauth-authorization-server' || path === '/.well-known/oauth-authorization-server/mcp') {
      return get ? json(res, 200, authServer(), { 'cache-control': 'public, max-age=300' }) : json(res, 405, { error: 'method_not_allowed' });
    }
    if (!oauthPaths.has(path)) return json(res, 404, { error: 'not_found' });
    if (path === '/oauth/authorize' && get) return await authorize(req, res, url);
    if (path === '/oauth/pair' && (get || req.method === 'POST')) return await pairCode(req, res);
    if (path === '/oauth/google/callback' && get) return await googleCallback(req, res, url);
    if (path === '/oauth/totp' && (get || req.method === 'POST')) return await totpStep(req, res);
    if (path === '/oauth/wait' && get) return await wait(req, res);
    if (path === '/oauth/token' && req.method === 'POST') return await token(req, res);
    if (path === '/oauth/revoke' && req.method === 'POST') return await revoke(req, res);
    if (path === '/oauth/register' && req.method === 'POST') return await register(req, res);
    return json(res, 404, { error: 'not_found' });
  }

  /** After a restart, tokens issued earlier are known again before the listener accepts anything. */
  const warm = (devices: Device[]) => {
    const t = now();
    for (const d of devices) {
      const until = Date.parse(d.family.accessExpiresAt ?? '');
      if (d.status === 'active' && mine(d) && d.family.accessHash && until > t) rememberAccess(d.family.accessHash, until);
    }
  };

  return { listener, origin, host: base.host, resource, isOAuthPath, route, authenticate, authenticateThrottled, wwwAuthenticate, mcp, warm, takeAll: (req) => take('all', req) };
}

/** The public listener: fixed routing table, Host check, overall limit (Spec §1, §9). */
export async function startPublicServer(opts: PublicServerOptions): Promise<RunningPublicServer> {
  const host = opts.host ?? '127.0.0.1';
  validateBindHost(host);
  const app = createOAuthApp({ ...opts, listener: 'public' });
  const log = opts.log ?? ((l: string) => process.stderr.write(`${l}\n`));
  // An unreadable state is not an error here: every request then fails closed.
  try {
    app.warm((await opts.oauth.read()).devices);
  } catch {
    // fail closed later
  }
  const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
    if (res.headersSent) return;
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', pragma: 'no-cache', ...headers });
    res.end(JSON.stringify(body));
  };
  const server = createServer(async (req, res) => {
    try {
      if (String(req.headers.host ?? '').toLowerCase() !== app.host) return json(res, 403, { error: 'forbidden_host' });
      const url = new URL(req.url ?? '/', app.origin);
      const path = url.pathname;
      // /mcp has its own per-device limit; the overall limit protects the unauthenticated routes.
      if (path !== '/mcp' && !app.takeAll(req)) return json(res, 429, { error: 'rate_limited' }, { 'retry-after': '60' });
      if (path === '/mcp') return await app.mcp(req, res);
      if (app.isOAuthPath(path)) return await app.route(req, res, url);
      return json(res, 404, { error: 'not_found' });
    } catch (err) {
      log(`perch: internal error on the public listener (${err instanceof PerchError ? err.code : 'internal'})`);
      if (!res.headersSent) json(res, 500, { error: 'server_error' });
      else res.end();
    }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  return {
    port: (server.address() as AddressInfo).port,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
