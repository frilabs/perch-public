import { PerchError } from '../errors.js';
import { runPkceLoopback, type PasteRedirect } from '../oauth/loopback.js';
import type { TokenGrantResponse } from '../oauth/tokenProvider.js';
import type { LumaAccount } from '../store/credentialStore.js';
import { UpstreamError, validateLumaOrigin, type Upstream } from '../upstream.js';

/**
 * OAuth for the official Luma MCP server (docs/LUMA_SPEC.md §3), MCP authorization: protected resource
 * metadata (RFC 9728) at https://mcp.luma.com, the first authorization server it names (RFC 8414, Luma hosts
 * only), PKCE S256, resource indicator (RFC 8707), loopback redirect. Client identity: Perch's Client ID
 * Metadata Document when Luma supports CIMD, otherwise Dynamic Client Registration (RFC 7591) for exactly
 * this redirect URI. Public client, no secret.
 */
export const LUMA_MCP_ORIGIN = 'https://mcp.luma.com';
// Live 2026-10-27: the MCP endpoint is the origin root (POST / answers 401 with resource_metadata; /mcp is 404).
export const LUMA_MCP_URL = `${LUMA_MCP_ORIGIN}/`;
/** Perch's Client ID Metadata Document, served as a static file by frilabs.dev (source: pages/luma-client.json, copy in frilabs-home public/perch/). */
export const DEFAULT_LUMA_CLIENT_ID = 'https://frilabs.dev/perch/luma-client.json';
export const LUMA_CALLBACK_PATH = '/callback';

export interface LumaAuthServer {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint?: string;
  revocationEndpoint?: string;
  cimd: boolean;
  /** Scopes to request (protected resource scopes, plus offline_access when announced). */
  scopes: string[];
  /** The resource value to send (RFC 8707). */
  resource: string;
}

const bad = (why: string) => new PerchError(`Luma OAuth metadata unusable: ${why}`, 'luma_metadata_invalid');

/** Splits an https URL on a Luma host into the origin and path the Upstream allowlist accepts. */
function endpoint(raw: unknown, what: string, allowQuery = false): { origin: string; path: string; url: string } {
  if (typeof raw !== 'string') throw bad(`${what} missing`);
  const origin = validateLumaOrigin(raw);
  const u = new URL(raw);
  // RFC 6749 §3.1: an authorization endpoint may carry a query (kept and extended by the browser login);
  // a fragment is never allowed. Endpoints Perch calls itself (token, revocation) stay query-free.
  if (u.hash || (u.search && !allowQuery)) throw bad(`${what} must not carry ${allowQuery ? 'a fragment' : 'a query or fragment'}`);
  return { origin, path: u.pathname, url: u.toString() };
}

const strings = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.length <= 200) : []);

export async function discoverLumaAuth(upstream: Upstream): Promise<LumaAuthServer> {
  let prm: Record<string, unknown> | undefined;
  for (const path of ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource']) {
    try {
      prm = await upstream.json<Record<string, unknown>>('luma', { method: 'GET', path, maxBytes: 64 * 1024 });
      break;
    } catch (err) {
      if (!(err instanceof UpstreamError && err.status === 404)) throw err;
    }
  }
  if (!prm) throw bad('no protected resource metadata at https://mcp.luma.com');
  const resource = typeof prm.resource === 'string' ? prm.resource : LUMA_MCP_URL;
  if (resource !== LUMA_MCP_URL && resource !== LUMA_MCP_ORIGIN && resource !== `${LUMA_MCP_ORIGIN}/`) throw bad('unexpected resource');
  const issuer = strings(prm.authorization_servers)[0];
  if (!issuer) throw bad('no authorization server');
  const iss = endpoint(issuer, 'issuer');
  const issuerPath = iss.path === '/' ? '' : iss.path.replace(/\/$/, '');
  let meta: Record<string, unknown> | undefined;
  for (const path of [`/.well-known/oauth-authorization-server${issuerPath}`, `${issuerPath}/.well-known/openid-configuration`]) {
    try {
      meta = await upstream.json<Record<string, unknown>>('lumaauth', { method: 'GET', path, origin: iss.origin, maxBytes: 64 * 1024 });
      break;
    } catch (err) {
      if (!(err instanceof UpstreamError && err.status === 404)) throw err;
    }
  }
  if (!meta) throw bad('no authorization server metadata');
  if (typeof meta.issuer !== 'string' || meta.issuer.replace(/\/$/, '') !== issuer.replace(/\/$/, '')) throw bad('issuer missing or mismatched');
  if (!strings(meta.code_challenge_methods_supported).includes('S256')) throw bad('PKCE S256 not announced');
  const authz = endpoint(meta.authorization_endpoint, 'authorization_endpoint', true);
  const token = endpoint(meta.token_endpoint, 'token_endpoint');
  const reg = meta.registration_endpoint !== undefined ? endpoint(meta.registration_endpoint, 'registration_endpoint') : undefined;
  const rev = meta.revocation_endpoint !== undefined ? endpoint(meta.revocation_endpoint, 'revocation_endpoint') : undefined;
  const authMethods = strings(meta.token_endpoint_auth_methods_supported);
  // CIMD clients are public clients: usable only if the token endpoint accepts "none" (or announces nothing).
  const cimd = meta.client_id_metadata_document_supported === true && (authMethods.length === 0 || authMethods.includes('none'));
  if (!cimd && !reg) throw bad('neither Client ID Metadata Documents nor Dynamic Client Registration is offered');
  const scopes = strings(prm.scopes_supported);
  if (strings(meta.scopes_supported).includes('offline_access') && !scopes.includes('offline_access')) scopes.push('offline_access');
  return {
    issuer,
    authorizationEndpoint: authz.url,
    tokenEndpoint: token.url,
    ...(reg ? { registrationEndpoint: reg.url } : {}),
    ...(rev ? { revocationEndpoint: rev.url } : {}),
    cimd,
    scopes,
    resource,
  };
}

async function registerClient(upstream: Upstream, as: LumaAuthServer, redirectUri: string): Promise<string> {
  const reg = endpoint(as.registrationEndpoint, 'registration_endpoint');
  const res = await upstream.json<{ client_id?: unknown }>('lumaauth', {
    method: 'POST',
    path: reg.path,
    origin: reg.origin,
    json: {
      client_name: 'Perch',
      client_uri: 'https://github.com/frilabs/perch-public',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      ...(as.scopes.length ? { scope: as.scopes.join(' ') } : {}),
    },
    maxBytes: 64 * 1024,
  });
  if (typeof res.client_id !== 'string' || !res.client_id || res.client_id.length > 512) throw bad('registration returned no client_id');
  return res.client_id;
}

export interface LumaGrant {
  clientId: string;
  registration: 'cimd' | 'dcr';
  accessToken: string;
  refreshToken: string;
  scopes: string[];
  server: LumaAuthServer;
}

async function tokenRequest(upstream: Upstream, tokenEndpoint: string, form: Record<string, string>): Promise<TokenGrantResponse> {
  const t = endpoint(tokenEndpoint, 'token_endpoint');
  return upstream.json<TokenGrantResponse>('lumaauth', { method: 'POST', path: t.path, origin: t.origin, form, maxBytes: 64 * 1024 });
}

export async function runLumaAuthorization(opts: {
  upstream: Upstream;
  clientIdUrl?: string;
  port?: number;
  timeoutMs?: number;
  onAuthUrl: (url: string) => void;
  paste?: PasteRedirect;
}): Promise<LumaGrant> {
  const as = await discoverLumaAuth(opts.upstream);
  let clientId = '';
  // Spec §3: Dynamic Client Registration when offered (no dependency on a hosted document), else CIMD.
  const registration: 'cimd' | 'dcr' = as.registrationEndpoint ? 'dcr' : 'cimd';
  return runPkceLoopback({
    provider: 'Luma',
    authEndpoint: as.authorizationEndpoint,
    authParams: { resource: as.resource, ...(as.scopes.length ? { scope: as.scopes.join(' ') } : {}) },
    redirectHost: '127.0.0.1',
    callbackPath: LUMA_CALLBACK_PATH,
    ...(opts.port !== undefined ? { port: opts.port } : {}),
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    onAuthUrl: opts.onAuthUrl,
    ...(opts.paste ? { paste: opts.paste } : {}),
    prepare: async (redirectUri) => {
      clientId = registration === 'cimd' ? (opts.clientIdUrl ?? DEFAULT_LUMA_CLIENT_ID) : await registerClient(opts.upstream, as, redirectUri);
      return { client_id: clientId };
    },
    exchange: async (code, verifier, redirectUri) => {
      const tok = await tokenRequest(opts.upstream, as.tokenEndpoint, {
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
        resource: as.resource,
      });
      if (!tok.access_token) throw new PerchError('Luma did not return an access token', 'oauth_incomplete');
      if (!tok.refresh_token) throw new PerchError('Luma did not return a refresh token; Perch needs one to stay connected', 'oauth_no_refresh_token');
      return {
        clientId,
        registration,
        accessToken: tok.access_token,
        refreshToken: tok.refresh_token,
        scopes: (tok.scope ?? as.scopes.join(' ')).split(/\s+/).filter(Boolean),
        server: as,
      };
    },
  });
}

/** refresh_token grant at the token endpoint stored at onboarding (re-validated against the Luma hosts). */
export function refreshLumaToken(upstream: Upstream, account: LumaAccount): Promise<TokenGrantResponse> {
  return tokenRequest(upstream, account.tokenEndpoint, {
    grant_type: 'refresh_token',
    refresh_token: account.refreshToken,
    client_id: account.clientId,
    resource: account.resource ?? LUMA_MCP_URL,
  });
}

/** Best-effort token revocation (RFC 7009) when Luma announced an endpoint. */
export async function revokeLumaToken(upstream: Upstream, account: LumaAccount): Promise<boolean> {
  if (!account.revocationEndpoint) return false;
  const r = endpoint(account.revocationEndpoint, 'revocation_endpoint');
  await upstream.raw('lumaauth', {
    method: 'POST',
    path: r.path,
    origin: r.origin,
    form: { token: account.refreshToken, token_type_hint: 'refresh_token', client_id: account.clientId },
  });
  return true;
}
