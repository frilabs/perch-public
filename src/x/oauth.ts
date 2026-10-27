import path from 'node:path';
import { PerchError } from '../errors.js';
import { newAccountId, validateLabel } from '../ids.js';
import { runPkceLoopback, type PasteRedirect } from '../oauth/loopback.js';
import { RefreshingTokenProvider, type TokenGrantResponse } from '../oauth/tokenProvider.js';
import { ensurePrivateDir, pathExists, readPrivateFile, writePrivateFileAtomic } from '../secureFs.js';
import type { CredentialStore, XAccount } from '../store/credentialStore.js';
import { UpstreamError, type Upstream } from '../upstream.js';

/**
 * X (docs/X_SPEC.md): OAuth 2.0 Authorization Code with PKCE through the operator's own X developer
 * app. One app per installation (x-client.json, 0600). Public client ("Native App"): client_id in the token
 * request body, no secret. Confidential client ("Web App" with a secret): HTTP Basic auth at the token endpoint.
 * Fixed redirect http://127.0.0.1:8771/x/callback (registered in the app), state checked, PKCE S256.
 */
export const X_OAUTH_PORT = 8771;
export const X_OAUTH_CALLBACK_PATH = '/x/callback';
export const X_OAUTH_REDIRECT_URI = `http://127.0.0.1:${X_OAUTH_PORT}${X_OAUTH_CALLBACK_PATH}`;
export const X_AUTHORIZE_URL = 'https://x.com/i/oauth2/authorize';
export const X_TOKEN_PATH = '/2/oauth2/token';
const X_REVOKE_PATH = '/2/oauth2/revoke';
/** offline.access: refresh tokens (access tokens live about 2 hours). */
export const X_SCOPES = ['tweet.read', 'tweet.write', 'users.read', 'offline.access'] as const;
export const X_DEVELOPER_URL = 'https://developer.x.com/en/portal/dashboard';
const MAX_CLIENT_FILE_BYTES = 4096;

export interface XClient {
  clientId: string;
  /** Present only for a confidential client. */
  clientSecret?: string;
}

/** Default location: $XDG_CONFIG_HOME/perch/x-client.json (~/.config/perch/…), from the given environment. */
export function xClientFileFor(env: Record<string, string | undefined>, home: string): string {
  return path.join(env.XDG_CONFIG_HOME || path.join(env.HOME || home, '.config'), 'perch', 'x-client.json');
}

const SAFE_VALUE = /^[\x21-\x7e]{8,512}$/;

/** Checks pasted client values (printable, no whitespace, sane length). Never echoes them. An empty secret = public client. */
export function parseXClient(raw: { clientId: string; clientSecret?: string }): XClient {
  const clientId = raw.clientId.trim();
  const clientSecret = raw.clientSecret?.trim() ?? '';
  if (!SAFE_VALUE.test(clientId)) throw new PerchError('The OAuth 2.0 Client ID looks wrong (copy it from "Keys and tokens" of your X app)', 'usage');
  if (!clientSecret) return { clientId };
  if (!SAFE_VALUE.test(clientSecret)) throw new PerchError('The OAuth 2.0 Client Secret looks wrong (copy it from "Keys and tokens", or leave it empty for a Native App)', 'usage');
  if (clientId === clientSecret) throw new PerchError('Client ID and Client Secret are the same value; copy each one separately', 'usage');
  return { clientId, clientSecret };
}

/** Reads the client file (owner-only, no symlink). Missing → PerchError 'not_found'; malformed → 'bad_client_file'. */
export async function readXClient(file: string): Promise<XClient> {
  const buf = await readPrivateFile(file);
  if (buf.length > MAX_CLIENT_FILE_BYTES) throw new PerchError(`The X client file ${file} is too large`, 'bad_client_file');
  try {
    const o = JSON.parse(buf.toString('utf8')) as { client_id?: unknown; client_secret?: unknown };
    if (typeof o.client_id !== 'string' || (o.client_secret !== undefined && typeof o.client_secret !== 'string')) throw new Error('shape');
    return parseXClient({ clientId: o.client_id, ...(o.client_secret !== undefined ? { clientSecret: o.client_secret as string } : {}) });
  } catch {
    throw new PerchError(`The X client file ${file} does not contain a valid client_id (and optional client_secret)`, 'bad_client_file');
  }
}

export async function saveXClient(file: string, client: XClient): Promise<void> {
  const dir = path.dirname(file);
  if (!(await pathExists(dir))) await ensurePrivateDir(dir);
  const json = `${JSON.stringify({ client_id: client.clientId, ...(client.clientSecret ? { client_secret: client.clientSecret } : {}) }, null, 2)}\n`;
  await writePrivateFileAtomic(file, Buffer.from(json, 'utf8'));
}

export const shortXClientId = (id: string) => `${id.slice(0, 8)}…`;
export const xClientKind = (c: { clientSecret?: string }) => (c.clientSecret ? 'confidential (with secret)' : 'public (no secret)');

/** Token endpoint call: Basic auth for a confidential client, client_id in the body for a public one. */
async function tokenRequest(upstream: Upstream, client: XClient, form: Record<string, string>): Promise<TokenGrantResponse> {
  const headers = client.clientSecret
    ? { authorization: `Basic ${Buffer.from(`${client.clientId}:${client.clientSecret}`, 'utf8').toString('base64')}` }
    : undefined;
  return upstream.json<TokenGrantResponse>('x', {
    method: 'POST',
    path: X_TOKEN_PATH,
    form: client.clientSecret ? form : { ...form, client_id: client.clientId },
    ...(headers ? { headers } : {}),
    maxBytes: 64 * 1024,
  });
}

export interface XGrant {
  client: XClient;
  accessToken: string;
  refreshToken: string;
  scopes: string[];
}

export interface XAuthorizationOptions {
  client: XClient;
  upstream: Upstream;
  timeoutMs?: number;
  onAuthUrl: (url: string) => void;
  paste?: PasteRedirect;
}

/** Login in the browser (fixed redirect, state, PKCE S256), then the code exchange with the verifier. */
export async function runXAuthorization(opts: XAuthorizationOptions): Promise<XGrant> {
  return runPkceLoopback({
    provider: 'X',
    authEndpoint: X_AUTHORIZE_URL,
    authParams: { client_id: opts.client.clientId, scope: X_SCOPES.join(' ') },
    redirectHost: '127.0.0.1',
    callbackPath: X_OAUTH_CALLBACK_PATH,
    port: X_OAUTH_PORT,
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    onAuthUrl: opts.onAuthUrl,
    ...(opts.paste ? { paste: opts.paste } : {}),
    exchange: async (code, verifier, redirectUri) => {
      const tok = await tokenRequest(opts.upstream, opts.client, {
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      });
      if (!tok.access_token) throw new PerchError('X did not return an access token', 'oauth_incomplete');
      if (!tok.refresh_token) {
        throw new PerchError('X did not return a refresh token (the offline.access scope is missing); Perch needs one to stay connected', 'oauth_no_refresh_token');
      }
      const scopes = (tok.scope ?? X_SCOPES.join(' ')).split(/\s+/).filter(Boolean);
      if (!scopes.includes('tweet.write')) throw new PerchError('X did not grant tweet.write: set the app permissions to "Read and write" and log in again', 'provider_scope_missing');
      return { client: opts.client, accessToken: tok.access_token, refreshToken: tok.refresh_token, scopes };
    },
  });
}

/** The connected user (GET /2/users/me): numeric id, @username, display name. */
export async function fetchXMe(upstream: Upstream, accessToken: string): Promise<{ userId: string; username: string; name?: string }> {
  const r = await upstream.json<{ data?: { id?: unknown; username?: unknown; name?: unknown } }>('x', {
    method: 'GET',
    path: '/2/users/me',
    headers: { authorization: `Bearer ${accessToken}` },
    maxBytes: 64 * 1024,
  });
  const d = r.data;
  if (!d || typeof d.id !== 'string' || !/^[0-9]{1,25}$/.test(d.id) || typeof d.username !== 'string' || !/^[A-Za-z0-9_]{1,50}$/.test(d.username)) {
    throw new PerchError('X returned no usable user for this login', 'upstream_bad_response');
  }
  return { userId: d.id, username: d.username, ...(typeof d.name === 'string' && d.name ? { name: d.name.slice(0, 200) } : {}) };
}

/**
 * Stores the login: a new x-… account, or the existing one of the same X user updated in place (same id, client
 * grants stay valid, the old refresh token is replaced).
 */
export async function upsertXAccount(
  store: CredentialStore,
  input: { label: string; grant: XGrant; me: { userId: string; username: string; name?: string } },
): Promise<{ account: XAccount; updated: boolean }> {
  const label = validateLabel(input.label);
  const { grant, me } = input;
  return store.update((data) => {
    const now = new Date().toISOString();
    const fields = {
      label,
      userId: me.userId,
      username: me.username,
      ...(me.name ? { name: me.name } : {}),
      clientId: grant.client.clientId,
      ...(grant.client.clientSecret ? { clientSecret: grant.client.clientSecret } : {}),
      refreshToken: grant.refreshToken,
      scopes: grant.scopes.slice(0, 50).map((s) => s.slice(0, 100)),
      updatedAt: now,
    };
    const existing = data.x.find((a) => a.userId === me.userId);
    if (existing) {
      delete existing.name;
      delete existing.clientSecret;
      Object.assign(existing, fields);
      return { account: existing, updated: true };
    }
    const account: XAccount = { id: newAccountId('x', data.x.map((a) => a.id)), ...fields, createdAt: now };
    data.x.push(account);
    return { account, updated: false };
  });
}

/** OAuth errors of a refresh that mean the stored login is gone (X answers invalid_request for a dead refresh token). */
const DEAD_REFRESH = new Set(['invalid_grant', 'invalid_request', 'unauthorized_client', 'invalid_client']);

/** refresh_token grant with the client stored on the account. X rotates the refresh token on every refresh. */
export async function refreshXToken(upstream: Upstream, account: XAccount, refreshToken: string): Promise<TokenGrantResponse> {
  try {
    return await tokenRequest(upstream, { clientId: account.clientId, ...(account.clientSecret ? { clientSecret: account.clientSecret } : {}) }, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    });
  } catch (err) {
    // Normalised so the token provider shows the reconnect hint (the request itself is fixed by Perch).
    if (err instanceof UpstreamError && (err.status === 400 || err.status === 401) && err.upstreamCode && DEAD_REFRESH.has(err.upstreamCode)) {
      throw new UpstreamError(err.message, err.status, 'invalid_grant');
    }
    throw err;
  }
}

/** Access tokens of X accounts (single-flight refresh, rotation persisted under the store lock). */
export function createXTokenProvider(store: CredentialStore, upstream: Upstream): RefreshingTokenProvider<XAccount> {
  return new RefreshingTokenProvider<XAccount>(store, {
    name: 'X',
    list: (d) => d.x,
    refresh: (a, rt) => refreshXToken(upstream, a, rt),
    reconnect: () => '`perch x add --label <label>` (updates the same account)',
  });
}

/** Best-effort revocation of the stored refresh token at X (perch x remove --revoke). */
export async function revokeXToken(upstream: Upstream, account: XAccount): Promise<void> {
  const client: XClient = { clientId: account.clientId, ...(account.clientSecret ? { clientSecret: account.clientSecret } : {}) };
  await upstream.raw('x', {
    method: 'POST',
    path: X_REVOKE_PATH,
    capability: 'admin',
    form: { token: account.refreshToken, token_type_hint: 'refresh_token', ...(client.clientSecret ? {} : { client_id: client.clientId }) },
    ...(client.clientSecret ? { headers: { authorization: `Basic ${Buffer.from(`${client.clientId}:${client.clientSecret}`, 'utf8').toString('base64')}` } } : {}),
    maxBytes: 64 * 1024,
  });
}
