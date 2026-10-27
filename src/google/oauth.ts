import { PerchError } from '../errors.js';
import { DEFAULT_AUTH_TIMEOUT_MS, MAX_AUTH_TIMEOUT_MS, runPkceLoopback, type PasteRedirect } from '../oauth/loopback.js';
import type { Upstream } from '../upstream.js';

export const DRIVE_READONLY_SCOPE = 'https://www.googleapis.com/auth/drive.readonly';
/** Full Drive access; requested only with `perch google add --allow-write`, and checked before every Drive write. */
export const DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive';
const AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const CALLBACK_PATH = '/oauth2/callback';
export { DEFAULT_AUTH_TIMEOUT_MS, MAX_AUTH_TIMEOUT_MS };

export interface GoogleClientCredentials {
  clientId: string;
  clientSecret: string;
}

export interface GoogleTokenResponse {
  access_token?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

export interface AuthorizationResult {
  refreshToken: string;
  accessToken: string;
  expiresAt: number;
  scopes: string[];
}

/** Parses the JSON downloaded for a Google Cloud "Desktop app" OAuth client. */
export function parseClientFile(contents: string): GoogleClientCredentials {
  try {
    const parsed = JSON.parse(contents) as { installed?: { client_id?: unknown; client_secret?: unknown } };
    const c = parsed.installed;
    if (c && typeof c.client_id === 'string' && typeof c.client_secret === 'string' && c.client_id && c.client_secret) {
      return { clientId: c.client_id, clientSecret: c.client_secret };
    }
  } catch {
    // fall through
  }
  throw new PerchError(
    'Google client file must be the JSON of an OAuth client of type "Desktop app" (top-level "installed" key)',
    'bad_client_file',
  );
}

function grantedScopes(tok: GoogleTokenResponse): string[] {
  return (tok.scope ?? '').split(/\s+/).filter(Boolean);
}

/**
 * Validates an authorization_code token response: offline refresh token + every required scope
 * actually granted (default drive.readonly; users can untick checkboxes on the consent screen).
 */
export function assertUsableGrant(tok: GoogleTokenResponse, required: string[] = [DRIVE_READONLY_SCOPE]): AuthorizationResult {
  if (!tok.access_token) throw new PerchError('Google did not return an access token', 'oauth_incomplete');
  if (!tok.refresh_token) {
    throw new PerchError(
      'Google did not return a refresh token. Remove Perch under https://myaccount.google.com/permissions and retry.',
      'oauth_no_refresh_token',
    );
  }
  const scopes = grantedScopes(tok);
  for (const scope of required) {
    if (!scopes.includes(scope)) {
      throw new PerchError(
        `The ${scope} permission was not granted. Retry and tick every requested checkbox on the consent screen.`,
        'oauth_scope_missing',
      );
    }
  }
  return {
    refreshToken: tok.refresh_token,
    accessToken: tok.access_token,
    expiresAt: Date.now() + (tok.expires_in ?? 0) * 1000,
    scopes,
  };
}

export interface LoopbackOptions {
  client: GoogleClientCredentials;
  upstream: Upstream;
  /** 0 = random free port. Use a fixed port when forwarding it over SSH (`ssh -L`). */
  port?: number;
  timeoutMs?: number;
  loginHint?: string;
  /** Requested scopes (default: drive.readonly). All of them must be granted. */
  scopes?: string[];
  /**
   * include_granted_scopes=true (incremental authorization): the new grant also covers what this OAuth client
   * was granted for the account before. Only the unified `perch google add` sets it; the separate grants keep false.
   */
  includeGrantedScopes?: boolean;
  /** Replaces the default "every requested scope granted" check (e.g. for scope aliases like `email`). */
  verify?: (tok: GoogleTokenResponse) => AuthorizationResult;
  onAuthUrl: (url: string) => void;
  /** Paste-the-redirect-address input racing the callback (login without a tunnel). */
  paste?: PasteRedirect;
}

/**
 * Desktop-app OAuth: loopback redirect on 127.0.0.1, random state, PKCE S256.
 * The state is verified before the code is ever exchanged.
 */
export async function runLoopbackAuthorization(opts: LoopbackOptions): Promise<AuthorizationResult> {
  const scopes = opts.scopes ?? [DRIVE_READONLY_SCOPE];
  return runPkceLoopback({
    provider: 'Google',
    authEndpoint: AUTH_ENDPOINT,
    authParams: {
      client_id: opts.client.clientId,
      scope: scopes.join(' '),
      access_type: 'offline',
      prompt: 'consent',
      include_granted_scopes: opts.includeGrantedScopes ? 'true' : 'false',
      ...(opts.loginHint ? { login_hint: opts.loginHint } : {}),
    },
    redirectHost: '127.0.0.1',
    callbackPath: CALLBACK_PATH,
    ...(opts.port !== undefined ? { port: opts.port } : {}),
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    onAuthUrl: opts.onAuthUrl,
    ...(opts.paste ? { paste: opts.paste } : {}),
    exchange: async (code, verifier, redirectUri) => {
      const tok = await opts.upstream.json<GoogleTokenResponse>('oauth', {
        method: 'POST',
        path: '/token',
        form: {
          grant_type: 'authorization_code',
          code,
          code_verifier: verifier,
          redirect_uri: redirectUri,
          client_id: opts.client.clientId,
          client_secret: opts.client.clientSecret,
        },
      });
      return opts.verify ? opts.verify(tok) : assertUsableGrant(tok, scopes);
    },
  });
}

/** The OAuth client of a record that holds its own login (connected separately, not through an account group). */
export function ownClient(a: { id: string; clientId?: string; clientSecret?: string }): GoogleClientCredentials {
  if (!a.clientId || !a.clientSecret) throw new PerchError(`Account ${a.id} has no OAuth client of its own`, 'grant_invalid');
  return { clientId: a.clientId, clientSecret: a.clientSecret };
}

export async function refreshAccessToken(
  upstream: Upstream,
  client: GoogleClientCredentials,
  refreshToken: string,
): Promise<GoogleTokenResponse> {
  return upstream.json<GoogleTokenResponse>('oauth', {
    method: 'POST',
    path: '/token',
    form: {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: client.clientId,
      client_secret: client.clientSecret,
    },
  });
}

/** Revokes the grant at Google (refresh token revocation revokes the whole grant). */
export async function revokeToken(upstream: Upstream, token: string): Promise<void> {
  await upstream.raw('oauth', { method: 'POST', path: '/revoke', form: { token } });
}
