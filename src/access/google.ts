import { createHash, randomBytes } from 'node:crypto';
import { z } from 'zod';
import { PerchError } from '../errors.js';
import { readPrivateFile } from '../secureFs.js';
import type { Upstream } from '../upstream.js';

/**
 * Google sign-in of the public access (Spec §5), OpenID Connect Authorization Code flow with PKCE, state
 * and nonce, scopes `openid email` only. The ID token is taken ONLY from the direct TLS response of the
 * fixed Google token endpoint (https://oauth2.googleapis.com/token). Per OpenID Connect Core 1.0 §3.1.3.7
 * the client MAY then rely on TLS server validation instead of checking the token signature, so no JWKS is
 * fetched and no JWT library is needed. The claims are still checked strictly.
 */
export const GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);
/** auth_time / iat must be this recent (fresh Google sign-in, Spec §0a item 8). */
export const MAX_AUTH_AGE_SECONDS = 600;
const CLOCK_SKEW_SECONDS = 60;

export interface GoogleLoginClient {
  clientId: string;
  clientSecret: string;
}

const WebClientSchema = z.object({
  web: z.object({
    client_id: z.string().regex(/^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$/),
    client_secret: z.string().min(10).max(200),
    redirect_uris: z.array(z.string()).optional(),
  }),
});

/** Reads the JSON of a Google OAuth client of type "Web application" (downloaded from the Cloud console). */
export async function loadGoogleLoginClient(file: string, expectedRedirect: string): Promise<GoogleLoginClient> {
  let json: unknown;
  try {
    json = JSON.parse((await readPrivateFile(file)).toString('utf8'));
  } catch (err) {
    if (err instanceof PerchError) throw err;
    throw new PerchError(`${file} is not valid JSON`, 'bad_config');
  }
  const parsed = WebClientSchema.safeParse(json);
  if (!parsed.success) {
    throw new PerchError(`${file} is not a Google OAuth client of type "Web application" (expected {"web": {"client_id", "client_secret", ...}})`, 'bad_config');
  }
  const uris = parsed.data.web.redirect_uris;
  if (uris && !uris.includes(expectedRedirect)) {
    throw new PerchError(`The Google web client does not list the redirect URI ${expectedRedirect}; add it in the Google Cloud console`, 'bad_config');
  }
  return { clientId: parsed.data.web.client_id, clientSecret: parsed.data.web.client_secret };
}

export interface GoogleAuthRequest {
  url: string;
  state: string;
  nonce: string;
  verifier: string;
}

const b64url = (b: Buffer) => b.toString('base64url');

export function googleAuthRequest(client: GoogleLoginClient, redirectUri: string): GoogleAuthRequest {
  const state = b64url(randomBytes(24));
  const nonce = b64url(randomBytes(24));
  const verifier = b64url(randomBytes(48));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const u = new URL(GOOGLE_AUTH_ENDPOINT);
  u.search = new URLSearchParams({
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: redirectUri,
    scope: 'openid email',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    prompt: 'select_account',
    max_age: '0',
  }).toString();
  return { url: u.toString(), state, nonce, verifier };
}

export interface GoogleIdentity {
  sub: string;
  email: string;
}

const ClaimsSchema = z.object({
  iss: z.string(),
  aud: z.union([z.string(), z.array(z.string())]),
  azp: z.string().optional(),
  sub: z.string().regex(/^[0-9]{1,64}$/),
  email: z.string().min(3).max(254),
  email_verified: z.union([z.boolean(), z.literal('true')]).optional(),
  exp: z.number(),
  iat: z.number(),
  nonce: z.string().optional(),
  auth_time: z.number().optional(),
});

/** Decodes the payload of a compact JWS without verifying the signature (see the module comment). */
function decodePayload(idToken: string): unknown {
  const parts = idToken.split('.');
  if (parts.length !== 3 || !parts.every((p) => /^[A-Za-z0-9_-]*$/.test(p))) throw new PerchError('Google returned a malformed ID token', 'google_login_failed');
  try {
    return JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
  } catch {
    throw new PerchError('Google returned a malformed ID token', 'google_login_failed');
  }
}

/** Strict claim checks (Spec §5). `nowSeconds` is injectable for tests. */
export function checkIdTokenClaims(payload: unknown, client: GoogleLoginClient, nonce: string, nowSeconds = Date.now() / 1000): GoogleIdentity {
  const parsed = ClaimsSchema.safeParse(payload);
  const fail = (why: string) => new PerchError(`Google sign-in rejected: ${why}`, 'google_login_failed');
  if (!parsed.success) throw fail('unexpected ID token claims');
  const c = parsed.data;
  if (!ISSUERS.has(c.iss)) throw fail('wrong issuer');
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(client.clientId)) throw fail('wrong audience');
  if (aud.length > 1 && c.azp !== client.clientId) throw fail('wrong authorized party');
  if (c.exp + CLOCK_SKEW_SECONDS <= nowSeconds) throw fail('ID token expired');
  if (c.iat > nowSeconds + CLOCK_SKEW_SECONDS || nowSeconds - c.iat > MAX_AUTH_AGE_SECONDS) throw fail('ID token too old');
  if (c.nonce !== nonce) throw fail('nonce mismatch');
  if (c.email_verified !== true && c.email_verified !== 'true') throw fail('email not verified');
  if (c.auth_time !== undefined && nowSeconds - c.auth_time > MAX_AUTH_AGE_SECONDS) throw fail('Google sign-in is not fresh');
  return { sub: c.sub, email: c.email.toLowerCase() };
}

/** Exchanges the authorization code at the fixed Google token endpoint and checks the ID token. */
export async function exchangeGoogleCode(
  upstream: Upstream,
  client: GoogleLoginClient,
  input: { code: string; redirectUri: string; verifier: string; nonce: string; nowSeconds?: number },
): Promise<GoogleIdentity> {
  if (!/^[A-Za-z0-9/_.~-]{10,512}$/.test(input.code)) throw new PerchError('Google sign-in rejected: malformed code', 'google_login_failed');
  let res: { id_token?: unknown };
  try {
    res = await upstream.json<{ id_token?: unknown }>('oauth', {
      method: 'POST',
      path: '/token',
      form: {
        grant_type: 'authorization_code',
        code: input.code,
        client_id: client.clientId,
        client_secret: client.clientSecret,
        redirect_uri: input.redirectUri,
        code_verifier: input.verifier,
      },
      maxBytes: 64 * 1024,
    });
  } catch (err) {
    if (err instanceof PerchError && err.code === 'upstream_error') throw new PerchError('Google sign-in rejected the code', 'google_login_failed');
    throw err;
  }
  if (typeof res.id_token !== 'string') throw new PerchError('Google returned no ID token', 'google_login_failed');
  return checkIdTokenClaims(decodePayload(res.id_token), client, input.nonce, input.nowSeconds);
}
