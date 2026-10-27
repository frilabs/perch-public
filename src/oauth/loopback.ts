import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { PerchError } from '../errors.js';

export const DEFAULT_AUTH_TIMEOUT_MS = 300_000;
/** Upper bound (also keeps setTimeout far below its 2^31 ms overflow). */
export const MAX_AUTH_TIMEOUT_MS = 3_600_000;

/**
 * Login without a tunnel (docs/GUIDED_PROVIDER_SETUP_SPEC.md §2): next to the loopback callback, the operator may
 * paste the address the browser could not open (the redirect to 127.0.0.1 on the server). Whichever arrives
 * first wins; the other is cancelled through `signal`.
 */
export interface PasteRedirect {
  /**
   * Reads one pasted address. Resolves undefined when no input is possible (no terminal, end of input): the flow
   * then only waits for the callback. Must stop reading (and release stdin) as soon as `signal` aborts.
   */
  read: (signal: AbortSignal) => Promise<string | undefined>;
  /** A pasted address was refused (wrong host, port, path or state); the flow keeps waiting. */
  onRejected?: (reason: string) => void;
}

export interface PkceLoopbackOptions<T> {
  /** Name used in messages, e.g. "Google" or "Microsoft". */
  provider: string;
  /** Fixed authorization endpoint (never user supplied). */
  authEndpoint: string;
  /** Extra authorization parameters (client_id, scope, prompt, ...). */
  authParams: Record<string, string>;
  /** Host name in the redirect URI. The listener always binds 127.0.0.1 only. */
  redirectHost: '127.0.0.1' | 'localhost';
  callbackPath: string;
  /** 0 = random free port. Use a fixed port when forwarding it over SSH (`ssh -L`). */
  port?: number;
  timeoutMs?: number;
  onAuthUrl: (url: string) => void;
  /**
   * Runs once the callback port is known, before the authorization URL is built; its parameters are added
   * (e.g. a client id registered for exactly this redirect URI).
   */
  prepare?: (redirectUri: string) => Promise<Record<string, string>>;
  /** Optional paste-the-redirect-address input that races the callback. */
  paste?: PasteRedirect;
  /**
   * Send the PKCE challenge (default true). Only false for providers whose standard apps do not support PKCE
   * (for a confidential client with a secret); state is checked either way.
   */
  pkce?: boolean;
  /** Exchanges the code (with the PKCE verifier) at the fixed token endpoint. */
  exchange: (code: string, verifier: string, redirectUri: string) => Promise<T>;
}

const b64url = (b: Buffer) => b.toString('base64url');

export function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb) && a.length === b.length;
}

export const LOOPBACK_HOSTS: readonly string[] = ['127.0.0.1', 'localhost', '[::1]'];
/** Upper bound for a pasted address (an authorization response is far below). */
export const MAX_PASTED_URL_LENGTH = 8192;

const providerError = (provider: string, error: string) =>
  new PerchError(`${provider} authorization failed: ${/^[a-z_]{1,64}$/.test(error) ? error : 'unknown_error'}`, 'oauth_denied');

/**
 * Checks a pasted redirect address as strictly as the callback: http on a loopback host with the expected port and
 * path, matching state (constant time). Returns the code; `error=` (with the right state) is a denial. Messages
 * never repeat the address (it carries the authorization code).
 */
export function parsePastedRedirect(raw: string, expected: { port: number; callbackPath: string; state: string; provider: string }): string {
  const bad = (why: string) => new PerchError(`That address was not accepted: ${why}`, 'paste_rejected');
  let text = raw.trim();
  if (!text) throw bad('it is empty');
  if (text.length > MAX_PASTED_URL_LENGTH) throw bad('it is too long');
  // Some browsers hide the scheme in the address bar; copying usually keeps it, but tolerate its absence.
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = `http://${text}`;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw bad('it is not a web address');
  }
  if (url.protocol !== 'http:') throw bad('it must start with http://');
  if (!LOOPBACK_HOSTS.includes(url.hostname)) throw bad('it must point to 127.0.0.1 or localhost');
  if (url.username || url.password) throw bad('it must not contain a user name');
  if (url.port !== String(expected.port)) throw bad(`it must use port ${expected.port}`);
  if (url.pathname !== expected.callbackPath) throw bad(`its path must be ${expected.callbackPath}`);
  const gotState = url.searchParams.get('state');
  if (!gotState || !safeEqual(gotState, expected.state)) throw bad('it belongs to a different or older login attempt (state does not match)');
  const error = url.searchParams.get('error');
  if (error) throw providerError(expected.provider, error);
  const code = url.searchParams.get('code');
  if (!code) throw bad('it contains no authorization code');
  return code;
}

/**
 * Native-app OAuth: loopback redirect, random state, PKCE S256. The state is verified (constant
 * time) before the code is ever exchanged; wrong paths get 404 and wrong states 400 while the
 * flow keeps waiting until the timeout.
 */
export async function runPkceLoopback<T>(opts: PkceLoopbackOptions<T>): Promise<T> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_AUTH_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_AUTH_TIMEOUT_MS) {
    throw new PerchError(`OAuth timeout must be positive and at most ${MAX_AUTH_TIMEOUT_MS / 1000} seconds`, 'bad_argument');
  }
  const state = b64url(randomBytes(32));
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());

  let settle!: { resolve: (code: string) => void; reject: (e: Error) => void };
  const codePromise = new Promise<string>((resolve, reject) => (settle = { resolve, reject }));
  codePromise.catch(() => {}); // a timeout during prepare() must not become an unhandled rejection
  let done = false;

  const server = createServer((req, res) => {
    const reply = (status: number, text: string) => {
      res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      res.end(text);
    };
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (req.method !== 'GET' || url.pathname !== opts.callbackPath) return reply(404, 'Not found');
    if (done) return reply(410, 'This authorization request is no longer active.');
    const gotState = url.searchParams.get('state');
    if (!gotState || !safeEqual(gotState, state)) return reply(400, 'Invalid or missing state. Ignored.');
    const error = url.searchParams.get('error');
    if (error) {
      done = true;
      reply(400, 'Authorization was not granted. You can close this window.');
      return settle.reject(providerError(opts.provider, error));
    }
    const code = url.searchParams.get('code');
    if (!code) return reply(400, 'Missing code.');
    done = true;
    reply(200, 'Perch received the authorization. You can close this window and return to the terminal.');
    settle.resolve(code);
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', () => reject(new PerchError('Could not open the OAuth callback port', 'oauth_port')));
    server.listen(opts.port ?? 0, '127.0.0.1', resolve);
  });
  const port = (server.address() as AddressInfo).port;
  const redirectUri = `http://${opts.redirectHost}:${port}${opts.callbackPath}`;
  const pasteAbort = new AbortController();
  // As soon as one input decided (code, denial or timeout), stop reading the terminal.
  codePromise.then(
    () => pasteAbort.abort(),
    () => pasteAbort.abort(),
  );
  async function readPasted(paste: PasteRedirect): Promise<void> {
    try {
      while (!done) {
        const raw = await paste.read(pasteAbort.signal);
        if (raw === undefined || done) return;
        try {
          const code = parsePastedRedirect(raw, { port, callbackPath: opts.callbackPath, state, provider: opts.provider });
          done = true;
          settle.resolve(code);
          return;
        } catch (err) {
          if (err instanceof PerchError && err.code === 'paste_rejected') {
            paste.onRejected?.(err.message);
            continue;
          }
          done = true;
          settle.reject(err as Error);
          return;
        }
      }
    } catch (err) {
      // The operator aborted the prompt (Ctrl+C) or it failed: end the whole flow, unless it already finished.
      if (done) return;
      done = true;
      settle.reject(err instanceof PerchError ? err : new PerchError('Reading the pasted address failed', 'aborted'));
    }
  }

  const timer = setTimeout(() => {
    done = true;
    settle.reject(new PerchError(`Timed out waiting for the ${opts.provider} authorization`, 'oauth_timeout'));
  }, timeoutMs);

  try {
    const auth = new URL(opts.authEndpoint);
    const extra = opts.prepare ? await opts.prepare(redirectUri) : {};
    // RFC 6749 §3.1: the endpoint may carry its own query (Luma: ?credential_type=personal); keep it and
    // add ours. Our protocol parameters win over a same-named endpoint parameter.
    const params: Record<string, string> = {
      ...opts.authParams,
      ...extra,
      redirect_uri: redirectUri,
      response_type: 'code',
      state,
      ...(opts.pkce === false ? {} : { code_challenge: challenge, code_challenge_method: 'S256' }),
    };
    for (const [k, v] of Object.entries(params)) auth.searchParams.set(k, v);
    opts.onAuthUrl(auth.toString());
    if (opts.paste) void readPasted(opts.paste);
    const code = await codePromise;
    return await opts.exchange(code, verifier, redirectUri);
  } finally {
    // Whichever input won, the other one stops: no more reading from the terminal, the server closes.
    done = true;
    pasteAbort.abort();
    clearTimeout(timer);
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
}
