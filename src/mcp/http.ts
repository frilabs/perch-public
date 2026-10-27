import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { isIP } from 'node:net';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { hasWriteCapability, principalForClientToken, READONLY_PRINCIPAL, tokenSha256, type Principal } from '../auth/grants.js';
import type { PerchContext } from '../context.js';
import { PerchError } from '../errors.js';
import { renderStatusPage, statusPageHeaders } from '../status/page.js';
import { collectStatus, type StatusOptions, type StatusReport } from '../status/status.js';
import { createMcpServer } from './server.js';
import type { OAuthApp } from '../access/server.js';

export const MIN_TOKEN_LENGTH = 43; // 32 random bytes as base64url
const MAX_BODY_BYTES = 1024 * 1024;
/** Draft/send clients may upload inline base64 attachments (10 MiB decoded is ~13.4 MiB base64). */
const MAX_WRITE_BODY_BYTES = 16 * 1024 * 1024;
const MCP_PATH = '/mcp';
const STATUS_PATH = '/status';
const LOCAL_PAIR_PATH = '/local/pair';
/**
 * Tailscale Funnel marks every request it forwards from the internet with `Tailscale-Funnel-Request: ?1`
 * (from our knowledge of the Tailscale Serve/Funnel docs; tailnet requests through Serve do not carry it).
 * ASSUMPTION, to verify live (docs/PHASE1_REMAINING.md): the header name and value. We only rely on its
 * PRESENCE to refuse, never on its absence to allow, so a client that sends it itself only locks itself out.
 * A request carrying it reached the local listener from the internet (a Funnel misconfigured onto this
 * port): private OAuth routes, private-device tokens and the local pairing page are refused for it.
 */
export const FUNNEL_HEADER = 'tailscale-funnel-request';
/** Live checks of the status page are reused for this long (page reloads never hammer the providers). */
export const STATUS_CACHE_SECONDS = 60;

/**
 * The status page accepts the same tokens as MCP, as a bearer token or as the password of HTTP Basic auth
 * (so a browser can show its own login prompt; the user name is ignored). Returns a Bearer header value.
 */
function statusCredential(header: string | undefined): string | undefined {
  const basic = /^Basic\s+([A-Za-z0-9+/=]{1,1024})\s*$/i.exec(header ?? '');
  if (!basic) return header;
  const decoded = Buffer.from(basic[1]!, 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  return colon < 0 ? undefined : `Bearer ${decoded.slice(colon + 1)}`;
}

export function generateHttpToken(): string {
  return randomBytes(32).toString('base64url');
}

export function validateHttpToken(token: string | undefined): string {
  const t = token?.trim();
  if (!t) throw new PerchError('No HTTP bearer token configured. Run `perch init` or set PERCH_HTTP_TOKEN_FILE.', 'no_token');
  if (t.length < MIN_TOKEN_LENGTH || !/^[A-Za-z0-9._~+/=-]+$/.test(t)) {
    throw new PerchError(`HTTP bearer token must be at least ${MIN_TOKEN_LENGTH} URL-safe characters (>= 32 random bytes)`, 'weak_token');
  }
  return t;
}

/** Loopback, or an explicit Tailscale address (100.64.0.0/10, fd7a:115c:a1e0::/48). Never wildcard. */
export function validateBindHost(host: string): void {
  const h = host.trim().toLowerCase();
  if (h === 'localhost') return;
  const v = isIP(h);
  if (v === 4) {
    const [a, b] = h.split('.').map(Number) as [number, number];
    if (a === 127) return;
    if (a === 100 && b >= 64 && b <= 127) return;
  } else if (v === 6) {
    if (h === '::1') return;
    if (h.startsWith('fd7a:115c:a1e0:')) return;
  }
  throw new PerchError(
    `Refusing to bind to ${JSON.stringify(host)}: use loopback (default 127.0.0.1) or an explicit Tailscale IP`,
    'bad_bind_host',
  );
}

const isLoopback = (h: string) => h === 'localhost' || h === '::1' || h.startsWith('127.');
const hostPort = (h: string, port: number) => (isIP(h) === 6 ? `[${h}]:${port}` : `${h}:${port}`);

/**
 * The global token is the operator in READ-ONLY mode. Any other well-formed token is looked up by hash
 * among the client grants (tokens carry 256 bits of entropy). A global token that also matches a client
 * grant is ambiguous and rejected.
 */
async function authenticate(header: string | undefined, expectedDigest: Buffer, ctx: PerchContext): Promise<Principal | null> {
  const m = /^Bearer\s+(\S+)\s*$/i.exec(header ?? '');
  const got = createHash('sha256').update(m?.[1] ?? '').digest();
  // Always compare (constant time on fixed-size digests), then require a well-formed header.
  if (timingSafeEqual(got, expectedDigest) && m !== null) {
    const digest = tokenSha256(m[1]!);
    if ((await ctx.store.read()).clients.some((c) => c.tokenSha256 === digest)) {
      throw new PerchError('The global token also matches a client token; refusing to choose a principal', 'ambiguous_token');
    }
    return READONLY_PRINCIPAL;
  }
  if (!m || m[1]!.length < MIN_TOKEN_LENGTH) return null;
  return principalForClientToken(ctx.store, m[1]!);
}

export interface HttpServerOptions {
  host: string;
  port: number;
  token: string;
  context: PerchContext;
  /** Extra exact Host header values, e.g. the Tailscale Serve MagicDNS name. */
  allowedHosts?: string[];
  /** Exact Origin values; a request carrying any other Origin is rejected. */
  allowedOrigins?: string[];
  log?: (line: string) => void;
  /** Tests only: MOCK IMAP/SMTP login for the status page's live checks. */
  statusOptions?: Pick<StatusOptions, 'imapVerify' | 'pairingOpen'>;
  /**
   * Local pairing page of the public access (GET/POST /local/pair), only on this local listener. It has its own
   * password (perch oauth local-page enable), never the global token. Absent: /local/pair is 404.
   */
  localPair?: (req: IncomingMessage, res: ServerResponse, url: URL) => Promise<void>;
  /**
   * Private OAuth issuer (docs/SIMPLE_CONNECT_SPEC.md §1): discovery and /oauth/* on this listener, and OAuth
   * access tokens issued HERE accepted on /mcp in addition to the global and client tokens. Absent: off.
   */
  oauth?: OAuthApp;
}

export interface RunningHttpServer {
  url: string;
  port: number;
  allowedHosts: string[];
  close(): Promise<void>;
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  if (res.headersSent) return;
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}

const rpcError = (code: number, message: string) => ({ jsonrpc: '2.0', error: { code, message }, id: null });

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

/** Stateless Streamable HTTP: one MCP server + transport per POST, JSON responses. */
export async function startHttpServer(opts: HttpServerOptions): Promise<RunningHttpServer> {
  validateBindHost(opts.host);
  const tokenDigest = createHash('sha256').update(validateHttpToken(opts.token)).digest();
  const log = opts.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const allowedOrigins = new Set(opts.allowedOrigins ?? []);
  let allowedHosts = new Set<string>();
  // One cached live report (single-flight while it runs).
  let statusCache: { at: number; report: Promise<StatusReport> } | undefined;
  const cachedStatus = () => {
    if (statusCache && Date.now() - statusCache.at < STATUS_CACHE_SECONDS * 1000) return statusCache.report;
    const report = collectStatus(opts.context, opts.statusOptions);
    const entry = { at: Date.now(), report };
    statusCache = entry;
    report.catch(() => {
      if (statusCache === entry) statusCache = undefined;
    });
    return report;
  };

  const server = createServer(async (req, res) => {
    try {
      const host = (req.headers.host ?? '').toLowerCase();
      if (!allowedHosts.has(host)) {
        log(`perch: rejected request with Host ${JSON.stringify(host.slice(0, 100))} (add it to PERCH_ALLOWED_HOSTS if legitimate)`);
        return sendJson(res, 403, rpcError(-32000, 'Forbidden host'));
      }
      const path = new URL(req.url ?? '/', 'http://localhost').pathname;
      const viaFunnel = req.headers[FUNNEL_HEADER] !== undefined;
      const isLocalPair = opts.localPair !== undefined && path === LOCAL_PAIR_PATH;
      const isOAuth = opts.oauth !== undefined && opts.oauth.isOAuthPath(path);
      if (viaFunnel && (isOAuth || isLocalPair)) {
        log('perch: refused a Tailscale Funnel request to a private OAuth route (point Funnel at the public listener only)');
        return sendJson(res, 404, { error: 'not_found' });
      }
      const origin = req.headers.origin;
      // The local pairing page posts its own forms: its own origin is allowed there (and only there). The
      // OAuth sign-in pages post to the issuer's own origin (and only those routes accept it).
      const ownOrigin =
        (isLocalPair && origin !== undefined && (origin === `http://${host}` || origin === `https://${host}`)) || (isOAuth && origin !== undefined && origin === opts.oauth!.origin);
      if (origin !== undefined && !allowedOrigins.has(origin) && !ownOrigin) {
        log('perch: rejected request with a disallowed Origin');
        return sendJson(res, 403, rpcError(-32000, 'Forbidden origin'));
      }
      if (isOAuth) return await opts.oauth!.route(req, res, new URL(req.url ?? '/', opts.oauth!.origin));
      const isStatus = path === STATUS_PATH || path === `${STATUS_PATH}/`;
      if (isLocalPair) {
        if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'POST') return sendJson(res, 405, { error: 'Method not allowed' }, { allow: 'GET, POST' });
        const site = req.headers['sec-fetch-site'];
        if (site !== undefined && site !== 'same-origin' && site !== 'none') return sendJson(res, 403, { error: 'Forbidden' });
        // Its own password (never the global token); checked by the handler.
        return await opts.localPair!(req, res, new URL(req.url ?? '/', 'http://localhost'));
      }
      if (isStatus) {
        if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'Method not allowed' }, { allow: 'GET, HEAD' });
        // Navigations and same-origin loads only: another site must not be able to trigger live checks.
        const site = req.headers['sec-fetch-site'];
        if (site !== undefined && site !== 'same-origin' && site !== 'none') return sendJson(res, 403, { error: 'Forbidden' });
      }
      let principal: Principal | null;
      let guard: (() => Promise<void>) | undefined;
      try {
        principal = await authenticate(isStatus ? statusCredential(req.headers.authorization) : req.headers.authorization, tokenDigest, opts.context);
      } catch (err) {
        if (err instanceof PerchError && err.code === 'ambiguous_token') {
          log('perch: rejected the global token because it also matches a client grant (check perch client list)');
          principal = null;
        } else throw err;
      }
      // Neither the global nor a client token: an OAuth access token of THIS listener's issuer (private).
      let expired = false;
      // Never over Funnel: private devices are bound to the tailnet.
      if (!principal && !isStatus && path === MCP_PATH && opts.oauth && !viaFunnel && req.headers.authorization !== undefined) {
        const a = await opts.oauth.authenticateThrottled(req.headers.authorization);
        if (a.kind === 'unavailable') return sendJson(res, 503, rpcError(-32000, 'Temporarily unavailable'));
        if (a.kind === 'limited') return sendJson(res, 429, rpcError(-32000, 'Rate limited'), { 'retry-after': '60' });
        if (a.kind === 'ok') {
          principal = a.principal;
          guard = a.guard;
        } else expired = true;
      }
      if (!principal) {
        if (isStatus) return sendJson(res, 401, { error: 'Unauthorized' }, { 'www-authenticate': 'Basic realm="Perch status", charset="UTF-8"' });
        // RFC 9728: point OAuth clients at the private resource metadata so they can start the sign-in.
        return sendJson(res, 401, rpcError(-32001, 'Unauthorized'), { 'www-authenticate': opts.oauth && !viaFunnel ? opts.oauth.wwwAuthenticate(expired, 'perch') : 'Bearer realm="perch"' });
      }
      if (isStatus) {
        // A client grant is narrower than the operator: only the global read-only token sees the overview.
        if (principal.kind !== 'operator_readonly') return sendJson(res, 403, { error: 'The status page needs the global read-only token, not a client grant' });
        const html = renderStatusPage(await cachedStatus(), { cachedSeconds: STATUS_CACHE_SECONDS });
        res.writeHead(200, statusPageHeaders());
        res.end(req.method === 'HEAD' ? undefined : html);
        return;
      }
      if (path !== MCP_PATH) return sendJson(res, 404, rpcError(-32000, 'Not found'));
      if (req.method !== 'POST') {
        return sendJson(res, 405, rpcError(-32000, 'Method not allowed (stateless server: POST only)'), { allow: 'POST' });
      }
      const body = await readBody(req, hasWriteCapability(principal) ? MAX_WRITE_BODY_BYTES : MAX_BODY_BYTES);
      if (body === 'too_large') return sendJson(res, 413, rpcError(-32000, 'Request body too large'));
      let parsed: unknown;
      try {
        parsed = JSON.parse(body.toString('utf8'));
      } catch {
        return sendJson(res, 400, rpcError(-32700, 'Parse error'));
      }

      await opts.context.luma.refresh(); // approved Luma tool schemas (perch luma add / tools --accept)
      const mcp = createMcpServer(opts.context, principal, guard ? { guard } : undefined);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
        enableDnsRebindingProtection: true,
        allowedHosts: [...allowedHosts],
        ...(allowedOrigins.size ? { allowedOrigins: [...allowedOrigins] } : {}),
      });
      res.on('close', () => {
        void transport.close();
        void mcp.close();
      });
      await mcp.connect(transport);
      await transport.handleRequest(req, res, parsed);
    } catch {
      log('perch: internal error while handling an HTTP request');
      sendJson(res, 500, rpcError(-32603, 'Internal error'));
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port, opts.host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const port = (server.address() as AddressInfo).port;
  const hosts = [hostPort(opts.host.toLowerCase(), port)];
  if (isLoopback(opts.host.toLowerCase())) hosts.push(`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`);
  for (const h of opts.allowedHosts ?? []) if (h.trim()) hosts.push(h.trim().toLowerCase());
  // The private issuer's own name (PERCH_PRIVATE_BASE_URL, or already one of the allowed hosts).
  if (opts.oauth) hosts.push(opts.oauth.host);
  allowedHosts = new Set(hosts);

  return {
    url: `http://${hostPort(opts.host, port)}${MCP_PATH}`,
    port,
    allowedHosts: [...allowedHosts],
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
