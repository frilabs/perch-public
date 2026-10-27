import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { PerchError } from '../errors.js';
import { parsePortableState, portableAllowedDomains, portableAllowedHosts, PORTABLE_STATE_MAX_BYTES, type PortableState } from './session/portableState.js';

interface Options { port: number; timeoutMs: number; label: string; extraHosts?: string[]; helperSource?: string }
export interface LocalSessionReceiver { port: number; token: string; helperSha256: string; done: Promise<PortableState | undefined>; close(): Promise<void> }
function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let size = 0, failed = false;
    const chunks: Buffer[] = [];
    req.on('data', chunk => {
      if (failed) return;
      size += chunk.length;
      if (size > PORTABLE_STATE_MAX_BYTES) { failed = true; chunks.length = 0; reject(new Error('large')); return; }
      chunks.push(Buffer.from(chunk));
    });
    req.on('end', () => {
      if (failed) return;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('body')); }
      chunks.length = 0;
    });
    req.on('error', () => reject(new Error('body')));
    req.on('aborted', () => reject(new Error('body')));
  });
}
export async function startLocalSessionReceiver(options: Options): Promise<LocalSessionReceiver> {
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65535 || !Number.isFinite(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 900_000) throw new PerchError('Invalid local Microsoft login port or timeout.', 'usage');
  const allowedHosts = portableAllowedHosts(options.extraHosts);
  const helper = options.helperSource ?? await readFile(new URL('../../assets/microsoft-local-login.mjs', import.meta.url), 'utf8');
  if (Buffer.byteLength(helper) > 1024 * 1024) throw new PerchError('Microsoft login helper is unavailable.', 'bad_config');
  const token = randomBytes(32).toString('hex');
  const expires = Date.now() + options.timeoutMs;
  let port = 0, finished = false, accepted = false, uploading = false, badTokens = 0, requests = 0, minute = Date.now();
  let resolveDone!: (state: PortableState | undefined) => void;
  const done = new Promise<PortableState | undefined>(resolve => { resolveDone = resolve; });
  let closePromise: Promise<void> | undefined;
  let timer: ReturnType<typeof setTimeout>;
  const server = createServer((req, res) => { void handle(req, res).catch(() => { if (!res.headersSent) reply(res, 400, { error: 'Invalid session transfer.' }); else res.end(); }); });
  server.requestTimeout = 15000; server.headersTimeout = 5000; server.maxConnections = 8;
  function reply(res: ServerResponse, status: number, data: unknown) { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(data)); }
  function close(): Promise<void> {
    if (!finished) { finished = true; clearTimeout(timer); resolveDone(undefined); }
    return closePromise ??= new Promise(resolve => { server.close(() => resolve()); server.closeAllConnections(); });
  }
  function complete(state: PortableState | undefined) {
    if (finished) return;
    finished = true; clearTimeout(timer); resolveDone(state);
    void close();
  }
  async function handle(req: IncomingMessage, res: ServerResponse) {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    if (req.headers.host !== `127.0.0.1:${port}` || req.headers.origin !== undefined || req.headers['sec-fetch-site'] !== undefined) return reply(res, 403, { error: 'Local helper required.' });
    if (finished || accepted || Date.now() >= expires) return reply(res, 410, { error: 'Login window expired. Restart in the server terminal.' });
    if (Date.now() - minute > 60000) { minute = Date.now(); requests = 0; }
    if (++requests > 120) return reply(res, 429, { error: 'Too many requests.' });
    if (req.method === 'GET' && req.url === '/helper.mjs') { res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', Connection: 'close' }); res.end(helper); return; }
    const supplied = req.headers.authorization;
    const expected = `Bearer ${token}`;
    if (badTokens >= 10 || typeof supplied !== 'string' || Buffer.byteLength(supplied) !== Buffer.byteLength(expected) || !timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) { badTokens++; return reply(res, 401, { error: 'Invalid login token.' }); }
    if (req.method === 'GET' && req.url === '/session') return reply(res, 200, { version: 1, label: options.label, expires, allowedDomains: portableAllowedDomains(), allowedHosts });
    if (req.method === 'POST' && req.url === '/cancel') { res.once('finish', () => complete(undefined)); return reply(res, 200, { ok: true }); }
    if (req.method !== 'POST' || req.url !== '/session') return reply(res, 404, { error: 'Not found.' });
    if (uploading) return reply(res, 409, { error: 'Transfer already in progress.' });
    if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] ?? '')) return reply(res, 415, { error: 'JSON required.' });
    if (Number(req.headers['content-length'] ?? 0) > PORTABLE_STATE_MAX_BYTES) { req.resume(); return reply(res, 413, { error: 'Session transfer too large.' }); }
    uploading = true;
    try {
      const state = parsePortableState(await readBody(req), allowedHosts);
      if (finished || Date.now() >= expires) return reply(res, 410, { error: 'Login window expired.' });
      accepted = true;
      res.once('finish', () => complete(state));
      reply(res, 200, { ok: true });
    } catch (error) { reply(res, error instanceof Error && error.message === 'large' ? 413 : 400, { error: 'Invalid Microsoft session transfer. No account was changed.' }); }
    finally { uploading = false; }
  }
  await new Promise<void>((resolve, reject) => {
    const failed = () => reject(new PerchError('Could not open local Microsoft login receiver. Choose another --port.', 'listen_failed'));
    server.once('error', failed);
    server.listen({ host: '127.0.0.1', port: options.port, exclusive: true }, () => { server.removeListener('error', failed); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') { await close(); throw new PerchError('Local Microsoft receiver is unavailable.', 'listen_failed'); }
  port = address.port;
  server.on('error', () => { void close(); });
  timer = setTimeout(() => { void close(); }, options.timeoutMs);
  return { port, token, helperSha256: createHash('sha256').update(helper).digest('hex'), done, close };
}
