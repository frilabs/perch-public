import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { PerchError } from '../errors.js';
import { sessionPage } from './sessionPage.js';
import { MICROSOFT_SIGN_IN_URL } from './session/login.js';

export type BrowserAction =
  | { type: 'navigate'; url: string }
  | { type: 'click'; x: number; y: number }
  | { type: 'wheel'; x: number; y: number; deltaY: number }
  | { type: 'key'; key: string; shift: boolean }
  | { type: 'text'; text: string }
  | { type: 'back' | 'reload' };
export interface SessionBrowser {
  snapshot(): Promise<{ image: string; host: string }>;
  action(action: BrowserAction): Promise<void>;
  close(): Promise<void>;
}
const services = { teams: 'unverified', mail: 'unverified', calendar: 'unverified', onedrive: 'unverified', sharepoint: 'unverified' };
export function serviceUrl(service: string, site?: string): string {
  const fixed: Record<string, string> = {
    login: MICROSOFT_SIGN_IN_URL, teams: 'https://teams.microsoft.com/v2/',
    mail: 'https://outlook.office.com/mail/', calendar: 'https://outlook.office.com/calendar/',
    onedrive: 'https://www.microsoft365.com/launch/onedrive',
  };
  if (Object.hasOwn(fixed, service)) return fixed[service]!;
  if (service === 'sharepoint' && site) {
    const u = new URL(site);
    if (u.protocol === 'https:' && /^[a-z0-9][a-z0-9-]*\.sharepoint\.com$/.test(u.hostname) && !u.port && !u.username && !u.password && !u.search && !u.hash) return u.href;
  }
  throw new PerchError('Choose a listed service or an HTTPS SharePoint site URL without credentials or query parameters.', 'usage');
}
function parseAction(a: Record<string, unknown>): BrowserAction {
  const coordinate = (v: unknown, max: number) => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v < max;
  if (a.type === 'service' && typeof a.service === 'string') return { type: 'navigate', url: serviceUrl(a.service, typeof a.site === 'string' ? a.site : undefined) };
  if (a.type === 'click' && coordinate(a.x, 1100) && coordinate(a.y, 780)) return { type: 'click', x: a.x as number, y: a.y as number };
  if (a.type === 'wheel' && coordinate(a.x, 1100) && coordinate(a.y, 780) && typeof a.deltaY === 'number' && Number.isFinite(a.deltaY) && Math.abs(a.deltaY) <= 2000) return { type: 'wheel', x: a.x as number, y: a.y as number, deltaY: a.deltaY };
  if (a.type === 'text' && typeof a.text === 'string' && a.text.length <= 4096) return { type: 'text', text: a.text };
  if (a.type === 'key' && typeof a.key === 'string' && ['Enter', 'Tab', 'Escape', 'Backspace', 'Delete', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(a.key)) return { type: 'key', key: a.key, shift: a.shift === true };
  if (a.type === 'back' || a.type === 'reload') return { type: a.type };
  throw new PerchError('Unsupported input.', 'usage');
}
async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 8192) throw new Error('too_large');
    chunks.push(Buffer.from(chunk));
  }
  const result: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('bad_body');
  return result as Record<string, unknown>;
}
const equal = (a: string, b: string) => { const left = Buffer.from(a); const right = Buffer.from(b); return left.length === right.length && timingSafeEqual(left, right); };
export async function startSessionViewer(browser: SessionBrowser, opts: { port: number; timeoutMs: number }): Promise<{
  url: string; done: Promise<'finished' | 'expired' | 'closed'>; close(): Promise<void>;
}> {
  if (!Number.isInteger(opts.port) || opts.port < 0 || opts.port > 65535 || !Number.isFinite(opts.timeoutMs) || opts.timeoutMs < 1 || opts.timeoutMs > 900_000) throw new PerchError('Login timeout must be at most 900 seconds; port must be 0-65535.', 'usage');
  const token = randomBytes(32).toString('hex');
  const cookie = randomBytes(32).toString('hex');
  const cookieName = `perch_ms_${randomBytes(6).toString('hex')}`;
  const nonce = randomBytes(18).toString('base64');
  let unlocked = false, stopped = false, busy = false;
  let expires = Date.now() + opts.timeoutMs;
  let minute = Date.now(), requests = 0, unlockAttempts = 0;
  let origin = '';
  let resolveDone!: (reason: 'finished' | 'expired' | 'closed') => void;
  const done = new Promise<'finished' | 'expired' | 'closed'>((r) => { resolveDone = r; });
  let closePromise: Promise<void> | undefined;
  let timer: ReturnType<typeof setTimeout>;
  const server = createServer((req, res) => { void handle(req, res).catch(() => { if (!res.headersSent) reply(res, 400, { error: 'Invalid request.' }); else res.end(); }); });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.maxConnections = 8;
  function reply(res: ServerResponse, code: number, data: unknown) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); }
  function stop(reason: 'finished' | 'expired' | 'closed'): Promise<void> {
    if (closePromise) return closePromise;
    stopped = true;
    clearTimeout(timer);
    closePromise = (async () => {
      server.close();
      server.closeAllConnections();
      try { await browser.close(); } finally { resolveDone(reason); }
    })();
    return closePromise;
  }
  function arm() { clearTimeout(timer); timer = setTimeout(() => { void stop('expired'); }, Math.max(1, expires - Date.now())); }
  async function handle(req: IncomingMessage, res: ServerResponse) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`);
    if (req.headers.host !== new URL(origin).host || (req.headers.origin && req.headers.origin !== origin)) return reply(res, 403, { error: 'Local origin required.' });
    if (stopped || Date.now() >= expires) return reply(res, 410, { error: 'Login window expired. Resume in the terminal.' });
    if (Date.now() - minute > 60_000) { minute = Date.now(); requests = 0; }
    if (++requests > 600) return reply(res, 429, { error: 'Slow down.' });
    if (req.method === 'GET' && req.url === '/') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(sessionPage(nonce)); return; }
    if (req.method === 'POST' && req.headers.origin !== origin) return reply(res, 403, { error: 'Local origin required.' });
    if (req.method === 'POST' && req.url === '/unlock') {
      const data = await body(req);
      if (++unlockAttempts > 10 || unlocked || typeof data.token !== 'string' || !equal(data.token, token)) return reply(res, 401, { error: 'Invalid or used login link. Resume in the terminal for a new link.' });
      unlocked = true;
      res.setHeader('Set-Cookie', `${cookieName}=${cookie}; HttpOnly; SameSite=Strict; Path=/`);
      return reply(res, 200, { ok: true });
    }
    const credential = (req.headers.cookie ?? '').split(';').map((v) => v.trim()).find((v) => v.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1) ?? '';
    if (!unlocked || !equal(credential, cookie)) return reply(res, 401, { error: 'Open the complete login link from your terminal.' });
    if (req.method === 'POST' && req.url === '/finish') {
      reply(res, 200, { ok: true, verified: false });
      setTimeout(() => { void stop('finished'); }, 20);
      return;
    }
    if (req.method === 'POST' && req.url === '/extend') {
      expires = Date.now() + opts.timeoutMs; arm(); return reply(res, 200, { expires });
    }
    if (busy) return reply(res, 409, { error: 'Browser busy. Try again.' });
    if (req.method === 'GET' && req.url === '/state') {
      busy = true;
      try { reply(res, 200, { ...await browser.snapshot(), expires, services }); }
      catch { reply(res, 502, { error: 'Server browser unavailable. Resume from the terminal; your profile is retained.' }); }
      finally { busy = false; }
      return;
    }
    if (req.method === 'POST' && req.url === '/action') {
      let action: BrowserAction;
      try { action = parseAction(await body(req)); } catch (err) { return reply(res, err instanceof Error && err.message === 'too_large' ? 413 : 400, { error: 'Invalid or unsupported browser input.' }); }
      if (stopped || Date.now() >= expires) return reply(res, 410, { error: 'Login window expired. Resume in the terminal.' });
      if (busy) return reply(res, 409, { error: 'Browser busy. Try again.' });
      busy = true;
      try { await browser.action(action); reply(res, 200, { ok: true }); }
      catch { reply(res, 502, { error: 'Browser operation failed. Check the server browser or resume in the terminal.' }); }
      finally { busy = false; }
      return;
    }
    reply(res, 404, { error: 'Not found.' });
  }
  await new Promise<void>((resolve, reject) => {
    const failed = (err: NodeJS.ErrnoException) => reject(new PerchError(err.code === 'EADDRINUSE' ? 'Login port already in use. Retry with --port 8784 (and use the printed tunnel command).' : 'Could not start the local login listener.', 'bad_config'));
    server.once('error', failed); server.listen(opts.port, '127.0.0.1', () => { server.removeListener('error', failed); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No loopback listener');
  origin = `http://127.0.0.1:${address.port}`;
  arm();
  return { url: `${origin}/#${token}`, done, close: () => stop('closed') };
}
