import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { PerchError } from '../../errors.js';
import type { SessionProtocol } from '../sessionBrowser.js';
import { MICROSOFT_LOGIN_HOSTS } from './login.js';

const PARAM = '__perch_request';
const LOGIN_HOSTS = new Set<string>(MICROSOFT_LOGIN_HOSTS);
const TEAMS_HOSTS = new Set(['teams.microsoft.com', 'teams.cloud.microsoft']);
const DATA_HOSTS = new Set([
  ...TEAMS_HOSTS, 'outlook.office.com', 'outlook.office365.com', 'outlook.live.com',
  'outlook.cloud.microsoft', 'graph.microsoft.com', 'substrate.office.com',
  'www.microsoft365.com', 'm365.cloud.microsoft',
]);
const METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']);
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
// Installed in the main world before any untrusted script, in every new frame.
// CDP URL blocking does not prevent WebSocket handshakes in current Chrome.
const CHANNEL_MARKER = randomBytes(32).toString('hex');
const CHANNEL_LOCKDOWN = `(() => {
  const marker = Symbol.for('perch:channels:${CHANNEL_MARKER}');
  const names = ['WebSocket', 'WebSocketStream', 'WebTransport'];
  const previous = globalThis[marker];
  if (previous && names.every(name => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
    return descriptor && !descriptor.writable && !descriptor.configurable && descriptor.value === previous.channels;
  }) && (typeof ServiceWorkerContainer !== 'function' || (() => {
    const descriptor = Object.getOwnPropertyDescriptor(ServiceWorkerContainer.prototype, 'register');
    return descriptor && !descriptor.writable && !descriptor.configurable && descriptor.value === previous.register;
  })())) return true;
  const disabled = function PerchDisabledChannel() { throw new DOMException('Microsoft background channels are disabled', 'SecurityError'); };
  for (const name of names) {
    Object.defineProperty(globalThis, name, { value: disabled, writable: false, configurable: false, enumerable: false });
  }
  // A paused service worker can deadlock Network.enable before its context exists.
  // Background adapters bypass service workers; prevent registration before page scripts.
  const register = function PerchDisabledRegistration() { return Promise.reject(new DOMException('Microsoft background service workers are disabled', 'SecurityError')); };
  if (typeof ServiceWorkerContainer === 'function') Object.defineProperty(ServiceWorkerContainer.prototype, 'register', { value: register, writable: false, configurable: false });
  Object.defineProperty(globalThis, marker, { value: {channels: disabled, register}, writable: false, configurable: false });
  return true;
})()`;
interface Ticket { original: string; tagged: string; method: string; expiresAt: number }
export interface SessionRequestGuard {
  prepare(request: { url: string; method: string }): { url: string; release(): void };
  close(): void;
}
function validUrl(raw: unknown): URL {
  if (typeof raw !== 'string' || raw.length > 65_536 || /[\\\u0000-\u0020\u007f]/.test(raw)) throw Error('Invalid URL');
  const url = new URL(raw);
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.hash || url.port) throw Error('Invalid URL');
  return url;
}
function extraLoginHost(raw: string): string {
  const host = raw.toLowerCase();
  if (host.length > 253 || !host.includes('.') || isIP(host) || !host.split('.').every(part => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))) throw new PerchError('Login exceptions require exact DNS hostnames.', 'bad_config');
  return host;
}

/** Fixed Microsoft sign-in form returns; the egress proxy separately restricts tenant hosts. */
function signInReturn(url: URL, request: { postData?: unknown }, resourceType: unknown): boolean {
  if (url.search || resourceType !== 'Document' || typeof request.postData !== 'string' || request.postData.length > 65_536) return false;
  const m365 = url.origin === 'https://m365.cloud.microsoft' && url.pathname === '/landingv2';
  const sharepoint = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.sharepoint\.(?:com|de)$/.test(url.hostname) && url.pathname === '/_forms/default.aspx';
  if (!m365 && !sharepoint) return false;
  const fields = new URLSearchParams(request.postData);
  const allowed = new Set(m365 ? ['code', 'id_token', 'state', 'session_state', 'correlation_id'] : ['ear_jwe', 'state']);
  const seen = new Set<string>();
  for (const [key, value] of fields) {
    if (!allowed.has(key) || seen.has(key) || !value || value.length > 32_768) return false;
    seen.add(key);
  }
  return seen.has(m365 ? 'code' : 'ear_jwe') && seen.has('state');
}

/** Worker-only mutation firewall. The interactive login viewer deliberately does not use it. */
export async function createSessionRequestGuard(protocol: SessionProtocol, sessionId: string, extraLoginHosts: string[] = [], options: { worker?: boolean; waitingForDebugger?: boolean } = {}): Promise<SessionRequestGuard> {
  const loginHosts = new Set(LOGIN_HOSTS);
  for (const raw of extraLoginHosts) {
    const host = extraLoginHost(raw);
    if (!DATA_HOSTS.has(host) && !/(?:^|\.)sharepoint\.(?:com|de)$/.test(host)) loginHosts.add(host);
  }
  const tickets = new Map<string, Ticket>();
  let active = true;
  const prune = () => { for (const [key, ticket] of tickets) if (ticket.expiresAt <= Date.now()) tickets.delete(key); };
  async function intercept(requestId: string, request: unknown, resourceType: unknown): Promise<void> {
    let allowed = false;
    let original: string | undefined;
    try {
      if (!request || typeof request !== 'object') throw Error('Invalid request');
      const { url: raw, method } = request as { url?: unknown; method?: unknown };
      const url = validUrl(raw);
      if (typeof method !== 'string' || !METHODS.has(method)) throw Error('Invalid method');
      const nonces = url.searchParams.getAll(PARAM);
      if (nonces.length) {
        prune();
        const nonce = nonces[0]!;
        const ticket = tickets.get(nonce);
        if (nonces.length !== 1 || !ticket || raw !== ticket.tagged || (method !== 'OPTIONS' && method !== ticket.method)) throw Error('Invalid ticket');
        // Consume synchronously before CDP I/O so simultaneous events cannot reuse it.
        if (method !== 'OPTIONS' || ticket.method === 'OPTIONS') tickets.delete(nonce);
        original = ticket.original;
        allowed = true;
      } else {
        allowed = READ_METHODS.has(method) || (url.protocol === 'https:' && method === 'POST' && (
          loginHosts.has(url.hostname) || signInReturn(url, request as { postData?: unknown }, resourceType) || (TEAMS_HOSTS.has(url.hostname) && url.pathname === '/api/authsvc/v1.0/authz')
        ));
      }
    } catch { allowed = false; }
    if (!active) return;
    try {
      await protocol.call(allowed ? 'Fetch.continueRequest' : 'Fetch.failRequest', {
        requestId, ...(allowed ? (original ? { url: original } : {}) : { errorReason: 'BlockedByClient' }),
      }, sessionId);
    } catch {
      if (allowed && active) try { await protocol.call('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }, sessionId); } catch { /* Closed target remains closed. */ }
    }
  }
  const removeListener = protocol.onEvent(event => {
    if (!active || event.sessionId !== sessionId || event.method !== 'Fetch.requestPaused') return;
    const requestId: unknown = event.params?.requestId;
    if (typeof requestId !== 'string' || !requestId || requestId.length > 1024) return;
    void intercept(requestId, event.params?.request, event.params?.resourceType);
  });
  try {
    await protocol.call('Network.enable', {}, sessionId);
    // Current CDP BlockPattern syntax, including any explicit port.
    await protocol.call('Network.setBlockedURLs', { urlPatterns: [
      { urlPattern: 'ws://*:*/*', block: true },
      { urlPattern: 'wss://*:*/*', block: true },
      // Chrome has no Fetch domain in worker targets. Keep their HTTP network
      // disabled; all authorized adapter I/O runs in guarded page targets.
      ...(options.worker ? [
        { urlPattern: 'http://*:*/*', block: true },
        { urlPattern: 'https://*:*/*', block: true },
      ] : []),
    ] }, sessionId);
    // Chrome only runs registered new-document scripts while Page is enabled.
    if (!options.worker) await protocol.call('Page.enable', {}, sessionId);
    if (!options.worker) await protocol.call('Page.addScriptToEvaluateOnNewDocument', {
      source: CHANNEL_LOCKDOWN, ...(options.waitingForDebugger ? { runImmediately: true } : {}),
    }, sessionId);
    // A paused new page/OOPIF can have no execution context yet; evaluating it
    // deadlocks its parent's window.open/frame creation. Register before resume.
    if (options.worker || !options.waitingForDebugger) {
      const lockdown = await protocol.call('Runtime.evaluate', { expression: CHANNEL_LOCKDOWN, returnByValue: true }, sessionId);
      if (lockdown.exceptionDetails || lockdown.result?.value !== true) throw Error('Channel lockdown failed');
    }
    if (!options.worker) await protocol.call('Fetch.enable', { patterns: [
      { urlPattern: 'http://*', requestStage: 'Request' },
      { urlPattern: 'https://*', requestStage: 'Request' },
    ] }, sessionId);
  } catch {
    active = false; removeListener();
    throw new PerchError('Could not install Microsoft background request restrictions.', 'browser_failed');
  }
  return {
    prepare(request) {
      if (!active || options.worker) throw new PerchError('Microsoft requests require an active guarded page.', 'browser_failed');
      let url: URL;
      try {
        url = validUrl(request.url);
        if (url.protocol !== 'https:' || url.searchParams.has(PARAM) || !METHODS.has(request.method)) throw Error('Invalid request');
      } catch { throw new PerchError('Invalid Microsoft guarded request.', 'bad_config'); }
      prune();
      if (tickets.size >= 64) throw new PerchError('Too many outstanding Microsoft requests.', 'browser_failed');
      const original = url.href;
      const nonce = randomBytes(32).toString('hex');
      // Append without reserializing existing queries (including provider-signed downloads).
      const tagged = `${original}${url.search ? '&' : '?'}${PARAM}=${nonce}`;
      tickets.set(nonce, { original, tagged, method: request.method, expiresAt: Date.now() + 10_000 });
      return { url: tagged, release() { tickets.delete(nonce); } };
    },
    close() {
      if (!active) return;
      active = false; tickets.clear(); removeListener();
      // Do not Fetch.disable: that would release paused requests. Owner closes target next.
    },
  };
}
