import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP, connect as netConnect, type Socket } from 'node:net';
import { createServer } from 'node:http';
import { PerchError } from '../../errors.js';
import type { SessionProtocol } from '../sessionBrowser.js';
import { MICROSOFT_LOGIN_HOSTS } from './login.js';

const BASELINE_HOSTS = [
  ...MICROSOFT_LOGIN_HOSTS,
  'www.microsoft365.com', 'm365.cloud.microsoft',
  'outlook.office.com', 'outlook.cloud.microsoft', 'outlook.live.com', 'outlook.office365.com',
  'teams.microsoft.com', 'teams.cloud.microsoft', 'graph.microsoft.com', 'substrate.office.com',
  'aadcdn.msauth.net', 'aadcdn.msftauth.net', 'logincdn.msauth.net',
  'res.cdn.office.net', 'res-1.cdn.office.net', 'statics.teams.cdn.office.net',
  'statics.teams.microsoft.com', 'shell.cdn.office.net',
  'res.public.onecdn.static.microsoft', 'teams.public.onecdn.static.microsoft',
] as const;
type AddressLookup = (hostname: string) => Promise<readonly { address: string; family: number }[]>;
export interface BrowserEgressOptions {
  selectedHosts?: string[];
  extraHosts?: string[];
  /** Dependency injection; production uses the OS resolver with all answers. */
  lookup?: AddressLookup;
}

function validHostname(value: string): boolean {
  return value.length <= 253 && value.includes('.') && !isIP(value) &&
    value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)) &&
    !/(?:^|\.)(?:localhost|local|internal|invalid|onion)$|(?:^|\.)home\.arpa$/i.test(value) &&
    // The URL parser recognizes legacy integer, octal and shortened IP spellings.
    !isIP(new URL(`https://${value}`).hostname);
}
function normalizedHostname(value: string): string {
  if (!validHostname(value)) throw new PerchError('Microsoft browser egress requires exact public DNS hostnames.', 'bad_config');
  return value.toLowerCase();
}
function ipv4Number(value: string): number {
  return value.split('.').reduce((number, octet) => ((number << 8) | Number(octet)) >>> 0, 0);
}
function ipv4In(value: number, address: string, bits: number): boolean {
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (value & mask) === (ipv4Number(address) & mask);
}
/** Conservative public-unicast policy: transitional/mapped IPv6 is excluded. */
export function isPublicSessionAddress(address: string): boolean {
  if (address.includes('%')) return false;
  if (isIP(address) === 4) {
    const value = ipv4Number(address);
    return !([
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
      ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
      ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
      ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
    ] as const).some(([base, bits]) => ipv4In(value, base, bits));
  }
  if (isIP(address) !== 6 || address.includes('.')) return false;
  const [left = '', right = ''] = address.toLowerCase().split('::');
  const head = left ? left.split(':') : [];
  const tail = right ? right.split(':') : [];
  const words = address.includes('::') ? [...head, ...Array<string>(8 - head.length - tail.length).fill('0'), ...tail] : head;
  const value = words.reduce((result, word) => (result << 16n) | BigInt(`0x${word}`), 0n);
  const prefix = (base: bigint, bits: number) => (value >> BigInt(128 - bits)) === base;
  return prefix(1n, 3) && !prefix(0x200100n >> 1n, 23) && !prefix(0x20010db8n, 32) &&
    !prefix(0x2002n, 16) && !prefix(0x3ffen, 16) && !prefix(0x3fff0n, 20);
}

/**
 * Install before navigation on every page/worker target. Each redirect is a new
 * intercepted request. This DNS precheck does not pin Chrome's resolver; network
 * egress controls are still required to provide protection against DNS rebinding.
 * The returned disposer is for target teardown, not for continuing unguarded use.
 */
export async function installBrowserEgress(
  protocol: SessionProtocol, sessionId: string, options: BrowserEgressOptions,
  blocked: (host: string) => void,
): Promise<() => void> {
  const configured = [...(options.selectedHosts ?? []), ...(options.extraHosts ?? [])];
  if (configured.length > 256) throw new PerchError('Too many Microsoft browser egress hosts.', 'bad_config');
  const allowed = new Set<string>([...BASELINE_HOSTS, ...configured.map(normalizedHostname)]);
  const lookup: AddressLookup = options.lookup ?? (host => dnsLookup(host, { all: true, verbatim: true }));
  const cache = new Map<string, { expiresAt: number; result: Promise<boolean> }>();
  const diagnostics = new Set<string>();
  let active = true;
  async function publicDns(host: string): Promise<boolean> {
    const cached = cache.get(host);
    if (cached && cached.expiresAt > Date.now()) return cached.result;
    if (cache.size >= 256) cache.delete(cache.keys().next().value!);
    const result = (async () => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const answers = await Promise.race([
          lookup(host), new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error('DNS timeout')), 2000); }),
        ]);
        return answers.length > 0 && answers.length <= 64 && answers.every(answer =>
          isIP(answer.address) === answer.family && isPublicSessionAddress(answer.address));
      } catch { return false; }
      finally { if (timer) clearTimeout(timer); }
    })();
    cache.set(host, { expiresAt: Date.now() + 30_000, result });
    return result;
  }
  function diagnostic(host: string) {
    if (!host || diagnostics.size >= 20 || diagnostics.has(host)) return;
    diagnostics.add(host);
    try { blocked(host); } catch { /* Reporting cannot release a blocked request. */ }
  }
  async function intercept(requestId: string, rawUrl: unknown): Promise<void> {
    let host = '', permitted = false;
    try {
      if (typeof rawUrl === 'string' && rawUrl.length <= 65_536 && !/[\\\u0000-\u0020\u007f]/.test(rawUrl)) {
        const url = new URL(rawUrl);
        // Diagnostics are validated hostnames only, never paths, credentials or queries.
        if (validHostname(url.hostname)) host = url.hostname.toLowerCase();
        permitted = url.protocol === 'https:' && !url.username && !url.password && !url.port &&
          allowed.has(host) && await publicDns(host);
      }
    } catch { permitted = false; }
    if (!active) return;
    if (!permitted) diagnostic(host);
    try {
      await protocol.call(permitted ? 'Fetch.continueRequest' : 'Fetch.failRequest', {
        requestId, ...(!permitted ? { errorReason: 'BlockedByClient' } : {}),
      }, sessionId);
    } catch {
      // A failed continue must never cause a retry. Best effort fail-closed when
      // the target remains attached; closed targets naturally have no request.
      if (permitted) {
        diagnostic(host);
        try { await protocol.call('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }, sessionId); } catch { /* detached */ }
      }
    }
  }
  const removeListener = protocol.onEvent(event => {
    if (!active || event.sessionId !== sessionId || event.method !== 'Fetch.requestPaused') return;
    const requestId: unknown = event.params?.requestId;
    if (typeof requestId !== 'string' || !requestId || requestId.length > 1024) return;
    void intercept(requestId, event.params?.request?.url);
  });
  try {
    await protocol.call('Fetch.enable', { patterns: [
      { urlPattern: 'http://*', requestStage: 'Request' },
      { urlPattern: 'https://*', requestStage: 'Request' },
    ] }, sessionId);
  } catch {
    active = false; removeListener();
    throw new PerchError('Could not install Microsoft browser egress restrictions.', 'browser_failed');
  }
  return () => {
    if (!active) return;
    active = false; removeListener(); cache.clear();
    // Keep Fetch interception enabled until the owner closes the target. Turning
    // it off here would release in-flight requests without validation.
  };
}

export interface BrowserEgressProxyOptions extends BrowserEgressOptions {
  /** Reject all CONNECT requests until the worker installs its target guards. */
  paused?: boolean;
  /** Test dependency. The production connector receives a checked IP, never DNS. */
  connect?: (destination: { host: string; port: number; family: 4 | 6 }) => Socket;
}
export interface BrowserEgressProxy {
  url: string;
  resume(): void;
  close(): Promise<void>;
  /** Called only after the local operator selects a SharePoint/OneDrive site. */
  allowSelectedHost(host: string): void;
}
const MAX_PROXY_CONNECTIONS = 128;
const TUNNEL_IDLE_TIMEOUT_MS = 30_000;

/**
 * The browser's sole HTTP proxy: TLS stays opaque, while CONNECT destinations are
 * resolved here and the socket is opened directly to that checked public IP.
 * Browser launch must disable proxy bypass, QUIC and non-proxied WebRTC UDP.
 */
export async function startBrowserEgressProxy(
  options: BrowserEgressProxyOptions, blocked: (host: string) => void,
): Promise<BrowserEgressProxy> {
  const configured = [...(options.selectedHosts ?? []), ...(options.extraHosts ?? [])];
  if (configured.length > 256) throw new PerchError('Too many Microsoft browser egress hosts.', 'bad_config');
  const allowed = new Set<string>([...BASELINE_HOSTS, ...configured.map(normalizedHostname)]);
  const lookup: AddressLookup = options.lookup ?? (host => dnsLookup(host, { all: true, verbatim: true }));
  const connect = options.connect ?? (destination => netConnect(destination));
  const cache = new Map<string, { expiresAt: number; result: Promise<readonly { address: string; family: number }[]> }>();
  const diagnostics = new Set<string>();
  const clients = new Set<Socket>(), upstreams = new Set<Socket>();
  let closing = false, paused = options.paused ?? false, closePromise: Promise<void> | undefined;
  const diagnostic = (host: string) => {
    if (!host || diagnostics.has(host) || diagnostics.size >= 20) return;
    diagnostics.add(host);
    try { blocked(host); } catch { /* Diagnostics never control access. */ }
  };
  async function addresses(host: string): Promise<readonly { address: string; family: number }[]> {
    const cached = cache.get(host);
    if (cached && cached.expiresAt > Date.now()) return cached.result;
    if (cache.size >= 256) cache.delete(cache.keys().next().value!);
    const result = (async () => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const records = await Promise.race([
          lookup(host), new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error('DNS timeout')), 2000); }),
        ]);
        return records.length > 0 && records.length <= 64 && records.every(record =>
          isIP(record.address) === record.family && isPublicSessionAddress(record.address)) ? records : [];
      } catch { return []; }
      finally { if (timer) clearTimeout(timer); }
    })();
    cache.set(host, { expiresAt: Date.now() + 30_000, result });
    return result;
  }
  const reject = (socket: Socket, status = '403 Forbidden') => {
    if (!socket.destroyed) socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  };
  const server = createServer({ maxHeaderSize: 8192, headersTimeout: 5000, requestTimeout: 5000 }, (_req, res) => {
    res.writeHead(403, { Connection: 'close', 'Content-Length': '0' }); res.end();
  });
  server.maxConnections = MAX_PROXY_CONNECTIONS;
  server.on('connection', socket => {
    if (closing || clients.size >= MAX_PROXY_CONNECTIONS) { socket.destroy(); return; }
    clients.add(socket);
    socket.setTimeout(5000, () => socket.destroy());
    socket.on('error', () => { socket.destroy(); });
    socket.once('close', () => clients.delete(socket));
  });
  server.on('clientError', (_error, socket) => reject(socket as Socket, '400 Bad Request'));
  server.on('upgrade', (_req, socket) => reject(socket as Socket));
  server.on('connect', (req, stream, head) => {
    const client = stream as Socket;
    void (async () => {
      // No URL parser normalization, userinfo, wildcard, path, IP or alternate port.
      const match = /^([a-z0-9.-]{1,253}):443$/i.exec(req.url ?? '');
      let host = '';
      try { if (match) host = normalizedHostname(match[1]!); } catch { /* deny below */ }
      if (closing || paused || !host || !allowed.has(host) || head.length > 65_536) {
        if (!closing && !paused) diagnostic(host);
        reject(client); return;
      }
      const records = await addresses(host);
      if (closing || client.destroyed) return;
      const selected = records[0];
      if (!selected) { diagnostic(host); reject(client); return; }
      let upstream: Socket;
      try { upstream = connect({ host: selected.address, port: 443, family: selected.family as 4 | 6 }); }
      catch { reject(client, '502 Bad Gateway'); return; }
      upstreams.add(upstream);
      const timer = setTimeout(() => { upstream.destroy(); reject(client, '502 Bad Gateway'); }, 5000);
      upstream.once('error', () => { reject(client, '502 Bad Gateway'); upstream.destroy(); });
      upstream.once('close', () => { clearTimeout(timer); upstreams.delete(upstream); client.destroy(); });
      client.once('close', () => { clearTimeout(timer); upstream.destroy(); });
      upstream.once('connect', () => {
        clearTimeout(timer);
        if (closing || client.destroyed) { upstream.destroy(); return; }
        // Socket inactivity timeouts reset on traffic; active transfers are not
        // capped. Release idle CDN/site tunnels before they exhaust capacity.
        client.setTimeout(TUNNEL_IDLE_TIMEOUT_MS); upstream.setTimeout(TUNNEL_IDLE_TIMEOUT_MS, () => upstream.destroy());
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length) upstream.write(head);
        client.pipe(upstream); upstream.pipe(client);
      });
    })().catch(() => { reject(client); });
  });
  await new Promise<void>((resolve, rejectListen) => {
    const failed = () => rejectListen(new PerchError('Could not start the private Microsoft browser proxy.', 'browser_failed'));
    server.once('error', failed);
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => { server.removeListener('error', failed); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') { server.close(); throw new PerchError('Could not start the private Microsoft browser proxy.', 'browser_failed'); }
  server.on('error', () => { for (const socket of [...clients, ...upstreams]) socket.destroy(); });
  return {
    url: `http://127.0.0.1:${address.port}`,
    resume() { if (!closing) paused = false; },
    allowSelectedHost(host) {
      const normalized = normalizedHostname(host);
      if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.sharepoint\.(?:com|de)$/.test(normalized) || allowed.size >= BASELINE_HOSTS.length + 256) {
        throw new PerchError('Select an exact SharePoint site host within the browser egress limit.', 'bad_config');
      }
      allowed.add(normalized);
    },
    close() {
      return closePromise ??= new Promise<void>(resolve => {
        closing = true; cache.clear();
        for (const socket of [...clients, ...upstreams]) socket.destroy();
        server.close(() => resolve());
      });
    },
  };
}
