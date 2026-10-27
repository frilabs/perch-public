import { describe, expect, it, vi } from 'vitest';
import type { BrowserEvent, SessionProtocol } from '../src/microsoft/sessionBrowser.js';
import { installBrowserEgress, isPublicSessionAddress } from '../src/microsoft/session/egress.js';

function harness() {
  let listener: ((event: BrowserEvent) => void) | undefined;
  const calls: { method: string; params?: Record<string, unknown>; sessionId?: string }[] = [];
  const protocol: SessionProtocol = {
    onEvent(fn) { listener = fn; return () => { listener = undefined; }; },
    async call(method, params, sessionId) { calls.push({ method, params, sessionId }); return {}; },
  };
  return { protocol, calls, emit(url: string, id = 'request', sessionId = 'page') {
    listener?.({ method: 'Fetch.requestPaused', sessionId, params: { requestId: id, request: { url } } });
  } };
}
const publicLookup = vi.fn(async (_host: string) => [{ address: '20.190.128.1', family: 4 }]);
async function settled() { await new Promise((resolve) => setImmediate(resolve)); }

describe('Microsoft browser egress', () => {
  it('allows exact baseline, selected site and explicit federation hosts only', async () => {
    const h = harness(); const blocked = vi.fn(); const lookup = vi.fn(publicLookup);
    const stop = await installBrowserEgress(h.protocol, 'page', { selectedHosts: ['tenant.sharepoint.com'], extraHosts: ['sso.example.com'], lookup }, blocked);
    expect(h.calls[0]).toEqual({ method: 'Fetch.enable', sessionId: 'page', params: { patterns: [{ urlPattern: 'http://*', requestStage: 'Request' }, { urlPattern: 'https://*', requestStage: 'Request' }] } });
    for (const host of ['login.microsoftonline.com', 'teams.cloud.microsoft', 'tenant.sharepoint.com', 'sso.example.com']) h.emit(`https://${host}/path?secret=hidden`, host);
    for (const host of ['evil.example.com', 'login.microsoftonline.com.evil.example.com', 'other.sharepoint.com']) h.emit(`https://${host}/`, host);
    await settled();
    expect(h.calls.filter(c => c.method === 'Fetch.continueRequest')).toHaveLength(4);
    expect(h.calls.filter(c => c.method === 'Fetch.failRequest')).toHaveLength(3);
    expect(blocked.mock.calls.flat()).toEqual(['evil.example.com', 'login.microsoftonline.com.evil.example.com', 'other.sharepoint.com']);
    expect(lookup).toHaveBeenCalledTimes(4);
    stop(); h.emit('https://teams.cloud.microsoft/'); await settled();
    expect(h.calls.filter(c => c.method === 'Fetch.continueRequest')).toHaveLength(4);
  });
  it('rejects HTTP, credentials, non443 ports, IP literals and malformed URL normalization', async () => {
    const h = harness(); const lookup = vi.fn(publicLookup);
    await installBrowserEgress(h.protocol, 'page', { lookup }, () => {});
    for (const url of ['http://teams.microsoft.com/', 'https://user:secret@teams.microsoft.com/', 'https://teams.microsoft.com:444/', 'https://127.0.0.1/', 'https://[::1]/', 'https://teams.microsoft.com\\@evil.com/', 'https://teams.microsoft.com\n/']) h.emit(url);
    h.emit('https://teams.microsoft.com:443/');
    await settled();
    expect(h.calls.filter(c => c.method === 'Fetch.failRequest')).toHaveLength(7);
    expect(h.calls.filter(c => c.method === 'Fetch.continueRequest')).toHaveLength(1);
    expect(lookup).toHaveBeenCalledTimes(1);
  });
  it('fails closed for mixed private answers, empty answers and DNS errors', async () => {
    for (const addresses of [[{ address: '20.1.1.1', family: 4 }, { address: '127.0.0.1', family: 4 }], [], [{ address: '::ffff:127.0.0.1', family: 6 }]]) {
      const h = harness();
      await installBrowserEgress(h.protocol, 'page', { lookup: async () => addresses }, () => {});
      h.emit('https://teams.microsoft.com/'); await settled();
      expect(h.calls.at(-1)).toMatchObject({ method: 'Fetch.failRequest', params: { errorReason: 'BlockedByClient' } });
    }
    const h = harness(); await installBrowserEgress(h.protocol, 'page', { lookup: async () => { throw new Error('secret DNS'); } }, () => {});
    h.emit('https://teams.microsoft.com/'); await settled();
    expect(h.calls.at(-1)?.method).toBe('Fetch.failRequest');
  });
  it('validates configured hostnames before enabling interception', async () => {
    for (const host of ['localhost', '127.0.0.1', '2130706433', '[::1]', '*.example.com', 'https://sso.example.com', 'a.example.com:443', 'foo.localhost', 'foo.local', 'bad..example.com', 'foo.example.com/secret', 'foo.example.com\n']) {
      const h = harness();
      await expect(installBrowserEgress(h.protocol, 'page', { extraHosts: [host], lookup: publicLookup }, () => {})).rejects.toThrow();
      expect(h.calls).toHaveLength(0);
    }
  });
  it('limits hostname-only diagnostics and isolates events by session', async () => {
    const h = harness(); const blocked = vi.fn();
    await installBrowserEgress(h.protocol, 'page', { lookup: publicLookup }, blocked);
    h.emit('https://outside.example.com/', 'other', 'other-page');
    for (let i = 0; i < 30; i++) h.emit(`https://host${i}.example.com/private?token=secret`);
    h.emit('https://host0.example.com/other-secret'); await settled();
    expect(blocked).toHaveBeenCalledTimes(20);
    expect(blocked.mock.calls.every(([value]) => /^host\d+\.example\.com$/.test(value))).toBe(true);
    expect(h.calls.filter(c => c.method === 'Fetch.failRequest')).toHaveLength(31);
  });
  it('shares bounded DNS work and rechecks after cache expiration', async () => {
    vi.useFakeTimers();
    try {
      const h = harness(); const lookup = vi.fn(publicLookup);
      await installBrowserEgress(h.protocol, 'page', { lookup }, () => {});
      for (let i = 0; i < 8; i++) h.emit('https://teams.microsoft.com/');
      await vi.advanceTimersByTimeAsync(1);
      expect(lookup).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(30_001);
      h.emit('https://teams.microsoft.com/'); await vi.advanceTimersByTimeAsync(1);
      expect(lookup).toHaveBeenCalledTimes(2);
    } finally { vi.useRealTimers(); }
  });
  it('keeps cache bounded across many explicitly configured hosts', async () => {
    const h = harness(); const lookup = vi.fn(publicLookup);
    const extraHosts = Array.from({ length: 256 }, (_, i) => `host${i}.example.com`);
    await installBrowserEgress(h.protocol, 'page', { extraHosts, lookup }, () => {});
    h.emit('https://teams.microsoft.com/'); await settled();
    for (const host of extraHosts) h.emit(`https://${host}/`);
    await settled();
    h.emit('https://teams.microsoft.com/'); await settled();
    expect(lookup).toHaveBeenCalledTimes(258);
  });
  it('never releases a pending DNS check after its target guard is disposed', async () => {
    const h = harness(); let finish!: (addresses: { address: string; family: number }[]) => void;
    const stop = await installBrowserEgress(h.protocol, 'page', { lookup: () => new Promise(resolve => { finish = resolve; }) }, () => {});
    h.emit('https://teams.microsoft.com/'); stop();
    finish([{ address: '20.190.128.1', family: 4 }]); await settled();
    expect(h.calls).toHaveLength(1);
  });
  it('fails closed if continuing a request fails and suppresses diagnostic callback errors', async () => {
    const h = harness(); const original = h.protocol.call;
    h.protocol.call = async (method, params, sessionId) => {
      if (method === 'Fetch.continueRequest') throw new Error('closed target');
      return original(method, params, sessionId);
    };
    await installBrowserEgress(h.protocol, 'page', { lookup: publicLookup }, () => { throw new Error('report failed'); });
    h.emit('https://teams.microsoft.com/'); await settled();
    expect(h.calls.at(-1)).toMatchObject({ method: 'Fetch.failRequest', params: { errorReason: 'BlockedByClient' } });
  });
  it('does not install a partial guard if Fetch interception fails', async () => {
    const h = harness();
    h.protocol.call = async () => { throw new Error('protocol secret'); };
    await expect(installBrowserEgress(h.protocol, 'page', { lookup: publicLookup }, () => {})).rejects.toThrow('Could not install Microsoft browser egress restrictions.');
    h.emit('https://teams.microsoft.com/'); await settled();
    expect(h.calls).toHaveLength(0);
  });
  it('fails a paused request when DNS exceeds the time bound', async () => {
    vi.useFakeTimers();
    try {
      const h = harness();
      await installBrowserEgress(h.protocol, 'page', { lookup: () => new Promise(() => {}) }, () => {});
      h.emit('https://teams.microsoft.com/'); await vi.advanceTimersByTimeAsync(2500);
      expect(h.calls.at(-1)?.method).toBe('Fetch.failRequest');
    } finally { vi.useRealTimers(); }
  });
});

describe('public browser DNS addresses', () => {
  it.each(['8.8.8.8', '20.190.128.1', '1.1.1.1', '2603:1030:20e:3::23c', '2606:4700:4700::1111'])('accepts public %s', address => expect(isPublicSessionAddress(address)).toBe(true));
  it.each(['0.0.0.0', '10.1.2.3', '100.64.0.1', '127.0.0.1', '169.254.169.254', '172.16.0.1', '192.168.1.2', '192.0.0.8', '192.0.2.1', '192.88.99.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '240.0.0.1', '255.255.255.255', '::', '::1', '::ffff:8.8.8.8', '::ffff:127.0.0.1', '64:ff9b::7f00:1', '100::1', '2001:db8::1', '2001::1', '2002:7f00:1::', '3fff::1', 'fc00::1', 'fe80::1', 'fe80::1%eth0', 'ff02::1', 'not-an-ip', '127.1'])('rejects private, reserved or malformed %s', address => expect(isPublicSessionAddress(address)).toBe(false));
});

// The fake connector receives a public destination, then connects to a local echo
// server. No test reaches a Microsoft host or any other Internet service.
import { createServer as createTcpServer, connect as netConnect, Socket } from 'node:net';
import { once } from 'node:events';
import { startBrowserEgressProxy } from '../src/microsoft/session/egress.js';
async function proxyFixture(options: Parameters<typeof startBrowserEgressProxy>[0] = {}) {
  const peers = new Set<Socket>();
  const echo = createTcpServer(socket => { peers.add(socket); socket.on('close', () => peers.delete(socket)); socket.pipe(socket); });
  echo.listen(0, '127.0.0.1'); await once(echo, 'listening');
  const echoPort = (echo.address() as { port: number }).port;
  const connect = vi.fn((_destination: { host: string; port: number; family: 4 | 6 }) => netConnect({ host: '127.0.0.1', port: echoPort }));
  const blocked = vi.fn();
  const proxy = await startBrowserEgressProxy({ lookup: publicLookup, connect, ...options }, blocked);
  async function request(raw: string) {
    const socket = netConnect({ host: '127.0.0.1', port: Number(new URL(proxy.url).port) });
    await once(socket, 'connect'); socket.write(raw);
    const [chunk] = await Promise.race([
      once(socket, 'data'),
      once(socket, 'close').then(() => { throw new Error('Proxy closed before responding'); }),
    ]);
    return { socket, text: String(chunk) };
  }
  return { proxy, connect, blocked, request, async close() {
    await proxy.close(); for (const socket of peers) socket.destroy();
    await new Promise<void>(resolve => echo.close(() => resolve()));
  } };
}
describe('Microsoft browser CONNECT proxy', () => {
  it('allows the Microsoft login bridge and observed static CDN without allowing sibling or lookalike hosts', async () => {
    const h = await proxyFixture();
    try {
      for (const host of ['login.microsoft.com', 'res.public.onecdn.static.microsoft']) {
        const { socket, text } = await h.request(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}\r\n\r\n`);
        socket.destroy();
        expect(text).toContain('200 Connection Established');
      }
      for (const host of ['login.microsoft.com.evil.test', 'other.microsoft.com', 'other.static.microsoft', 'res.public.onecdn.static.microsoft.evil.test']) {
        const { socket, text } = await h.request(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}\r\n\r\n`);
        socket.destroy();
        expect(text).toContain('403');
      }
      expect(h.connect).toHaveBeenCalledTimes(2);
    } finally { await h.close(); }
  });
  it('rejects every CONNECT before DNS while paused and resumes only validated destinations', async () => {
    const lookup = vi.fn(publicLookup); const h = await proxyFixture({ paused: true, lookup });
    try {
      const denied = await h.request('CONNECT teams.microsoft.com:443 HTTP/1.1\r\nHost: teams.microsoft.com\r\n\r\n');
      expect(denied.text).toContain('403'); denied.socket.destroy();
      expect(lookup).not.toHaveBeenCalled();
      expect(h.blocked).not.toHaveBeenCalled(); expect(h.connect).not.toHaveBeenCalled();
      h.proxy.resume(); h.proxy.resume();
      const permitted = await h.request('CONNECT teams.microsoft.com:443 HTTP/1.1\r\nHost: teams.microsoft.com\r\n\r\n');
      expect(permitted.text).toContain('200'); permitted.socket.destroy();
      expect(h.connect).toHaveBeenCalledWith({ host: '20.190.128.1', port: 443, family: 4 });
      expect(lookup).toHaveBeenCalledTimes(1);
    } finally { await h.close(); }
  });
  it('pins the validated DNS address and tunnels opaque TLS bytes', async () => {
    const h = await proxyFixture();
    try {
      const { socket, text } = await h.request('CONNECT teams.microsoft.com:443 HTTP/1.1\r\nHost: teams.microsoft.com:443\r\n\r\n');
      expect(text).toContain('200 Connection Established');
      expect(h.connect).toHaveBeenCalledWith({ host: '20.190.128.1', port: 443, family: 4 });
      const received = once(socket, 'data'); socket.write(Buffer.from([0x16, 0x03, 0x03, 0x00, 0x02, 0x12, 0x34]));
      expect((await received)[0]).toEqual(Buffer.from([0x16, 0x03, 0x03, 0x00, 0x02, 0x12, 0x34]));
      socket.destroy();
    } finally { await h.close(); }
  });
  it('rejects HTTP, unknown/private targets, credentials and non443 CONNECT without connecting', async () => {
    const h = await proxyFixture();
    try {
      for (const target of ['evil.example.com:443', '127.0.0.1:443', '[::1]:443', 'user:secret@teams.microsoft.com:443', 'teams.microsoft.com:80', 'https://teams.microsoft.com:443', 'teams.microsoft.com:443/path?secret=value']) {
        const { socket, text } = await h.request(`CONNECT ${target} HTTP/1.1\r\nHost: ignored.example.com\r\n\r\n`);
        expect(text).toMatch(/HTTP\/1\.1 40[03]/); socket.destroy();
      }
      const { socket, text } = await h.request('GET http://teams.microsoft.com/private?secret=value HTTP/1.1\r\nHost: teams.microsoft.com\r\n\r\n');
      expect(text).toContain('403'); socket.destroy();
      expect(h.connect).not.toHaveBeenCalled();
      expect(JSON.stringify(h.blocked.mock.calls)).not.toMatch(/secret|private|@|\//);
    } finally { await h.close(); }
  });
  it('rejects mixed private DNS answers and adds only selected SharePoint hosts', async () => {
    const h = await proxyFixture({ lookup: async () => [{ address: '20.190.128.1', family: 4 }, { address: '10.0.0.1', family: 4 }] });
    try {
      const { socket, text } = await h.request('CONNECT teams.microsoft.com:443 HTTP/1.1\r\nHost: teams.microsoft.com\r\n\r\n');
      expect(text).toContain('403'); socket.destroy(); expect(h.connect).not.toHaveBeenCalled();
    } finally { await h.close(); }
    const selected = await proxyFixture();
    try {
      expect(() => selected.proxy.allowSelectedHost('arbitrary.example.com')).toThrow();
      selected.proxy.allowSelectedHost('tenant.sharepoint.com');
      const { socket, text } = await selected.request('CONNECT tenant.sharepoint.com:443 HTTP/1.1\r\nHost: tenant.sharepoint.com\r\n\r\n');
      expect(text).toContain('200'); socket.destroy();
    } finally { await selected.close(); }
  });
  it('supports multi-service browser traffic above 32 tunnels while capping capacity at 128', async () => {
    const h = await proxyFixture();
    try {
      for (let i = 0; i < 128; i++) {
        const { text } = await h.request('CONNECT teams.microsoft.com:443 HTTP/1.1\r\nHost: teams.microsoft.com\r\n\r\n');
        expect(text).toContain('200');
      }
      const extra = netConnect({ host: '127.0.0.1', port: Number(new URL(h.proxy.url).port) });
      extra.on('error', () => {});
      await new Promise<void>(resolve => extra.once('close', () => resolve()));
      expect(h.connect).toHaveBeenCalledTimes(128);
    } finally { await h.close(); }
  });
  it('reclaims idle tunnels after 30 seconds without limiting an active transfer lifetime', async () => {
    // Scale only the specified idle timeout, keeping real socket activity/reset semantics.
    const originalSetTimeout = Socket.prototype.setTimeout;
    const timeouts: number[] = [];
    const timeoutSpy = vi.spyOn(Socket.prototype, 'setTimeout').mockImplementation(function (this: Socket, ms, callback) {
      timeouts.push(ms);
      return originalSetTimeout.call(this, ms === 30_000 ? 750 : ms, callback);
    });
    const h = await proxyFixture();
    try {
      const { socket } = await h.request('CONNECT teams.microsoft.com:443 HTTP/1.1\r\nHost: teams.microsoft.com\r\n\r\n');
      expect(timeouts.filter(ms => ms === 30_000)).toHaveLength(2);
      const upstream = h.connect.mock.results[0]!.value;
      for (let i = 0; i < 4; i++) {
        await new Promise(resolve => setTimeout(resolve, 250));
        expect(socket.destroyed).toBe(false);
        const echoed = once(socket, 'data');
        socket.write(`active-${i}`);
        expect(String((await echoed)[0])).toBe(`active-${i}`);
      }
      const closed = once(socket, 'close');
      await closed;
      expect(socket.destroyed).toBe(true);
      expect(upstream.destroyed).toBe(true);
      const next = await h.request('CONNECT teams.microsoft.com:443 HTTP/1.1\r\nHost: teams.microsoft.com\r\n\r\n');
      expect(next.text).toContain('200'); next.socket.destroy();
    } finally { await h.close(); timeoutSpy.mockRestore(); }
  });
  it('destroys live tunnels on close and close is idempotent', async () => {
    const h = await proxyFixture();
    const { socket } = await h.request('CONNECT teams.microsoft.com:443 HTTP/1.1\r\nHost: teams.microsoft.com\r\n\r\n');
    const closed = once(socket, 'close');
    await h.proxy.close(); await closed; await h.proxy.close(); await h.close();
    expect(socket.destroyed).toBe(true);
  });
});
it('allows the exact Teams static CDN while rejecting lookalikes',async()=>{
 const h=harness();await installBrowserEgress(h.protocol,'page',{lookup:publicLookup},()=>{});
 h.emit('https://teams.public.onecdn.static.microsoft/app.js','cdn');
 h.emit('https://teams.public.onecdn.static.microsoft.evil.example/app.js','evil');await settled();
 expect(h.calls).toContainEqual({method:'Fetch.continueRequest',params:{requestId:'cdn'},sessionId:'page'});
 expect(h.calls).toContainEqual({method:'Fetch.failRequest',params:{requestId:'evil',errorReason:'BlockedByClient'},sessionId:'page'});
});
