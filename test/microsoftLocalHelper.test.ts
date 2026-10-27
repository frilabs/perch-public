import { describe, expect, it, vi } from 'vitest';
import { PassThrough } from 'node:stream';
import { EventEmitter } from 'node:events';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createTcpServer, connect, type AddressInfo } from 'node:net';

// Dynamic path keeps the dependency-free distributable outside TypeScript compilation.
const helperPath = new URL('../assets/microsoft-local-login.mjs', import.meta.url).href;
const helper = await import(helperPath);
const token = 'a'.repeat(64);
const metadata = () => ({ version: 1, label: 'Test', expires: Date.now() + 60_000,
  allowedDomains: ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'microsoft365.com', 'cloud.microsoft'],
  allowedHosts: ['tenant.sharepoint.com'] });
const cookie = (domain = '.login.microsoftonline.com') => ({ name: 'session', value: 'secret', domain,
  path: '/', secure: true, httpOnly: true, expires: -1, sameSite: 'None', size: 999, session: true });

describe('standalone native Microsoft helper', () => {
  it('validates all arguments before launching commands and rejects SSH option injection', () => {
    expect(helper.parseArgs(['--ssh', 'me@example-server', '--port', '12345', '--token', token]))
      .toEqual({ ssh: 'me@example-server', port: 12345, token });
    for (const ssh of ['-oProxyCommand=x', 'host;touch /tmp/x', 'host\nother', 'a b']) {
      expect(() => helper.parseArgs(['--ssh', ssh, '--port', '12345', '--token', token])).toThrow();
    }
    for (const extra of [['--port', '0'], ['--token', 'secret'], ['--other', 'x']]) {
      expect(() => helper.parseArgs(['--ssh', 'home', '--port', '12345', '--token', token, ...extra])).toThrow();
    }
  });

  it('uses strict SSH trust and a loopback-only owned forward without shell expansion', () => {
    const args = helper.sshArgs({ ssh: 'example-server', port: 12345 }, 23456);
    expect(args).toContain('StrictHostKeyChecking=yes');
    expect(args).toContain('ExitOnForwardFailure=yes');
    expect(args).toContain('ControlPath=none');
    expect(args).toContain('127.0.0.1:23456:127.0.0.1:12345');
    expect(args.at(-1)).toBe('example-server');
    expect(args).not.toContain(token);
  });

  it('retains native macOS WebAuthn and sandbox while using a fresh profile and private pipes', () => {
    const args: string[] = helper.chromeArgs('/tmp/perch-test');
    expect(args).toContain('--user-data-dir=/tmp/perch-test');
    expect(args).toContain('--remote-debugging-pipe');
    expect(args.join(' ')).not.toMatch(/mock|no-sandbox|disable-web-security|ignore-certificate|remote-debugging-port|enable-automation|headless/i);
  });

  it('checks receiver expiry and limits suffix grants to known Microsoft roots', () => {
    const policy = helper.validateMetadata(metadata());
    expect(helper.allowedOrigin('https://login.microsoftonline.com/', policy)).toBe('https://login.microsoftonline.com');
    expect(helper.allowedOrigin('https://tenant.sharepoint.com/', policy)).toBe('https://tenant.sharepoint.com');
    for (const origin of ['http://login.microsoftonline.com', 'https://microsoft.com.evil.test', 'https://sub.tenant.sharepoint.com', 'https://tenant.sharepoint.com:444', 'https://x:pass@microsoft.com']) {
      expect(helper.allowedOrigin(origin, policy)).toBeUndefined();
    }
    expect(() => helper.validateMetadata({ ...metadata(), allowedDomains: ['com'] })).toThrow();
    expect(() => helper.validateMetadata({ ...metadata(), expires: Date.now() - 1 })).toThrow();
    expect(() => helper.validateMetadata({ ...metadata(), allowedHosts: ['*.sharepoint.com'] })).toThrow();
  });

  it('exports only allowed cookies and portable fields, preserving session/partition semantics', () => {
    const partitionKey = { topLevelSite: 'https://microsoft.com', hasCrossSiteAncestor: false };
    const state = helper.buildState([cookie(), cookie('.evil.test'), { ...cookie(), partitionKey }], [], helper.validateMetadata(metadata()));
    expect(state.cookies).toHaveLength(2);
    expect(state.cookies[0]).toEqual({ name: 'session', value: 'secret', domain: '.login.microsoftonline.com', path: '/', secure: true, httpOnly: true, expires: -1, sameSite: 'None' });
    expect(state.cookies[1].partitionKey).toEqual(partitionKey);
    expect(() => helper.buildState([{ ...cookie(), partitionKey: { opaque: true } }], [], helper.validateMetadata(metadata()))).toThrow();
  });

  it('keeps exact extra-host cookies host-only and enforces receiver-compatible field limits', () => {
    const policy = helper.validateMetadata(metadata());
    expect(helper.buildState([cookie('.tenant.sharepoint.com'), cookie('tenant.sharepoint.com')], [], policy).cookies)
      .toEqual([expect.objectContaining({ domain: 'tenant.sharepoint.com' })]);
    for (const patch of [{ name: 'bad name' }, { name: 'x'.repeat(1025) }, { value: 'x'.repeat(16385) }, { value: 'bad\nsecret' }, { path: '/bad\rpath' }]) {
      expect(() => helper.buildState([{ ...cookie(), ...patch }], [], policy)).toThrow();
    }
    for (const localStorage of [[{ name: 'key', value: 'x'.repeat(65537) }], [{ name: 'key', value: 'a' }, { name: 'key', value: 'b' }]]) {
      expect(() => helper.buildState([], [{ origin: 'https://microsoft.com', localStorage, sessionStorage: [] }], policy)).toThrow();
    }
    for (const host of ['127.0.0.1', '0x7f.1', 'x.localhost', `${'x'.repeat(64)}.com`]) {
      expect(() => helper.validateMetadata({ ...metadata(), allowedHosts: [host] })).toThrow();
    }
  });

  it('does not execute when imported by a separate stdin application', () => {
    const output = execFileSync(process.execPath, ['--input-type=module', '-'], {
      input: `await import(${JSON.stringify(helperPath)}); console.log('import-only');`, encoding: 'utf8', timeout: 2000,
    });
    expect(output).toBe('import-only\n');
  });

  it('executes the downloaded stdin module and never echoes a malformed secret-bearing argument', () => {
    const child = spawnSync(process.execPath, ['--input-type=module', '-', '--token', 'DO-NOT-PRINT-SECRET'], {
      input: readFileSync(new URL(helperPath), 'utf8'), encoding: 'utf8', timeout: 2000,
    });
    expect(child.status).toBe(1);
    expect(child.stderr).toContain('Invalid sign-in command');
    expect(child.stdout + child.stderr).not.toContain('DO-NOT-PRINT-SECRET');
  });

  it('imports a verified data URL without starting login and exposes an explicit sanitized entry point', () => {
    const source = readFileSync(new URL(helperPath), 'utf8');
    const dataUrl = `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
    const imported = spawnSync(process.execPath, ['--input-type=module', '-e',
      `await import(${JSON.stringify(dataUrl)}); console.log('import-only');`, '--', '--token', 'DO-NOT-PRINT-SECRET'],
    { encoding: 'utf8', timeout: 2000 });
    expect(imported.status).toBe(0);
    expect(imported.stdout).toBe('import-only\n');
    expect(imported.stderr).toBe('');
    const invoked = spawnSync(process.execPath, ['--input-type=module', '-e',
      `const m = await import(${JSON.stringify(dataUrl)}); await m.run(process.argv.slice(1));`, '--', '--token', 'DO-NOT-PRINT-SECRET'],
    { encoding: 'utf8', timeout: 2000 });
    expect(invoked.status).toBe(1);
    expect(invoked.stderr).toContain('Invalid sign-in command');
    expect(invoked.stdout + invoked.stderr).not.toContain('DO-NOT-PRINT-SECRET');
  });

  it('bounds serialized state, counts and values without revealing secrets', () => {
    const policy = helper.validateMetadata(metadata());
    expect(() => helper.buildState(Array(501).fill(cookie()), [], policy)).toThrow();
    expect(() => helper.buildState([ { ...cookie(), value: 'SECRET'.repeat(300000) } ], [], policy)).toThrowError(/Session/);
    expect(() => helper.buildState([], [{ origin: 'https://microsoft.com', localStorage: Array(501).fill({ name: 'a', value: 'secret' }), sessionStorage: [] }], policy)).toThrow();
    expect(() => helper.buildState([], Array.from({ length: 65 }, (_, i) => ({ origin: `https://${i}.microsoft.com`, localStorage: [], sessionStorage: [] })), policy)).toThrow();
    expect(() => helper.buildState([], [{ origin: 'https://microsoft.com', localStorage: Array.from({ length: 129 }, (_, i) => ({ name: String(i), value: 'x'.repeat(65_536) })), sessionStorage: [] }], policy)).toThrow();
  });

  it('speaks bounded NUL-delimited CDP over pipes and suppresses remote error payloads', async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const protocol = helper.createProtocol(input, output);
    let sent = '';
    input.on('data', (chunk) => { sent += chunk.toString(); });
    const request = protocol.send('Storage.getCookies');
    const id = JSON.parse(sent.slice(0, -1)).id;
    output.write(JSON.stringify({ id, result: { cookies: [] } }) + '\0');
    await expect(request).resolves.toEqual({ cookies: [] });
    const rejected = protocol.send('Bad.method');
    output.write(JSON.stringify({ id: id + 1, error: { message: 'SECRET-COOKIE' } }) + '\0');
    await expect(rejected).rejects.toThrow('Browser');
    protocol.close();
  });

  it('uses the receiver Host for metadata, upload and cancellation through a different local forwarding port', async () => {
    const received: { host?: string; path?: string; method?: string; authorization?: string; body: string }[] = [];
    let remotePort = 0;
    const receiver = createHttpServer(async (request, response) => {
      let body = '';
      for await (const chunk of request) body += chunk.toString();
      received.push({ host: request.headers.host, path: request.url, method: request.method, authorization: request.headers.authorization, body });
      response.writeHead(request.headers.host === `127.0.0.1:${remotePort}` ? 200 : 403, { 'content-type': 'application/json' });
      response.end(JSON.stringify(request.method === 'GET' ? metadata() : { ok: true }));
    });
    const forward = createTcpServer((client) => {
      const upstream = connect(remotePort, '127.0.0.1');
      client.on('error', () => upstream.destroy());
      upstream.on('error', () => client.destroy());
      client.pipe(upstream).pipe(client);
    });
    try {
      await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
      remotePort = (receiver.address() as AddressInfo).port;
      await new Promise<void>((resolve) => forward.listen(0, '127.0.0.1', resolve));
      const localPort = (forward.address() as AddressInfo).port;
      expect(localPort).not.toBe(remotePort);
      const url = `http://127.0.0.1:${localPort}/session`;
      const signal = AbortSignal.timeout(2000);
      await expect(helper.requestSession(url, token, signal, undefined, remotePort)).resolves.toHaveProperty('version', 1);
      await expect(helper.requestSession(url, token, signal, { version: 1, cookies: [], origins: [] }, remotePort)).resolves.toEqual({ ok: true });
      await expect(helper.requestSession(url.replace('/session', '/cancel'), token, signal, {}, remotePort)).resolves.toEqual({ ok: true });
      expect(received.map(({ host, path, method }) => ({ host, path, method }))).toEqual([
        { host: `127.0.0.1:${remotePort}`, path: '/session', method: 'GET' },
        { host: `127.0.0.1:${remotePort}`, path: '/session', method: 'POST' },
        { host: `127.0.0.1:${remotePort}`, path: '/cancel', method: 'POST' },
      ]);
      expect(received.every((request) => request.authorization === `Bearer ${token}`)).toBe(true);
      expect(received[2]?.body).toBe('{}');
    } finally {
      await Promise.all([new Promise<void>((resolve) => forward.close(() => resolve())), new Promise<void>((resolve) => receiver.close(() => resolve()))]);
    }
  });

  it('rejects redirects, oversized responses and expired requests without exposing response secrets', async () => {
    let mode = 'redirect';
    let calls = 0;
    const receiver = createHttpServer((_request, response) => {
      calls++;
      if (mode === 'redirect') { response.writeHead(302, { location: '/secret-redirect' }); response.end('SECRET-RESPONSE'); }
      else if (mode === 'large') { response.end(JSON.stringify({ secret: 'SECRET-RESPONSE'.repeat(2000) })); }
      // The remaining mode deliberately leaves the request pending until its deadline.
    });
    try {
      await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
      const port = (receiver.address() as AddressInfo).port;
      const url = `http://127.0.0.1:${port}/session`;
      await expect(helper.requestSession(url, token, AbortSignal.timeout(2000), undefined, port)).rejects.toThrow('rejected');
      expect(calls).toBe(1);
      mode = 'large';
      await expect(helper.requestSession(url, token, AbortSignal.timeout(2000), undefined, port)).rejects.toThrow('too large');
      mode = 'pending';
      await expect(helper.requestSession(url, token, AbortSignal.timeout(25), undefined, port)).rejects.toThrow('expired');
      expect(calls).toBe(3);
      await expect(helper.requestSession('http://example.com:8080/session', token, AbortSignal.timeout(100), undefined, port)).rejects.toThrow();
      expect(calls).toBe(3);
    } finally {
      receiver.closeAllConnections();
      await new Promise<void>((resolve) => receiver.close(() => resolve()));
    }
  });

  it('collects only dedicated page/frame origins and queries both stores via CDP', async () => {
    const policy = helper.validateMetadata(metadata());
    let onEvent: (event: any) => void = () => undefined;
    const send = vi.fn(async (method: string) => {
      if (method === 'Page.getFrameTree') return { frameTree: { frame: { url: 'https://login.microsoftonline.com/' }, childFrames: [{ frame: { url: 'https://evil.test/' } }] } };
      if (method === 'DOMStorage.getDOMStorageItems') return { entries: [['key', 'secret']] };
      return {};
    });
    const collector = helper.createOriginCollector({ send, onEvent: (fn: typeof onEvent) => { onEvent = fn; return () => undefined; } }, policy);
    onEvent({ method: 'Target.attachedToTarget', params: { sessionId: 'dedicated', targetInfo: { type: 'page', url: 'about:blank' } } });
    await collector.ready();
    onEvent({ method: 'Page.frameNavigated', sessionId: 'dedicated', params: { frame: { url: 'https://tenant.sharepoint.com/site' } } });
    onEvent({ method: 'Page.frameNavigated', sessionId: 'unknown', params: { frame: { url: 'https://rogue.microsoft.com/' } } });
    const origins = await collector.capture();
    expect(origins.map((entry: any) => entry.origin).sort()).toEqual(['https://login.microsoftonline.com', 'https://tenant.sharepoint.com']);
    expect(origins[0].localStorage).toEqual([{ name: 'key', value: 'secret' }]);
    expect(origins[0].sessionStorage).toEqual([{ name: 'key', value: 'secret' }]);
    collector.close();
  });

  it('cleans all owned resources even if one cleanup action fails, and only once', async () => {
    const cleanup = helper.createCleanup();
    const actions: number[] = [];
    cleanup.add(async () => { actions.push(1); });
    cleanup.add(async () => { actions.push(2); throw new Error('secret'); });
    cleanup.add(async () => { actions.push(3); });
    await cleanup.run();
    await cleanup.run();
    expect(actions).toEqual([3, 2, 1]);
  });

  function workflow(cancel = false) {
    const children: any[] = [];
    const spawn = vi.fn((command: string) => {
      const child: any = new EventEmitter();
      Object.assign(child, { exitCode: null, signalCode: null, stdio: [null, null, null, new PassThrough(), new PassThrough()] });
      child.kill = vi.fn(() => { child.signalCode = 'SIGTERM'; child.emit('exit'); return true; });
      child.stdio[3].on('data', (data: Buffer) => {
        const request = JSON.parse(data.toString().slice(0, -1));
        const result = request.method === 'Storage.getCookies' ? { cookies: [cookie()] } : {};
        queueMicrotask(() => child.stdio[4].write(JSON.stringify({ id: request.id, result }) + '\0'));
      });
      children.push(child);
      return child;
    });
    const request = vi.fn(async (_url: string, _token: string, _signal: AbortSignal, state: unknown, _receiverPort: number) => state ? { ok: true } : metadata());
    const remove = vi.fn(async () => undefined);
    const output = vi.fn();
    const deps = { platform: 'darwin', findChrome: async () => '/mock/Chrome', freePort: async () => 23456, spawn,
      mkdtemp: async () => '/tmp/owned-profile', chmod: async () => undefined, rm: remove,
      requestSession: request, waitForEnter: async () => { if (cancel) throw new Error('USER-SECRET'); }, output };
    return { children, spawn, request, remove, output, deps };
  }

  it('completes a mocked native login and disposes owned children/profile without cancelling upload', async () => {
    const fixture = workflow();
    await helper.main(['--ssh', 'example-server', '--port', '12345', '--token', token], fixture.deps);
    expect(fixture.spawn.mock.calls.map((call) => call[0])).toEqual(['ssh', '/mock/Chrome']);
    const upload = fixture.request.mock.calls.find((call) => (call[3] as any)?.version === 1);
    expect(upload?.[0]).toBe('http://127.0.0.1:23456/session');
    expect(upload?.[1]).toBe(token);
    expect(fixture.request.mock.calls.every((call) => call[4] === 12345)).toBe(true);
    expect((upload?.[3] as any).cookies[0].value).toBe('secret');
    expect(fixture.request.mock.calls.some((call) => call[0].endsWith('/cancel'))).toBe(false);
    expect(fixture.children.every((child) => child.kill.mock.calls.length === 1)).toBe(true);
    expect(fixture.remove).toHaveBeenCalledWith('/tmp/owned-profile', expect.objectContaining({ recursive: true }));
    expect(JSON.stringify(fixture.output.mock.calls)).not.toContain('secret');
  });

  it('cancels the receiver on an unsuccessful login and still cleans Chrome, SSH and the profile', async () => {
    const fixture = workflow(true);
    await expect(helper.main(['--ssh', 'example-server', '--port', '12345', '--token', token], fixture.deps)).rejects.toThrow();
    expect(fixture.request.mock.calls.some((call) => call[0] === 'http://127.0.0.1:23456/cancel')).toBe(true);
    expect(fixture.request.mock.calls.some((call) => (call[3] as any)?.version === 1)).toBe(false);
    expect(fixture.children.every((child) => child.kill.mock.calls.length === 1)).toBe(true);
    expect(fixture.remove).toHaveBeenCalledOnce();
  });

  it('gracefully closes native Chrome before deleting its private profile', async () => {
    const fixture = workflow();
    const commands: string[] = [];
    fixture.deps.waitForEnter = async () => {
      fixture.children[1].stdio[3].on('data', (data: Buffer) => commands.push(JSON.parse(data.toString().slice(0, -1)).method));
    };
    await helper.main(['--ssh', 'example-server', '--port', '12345', '--token', token], fixture.deps);
    expect(commands).toContain('Browser.close');
  });

  it('honors a termination signal without uploading and releases its process signal handlers', async () => {
    const fixture = workflow();
    const handlers = process.listenerCount('SIGTERM');
    fixture.deps.waitForEnter = async () => { process.emit('SIGTERM'); };
    await expect(helper.main(['--ssh', 'example-server', '--port', '12345', '--token', token], fixture.deps)).rejects.toThrow('cancelled');
    expect(process.listenerCount('SIGTERM')).toBe(handlers);
    expect(fixture.request.mock.calls.some((call) => (call[3] as any)?.version === 1)).toBe(false);
    expect(fixture.children.every((child) => child.kill.mock.calls.length === 1)).toBe(true);
    expect(fixture.remove).toHaveBeenCalledOnce();
  });
});
