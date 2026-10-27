// Standalone Node.js module; deliberately has no package dependencies.
import { spawn } from 'node:child_process';
import { access, chmod, mkdtemp, rm } from 'node:fs/promises';
import { constants, openSync } from 'node:fs';
import { ReadStream, WriteStream } from 'node:tty';
import { createServer, isIP } from 'node:net';
import { request as httpRequest } from 'node:http';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline';

const BASE_DOMAINS = ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'microsoft365.com', 'cloud.microsoft'];
const MAX_BYTES = 8 * 1024 * 1024;
const LOGIN_URL = 'https://www.microsoft365.com/signin';
class UserError extends Error {}
const invalid = () => new UserError('Session is invalid or too large. Sign in again.');
const browserError = () => new UserError('Browser is not responding. Restart sign-in.');
const hostname = (value) => {
  if (typeof value !== 'string' || value.length > 253 || !value.includes('.') || isIP(value)
      || !value.split('.').every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))
      || /(?:^|\.)(?:local|localhost|internal|invalid|onion)$|(?:^|\.)home\.arpa$/.test(value)) return false;
  try { return !isIP(new URL(`https://${value}`).hostname); } catch { return false; }
};
const bounded = (value, max) => typeof value === 'string' && Buffer.byteLength(value) <= max;

export function parseArgs(args) {
  const result = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]?.slice(2);
    if (!['ssh', 'port', 'token'].includes(name) || args[index] !== `--${name}` || name in result || !args[index + 1]) throw new UserError('Invalid sign-in command. Copy the full command.');
    result[name] = args[index + 1];
  }
  if (!/^(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(result.ssh ?? '') || result.ssh.length > 253
      || !/^[1-9][0-9]{0,4}$/.test(result.port ?? '') || Number(result.port) > 65535 || !/^[a-f0-9]{64}$/.test(result.token ?? '')) throw new UserError('Invalid sign-in command. Copy the full command.');
  return { ssh: result.ssh, port: Number(result.port), token: result.token };
}

export function sshArgs(options, port) {
  return ['-N', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ExitOnForwardFailure=yes',
    '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=2', '-L', `127.0.0.1:${port}:127.0.0.1:${options.port}`, options.ssh];
}

export function chromeArgs(profile) {
  // No automation, mock-keychain, sandbox or WebAuthn overrides: Touch ID stays native.
  return [`--user-data-dir=${profile}`, '--remote-debugging-pipe', '--no-first-run', '--no-default-browser-check', 'about:blank'];
}

export function validateMetadata(value, now = Date.now()) {
  if (!value || value.version !== 1 || !bounded(value.label, 256) || !Number.isSafeInteger(value.expires)
      || value.expires <= now || value.expires > now + 60 * 60 * 1000
      || !Array.isArray(value.allowedDomains) || !value.allowedDomains.length || value.allowedDomains.length > BASE_DOMAINS.length
      || value.allowedDomains.some((domain) => !BASE_DOMAINS.includes(domain))
      || !Array.isArray(value.allowedHosts ?? []) || (value.allowedHosts ?? []).length > 64
      || (value.allowedHosts ?? []).some((host) => !hostname(host))) throw invalid();
  return { allowedDomains: [...new Set(value.allowedDomains)], allowedHosts: [...new Set(value.allowedHosts ?? [])], expires: value.expires };
}

function allowedHost(host, policy) {
  return hostname(host) && (policy.allowedHosts.includes(host) || policy.allowedDomains.some((domain) => host === domain || host.endsWith(`.${domain}`)));
}

export function allowedOrigin(value, policy) {
  try {
    const url = new URL(value);
    if (url.protocol === 'https:' && !url.username && !url.password && !url.port && allowedHost(url.hostname, policy)) return url.origin;
  } catch { /* URLs and protocol payloads never reach terminal output. */ }
  return undefined;
}

function storageEntries(entries) {
  if (!Array.isArray(entries) || entries.length > 500 || new Set(entries.map((entry) => entry?.name)).size !== entries.length) throw invalid();
  return entries.map((entry) => {
    if (!entry || !bounded(entry.name, 4096) || !bounded(entry.value, 65_536)) throw invalid();
    return { name: entry.name, value: entry.value };
  });
}

export function buildState(rawCookies, rawOrigins, policy) {
  if (!Array.isArray(rawCookies) || !Array.isArray(rawOrigins)) throw invalid();
  const cookies = [];
  for (const cookie of rawCookies) {
    if (!cookie || typeof cookie.domain !== 'string' || !allowedHost(cookie.domain.replace(/^\./, ''), policy)) continue;
    const host = cookie.domain.replace(/^\./, '');
    if (cookie.domain.startsWith('.') && !policy.allowedDomains.some((root) => host === root || host.endsWith(`.${root}`))) continue;
    if (!bounded(cookie.name, 1024) || !cookie.name || /[\x00-\x20\x7f;=]/.test(cookie.name)
        || !bounded(cookie.value, 16_384) || /[\x00-\x1f\x7f]/.test(cookie.value)
        || !bounded(cookie.path, 4096) || !cookie.path.startsWith('/') || /[\x00-\x1f\x7f]/.test(cookie.path)
        || typeof cookie.secure !== 'boolean' || typeof cookie.httpOnly !== 'boolean') throw invalid();
    const clean = Object.fromEntries(['name', 'value', 'domain', 'path', 'secure', 'httpOnly'].map((key) => [key, cookie[key]]));
    if (cookie.sameSite !== undefined) {
      if (!['Strict', 'Lax', 'None'].includes(cookie.sameSite)) throw invalid();
      clean.sameSite = cookie.sameSite;
    }
    if (cookie.expires !== undefined) {
      if (!Number.isFinite(cookie.expires) || (cookie.expires < 0 && cookie.expires !== -1) || cookie.expires > 253402300799) throw invalid();
      clean.expires = cookie.expires;
    }
    if (cookie.partitionKey !== undefined) {
      const partition = cookie.partitionKey;
      if (!partition || typeof partition !== 'object' || typeof partition.hasCrossSiteAncestor !== 'boolean'
          || !allowedOrigin(partition.topLevelSite, policy) || new URL(partition.topLevelSite).origin !== partition.topLevelSite
          || Object.keys(partition).some((key) => !['topLevelSite', 'hasCrossSiteAncestor'].includes(key))) throw invalid();
      clean.partitionKey = { topLevelSite: partition.topLevelSite, hasCrossSiteAncestor: partition.hasCrossSiteAncestor };
    }
    if (cookie.partitionKeyOpaque) throw invalid();
    cookies.push(clean);
    if (cookies.length > 500) throw invalid();
  }
  const origins = [];
  const seen = new Set();
  for (const entry of rawOrigins) {
    const origin = allowedOrigin(entry?.origin, policy);
    if (!origin) continue;
    if (origin !== entry.origin || seen.has(origin)) throw invalid();
    seen.add(origin);
    origins.push({ origin, localStorage: storageEntries(entry.localStorage), sessionStorage: storageEntries(entry.sessionStorage) });
    if (origins.length > 64) throw invalid();
  }
  const state = { version: 1, cookies, origins };
  if (Buffer.byteLength(JSON.stringify(state)) > MAX_BYTES) throw invalid();
  return state;
}

export function createProtocol(input, output) {
  let nextId = 0;
  let buffer = Buffer.alloc(0);
  let closed = false;
  const pending = new Map();
  const listeners = new Set();
  const close = () => {
    if (closed) return;
    closed = true;
    for (const request of pending.values()) { clearTimeout(request.timer); request.reject(browserError()); }
    pending.clear(); listeners.clear(); buffer = Buffer.alloc(0);
  };
  output.on('data', (chunk) => {
    if (closed) return;
    buffer = Buffer.concat([buffer, chunk]);
    if (buffer.length > MAX_BYTES * 2) { close(); return; }
    let end;
    while ((end = buffer.indexOf(0)) >= 0) {
      let message;
      try { message = JSON.parse(buffer.subarray(0, end).toString('utf8')); } catch { close(); return; }
      buffer = buffer.subarray(end + 1);
      if (!message || typeof message !== 'object') { close(); return; }
      if (message.id !== undefined) {
        const request = pending.get(message.id);
        if (request) {
          pending.delete(message.id); clearTimeout(request.timer);
          if (message.error) request.reject(browserError()); else request.resolve(message.result ?? {});
        }
      } else for (const listener of listeners) listener(message);
    }
  });
  output.on('error', close); output.on('end', close); input.on('error', close);
  return {
    close,
    onEvent(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    send(method, params = {}, sessionId) {
      if (closed || pending.size >= 128) return Promise.reject(browserError());
      return new Promise((resolve, reject) => {
        const id = ++nextId;
        const timer = setTimeout(() => { pending.delete(id); reject(browserError()); }, 10_000);
        pending.set(id, { resolve, reject, timer });
        input.write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0', (error) => { if (error) close(); });
      });
    },
  };
}

export function createOriginCollector(protocol, policy) {
  const sessions = new Set();
  const origins = new Map();
  const pending = new Set();
  let failure;
  const record = (url, sessionId) => {
    const origin = allowedOrigin(url, policy);
    if (origin) {
      if (!origins.has(origin) && origins.size >= 64) { failure = invalid(); return; }
      origins.set(origin, sessionId);
    }
  };
  const walk = (tree, sessionId) => {
    if (!tree) return;
    record(tree.frame?.url, sessionId);
    for (const child of tree.childFrames ?? []) walk(child, sessionId);
  };
  const unsubscribe = protocol.onEvent((event) => {
    if (event.method === 'Target.attachedToTarget') {
      const { sessionId, targetInfo } = event.params ?? {};
      if (!sessionId || !['page', 'iframe'].includes(targetInfo?.type)) return;
      sessions.add(sessionId);
      record(targetInfo.url, sessionId);
      const task = (async () => {
        await protocol.send('Page.enable', {}, sessionId);
        await protocol.send('DOMStorage.enable', {}, sessionId);
        walk((await protocol.send('Page.getFrameTree', {}, sessionId)).frameTree, sessionId);
        await protocol.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }, sessionId);
      })().catch(() => { /* A login popup can close while its target is being attached. */ });
      pending.add(task); void task.finally(() => pending.delete(task));
    } else if (event.method === 'Page.frameNavigated' && sessions.has(event.sessionId)) record(event.params?.frame?.url, event.sessionId);
    else if (event.method === 'Target.detachedFromTarget') sessions.delete(event.params?.sessionId);
  });
  const ready = async () => { while (pending.size) await Promise.all([...pending]); if (failure) throw failure; };
  return {
    ready,
    close: unsubscribe,
    async capture() {
      await ready();
      const result = [];
      for (const [origin, sessionId] of origins) {
        const entry = { origin, localStorage: [], sessionStorage: [] };
        for (const [name, isLocalStorage] of [['localStorage', true], ['sessionStorage', false]]) {
          // Closed popup origins can be unavailable; cookies remain the primary web SSO state.
          let response;
          try { response = await protocol.send('DOMStorage.getDOMStorageItems', { storageId: { securityOrigin: origin, isLocalStorage } }, sessionId); }
          catch { continue; }
          if (!Array.isArray(response.entries)) throw invalid();
          entry[name] = storageEntries(response.entries.map(([name, value]) => ({ name, value })));
        }
        result.push(entry);
      }
      return result;
    },
  };
}

export function createCleanup() {
  const actions = [];
  let running;
  return {
    add(action) { actions.push(action); },
    run() { return running ??= (async () => { for (const action of actions.reverse()) { try { await action(); } catch { /* Continue cleaning all owned resources. */ } } })(); },
  };
}

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function findChrome() {
  const candidates = process.platform === 'darwin'
    ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', join(homedir(), 'Applications/Google Chrome.app/Contents/MacOS/Google Chrome')]
    : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/opt/google/chrome/chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  for (const path of candidates) { try { await access(path, constants.X_OK); return path; } catch { /* Try the next standard installation. */ } }
  throw new UserError('Install Google Chrome, then restart sign-in.');
}

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  let timeout;
  await Promise.race([exited, new Promise((resolve) => { timeout = setTimeout(resolve, 2000); })]);
  clearTimeout(timeout);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGKILL');
    await Promise.race([exited, new Promise((resolve) => { timeout = setTimeout(resolve, 2000); })]);
    clearTimeout(timeout);
  }
}

export async function requestSession(url, token, signal, state, receiverPort) {
  const address = new URL(url);
  if (address.protocol !== 'http:' || address.hostname !== '127.0.0.1' || !address.port
      || address.username || address.password || address.search || address.hash || !['/session', '/cancel'].includes(address.pathname)
      || !Number.isInteger(receiverPort) || receiverPort < 1 || receiverPort > 65535 || !/^[a-f0-9]{64}$/.test(token)) throw invalid();
  const body = state === undefined ? undefined : JSON.stringify(state);
  if (body !== undefined && Buffer.byteLength(body) > MAX_BYTES) throw invalid();
  const failed = () => new UserError('Sign-in expired or was rejected. Restart sign-in.');
  // Connect only to the owned local forward, but address the remote loopback receiver.
  // node:http preserves this explicit Host header; fetch implementations can override it.
  return new Promise((resolve, reject) => {
    const request = httpRequest(address, {
      method: body === undefined ? 'GET' : 'POST', agent: false,
      signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]),
      headers: { host: `127.0.0.1:${receiverPort}`, authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }) },
    }, (response) => {
      // No redirects, regardless of destination. No response body or network error is echoed.
      if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
        reject(failed()); response.destroy(); return;
      }
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > 16 * 1024) { reject(invalid()); response.destroy(); return; }
        chunks.push(chunk);
      });
      response.on('aborted', () => reject(failed()));
      response.on('error', () => reject(failed()));
      response.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(invalid()); }
      });
    });
    request.on('error', () => reject(failed()));
    request.end(body);
  });
}

async function waitForEnter(signal, cleanup) {
  // stdin contains this module when run with `node --input-type=module -`.
  // TTY streams use pollable handles; filesystem read streams can block cleanup on a pending read.
  const input = new ReadStream(openSync('/dev/tty', 'r'));
  cleanup.add(() => input.destroy());
  const output = new WriteStream(openSync('/dev/tty', 'w'));
  cleanup.add(() => output.destroy());
  const readline = createInterface({ input, output, terminal: true });
  cleanup.add(() => readline.close());
  output.write('Sign in to Microsoft in the opened Chrome window (password or Touch ID).\nThen press Enter here: ');
  await new Promise((resolve, reject) => {
    const abort = () => { readline.close(); reject(new UserError('Sign-in cancelled.')); };
    signal.addEventListener('abort', abort, { once: true });
    const done = () => signal.removeEventListener('abort', abort);
    readline.once('line', () => { done(); resolve(); });
    readline.once('close', () => { done(); reject(new UserError('Sign-in cancelled.')); });
    readline.once('SIGINT', abort);
    if (signal.aborted) abort();
  });
}

export async function main(args = process.argv.slice(2), dependencies = {}) {
  const deps = { platform: process.platform, findChrome, freePort, spawn, mkdtemp, chmod, rm, requestSession, waitForEnter,
    output: (text) => process.stdout.write(text), ...dependencies };
  const options = parseArgs(args);
  if (!['darwin', 'linux'].includes(deps.platform)) throw new UserError('Sign-in requires macOS or Linux with Google Chrome.');
  const executable = await deps.findChrome();
  const cleanup = createCleanup();
  const controller = new AbortController();
  const abort = () => controller.abort();
  for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(name, abort);
  let expiryTimer;
  let url;
  let uploaded = false;
  try {
    const port = await deps.freePort();
    const ssh = deps.spawn('ssh', sshArgs(options, port), { stdio: 'ignore', shell: false });
    let sshFailed = false;
    ssh.on('error', () => { sshFailed = true; abort(); });
    ssh.on('exit', () => { sshFailed = true; abort(); });
    cleanup.add(() => stopChild(ssh));
    url = `http://127.0.0.1:${port}/session`;
    let metadata;
    const deadline = Date.now() + 12_000;
    while (Date.now() < deadline && !controller.signal.aborted) {
      try { metadata = await deps.requestSession(url, options.token, controller.signal, undefined, options.port); break; }
      catch { if (sshFailed) break; await new Promise((resolve) => setTimeout(resolve, 150)); }
    }
    if (!metadata || sshFailed) throw new UserError('SSH connection failed. Connect to the server in a terminal, then retry this command.');
    const policy = validateMetadata(metadata);
    expiryTimer = setTimeout(abort, policy.expires - Date.now());
    const profile = await deps.mkdtemp(join(tmpdir(), 'perch-microsoft-login-'));
    cleanup.add(() => deps.rm(profile, { recursive: true, force: true, maxRetries: 3 }));
    await deps.chmod(profile, 0o700);
    const chrome = deps.spawn(executable, chromeArgs(profile), { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'], shell: false });
    chrome.on('error', abort); chrome.on('exit', abort);
    cleanup.add(() => stopChild(chrome));
    const protocol = createProtocol(chrome.stdio[3], chrome.stdio[4]);
    cleanup.add(async () => {
      let closeTimeout;
      try {
        await Promise.race([protocol.send('Browser.close').catch(() => {}),
          new Promise((resolve) => { closeTimeout = setTimeout(resolve, 1500); })]);
      } finally { clearTimeout(closeTimeout); protocol.close(); }
    });
    const collector = createOriginCollector(protocol, policy);
    cleanup.add(() => collector.close());
    await protocol.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true });
    await protocol.send('Target.createTarget', { url: LOGIN_URL });
    await deps.waitForEnter(controller.signal, cleanup);
    if (controller.signal.aborted) throw new UserError('Sign-in cancelled or expired.');
    const cookies = (await protocol.send('Storage.getCookies')).cookies;
    const origins = await collector.capture();
    const state = buildState(cookies, origins, policy);
    const result = await deps.requestSession(url, options.token, controller.signal, state, options.port);
    if (result?.ok !== true) throw invalid();
    uploaded = true;
    deps.output('Sign-in transferred. Continue in the server terminal.\n');
  } finally {
    clearTimeout(expiryTimer);
    if (url && !uploaded) {
      try { await deps.requestSession(url.replace(/\/session$/, '/cancel'), options.token, AbortSignal.timeout(2000), {}, options.port); }
      catch { /* Best-effort cancellation while the owned SSH forward still exists. */ }
    }
    await cleanup.run();
    for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.off(name, abort);
  }
}

export async function run(args = process.argv.slice(2)) {
  try { await main(args); }
  catch (error) {
    // Never echo browser/protocol/fetch exceptions: they can contain account state.
    process.stderr.write((error instanceof UserError ? error.message : 'Sign-in incomplete. Check Chrome and SSH, then retry.') + '\n');
    process.exitCode = 1;
  }
}

const standalone = (process.argv[1] === '-' && import.meta.url.endsWith('/[eval1]'))
  || (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href);
if (standalone) await run();
