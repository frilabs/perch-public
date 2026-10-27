import { request } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { startSessionViewer, serviceUrl, type SessionBrowser } from '../src/microsoft/sessionViewer.js';

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { for (const close of cleanups.splice(0)) await close(); });
function mockBrowser() {
  const calls: unknown[] = [];
  const browser: SessionBrowser = {
    snapshot: async () => ({ image: 'AA==', host: 'login.microsoftonline.com' }),
    action: async (action) => { calls.push(action); },
    close: async () => { calls.push('closed'); },
  };
  return { browser, calls };
}
async function fixture(timeoutMs = 60_000) {
  const { browser, calls } = mockBrowser();
  const viewer = await startSessionViewer(browser, { port: 0, timeoutMs });
  cleanups.push(viewer.close);
  const url = new URL(viewer.url);
  const base = url.origin;
  const unlock = await fetch(`${base}/unlock`, { method: 'POST', headers: { Origin: base, 'Content-Type': 'application/json' }, body: JSON.stringify({ token: url.hash.slice(1) }) });
  const cookie = unlock.headers.get('set-cookie')!.split(';')[0]!;
  const headers = { Origin: base, Cookie: cookie, 'Content-Type': 'application/json' };
  return { viewer, base, headers, calls, token: url.hash.slice(1), unlock };
}

describe('experimental Microsoft login viewer', () => {
  it('requires a fragment secret, then an HttpOnly cookie for screenshots and input', async () => {
    const { base, headers, token, unlock } = await fixture();
    expect(unlock.status).toBe(200);
    expect(unlock.headers.get('set-cookie')).toMatch(/HttpOnly.*SameSite=Strict/);
    const page = await fetch(base);
    expect(await page.text()).not.toContain(token);
    expect(page.headers.get('referrer-policy')).toBe('no-referrer');
    expect(page.headers.get('cache-control')).toBe('no-store');
    expect((await fetch(`${base}/state`)).status).toBe(401);
    expect((await fetch(`${base}/action`, { method: 'POST', headers: { Origin: base }, body: '{}' })).status).toBe(401);
    expect((await fetch(`${base}/state`, { headers })).status).toBe(200);
    expect((await fetch(`${base}/unlock`, { method: 'POST', headers, body: JSON.stringify({ token }) })).status).toBe(401);
  });

  it('rejects cross-origin and rebinding requests, arbitrary commands, URLs and large inputs', async () => {
    const { base, headers, calls } = await fixture();
    expect((await fetch(`${base}/action`, { method: 'POST', headers: { ...headers, Origin: 'https://evil.test' }, body: '{}' })).status).toBe(403);
    const status = await new Promise<number | undefined>((resolve, reject) => { const r = request(`${base}/state`, { headers: { ...headers, Host: 'evil.test' } }, (res) => { res.resume(); resolve(res.statusCode); }); r.on('error', reject); r.end(); });
    expect(status).toBe(403);
    for (const action of [{ type: 'eval', expression: 'document.cookie' }, { type: 'navigate', url: 'http://169.254.169.254/' }, { type: 'click', x: -1, y: 5 }, { type: 'text', text: 'x'.repeat(9000) }]) {
      const r = await fetch(`${base}/action`, { method: 'POST', headers, body: JSON.stringify(action) });
      expect([400, 413]).toContain(r.status);
    }
    expect(calls).toEqual([]);
  });

  it('dispatches bounded input and only named service navigation', async () => {
    const { base, headers, calls } = await fixture();
    for (const action of [{ type: 'click', x: 12, y: 20 }, { type: 'key', key: 'Tab', shift: true }, { type: 'text', text: 'test' }, { type: 'service', service: 'calendar' }]) {
      expect((await fetch(`${base}/action`, { method: 'POST', headers, body: JSON.stringify(action) })).status).toBe(200);
    }
    expect(calls).toHaveLength(4);
    expect(calls[3]).toEqual({ type: 'navigate', url: 'https://outlook.office.com/calendar/' });
  });

  it('never labels a page visit as verified Microsoft or MCP access', async () => {
    const { base, headers } = await fixture();
    const state = await (await fetch(`${base}/state`, { headers })).json() as Record<string, unknown>;
    expect(state.services).toEqual({ teams: 'unverified', mail: 'unverified', calendar: 'unverified', onedrive: 'unverified', sharepoint: 'unverified' });
    expect(state).not.toHaveProperty('identity');
  });

  it('finishes and closes the browser without converting confirmation to verified access', async () => {
    const { base, headers, viewer, calls } = await fixture();
    expect((await fetch(`${base}/finish`, { method: 'POST', headers, body: '{}' })).status).toBe(200);
    expect(await viewer.done).toBe('finished');
    expect(calls).toEqual(['closed']);
  });

  it('expires and releases the browser', async () => {
    const { viewer, calls } = await fixture(200);
    expect(await viewer.done).toBe('expired');
    expect(calls).toEqual(['closed']);
  });
});

describe('explicit service destinations', () => {
  it('starts at Microsoft sign-in instead of the unauthenticated product landing page', () => {
    expect(serviceUrl('login')).toBe('https://www.microsoft365.com/signin');
  });
  it('accepts a selected SharePoint site but not other hosts or embedded credentials', () => {
    expect(serviceUrl('sharepoint', 'https://example.sharepoint.com/sites/test')).toBe('https://example.sharepoint.com/sites/test');
    for (const url of ['http://example.sharepoint.com/', 'https://example.sharepoint.com.evil.test/', 'https://a:b@example.sharepoint.com/', 'https://example.sharepoint.com:444/', 'https://127.0.0.1/', 'https://example.sharepoint.com/?token=secret']) {
      expect(() => serviceUrl('sharepoint', url)).toThrow();
    }
    expect(() => serviceUrl('eval')).toThrow();
  });
});

// No real browser or Microsoft data in these tests.
import { sessionProfileId, browserArguments, openSessionProfile } from '../src/microsoft/sessionBrowser.js';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
describe('isolated browser profiles', () => {
  it('maps labels to stable safe paths, never shell/path fragments', () => {
    expect(sessionProfileId('Work')).toBe(sessionProfileId('Work'));
    expect(sessionProfileId('../../x;$(touch /tmp/x)')).toMatch(/^ms-session-[a-f0-9]{24}$/);
    expect(sessionProfileId('Work')).not.toBe(sessionProfileId('Other'));
    expect(() => sessionProfileId('\u001b[2J')).toThrow();
  });
  it('uses private pipes and the normal sandbox, never a debugging listener', () => {
    const args = browserArguments('/private/profile');
    expect(args).toContain('--remote-debugging-pipe');
    expect(args).toContain('--user-data-dir=/private/profile');
    expect(args.join(' ')).not.toMatch(/no-sandbox|remote-debugging-port|ignore-certificate/);
  });
  it('creates an owner-only profile and refuses concurrent use without deleting it', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'perch-ms-'));
    cleanups.push(() => rm(root, { recursive: true, force: true }));
    const profile = await openSessionProfile(root, 'Work');
    expect((await stat(profile.path)).mode & 0o777).toBe(0o700);
    await expect(openSessionProfile(root, 'Work')).rejects.toThrow(/already in use/);
    await profile.release();
    const resumed = await openSessionProfile(root, 'Work');
    expect(resumed.path).toBe(profile.path);
    await resumed.release();
  });
});

import { sessionInstructions, sessionResumeCommand } from '../src/cli/microsoftSession.js';
describe('Microsoft session instructions', () => {
  it('prints only four actionable steps and keeps troubleshooting out of the normal path', () => {
    const instructions = sessionInstructions('http://127.0.0.1:8783/#dummy', 'example-server');
    expect(instructions).toContain('ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8783:127.0.0.1:8783');
    expect(instructions).toContain('example-server');
    expect(instructions).toContain('http://127.0.0.1:8783/#dummy');
    expect(instructions.match(/^\d\./gm)).toHaveLength(4);
    expect(instructions).toContain('Finish sign-in');
    expect(instructions).toContain('Confirm access');
    expect(instructions).not.toMatch(/Passkey|Sandbox|Entra|DevTools|Ablauf|--session|Browserprofil|15 Minuten/);
    expect(instructions.split('\n').length).toBeLessThanOrEqual(15);
    expect(sessionInstructions('http://127.0.0.1:8783/#dummy')).toContain('Replace USER@SERVER with your SSH destination');
  });
  it('quotes the separate recovery command safely', () => {
    expect(sessionResumeCommand("x';$(false)", 8783, 'example-server')).toBe(`perch microsoft add --label 'x'"'"';$(false)' --port 8783 --ssh-host 'example-server'`);
  });
});

it('serializes an action whose body arrives while a screenshot is in progress', async () => {
  let release!: () => void;
  let entered!: () => void;
  const enteredPromise = new Promise<void>((r) => { entered = r; });
  const hold = new Promise<void>((r) => { release = r; });
  const { browser, calls } = mockBrowser();
  browser.snapshot = async () => { entered(); await hold; return { image: 'AA==', host: '' }; };
  const viewer = await startSessionViewer(browser, { port: 0, timeoutMs: 30_000 });
  cleanups.push(viewer.close);
  const u = new URL(viewer.url);
  const unlocked = await fetch(u.origin + '/unlock', { method: 'POST', headers: { Origin: u.origin }, body: JSON.stringify({ token: u.hash.slice(1) }) });
  const headers = { Origin: u.origin, Cookie: unlocked.headers.get('set-cookie')!.split(';')[0]! };
  let endBody!: () => void;
  const action = new Promise<number | undefined>((resolve, reject) => {
    const req = request(u.origin + '/action', { method: 'POST', headers }, (res) => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject);
    req.write('{"type":"text",');
    endBody = () => req.end('"text":"test"}');
  });
  await new Promise((r) => setTimeout(r, 20));
  const state = fetch(u.origin + '/state', { headers });
  await enteredPromise;
  endBody();
  const status = await action;
  release(); await state;
  expect(status).toBe(409);
  expect(calls).toEqual([]);
});

import { runInNewContext } from 'node:vm';
import { sessionPage } from '../src/microsoft/sessionPage.js';
it('forwards printable Mac Option and Windows AltGr characters without forwarding command shortcuts', async () => {
  const elements = new Map<string, any>();
  const actions: unknown[] = [];
  const element = (id: string) => {
    if (!elements.has(id)) elements.set(id, { addEventListener() {}, focus() {}, removeAttribute() {} });
    return elements.get(id);
  };
  const script = sessionPage('test').match(/<script nonce="test">([\s\S]*?)<\/script>/)![1]!;
  runInNewContext(script, {
    document: { getElementById: element, querySelectorAll: () => [] }, location: { hash: '' }, history: { replaceState() {} },
    setInterval() {}, setTimeout() {},
    fetch: async (url: string, options: any) => {
      if (url === '/action') actions.push(JSON.parse(options.body));
      return { ok: true, json: async () => ({ image: 'AA==', host: '', expires: Date.now() + 1000 }) };
    },
  });
  const press = (extra: object) => element('screen').onkeydown({ key: '@', metaKey: false, ctrlKey: false, altKey: false, preventDefault() {}, getModifierState: () => false, ...extra });
  press({ altKey: true });
  press({ altKey: true, ctrlKey: true, getModifierState: (key: string) => key === 'AltGraph' });
  press({ metaKey: true });
  await new Promise((r) => setImmediate(r));
  expect(actions).toEqual([{ type: 'text', text: '@@' }]);
});

import { runCli } from '../src/cli/run.js';
it('routes directly to session consent before store initialization and supports cancellation', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'perch-ms-cli-'));
  cleanups.push(() => rm(root, { recursive: true, force: true }));
  const prompts: string[] = [], answers = ['n'];
  let out = '', err = '';
  const result = await runCli(['microsoft', 'add', '--label', 'Work'], {
    env: { HOME: root, PERCH_DATA_DIR: path.join(root, 'data') }, stdoutIsTTY: true,
    stdout: (s) => { out += s; }, stderr: (s) => { err += s; }, readSecret: async () => { throw new Error('Unexpected secret prompt'); },
    readLine: async (p) => { prompts.push(p); const answer = answers.shift(); if (answer === undefined) throw new Error('Unexpected prompt'); return answer; },
  });
  expect(result).toBe(0); expect(err).toBe('');
  expect(prompts).toHaveLength(1);
  expect(prompts[0]).toBe('Start Microsoft sign-in? [y/N] ');
  expect(out).toMatch(/no browser started/);
  await expect(stat(path.join(root, 'data'))).rejects.toThrow();
});

it('reports a busy login port with a concrete remedy', async () => {
  const { base } = await fixture();
  await expect(startSessionViewer(mockBrowser().browser, { port: Number(new URL(base).port), timeoutMs: 1000 })).rejects.toThrow(/--port 8784/);
});
