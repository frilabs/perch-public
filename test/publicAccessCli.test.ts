// CLI and wiring of the public access (docs/PUBLIC_ACCESS_SPEC.md §10, §12 items 10, 15, 18): TOTP setup,
// login allowlist, a full `perch oauth pair` over the control socket (with the first-use check), revocation,
// the kill switch, control-socket checks and the local pairing page. MOCK Google and MOCK client metadata
// only; nothing leaves the machine.
import { chmod, mkdir, symlink, rm } from 'node:fs/promises';
import { request } from 'node:http';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { base32Decode } from '../src/access/base32.js';
import { connectControl, controlSocketPath } from '../src/access/control.js';
import { startPublicAccess, type PublicAccess } from '../src/access/runtime.js';
import { OAuthStore } from '../src/access/state.js';
import { hotp, totpStep } from '../src/access/totp.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { createPerchContext } from '../src/context.js';
import { generateHttpToken, startHttpServer, type RunningHttpServer } from '../src/mcp/http.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream, type UpstreamTransport } from '../src/upstream.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { authorizeUrl, BASE, CLAUDE_CALLBACK, cookieFrom, csrfOf, form, GOOGLE, HOSTED_CIMD, HOST, idToken, OPERATOR, pkce, waitFor } from './support/publicAccessFixtures.js';

let dirs: TempDirs;
let env: Record<string, string>;
let store: CredentialStore;
let google: { nonce?: string };
let transport: UpstreamTransport;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  env = { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, PERCH_PUBLIC_BASE_URL: BASE, HOME: dirs.root };
  google = {};
  transport = async (req) => {
    const json = (status: number, body: unknown) => ({ status, headers: {}, body: Buffer.from(JSON.stringify(body)) });
    if (req.url.origin === 'https://oauth2.googleapis.com') {
      const t = Math.floor(Date.now() / 1000);
      return json(200, { id_token: idToken({ iss: 'https://accounts.google.com', aud: GOOGLE.clientId, sub: OPERATOR.sub, email: OPERATOR.email, email_verified: true, iat: t, exp: t + 3600, nonce: google.nonce }) });
    }
    if (`${req.url.origin}${req.url.pathname}` === HOSTED_CIMD) return json(200, { client_id: HOSTED_CIMD, client_name: 'Claude', redirect_uris: [CLAUDE_CALLBACK] });
    if (req.url.origin === 'https://api.telegram.org') return json(200, { ok: true });
    return json(404, {});
  };
});
afterEach(async () => {
  await dirs.cleanup();
});

function cliIo(answers: (prompt: string, out: string) => string): CliIo & { out: () => string; err: () => string } {
  let out = '';
  let err = '';
  return {
    env,
    stdout: (s) => (out += s),
    stderr: (s) => (err += s),
    readSecret: async () => '',
    readLine: async (prompt) => answers(prompt, out),
    transport,
    out: () => out,
    err: () => err,
  };
}

/** Reads the manual key from the setup output and answers with the current code. */
const totpAnswer = (_prompt: string, out: string) => {
  const key = /enter this key by hand: ([A-Z2-7 ]+)/.exec(out)![1]!.replace(/ /g, '');
  return hotp(base32Decode(key), totpStep(Date.now()));
};

async function setUp() {
  expect(await runCli(['oauth', 'login-allow', 'add', OPERATOR.email], cliIo(() => ''))).toBe(0);
  const io = cliIo(totpAnswer);
  expect(await runCli(['oauth', 'totp', 'setup'], io), io.err()).toBe(0);
  return io;
}

function http(port: number, method: string, p: string, o: { body?: string; cookie?: string; headers?: Record<string, string>; host?: string } = {}) {
  return new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string; location?: string }>((resolve, reject) => {
    const headers: Record<string, string> = { host: o.host ?? HOST, ...(o.headers ?? {}) };
    if (o.cookie) headers.cookie = o.cookie;
    if (o.body !== undefined) {
      headers['content-type'] ??= 'application/x-www-form-urlencoded';
      headers['content-length'] = String(Buffer.byteLength(o.body));
    }
    const req = request({ host: '127.0.0.1', port, method, path: p, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), ...(res.headers.location ? { location: res.headers.location } : {}) }));
    });
    req.on('error', reject);
    if (o.body !== undefined) req.write(o.body);
    req.end();
  });
}

describe('perch oauth totp / login-allow', () => {
  it('sets up the Perch code from a terminal QR code and prints recovery codes once', async () => {
    const io = await setUp();
    expect(io.out()).toMatch(/Scan this QR code/);
    expect(io.out()).toMatch(/[█▀▄]/);
    expect((io.out().match(/^ {2}[A-Z2-7]{5}-[A-Z2-7]{5}$/gm) ?? []).length).toBe(10);
    const s = await new OAuthStore(store).read();
    expect(s.totp?.recovery).toHaveLength(10);
    expect(JSON.stringify(s)).not.toContain(io.out().match(/^ {2}([A-Z2-7]{5})-/m)![1]);
    const list = cliIo(() => '');
    await runCli(['oauth', 'login-allow', 'list'], list);
    expect(list.out()).toContain(OPERATOR.email);
  });

  it('refuses a wrong confirmation code three times and changes nothing', async () => {
    const io = cliIo(() => '000000');
    expect(await runCli(['oauth', 'totp', 'setup'], io)).toBe(1);
    expect((await new OAuthStore(store).read()).totp).toBeUndefined();
  });
});

describe('perch oauth pair (end to end over the control socket)', () => {
  let access: PublicAccess;
  beforeEach(async () => {
    await setUp();
    access = await startPublicAccess({
      baseUrl: BASE,
      port: 0,
      context: createPerchContext(store, transport),
      upstream: new Upstream(transport),
      googleClient: GOOGLE,
      dcrEnabled: true,
      trustForwarded: false,
      log: () => {},
    });
  });
  afterEach(async () => {
    await access.close();
  });

  async function browser(pairingCode: string) {
    const port = access.publicServer.port;
    const { verifier, challenge } = pkce();
    const a = await http(port, 'GET', authorizeUrl({ challenge }));
    const cookie = cookieFrom(a)!;
    const p = await http(port, 'GET', '/oauth/pair', { cookie });
    const g = await http(port, 'POST', '/oauth/pair', { cookie, body: form({ csrf: csrfOf(p.body), code: pairingCode }) });
    const gu = new URL(g.location!);
    google.nonce = gu.searchParams.get('nonce')!;
    await http(port, 'GET', `/oauth/google/callback?state=${encodeURIComponent(gu.searchParams.get('state')!)}&code=google-code-0123456789`, { cookie });
    const t = await http(port, 'GET', '/oauth/totp', { cookie });
    const secret = Buffer.from((await new OAuthStore(store).read()).totp!.secret, 'base64');
    await http(port, 'POST', '/oauth/totp', { cookie, body: form({ csrf: csrfOf(t.body), code: hotp(secret, totpStep(Date.now()) + 1) }) });
    return { cookie, verifier };
  }

  it('pairs one device after the terminal confirmation and reports its first request', async () => {
    const prompts: string[] = [];
    const io = cliIo((prompt) => {
      prompts.push(prompt);
      return /\[f\]ull/.test(prompt) ? 'f' : 'y';
    });
    const run = runCli(['oauth', 'pair'], io);
    await waitFor(() => /Pairing code: {2}([A-Z2-7]{8})/.test(io.out()));
    const code = /Pairing code: {2}([A-Z2-7]{8})/.exec(io.out())![1]!;
    const { cookie, verifier } = await browser(code);
    await waitFor(() => io.out().includes('Paired device'));
    expect(prompts[0]).toMatch(/Pair this device\?/);
    expect(prompts[1]).toMatch(/\[r\]ead only, or \[f\]ull/);
    expect(io.out()).toContain(`Google account:  ${OPERATOR.email}`);
    expect(io.out()).toContain('Returns to:      claude.ai');
    const port = access.publicServer.port;
    const w = await http(port, 'GET', '/oauth/wait', { cookie });
    const authCode = new URL(w.location!).searchParams.get('code')!;
    const tok = JSON.parse(
      (await http(port, 'POST', '/oauth/token', { body: form({ grant_type: 'authorization_code', code: authCode, redirect_uri: CLAUDE_CALLBACK, client_id: HOSTED_CIMD, code_verifier: verifier }) })).body,
    );
    const mcp = await http(port, 'POST', '/mcp', {
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${tok.access_token}` },
    });
    expect(mcp.status).toBe(200);
    expect(await run).toBe(0);
    expect(io.out()).toMatch(/First request from oc-[a-f0-9]{16} received/);

    // devices, revoke, kill switch
    const list = cliIo(() => '');
    await runCli(['oauth', 'devices'], list);
    const id = /(oc-[a-f0-9]{16}) {2}active/.exec(list.out())![1]!;
    // "f" at pairing gave the device a full-access grant (every capability, every account).
    expect(list.out()).toMatch(/grant client-[a-f0-9]{8}/);
    const grantId = /grant (client-[a-f0-9]{8})/.exec(list.out())![1]!;
    expect((await store.read()).clients.find((c) => c.id === grantId)).toMatchObject({ full: true });
    // Removing a grant would widen a device to reading every account: only with an explicit --read-all.
    const narrow = cliIo(() => '');
    expect(await runCli(['oauth', 'ungrant', id], narrow)).toBe(1);
    expect(narrow.err()).toMatch(/READ EVERY connected account[\s\S]*perch oauth revoke/);
    const wide = cliIo(() => '');
    expect(await runCli(['oauth', 'ungrant', id, '--read-all'], wide)).toBe(0);
    expect(wide.out()).toMatch(/can read every connected account and write nothing/);
    expect(await runCli(['oauth', 'revoke', id], cliIo(() => ''))).toBe(0);
    const after = await http(port, 'POST', '/mcp', { body: '{}', headers: { 'content-type': 'application/json', authorization: `Bearer ${tok.access_token}` } });
    expect(after.status).toBe(401);
    const off = cliIo(() => '');
    expect(await runCli(['public', 'off'], off)).toBe(0);
    expect(off.out()).toContain('Public access is OFF');
    expect((await http(port, 'POST', '/oauth/token', { body: form({ grant_type: 'refresh_token', refresh_token: tok.refresh_token }) })).status).toBe(503);
    const pairAgain = cliIo(() => 'y');
    expect(await runCli(['oauth', 'pair'], pairAgain)).toBe(1);
    expect(pairAgain.err()).toMatch(/switched off/);
    expect(await runCli(['public', 'on'], cliIo(() => ''))).toBe(0);
    const status = cliIo(() => '');
    await runCli(['public', 'status'], status);
    expect(status.out()).toContain('Pairing: possible');
  });

  it('closes the window without pairing when the operator answers no', async () => {
    const io = cliIo(() => 'n');
    const run = runCli(['oauth', 'pair'], io);
    await waitFor(() => /Pairing code: {2}([A-Z2-7]{8})/.test(io.out()));
    await browser(/Pairing code: {2}([A-Z2-7]{8})/.exec(io.out())![1]!);
    expect(await run).toBe(1);
    expect(io.err()).toMatch(/closed \(rejected\)/);
    expect((await new OAuthStore(store).read()).devices).toEqual([]);
  });

  it('18: the client refuses a control socket with wrong permissions or a symlink', async () => {
    const file = controlSocketPath(dirs.dataDir);
    await chmod(file, 0o666);
    expect((await rejection(connectControl(dirs.dataDir))).message).toMatch(/accessible by other users/);
    await chmod(file, 0o600);
    const other = path.join(dirs.root, 'other.sock');
    await rm(file);
    await mkdir(path.dirname(other), { recursive: true });
    await symlink(other, file);
    expect((await rejection(connectControl(dirs.dataDir))).message).toMatch(/not a socket/);
  });

  it('the local pairing page has its own password (never the global token) and needs a same-origin form', async () => {
    const token = generateHttpToken();
    const server: RunningHttpServer = await startHttpServer({ host: '127.0.0.1', port: 0, token, context: createPerchContext(store, transport), localPair: access.localPair, log: () => {} });
    try {
      const port = server.port;
      const local = { host: `127.0.0.1:${port}` };
      const basicOf = (pw: string) => `Basic ${Buffer.from(`perch:${pw}`).toString('base64')}`;
      expect((await http(port, 'GET', '/local/pair', { ...local, headers: { authorization: basicOf(token) } })).status).toBe(404); // disabled
      const en = cliIo(() => '');
      expect(await runCli(['oauth', 'local-page', 'enable'], en)).toBe(0);
      const password = /Password \(any user name; shown once, a new enable replaces it\): (\S+)/.exec(en.out())![1]!;
      expect((await http(port, 'GET', '/local/pair', local)).status).toBe(401);
      expect((await http(port, 'GET', '/local/pair', { ...local, headers: { authorization: basicOf(token) } })).status).toBe(401); // global token: no
      expect((await http(port, 'GET', '/local/pair', { ...local, headers: { authorization: `Bearer ${token}` } })).status).toBe(401);
      const basic = basicOf(password);
      const page = await http(port, 'GET', '/local/pair', { ...local, headers: { authorization: basic } });
      expect(page.status).toBe(200);
      expect(page.body).toContain('Open a window for the public address');
      expect((await http(port, 'GET', '/local/pair', { ...local, headers: { authorization: basic, 'sec-fetch-site': 'cross-site' } })).status).toBe(403);
      const bad = await http(port, 'POST', '/local/pair', { ...local, body: form({ csrf: 'nope', action: 'open' }), headers: { authorization: basic, origin: `http://127.0.0.1:${port}` } });
      expect(bad.status).toBe(403);
      // Approve without an own window is refused (never blind on a terminal's window).
      access.pairing.open(() => {});
      const blind = await http(port, 'POST', '/local/pair', { ...local, body: form({ csrf: csrfOf(page.body), action: 'approve' }), headers: { authorization: basic, origin: `http://127.0.0.1:${port}` } });
      expect(blind.status).toBe(303);
      expect(access.pairing.isOpen).toBe(true);
      access.pairing.close('aborted');
      const page2 = await http(port, 'GET', '/local/pair', { ...local, headers: { authorization: basic } });
      const open = await http(port, 'POST', '/local/pair', { ...local, body: form({ csrf: csrfOf(page2.body), action: 'open' }), headers: { authorization: basic, origin: `http://127.0.0.1:${port}` } });
      expect(open.status).toBe(303);
      const shown = await http(port, 'GET', '/local/pair', { ...local, headers: { authorization: basic } });
      expect(shown.body).toMatch(/class="mono code">[A-Z2-7]{8}</);
      expect(access.pairing.isOpen).toBe(true);
      expect((await http(port, 'POST', '/local/pair', { ...local, body: form({ csrf: csrfOf(shown.body), action: 'open' }), headers: { authorization: basic, origin: 'https://evil.example' } })).status).toBe(403);
    } finally {
      await server.close();
    }
  });

  it('perch public off closes an open window within seconds', async () => {
    const events: string[] = [];
    access.pairing.open((ev) => events.push(ev.type === 'closed' ? `closed:${ev.reason}` : ev.type));
    expect(await runCli(['public', 'off'], cliIo(() => ''))).toBe(0);
    await waitFor(() => events.includes('closed:kill_switch'), 5000);
  });

  it('a malformed control message does not crash the server', async () => {
    const ctl = await connectControl(dirs.dataDir);
    ctl.socket.write('null\n');
    ctl.socket.write('42\n');
    const msgs: Array<Record<string, unknown>> = [];
    ctl.onMessage((m) => msgs.push(m));
    await waitFor(() => msgs.length >= 2);
    expect(msgs.every((m) => m.type === 'error')).toBe(true);
    ctl.socket.end();
  });

  it('perch status shows the public access without secrets', async () => {
    const io = cliIo(() => '');
    await runCli(['status', '--no-check', '--plain'], io);
    expect(io.out()).toMatch(/Public access: set up · Perch code set up · 1 allowed Google account\(s\) · 0 active device\(s\)/);
    const fancy = cliIo(() => '');
    await runCli(['status', '--no-check'], fancy);
    expect(fancy.out()).toMatch(/☑ public access \(OAuth for claude\.ai, ChatGPT …\) +on\n {4}Perch code set up · 1 allowed Google account\(s\) · 0 active device\(s\)/);
  });
});
