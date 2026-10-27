// Guided public setup (docs/SIMPLE_CONNECT_SPEC.md §6, Nachtrag 2026-10-27): the "Web application" client
// guide and check, file permissions, the address suggestion and the .env edit, the closing checklist, the
// connect → setup hand-over and perch public status. MOCK data only; nothing leaves the machine.
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { base32Decode } from '../src/access/base32.js';
import { OAuthStore } from '../src/access/state.js';
import { hotp, totpStep } from '../src/access/totp.js';
import {
  checklistText,
  detectEnvFile,
  parseFunnelStatus,
  serviceCommand,
  suggestPublicBaseUrl,
  webClientGuideText,
} from '../src/cli/publicSetup.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { resolveConfig } from '../src/config.js';
import { validateWebClientJson } from '../src/google/clientSetup.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { GOOGLE, webClientJson } from './support/publicAccessFixtures.js';

const TAILNET = 'server.tailnet-test.ts.net';
const PUB = `https://${TAILNET}:10000`;
const REDIRECT = `${PUB}/oauth/google/callback`;
const SED = "sed -i 's#serve --http$#serve --http --public#' ~/.config/systemd/user/perch.service && systemctl --user daemon-reload && systemctl --user restart perch";
const UNIT = `[Unit]\nDescription=Perch MCP server\n\n[Service]\nExecStart=/usr/bin/node --env-file=/home/example/perch/.env /home/example/perch/dist/cli.js serve --http\n\n[Install]\nWantedBy=default.target\n`;

/** Lines over 80 columns are allowed only when they carry a URL, a path or a command to copy. */
const overlong = (text: string) =>
  text
    .split('\n')
    .filter((l) => [...l].length > 80)
    .filter((l) => !/:\/\//.test(l) && !/^\s+(sudo|sed|perch|curl|systemctl|PERCH_)/.test(l) && !/^\s+(to )?\/\S+/.test(l) && !/\s\/\S+$/.test(l));

let dirs: TempDirs;
let env: Record<string, string>;
let closers: Server[];

beforeEach(async () => {
  dirs = await makeTempDirs();
  closers = [];
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  env = {
    PERCH_DATA_DIR: dirs.dataDir,
    PERCH_KEY_FILE: dirs.keyFile,
    PERCH_HTTP_TOKEN_FILE: dirs.tokenFile,
    PERCH_ALLOWED_HOSTS: TAILNET,
    PERCH_PUBLIC_BASE_URL: PUB,
    // A port nothing listens on (the public listener is "not running").
    PERCH_PUBLIC_PORT: '1',
    HOME: dirs.root,
  };
});
afterEach(async () => {
  for (const s of closers) await new Promise((r) => s.close(r));
  await dirs.cleanup();
});

type Answer = (prompt: string, out: string) => string;
type TestIo = CliIo & { out: () => string; prompts: string[]; pastes: number };

function io(answer: Answer, pastes: string[] = [], extra: Partial<CliIo> = {}): TestIo {
  let out = '';
  const prompts: string[] = [];
  const t: TestIo = {
    env,
    stdout: (s) => (out += s),
    stderr: (s) => (out += s),
    readSecret: async () => '',
    readLine: async (p) => {
      prompts.push(p);
      out += p;
      const a = answer(p, out);
      out += `${a}\n`;
      return a;
    },
    readSecretJson: async (p) => {
      out += `${p}\n`;
      t.pastes++;
      const next = pastes.shift();
      if (next === undefined) throw new Error('no more pastes');
      return next;
    },
    funnelStatus: async () => '',
    out: () => out,
    prompts,
    pastes: 0,
    ...extra,
  };
  return t;
}

/** The answers of an operator who says yes, presses Enter, and types the current TOTP code. */
const operator =
  (email = 'example@example.test'): Answer =>
  (p, out) => {
    if (/Google account \(email\)/.test(p)) return email;
    if (/6-digit code/.test(p)) {
      const key = /enter this key by hand: ([A-Z2-7 ]+)/.exec(out)![1]!.replace(/ /g, '');
      return hotp(base32Decode(key), totpStep(Date.now()));
    }
    return '';
  };

const loginFile = () => path.join(dirs.root, '.config', 'perch', 'google-web-client.json');

async function writeUnit(text = UNIT) {
  await mkdir(path.join(dirs.root, '.config', 'systemd', 'user'), { recursive: true });
  await writeFile(path.join(dirs.root, '.config', 'systemd', 'user', 'perch.service'), text);
}

async function oauthState() {
  return new OAuthStore(await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile })).read();
}

describe('the "Web application" client check', () => {
  it('accepts the downloaded JSON with the exact redirect URI', () => {
    const c = validateWebClientJson(webClientJson(PUB), REDIRECT);
    expect(c.clientId).toBe(GOOGLE.clientId);
    expect(JSON.parse(c.json).web.redirect_uris).toEqual([REDIRECT]);
  });

  it('refuses a Desktop client, names a missing redirect URI and never repeats the secret', () => {
    const desktop = JSON.stringify({ installed: { client_id: GOOGLE.clientId, client_secret: GOOGLE.clientSecret, redirect_uris: ['http://localhost'] } });
    const errs = [
      [desktop, /"Desktop app" client .* "Web application"/],
      [webClientJson(PUB, ['https://other.example.test/oauth/google/callback']), new RegExp(`redirect_uris lacks ${REDIRECT.replace(/[.]/g, '\\.')}`)],
      [webClientJson(PUB, []), /redirect_uris lacks/],
      [JSON.stringify({ web: { client_id: 'nope', client_secret: GOOGLE.clientSecret, redirect_uris: [REDIRECT] } }), /client_id must end with \.apps\.googleusercontent\.com/],
      [JSON.stringify({ web: { client_id: GOOGLE.clientId, redirect_uris: [REDIRECT] } }), /client_secret is missing/],
      [JSON.stringify({ other: {} }), /the "web" key/],
      ['{"web": {', /not valid JSON/],
      ['', /nothing was pasted/],
    ] as const;
    for (const [text, want] of errs) {
      let msg = '';
      try {
        validateWebClientJson(text, REDIRECT);
      } catch (err) {
        msg = (err as Error).message;
      }
      expect(msg).toMatch(want);
      expect(msg).not.toContain(GOOGLE.clientSecret);
    }
  });

  it('the guide names the console, the client type, the exact redirect URI and the scopes', () => {
    const t = webClientGuideText(PUB);
    expect(t).toContain('https://console.cloud.google.com/auth/clients');
    expect(t).toContain('"Web application"');
    expect(t).toContain(`       ${REDIRECT}\n`);
    expect(t).toMatch(/openid and email/);
    expect(t).toMatch(/Test users/);
    expect(overlong(t)).toEqual([]);
  });
});

describe('address, env file, Funnel and checklist helpers', () => {
  it('suggests port 10000 when the private address uses 443, else 443', () => {
    expect(suggestPublicBaseUrl(resolveConfig({ PERCH_ALLOWED_HOSTS: `127.0.0.1,${TAILNET}` }))).toBe(PUB);
    expect(suggestPublicBaseUrl(resolveConfig({ PERCH_ALLOWED_HOSTS: TAILNET, PERCH_PRIVATE_OAUTH: 'off' }))).toBe(`https://${TAILNET}`);
    expect(suggestPublicBaseUrl(resolveConfig({ PERCH_ALLOWED_HOSTS: 'localhost' }))).toBeUndefined();
  });

  it('finds the env file of node --env-file, else PERCH_ENV_FILE', () => {
    expect(detectEnvFile(['--env-file=/srv/perch/.env'], {})).toBe('/srv/perch/.env');
    expect(detectEnvFile(['--env-file', '/a/.env', '--env-file-if-exists=/b/.env'], {})).toBe('/b/.env');
    expect(detectEnvFile([], { PERCH_ENV_FILE: '/c/.env' })).toBe('/c/.env');
    expect(detectEnvFile(['--no-warnings'], {})).toBeUndefined();
  });

  it('reads tailscale funnel status', () => {
    const on = `# Funnel on:\n#     - ${PUB}\n\n${PUB} (Funnel on)\n|-- / proxy http://127.0.0.1:8767\n`;
    expect(parseFunnelStatus(on, PUB, 8767)).toBe('on');
    expect(parseFunnelStatus(on, PUB, 9999)).toBe('wrong_target');
    expect(parseFunnelStatus(`https://${TAILNET} (tailnet only)\n|-- / proxy http://127.0.0.1:8765\n`, PUB, 8767)).toBe('off');
    expect(parseFunnelStatus(undefined, PUB, 8767)).toBe('unknown');
  });

  it('the checklist prints the exact commands', () => {
    const t = checklistText({ origin: PUB, publicPort: 8767, unit: { shown: '~/.config/systemd/user/perch.service', hasPublic: false, sedable: true }, restartNeeded: true, listener: false, funnel: 'off' });
    expect(t).toContain(`         ${SED}\n`);
    expect(t).toContain('         sudo tailscale funnel --bg --https=10000 http://127.0.0.1:8767\n');
    expect(t).toContain(`         curl -s ${PUB}/.well-known/oauth-authorization-server\n`);
    expect(t).toContain('         perch connect --target claude-ai\n');
    expect(overlong(t)).toEqual([]);
    expect(serviceCommand(undefined).command).toBe('perch serve --http --public');
    expect(serviceCommand({ shown: 'x', hasPublic: true, sedable: false }).command).toBe('systemctl --user restart perch');
    expect(serviceCommand({ shown: '/etc/u', hasPublic: false, sedable: false }).why).toMatch(/add --public/);
    const done = checklistText({ origin: PUB, publicPort: 8767, restartNeeded: false, listener: true, funnel: 'on' });
    expect(done).toMatch(/☑ 1\. Perch runs with the public listener/);
    expect(done).toMatch(/☑ 2\. Tailscale Funnel serves port 10000/);
    expect(done).not.toContain('sudo tailscale');
  });
});

describe('perch public setup', () => {
  it("guides a new operator through: client, account, Perch code, checklist", async () => {
    await writeUnit();
    const desktop = JSON.stringify({ installed: { client_id: GOOGLE.clientId, client_secret: GOOGLE.clientSecret, redirect_uris: ['http://localhost'] } });
    const t = io(operator(), [desktop, webClientJson(PUB, ['https://wrong.example.test/cb']), webClientJson(PUB)], { env: { ...env, PERCH_PUBLIC_PORT: '8767' } });
    expect(await runCli(['public', 'setup'], t)).toBe(0);
    const out = t.out();
    expect(out).toContain('Step 1/4 - Public address');
    expect(out).toContain(`MCP endpoint: ${PUB}/mcp`);
    expect(out).toMatch(/No usable Google sign-in client at\s+\S+google-web-client\.json\s+\(it\s+does\s+not\s+exist\s+yet\)/);
    expect(out).toContain(`       ${REDIRECT}\n`);
    expect(out).toMatch(/"Desktop app" client .* Try again/s);
    expect(out).toMatch(/redirect_uris lacks/);
    expect(t.pastes).toBe(3);
    expect((await stat(loginFile())).mode & 0o777).toBe(0o600);
    expect(JSON.parse(await readFile(loginFile(), 'utf8')).web.client_id).toBe(GOOGLE.clientId);
    const s = await oauthState();
    expect(s.loginAllow.map((e) => e.email)).toEqual(['example@example.test']);
    expect(s.totp).toBeTruthy();
    expect(out).toContain(`         ${SED}\n`);
    expect(out).toContain('         sudo tailscale funnel --bg --https=10000 http://127.0.0.1:8767\n');
    expect(out).toContain(`         curl -s ${PUB}/.well-known/oauth-authorization-server\n`);
    expect(out).toContain('         perch connect --target claude-ai\n');
    expect(out).not.toContain(GOOGLE.clientSecret);
    expect(overlong(out.replace(/^\s*(█|▀|▄| )+$/gm, ''))).toEqual([]);
    // A second run finds everything in place and only prints the checklist.
    const again = io(operator(), []);
    expect(await runCli(['public', 'setup'], again)).toBe(0);
    expect(again.pastes).toBe(0);
    expect(again.out()).toMatch(/OK: 12345678…cdef\.apps\.googleusercontent\.com/);
    expect(again.out()).toContain('Allowed: example@example.test');
    expect(again.out()).toContain('Already set up');
  });

  it('stores the client at PERCH_GOOGLE_LOGIN_CLIENT_FILE when set, and stops after three bad pastes', async () => {
    const file = path.join(dirs.root, 'custom', 'login.json');
    env.PERCH_GOOGLE_LOGIN_CLIENT_FILE = file;
    const bad = io(operator(), ['{', '{', '{']);
    const err = await rejection(runCli(['public', 'setup'], bad).then((c) => (c === 0 ? undefined : Promise.reject(new Error(bad.out())))));
    expect(err.message).toMatch(/not valid JSON/);
    const ok = io(operator(), [webClientJson(PUB)]);
    expect(await runCli(['public', 'setup'], ok)).toBe(0);
    expect((await stat(file)).mode & 0o777).toBe(0o600);
    expect(ok.out()).not.toMatch(/nothing to add to \.env/);
  });

  it('suggests the address, and writes it to the env file only after y', async () => {
    delete env.PERCH_PUBLIC_BASE_URL;
    const envFile = path.join(dirs.root, 'perch.env');
    await writeFile(envFile, 'PERCH_ALLOWED_HOSTS=server.tailnet-test.ts.net\nPERCH_PUBLIC_BASE_URL=\n', { mode: 0o600 });
    const no = io((p, o) => (/Add it to this file/.test(p) ? 'n' : operator()(p, o)), [webClientJson(PUB)], { envFile });
    expect(await runCli(['public', 'setup'], no)).toBe(0);
    expect(no.prompts).toContain(`  Public address [${PUB}]: `);
    expect(no.out()).toMatch(/Port 443 already serves your private address/);
    expect(await readFile(envFile, 'utf8')).toBe('PERCH_ALLOWED_HOSTS=server.tailnet-test.ts.net\nPERCH_PUBLIC_BASE_URL=\n');
    expect(no.out()).toContain(`      PERCH_PUBLIC_BASE_URL=${PUB}\n`);
    const y = io((p, o) => (/Add it to this file/.test(p) ? 'y' : operator()(p, o)), [], { envFile });
    expect(await runCli(['public', 'setup'], y)).toBe(0);
    expect(await readFile(envFile, 'utf8')).toBe(`PERCH_ALLOWED_HOSTS=server.tailnet-test.ts.net\nPERCH_PUBLIC_BASE_URL=${PUB}\n`);
    expect((await stat(envFile)).mode & 0o777).toBe(0o600);
    expect(y.out()).toContain(`  Your env file:\n  ${envFile}\n  The line for it:\n      PERCH_PUBLIC_BASE_URL=${PUB}\n  Add it to this file now? [y/N] y\n  Saved.\n`);
    // The service has to be restarted to read the new address.
    expect(y.out()).toContain('      perch serve --http --public\n');
  });

  it('without a known env file it prints the line; a bad port is refused', async () => {
    delete env.PERCH_PUBLIC_BASE_URL;
    const answers = ['https://server.tailnet-test.ts.net:9000', `https://${TAILNET}`, 'https://server.tailnet-test.ts.net:8443'];
    const t = io((p, o) => (/Public address/.test(p) ? answers.shift()! : operator()(p, o)), [webClientJson('https://server.tailnet-test.ts.net:8443')]);
    expect(await runCli(['public', 'setup'], t)).toBe(0);
    expect(t.out()).toMatch(/Funnel serves only the ports 443, 8443, 10000\. Try again/);
    expect(t.out()).toMatch(/This is your private address/);
    expect(t.out()).toMatch(/started without --env-file/);
    expect(t.out()).toContain('      PERCH_PUBLIC_BASE_URL=https://server.tailnet-test.ts.net:8443\n');
    expect(t.out()).toContain('--https=8443 http://127.0.0.1:1');
    expect(t.prompts.some((p) => /Add it to this file/.test(p))).toBe(false);
  });

  it('needs a terminal', async () => {
    const t = io(operator());
    delete t.readLine;
    expect(await runCli(['public', 'setup'], t)).not.toBe(0);
    expect(t.out()).toMatch(/interactive terminal/);
  });
});

describe('perch connect → perch public setup', () => {
  it('offers the setup right away and ends with the connect command of the target', async () => {
    const no = io(() => 'n');
    expect(await runCli(['connect', '--target', 'claude-ai'], no)).toBe(1);
    expect(no.out()).toMatch(/No usable Google sign-in client/);
    expect(no.out()).toContain('  perch public setup\n');
    expect(no.out()).toContain('  perch connect --target claude-ai\n');
    const t = io(operator(), [webClientJson(PUB)]);
    expect(await runCli(['connect', '--target', 'chatgpt'], t)).toBe(0);
    expect(t.prompts[0]).toBe('Set it up now? [Y/n] ');
    expect(t.prompts.filter((p) => /Set it up now/.test(p))).toHaveLength(1);
    expect(t.out()).toContain('Step 4/4 - Perch code');
    expect(t.out()).toContain('         perch connect --target chatgpt\n');
    expect(overlong(t.out().replace(/^\s*(█|▀|▄| )+$/gm, ''))).toEqual([]);
  });
});

describe('perch public status', () => {
  it('shows one box per requirement with the command that fixes it', async () => {
    await writeUnit();
    const before = io(() => '');
    expect(await runCli(['public', 'status'], before)).toBe(0);
    const o = before.out();
    expect(o).toMatch(/☑ Public address +https:\/\/server\.tailnet-test\.ts\.net:10000/);
    expect(o).toMatch(/☐ Google sign-in client +not found:\s+\S+google-web-client\.json\n {6}perch public setup/);
    expect(o).toMatch(/☐ Allowed Google account +none\n {6}perch oauth login-allow add/);
    expect(o).toMatch(/☐ Perch code \(TOTP\) +not set up\n {6}perch oauth totp setup/);
    expect(o).toContain(`☐ Public listener         not running on 127.0.0.1:1\n      ${SED.replace('8767', '1')}`);
    expect(o).toContain('☐ Tailscale Funnel        port 10000 is not open\n      sudo tailscale funnel --bg --https=10000 http://127.0.0.1:1');
    expect(overlong(o)).toEqual([]);

    expect(await runCli(['public', 'setup'], io(operator(), [webClientJson(PUB)]))).toBe(0);
    // A running public listener (stand-in) and an open Funnel.
    const server = createServer((req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(req.url === '/.well-known/oauth-authorization-server' && req.headers.host === `${TAILNET}:10000` ? { issuer: PUB } : {}));
    });
    closers.push(server);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as { port: number }).port;
    env.PERCH_PUBLIC_PORT = String(port);
    const after = io(() => '', [], { funnelStatus: async () => `${PUB} (Funnel on)\n|-- / proxy http://127.0.0.1:${port}\n` });
    expect(await runCli(['public', 'status'], after)).toBe(0);
    const a = after.out();
    for (const label of ['Public address', 'Google sign-in client', 'Allowed Google account', 'Perch code (TOTP)', 'Public listener', 'Tailscale Funnel']) expect(a).toContain(`☑ ${label}`);
    expect(a).not.toContain('☐');
    expect(a).toContain('Pairing: possible');
    expect(a).not.toContain(GOOGLE.clientSecret);
  });

  it('without an address it says so', async () => {
    delete env.PERCH_PUBLIC_BASE_URL;
    const t = io(() => '', [], { funnelStatus: async () => undefined });
    expect(await runCli(['public', 'status'], t)).toBe(0);
    expect(t.out()).toMatch(/☐ Public address +not set \(PERCH_PUBLIC_BASE_URL\)\n {6}perch public setup/);
  });
});
