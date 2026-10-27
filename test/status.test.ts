// `perch status` and the read-only /status page against MOCK upstream worlds (Drive, Notion, Gmail, Graph,
// Calendar/Contacts, plus MOCK Slack and GOWA). IMAP/SMTP logins are MOCK checks. Nothing
// reaches a real provider; every secret is generated dummy data.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant } from '../src/auth/grants.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { generateHttpToken, startHttpServer, type RunningHttpServer } from '../src/mcp/http.js';
import { addSlackWorkspace } from '../src/slack/slack.js';
import { renderStatusPage, STATUS_STYLE_HASH } from '../src/status/page.js';
import { collectStatus, formatStatusText } from '../src/status/status.js';
import { CredentialStore, initStore, type ImapAccount } from '../src/store/credentialStore.js';
import { Upstream, type UpstreamTransport } from '../src/upstream.js';
import { pairWhatsappAccount, setWhatsappInstance } from '../src/whatsapp/whatsapp.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockGowa } from './support/mockGowa.js';
import { MockSlack } from './support/mockSlack.js';
import { createWorld, IDS, seedWorld, worldContext, worldTransport, type IoLog, type World } from './support/worldFixtures.js';

let dirs: TempDirs;
let rootStore: CredentialStore;
let io: IoLog;
let worlds: Map<string, World>;
let ROOT: World;
let slack: MockSlack;
let gowa: MockGowa;
let imapChecks: string[];
let server: RunningHttpServer | undefined;

/** Root world plus MOCK Slack (by origin) and MOCK GOWA (loopback origin). */
const transportFor = (w: World): UpstreamTransport => {
  const base = worldTransport(w, io);
  return (req) => {
    if (req.url.origin === 'https://slack.com') return slack.transport(req);
    if (req.url.origin === gowa.origin) return gowa.transport(req);
    return base(req);
  };
};
const imapVerify = async (a: ImapAccount) => {
  imapChecks.push(a.id);
  if (a.label.includes('BROKEN')) throw new Error('MOCK: login failed with secret details');
};
const secretsOf = async (store: CredentialStore) => {
  const d = await store.read();
  return [
    ...d.google.flatMap((a) => [a.refreshToken, a.clientSecret]),
    ...d.notion.map((w) => w.token),
    ...d.gmail.map((a) => a.refreshToken),
    ...d.microsoft.map((a) => a.refreshToken),
    ...d.imap.map((a) => a.password),
    ...d.googleProductivity.map((a) => a.refreshToken),
    ...d.slack.map((w) => w.token),
    ...(d.whatsappInstance ? [d.whatsappInstance.password] : []),
  ];
};

beforeEach(async () => {
  dirs = await makeTempDirs();
  io = [];
  imapChecks = [];
  worlds = new Map();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  rootStore = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  ROOT = createWorld('ROOT', io);
  worlds.set('root', ROOT);
  await seedWorld(rootStore, ROOT);
  slack = new MockSlack();
  gowa = new MockGowa();
  const up = new Upstream(transportFor(ROOT));
  const team = slack.addTeam('A');
  await addSlackWorkspace(store(), up, { label: 'Company', token: team.token });
  const revoked = slack.addTeam('Gone');
  await addSlackWorkspace(store(), up, { label: 'Old workspace', token: revoked.token });
  revoked.token = 'xoxp-rotated-away-0000'; // the app was uninstalled: Slack now answers invalid_auth
  await setWhatsappInstance(store(), up, { url: gowa.origin, username: gowa.username, password: gowa.password });
  await pairWhatsappAccount(store(), up, { label: 'Private', phone: '+4366012345678', sleep: async () => {}, onCode: () => {} });
});
afterEach(async () => {
  await server?.close();
  server = undefined;
  await dirs.cleanup();
});

const store = () => rootStore;
/** Root context whose identity calls also reach MOCK Slack and GOWA (token refresh stays on the world fakes). */
const rootContext = () => ({ ...worldContext(rootStore, ROOT, io), upstream: new Upstream(transportFor(ROOT)) });

describe('collectStatus [MOCK upstreams]', () => {
  it('lists every account family with identities, permissions and a live check per account', async () => {
    const r = await collectStatus(rootContext(), { imapVerify });
    const byId = new Map(r.accounts.map((a) => [a.id, a]));
    expect([...new Set(r.accounts.map((a) => a.family))].sort()).toEqual(['calendar', 'drive', 'mail', 'notion', 'slack', 'whatsapp']);
    for (const id of [IDS.google, IDS.notion, IDS.gmail, IDS.imap, IDS.gprod]) expect(byId.get(id)?.check?.state, id).toBe('ok');
    expect(byId.get(IDS.gmail)).toMatchObject({ provider: 'gmail', permissions: 'read, send', identity: ROOT.gmail.accounts[0]!.email });
    const slackRows = r.accounts.filter((a) => a.family === 'slack');
    expect(slackRows.find((a) => a.label === 'Company')?.check?.state).toBe('ok');
    expect(slackRows.find((a) => a.label === 'Old workspace')?.check).toMatchObject({ state: 'error', message: expect.stringMatching(/invalid_auth/) });
    expect(r.accounts.find((a) => a.family === 'whatsapp')).toMatchObject({ identity: '+4366012345678', check: { state: 'ok' } });
    expect(r.whatsappBridge?.origin).toBe(gowa.origin);
    expect(r.ledger).toMatchObject({ sends: 0, maxSends: 1000, pending: 0 });
    expect(imapChecks).toEqual([IDS.imap]);
  });

  it('never contains a secret, in the report, the text or the page', async () => {
    const r = await collectStatus(rootContext(), { imapVerify, live: false });
    const outputs = [JSON.stringify(r), formatStatusText(r), renderStatusPage(r)];
    for (const secret of await secretsOf(rootStore)) for (const out of outputs) expect(out).not.toContain(secret);
  });

  it('reports a failing check with a sanitised message only', async () => {
    await rootStore.update((d) => {
      d.imap[0]!.label = 'BROKEN GMX';
    });
    const r = await collectStatus(rootContext(), { imapVerify });
    expect(r.accounts.find((a) => a.id === IDS.imap)?.check).toMatchObject({ state: 'error', message: 'Internal error (details withheld)' });
    expect(formatStatusText(r)).toMatch(/2 check\(s\) failed/);
  });

  it('makes no upstream request without live checks', async () => {
    const before = io.length + slack.calls.length + gowa.calls.length;
    const r = await collectStatus(rootContext(), { live: false, imapVerify });
    expect(r.checked).toBe(false);
    expect(r.accounts.every((a) => !a.check)).toBe(true);
    expect(io.length + slack.calls.length + gowa.calls.length).toBe(before);
    expect(imapChecks).toEqual([]);
  });

  it('escapes user-assigned labels on the page', async () => {
    await rootStore.update((d) => {
      d.notion[0]!.label = '<script>alert(1)</script>';
    });
    const html = renderStatusPage(await collectStatus(rootContext(), { live: false }));
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });
});

describe('perch status (CLI) [MOCK upstreams]', () => {
  function cli(): { io: CliIo; out: string[] } {
    const out: string[] = [];
    return {
      out,
      io: {
        env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root },
        stdout: (s) => out.push(s),
        stderr: (s) => out.push(s),
        readSecret: async () => {
          throw new Error('no TTY');
        },
        transport: transportFor(ROOT),
        imapVerify,
      },
    };
  }

  it('prints the plain overview with --plain and exits 1 when a check failed', async () => {
    const { io: cio, out } = cli();
    expect(await runCli(['status', '--plain'], cio)).toBe(1);
    const text = out.join('');
    expect(text).toMatch(/✓ notion-0000000a/);
    expect(text).toMatch(/✗ slack-[a-f0-9]{8}  "Old workspace".*ERROR: Slack refused the token \(invalid_auth\)/);
    expect(text).toMatch(/Send ledger: 0 \/ 1000/);
    expect(text).toMatch(/1 check\(s\) failed/);
  });

  it('renders the terminal overview by default: Unicode checkboxes, no ANSI when piped, colour on a TTY', async () => {
    const piped = cli();
    expect(await runCli(['status'], piped.io)).toBe(1);
    const text = piped.out.join('');
    expect(text).not.toMatch(/\u001b\[/);
    expect(text).toMatch(/── Notion ─+\n☑ /);
    expect(text).toMatch(/✗ Old workspace .*FAILED\n {2}slack-[a-f0-9]{8} · slack · since \d{4}-\d{2}-\d{2}\n {2}Slack refused the token \(invalid_auth\)/);
    expect(text).toMatch(/── Not connected ─+[\s\S]*☐ Luma +events and guests/);
    expect(text).toMatch(/── Onboarding \d\/4/);
    expect(text.trimEnd().split('\n').pop()).toBe('✗ 1 check(s) failed');
    for (const secret of await secretsOf(rootStore)) expect(text).not.toContain(secret);

    const tty = cli();
    tty.io.stdoutIsTTY = true;
    tty.io.stdoutColumns = 100;
    expect(await runCli(['status', '--no-check'], tty.io)).toBe(0);
    expect(tty.out.join('')).toContain('\u001b[32m☑\u001b[0m');
    expect(tty.out.join('').split('\n')[1]).toBe('═'.repeat(100));

    const noColor = cli();
    noColor.io.stdoutIsTTY = true;
    noColor.io.env.NO_COLOR = '1';
    await runCli(['status', '--no-check'], noColor.io);
    expect(noColor.out.join('')).not.toMatch(/\u001b\[/);
    expect(noColor.out.join('')).toContain('☑');
  });

  it('--no-check exits 0 and --json is machine-readable', async () => {
    const a = cli();
    expect(await runCli(['status', '--no-check', '--plain'], a.io)).toBe(0);
    expect(a.out.join('')).toMatch(/live checks skipped/);
    const b = cli();
    await runCli(['status', '--json', '--no-check'], b.io);
    expect(JSON.parse(b.out.join(''))).toMatchObject({ namespace: 'root', checked: false });
  });
});

describe('GET /status [MOCK upstreams]', () => {
  let globalToken: string;

  beforeEach(async () => {
    globalToken = generateHttpToken();
    server = await startHttpServer({ host: '127.0.0.1', port: 0, token: globalToken, context: rootContext(), log: () => {}, statusOptions: { imapVerify } });
  });

  const statusUrl = () => server!.url.replace(/\/mcp$/, '/status');
  const basic = (token: string) => `Basic ${Buffer.from(`perch:${token}`).toString('base64')}`;

  it('asks the browser for credentials', async () => {
    const res = await fetch(statusUrl());
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toMatch(/^Basic realm="Perch status"/);
  });

  it('shows the overview to the global token (Basic or Bearer), with strict headers', async () => {
    for (const authorization of [basic(globalToken), `Bearer ${globalToken}`]) {
      const res = await fetch(statusUrl(), { headers: { authorization } });
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('Perch status');
      expect(html).toContain('Old workspace');
      expect(res.headers.get('content-security-policy')).toBe(`default-src 'none'; style-src '${STATUS_STYLE_HASH}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`);
      expect(res.headers.get('cache-control')).toBe('no-store');
      expect(html).not.toMatch(/<script|<form|<iframe|https?:\/\/(?!127\.0\.0\.1)/);
      for (const secret of await secretsOf(rootStore)) expect(html).not.toContain(secret);
    }
  });

  it('refuses client grants, other methods and cross-site requests before any check', async () => {
    const tokenFile = path.join(dirs.root, 'config', 'clients', 'c.token');
    await createClientGrant(rootStore, { label: 'Codex', capabilities: ['read'], accountIds: [IDS.gmail], tokenFile });
    const clientToken = (await readFile(tokenFile, 'utf8')).trim();
    const before = io.length + slack.calls.length;
    expect((await fetch(statusUrl(), { headers: { authorization: basic(clientToken) } })).status).toBe(403);
    expect((await fetch(statusUrl(), { method: 'POST', headers: { authorization: basic(globalToken) } })).status).toBe(405);
    expect((await fetch(statusUrl(), { headers: { authorization: basic(globalToken), 'sec-fetch-site': 'cross-site' } })).status).toBe(403);
    expect((await fetch(statusUrl(), { headers: { authorization: basic('wrong-token') } })).status).toBe(401);
    expect(io.length + slack.calls.length).toBe(before);
  });

  it('reuses the live checks for repeated loads', async () => {
    await fetch(statusUrl(), { headers: { authorization: basic(globalToken) } });
    const after = slack.calls.length;
    await fetch(statusUrl(), { headers: { authorization: basic(globalToken) } });
    expect(slack.calls.length).toBe(after);
  });
});
