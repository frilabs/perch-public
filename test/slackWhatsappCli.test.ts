// CLI onboarding for Slack (masked browser session) and WhatsApp (bridge + pairing code), and client grants
// with the Slack/WhatsApp capability families. MOCK Slack and GOWA upstreams only.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runCli, type CliIo } from '../src/cli/run.js';
import { addSlackWorkspace } from '../src/slack/slack.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import { Upstream, type UpstreamTransport } from '../src/upstream.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockGowa } from './support/mockGowa.js';
import { MockSlack, type MockSlackTeam } from './support/mockSlack.js';

let dirs: TempDirs;
let out: string[];
let err: string[];
let slack: MockSlack;
let gowa: MockGowa;
let team: MockSlackTeam;

/** Routes MOCK calls by origin (Slack fixed origin, GOWA on loopback). */
const transport: UpstreamTransport = (req) => (req.url.origin === 'https://slack.com' ? slack.transport(req) : gowa.transport(req));

function io(secrets: string[] = []): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root },
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    readSecret: async () => {
      const s = secrets.shift();
      if (s === undefined) throw new Error('no TTY in tests');
      return s;
    },
    transport,
    sleep: async () => {},
  };
}

const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = [];
  err = [];
  slack = new MockSlack();
  gowa = new MockGowa();
  team = slack.addTeam('A', { session: true });
  expect(await runCli(['init'], io())).toBe(0);
  out = [];
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('perch slack [MOCK Slack]', () => {
  it('redirects the retired manifest command to session login', async () => {
    expect(await runCli(['slack', 'manifest'], io())).toBe(0);
    expect(out.join('')).toBe('Connect Slack with: perch slack add --label NAME\n');
  });

  it('documents session login without an app setup command', async () => {
    expect(await runCli(['--help'], io())).toBe(0);
    const slackHelp = out.join('').split('\n').filter((line) => line.includes('perch slack')).join('\n');
    expect(slackHelp).toContain('perch slack add --label NAME');
    expect(slackHelp).toContain('browser session');
    expect(slackHelp).not.toMatch(/manifest|xoxp|--yes|UNOFFICIAL/);
  });

  it('adds a workspace from the masked prompt, lists it and never prints the token', async () => {
    expect(await runCli(['slack', 'add', '--label', 'Company'], io([team.cookie!, team.token]))).toBe(0);
    const id = (await (await openStore()).read()).slack[0]!.id;
    expect(out.join('')).toContain(`Connected Slack workspace ${id} "Company"`);
    expect(out.join('')).toContain('--allow slack_read,slack_send');
    out = [];
    expect(await runCli(['slack', 'list'], io())).toBe(0);
    expect(out.join('')).toContain(id);
    expect([...out, ...err].join('')).not.toContain(team.token);
    expect(await runCli(['slack', 'remove', id], io())).toBe(0);
    expect((await (await openStore()).read()).slack).toHaveLength(0);
  });

  it('refuses the token as a command-line argument', async () => {
    expect(await runCli(['slack', 'add', '--label', 'X', `--token=${team.token}`], io())).toBe(2);
  });

  it('keeps existing app workspaces stored and listed when adding a session workspace', async () => {
    const legacy = slack.addTeam('Legacy');
    const existing = await addSlackWorkspace(await openStore(), new Upstream(transport), { label: 'Legacy', token: legacy.token });
    expect(await runCli(['slack', 'add', '--label', 'Company'], io([team.cookie!, team.token]))).toBe(0);
    const workspaces = (await (await openStore()).read()).slack;
    expect(workspaces).toHaveLength(2);
    expect(workspaces.find((w) => w.id === existing.id)).toEqual(existing);
    expect(await runCli(['slack', 'list'], io())).toBe(0);
    expect(out.join('')).toContain(existing.id);
  });
});

describe('perch whatsapp [MOCK GOWA]', () => {
  it('sets the bridge, pairs by code, shows status and removes the account', async () => {
    expect(await runCli(['whatsapp', 'instance', 'set', '--url', gowa.origin], io([gowa.username, gowa.password]))).toBe(0);
    expect(out.join('')).toContain('verified');
    out = [];
    expect(await runCli(['whatsapp', 'add', '--label', 'Private', '--phone', '+4366012345678'], io())).toBe(0);
    expect(out.join('')).toContain('Pairing code: ABCD-1234');
    const data = await (await openStore()).read();
    expect(data.whatsapp).toHaveLength(1);
    expect(JSON.stringify(data.whatsappInstance)).toContain(gowa.password); // stored (encrypted at rest) ...
    out = [];
    expect(await runCli(['whatsapp', 'instance', 'show'], io())).toBe(0);
    expect(out.join('')).not.toContain(gowa.password); // ... but never printed
    out = [];
    expect(await runCli(['whatsapp', 'status'], io())).toBe(0);
    expect(out.join('')).toContain('logged in');
    expect(await runCli(['whatsapp', 'remove', data.whatsapp[0]!.id], io())).toBe(0);
    expect(gowa.devices).toHaveLength(0);
  });

  it('refuses a bridge URL outside loopback/Tailscale before any request', async () => {
    expect(await runCli(['whatsapp', 'instance', 'set', '--url', 'http://192.168.1.5:3000'], io(['u', 'p']))).toBe(1);
    expect(err.join('')).toMatch(/GOWA URL/);
    expect(gowa.calls).toHaveLength(0);
  });

  it('refuses the password as a command-line argument', async () => {
    expect(await runCli(['whatsapp', 'instance', 'set', '--url', gowa.origin, '--password', 'x'], io())).toBe(2);
  });
});

describe('perch client add with Slack/WhatsApp capabilities', () => {
  it('creates family-scoped grants and refuses mismatched families', async () => {
    expect(await runCli(['slack', 'add', '--label', 'Company'], io([team.cookie!, team.token]))).toBe(0);
    expect(await runCli(['whatsapp', 'instance', 'set', '--url', gowa.origin], io([gowa.username, gowa.password]))).toBe(0);
    expect(await runCli(['whatsapp', 'add', '--label', 'Private', '--phone', '+4366012345678'], io())).toBe(0);
    const data = await (await openStore()).read();
    const slackId = data.slack[0]!.id;
    const waId = data.whatsapp[0]!.id;
    err = [];
    expect(await runCli(['client', 'add', '--label', 'Codex', '--allow', 'slack_read,slack_send,whatsapp_read', '--account', slackId, '--account', waId], io())).toBe(0);
    expect(await runCli(['client', 'add', '--label', 'Bad', '--allow', 'slack_send', '--account', waId], io())).toBe(1);
    expect(err.join('')).toMatch(/Slack capabilities .* need at least one Slack workspace/);
    err = [];
    expect(await runCli(['client', 'add', '--label', 'Bad2', '--allow', 'whatsapp_send', '--account', waId, '--account', slackId], io())).toBe(1);
    expect(err.join('')).toMatch(/has no granted capability/);
    err = [];
    expect(await runCli(['client', 'add', '--label', 'Bad3', '--allow', 'slack_read', '--account', 'slack-00000000'], io())).toBe(1);
    expect(err.join('')).toMatch(/Unknown Slack workspace/);
    const clients = (await (await openStore()).read()).clients;
    expect(clients.map((c) => c.label)).toEqual(['Codex']);
  });
});
