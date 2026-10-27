// Easier onboarding: read/write choice when connecting, full-access client grants, and `perch setup`.
// MOCK only: IMAP logins are a MOCK check, Slack is the MOCK Slack Web API; nothing reaches a provider.
import { readFile } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { principalForClientToken } from '../src/auth/grants.js';
import { chooseAccess } from '../src/cli/onboarding.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { createPerchContext } from '../src/context.js';
import { createMcpServer } from '../src/mcp/server.js';
import { addSlackWorkspace } from '../src/slack/slack.js';
import { CAPABILITIES, CredentialStore } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockSlack } from './support/mockSlack.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

let dirs: TempDirs;
let out: string;
let err: string;
const password = dummySecret('IMAP-PW');

function io(answers: string[] = [], extra: Partial<CliIo> = {}): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root, PERCH_ALLOWED_HOSTS: 'homeserver.example.ts.net' },
    stdout: (s) => void (out += s),
    stderr: (s) => void (err += s),
    readSecret: async () => password,
    readLine: async () => {
      const a = answers.shift();
      if (a === undefined) throw new Error('MOCK: no more answers');
      return a;
    },
    imapVerify: async () => {},
    ...extra,
  };
}

const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = '';
  err = '';
  expect(await runCli(['init'], io())).toBe(0);
  out = '';
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('read or write when connecting an account', () => {
  it('sets the provider opt-ins for the chosen access', async () => {
    const ask = (a: string) => async () => a;
    const values: Record<string, unknown> = {};
    expect(await chooseAccess('gmail', values, ask('w'), () => {})).toBe(true);
    expect(values).toMatchObject({ 'allow-drafts': true, 'allow-send': true, 'allow-modify': true });
    const read: Record<string, unknown> = {};
    expect(await chooseAccess('google', read, ask(''), () => {})).toBe(false);
    expect(read['allow-write']).toBeUndefined();
    const flag: Record<string, unknown> = { write: true };
    expect(await chooseAccess('google-productivity', flag, undefined, () => {})).toBe(true);
    expect(flag['allow-calendar-write']).toBe(true);
    // Services without provider-side write scopes are not asked.
    expect(await chooseAccess('notion', {}, async () => { throw new Error('must not ask'); }, () => {})).toBe(false);
  });

  it('keeps explicit flags, refuses contradictions and falls back to read-only without a terminal', async () => {
    const legacy: Record<string, unknown> = { 'allow-send': true };
    expect(await chooseAccess('imap', legacy, async () => { throw new Error('must not ask'); }, () => {})).toBe(true);
    expect(legacy['allow-modify']).toBeUndefined();
    await expect(chooseAccess('gmail', { write: true, 'read-only': true }, undefined, () => {})).rejects.toThrow(/either/);
    await expect(chooseAccess('gmail', { 'read-only': true, 'allow-send': true }, undefined, () => {})).rejects.toThrow(/cannot be combined/);
    await expect(chooseAccess('gmail', {}, async () => 'maybe', () => {})).rejects.toThrow(/Choose r/);
    let note = '';
    expect(await chooseAccess('gmail', {}, undefined, (s) => void (note += s))).toBe(false);
    expect(note).toMatch(/read-only/);
  });

  it('perch imap add asks and stores write opt-ins on "w"', async () => {
    expect(await runCli(['imap', 'add', '--label', 'GMX', '--email', 'dummy@gmx.at'], io(['w']))).toBe(0);
    const a = (await (await openStore()).read()).imap[0]!;
    expect(a).toMatchObject({ allowDrafts: true, allowSend: true, allowModify: true });
    expect(out).toMatch(/Client grants separately limit read, draft, send and modify/);
    expect(await runCli(['imap', 'add', '--label', 'GMX2', '--email', 'dummy2@gmx.at', '--read-only'], io())).toBe(0);
    const b = (await (await openStore()).read()).imap[1]!;
    expect(b).toMatchObject({ allowDrafts: false, allowSend: false });
    expect(b.allowModify ?? false).toBe(false);
  });
});

describe('perch client add --full', () => {
  it('grants every capability on every account, including accounts connected later', async () => {
    expect(await runCli(['client', 'add', '--label', 'Claude Code', '--full', '--token-file', `${dirs.root}/full.token`], io())).toBe(0);
    expect(out).toMatch(/FULL access/);
    expect(out).toMatch(/claude mcp add --scope user --transport http perch https:\/\/homeserver\.example\.ts\.net\/mcp/);
    expect(out).not.toMatch(/Bearer [A-Za-z0-9_-]{30,}/);
    const token = (await readFile(`${dirs.root}/full.token`, 'utf8')).trim();
    const store = await openStore();
    // A workspace connected AFTER the grant is covered too.
    const slack = new MockSlack();
    const team = slack.addTeam('Later');
    const ws = await addSlackWorkspace(store, new Upstream(slack.transport), { label: 'Later', token: team.token });
    const p = (await principalForClientToken(store, token))!;
    expect([...p.capabilities].sort()).toEqual([...CAPABILITIES].sort());
    expect(p.slackAccounts).toBe('all');
    expect(p.mailAccounts).toBe('all');
    const mcp = createMcpServer(createPerchContext(store, slack.transport), p);
    const [x, y] = InMemoryTransport.createLinkedPair();
    await mcp.connect(y);
    const client = new Client({ name: 'full', version: '0' });
    await client.connect(x);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(['slack_send_message', 'mail_send', 'drive_upload_file', 'notion_create_page', 'drive_search', 'notion_search']));
    const listed = await client.callTool({ name: 'perch_list_accounts', arguments: {} });
    expect((listed.content as Array<{ text: string }>)[0]!.text).toContain(ws.id);
    out = '';
    await runCli(['client', 'list'], io());
    expect(out).toMatch(/FULL access \(all capabilities, all accounts incl\. later ones\)/);
  });

  it('refuses --full together with --allow or --account', async () => {
    expect(await runCli(['client', 'add', '--label', 'X', '--full', '--allow', 'read'], io())).toBe(2);
    expect(err).toMatch(/--full replaces --allow and --account/);
  });
});

describe('perch setup', () => {
  it('walks through the services, connects the chosen ones and creates one full-access client', async () => {
    const answers = [
      'n', // Google account (Drive, Gmail, Calendar, Contacts)
      'n', // Outlook
      'y', // GMX/IMAP
      'Private', // label
      'dummy@gmx.at', // e-mail
      'w', // access
      'n', // another IMAP account
      'n', // Notion
      'n', // Slack
      'n', // WhatsApp
      'n', // Luma
      'n', // X
      'y', // explicitly create a client
      'Claude Code', // client label
      'w', // explicit full access
    ];
    expect(await runCli(['setup'], io(answers)), err).toBe(0);
    const data = await (await openStore()).read();
    expect(data.imap).toHaveLength(1);
    expect(data.imap[0]).toMatchObject({ label: 'Private', allowSend: true, allowModify: true });
    expect(data.clients).toHaveLength(1);
    expect(data.clients[0]).toMatchObject({ label: 'Claude Code', full: true });
    expect(out).toMatch(/GMX: allow IMAP/);
    expect(out).toMatch(/claude mcp add/);
    expect(out).toMatch(/Mail/);
    expect(answers).toHaveLength(0);
    expect(out + err).not.toContain(password);
  });

  it('needs a terminal', async () => {
    expect(await runCli(['setup'], io([], { readLine: undefined }))).toBe(1);
    expect(err).toMatch(/interactive terminal/);
  });
});

it('draft-only mail never opts into sending, organizing or unrelated Google writes', async () => {
  for (const cmd of ['gmail', 'imap', 'google']) {
    const values: Record<string, unknown> = {};
    expect(await chooseAccess(cmd, values, async () => 'd', () => {})).toBe(true);
    expect(values).toEqual({ 'allow-drafts': true, 'drafts-only': true });
    for (const conflict of ['write', 'read-only', 'allow-send', 'allow-modify']) {
      await expect(chooseAccess(cmd, { 'drafts-only': true, [conflict]: true }, undefined, () => {})).rejects.toMatchObject({ code: 'usage' });
    }
  }
  const values: Record<string, unknown> = { 'drafts-only': true };
  expect(await chooseAccess('imap', values, undefined, () => {})).toBe(true);
  expect(values['allow-drafts']).toBe(true);
  await expect(chooseAccess('google-productivity', { 'drafts-only': true }, undefined, () => {})).rejects.toMatchObject({ code: 'usage' });
});

it('creates no client grant when setup prompts are accepted with Enter', async () => {
  expect(await runCli(['setup'], io(Array(9).fill(''))), err).toBe(0);
  expect((await (await openStore()).read()).clients).toEqual([]);
});
