// Slack session mode (docs/SLACK_SESSION_NOTION_GUIDE_SPEC.md §1): browser token xoxc-… + cookie d=xoxd-….
// MOCK Slack Web API only (it requires the exact cookie for session teams); nothing reaches Slack.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { SLACK_SESSION_WARNING, SLACK_TOKEN_CONSOLE_LINE } from '../src/cli/slackGuide.js';
import { createPerchContext } from '../src/context.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { createMcpServer } from '../src/mcp/server.js';
import { addSlackWorkspace, normalizeSlackCookie } from '../src/slack/slack.js';
import { accountCapabilities, formatStatusTerminal } from '../src/status/terminal.js';
import { collectStatus, formatStatusText } from '../src/status/status.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import { Upstream, type UpstreamRequest } from '../src/upstream.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockSlack, type MockSlackTeam } from './support/mockSlack.js';

let dirs: TempDirs;
let out: string;
let err: string;
let prompts: string[];
let slack: MockSlack;
let team: MockSlackTeam;

function io(answers: string[], secrets: string[], extra: Partial<CliIo> = {}): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root },
    stdout: (s) => void (out += s),
    stderr: (s) => void (err += s),
    readSecret: async (p) => {
      prompts.push(`SECRET:${p}`);
      const s = secrets.shift();
      if (s === undefined) throw new Error('MOCK: no secret');
      return s;
    },
    readLine: async (p) => {
      prompts.push(p);
      const a = answers.shift();
      if (a === undefined) throw new Error(`MOCK: no more answers (prompt: ${p})`);
      return a;
    },
    transport: slack.transport,
    ...extra,
  };
}

const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
const secretsOf = (t: MockSlackTeam) => [t.token, t.cookie!, decodeURIComponent(t.cookie!)];

/** Everything Perch wrote or stored in plain text: output, prompts, ledger/audit and status. */
async function plainDump(): Promise<string> {
  const store = await openStore();
  const ledger = JSON.stringify(await new MailWorkflowLedger(store).read());
  const status = formatStatusText(await collectStatus(createPerchContext(store, slack.transport)));
  return [out, err, prompts.join('\n'), ledger, status].join('\n');
}

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = '';
  err = '';
  prompts = [];
  slack = new MockSlack();
  team = slack.addTeam('S', { session: true });
  team.channels.push({ id: 'C0GENERAL', name: 'general', kind: 'public_channel', messages: [{ ts: '1760000100.000100', user: team.userId, text: 'hello' }] });
  expect(await runCli(['init'], io([], []))).toBe(0);
  out = '';
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('perch slack add --session [MOCK Slack]', () => {
  it('shows one storage note and the guide, then connects; token and cookie never appear in output, prompts or audit', async () => {
    expect(await runCli(['slack', 'add', '--label', 'Work', '--session'], io([], [team.cookie!, team.token]))).toBe(0);
    expect(out).toContain(SLACK_SESSION_WARNING);
    expect(out.split(SLACK_SESSION_WARNING)).toHaveLength(2);
    expect(out).toContain('https://app.slack.com/client');
    expect(out).toContain(SLACK_TOKEN_CONSOLE_LINE);
    expect(prompts.map((p) => p.slice(0, 12))).toEqual(['SECRET:Slack', 'SECRET:Slack']);
    expect(prompts[0]).toMatch(/cookie "d" \(xoxd-…\)/);
    expect(prompts[1]).toMatch(/session token \(xoxc-…\)/);
    expect(out.indexOf(SLACK_SESSION_WARNING)).toBeLessThan(out.indexOf('app.slack.com/client'));
    const [ws] = (await (await openStore()).read()).slack;
    expect(ws).toMatchObject({ label: 'Work', authMode: 'session', token: team.token, sessionCookie: team.cookie, teamId: team.teamId, scopes: [] });
    expect(out).toContain(`Connected Slack workspace ${ws!.id} "Work"`);
    expect(out).toMatch(/browser session/);
    // A read through MCP with the cookie, then check nothing secret was written anywhere in plain text.
    const ctx = createPerchContext(await openStore(), slack.transport);
    await ctx.slack.getHistory(READONLY_PRINCIPAL, { workspaceId: ws!.id, channelId: 'C0GENERAL' });
    const dump = await plainDump();
    for (const s of secretsOf(team)) expect(dump).not.toContain(s);
    out = '';
    expect(await runCli(['slack', 'list'], io([], []))).toBe(0);
    expect(out).toContain('session');
    for (const s of secretsOf(team)) expect(out).not.toContain(s);
  });

  it.each([{ secrets: [] }, { secrets: [''] }])('missing cookie is rejected before storage or Slack requests: $secrets', async ({ secrets }) => {
    expect(await runCli(['slack', 'add', '--label', 'Work'], io([], secrets))).toBe(1);
    expect((await (await openStore()).read()).slack).toHaveLength(0);
    expect(slack.calls).toHaveLength(0);
  });

  it('missing token is rejected without storing the cookie', async () => {
    expect(await runCli(['slack', 'add', '--label', 'Work'], io([], [team.cookie!, '']))).toBe(1);
    expect((await (await openStore()).read()).slack).toHaveLength(0);
    expect(slack.calls).toHaveLength(0);
  });

  it.each([{ args: [] }, { args: ['--session'] }, { args: ['--session', '--yes'] }])('needs only masked credentials without a line prompt ($args)', async ({ args }) => {
    const noTty = io([], [team.cookie!, team.token]);
    delete noTty.readLine;
    expect(await runCli(['slack', 'add', '--label', 'Work', ...args], noTty)).toBe(0);
    expect(prompts.every((p) => p.startsWith('SECRET:'))).toBe(true);
    expect((await (await openStore()).read()).slack[0]?.authMode).toBe('session');
  });

  it('defaults directly to session login and --skip-guide skips only the steps', async () => {
    expect(await runCli(['slack', 'add', '--label', 'Work', '--skip-guide'], io([], [team.cookie!, team.token]))).toBe(0);
    expect(prompts.every((p) => p.startsWith('SECRET:'))).toBe(true);
    expect(out).not.toContain('app.slack.com/client');
    expect((await (await openStore()).read()).slack[0]?.authMode).toBe('session');
  });

  it('accepts the cookie with a leading d= and a decoded copy; refuses wrong formats before any Slack call', async () => {
    expect(normalizeSlackCookie(`d=${team.cookie}`)).toBe(team.cookie);
    expect(normalizeSlackCookie(` ${decodeURIComponent(team.cookie!)}; `)).toBe(team.cookie);
    const store = await openStore();
    const up = new Upstream(slack.transport);
    for (const [token, cookie] of [
      [team.token, 'abc'],
      [team.token, 'xoxd-short'],
      [team.token, `xoxd-${'a'.repeat(30)}\r\nX-Evil: 1`],
      [team.token, `xoxd-${'a'.repeat(30)}; other=1`],
      ['xoxp-1234567890-abc', team.cookie!],
      ['xoxc-bad token!', team.cookie!],
    ]) {
      const e = await rejection(addSlackWorkspace(store, up, { label: 'X', token: token!, sessionCookie: cookie! }));
      expect(e.message).toMatch(/xoxd-|xoxc-/);
      for (const s of secretsOf(team)) expect(e.message).not.toContain(s);
    }
    expect(slack.calls).toHaveLength(0);
    // A session token through the app path points to --session.
    expect((await rejection(addSlackWorkspace(store, up, { label: 'X', token: team.token }))).message).toMatch(/--session/);
  });

  it('a cookie that does not match the session: clear error, nothing stored, no secret in the message', async () => {
    const wrong = `xoxd-${'Z'.repeat(40)}%2F`;
    expect(await runCli(['slack', 'add', '--label', 'Work', '--session', '--yes', '--skip-guide'], io([], [wrong, team.token]))).toBe(1);
    expect(err).toMatch(/Slack refused the session \(invalid_auth\).*Nothing was stored/);
    expect((await (await openStore()).read()).slack).toHaveLength(0);
    for (const s of [...secretsOf(team), wrong]) expect(out + err).not.toContain(s);
  });

  it('the same team again updates the record (same id, grants stay); switching to the app keeps the id too', async () => {
    const up = new Upstream(slack.transport);
    const store = await openStore();
    const first = await addSlackWorkspace(store, up, { label: 'Work', token: team.token, sessionCookie: team.cookie! });
    const { token } = await createClientGrant(store, { label: 'Codex', capabilities: ['slack_read', 'slack_send'], accountIds: [first.id], tokenFile: path.join(dirs.root, 'c.token') });
    // New browser session (after signing in again): new token and cookie for the same team.
    const oldToken = team.token;
    team.token = team.token.replace('xoxc-', 'xoxc-NEW');
    team.cookie = `${team.cookie}NEW`;
    expect(await runCli(['slack', 'add', '--label', 'Work', '--session', '--yes'], io([], [team.cookie, team.token]))).toBe(0);
    expect(prompts).toHaveLength(2);
    expect(prompts.every((p) => p.startsWith('SECRET:'))).toBe(true);
    expect(out).toContain(`Updated Slack workspace ${first.id}`);
    const data = await (await openStore()).read();
    expect(data.slack).toHaveLength(1);
    expect(data.slack[0]).toMatchObject({ id: first.id, token: team.token, sessionCookie: team.cookie, createdAt: first.createdAt });
    expect(data.slack[0]!.token).not.toBe(oldToken);
    expect(data.clients[0]?.accountIds).toEqual([first.id]);
    expect(await principalForClientToken(await openStore(), token)).toBeTruthy();
    // Switch to the app: same team, user token, record becomes an app record with the same id.
    const appToken = `xoxp-${'1'.repeat(20)}`;
    team.token = appToken;
    delete team.cookie;
    const switched = await addSlackWorkspace(await openStore(), up, { label: 'Work', token: appToken });
    expect(switched.id).toBe(first.id);
    const after = (await (await openStore()).read()).slack;
    expect(after).toHaveLength(1);
    expect(after[0]!.authMode).toBeUndefined();
    expect(after[0]!.sessionCookie).toBeUndefined();
    expect(after[0]!.scopes.length).toBeGreaterThan(0);
  });
});

describe('session workspaces at runtime [MOCK Slack]', () => {
  let wsId: string;
  beforeEach(async () => {
    wsId = (await addSlackWorkspace(await openStore(), new Upstream(slack.transport), { label: 'Work team', token: team.token, sessionCookie: team.cookie! })).id;
    slack.calls.length = 0;
  });

  async function clientFor(principal: Principal) {
    const mcp = createMcpServer(createPerchContext(await openStore(), slack.transport), principal);
    const [a, b] = InMemoryTransport.createLinkedPair();
    await mcp.connect(b);
    const client = new Client({ name: 'session-test', version: '0' });
    await client.connect(a);
    return client;
  }
  async function call(client: Client, name: string, args: Record<string, unknown>) {
    const r = await client.callTool({ name, arguments: args });
    return { isError: r.isError === true, text: (r.content as Array<{ text: string }>)[0]?.text ?? '' };
  }

  it('sends the cookie only to slack.com and files.slack.com, never to the upload URL; scopes are not checked', async () => {
    const store = await openStore();
    const { token } = await createClientGrant(store, { label: 'Codex', capabilities: ['slack_read', 'slack_send'], accountIds: [wsId], tokenFile: path.join(dirs.root, 'c.token') });
    const client = await clientFor((await principalForClientToken(store, token))!);
    team.files.push({ id: 'F0DOC', name: 'notes.txt', mimetype: 'text/plain', content: Buffer.from('file body') });
    expect((await call(client, 'slack_get_history', { workspaceId: wsId, channelId: 'C0GENERAL' })).isError).toBe(false);
    expect((await call(client, 'slack_search', { query: 'hello' })).isError).toBe(false);
    const sent = await call(client, 'slack_send_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'hi', requestId: 'session-req-000001' });
    expect(sent.isError, sent.text).toBe(false);
    expect(team.posted.map((p) => p.text)).toEqual(['hi']);
    const file = await call(client, 'slack_get_file', { workspaceId: wsId, fileId: 'F0DOC' });
    expect(file.isError, file.text).toBe(false);
    expect(file.text).toContain(Buffer.from('file body').toString('base64'));
    const up = await call(client, 'slack_upload_file', { workspaceId: wsId, channelId: 'C0GENERAL', filename: 'a.txt', contentBase64: Buffer.from('abc').toString('base64'), requestId: 'session-req-000002' });
    expect(up.isError, up.text).toBe(false);
    const byHost = (r: UpstreamRequest) => `${r.url.host}${r.url.pathname.startsWith('/upload/') ? ' upload' : ''}`;
    for (const r of slack.calls) {
      if (byHost(r).endsWith('upload')) expect(r.headers.cookie, byHost(r)).toBeUndefined();
      else expect(r.headers.cookie, byHost(r)).toBe(`d=${team.cookie}`);
      expect(['slack.com', 'files.slack.com']).toContain(r.url.host);
    }
    expect(slack.calls.some((r) => r.url.host === 'files.slack.com' && r.method === 'GET')).toBe(true);
    // perch_list_accounts carries the hint and every capability (no scopes to check).
    const accounts = await call(client, 'perch_list_accounts', {});
    expect(accounts.text).toContain('session (unofficial)');
    expect(accounts.text).toMatch(/"canPost":\s*true/);
    const audit = JSON.stringify(await new MailWorkflowLedger(await openStore()).read());
    for (const s of secretsOf(team)) {
      expect(audit).not.toContain(s);
      expect(accounts.text).not.toContain(s);
    }
  });

  it('an expired session: tools and status name the renew command; nothing secret in errors', async () => {
    team.expired = true;
    const client = await clientFor(READONLY_PRINCIPAL);
    const r = await call(client, 'slack_get_history', { workspaceId: wsId, channelId: 'C0GENERAL' });
    expect(r.isError).toBe(true);
    expect(r.text).toContain("Slack session expired (invalid_auth): run perch slack add --label 'Work team' --session again (updates the same workspace)");
    const report = await collectStatus(createPerchContext(await openStore(), slack.transport));
    const row = report.accounts.find((a) => a.id === wsId)!;
    expect(row.check?.state).toBe('error');
    expect(row.check?.message).toContain("perch slack add --label 'Work team' --session");
    const text = formatStatusText(report);
    expect(text).toMatch(/✗ slack-/);
    const term = formatStatusTerminal(report, accountCapabilities(await (await openStore()).read()), { tty: true, env: {}, columns: 100 });
    expect(term).toContain('--session');
    for (const s of secretsOf(team)) expect(text + term + r.text).not.toContain(s);
  });

  it('status: session hint in yellow, all capabilities on, no reinstall hint', async () => {
    const report = await collectStatus(createPerchContext(await openStore(), slack.transport));
    const row = report.accounts.find((a) => a.id === wsId)!;
    expect(row.check?.state).toBe('ok');
    expect(row.hint).toMatch(/^session \(unofficial\)/);
    expect(row.permissions).toBe('read, search, post, open dm');
    const caps = accountCapabilities(await (await openStore()).read())[wsId]!;
    expect(caps.every((c) => c.enabled)).toBe(true);
    const term = formatStatusTerminal(report, accountCapabilities(await (await openStore()).read()), { tty: true, env: {}, columns: 100 });
    expect(term).toContain('\u001b[33mhint: session (unofficial)');
    expect(term).not.toMatch(/reinstall/);
  });

  it('a raw Cookie header or the cookie for another service is refused before any I/O', async () => {
    const up = new Upstream(slack.transport);
    await expect(up.raw('slack', { method: 'GET', path: '/api/auth.test', headers: { Cookie: `d=${team.cookie}` } })).rejects.toMatchObject({ code: 'route_not_allowed' });
    await expect(up.raw('notion', { method: 'GET', path: '/v1/users/me', slackCookie: team.cookie! })).rejects.toMatchObject({ code: 'route_not_allowed' });
    await expect(up.raw('slack', { method: 'GET', path: '/api/auth.test', slackCookie: 'xoxd-bad;x' })).rejects.toMatchObject({ code: 'bad_argument' });
    expect(slack.calls).toHaveLength(0);
  });

  it('stores token and cookie only encrypted (old records without authMode still load as app)', async () => {
    const files = ['store.enc'].map((f) => path.join(dirs.dataDir, f));
    for (const f of files) {
      const raw = await readFile(f, 'utf8');
      for (const s of secretsOf(team)) expect(raw).not.toContain(s);
    }
    const app = slack.addTeam('App');
    const appWs = await addSlackWorkspace(await openStore(), new Upstream(slack.transport), { label: 'App', token: app.token });
    expect(appWs.authMode).toBeUndefined();
    expect((await (await openStore()).read()).slack.map((w) => w.authMode ?? 'app')).toEqual(['session', 'app']);
  });
});

describe('perch setup offers the session way [MOCK Slack]', () => {
  it('the Slack step asks app or session and shows the same warning and guide', async () => {
    // google, microsoft, imap, notion n; slack y; label; choice s; confirm y; Enter after the guide.
    const code = await runCli(['setup'], io(['n', 'n', 'n', 'n', 'y', 'Work', 's', 'y', ''], [team.cookie!, team.token]));
    expect(out).toContain(SLACK_SESSION_WARNING);
    expect(out).toContain(SLACK_TOKEN_CONSOLE_LINE);
    expect((await (await openStore()).read()).slack[0]?.authMode).toBe('session');
    expect(code === 0 || code === 1).toBe(true);
  });
});
