// Slack files and reactions through the real MCP SDK client (in-memory transport) against the MOCK Slack
// Web API and file host. Covers grants, scopes, idempotent uploads, hostile URLs, size limits and audit.
// No live Slack calls: passing tests are NOT evidence of a live integration.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, removeClientGrant, type Principal } from '../src/auth/grants.js';
import { createPerchContext } from '../src/context.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { createMcpServer } from '../src/mcp/server.js';
import { slackExtraTools } from '../src/mcp/tools/slackExtra.js';
import { addSlackWorkspace, MAX_SLACK_FILE_BYTES } from '../src/slack/slack.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { isAllowedRoute, Upstream, type RouteCapability } from '../src/upstream.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockSlack, type MockSlackTeam } from './support/mockSlack.js';

let dirs: TempDirs;
let store: CredentialStore;
let slack: MockSlack;
let team: MockSlackTeam;
let other: MockSlackTeam;
let wsId: string;
let otherId: string;

const MY_TS = '1760000100.000100';
const THEIR_TS = '1760000200.000200';
const WRITES = ['slack_add_reaction', 'slack_remove_reaction', 'slack_edit_message', 'slack_upload_file'];

async function clientFor(principal: Principal) {
  const mcp = createMcpServer(createPerchContext(store, slack.transport), principal);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await mcp.connect(b);
  const client = new Client({ name: 'slack-extra-test', version: '0' });
  await client.connect(a);
  return client;
}

async function grant(capabilities: Array<'slack_read' | 'slack_send'>, accountIds: string[]) {
  const { client, token } = await createClientGrant(store, {
    label: 'Codex',
    capabilities,
    accountIds,
    tokenFile: `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token`,
  });
  return { id: client.id, principal: (await principalForClientToken(store, token))! };
}

async function call(client: Client, name: string, args: Record<string, unknown>) {
  try {
    const r = await client.callTool({ name, arguments: args });
    const text = (r.content as Array<{ text: string }>)[0]?.text ?? '';
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(text) as Record<string, unknown>;
    } catch {
      body = { error: text };
    }
    return { isError: r.isError === true, body };
  } catch (err) {
    return { isError: true, body: { error: (err as Error).message } };
  }
}

const rid = () => `slack-x-${Math.random().toString(16).slice(2, 14)}`;
const fileHostCalls = () => slack.calls.filter((c) => c.url.origin === 'https://files.slack.com');
const apiCalls = (method: string) => slack.calls.filter((c) => c.url.pathname === `/api/${method}`);
const b64 = (s: string) => Buffer.from(s).toString('base64');

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  slack = new MockSlack();
  team = slack.addTeam('A');
  other = slack.addTeam('B');
  team.channels.push({
    id: 'C0GENERAL',
    name: 'general',
    kind: 'public_channel',
    messages: [
      { ts: MY_TS, user: team.userId, text: 'my message' },
      { ts: THEIR_TS, user: 'U0ALICE', text: 'their message' },
    ],
  });
  other.channels.push({ id: 'C0OTHER', name: 'other', kind: 'public_channel', messages: [{ ts: MY_TS, user: other.userId, text: 'x' }] });
  const upstream = new Upstream(slack.transport);
  wsId = (await addSlackWorkspace(store, upstream, { label: 'Company', token: team.token })).id;
  otherId = (await addSlackWorkspace(store, upstream, { label: 'Other', token: other.token })).id;
});

afterEach(async () => {
  await dirs.cleanup();
});

describe('Slack files and reactions: tool exposure [MOCK Slack]', () => {
  it('gives the read-only operator slack_get_file but no write tools', async () => {
    const names = (await (await clientFor(READONLY_PRINCIPAL)).listTools()).tools.map((t) => t.name);
    expect(names).toContain('slack_get_file');
    for (const w of WRITES) expect(names).not.toContain(w);
    expect(slackExtraTools.writeTools).toEqual(expect.arrayContaining(WRITES));
  });

  it('gives slack_read clients only the read tool and slack_send clients only the writes', async () => {
    const reader = (await (await clientFor((await grant(['slack_read'], [wsId])).principal)).listTools()).tools.map((t) => t.name);
    expect(reader).toContain('slack_get_file');
    for (const w of WRITES) expect(reader).not.toContain(w);
    const sender = (await (await clientFor((await grant(['slack_send'], [wsId])).principal)).listTools()).tools.map((t) => t.name);
    expect(sender).not.toContain('slack_get_file');
    for (const w of WRITES) expect(sender).toContain(w);
  });

  it('denies writes to a client without slack_send before any Slack call', async () => {
    const { principal } = await grant(['slack_read'], [wsId]);
    const client = await clientFor(principal);
    const calls = slack.calls.length;
    const r = await call(client, 'slack_add_reaction', { workspaceId: wsId, channelId: 'C0GENERAL', ts: MY_TS, emoji: 'thumbsup' });
    expect(r.isError).toBe(true);
    const ctx = createPerchContext(store, slack.transport);
    await expect(ctx.slack.addReaction(principal, { workspaceId: wsId, channelId: 'C0GENERAL', ts: MY_TS, emoji: 'thumbsup' })).rejects.toMatchObject({ code: 'capability_denied' });
    await expect(ctx.slack.editMessage(READONLY_PRINCIPAL, { workspaceId: wsId, channelId: 'C0GENERAL', ts: MY_TS, text: 'x' })).rejects.toMatchObject({ code: 'capability_denied' });
    await expect(
      ctx.slack.uploadFile(principal, { workspaceId: wsId, channelId: 'C0GENERAL', filename: 'a.txt', contentBase64: b64('a'), requestId: rid() }),
    ).rejects.toMatchObject({ code: 'capability_denied' });
    expect(slack.calls.length).toBe(calls);
  });

  it('allowlists the new methods only behind the right tag and never deletion or public links', () => {
    const caps: RouteCapability[] = ['read', 'send', 'slack_send', 'admin', 'draft'];
    for (const m of ['reactions.add', 'reactions.remove', 'chat.update', 'files.getUploadURLExternal', 'files.completeUploadExternal']) {
      expect(isAllowedRoute('slack', 'POST', `/api/${m}`, 'slack_send')).toBe(true);
      expect(isAllowedRoute('slack', 'POST', `/api/${m}`)).toBe(false);
      expect(isAllowedRoute('slack', 'GET', `/api/${m}`)).toBe(false);
    }
    expect(isAllowedRoute('slack', 'GET', '/api/files.info')).toBe(true);
    expect(isAllowedRoute('slack', 'GET', '/api/files.info', 'slack_send')).toBe(false);
    for (const m of ['chat.delete', 'files.delete', 'files.sharedPublicURL', 'files.revokePublicURL', 'files.upload']) {
      for (const method of ['GET', 'POST', 'DELETE']) for (const c of caps) expect(isAllowedRoute('slack', method, `/api/${m}`, c)).toBe(false);
    }
    // File host: uploads only as slack_send, downloads only as read, nothing else.
    expect(isAllowedRoute('slackfiles', 'POST', '/upload/v1/abc_DEF-1', 'slack_send')).toBe(true);
    expect(isAllowedRoute('slackfiles', 'POST', '/upload/v1/abc')).toBe(false);
    expect(isAllowedRoute('slackfiles', 'GET', '/upload/v1/abc')).toBe(false);
    expect(isAllowedRoute('slackfiles', 'GET', '/files-pri/T0MOCK1-F0ABC/download/report.pdf')).toBe(true);
    expect(isAllowedRoute('slackfiles', 'POST', '/files-pri/T0MOCK1-F0ABC/download/report.pdf', 'slack_send')).toBe(false);
    for (const bad of ['/files-pri/T0MOCK1-F0ABC/download/..%2Fx', '/files-pri/T0MOCK1-F0ABC/download/a%2Fb', '/files-pri/T0MOCK1-F0ABC/a/b/c', '/files-tmb/T0MOCK1-F0ABC/x', '/upload/v1/a/b']) {
      for (const c of caps) expect(isAllowedRoute('slackfiles', 'GET', bad, c)).toBe(false);
    }
    for (const c of caps) expect(isAllowedRoute('slackfiles', 'DELETE', '/files-pri/T0MOCK1-F0ABC/download/x', c)).toBe(false);
  });
});

describe('slack_add_reaction / slack_remove_reaction [MOCK Slack]', () => {
  it('adds and removes reactions; repeats count as success', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    const args = { workspaceId: wsId, channelId: 'C0GENERAL', ts: THEIR_TS, emoji: 'white_check_mark' };
    expect((await call(client, 'slack_add_reaction', args)).body).toMatchObject({ status: 'added', workspaceId: wsId });
    expect((await call(client, 'slack_add_reaction', args)).body).toMatchObject({ status: 'already_present' });
    expect(team.reactions).toEqual([{ channel: 'C0GENERAL', ts: THEIR_TS, name: 'white_check_mark' }]);
    expect((await call(client, 'slack_remove_reaction', args)).body).toMatchObject({ status: 'removed' });
    expect((await call(client, 'slack_remove_reaction', args)).body).toMatchObject({ status: 'not_present' });
    expect(team.reactions).toEqual([]);
  });

  it('refuses invalid emoji names and reports Slack errors', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    const calls = slack.calls.length;
    for (const emoji of [':thumbsup:', 'Thumbsup', 'a b', '', 'x'.repeat(101)]) {
      expect((await call(client, 'slack_add_reaction', { workspaceId: wsId, channelId: 'C0GENERAL', ts: MY_TS, emoji })).isError).toBe(true);
    }
    const ctx = createPerchContext(store, slack.transport);
    await expect(ctx.slack.addReaction(principal, { workspaceId: wsId, channelId: 'C0GENERAL', ts: MY_TS, emoji: ':x:' })).rejects.toMatchObject({ code: 'bad_argument' });
    expect(slack.calls.length).toBe(calls);
    const r = await call(client, 'slack_add_reaction', { workspaceId: wsId, channelId: 'C0GENERAL', ts: '1760009999.000999', emoji: 'eyes' });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/message_not_found/);
  });

  it('denies a workspace outside the grant without contacting Slack', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    const calls = slack.calls.length;
    const r = await call(client, 'slack_add_reaction', { workspaceId: otherId, channelId: 'C0OTHER', ts: MY_TS, emoji: 'eyes' });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/not granted/);
    const u = await call(client, 'slack_upload_file', { workspaceId: otherId, channelId: 'C0OTHER', filename: 'a.txt', contentBase64: b64('a'), requestId: rid() });
    expect(u.isError).toBe(true);
    expect(String(u.body.error)).toMatch(/not granted/);
    expect(slack.calls.length).toBe(calls);
    expect(other.reactions).toEqual([]);
  });

  it('fails closed after the grant is revoked on a live session', async () => {
    const { id, principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    await removeClientGrant(store, id);
    const calls = slack.calls.length;
    expect((await call(client, 'slack_add_reaction', { workspaceId: wsId, channelId: 'C0GENERAL', ts: MY_TS, emoji: 'eyes' })).isError).toBe(true);
    expect(slack.calls.length).toBe(calls);
  });
});

describe('slack_edit_message [MOCK Slack]', () => {
  it('edits own messages and explains why others cannot be edited', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    const ok = await call(client, 'slack_edit_message', { workspaceId: wsId, channelId: 'C0GENERAL', ts: MY_TS, text: 'fixed typo' });
    expect(ok.body).toMatchObject({ status: 'updated', ts: MY_TS });
    expect(team.edits).toEqual([{ channel: 'C0GENERAL', ts: MY_TS, text: 'fixed typo' }]);
    const bad = await call(client, 'slack_edit_message', { workspaceId: wsId, channelId: 'C0GENERAL', ts: THEIR_TS, text: 'hijack' });
    expect(bad.isError).toBe(true);
    expect(String(bad.body.error)).toMatch(/only messages written by the connected user/);
    expect(team.channels[0]!.messages[1]!.text).toBe('their message');
  });
});

describe('slack_upload_file [MOCK Slack]', () => {
  it('uploads through files.slack.com and shares into a thread with a comment', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    const r = await call(client, 'slack_upload_file', {
      workspaceId: wsId,
      channelId: 'C0GENERAL',
      filename: 'report.txt',
      contentBase64: b64('hello file'),
      title: 'Report',
      initialComment: 'here you go',
      threadTs: MY_TS,
      requestId: rid(),
    });
    expect(r.isError).toBe(false);
    expect(r.body).toMatchObject({ status: 'accepted', replayed: false, workspaceId: wsId, channelId: 'C0GENERAL', fileId: 'F0MOCK1' });
    const file = team.files.find((f) => f.id === 'F0MOCK1')!;
    expect(file.content!.toString()).toBe('hello file');
    expect(file.title).toBe('Report');
    expect(file.shared).toEqual({ channel_id: 'C0GENERAL', thread_ts: MY_TS, initial_comment: 'here you go' });
    const up = fileHostCalls();
    expect(up).toHaveLength(1);
    expect(up[0]!.method).toBe('POST');
    // The pre-signed upload URL never receives the token.
    expect(up[0]!.headers.authorization).toBeUndefined();
    expect(new URLSearchParams(apiCalls('files.getUploadURLExternal')[0]!.body).get('length')).toBe('10');
  });

  it('replays a repeated requestId without uploading again and refuses changed content', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    const args = { workspaceId: wsId, channelId: 'C0GENERAL', filename: 'a.txt', contentBase64: b64('one'), requestId: rid() };
    const first = await call(client, 'slack_upload_file', args);
    expect(first.body).toMatchObject({ status: 'accepted', fileId: 'F0MOCK1' });
    const calls = slack.calls.length;
    const again = await call(client, 'slack_upload_file', args);
    expect(again.body).toMatchObject({ status: 'accepted', replayed: true, fileId: 'F0MOCK1' });
    const conflict = await call(client, 'slack_upload_file', { ...args, contentBase64: b64('two') });
    expect(conflict.isError).toBe(true);
    expect(String(conflict.body.error)).toMatch(/already used/);
    expect(slack.calls.length).toBe(calls);
    expect(team.files).toHaveLength(1);
  });

  it('never sends bytes to an upload_url outside https://files.slack.com/upload/v1/', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    const hostile = [
      'https://evil.example/upload/v1/abc',
      'https://files.slack.com.evil.example/upload/v1/abc',
      'http://files.slack.com/upload/v1/abc',
      'https://files.slack.com:8443/upload/v1/abc',
      'https://user:pw@files.slack.com/upload/v1/abc',
      'https://files.slack.com/upload/v2/abc',
      'https://files.slack.com/upload/v1/abc?redirect=https://evil.example',
      'https://files.slack.com/upload/v1/abc#x',
      'https://files.slack.com/upload/v1/../../api/chat.delete',
      'https://files.slack.com/upload/v1/a/b',
      'https://slack.com/api/chat.delete',
      'not a url',
    ];
    for (const url of hostile) {
      slack.uploadUrlOverride = url;
      const r = await call(client, 'slack_upload_file', { workspaceId: wsId, channelId: 'C0GENERAL', filename: 'a.txt', contentBase64: b64('x'), requestId: rid() });
      expect(r.body, url).toMatchObject({ status: 'rejected' });
      expect(String(r.body.detail)).toMatch(/refusing/);
    }
    expect(fileHostCalls()).toHaveLength(0);
    expect(apiCalls('files.completeUploadExternal')).toHaveLength(0);
    expect(slack.calls.every((c) => c.url.origin === 'https://slack.com')).toBe(true);
  });

  it('enforces the size limit and strict base64 before any Slack call', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    const calls = slack.calls.length;
    const tooBig = Buffer.alloc(MAX_SLACK_FILE_BYTES + 1).toString('base64');
    const r = await call(client, 'slack_upload_file', { workspaceId: wsId, channelId: 'C0GENERAL', filename: 'big.bin', contentBase64: tooBig, requestId: rid() });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/exceeds/);
    for (const contentBase64 of ['not base64!', 'YQ', 'YQ==YQ==']) {
      expect((await call(client, 'slack_upload_file', { workspaceId: wsId, channelId: 'C0GENERAL', filename: 'a.txt', contentBase64, requestId: rid() })).isError).toBe(true);
    }
    for (const filename of ['../etc/passwd', 'a\\b', 'line\nbreak']) {
      expect((await call(client, 'slack_upload_file', { workspaceId: wsId, channelId: 'C0GENERAL', filename, contentBase64: b64('a'), requestId: rid() })).isError).toBe(true);
    }
    expect(slack.calls.length).toBe(calls);
    // Exactly the limit is accepted.
    const max = Buffer.alloc(MAX_SLACK_FILE_BYTES, 1).toString('base64');
    const ok = await call(client, 'slack_upload_file', { workspaceId: wsId, channelId: 'C0GENERAL', filename: 'max.bin', contentBase64: max, requestId: rid() });
    expect(ok.body).toMatchObject({ status: 'accepted' });
  });

  it('reports a lost completion as indeterminate and never repeats it; a refusal as rejected', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    slack.completeMode = { kind: 'throw' };
    const args = { workspaceId: wsId, channelId: 'C0GENERAL', filename: 'a.txt', contentBase64: b64('x'), requestId: rid() };
    expect((await call(client, 'slack_upload_file', args)).body).toMatchObject({ status: 'indeterminate', replayed: false });
    slack.completeMode = { kind: 'ok' };
    const calls = slack.calls.length;
    expect((await call(client, 'slack_upload_file', args)).body).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(slack.calls.length).toBe(calls);
    slack.completeMode = { kind: 'error', code: 'not_in_channel' };
    const refused = await call(client, 'slack_upload_file', { ...args, requestId: rid() });
    expect(refused.body).toMatchObject({ status: 'rejected' });
    expect(String(refused.body.detail)).toMatch(/not_in_channel/);
  });
});

describe('missing scopes [MOCK Slack]', () => {
  it('asks to reconnect when a workspace lacks the new scopes, before any call', async () => {
    const old = slack.addTeam('Old', { scopes: ['channels:read', 'channels:history', 'chat:write'] });
    old.channels.push({ id: 'C0OLD', kind: 'public_channel', messages: [{ ts: MY_TS, user: old.userId, text: 'x' }] });
    const oldId = (await addSlackWorkspace(store, new Upstream(slack.transport), { label: 'Old', token: old.token })).id;
    const { principal } = await grant(['slack_read', 'slack_send'], [oldId]);
    const client = await clientFor(principal);
    const calls = slack.calls.length;
    const ctx = createPerchContext(store, slack.transport);
    await expect(ctx.slack.addReaction(principal, { workspaceId: oldId, channelId: 'C0OLD', ts: MY_TS, emoji: 'eyes' })).rejects.toMatchObject({ code: 'provider_scope_missing' });
    await expect(ctx.slack.getFile(principal, { workspaceId: oldId, fileId: 'F0ABC' })).rejects.toMatchObject({ code: 'provider_scope_missing' });
    for (const [name, args] of [
      ['slack_add_reaction', { workspaceId: oldId, channelId: 'C0OLD', ts: MY_TS, emoji: 'eyes' }],
      ['slack_remove_reaction', { workspaceId: oldId, channelId: 'C0OLD', ts: MY_TS, emoji: 'eyes' }],
      ['slack_upload_file', { workspaceId: oldId, channelId: 'C0OLD', filename: 'a.txt', contentBase64: b64('a'), requestId: rid() }],
      ['slack_get_file', { workspaceId: oldId, fileId: 'F0ABC' }],
    ] as const) {
      const r = await call(client, name, args);
      expect(r.isError, name).toBe(true);
      expect(String(r.body.error)).toMatch(/Reconnect: perch slack add .* --session/);
    }
    expect(slack.calls.length).toBe(calls);
    // Editing needs only chat:write, which the old manifest had.
    expect((await call(client, 'slack_edit_message', { workspaceId: oldId, channelId: 'C0OLD', ts: MY_TS, text: 'y' })).body).toMatchObject({ status: 'updated' });
  });
});

describe('slack_get_file [MOCK Slack]', () => {
  beforeEach(() => {
    team.files.push({ id: 'F0DOC', name: 'notes v1.txt', mimetype: 'text/plain', content: Buffer.from('file body') });
  });

  it('returns metadata and base64 content with the token, for the operator', async () => {
    const client = await clientFor(READONLY_PRINCIPAL);
    const r = await call(client, 'slack_get_file', { workspaceId: wsId, fileId: 'F0DOC' });
    expect(r.isError).toBe(false);
    expect(r.body).toMatchObject({ workspaceId: wsId, fileId: 'F0DOC', name: 'notes v1.txt', mimetype: 'text/plain', size: 9, bytes: 9 });
    expect(Buffer.from(String(r.body.contentBase64), 'base64').toString()).toBe('file body');
    expect(JSON.stringify(r.body)).not.toContain('files-pri');
    const dl = fileHostCalls();
    expect(dl).toHaveLength(1);
    expect(dl[0]!.url.href).toBe(`https://files.slack.com/files-pri/${team.teamId}-F0DOC/download/notes%20v1.txt`);
    expect(dl[0]!.headers.authorization).toBe(`Bearer ${team.token}`);
  });

  it('refuses files above maxBytes instead of truncating, without downloading', async () => {
    const client = await clientFor((await grant(['slack_read'], [wsId])).principal);
    const r = await call(client, 'slack_get_file', { workspaceId: wsId, fileId: 'F0DOC', maxBytes: 4 });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/raise maxBytes/);
    expect(fileHostCalls()).toHaveLength(0);
    expect((await call(client, 'slack_get_file', { workspaceId: wsId, fileId: 'F0DOC', maxBytes: MAX_SLACK_FILE_BYTES + 1 })).isError).toBe(true);
  });

  it('never fetches a download URL outside files.slack.com/files-pri/<team>-<file>/', async () => {
    const client = await clientFor(READONLY_PRINCIPAL);
    const file = team.files[0]!;
    for (const url of [
      'https://evil.example/files-pri/T0MOCK1-F0DOC/download/x',
      'http://files.slack.com/files-pri/T0MOCK1-F0DOC/download/x',
      'https://files.slack.com.evil.example/files-pri/T0MOCK1-F0DOC/download/x',
      'https://files.slack.com:444/files-pri/T0MOCK1-F0DOC/download/x',
      `https://files.slack.com/files-pri/${team.teamId}-F0OTHER/download/x`,
      `https://files.slack.com/files-pri/${team.teamId}-F0DOC/download/x?u=https://evil.example`,
      `https://files.slack.com/files-pri/${team.teamId}-F0DOC/download/a%2F..%2Fb`,
      'https://files.slack.com/upload/v1/abc',
      'https://slack.com/api/chat.delete',
    ]) {
      file.downloadUrl = url;
      const r = await call(client, 'slack_get_file', { workspaceId: wsId, fileId: 'F0DOC' });
      expect(r.isError, url).toBe(true);
      expect(String(r.body.error)).toMatch(/refusing/);
    }
    expect(fileHostCalls()).toHaveLength(0);
  });

  it('rejects an HTML login page instead of returning it as the file, and denies other workspaces', async () => {
    const client = await clientFor((await grant(['slack_read'], [wsId])).principal);
    team.files[0]!.content = undefined;
    team.files.push({ id: 'F0EMPTY', name: 'x.txt', mimetype: 'text/plain' });
    const r = await call(client, 'slack_get_file', { workspaceId: wsId, fileId: 'F0EMPTY' });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/web page instead of the file/);
    const calls = slack.calls.length;
    const denied = await call(client, 'slack_get_file', { workspaceId: otherId, fileId: 'F0DOC' });
    expect(String(denied.body.error)).toMatch(/not granted/);
    expect((await call(client, 'slack_get_file', { workspaceId: wsId, fileId: '../F0DOC' })).isError).toBe(true);
    expect(slack.calls.length).toBe(calls);
  });
});

describe('audit [MOCK Slack]', () => {
  it('records attempts and outcomes without content, names, emoji or channels', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    await call(client, 'slack_add_reaction', { workspaceId: wsId, channelId: 'C0GENERAL', ts: THEIR_TS, emoji: 'tada' });
    await call(client, 'slack_edit_message', { workspaceId: wsId, channelId: 'C0GENERAL', ts: MY_TS, text: 'secret edit' });
    await call(client, 'slack_edit_message', { workspaceId: wsId, channelId: 'C0GENERAL', ts: THEIR_TS, text: 'secret hijack' });
    await call(client, 'slack_upload_file', { workspaceId: wsId, channelId: 'C0GENERAL', filename: 'secret-name.txt', contentBase64: b64('secret bytes'), requestId: rid() });
    const ledger = await new MailWorkflowLedger(store).read();
    const of = (t: string) => ledger.audit.filter((e) => e.type === t).map((e) => e.outcome);
    expect(of('slack_add_reaction')).toEqual(['attempt', 'ok']);
    expect(of('slack_edit_message')).toEqual(['attempt', 'ok', 'attempt', 'error']);
    expect(of('slack_send_message')).toEqual(['pending', 'accepted']);
    expect(ledger.audit.every((e) => !e.accountId || e.accountId === wsId)).toBe(true);
    const dump = JSON.stringify(ledger);
    for (const s of ['secret', 'tada', 'C0GENERAL', b64('secret bytes'), MY_TS, THEIR_TS]) expect(dump).not.toContain(s);
  });
});
