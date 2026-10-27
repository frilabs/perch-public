// Slack DMs / group DMs and scheduled messages (docs/MAIL_CALENDAR_SLACK_SPEC.md §3) through the real MCP SDK
// client (in-memory transport) against the MOCK Slack Web API. Covers grants, scopes, the schedule window,
// idempotency, listing, cancelling, workspace isolation and that posted messages stay undeletable.
// No live Slack calls: passing tests are NOT evidence of a live integration.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { createPerchContext } from '../src/context.js';
import { createMcpServer } from '../src/mcp/server.js';
import { slackExtraTools } from '../src/mcp/tools/slackExtra.js';
import { addSlackWorkspace, SLACK_USER_SCOPES } from '../src/slack/slack.js';
import { SLACK_APP_MANIFEST } from '../src/slack/manifest.js';
import { collectStatus, formatStatusText } from '../src/status/status.js';
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

const NEW_WRITES = ['slack_open_conversation', 'slack_schedule_message', 'slack_cancel_scheduled_message'];
const PARENT_TS = '1760000100.000100';

async function clientFor(principal: Principal) {
  const mcp = createMcpServer(createPerchContext(store, slack.transport), principal);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await mcp.connect(b);
  const client = new Client({ name: 'slack-scheduled-test', version: '0' });
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

const rid = () => `slack-s-${Math.random().toString(16).slice(2, 14)}`;
const apiCalls = (method: string) => slack.calls.filter((c) => c.url.pathname === `/api/${method}`);
const inSeconds = (s: number) => Math.floor(Date.now() / 1000) + s;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  slack = new MockSlack();
  team = slack.addTeam('A');
  other = slack.addTeam('B');
  team.users = { U0ALICE: 'Alice', U0BOB: 'Bob', U0CAROL: 'Carol' };
  other.users = { U0ALICE: 'Alice (B)' };
  team.channels.push({ id: 'C0GENERAL', name: 'general', kind: 'public_channel', messages: [{ ts: PARENT_TS, user: 'U0ALICE', text: 'hi' }] });
  team.channels.push({ id: 'C0RANDOM', name: 'random', kind: 'public_channel', messages: [] });
  other.channels.push({ id: 'C0OTHER', name: 'other', kind: 'public_channel', messages: [] });
  const upstream = new Upstream(slack.transport);
  wsId = (await addSlackWorkspace(store, upstream, { label: 'Company', token: team.token })).id;
  otherId = (await addSlackWorkspace(store, upstream, { label: 'Other', token: other.token })).id;
});

afterEach(async () => {
  vi.useRealTimers();
  await dirs.cleanup();
});

describe('Slack DMs and scheduled messages: exposure and allowlist [MOCK Slack]', () => {
  it('gives the operator and slack_read only the list tool, slack_send only the writes', async () => {
    const op = (await (await clientFor(READONLY_PRINCIPAL)).listTools()).tools.map((t) => t.name);
    expect(op).toContain('slack_list_scheduled_messages');
    for (const w of NEW_WRITES) expect(op).not.toContain(w);
    const reader = (await (await clientFor((await grant(['slack_read'], [wsId])).principal)).listTools()).tools.map((t) => t.name);
    expect(reader).toContain('slack_list_scheduled_messages');
    for (const w of NEW_WRITES) expect(reader).not.toContain(w);
    const sender = (await (await clientFor((await grant(['slack_send'], [wsId])).principal)).listTools()).tools.map((t) => t.name);
    expect(sender).not.toContain('slack_list_scheduled_messages');
    for (const w of NEW_WRITES) expect(sender).toContain(w);
    expect(slackExtraTools.writeTools).toEqual(expect.arrayContaining(NEW_WRITES));
    expect(slackExtraTools.readTools).toContain('slack_list_scheduled_messages');
  });

  it('allowlists the new methods behind the right tag; chat.delete and channel management stay blocked', async () => {
    const caps: RouteCapability[] = ['read', 'send', 'slack_send', 'admin', 'draft'];
    for (const m of ['conversations.open', 'chat.scheduleMessage', 'chat.deleteScheduledMessage']) {
      expect(isAllowedRoute('slack', 'POST', `/api/${m}`, 'slack_send')).toBe(true);
      expect(isAllowedRoute('slack', 'POST', `/api/${m}`)).toBe(false);
      expect(isAllowedRoute('slack', 'GET', `/api/${m}`)).toBe(false);
    }
    expect(isAllowedRoute('slack', 'GET', '/api/chat.scheduledMessages.list')).toBe(true);
    expect(isAllowedRoute('slack', 'GET', '/api/chat.scheduledMessages.list', 'slack_send')).toBe(false);
    expect(isAllowedRoute('slack', 'POST', '/api/chat.scheduledMessages.list', 'slack_send')).toBe(false);
    for (const m of ['chat.delete', 'conversations.create', 'conversations.archive', 'conversations.kick', 'conversations.invite', 'conversations.close', 'chat.deleteScheduledMessages']) {
      for (const method of ['GET', 'POST', 'DELETE']) for (const c of caps) expect(isAllowedRoute('slack', method, `/api/${m}`, c), m).toBe(false);
    }
    const calls = slack.calls.length;
    await expect(
      new Upstream(slack.transport).json('slack', { method: 'POST', path: '/api/chat.delete', capability: 'slack_send', headers: { authorization: `Bearer ${team.token}` }, json: { channel: 'C0GENERAL', ts: PARENT_TS } }),
    ).rejects.toMatchObject({ code: 'route_not_allowed' });
    expect(slack.calls.length).toBe(calls);
  });

  it('keeps the manifest and the code scopes in sync and asks for im:write and mpim:write', () => {
    expect(SLACK_APP_MANIFEST.oauth_config.scopes.user).toEqual([...SLACK_USER_SCOPES]);
    expect(SLACK_USER_SCOPES).toEqual(expect.arrayContaining(['im:write', 'mpim:write']));
  });
});

describe('slack_open_conversation [MOCK Slack]', () => {
  it('opens a DM with one user and a group DM with several; repeats return the same conversation', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    const dm = await call(client, 'slack_open_conversation', { workspaceId: wsId, users: ['U0ALICE'] });
    expect(dm.isError).toBe(false);
    expect(dm.body).toMatchObject({ workspaceId: wsId, type: 'im', channelId: expect.stringMatching(/^D/), alreadyOpen: false, users: ['U0ALICE'] });
    const again = await call(client, 'slack_open_conversation', { workspaceId: wsId, users: ['U0ALICE'] });
    expect(again.body).toMatchObject({ channelId: dm.body.channelId, alreadyOpen: true });
    const group = await call(client, 'slack_open_conversation', { workspaceId: wsId, users: ['U0ALICE', 'U0BOB', 'U0CAROL'] });
    expect(group.body).toMatchObject({ type: 'mpim', channelId: expect.stringMatching(/^G/), alreadyOpen: false });
    expect(new URLSearchParams(apiCalls('conversations.open').at(-1)!.body).get('users')).toBe('U0ALICE,U0BOB,U0CAROL');
    // The opened DM is then writable with slack_send_message.
    const sent = await call(client, 'slack_send_message', { workspaceId: wsId, channelId: dm.body.channelId, text: 'hello', requestId: rid() });
    expect(sent.body).toMatchObject({ status: 'accepted' });
    expect(team.posted.at(-1)).toMatchObject({ channel: dm.body.channelId, text: 'hello' });
  });

  it('enforces 1-8 distinct valid user ids before any Slack call', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    const ctx = createPerchContext(store, slack.transport);
    const calls = slack.calls.length;
    const nine = Array.from({ length: 9 }, (_, i) => `U0USER${i}`);
    for (const users of [[], nine, ['U0ALICE', 'U0ALICE'], ['alice'], ['C0GENERAL'], ['U0ALICE', '']]) {
      expect((await call(client, 'slack_open_conversation', { workspaceId: wsId, users })).isError, JSON.stringify(users)).toBe(true);
    }
    await expect(ctx.slack.openConversation(principal, { workspaceId: wsId, users: nine })).rejects.toMatchObject({ code: 'bad_argument' });
    await expect(ctx.slack.openConversation(principal, { workspaceId: wsId, users: ['U0ALICE', 'U0ALICE'] })).rejects.toMatchObject({ code: 'bad_argument' });
    expect(slack.calls.length).toBe(calls);
    // Exactly eight is allowed (Slack decides whether all users exist).
    team.users = Object.fromEntries(nine.slice(0, 8).map((u) => [u, u]));
    expect((await call(client, 'slack_open_conversation', { workspaceId: wsId, users: nine.slice(0, 8) })).body).toMatchObject({ type: 'mpim' });
    const unknown = await call(client, 'slack_open_conversation', { workspaceId: wsId, users: ['U0NOBODY'] });
    expect(unknown.isError).toBe(true);
    expect(String(unknown.body.error)).toMatch(/user_not_found/);
  });

  it('needs im:write for DMs and mpim:write for group DMs, checked before any call', async () => {
    const old = slack.addTeam('Old', { scopes: ['channels:read', 'im:read', 'chat:write', 'im:write'] });
    old.users = { U0ALICE: 'Alice', U0BOB: 'Bob' };
    const oldId = (await addSlackWorkspace(store, new Upstream(slack.transport), { label: 'Old', token: old.token })).id;
    const client = await clientFor((await grant(['slack_send'], [oldId])).principal);
    expect((await call(client, 'slack_open_conversation', { workspaceId: oldId, users: ['U0ALICE'] })).body).toMatchObject({ type: 'im' });
    const calls = slack.calls.length;
    const g = await call(client, 'slack_open_conversation', { workspaceId: oldId, users: ['U0ALICE', 'U0BOB'] });
    expect(g.isError).toBe(true);
    expect(String(g.body.error)).toMatch(/lacks mpim:write\. Reconnect: perch slack add/);
    expect(slack.calls.length).toBe(calls);
  });
});

describe('slack_schedule_message [MOCK Slack]', () => {
  it('schedules with Unix seconds or RFC 3339, in a thread, and returns the scheduled message id', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    const at = inSeconds(3600);
    const r = await call(client, 'slack_schedule_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'later', postAt: at, threadTs: PARENT_TS, requestId: rid() });
    expect(r.isError).toBe(false);
    expect(r.body).toMatchObject({ status: 'accepted', replayed: false, workspaceId: wsId, channelId: 'C0GENERAL', scheduledMessageId: 'Q0MOCK1', postAt: new Date(at * 1000).toISOString() });
    expect(r.body).not.toHaveProperty('providerMessageId');
    expect(team.scheduled).toEqual([expect.objectContaining({ id: 'Q0MOCK1', channel: 'C0GENERAL', text: 'later', post_at: at, thread_ts: PARENT_TS })]);
    expect(team.posted).toEqual([]);
    const iso = new Date((at + 60) * 1000).toISOString().replace('.000Z', '+00:00');
    const r2 = await call(client, 'slack_schedule_message', { workspaceId: wsId, channelId: 'C0RANDOM', text: 'iso', postAt: iso, requestId: rid() });
    expect(r2.body).toMatchObject({ status: 'accepted', scheduledMessageId: 'Q0MOCK2' });
    expect(team.scheduled[1]!.post_at).toBe(at + 60);
  });

  it('accepts 60 s to 120 days ahead and refuses anything else before any Slack call', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    const calls = slack.calls.length;
    for (const postAt of [inSeconds(30), inSeconds(-10), inSeconds(121 * 86_400), 0, -5, 1.5, 'tomorrow', '2026-10-21 09:00', '2026-10-21T09:00:00']) {
      const r = await call(client, 'slack_schedule_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'x', postAt, requestId: rid() });
      expect(r.isError, String(postAt)).toBe(true);
    }
    const ctx = createPerchContext(store, slack.transport);
    await expect(ctx.slack.scheduleMessage(principal, { workspaceId: wsId, channelId: 'C0GENERAL', text: 'x', postAt: inSeconds(10), requestId: rid() })).rejects.toMatchObject({
      code: 'bad_argument',
      message: expect.stringMatching(/at least 60 seconds/),
    });
    await expect(ctx.slack.scheduleMessage(principal, { workspaceId: wsId, channelId: 'C0GENERAL', text: 'x', postAt: inSeconds(130 * 86_400), requestId: rid() })).rejects.toMatchObject({
      message: expect.stringMatching(/at most 120 days/),
    });
    expect(slack.calls.length).toBe(calls);
    for (const postAt of [inSeconds(90), inSeconds(119 * 86_400)]) {
      expect((await call(client, 'slack_schedule_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'ok', postAt, requestId: rid() })).body).toMatchObject({ status: 'accepted' });
    }
  });

  it('replays a repeated requestId (also after the window passed) and refuses changed content', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    const at = inSeconds(300);
    const args = { workspaceId: wsId, channelId: 'C0GENERAL', text: 'standup', postAt: at, requestId: rid() };
    expect((await call(client, 'slack_schedule_message', args)).body).toMatchObject({ status: 'accepted', scheduledMessageId: 'Q0MOCK1' });
    const calls = slack.calls.length;
    // Same instant written as RFC 3339: the same canonical request.
    const sameIso = { ...args, postAt: new Date(at * 1000).toISOString() };
    expect((await call(client, 'slack_schedule_message', sameIso)).body).toMatchObject({ status: 'accepted', replayed: true, scheduledMessageId: 'Q0MOCK1' });
    const conflict = await call(client, 'slack_schedule_message', { ...args, text: 'other' });
    expect(conflict.isError).toBe(true);
    expect(String(conflict.body.error)).toMatch(/already used/);
    vi.setSystemTime(Date.now() + 3600_000);
    expect((await call(client, 'slack_schedule_message', args)).body).toMatchObject({ status: 'accepted', replayed: true, scheduledMessageId: 'Q0MOCK1' });
    // A new requestId for the now past time is refused locally.
    expect((await call(client, 'slack_schedule_message', { ...args, requestId: rid() })).isError).toBe(true);
    expect(slack.calls.length).toBe(calls);
    expect(team.scheduled).toHaveLength(1);
  });

  it('reports a lost response as indeterminate and never repeats it; a refusal as rejected', async () => {
    const client = await clientFor((await grant(['slack_send'], [wsId])).principal);
    slack.scheduleMode = { kind: 'throw' };
    const args = { workspaceId: wsId, channelId: 'C0GENERAL', text: 'x', postAt: inSeconds(600), requestId: rid() };
    expect((await call(client, 'slack_schedule_message', args)).body).toMatchObject({ status: 'indeterminate', replayed: false });
    slack.scheduleMode = { kind: 'ok' };
    const calls = slack.calls.length;
    expect((await call(client, 'slack_schedule_message', args)).body).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(slack.calls.length).toBe(calls);
    slack.scheduleMode = { kind: 'error', code: 'not_in_channel' };
    const refused = await call(client, 'slack_schedule_message', { ...args, requestId: rid() });
    expect(refused.body).toMatchObject({ status: 'rejected' });
    expect(String(refused.body.detail)).toMatch(/Not scheduled: .*not_in_channel/);
    slack.scheduleMode = { kind: 'http', status: 503 };
    expect((await call(client, 'slack_schedule_message', { ...args, requestId: rid() })).body).toMatchObject({ status: 'indeterminate' });
    expect(team.scheduled).toEqual([]);
  });
});

describe('slack_list_scheduled_messages / slack_cancel_scheduled_message [MOCK Slack]', () => {
  async function scheduleThree(client: Client) {
    for (const [channelId, text, s] of [
      ['C0GENERAL', 'one', 600],
      ['C0RANDOM', 'two', 1200],
      ['C0GENERAL', 'three', 1800],
    ] as const) {
      expect((await call(client, 'slack_schedule_message', { workspaceId: wsId, channelId, text, postAt: inSeconds(s), requestId: rid() })).body).toMatchObject({ status: 'accepted' });
    }
  }

  it('lists pending scheduled messages with paging and a channel filter', async () => {
    const { principal } = await grant(['slack_read', 'slack_send'], [wsId]);
    const client = await clientFor(principal);
    await scheduleThree(client);
    const all = await call(client, 'slack_list_scheduled_messages', { workspaceId: wsId });
    expect(all.body).toMatchObject({ workspaceId: wsId, hasMore: false, nextCursor: null });
    expect((all.body.messages as Array<{ text: string }>).map((m) => m.text)).toEqual(['one', 'two', 'three']);
    expect((all.body.messages as unknown[])[0]).toMatchObject({ scheduledMessageId: 'Q0MOCK1', channelId: 'C0GENERAL', postAt: expect.any(String), createdAt: expect.any(String) });
    const general = await call(client, 'slack_list_scheduled_messages', { workspaceId: wsId, channelId: 'C0GENERAL' });
    expect((general.body.messages as Array<{ text: string }>).map((m) => m.text)).toEqual(['one', 'three']);
    const p1 = await call(client, 'slack_list_scheduled_messages', { workspaceId: wsId, pageSize: 2 });
    expect((p1.body.messages as unknown[]).length).toBe(2);
    expect(p1.body.hasMore).toBe(true);
    const p2 = await call(client, 'slack_list_scheduled_messages', { workspaceId: wsId, pageSize: 2, cursor: p1.body.nextCursor });
    expect((p2.body.messages as Array<{ text: string }>).map((m) => m.text)).toEqual(['three']);
    // The cursor is bound to workspace and filter.
    expect((await call(client, 'slack_list_scheduled_messages', { workspaceId: wsId, channelId: 'C0RANDOM', pageSize: 2, cursor: p1.body.nextCursor })).isError).toBe(true);
    expect((await call(client, 'slack_list_scheduled_messages', { workspaceId: wsId, pageSize: 101 })).isError).toBe(true);
    // The read-only operator can list too.
    const op = await call(await clientFor(READONLY_PRINCIPAL), 'slack_list_scheduled_messages', { workspaceId: wsId });
    expect((op.body.messages as unknown[]).length).toBe(3);
  });

  it('cancels a pending scheduled message once; a second cancel or a bad id fails', async () => {
    const { principal } = await grant(['slack_read', 'slack_send'], [wsId]);
    const client = await clientFor(principal);
    await scheduleThree(client);
    const ok = await call(client, 'slack_cancel_scheduled_message', { workspaceId: wsId, channelId: 'C0GENERAL', scheduledMessageId: 'Q0MOCK1' });
    expect(ok.body).toMatchObject({ status: 'cancelled', scheduledMessageId: 'Q0MOCK1', channelId: 'C0GENERAL' });
    expect(team.scheduled.map((m) => m.id)).toEqual(['Q0MOCK2', 'Q0MOCK3']);
    const again = await call(client, 'slack_cancel_scheduled_message', { workspaceId: wsId, channelId: 'C0GENERAL', scheduledMessageId: 'Q0MOCK1' });
    expect(again.isError).toBe(true);
    expect(String(again.body.error)).toMatch(/already posted, cancelled or never existed/);
    // Wrong conversation for the id.
    expect((await call(client, 'slack_cancel_scheduled_message', { workspaceId: wsId, channelId: 'C0GENERAL', scheduledMessageId: 'Q0MOCK2' })).isError).toBe(true);
    const calls = slack.calls.length;
    for (const scheduledMessageId of ['1760000100.000100', 'q0mock2', 'F0FILE', '']) {
      expect((await call(client, 'slack_cancel_scheduled_message', { workspaceId: wsId, channelId: 'C0RANDOM', scheduledMessageId })).isError).toBe(true);
    }
    expect(slack.calls.length).toBe(calls);
    expect(team.scheduled.map((m) => m.id)).toEqual(['Q0MOCK2', 'Q0MOCK3']);
    // Only deleteScheduledMessage was used, never chat.delete.
    expect(apiCalls('chat.delete')).toHaveLength(0);
  });
  it('after a cancel, the scheduling requestId still replays "accepted" and slack_send_status shows the scheduled message id', async () => {
    const client = await clientFor((await grant(['slack_read', 'slack_send'], [wsId])).principal);
    const args = { workspaceId: wsId, channelId: 'C0GENERAL', text: 'later', postAt: inSeconds(600), requestId: rid() };
    expect((await call(client, 'slack_schedule_message', args)).body).toMatchObject({ status: 'accepted', scheduledMessageId: 'Q0MOCK1' });
    expect((await call(client, 'slack_send_status', { workspaceId: wsId, requestId: args.requestId })).body).toMatchObject({ status: 'accepted', scheduledMessageId: 'Q0MOCK1' });
    expect((await call(client, 'slack_cancel_scheduled_message', { workspaceId: wsId, channelId: 'C0GENERAL', scheduledMessageId: 'Q0MOCK1' })).body).toMatchObject({ status: 'cancelled' });
    const calls = slack.calls.length;
    expect((await call(client, 'slack_schedule_message', args)).body).toMatchObject({ status: 'accepted', replayed: true, scheduledMessageId: 'Q0MOCK1' });
    const status = (await call(client, 'slack_send_status', { workspaceId: wsId, requestId: args.requestId })).body;
    expect(status).toMatchObject({ status: 'accepted', scheduledMessageId: 'Q0MOCK1' });
    expect(status).not.toHaveProperty('messageTs');
    expect(slack.calls.length).toBe(calls);
    expect(team.scheduled).toEqual([]);
  });
});

describe('capability gating and workspace isolation [MOCK Slack]', () => {
  it('denies writes without slack_send and listing without slack_read, before any Slack call', async () => {
    const reader = (await grant(['slack_read'], [wsId])).principal;
    const sender = (await grant(['slack_send'], [wsId])).principal;
    const ctx = createPerchContext(store, slack.transport);
    const calls = slack.calls.length;
    for (const p of [reader, READONLY_PRINCIPAL]) {
      await expect(ctx.slack.openConversation(p, { workspaceId: wsId, users: ['U0ALICE'] })).rejects.toMatchObject({ code: 'capability_denied' });
      await expect(ctx.slack.scheduleMessage(p, { workspaceId: wsId, channelId: 'C0GENERAL', text: 'x', postAt: inSeconds(600), requestId: rid() })).rejects.toMatchObject({
        code: 'capability_denied',
      });
      await expect(ctx.slack.cancelScheduledMessage(p, { workspaceId: wsId, channelId: 'C0GENERAL', scheduledMessageId: 'Q0MOCK1' })).rejects.toMatchObject({ code: 'capability_denied' });
    }
    await expect(ctx.slack.listScheduledMessages(sender, { workspaceId: wsId })).rejects.toMatchObject({ code: 'capability_denied' });
    expect(slack.calls.length).toBe(calls);
  });

  it('keeps workspaces apart: no access outside the grant, no cross-workspace ids', async () => {
    const both = await clientFor((await grant(['slack_read', 'slack_send'], [wsId, otherId])).principal);
    expect((await call(both, 'slack_schedule_message', { workspaceId: otherId, channelId: 'C0OTHER', text: 'b', postAt: inSeconds(900), requestId: rid() })).body).toMatchObject({
      status: 'accepted',
      scheduledMessageId: 'Q0MOCK1',
    });
    const onlyA = await clientFor((await grant(['slack_read', 'slack_send'], [wsId])).principal);
    const calls = slack.calls.length;
    for (const [name, args] of [
      ['slack_open_conversation', { workspaceId: otherId, users: ['U0ALICE'] }],
      ['slack_schedule_message', { workspaceId: otherId, channelId: 'C0OTHER', text: 'x', postAt: inSeconds(900), requestId: rid() }],
      ['slack_list_scheduled_messages', { workspaceId: otherId }],
      ['slack_cancel_scheduled_message', { workspaceId: otherId, channelId: 'C0OTHER', scheduledMessageId: 'Q0MOCK1' }],
    ] as const) {
      const r = await call(onlyA, name, args);
      expect(r.isError, name).toBe(true);
      expect(String(r.body.error)).toMatch(/not granted/);
    }
    expect(slack.calls.length).toBe(calls);
    // Workspace A sees none of B's scheduled messages and cannot cancel them with A's token.
    expect((await call(onlyA, 'slack_list_scheduled_messages', { workspaceId: wsId })).body.messages).toEqual([]);
    expect((await call(onlyA, 'slack_cancel_scheduled_message', { workspaceId: wsId, channelId: 'C0OTHER', scheduledMessageId: 'Q0MOCK1' })).isError).toBe(true);
    expect(other.scheduled).toHaveLength(1);
    // A cursor from workspace A is not valid for workspace B.
    team.scheduled.push(
      { id: 'Q0A1', channel: 'C0GENERAL', text: 'a1', post_at: inSeconds(1000), date_created: inSeconds(0) },
      { id: 'Q0A2', channel: 'C0GENERAL', text: 'a2', post_at: inSeconds(2000), date_created: inSeconds(0) },
    );
    const page = await call(both, 'slack_list_scheduled_messages', { workspaceId: wsId, pageSize: 1 });
    expect((await call(both, 'slack_list_scheduled_messages', { workspaceId: otherId, pageSize: 1, cursor: page.body.nextCursor })).isError).toBe(true);
  });
});

describe('missing DM scopes in perch status [MOCK Slack]', () => {
  it('shows a reconnect hint for a workspace without im:write/mpim:write, not an error', async () => {
    const old = slack.addTeam('Old', { scopes: SLACK_USER_SCOPES.filter((s) => s !== 'im:write' && s !== 'mpim:write') });
    const oldId = (await addSlackWorkspace(store, new Upstream(slack.transport), { label: 'Old', token: old.token })).id;
    const report = await collectStatus(createPerchContext(store, slack.transport), { live: false });
    const row = report.accounts.find((a) => a.id === oldId)!;
    expect(row.hint).toMatch(/lacks im:write, mpim:write; reconnect: perch slack add --label Old/);
    expect(row.permissions).not.toMatch(/open dm/);
    expect(report.accounts.find((a) => a.id === wsId)).not.toHaveProperty('hint');
    expect(report.accounts.find((a) => a.id === wsId)!.permissions).toMatch(/open dm/);
    expect(formatStatusText(report)).toMatch(new RegExp(`${oldId}.*\\n\\s+hint: token lacks im:write, mpim:write`));
  });
});
