// Slack posting through the real MCP SDK client (in-memory transport) against the MOCK Slack Web API.
// Covers grants, idempotency, outcomes and audit. No live Slack calls.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, removeClientGrant, type Principal } from '../src/auth/grants.js';
import { createPerchContext } from '../src/context.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { createMcpServer } from '../src/mcp/server.js';
import { addSlackWorkspace } from '../src/slack/slack.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockSlack, type MockSlackTeam } from './support/mockSlack.js';

let dirs: TempDirs;
let store: CredentialStore;
let slack: MockSlack;
let team: MockSlackTeam;
let other: MockSlackTeam;
let wsId: string;
let otherId: string;

async function clientFor(principal: Principal) {
  const mcp = createMcpServer(createPerchContext(store, slack.transport), principal);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await mcp.connect(b);
  const client = new Client({ name: 'slack-test', version: '0' });
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
    return { isError: r.isError === true, body: JSON.parse(text) as Record<string, unknown> };
  } catch (err) {
    return { isError: true, body: { error: (err as Error).message } };
  }
}

const rid = () => `slack-test-${Math.random().toString(16).slice(2, 14)}`;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  slack = new MockSlack();
  team = slack.addTeam('A');
  other = slack.addTeam('B');
  team.channels.push({ id: 'C0GENERAL', name: 'general', kind: 'public_channel', messages: [] });
  other.channels.push({ id: 'C0OTHER', name: 'other', kind: 'public_channel', messages: [] });
  const upstream = new Upstream(slack.transport);
  wsId = (await addSlackWorkspace(store, upstream, { label: 'Company', token: team.token })).id;
  otherId = (await addSlackWorkspace(store, upstream, { label: 'Other', token: other.token })).id;
});

afterEach(async () => {
  await dirs.cleanup();
});

describe('slack_send_message [MOCK Slack]', () => {
  it('is not offered to the read-only global token', async () => {
    const client = await clientFor(READONLY_PRINCIPAL);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('slack_search');
    expect(names).not.toContain('slack_send_message');
    expect(names).not.toContain('slack_send_status');
  });

  it('posts once per requestId; a repeat replays the stored outcome without posting again', async () => {
    const { principal } = await grant(['slack_read', 'slack_send'], [wsId]);
    const client = await clientFor(principal);
    const args = { workspaceId: wsId, channelId: 'C0GENERAL', text: 'Hello from Perch', requestId: rid() };
    const first = await call(client, 'slack_send_message', args);
    expect(first.isError).toBe(false);
    expect(first.body).toMatchObject({ status: 'accepted', replayed: false, workspaceId: wsId, channelId: 'C0GENERAL' });
    expect(first.body.messageTs).toMatch(/^\d{10}\.\d{6}$/);
    const again = await call(client, 'slack_send_message', args);
    expect(again.body).toMatchObject({ status: 'accepted', replayed: true, messageTs: first.body.messageTs });
    expect(team.posted).toEqual([{ channel: 'C0GENERAL', text: 'Hello from Perch' }]);
    const status = await call(client, 'slack_send_status', { workspaceId: wsId, requestId: args.requestId });
    expect(status.body).toMatchObject({ status: 'accepted', operationId: first.body.operationId, messageTs: first.body.messageTs });
  });

  it('refuses a reused requestId with different content before any request', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    const requestId = rid();
    await call(client, 'slack_send_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'one', requestId });
    const calls = slack.calls.length;
    const r = await call(client, 'slack_send_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'two', requestId });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/already used/);
    expect(slack.calls.length).toBe(calls);
    expect(team.posted).toHaveLength(1);
  });

  it('posts thread replies', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    await call(client, 'slack_send_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'reply', threadTs: '1760000100.000100', replyBroadcast: true, requestId: rid() });
    expect(team.posted).toEqual([{ channel: 'C0GENERAL', text: 'reply', thread_ts: '1760000100.000100', reply_broadcast: true }]);
  });

  it('denies a workspace outside the grant without contacting Slack', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    const calls = slack.calls.length;
    const r = await call(client, 'slack_send_message', { workspaceId: otherId, channelId: 'C0OTHER', text: 'x', requestId: rid() });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/not granted/);
    expect(slack.calls.length).toBe(calls);
    expect(other.posted).toHaveLength(0);
  });

  it('reports a Slack refusal as rejected and never retries it', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    slack.postMode = { kind: 'error', code: 'not_in_channel' };
    const args = { workspaceId: wsId, channelId: 'C0GENERAL', text: 'x', requestId: rid() };
    const r = await call(client, 'slack_send_message', args);
    expect(r.body).toMatchObject({ status: 'rejected' });
    expect(String(r.body.detail)).toMatch(/not_in_channel/);
    slack.postMode = { kind: 'ok' };
    expect((await call(client, 'slack_send_message', args)).body).toMatchObject({ status: 'rejected', replayed: true });
    expect(team.posted).toHaveLength(0);
  });

  it('reports a lost response as indeterminate and never resends it', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    slack.postMode = { kind: 'throw' };
    const args = { workspaceId: wsId, channelId: 'C0GENERAL', text: 'x', requestId: rid() };
    expect((await call(client, 'slack_send_message', args)).body).toMatchObject({ status: 'indeterminate', replayed: false });
    slack.postMode = { kind: 'ok' };
    const calls = slack.calls.length;
    expect((await call(client, 'slack_send_message', args)).body).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(slack.calls.length).toBe(calls);
  });

  it('treats HTTP 5xx as indeterminate and 429 as rejected', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    slack.postMode = { kind: 'http', status: 503 };
    expect((await call(client, 'slack_send_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'x', requestId: rid() })).body.status).toBe('indeterminate');
    slack.postMode = { kind: 'http', status: 429 };
    expect((await call(client, 'slack_send_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'y', requestId: rid() })).body.status).toBe('rejected');
  });

  it('fails closed after the grant is revoked on a live session', async () => {
    const { id, principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    await removeClientGrant(store, id);
    const calls = slack.calls.length;
    const r = await call(client, 'slack_send_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'x', requestId: rid() });
    expect(r.isError).toBe(true);
    expect(slack.calls.length).toBe(calls);
  });

  it('audits attempts and outcomes without content', async () => {
    const { principal } = await grant(['slack_send'], [wsId]);
    const client = await clientFor(principal);
    await call(client, 'slack_send_message', { workspaceId: wsId, channelId: 'C0GENERAL', text: 'secret text', requestId: rid() });
    const ledger = await new MailWorkflowLedger(store).read();
    const events = ledger.audit.filter((e) => e.type === 'slack_send_message');
    expect(events.map((e) => e.outcome)).toEqual(['pending', 'accepted']);
    expect(events.every((e) => e.provider === 'slack' && e.accountId === wsId)).toBe(true);
    expect(JSON.stringify(ledger)).not.toContain('secret text');
    expect(JSON.stringify(ledger)).not.toContain('C0GENERAL');
  });
});
