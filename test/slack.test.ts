// Slack read operations and onboarding against the MOCK Slack Web API. No live Slack calls.
import { readFile } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../src/audit/audit.js';
import { createClientGrant, principalFromGrant, READONLY_PRINCIPAL } from '../src/auth/grants.js';
import { SendWorkflow } from '../src/mail/workflow.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { SLACK_APP_MANIFEST } from '../src/slack/manifest.js';
import { addSlackWorkspace, removeSlackWorkspace, SlackService } from '../src/slack/slack.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { isAllowedRoute, Upstream } from '../src/upstream.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockSlack, mockTs, type MockSlackTeam } from './support/mockSlack.js';

let dirs: TempDirs;
let store: CredentialStore;
let slack: MockSlack;
let upstream: Upstream;
let service: SlackService;
let teamA: MockSlackTeam;
let teamB: MockSlackTeam;
let idA: string;
let idB: string;
let sleeps: number[];

const READ_CALLS = /^GET \/api\/(auth\.test|conversations\.(list|history|replies)|users\.info|search\.messages)$/;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  slack = new MockSlack();
  teamA = slack.addTeam('A');
  teamB = slack.addTeam('B', { scopes: ['channels:read', 'channels:history', 'users:read'] });
  teamA.users = { U0ALICE: 'Alice Example', U0BOB: 'Bob Example' };
  teamA.channels.push(
    {
      id: 'C0GENERAL',
      name: 'general',
      kind: 'public_channel',
      messages: [
        { ts: '1760000100.000100', user: 'U0ALICE', text: 'Launch plan is ready', reply_count: 2, thread_ts: '1760000100.000100' },
        { ts: '1760000200.000200', user: 'U0BOB', text: 'Thanks!', files: [{ name: 'plan.pdf', mimetype: 'application/pdf', size: 10 }] },
      ],
      replies: {
        '1760000100.000100': [
          { ts: '1760000100.000100', user: 'U0ALICE', text: 'Launch plan is ready', thread_ts: '1760000100.000100' },
          { ts: '1760000150.000150', user: 'U0BOB', text: 'Looks good', thread_ts: '1760000100.000100' },
        ],
      },
    },
    { id: 'C0RANDOM', name: 'random', kind: 'public_channel', messages: [] },
    { id: 'D0ALICE', user: 'U0ALICE', kind: 'im', messages: [{ ts: '1760000300.000300', user: 'U0ALICE', text: 'launch tomorrow?' }] },
  );
  teamB.channels.push({ id: 'C0BGEN', name: 'b-general', kind: 'public_channel', messages: [{ ts: '1760000400.000400', text: 'launch in B' }] });
  upstream = new Upstream(slack.transport);
  idA = (await addSlackWorkspace(store, upstream, { label: 'Company', token: teamA.token })).id;
  idB = (await addSlackWorkspace(store, upstream, { label: 'Community', token: teamB.token })).id;
  sleeps = [];
  const ledger = new MailWorkflowLedger(store);
  service = new SlackService(store, upstream, new SendWorkflow(ledger), new AuditLog(ledger), { sleep: async (ms) => void sleeps.push(ms) });
});

afterEach(async () => {
  // Reads never reach a write method; every call carries the workspace's bearer token.
  for (const c of slack.calls) {
    if (c.url.pathname !== '/api/chat.postMessage') expect(READ_CALLS.test(`${c.method} ${c.url.pathname}`)).toBe(true);
    expect(c.headers.authorization).toMatch(/^Bearer xoxp-/);
  }
  await dirs.cleanup();
});

describe('Slack onboarding [mock Slack]', () => {
  it('validates the user token with auth.test and stores team, user and granted scopes', async () => {
    const ws = (await store.read()).slack.find((w) => w.id === idA)!;
    expect(ws).toMatchObject({ label: 'Company', teamId: teamA.teamId, teamName: teamA.team, userId: teamA.userId, userName: teamA.user });
    expect(ws.scopes).toContain('chat:write');
    expect(idA).toMatch(/^slack-[a-f0-9]{8}$/);
  });

  it('refuses bot and rotating tokens before any request', async () => {
    const before = slack.calls.length;
    for (const token of ['xoxb-123-456-abcdefabcdef', 'xoxe.xoxp-1-abcdefabcdef', 'xapp-1-abcdefabcdef']) {
      expect((await rejection(addSlackWorkspace(store, upstream, { label: 'Bot', token }))).message).toMatch(/user token/);
    }
    expect(slack.calls.length).toBe(before);
  });

  it('rejects an invalid token without storing or echoing it', async () => {
    const token = 'xoxp-0000-invalid-token-value';
    const err = await rejection(addSlackWorkspace(store, upstream, { label: 'X', token }));
    expect(err.message).toMatch(/invalid_auth/);
    expect(err.message).not.toContain(token);
    expect((await store.read()).slack).toHaveLength(2);
  });

  it('rejects the same token or the same user in the same workspace twice', async () => {
    expect((await rejection(addSlackWorkspace(store, upstream, { label: 'Again', token: teamA.token }))).message).toMatch(/already connected/);
  });

  it('removes a workspace locally', async () => {
    await removeSlackWorkspace(store, idB);
    expect((await store.read()).slack.map((w) => w.id)).toEqual([idA]);
  });

  it('ships the manifest from docs/ unchanged, with user scopes only and no token rotation', async () => {
    const doc = JSON.parse(await readFile(new URL('../docs/slack-app-manifest.json', import.meta.url), 'utf8'));
    expect(doc).toEqual(SLACK_APP_MANIFEST);
    expect(SLACK_APP_MANIFEST.oauth_config.scopes).not.toHaveProperty('bot');
    expect(SLACK_APP_MANIFEST.settings.token_rotation_enabled).toBe(false);
  });
});

describe('Slack reads [mock Slack]', () => {
  it('lists conversations across workspaces with provenance and resolves DM user names', async () => {
    const r = await service.listConversations(READONLY_PRINCIPAL, {});
    const ids = r.results.map((c) => [c.workspaceId, c.channelId]);
    expect(ids).toEqual(expect.arrayContaining([[idA, 'C0GENERAL'], [idA, 'D0ALICE'], [idB, 'C0BGEN']]));
    expect(r.results.find((c) => c.channelId === 'D0ALICE')).toMatchObject({ type: 'im', user: 'U0ALICE', userName: 'Alice Example', workspaceLabel: 'Company' });
  });

  it('filters conversations by channel or user name', async () => {
    const byName = await service.listConversations(READONLY_PRINCIPAL, { query: 'rand' });
    expect(byName.results.map((c) => c.channelId)).toEqual(['C0RANDOM']);
    const byUser = await service.listConversations(READONLY_PRINCIPAL, { workspaceId: idA, query: 'alice' });
    expect(byUser.results.map((c) => c.channelId)).toEqual(['D0ALICE']);
  });

  it('reads history newest first with user names, thread hints and file metadata only', async () => {
    const r = await service.getHistory(READONLY_PRINCIPAL, { workspaceId: idA, channelId: 'C0GENERAL' });
    expect(r.messages.map((m) => m.text)).toEqual(['Thanks!', 'Launch plan is ready']);
    expect(r.messages[0]).toMatchObject({ userName: 'Bob Example', files: [{ name: 'plan.pdf', mimetype: 'application/pdf', size: 10 }] });
    expect(r.messages[1]).toMatchObject({ replyCount: 2 });
    expect(r.messages[0]!.time).toBe(new Date(1760000200000).toISOString());
    expect(r).toMatchObject({ workspaceId: idA, workspaceLabel: 'Company', channelId: 'C0GENERAL' });
  });

  it('paginates history with a sealed cursor bound to workspace and channel', async () => {
    const p1 = await service.getHistory(READONLY_PRINCIPAL, { workspaceId: idA, channelId: 'C0GENERAL', pageSize: 1 });
    expect(p1.hasMore).toBe(true);
    const p2 = await service.getHistory(READONLY_PRINCIPAL, { workspaceId: idA, channelId: 'C0GENERAL', pageSize: 1, cursor: p1.nextCursor! });
    expect(p2.messages.map((m) => m.text)).toEqual(['Launch plan is ready']);
    const calls = slack.calls.length;
    expect((await rejection(service.getHistory(READONLY_PRINCIPAL, { workspaceId: idA, channelId: 'C0RANDOM', cursor: p1.nextCursor! }))).message).toMatch(/cursor/i);
    expect(slack.calls.length).toBe(calls);
  });

  it('applies a time window', async () => {
    const r = await service.getHistory(READONLY_PRINCIPAL, { workspaceId: idA, channelId: 'C0GENERAL', oldest: new Date(1760000150000).toISOString() });
    expect(r.messages.map((m) => m.text)).toEqual(['Thanks!']);
  });

  it('reads a thread', async () => {
    const r = await service.getThread(READONLY_PRINCIPAL, { workspaceId: idA, channelId: 'C0GENERAL', threadTs: '1760000100.000100' });
    expect(r.messages.map((m) => m.text)).toEqual(['Launch plan is ready', 'Looks good']);
  });

  it('validates ids before any request', async () => {
    const calls = slack.calls.length;
    await expect(service.getHistory(READONLY_PRINCIPAL, { workspaceId: idA, channelId: '../../api/chat.postMessage' })).rejects.toThrow(/conversation id/);
    await expect(service.getThread(READONLY_PRINCIPAL, { workspaceId: idA, channelId: 'C0GENERAL', threadTs: 'x' })).rejects.toThrow(/timestamp/);
    await expect(service.getHistory(READONLY_PRINCIPAL, { workspaceId: 'slack-00000000', channelId: 'C0GENERAL' })).rejects.toThrow(/Unknown Slack workspace/);
    expect(slack.calls.length).toBe(calls);
  });

  it('searches all workspaces and reports a workspace without search:read as partial', async () => {
    const r = await service.search(READONLY_PRINCIPAL, { query: 'launch' });
    expect(r.results.map((m) => [m.workspaceId, m.channelId, m.text])).toEqual(
      expect.arrayContaining([
        [idA, 'C0GENERAL', 'Launch plan is ready'],
        [idA, 'D0ALICE', 'launch tomorrow?'],
      ]),
    );
    expect(r.partial).toBe(true);
    expect(r.errors[0]).toMatchObject({ accountId: idB });
    expect(r.errors[0]!.message).toMatch(/search:read/);
  });

  it('retries a rate-limited read with the sanitised Retry-After', async () => {
    slack.rateLimitQueue.push('2');
    const r = await service.getHistory(READONLY_PRINCIPAL, { workspaceId: idA, channelId: 'C0GENERAL' });
    expect(r.messages).toHaveLength(2);
    expect(sleeps).toEqual([2000]);
  });

  it('caps users.info lookups per call across all scans of a filtered listing', async () => {
    for (let i = 0; i < 300; i++) {
      const u = `U0X${String(i).padStart(4, '0')}`;
      teamA.users[u] = `Person ${i}`;
      teamA.channels.push({ id: `D0X${String(i).padStart(4, '0')}`, user: u, kind: 'im', messages: [] });
    }
    await service.listConversations(READONLY_PRINCIPAL, { workspaceId: idA, query: 'nobody-matches-this' });
    expect(slack.calls.filter((c) => c.url.pathname === '/api/users.info').length).toBeLessThanOrEqual(50);
  });

  it('limits a client grant to its own workspaces', async () => {
    const { client } = await createClientGrant(store, { label: 'A only', capabilities: ['slack_read'], accountIds: [idA], tokenFile: `${dirs.root}/c.token` });
    const p = principalFromGrant(client);
    const r = await service.listConversations(p, {});
    expect(new Set(r.results.map((c) => c.workspaceId))).toEqual(new Set([idA]));
    const calls = slack.calls.length;
    await expect(service.getHistory(p, { workspaceId: idB, channelId: 'C0BGEN' })).rejects.toThrow(/not granted/);
    expect(slack.calls.length).toBe(calls);
  });

  it('allowlists only the read methods plus the approved writes behind slack_send', () => {
    expect(isAllowedRoute('slack', 'GET', '/api/conversations.history')).toBe(true);
    expect(isAllowedRoute('slack', 'POST', '/api/chat.postMessage')).toBe(false);
    expect(isAllowedRoute('slack', 'POST', '/api/chat.postMessage', 'slack_send')).toBe(true);
    expect(isAllowedRoute('slack', 'POST', '/api/chat.update')).toBe(false);
    expect(isAllowedRoute('slack', 'POST', '/api/chat.update', 'slack_send')).toBe(true);
    for (const m of ['chat.delete', 'files.delete', 'files.sharedPublicURL', 'conversations.create', 'conversations.invite', 'files.upload', 'admin.users.list']) {
      expect(isAllowedRoute('slack', 'POST', `/api/${m}`, 'slack_send')).toBe(false);
      expect(isAllowedRoute('slack', 'GET', `/api/${m}`)).toBe(false);
    }
    expect(mockTs()).toMatch(/^\d{10}\.\d{6}$/);
  });
});
