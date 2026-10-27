// MCP layer of the mail workflow and the shared audit runner, through the real MCP SDK client.
// Part 1 uses MOCK mail providers; part 2 uses a MOCK world (Calendar). Nothing reaches a real provider;
// secrets are dummies.
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, removeClientGrant, type Principal } from '../src/auth/grants.js';
import { createPerchContext, type PerchContext } from '../src/context.js';
import { MailService, type MailProviders } from '../src/mail/service.js';
import type { MailProvider } from '../src/mail/types.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { generateHttpToken, startHttpServer, type RunningHttpServer } from '../src/mcp/http.js';
import { createMcpServer, WRITE_TOOL_NAMES } from '../src/mcp/server.js';
import { CredentialStore, initStore, type Capability } from '../src/store/credentialStore.js';
import type { UpstreamTransport } from '../src/upstream.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';
import { createWorld, IDS, seedWorld, worldContext } from './support/worldFixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
let providerCalls: string[];

const MARK = {
  text: 'BODY-MARKER-a1b2c3',
  subject: 'SUBJECT-MARKER-d4e5',
  to: 'rcpt-marker-77@example.test',
  cc: 'cc-marker-88@example.test',
  file: 'ATTACH-NAME-MARKER.txt',
  content: Buffer.from('ATTACH-CONTENT-MARKER').toString('base64'),
  requestId: 'REQ-MARKER-mcp-0001',
  query: 'QUERY-MARKER-xyz',
  messageId: 'imap:SU5CT1g:1:7',
};

const noNetwork: UpstreamTransport = async () => {
  throw new Error('MOCK: no upstream expected');
};

function mockProvider(): MailProvider<{ id: string }> {
  return {
    kind: 'imap',
    providerCapabilities: () => ({ draft: true, send: true }),
    search: async () => (providerCalls.push('search'), { items: [{ messageId: MARK.messageId, subject: 'Mock subject' }] }),
    read: async (_a, id) => (providerCalls.push('read'), { messageId: id, subject: 'Mock subject', text: 'Mock body', truncated: false, attachments: [] }),
    getAttachment: async () => (providerCalls.push('attachment'), { attachmentId: '2', contentType: 'text/plain', size: 2, contentBase64: 'aGk=' }),
    replyContext: async () => (providerCalls.push('replyContext'), { references: [] }),
    createDraft: async () => (providerCalls.push('draft'), { draftId: 'imap:RHJhZnRz:1:1' }),
    send: async () => (providerCalls.push('send'), { status: 'accepted', providerMessageId: 'gmailid_XYZ', detail: 'MOCK accepted' }),
  };
}

function context(): PerchContext {
  const p = mockProvider() as unknown as MailProviders['imap'];
  return { ...createPerchContext(store, noNetwork), mail: new MailService(store, { gmail: p, microsoft: p, imap: p } as unknown as MailProviders) };
}

async function addImap(id: string, email: string) {
  const now = new Date().toISOString();
  await store.update((d) => {
    d.imap.push({
      id,
      label: `LABEL-MARKER ${id}`,
      email,
      username: email,
      password: dummySecret('PW'),
      imap: { host: 'imap.gmx.net', port: 993 },
      smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
      allowDrafts: true,
      allowSend: true,
      createdAt: now,
      updatedAt: now,
    });
  });
}

async function grant(s: CredentialStore, capabilities: Capability[], accountIds: string[]) {
  const tokenFile = path.join(dirs.root, 'config', 'clients', `${Math.random().toString(16).slice(2)}.token`);
  const { client } = await createClientGrant(s, { label: 'CLIENT-LABEL-MARKER', capabilities, accountIds, tokenFile });
  return { client, token: (await readFile(tokenFile, 'utf8')).trim() };
}

async function memory(principal: Principal, ctx = context()) {
  const mcp = createMcpServer(ctx, principal);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await mcp.connect(b);
  const c = new Client({ name: 'audit-mem', version: '0' });
  await c.connect(a);
  return c;
}

async function call(c: Client, name: string, args: Record<string, unknown> = {}) {
  try {
    const r = await c.callTool({ name, arguments: args });
    const text = (r.content as Array<{ text: string }>)[0]?.text ?? '';
    return { isError: r.isError === true, text, json: r.isError ? undefined : JSON.parse(text) };
  } catch (err) {
    return { isError: true, text: (err as Error).message, json: undefined };
  }
}

const send = (over: Record<string, unknown> = {}) => ({
  accountId: 'imap-0000000a',
  requestId: MARK.requestId,
  to: [MARK.to],
  cc: [MARK.cc],
  subject: MARK.subject,
  text: MARK.text,
  attachments: [{ filename: MARK.file, contentType: 'text/plain', contentBase64: MARK.content }],
  ...over,
});

const audit = async (s = store) => (await new MailWorkflowLedger(s).read()).audit;

describe('mail workflow and audit over MCP [MOCK providers]', () => {
  beforeEach(async () => {
    dirs = await makeTempDirs();
    await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    providerCalls = [];
    await addImap('imap-0000000a', 'owner-a@example.test');
    await addImap('imap-0000000b', 'owner-b@example.test');
  });
  afterEach(async () => {
    await dirs.cleanup();
  });

  it('requires an explicit, validated requestId on mail_send and offers mail_send_status to send grants only', async () => {
    const { token } = await grant(store, ['send'], ['imap-0000000a']);
    const c = await memory((await principalForClientToken(store, token))!);
    const tools = (await c.listTools()).tools;
    expect(tools.map((t) => t.name).sort()).toEqual(['mail_send', 'mail_send_draft', 'mail_send_status', 'perch_list_accounts']);
    const sendTool = tools.find((t) => t.name === 'mail_send')!;
    expect(sendTool.inputSchema.required).toContain('requestId');
    expect(sendTool.description).toMatch(/requestId/);
    for (const requestId of [undefined, 'short', 'has space 123', 'x'.repeat(129), 'new\nline-123']) {
      const r = await call(c, 'mail_send', send({ requestId }));
      expect(r.isError, String(requestId)).toBe(true);
    }
    expect(providerCalls).toEqual([]);
    const operator = await memory(READONLY_PRINCIPAL);
    const names = (await operator.listTools()).tools.map((t) => t.name);
    for (const w of WRITE_TOOL_NAMES) expect(names).not.toContain(w);
    expect(WRITE_TOOL_NAMES).toContain('mail_send_status');
  });

  it('replays a repeated send without provider I/O and reports status; accepted is not delivered', async () => {
    const { token } = await grant(store, ['send'], ['imap-0000000a']);
    const c = await memory((await principalForClientToken(store, token))!);
    const first = await call(c, 'mail_send', send());
    expect(first.json).toMatchObject({ status: 'accepted', replayed: false, requestState: 'accepted' });
    const again = await call(c, 'mail_send', send());
    expect(again.json).toMatchObject({ status: 'accepted', replayed: true, operationId: first.json.operationId });
    const conflict = await call(c, 'mail_send', send({ text: 'changed' }));
    expect(conflict.isError).toBe(true);
    expect(conflict.text).toMatch(/already used for a different message/);
    const status = await call(c, 'mail_send_status', { accountId: 'imap-0000000a', requestId: MARK.requestId });
    expect(status.json).toMatchObject({ status: 'accepted', requestState: 'accepted', operationId: first.json.operationId });
    expect(status.json.detail).toMatch(/not proof of delivery/i);
    expect(status.text).not.toContain(MARK.text);
    expect(providerCalls).toEqual(['send']);
  });

  it("keeps another client's status invisible and denies status/replay after narrowing or revocation, before any I/O", async () => {
    const owner = await grant(store, ['send'], ['imap-0000000a']);
    const c = await memory((await principalForClientToken(store, owner.token))!);
    expect((await call(c, 'mail_send', send())).json.status).toBe('accepted');
    const other = await grant(store, ['send'], ['imap-0000000a']);
    const o = await memory((await principalForClientToken(store, other.token))!);
    const peek = await call(o, 'mail_send_status', { accountId: 'imap-0000000a', requestId: MARK.requestId });
    expect(peek.isError).toBe(true);
    expect(peek.text).toMatch(/No send with this requestId/);
    expect(peek.text).not.toContain('op-');

    // Narrowed: send moved to another account -> the cached result and status are no longer revealed.
    await store.update((d) => void (d.clients.find((x) => x.id === owner.client.id)!.accountIds = ['imap-0000000b']));
    for (const [tool, args] of [
      ['mail_send', send()],
      ['mail_send_status', { accountId: 'imap-0000000a', requestId: MARK.requestId }],
    ] as const) {
      const r = await call(c, tool, args);
      expect(r.isError, tool).toBe(true);
      expect(r.text, tool).toMatch(/not granted/);
      expect(r.text).not.toMatch(/accepted|op-/);
    }
    await removeClientGrant(store, owner.client.id);
    for (const tool of ['mail_send', 'mail_send_status']) {
      const r = await call(c, tool, tool === 'mail_send' ? send() : { accountId: 'imap-0000000a', requestId: MARK.requestId });
      expect(r.text, tool).toMatch(/revoked/);
    }
    expect(providerCalls).toEqual(['send']);
  });

  it('audits every tool call with allowlisted fields only (no body, recipients, attachments, queries, ids, labels or tokens)', async () => {
    const full = await grant(store, ['read', 'draft', 'send'], ['imap-0000000a']);
    const p = (await principalForClientToken(store, full.token))!;
    const c = await memory(p);
    const op = await memory(READONLY_PRINCIPAL);
    expect((await call(op, 'perch_list_accounts')).isError).toBe(false);
    expect((await call(op, 'mail_search', { query: MARK.query })).isError).toBe(false);
    expect((await call(op, 'drive_search', { query: MARK.query, accountId: 'google-0000000a' })).isError).toBe(true);
    expect((await call(c, 'mail_read_message', { accountId: 'imap-0000000a', messageId: MARK.messageId })).isError).toBe(false);
    expect((await call(c, 'mail_get_attachment', { accountId: 'imap-0000000a', messageId: MARK.messageId, attachmentId: '2' })).isError).toBe(false);
    expect((await call(c, 'mail_create_draft', send({ requestId: undefined }))).isError).toBe(false);
    expect((await call(c, 'mail_send', send())).isError).toBe(false);
    expect((await call(c, 'mail_send', send())).isError).toBe(false);
    expect((await call(c, 'mail_send', send({ text: 'changed' }))).isError).toBe(true);
    expect((await call(c, 'mail_send_status', { accountId: 'imap-0000000a', requestId: MARK.requestId })).isError).toBe(false);
    expect((await call(c, 'mail_read_message', { accountId: 'imap-0000000b', messageId: MARK.messageId })).isError).toBe(true);

    const events = await audit();
    const client = { kind: 'client', clientId: full.client.id };
    const operator = { kind: 'operator_readonly' };
    expect(events.map((e) => [e.type, e.outcome, e.actor, e.accountId ?? null, e.provider ?? null, e.code ?? null])).toEqual([
      // The mail part of the cross-provider account list is audited by MailService itself (direct calls too).
      ['mail_list_accounts', 'ok', operator, null, null, null],
      ['perch_list_accounts', 'ok', operator, null, null, null],
      ['mail_search', 'ok', operator, null, null, null],
      ['drive_search', 'denied', operator, 'google-0000000a', 'drive', 'unknown_account'],
      ['mail_read_message', 'ok', client, 'imap-0000000a', 'imap', null],
      ['mail_get_attachment', 'ok', client, 'imap-0000000a', 'imap', null],
      ['mail_create_draft', 'attempt', client, 'imap-0000000a', 'imap', null],
      ['mail_create_draft', 'ok', client, 'imap-0000000a', 'imap', null],
      ['mail_send', 'pending', client, 'imap-0000000a', 'imap', null],
      ['mail_send', 'accepted', client, 'imap-0000000a', 'imap', 'provider_accepted'],
      ['mail_send', 'replayed', client, 'imap-0000000a', 'imap', 'accepted'],
      ['mail_send', 'conflict', client, 'imap-0000000a', 'imap', 'idempotency_conflict'],
      ['mail_send_status', 'ok', client, 'imap-0000000a', 'imap', null],
      ['mail_read_message', 'denied', client, 'imap-0000000b', 'imap', 'capability_denied'],
    ]);
    for (const e of events) {
      expect(Object.keys(e).every((k) => ['at', 'ns', 'actor', 'operationId', 'type', 'accountId', 'provider', 'outcome', 'code'].includes(k))).toBe(true);
      expect(e.ns).toBe('root');
    }
    // Attempt and outcome of one write share the operation id; every send event shares the send's id.
    expect(events[6]!.operationId).toBe(events[7]!.operationId);
    expect(new Set(events.slice(8, 12).map((e) => e.operationId)).size).toBe(1);
    const json = JSON.stringify(await new MailWorkflowLedger(store).read());
    for (const marker of [...Object.values(MARK), 'LABEL-MARKER', 'CLIENT-LABEL-MARKER', 'owner-a@example.test', 'Mock subject', 'Mock body', full.token, 'DUMMY-TEST']) {
      expect(json, marker).not.toContain(marker);
    }
  });

  it('fails write tools closed before provider I/O when the audit ledger cannot be written, and withholds read results', async () => {
    const full = await grant(store, ['read', 'draft', 'send'], ['imap-0000000a']);
    const c = await memory((await principalForClientToken(store, full.token))!);
    await writeFile(path.join(dirs.dataDir, 'mail-workflow.enc'), 'corrupt', { mode: 0o600 });
    const draft = await call(c, 'mail_create_draft', send({ requestId: undefined }));
    expect(draft.isError).toBe(true);
    expect(draft.text).toMatch(/ledger/i);
    const sent = await call(c, 'mail_send', send());
    expect(sent.isError).toBe(true);
    expect(providerCalls).toEqual([]);
    const read = await call(c, 'mail_read_message', { accountId: 'imap-0000000a', messageId: MARK.messageId });
    expect(read.isError).toBe(true);
    expect(read.text).toMatch(/withheld/i);
    expect(read.text).not.toContain('Mock body');
  });
});

describe('calendar audit [MOCK world]', () => {
  let world: ReturnType<typeof createWorld>;
  let ctx: PerchContext;

  async function persistent(token: string) {
    const principal = (await principalForClientToken(store, token))!;
    const mcp = createMcpServer(ctx, principal);
    const [x, y] = InMemoryTransport.createLinkedPair();
    await mcp.connect(y);
    const c = new Client({ name: 'cal', version: '0' });
    await c.connect(x);
    return c;
  }

  beforeEach(async () => {
    dirs = await makeTempDirs();
    await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    world = createWorld('A', []);
    await seedWorld(store, world);
    ctx = worldContext(store, world, []);
  });
  afterEach(async () => {
    await dirs.cleanup();
  });

  it('audits calendar writes (attempt + outcome) and provider reads with safe fields only', async () => {
    const cal = await grant(store, ['calendar_read', 'calendar_write'], [IDS.gprod]);
    const c = await persistent(cal.token);
    const created = await call(c, 'calendar_create_event', {
      accountId: IDS.gprod,
      requestId: 'cal-request-0001',
      summary: 'SUMMARY-MARKER-cal',
      start: { date: '2026-10-09' },
      end: { date: '2026-10-10' },
    });
    expect(created.isError, created.text).toBe(false);
    expect((await call(c, 'calendar_list_events', { accountId: IDS.gprod, timeMin: '2026-10-01T00:00:00Z' })).isError).toBe(false);
    const events = await audit(store);
    expect(events.map((e) => [e.type, e.outcome, e.provider])).toEqual([
      ['calendar_create_event', 'attempt', 'google_productivity'],
      ['calendar_create_event', 'ok', 'google_productivity'],
      ['calendar_list_events', 'ok', 'google_productivity'],
    ]);
    const json = JSON.stringify(await new MailWorkflowLedger(store).read());
    expect(json).not.toMatch(/SUMMARY-MARKER|cal-request-0001|event \d of A|prod\.A@example/);
  });
});
