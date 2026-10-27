// Real MCP SDK client over local HTTP (and in-memory transport) against the mail tools.
// Mail providers are MOCK fakes; no Gmail/Graph/IMAP/SMTP server is contacted.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, removeClientGrant } from '../src/auth/grants.js';
import { createPerchContext, type PerchContext } from '../src/context.js';
import { MailService, type MailProviders } from '../src/mail/service.js';
import type { MailProvider, OutgoingMime } from '../src/mail/types.js';
import { generateHttpToken, startHttpServer, type RunningHttpServer } from '../src/mcp/http.js';
import { createMcpServer, TOOL_NAMES, WRITE_TOOL_NAMES } from '../src/mcp/server.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import type { UpstreamTransport } from '../src/upstream.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
let server: RunningHttpServer | undefined;
let globalToken: string;
let sent: OutgoingMime[];
/** Every MOCK mail provider call (any operation), to prove denials happen before provider I/O. */
let providerCalls: string[];

const noNetwork: UpstreamTransport = async () => {
  throw new Error('MOCK: no upstream expected');
};

function mockImapProvider(): MailProvider<{ id: string }> {
  return {
    kind: 'imap',
    providerCapabilities: () => ({ draft: true, send: true }),
    search: async () => {
      providerCalls.push('search');
      return { items: [{ messageId: 'imap:SU5CT1g:1:7', subject: 'Mock subject' }] };
    },
    read: async (_a, id) => {
      providerCalls.push('read');
      return { messageId: id, subject: 'Mock subject', text: 'Mock body', truncated: false, attachments: [] };
    },
    getAttachment: async () => {
      providerCalls.push('attachment');
      return { attachmentId: '2', contentType: 'text/plain', size: 2, contentBase64: 'aGk=' };
    },
    replyContext: async () => {
      providerCalls.push('replyContext');
      return { references: [] };
    },
    createDraft: async () => {
      providerCalls.push('draft');
      return { draftId: 'imap:RHJhZnRz:1:1' };
    },
    send: async (_a, mail) => {
      providerCalls.push('send');
      sent.push(mail);
      return { status: 'accepted', detail: 'MOCK accepted' };
    },
  };
}

function context(): PerchContext {
  const imap = mockImapProvider() as unknown as MailProviders['imap'];
  const providers = { gmail: imap, microsoft: imap, imap } as unknown as MailProviders;
  return { ...createPerchContext(store, noNetwork), mail: new MailService(store, providers) };
}

async function addImap(id: string) {
  const now = new Date().toISOString();
  await store.update((d) => {
    d.imap.push({
      id,
      label: `GMX ${id}`,
      email: `${id}@example.test`,
      username: `${id}@example.test`,
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

/** Drive/Notion entries that a mail-only client must never see (dummy data only). */
async function addDriveAndNotion() {
  const now = new Date().toISOString();
  await store.update((d) => {
    d.google.push({
      id: 'google-0000000a',
      label: 'Drive secret label',
      email: 'drive.owner@example.test',
      clientId: dummySecret('C'),
      clientSecret: dummySecret('S'),
      refreshToken: dummySecret('RT'),
      scopes: ['https://www.googleapis.com/auth/drive.readonly'],
      createdAt: now,
      updatedAt: now,
    });
    d.notion.push({ id: 'notion-0000000a', label: 'Notion secret label', token: dummySecret('PAT'), createdAt: now, updatedAt: now });
  });
}

async function setGrant(id: string, change: { capabilities?: Array<'read' | 'draft' | 'send'>; accountIds?: string[] }) {
  await store.update((d) => {
    const g = d.clients.find((c) => c.id === id)!;
    if (change.capabilities) g.capabilities = change.capabilities;
    if (change.accountIds) g.accountIds = change.accountIds;
  });
}

/** Tool call that normalises "unknown tool" (thrown or isError) and transport failures to an error result. */
async function call(client: Client, name: string, args: Record<string, unknown>): Promise<{ isError: boolean; text: string }> {
  try {
    const r = await client.callTool({ name, arguments: args });
    return { isError: r.isError === true, text: (r.content as Array<{ text: string }>)[0]?.text ?? '' };
  } catch (err) {
    return { isError: true, text: (err as Error).message };
  }
}

async function grant(label: string, capabilities: Array<'read' | 'draft' | 'send'>, accountIds: string[]) {
  return createClientGrant(store, {
    label,
    capabilities,
    accountIds,
    tokenFile: `${dirs.root}/config/clients/${label.replace(/\W/g, '')}-${Math.random().toString(16).slice(2)}.token`,
  });
}

async function memoryClient(token: string) {
  const principal = (await principalForClientToken(store, token))!;
  const mcp = createMcpServer(context(), principal);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await mcp.connect(b);
  const client = new Client({ name: 'mem', version: '0' });
  await client.connect(a);
  return client;
}

async function connect(token: string) {
  const client = new Client({ name: 'mail-test', version: '0.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(server!.url), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  return client;
}

const parse = (r: Awaited<ReturnType<Client['callTool']>>) => JSON.parse((r.content as Array<{ text: string }>)[0]!.text);
// requestId is required on mail_send (mail workflow milestone); a fresh id per call keeps each call a new send.
const sendArgs = (accountId: string) => ({ accountId, to: ['friend@example.test'], subject: 'Hi', text: 'Body', requestId: `mcp-test-${Math.random().toString(16).slice(2, 14)}` });

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  globalToken = generateHttpToken();
  sent = [];
  providerCalls = [];
  await addImap('imap-0000000a');
  await addImap('imap-0000000b');
  server = await startHttpServer({ host: '127.0.0.1', port: 0, token: globalToken, context: context(), log: () => {} });
});
afterEach(async () => {
  await server?.close();
  server = undefined;
  await dirs.cleanup();
});

describe('mail MCP tools over HTTP [MOCK providers]', () => {
  it.each(['array', 'nested record'])('rejects excessive %s elements before schema validation and remains usable', async (shape) => {
    const { token } = await grant('Bounded sender', ['send'], ['imap-0000000a']);
    const client = await connect(token);
    try {
      const excessive = shape === 'array'
        ? { to: Array.from({ length: 10_001 }, () => null) }
        : { extra: { nested: Object.fromEntries(Array.from({ length: 10_001 }, (_, i) => [`key${i}`, null])) } };
      const result = await client.callTool({ name: 'mail_send', arguments: { ...sendArgs('imap-0000000a'), ...excessive } });
      expect(result.isError).toBe(true);
      expect((result.content as Array<{ text: string }>)[0]!.text).toContain('maximum of 10000 elements');
      expect(JSON.stringify(result).length).toBeLessThan(1000);
      expect(providerCalls).toEqual([]);
      expect(sent).toEqual([]);
      const next = parse(await client.callTool({ name: 'mail_send', arguments: sendArgs('imap-0000000a') }));
      expect(next.status).toBe('accepted');
      expect(sent).toHaveLength(1);
    } finally { await client.close(); }
  });

  it('keeps the global token read-only: no write tools listed, calls denied', async () => {
    const client = await connect(globalToken);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names.sort()).toEqual([...TOOL_NAMES].sort());
    for (const w of WRITE_TOOL_NAMES) expect(names).not.toContain(w);
    const search = parse(await client.callTool({ name: 'mail_search', arguments: {} }));
    expect(search.results[0]).toMatchObject({ accountId: 'imap-0000000a', accountLabel: 'GMX imap-0000000a', provider: 'imap' });
    const denied = await client.callTool({ name: 'mail_send', arguments: sendArgs('imap-0000000a') }).catch((e: Error) => ({ thrown: e }));
    expect('thrown' in denied ? true : (denied as { isError?: boolean }).isError).toBe(true);
    expect(sent).toEqual([]);
    await client.close();
  });

  it('lets a client token send only from its granted account', async () => {
    const { token } = await createClientGrant(store, {
      label: 'Laptop',
      capabilities: ['read', 'send'],
      accountIds: ['imap-0000000a'],
      tokenFile: `${dirs.root}/config/clients/laptop.token`,
    });
    const client = await connect(token);
    const tools = (await client.listTools()).tools;
    const send = tools.find((t) => t.name === 'mail_send')!;
    expect(send.annotations).toMatchObject({ readOnlyHint: false, idempotentHint: false });
    expect(tools.map((t) => t.name)).not.toContain('mail_create_draft');

    const other = await client.callTool({ name: 'mail_send', arguments: sendArgs('imap-0000000b') });
    expect(other.isError).toBe(true);
    expect(parse(other).error).toMatch(/not granted/i);
    expect(sent).toEqual([]);

    const ok = parse(await client.callTool({ name: 'mail_send', arguments: sendArgs('imap-0000000a') }));
    expect(ok).toMatchObject({ status: 'accepted', accountId: 'imap-0000000a', from: 'imap-0000000a@example.test' });
    expect(sent).toHaveLength(1);

    const accounts = parse(await client.callTool({ name: 'perch_list_accounts', arguments: {} }));
    expect(accounts.connection).toMatchObject({ kind: 'client', capabilities: ['read', 'send'] });
    // Least privilege: accounts outside the grant are not listed at all.
    expect(accounts.mail.map((m: { accountId: string }) => m.accountId)).toEqual(['imap-0000000a']);
    await client.close();
  });

  it('rejects a removed client token with 401', async () => {
    const { client: grant, token } = await createClientGrant(store, {
      label: 'Old',
      capabilities: ['send'],
      accountIds: ['imap-0000000a'],
      tokenFile: `${dirs.root}/config/clients/old.token`,
    });
    await removeClientGrant(store, grant.id);
    await expect(connect(token)).rejects.toThrow();
    await expect(connect(dummySecret('RANDOM-TOKEN-THAT-IS-LONG-ENOUGH-1234567890'))).rejects.toThrow();
  });
});

describe('client grants are mail-only and least-privilege [MOCK providers]', () => {
  it('gives a send-only HTTP client no Drive/Notion/read tools and no Drive/Notion/other-account metadata', async () => {
    await addDriveAndNotion();
    const { token } = await grant('Send only', ['send'], ['imap-0000000a']);
    const client = await connect(token);
    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual(['mail_send', 'mail_send_draft', 'mail_send_status', 'perch_list_accounts']);
    for (const n of names) expect(n).not.toMatch(/^(drive|notion)_/);
    for (const [tool, args] of [
      ['drive_search', { query: 'x' }],
      ['notion_search', {}],
      ['mail_search', {}],
    ] as const) {
      expect((await call(client, tool, args)).isError, tool).toBe(true);
    }
    const listed = await call(client, 'perch_list_accounts', {});
    expect(listed.isError).toBe(false);
    const accounts = JSON.parse(listed.text);
    expect(Object.keys(accounts).sort()).toEqual(['connection', 'mail']);
    expect(accounts.mail.map((m: { accountId: string }) => m.accountId)).toEqual(['imap-0000000a']);
    for (const leak of ['google-0000000a', 'drive.owner@example.test', 'Drive secret label', 'notion-0000000a', 'Notion secret label', 'imap-0000000b']) {
      expect(listed.text).not.toContain(leak);
    }
    expect(providerCalls).toEqual([]);
    await client.close();
  });

  it('keeps the operator (global token) on the full read-only tool set with Drive/Notion metadata', async () => {
    await addDriveAndNotion();
    const client = await connect(globalToken);
    expect((await client.listTools()).tools.map((t) => t.name).sort()).toEqual([...TOOL_NAMES].sort());
    const accounts = parse(await client.callTool({ name: 'perch_list_accounts', arguments: {} }));
    expect(accounts.google.map((g: { accountId: string }) => g.accountId)).toEqual(['google-0000000a']);
    expect(accounts.notion.map((w: { workspaceId: string }) => w.workspaceId)).toEqual(['notion-0000000a']);
    expect(accounts.mail.map((m: { accountId: string }) => m.accountId)).toEqual(['imap-0000000a', 'imap-0000000b']);
    await client.close();
  });
});

describe('grant revocation and narrowing take effect on the next tool call [MOCK providers]', () => {
  it('HTTP: a connected client fails closed after removal, with no provider call', async () => {
    const { client: g, token } = await grant('Revoked HTTP', ['read', 'send'], ['imap-0000000a']);
    const client = await connect(token);
    expect((await call(client, 'mail_search', {})).isError).toBe(false);
    providerCalls = [];
    await removeClientGrant(store, g.id);
    expect((await call(client, 'mail_send', sendArgs('imap-0000000a'))).isError).toBe(true);
    expect((await call(client, 'mail_search', {})).isError).toBe(true);
    expect((await call(client, 'perch_list_accounts', {})).isError).toBe(true);
    expect(providerCalls).toEqual([]);
    expect(sent).toEqual([]);
  });

  it('HTTP: removing a capability or an account from the grant denies it on the next call', async () => {
    const { client: g, token } = await grant('Narrowed HTTP', ['read', 'send'], ['imap-0000000a', 'imap-0000000b']);
    const client = await connect(token);
    await setGrant(g.id, { capabilities: ['read'] });
    expect((await call(client, 'mail_send', sendArgs('imap-0000000a'))).isError).toBe(true);
    await setGrant(g.id, { accountIds: ['imap-0000000b'] });
    const read = await call(client, 'mail_read_message', { accountId: 'imap-0000000a', messageId: 'imap:SU5CT1g:1:7' });
    expect(read.isError).toBe(true);
    expect(read.text).toMatch(/not granted/i);
    expect(providerCalls).toEqual([]);
    expect(sent).toEqual([]);
    await client.close();
  });

  it('persistent session (stdio-equivalent): removal fails every tool closed, with no provider call', async () => {
    const { client: g, token } = await grant('Revoked stdio', ['read', 'draft', 'send'], ['imap-0000000a']);
    const client = await memoryClient(token);
    expect((await call(client, 'mail_search', {})).isError).toBe(false);
    providerCalls = [];
    await removeClientGrant(store, g.id);
    for (const [tool, args] of [
      ['mail_send', sendArgs('imap-0000000a')],
      ['mail_create_draft', sendArgs('imap-0000000a')],
      ['mail_search', {}],
      ['mail_read_message', { accountId: 'imap-0000000a', messageId: 'imap:SU5CT1g:1:7' }],
      ['mail_get_attachment', { accountId: 'imap-0000000a', messageId: 'imap:SU5CT1g:1:7', attachmentId: '2' }],
      ['perch_list_accounts', {}],
    ] as const) {
      const r = await call(client, tool, args);
      expect(r.isError, tool).toBe(true);
      expect(r.text, tool).toMatch(/revoked/i);
    }
    expect(providerCalls).toEqual([]);
    expect(sent).toEqual([]);
    await client.close();
  });

  it('persistent session (stdio-equivalent): narrowing capabilities or accounts is enforced on the next call', async () => {
    const { client: g, token } = await grant('Narrowed stdio', ['read', 'send'], ['imap-0000000a', 'imap-0000000b']);
    const client = await memoryClient(token);
    await setGrant(g.id, { capabilities: ['read'] });
    const send = await call(client, 'mail_send', sendArgs('imap-0000000a'));
    expect(send.isError).toBe(true);
    expect(send.text).toMatch(/not granted/i);
    await setGrant(g.id, { capabilities: ['read', 'send'], accountIds: ['imap-0000000b'] });
    expect((await call(client, 'mail_send', sendArgs('imap-0000000a'))).isError).toBe(true);
    expect((await call(client, 'mail_read_message', { accountId: 'imap-0000000a', messageId: 'imap:SU5CT1g:1:7' })).isError).toBe(true);
    const search = JSON.parse((await call(client, 'mail_search', {})).text);
    expect(search.results.map((r: { accountId: string }) => r.accountId)).toEqual(['imap-0000000b']);
    const accounts = JSON.parse((await call(client, 'perch_list_accounts', {})).text);
    expect(accounts.mail.map((m: { accountId: string }) => m.accountId)).toEqual(['imap-0000000b']);
    expect(sent).toEqual([]);
    expect(providerCalls).toEqual(['search']);
    await client.close();
  });

  it('a removed client token is rejected with 401 before any MCP handling', async () => {
    const { client: g, token } = await grant('Removed', ['send'], ['imap-0000000a']);
    await removeClientGrant(store, g.id);
    const res = await fetch(server!.url, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'mail_send', arguments: sendArgs('imap-0000000a') } }),
    });
    expect(res.status).toBe(401);
    expect(providerCalls).toEqual([]);
  });
});

describe('mail MCP tools over an in-memory transport (stdio-equivalent principal selection)', () => {
  it('registers drafting for a draft-only client and refuses sends', async () => {
    const { token } = await createClientGrant(store, {
      label: 'Drafts only',
      capabilities: ['draft'],
      accountIds: ['imap-0000000b'],
      tokenFile: `${dirs.root}/config/clients/drafts.token`,
    });
    const principal = (await principalForClientToken(store, token))!;
    const mcp = createMcpServer(context(), principal);
    const [a, b] = InMemoryTransport.createLinkedPair();
    await mcp.connect(b);
    const client = new Client({ name: 'mem', version: '0' });
    await client.connect(a);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('mail_create_draft');
    expect(names).not.toContain('mail_send');
    const draft = parse(await client.callTool({ name: 'mail_create_draft', arguments: sendArgs('imap-0000000b') }));
    expect(draft).toMatchObject({ draftId: 'imap:RHJhZnRz:1:1', accountId: 'imap-0000000b' });
    // Read is not part of this grant.
    expect(names).not.toContain('mail_read_message');
    const read = await call(client, 'mail_read_message', { accountId: 'imap-0000000b', messageId: 'imap:SU5CT1g:1:7' });
    expect(read.isError).toBe(true);
    expect(providerCalls).toEqual(['draft']);
    await client.close();
  });
});
