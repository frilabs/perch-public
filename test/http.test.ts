// Real MCP SDK Client over actual local HTTP. Upstreams are MOCK transports (no live Google/Notion).
import { request } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createPerchContext } from '../src/context.js';
import { generateHttpToken, startHttpServer, validateBindHost, validateHttpToken, type RunningHttpServer } from '../src/mcp/http.js';
import { TOOL_NAMES } from '../src/mcp/server.js';
import { addNotionWorkspace } from '../src/notion/notion.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream, type UpstreamTransport } from '../src/upstream.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';
import { mockId, MockNotion } from './support/mockNotion.js';

let dirs: TempDirs;
let store: CredentialStore;
let server: RunningHttpServer;
let token: string;
let upstreamCalls: number;

/** MOCK transport that records that no upstream call happened. */
const noNetwork: UpstreamTransport = async () => {
  upstreamCalls++;
  throw new Error('MOCK: no upstream expected');
};

async function start(transport: UpstreamTransport = noNetwork, extra: Partial<Parameters<typeof startHttpServer>[0]> = {}) {
  const ctx = createPerchContext(store, transport);
  server = await startHttpServer({ host: '127.0.0.1', port: 0, token, context: ctx, log: () => {}, ...extra });
  return server;
}

function rawRequest(opts: { method?: string; path?: string; headers?: Record<string, string>; body?: string }) {
  return new Promise<{ status: number; headers: Record<string, unknown>; body: string }>((resolve, reject) => {
    const req = request(
      { host: '127.0.0.1', port: server.port, method: opts.method ?? 'POST', path: opts.path ?? '/mcp', headers: opts.headers },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body }));
      },
    );
    req.on('error', reject);
    req.end(opts.body);
  });
}

const initBody = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'raw', version: '0' } },
});
const mcpHeaders = (extra: Record<string, string> = {}) => ({
  'content-type': 'application/json',
  accept: 'application/json, text/event-stream',
  host: `127.0.0.1:${server.port}`,
  ...extra,
});

async function connectClient(authToken = token) {
  const client = new Client({ name: 'perch-test', version: '0.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(server.url), {
    requestInit: { headers: { authorization: `Bearer ${authToken}` } },
  });
  await client.connect(transport);
  return client;
}

const parse = (r: Awaited<ReturnType<Client['callTool']>>) =>
  JSON.parse((r.content as Array<{ type: string; text: string }>)[0]!.text);

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  token = generateHttpToken();
  upstreamCalls = 0;
});
afterEach(async () => {
  await server?.close();
  await dirs.cleanup();
});

describe('bind and token validation', () => {
  it.each(['127.0.0.1', '::1', 'localhost', '100.101.102.103', 'fd7a:115c:a1e0::1'])('accepts %s', (h) => {
    expect(() => validateBindHost(h)).not.toThrow();
  });
  it.each(['0.0.0.0', '::', '192.168.1.10', '10.0.0.1', '8.8.8.8', '100.128.0.1', 'example.com', ''])('rejects %s', (h) => {
    expect(() => validateBindHost(h)).toThrow();
  });
  it('requires a strong token (fail closed)', async () => {
    expect(generateHttpToken().length).toBeGreaterThanOrEqual(43);
    expect(() => validateHttpToken('short')).toThrow(/at least/);
    expect(() => validateHttpToken(undefined)).toThrow();
    await expect(start(noNetwork, { token: '' })).rejects.toThrow();
  });
});

describe('HTTP request gate', () => {
  beforeEach(async () => {
    await start();
  });

  it('rejects a missing bearer token with 401', async () => {
    const res = await rawRequest({ headers: mcpHeaders(), body: initBody });
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/^Bearer/);
  });

  it('rejects a wrong bearer token with 401', async () => {
    const res = await rawRequest({ headers: mcpHeaders({ authorization: `Bearer ${generateHttpToken()}` }), body: initBody });
    expect(res.status).toBe(401);
    const basic = await rawRequest({ headers: mcpHeaders({ authorization: `Basic ${token}` }), body: initBody });
    expect(basic.status).toBe(401);
  });

  it('rejects a foreign Host header (DNS rebinding) with 403 even with a valid token', async () => {
    const res = await rawRequest({
      headers: mcpHeaders({ host: 'evil.example:80', authorization: `Bearer ${token}` }),
      body: initBody,
    });
    expect(res.status).toBe(403);
  });

  it('rejects a disallowed Origin with 403', async () => {
    const res = await rawRequest({
      headers: mcpHeaders({ origin: 'https://evil.example', authorization: `Bearer ${token}` }),
      body: initBody,
    });
    expect(res.status).toBe(403);
  });

  it('only serves POST /mcp and bounds the body', async () => {
    const auth = { authorization: `Bearer ${token}` };
    expect((await rawRequest({ method: 'GET', headers: mcpHeaders(auth) })).status).toBe(405);
    expect((await rawRequest({ method: 'DELETE', headers: mcpHeaders(auth) })).status).toBe(405);
    expect((await rawRequest({ path: '/other', headers: mcpHeaders(auth), body: initBody })).status).toBe(404);
    expect((await rawRequest({ headers: mcpHeaders(auth), body: 'x'.repeat(1024 * 1024 + 10) })).status).toBe(413);
    expect((await rawRequest({ headers: mcpHeaders(auth), body: '{not json' })).status).toBe(400);
  });

  it('accepts the correct token with a raw initialize', async () => {
    const res = await rawRequest({ headers: mcpHeaders({ authorization: `Bearer ${token}` }), body: initBody });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).result.serverInfo.name).toBe('perch');
  });
});

describe('MCP SDK client over HTTP with no configured accounts', () => {
  it('initializes, lists read-only tools and calls them', async () => {
    await start();
    const client = await connectClient();
    expect(client.getServerVersion()?.name).toBe('perch');
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([...TOOL_NAMES].sort());
    for (const t of tools) expect(t.annotations?.readOnlyHint).toBe(true);

    const raw = await client.callTool({ name: 'perch_list_accounts', arguments: {} });
    // Compact JSON keeps tool output small for the client's output limit.
    expect((raw.content as Array<{ text: string }>)[0]!.text).not.toContain('\n');
    const accounts = parse(raw);
    expect(accounts).toMatchObject({ google: [], notion: [] });
    const search = parse(await client.callTool({ name: 'drive_search', arguments: { query: 'anything' } }));
    expect(search).toMatchObject({ results: [], hasMore: false, nextCursor: null, partial: false });
    const notion = parse(await client.callTool({ name: 'notion_search', arguments: {} }));
    expect(notion.results).toEqual([]);
    expect(notion.note).toMatch(/not full-text/i);

    const err = await client.callTool({ name: 'drive_get_file', arguments: { accountId: 'google-00000000', fileId: 'x' } });
    expect(err.isError).toBe(true);
    expect(parse(err).error).toMatch(/unknown google account/i);
    expect(upstreamCalls).toBe(0);
    await client.close();
  });

  it('fails to connect with a wrong token', async () => {
    await start();
    await expect(connectClient(generateHttpToken())).rejects.toThrow();
  });

  it('accepts configured extra hosts and origins', async () => {
    await start(noNetwork, { allowedHosts: ['perch.example.ts.net'], allowedOrigins: ['https://ok.example'] });
    const res = await rawRequest({
      headers: mcpHeaders({ host: 'perch.example.ts.net', origin: 'https://ok.example', authorization: `Bearer ${token}` }),
      body: initBody,
    });
    expect(res.status).toBe(200);
  });
});

describe('MCP tools over HTTP with a MOCK Notion workspace', () => {
  it('sees a workspace added by another process without restart and labels provenance', async () => {
    const notion = new MockNotion();
    const ws = notion.addWorkspace('A');
    const pageId = mockId();
    ws.pages.push({ id: pageId, title: 'Hello', blocks: [{ id: mockId(), text: 'Body text' }] });
    await start(notion.transport);
    const client = await connectClient();
    expect(parse(await client.callTool({ name: 'perch_list_accounts', arguments: {} })).notion).toEqual([]);

    const cli = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    const added = await addNotionWorkspace(cli, new Upstream(notion.transport), { label: 'Mine', token: ws.token });

    const accounts = parse(await client.callTool({ name: 'perch_list_accounts', arguments: {} }));
    expect(accounts.notion).toEqual([expect.objectContaining({ workspaceId: added.id, label: 'Mine' })]);
    expect(JSON.stringify(accounts)).not.toContain(ws.token);

    const content = parse(
      await client.callTool({ name: 'notion_get_page_content', arguments: { workspaceId: added.id, pageId } }),
    );
    expect(content).toMatchObject({ workspaceId: added.id, workspaceLabel: 'Mine', hasMore: false });
    expect(content.blocks[0].text).toBe('Body text');
    await client.close();
  });
});
