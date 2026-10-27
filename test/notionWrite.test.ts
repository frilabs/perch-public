// Notion create/edit/trash and comments through the real MCP SDK client (in-memory transport) against the MOCK
// Notion API. Covers grants, idempotency, outcomes, payload bounds and audit. No live Notion calls.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, removeClientGrant, type Principal } from '../src/auth/grants.js';
import { createPerchContext, type PerchContext } from '../src/context.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { createMcpServer } from '../src/mcp/server.js';
import { addNotionWorkspace } from '../src/notion/notion.js';
import { MAX_REQUEST_JSON_BYTES } from '../src/notion/notionWrite.js';
import type { NotionCapability } from '../src/store/credentialStore.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { isAllowedRoute, Upstream, type RouteCapability } from '../src/upstream.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';
import { mockId, MockNotion, type MockWorkspace } from './support/mockNotion.js';

let dirs: TempDirs;
let store: CredentialStore;
let notion: MockNotion;
let ctx: PerchContext;
let wsA: MockWorkspace;
let wsB: MockWorkspace;
let idA: string;
let idB: string;
let pageA: string;
let blockA: string;
let dsA: string;

const WRITE_TOOLS = [
  'notion_create_page',
  'notion_update_page',
  'notion_append_blocks',
  'notion_update_block',
  'notion_trash_page',
  'notion_restore_page',
  'notion_trash_block',
  'notion_add_comment',
];

async function clientFor(principal: Principal) {
  const mcp = createMcpServer(ctx, principal);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await mcp.connect(b);
  const client = new Client({ name: 'notion-write-test', version: '0' });
  await client.connect(a);
  return client;
}

async function grant(capabilities: NotionCapability[], accountIds: string[]) {
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
      body = { error: text }; // SDK input validation errors are plain text
    }
    return { isError: r.isError === true, body };
  } catch (err) {
    return { isError: true, body: { error: (err as Error).message } };
  }
}

const rid = () => `notion-test-${Math.random().toString(16).slice(2, 14)}`;
const para = (content: string) => ({ object: 'block', type: 'paragraph', paragraph: { rich_text: [{ type: 'text', text: { content } }] } });

async function writer() {
  const { principal } = await grant(['notion_read', 'notion_write'], [idA]);
  return { principal, client: await clientFor(principal) };
}

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  notion = new MockNotion();
  wsA = notion.addWorkspace('A');
  wsB = notion.addWorkspace('B');
  pageA = mockId();
  blockA = mockId();
  dsA = mockId();
  wsA.pages.push({ id: pageA, title: 'Project plan', blocks: [{ id: blockA, text: 'first' }] });
  wsA.dataSources.push({ id: dsA, title: 'Tasks', rows: [] });
  wsB.pages.push({ id: mockId(), title: 'Project budget' });
  const upstream = new Upstream(notion.transport);
  idA = (await addNotionWorkspace(store, upstream, { label: 'Personal', token: wsA.token })).id;
  idB = (await addNotionWorkspace(store, upstream, { label: 'Company', token: wsB.token })).id;
  ctx = createPerchContext(store, notion.transport);
  notion.calls.length = 0;
});

afterEach(async () => {
  await dirs.cleanup();
});

describe('Notion write permissions [MOCK Notion]', () => {
  it('offers no write tools to the read-only operator, but the comment reader', async () => {
    const names = (await (await clientFor(READONLY_PRINCIPAL)).listTools()).tools.map((t) => t.name);
    expect(names).toContain('notion_search');
    expect(names).toContain('notion_list_comments');
    for (const t of WRITE_TOOLS) expect(names).not.toContain(t);
    // Direct service call as the operator: denied before any request.
    await expect(ctx.notion.write!.createPage(READONLY_PRINCIPAL, { workspaceId: idA, parentPageId: pageA, title: 'x', requestId: rid() })).rejects.toThrow(/read-only/);
    await expect(ctx.notion.write!.setPageTrashed(READONLY_PRINCIPAL, { workspaceId: idA, pageId: pageA }, true)).rejects.toThrow(/read-only/);
    expect(notion.calls).toHaveLength(0);
  });

  it('a client without notion_write gets reads only and is denied before any upstream call', async () => {
    const { principal } = await grant(['notion_read'], [idA]);
    const names = (await (await clientFor(principal)).listTools()).tools.map((t) => t.name);
    expect(names).toContain('notion_get_page');
    expect(names).toContain('notion_list_comments');
    for (const t of WRITE_TOOLS) expect(names).not.toContain(t);
    const w = ctx.notion.write!;
    await expect(w.createPage(principal, { workspaceId: idA, parentPageId: pageA, title: 'x', requestId: rid() })).rejects.toThrow(/notion_write/);
    await expect(w.appendBlocks(principal, { workspaceId: idA, blockId: pageA, children: [para('x')], requestId: rid() })).rejects.toThrow(/notion_write/);
    await expect(w.updatePage(principal, { workspaceId: idA, pageId: pageA, icon: null })).rejects.toThrow(/notion_write/);
    await expect(w.trashBlock(principal, { workspaceId: idA, blockId: blockA })).rejects.toThrow(/notion_write/);
    expect(notion.calls).toHaveLength(0);
  });

  it('a client with notion_read sees and searches only its granted workspaces', async () => {
    const { principal } = await grant(['notion_read'], [idA]);
    const client = await clientFor(principal);
    const accounts = await call(client, 'perch_list_accounts', {});
    expect((accounts.body.notion as Array<{ workspaceId: string }>).map((w) => w.workspaceId)).toEqual([idA]);
    const search = await call(client, 'notion_search', { query: 'project' });
    expect(search.isError).toBe(false);
    const hits = search.body.results as Array<{ workspaceId: string; title: string }>;
    expect(hits.map((h) => h.workspaceId)).toEqual([idA]);
    expect(notion.calls.every((c) => c.headers.authorization === `Bearer ${wsA.token}`)).toBe(true);
    const before = notion.calls.length;
    const other = await call(client, 'notion_get_page', { workspaceId: idB, pageId: wsB.pages[0]!.id });
    expect(other.isError).toBe(true);
    expect(String(other.body.error)).toMatch(/notion_read/);
    const otherSearch = await call(client, 'notion_search', { workspaceId: idB, query: 'project' });
    expect(otherSearch.isError).toBe(true);
    expect(notion.calls.length).toBe(before);
  });

  it('a client with only notion_write gets no read tools', async () => {
    const { principal } = await grant(['notion_write'], [idA]);
    const names = (await (await clientFor(principal)).listTools()).tools.map((t) => t.name);
    expect(names).not.toContain('notion_search');
    expect(names).not.toContain('notion_list_comments');
    expect(names).toContain('notion_create_page');
  });

  it('denies a workspace outside the grant without contacting Notion', async () => {
    const { client } = await writer();
    const r = await call(client, 'notion_create_page', { workspaceId: idB, parentPageId: wsB.pages[0]!.id, title: 'x', requestId: rid() });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/not granted/);
    const t = await call(client, 'notion_trash_page', { workspaceId: idB, pageId: wsB.pages[0]!.id });
    expect(t.isError).toBe(true);
    expect(notion.calls).toHaveLength(0);
  });

  it('applies a revoked grant before the provider call', async () => {
    const { id, principal } = await grant(['notion_write'], [idA]);
    const client = await clientFor(principal);
    await removeClientGrant(store, id);
    const r = await call(client, 'notion_update_page', { workspaceId: idA, pageId: pageA, icon: null });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/revoked/);
    expect(notion.calls).toHaveLength(0);
  });
});

describe('Notion write tools [MOCK Notion]', () => {
  it('creates a page under a page once per requestId; replay and payload conflict', async () => {
    const { client } = await writer();
    const args = { workspaceId: idA, parentPageId: pageA, title: 'Meeting notes', children: [para('Agenda')], icon: { type: 'emoji', emoji: '📝' }, requestId: rid() };
    const first = await call(client, 'notion_create_page', args);
    expect(first.isError).toBe(false);
    expect(first.body).toMatchObject({ status: 'accepted', replayed: false, workspaceId: idA });
    const created = wsA.pages.find((p) => p.title === 'Meeting notes')!;
    expect(created).toMatchObject({ parentId: pageA, icon: { type: 'emoji', emoji: '📝' } });
    expect(created.blocks!.map((b) => b.text)).toEqual(['Agenda']);
    expect(first.body.pageId).toBe(created.id);
    const writes = notion.writes;
    const again = await call(client, 'notion_create_page', args);
    expect(again.body).toMatchObject({ status: 'accepted', replayed: true, pageId: created.id });
    const conflict = await call(client, 'notion_create_page', { ...args, title: 'Other title' });
    expect(conflict.isError).toBe(true);
    expect(String(conflict.body.error)).toMatch(/already used/);
    expect(notion.writes).toBe(writes);
    expect(wsA.pages.filter((p) => p.parentId === pageA)).toHaveLength(1);
  });

  it('creates a data source row from properties', async () => {
    const { client } = await writer();
    const r = await call(client, 'notion_create_page', {
      workspaceId: idA,
      parentDataSourceId: dsA,
      properties: { Name: { title: [{ text: { content: 'Task 1' } }] }, Done: { checkbox: false } },
      requestId: rid(),
    });
    expect(r.body).toMatchObject({ status: 'accepted' });
    expect(wsA.dataSources[0]!.rows.map((x) => x.title)).toEqual(['Task 1']);
    const sent = JSON.parse(notion.calls.at(-1)!.body!) as { parent: unknown };
    expect(sent.parent).toEqual({ type: 'data_source_id', data_source_id: dsA });
  });

  it('rejects ambiguous parents and title on a data source before any request', async () => {
    const { client } = await writer();
    const both = await call(client, 'notion_create_page', { workspaceId: idA, parentPageId: pageA, parentDataSourceId: dsA, title: 'x', requestId: rid() });
    expect(String(both.body.error)).toMatch(/exactly one/);
    const dsTitle = await call(client, 'notion_create_page', { workspaceId: idA, parentDataSourceId: dsA, title: 'x', requestId: rid() });
    expect(String(dsTitle.body.error)).toMatch(/page parent only|title property/);
    expect(notion.calls).toHaveLength(0);
  });

  it('updates page properties, icon and cover', async () => {
    const { client } = await writer();
    const r = await call(client, 'notion_update_page', { workspaceId: idA, pageId: pageA, properties: { Status: { select: { name: 'Done' } } }, icon: { type: 'emoji', emoji: '✅' } });
    expect(r.isError).toBe(false);
    expect(r.body).toMatchObject({ status: 'accepted', workspaceId: idA, object: { object: 'page', id: pageA, in_trash: false } });
    expect(wsA.pages[0]!.properties).toEqual({ Status: { select: { name: 'Done' } } });
    expect(wsA.pages[0]!.icon).toEqual({ type: 'emoji', emoji: '✅' });
    const empty = await call(client, 'notion_update_page', { workspaceId: idA, pageId: pageA });
    expect(String(empty.body.error)).toMatch(/Nothing to change/);
  });

  it('appends blocks (also after a given block) idempotently', async () => {
    const { client } = await writer();
    const args = { workspaceId: idA, blockId: pageA, children: [para('second'), para('third')], requestId: rid() };
    const r = await call(client, 'notion_append_blocks', args);
    expect(r.body).toMatchObject({ status: 'accepted', replayed: false });
    expect((r.body.blockIds as string[]).length).toBe(2);
    expect(r.body.firstBlockId).toBe((r.body.blockIds as string[])[0]);
    const again = await call(client, 'notion_append_blocks', args);
    expect(again.body).toMatchObject({ status: 'accepted', replayed: true, firstBlockId: r.body.firstBlockId });
    await call(client, 'notion_append_blocks', { workspaceId: idA, blockId: pageA, children: [para('between')], after: blockA, requestId: rid() });
    expect(wsA.pages[0]!.blocks!.map((b) => b.text)).toEqual(['first', 'between', 'second', 'third']);
  });

  it('updates one block', async () => {
    const { client } = await writer();
    const r = await call(client, 'notion_update_block', {
      workspaceId: idA,
      blockId: blockA,
      type: 'to_do',
      content: { rich_text: [{ text: { content: 'done item' } }], checked: true },
    });
    expect(r.body).toMatchObject({ status: 'accepted', object: { object: 'block', id: blockA } });
    expect(wsA.pages[0]!.blocks![0]).toMatchObject({ type: 'to_do', text: 'done item' });
    const sent = JSON.parse(notion.calls.at(-1)!.body!) as Record<string, unknown>;
    expect(Object.keys(sent)).toEqual(['to_do']);
    const meta = await call(client, 'notion_update_block', { workspaceId: idA, blockId: blockA, type: 'in_trash', content: {} });
    expect(String(meta.body.error)).toMatch(/block type/);
  });

  it('trashes and restores a page, trashes a block (PATCH in_trash, never DELETE)', async () => {
    const { client } = await writer();
    const t = await call(client, 'notion_trash_page', { workspaceId: idA, pageId: pageA });
    expect(t.body).toMatchObject({ status: 'accepted', object: { in_trash: true } });
    expect(wsA.pages[0]!.inTrash).toBe(true);
    const r = await call(client, 'notion_restore_page', { workspaceId: idA, pageId: pageA });
    expect(r.body).toMatchObject({ status: 'accepted', object: { in_trash: false } });
    expect(wsA.pages[0]!.inTrash).toBe(false);
    const b = await call(client, 'notion_trash_block', { workspaceId: idA, blockId: blockA });
    expect(b.body).toMatchObject({ status: 'accepted', object: { in_trash: true } });
    expect(wsA.pages[0]!.blocks![0]!.inTrash).toBe(true);
    for (const c of notion.calls) expect(c.method).not.toBe('DELETE');
    expect(notion.calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual([
      `PATCH /v1/pages/${pageA}`,
      `PATCH /v1/pages/${pageA}`,
      `PATCH /v1/blocks/${blockA}`,
    ]);
  });

  it('adds comments to a page and to a discussion, and lists them', async () => {
    const { client } = await writer();
    const c1 = await call(client, 'notion_add_comment', { workspaceId: idA, pageId: pageA, richText: [{ text: { content: 'Looks good' } }], requestId: rid() });
    expect(c1.body).toMatchObject({ status: 'accepted', replayed: false });
    const list = await call(client, 'notion_list_comments', { workspaceId: idA, blockId: pageA });
    const comments = list.body.comments as Array<{ id: string; discussionId: string; text: string }>;
    expect(comments).toHaveLength(1);
    expect(comments[0]).toMatchObject({ id: c1.body.commentId, text: 'Looks good' });
    const reply = await call(client, 'notion_add_comment', {
      workspaceId: idA,
      discussionId: comments[0]!.discussionId,
      richText: [{ text: { content: 'Thanks' } }],
      requestId: rid(),
    });
    expect(reply.body).toMatchObject({ status: 'accepted' });
    expect(wsA.comments.map((c) => [c.discussionId, c.text])).toEqual([
      [comments[0]!.discussionId, 'Looks good'],
      [comments[0]!.discussionId, 'Thanks'],
    ]);
    const neither = await call(client, 'notion_add_comment', { workspaceId: idA, richText: [{ text: { content: 'x' } }], requestId: rid() });
    expect(String(neither.body.error)).toMatch(/exactly one/);
  });

  it('the operator can list comments', async () => {
    wsA.comments.push({ id: mockId(), discussionId: mockId(), parentId: pageA, text: 'hello' });
    const r = await call(await clientFor(READONLY_PRINCIPAL), 'notion_list_comments', { workspaceId: idA, blockId: pageA });
    expect(r.isError).toBe(false);
    expect((r.body.comments as Array<{ text: string }>).map((c) => c.text)).toEqual(['hello']);
  });
});

describe('Notion write bounds and outcomes [MOCK Notion]', () => {
  it('rejects oversized payloads before any I/O', async () => {
    const { client } = await writer();
    const long = 'x'.repeat(2001);
    const cases: Array<[string, Record<string, unknown>, RegExp]> = [
      ['notion_append_blocks', { workspaceId: idA, blockId: pageA, children: [para(long)], requestId: rid() }, /2000 characters/],
      [
        'notion_append_blocks',
        {
          workspaceId: idA,
          blockId: pageA,
          children: Array.from({ length: 2 }, () => ({ type: 'toggle', toggle: { rich_text: [], children: Array.from({ length: 50 }, () => para('n')) } })),
          requestId: rid(),
        },
        /at most 100 blocks/i,
      ],
      ['notion_append_blocks', { workspaceId: idA, blockId: pageA, children: Array.from({ length: 101 }, () => para('n')), requestId: rid() }, /100|too_big|array/i],
      [
        'notion_create_page',
        { workspaceId: idA, parentPageId: pageA, title: 'big', properties: { Big: { rich_text: Array.from({ length: 90 }, () => ({ text: { content: 'y'.repeat(1990) } })) }, Big2: { rich_text: Array.from({ length: 90 }, () => ({ text: { content: 'y'.repeat(1990) } })) }, Big3: { rich_text: Array.from({ length: 90 }, () => ({ text: { content: 'y'.repeat(1990) } })) } }, requestId: rid() },
        new RegExp(String(MAX_REQUEST_JSON_BYTES)),
      ],
      ['notion_update_block', { workspaceId: idA, blockId: blockA, type: 'paragraph', content: { rich_text: [{ text: { content: long } }] } }, /2000 characters/],
      ['notion_add_comment', { workspaceId: idA, pageId: pageA, richText: [{ text: { content: long } }], requestId: rid() }, /2000 characters/],
      ['notion_update_page', { workspaceId: idA, pageId: '../users', icon: null }, /invalid notion id/i],
    ];
    for (const [name, args, re] of cases) {
      const r = await call(client, name, args);
      expect(r.isError, name).toBe(true);
      expect(String(r.body.error), name).toMatch(re);
    }
    expect(notion.calls).toHaveLength(0);
  });

  it('maps restricted_resource to a clear message (create: rejected; edit: error)', async () => {
    const { client } = await writer();
    notion.restrictedTokens.add(wsA.token);
    const c = await call(client, 'notion_create_page', { workspaceId: idA, parentPageId: pageA, title: 'x', requestId: rid() });
    expect(c.body).toMatchObject({ status: 'rejected' });
    expect(String(c.body.detail)).toMatch(/Update content.*Insert content/);
    const e = await call(client, 'notion_trash_page', { workspaceId: idA, pageId: pageA });
    expect(e.isError).toBe(true);
    expect(String(e.body.error)).toMatch(/restricted_resource.*Update content/);
  });

  it('reports 5xx after submission as indeterminate and never retries writes (also not on 429)', async () => {
    const { client } = await writer();
    notion.failWritesWith = 502;
    const args = { workspaceId: idA, parentPageId: pageA, title: 'x', requestId: rid() };
    const c = await call(client, 'notion_create_page', args);
    expect(c.body).toMatchObject({ status: 'indeterminate' });
    const again = await call(client, 'notion_create_page', args);
    expect(again.body).toMatchObject({ status: 'indeterminate', replayed: true });
    const e = await call(client, 'notion_update_block', { workspaceId: idA, blockId: blockA, type: 'paragraph', content: { rich_text: [] } });
    expect(String(e.body.error)).toMatch(/outcome is unknown/);
    expect(notion.writes).toBe(2);
    notion.failWritesWith = null;
    notion.rateLimitQueue.push('1');
    const before = notion.calls.length;
    const limited = await call(client, 'notion_create_page', { ...args, requestId: rid() });
    expect(limited.body).toMatchObject({ status: 'rejected' });
    expect(String(limited.body.detail)).toMatch(/429/);
    expect(notion.calls.length).toBe(before + 1);
  });

  it('audits writes without titles or content', async () => {
    const { principal, client } = await writer();
    await call(client, 'notion_create_page', { workspaceId: idA, parentPageId: pageA, title: 'SECRET-TITLE', children: [para('SECRET-BODY')], requestId: rid() });
    await call(client, 'notion_update_page', { workspaceId: idA, pageId: pageA, properties: { Note: { rich_text: [{ text: { content: 'SECRET-PROP' } }] } } });
    await call(client, 'notion_add_comment', { workspaceId: idA, pageId: pageA, richText: [{ text: { content: 'SECRET-COMMENT' } }], requestId: rid() });
    await call(client, 'notion_trash_block', { workspaceId: idA, blockId: blockA });
    const ledger = await new MailWorkflowLedger(store).read();
    const types = ledger.audit.map((e) => `${e.type}:${e.outcome}`);
    expect(types).toEqual(expect.arrayContaining(['notion_write:accepted', 'notion_update_page:attempt', 'notion_update_page:ok', 'notion_trash_block:ok']));
    expect(ledger.audit.filter((e) => e.type === 'notion_write').every((e) => e.accountId === idA && e.actor.kind === 'client')).toBe(true);
    expect(ledger.sends.filter((s) => s.provider === 'notion')).toHaveLength(2);
    const raw = JSON.stringify(ledger);
    for (const secret of ['SECRET-TITLE', 'SECRET-BODY', 'SECRET-PROP', 'SECRET-COMMENT', pageA, blockA]) expect(raw).not.toContain(secret);
    expect(principal.clientId).toBeTruthy();
  });
});

describe('Notion upstream allowlist', () => {
  const id = '0000dead000000000000000000000001';
  const caps: RouteCapability[] = ['read', 'draft', 'send', 'calendar_write', 'slack_send', 'whatsapp_send', 'admin', 'notify', 'drive_write', 'notion_write', 'mail_modify'];

  it('never reaches a DELETE route or a schema change, for any capability', async () => {
    for (const cap of caps) {
      for (const path of [`/v1/blocks/${id}`, `/v1/pages/${id}`, `/v1/comments`, `/v1/databases/${id}`, `/v1/data_sources/${id}`]) {
        expect(isAllowedRoute('notion', 'DELETE', path, cap)).toBe(false);
      }
      expect(isAllowedRoute('notion', 'PATCH', `/v1/databases/${id}`, cap)).toBe(false);
      expect(isAllowedRoute('notion', 'PATCH', `/v1/data_sources/${id}`, cap)).toBe(false);
      expect(isAllowedRoute('notion', 'POST', '/v1/databases', cap)).toBe(false);
      expect(isAllowedRoute('notion', 'POST', '/v1/data_sources', cap)).toBe(false);
    }
    const upstream = new Upstream(notion.transport);
    await expect(upstream.json('notion', { method: 'DELETE', path: `/v1/blocks/${id}`, capability: 'notion_write' })).rejects.toThrow(/non-allowlisted/);
    expect(notion.calls).toHaveLength(0);
  });

  it('write routes need the notion_write tag; reading comments does not', () => {
    expect(isAllowedRoute('notion', 'POST', '/v1/pages')).toBe(false);
    expect(isAllowedRoute('notion', 'POST', '/v1/pages', 'notion_write')).toBe(true);
    expect(isAllowedRoute('notion', 'PATCH', `/v1/pages/${id}`)).toBe(false);
    expect(isAllowedRoute('notion', 'PATCH', `/v1/blocks/${id}/children`, 'notion_write')).toBe(true);
    expect(isAllowedRoute('notion', 'PATCH', `/v1/blocks/../x`, 'notion_write')).toBe(false);
    expect(isAllowedRoute('notion', 'POST', '/v1/comments')).toBe(false);
    expect(isAllowedRoute('notion', 'GET', '/v1/comments')).toBe(true);
  });
});
