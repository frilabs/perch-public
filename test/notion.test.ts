// Notion operations against the MOCK Notion API (in-memory fake). No live Notion calls.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { READONLY_PRINCIPAL } from '../src/auth/grants.js';
import { addNotionWorkspace, NotionService, removeNotionWorkspace } from '../src/notion/notion.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';
import { mockId, MockNotion, NOTION_VERSION, type MockWorkspace } from './support/mockNotion.js';

let dirs: TempDirs;
let store: CredentialStore;
let notion: MockNotion;
let service: NotionService;
let wsA: MockWorkspace;
let wsB: MockWorkspace;
let idA: string;
let idB: string;

const READ_ONLY_CALLS = [
  /^GET \/v1\/users\/me$/,
  /^POST \/v1\/search$/,
  /^GET \/v1\/pages\/[0-9a-f-]+$/,
  /^GET \/v1\/blocks\/[0-9a-f-]+\/children$/,
  /^GET \/v1\/databases\/[0-9a-f-]+$/,
  /^GET \/v1\/data_sources\/[0-9a-f-]+$/,
  /^POST \/v1\/data_sources\/[0-9a-f-]+\/query$/,
];

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  notion = new MockNotion();
  wsA = notion.addWorkspace('A');
  wsB = notion.addWorkspace('B');
  wsA.pages.push({ id: mockId(), title: 'Project plan' }, { id: mockId(), title: 'Project notes' }, { id: mockId(), title: 'Other' });
  const ds = { id: mockId(), title: 'Project tasks', rows: Array.from({ length: 3 }, (_, i) => ({ id: mockId(), title: `Task ${i}` })) };
  wsA.dataSources.push(ds);
  wsA.databases.push({ id: mockId(), title: 'Tasks DB', dataSourceIds: [ds.id] });
  wsB.pages.push({ id: mockId(), title: 'Project budget' });
  const upstream = new Upstream(notion.transport);
  idA = (await addNotionWorkspace(store, upstream, { label: 'Personal', token: wsA.token })).id;
  idB = (await addNotionWorkspace(store, upstream, { label: 'Company', token: wsB.token })).id;
  sleeps = [];
  service = new NotionService(store, upstream, { sleep: async (ms) => void sleeps.push(ms) });
});

let sleeps: number[];

afterEach(async () => {
  // Every call Perch made must be a read-only endpoint and carry the pinned API version.
  for (const c of notion.calls) {
    expect(READ_ONLY_CALLS.some((re) => re.test(`${c.method} ${c.url.pathname}`))).toBe(true);
    expect(c.headers['notion-version']).toBe(NOTION_VERSION);
  }
  await dirs.cleanup();
});

describe('Notion workspaces [mock Notion]', () => {
  it('validates the PAT via /users/me and stores label + token owner (not a verified workspace identity)', async () => {
    const data = await store.read();
    expect(data.notion.map((w) => [w.id, w.label, w.tokenOwner?.name])).toEqual([
      [idA, 'Personal', wsA.owner.name],
      [idB, 'Company', wsB.owner.name],
    ]);
    expect(idA).toMatch(/^notion-[a-f0-9]{8}$/);
  });

  it('rejects an invalid PAT without storing it or echoing it', async () => {
    const bad = dummySecret('NOTION-PAT-BAD');
    const err = await addNotionWorkspace(store, new Upstream(notion.transport), { label: 'X', token: bad }).catch(
      (e: Error) => e,
    );
    expect((err as Error).message).toMatch(/401/);
    expect((err as Error).message).not.toContain(bad);
    expect((await store.read()).notion).toHaveLength(2);
  });

  it('rejects connecting the same PAT twice', async () => {
    await expect(
      addNotionWorkspace(store, new Upstream(notion.transport), { label: 'Again', token: wsA.token }),
    ).rejects.toThrow(/already connected/i);
  });

  it('disconnects locally; the workspace disappears from results', async () => {
    await removeNotionWorkspace(store, idB);
    const res = await service.search(READONLY_PRINCIPAL, { query: 'project' });
    expect(res.results.every((r) => r.workspaceId === idA)).toBe(true);
    await expect(removeNotionWorkspace(store, idB)).rejects.toThrow(/unknown/i);
  });
});

describe('NotionService.search [mock Notion]', () => {
  it('title-searches all workspaces with provenance and composite cursor pagination', async () => {
    const p1 = await service.search(READONLY_PRINCIPAL, { query: 'project', pageSize: 2 });
    expect(p1.results.map((r) => [r.workspaceLabel, r.object, r.title])).toEqual([
      ['Personal', 'page', 'Project plan'],
      ['Personal', 'page', 'Project notes'],
      ['Company', 'page', 'Project budget'],
    ]);
    expect(p1.hasMore).toBe(true);
    const p2 = await service.search(READONLY_PRINCIPAL, { query: 'project', pageSize: 2, cursor: p1.nextCursor! });
    expect(p2.results.map((r) => [r.workspaceId, r.object, r.title])).toEqual([[idA, 'data_source', 'Project tasks']]);
    expect(p2.hasMore).toBe(false);
  });

  it('filters by object type and by workspace', async () => {
    const res = await service.search(READONLY_PRINCIPAL, { filter: 'data_source' });
    expect(res.results.map((r) => r.object)).toEqual(['data_source']);
    const body = JSON.parse(notion.calls.at(-1)!.body!);
    expect(body.filter).toEqual({ property: 'object', value: 'data_source' });
    const one = await service.search(READONLY_PRINCIPAL, { workspaceId: idB });
    expect(one.results.map((r) => r.title)).toEqual(['Project budget']);
  });

  it('reports partial results when a workspace fails', async () => {
    notion.failingTokens.add(wsB.token);
    const res = await service.search(READONLY_PRINCIPAL, { query: 'project' });
    expect(res.partial).toBe(true);
    expect(res.errors.map((e) => e.accountId)).toEqual([idB]);
    expect(JSON.stringify(res)).not.toContain(wsB.token);
  });
});

describe('Notion rate limiting [mock Notion 429]', () => {
  it('retries 429 honouring a sanitised, bounded Retry-After', async () => {
    notion.rateLimitQueue.push('2', 'abc', '99999');
    const res = await service.search(READONLY_PRINCIPAL, { workspaceId: idA, query: 'project' });
    expect(res.results.length).toBeGreaterThan(0);
    expect(sleeps).toEqual([2000, 1000, 10_000]);
  });

  it('gives up after the per-request retry limit with a rate-limit error', async () => {
    notion.rateLimitQueue.push(...Array(10).fill('0'));
    await expect(service.getPage(READONLY_PRINCIPAL, idA, wsA.pages[0]!.id)).rejects.toThrow(/429/);
    expect(sleeps).toHaveLength(3);
  });

  it('bounds total retries per tool call and keeps content already loaded', async () => {
    const parents = Array.from({ length: 4 }, (_, i) => ({ id: mockId(), text: `p${i}`, children: [{ id: mockId(), text: `c${i}` }] }));
    const page = { id: mockId(), title: 'RL', blocks: parents };
    wsA.pages.push(page);
    notion.rateLimitEachRequest = 2;
    const res = await service.getPageContent(READONLY_PRINCIPAL, idA, page.id, { maxDepth: 2 });
    expect(sleeps.length).toBeLessThanOrEqual(6);
    expect(res.blocks.map((b) => b.text)).toEqual(['p0', 'p1', 'p2', 'p3']);
    expect(res.partial).toBe(true);
    expect(res.truncated).toBe(true);
    expect(res.errors.length).toBeGreaterThan(0);
  });
});

describe('NotionService content [mock Notion]', () => {
  it('returns partial page content with explicit errors when a nested fetch fails', async () => {
    const failing = { id: mockId(), text: 'broken parent', children: [{ id: mockId(), text: 'unreachable' }] };
    const ok = { id: mockId(), text: 'ok parent', children: [{ id: mockId(), text: 'ok child' }] };
    const page = { id: mockId(), title: 'Partial', blocks: [failing, ok] };
    wsA.pages.push(page);
    notion.failingBlockIds.add(failing.id);
    const res = await service.getPageContent(READONLY_PRINCIPAL, idA, page.id, {});
    expect(res.blocks.map((b) => b.text)).toEqual(['broken parent', 'ok parent']);
    expect(res.partial).toBe(true);
    expect(res.truncated).toBe(true);
    expect(res.errors).toEqual([{ blockId: failing.id, message: expect.stringMatching(/HTTP 500/) }]);
    expect(res.blocks[0]!.childrenError).toMatch(/HTTP 500/);
    expect(res.blocks[0]!.childrenNotLoaded).toBe(true);
  });

  function seedPage() {
    const deep = { id: mockId(), text: 'grandchild' };
    const kids = Array.from({ length: 5 }, (_, i) => ({ id: mockId(), text: `child ${i}`, children: i === 0 ? [deep] : undefined }));
    const page = {
      id: mockId(),
      title: 'Nested',
      blocks: [
        { id: mockId(), text: 'top 0', children: kids },
        { id: mockId(), text: 'top 1' },
        { id: mockId(), text: 'top 2' },
      ],
    };
    wsA.pages.push(page);
    return page;
  }

  it('paginates top-level blocks and traverses nested children up to maxDepth', async () => {
    const page = seedPage();
    const r1 = await service.getPageContent(READONLY_PRINCIPAL, idA, page.id, { pageSize: 2, maxDepth: 3 });
    expect(r1.workspaceId).toBe(idA);
    expect(r1.blocks.map((b) => b.text)).toEqual(['top 0', 'top 1']);
    expect(r1.hasMore).toBe(true);
    const top0 = r1.blocks[0]!;
    expect(top0.children!.map((b) => b.text)).toEqual(['child 0', 'child 1', 'child 2', 'child 3', 'child 4']);
    expect(top0.children![0]!.children!.map((b) => b.text)).toEqual(['grandchild']);
    const r2 = await service.getPageContent(READONLY_PRINCIPAL, idA, page.id, { pageSize: 2, maxDepth: 3, cursor: r1.nextCursor! });
    expect(r2.blocks.map((b) => b.text)).toEqual(['top 2']);
    expect(r2.hasMore).toBe(false);
    expect(r2.nextCursor).toBeNull();
  });

  it('marks children not loaded when depth or block budget is exhausted', async () => {
    const page = seedPage();
    const shallow = await service.getPageContent(READONLY_PRINCIPAL, idA, page.id, { maxDepth: 1 });
    expect(shallow.blocks[0]!.children).toBeUndefined();
    expect(shallow.blocks[0]!.childrenNotLoaded).toBe(true);
    expect(shallow.truncated).toBe(true);

    const budget = await service.getPageContent(READONLY_PRINCIPAL, idA, page.id, { maxDepth: 3, maxBlocks: 5 });
    expect(budget.blocksReturned).toBeLessThanOrEqual(5);
    expect(budget.truncated).toBe(true);
    const top0 = budget.blocks[0]!;
    expect(top0.children!.length).toBeLessThan(5);
    expect(top0.childrenHasMore).toBe(true);
    expect(typeof top0.childrenNextCursor).toBe('string');

    const rest = await service.getBlockChildren(READONLY_PRINCIPAL, idA, top0.id, { cursor: top0.childrenNextCursor! });
    expect(rest.blocks.length).toBeGreaterThan(0);
    expect(rest.blocks.at(-1)!.text).toBe('child 4');
  });

  it('retrieves pages, databases with data_sources, and queries data sources with pagination', async () => {
    const page = await service.getPage(READONLY_PRINCIPAL, idA, wsA.pages[0]!.id);
    expect(page).toMatchObject({ workspaceId: idA, workspaceLabel: 'Personal', id: wsA.pages[0]!.id });
    const db = await service.getDatabase(READONLY_PRINCIPAL, idA, wsA.databases[0]!.id);
    expect((db.data_sources as unknown[]).length).toBe(1);
    const dsId = wsA.dataSources[0]!.id;
    expect(await service.getDataSource(READONLY_PRINCIPAL, idA, dsId)).toMatchObject({ object: 'data_source', id: dsId });
    const q1 = await service.queryDataSource(READONLY_PRINCIPAL, idA, dsId, { pageSize: 2, filter: { property: 'Name', title: { contains: 'Task' } } });
    expect(q1.results).toHaveLength(2);
    expect(q1.hasMore).toBe(true);
    const sent = JSON.parse(notion.calls.at(-1)!.body!);
    expect(sent.filter).toEqual({ property: 'Name', title: { contains: 'Task' } });
    const q2 = await service.queryDataSource(READONLY_PRINCIPAL, idA, dsId, { pageSize: 2, cursor: q1.nextCursor! });
    expect(q2.results).toHaveLength(1);
    expect(q2.hasMore).toBe(false);
  });

  it('validates Notion ids and accepts dashed UUIDs', async () => {
    await expect(service.getPage(READONLY_PRINCIPAL, idA, '../users')).rejects.toThrow(/invalid notion id/i);
    const raw = wsA.pages[0]!.id;
    const dashed = `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
    await expect(service.getPage(READONLY_PRINCIPAL, idA, dashed)).resolves.toBeDefined();
  });
});
