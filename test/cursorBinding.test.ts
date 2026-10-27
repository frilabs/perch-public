// Cursors are bound to the store (namespace) that issued them: two stores with the SAME account ids must not
// accept each other's cursors, and a tampered cursor is rejected before any provider I/O. MOCK upstreams only.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { READONLY_PRINCIPAL } from '../src/auth/grants.js';
import { GoogleTokenProvider } from '../src/google/accounts.js';
import { DriveService } from '../src/google/drive.js';
import { NotionService } from '../src/notion/notion.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { createWorld, IDS, seedWorld, worldTransport, type IoLog, type World } from './support/worldFixtures.js';

let dirsA: TempDirs;
let dirsB: TempDirs;
let io: IoLog;
let a: { store: CredentialStore; world: World; drive: DriveService; notion: NotionService };
let b: { store: CredentialStore; world: World; drive: DriveService; notion: NotionService };

async function side(dirs: TempDirs, tag: string) {
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  const world = createWorld(tag, io);
  await seedWorld(store, world);
  const upstream = new Upstream(worldTransport(world, io));
  return { store, world, drive: new DriveService(store, upstream, new GoogleTokenProvider(store, upstream)), notion: new NotionService(store, upstream) };
}

beforeEach(async () => {
  io = [];
  dirsA = await makeTempDirs();
  dirsB = await makeTempDirs();
  a = await side(dirsA, 'A');
  b = await side(dirsB, 'B');
});
afterEach(async () => {
  await dirsA.cleanup();
  await dirsB.cleanup();
});

async function noIo(p: Promise<unknown>) {
  const start = io.length;
  const err = await rejection(p);
  expect(err.message).toMatch(/cursor/i);
  expect(io.slice(start)).toEqual([]);
}

describe('fan-out cursors [MOCK Drive]', () => {
  it('are accepted by the issuing store and rejected by another store with colliding account ids', async () => {
    const p1 = await a.drive.search({ query: 'report', pageSize: 1 });
    expect(p1.nextCursor).toBeTruthy();
    expect((await a.drive.search({ query: 'report', pageSize: 1, cursor: p1.nextCursor! })).results[0]!.name).toBe('report A two');
    await noIo(b.drive.search({ query: 'report', pageSize: 1, cursor: p1.nextCursor! }));
  });

  it('reject a re-encoded or tampered cursor before provider I/O', async () => {
    const p1 = await a.drive.search({ query: 'report', pageSize: 1 });
    const c = p1.nextCursor!;
    await noIo(a.drive.search({ query: 'report', pageSize: 1, cursor: `${c.slice(0, -1)}${c.endsWith('A') ? 'B' : 'A'}` }));
    // An unsigned cursor in the pre-milestone format (base64url JSON) is no longer accepted.
    const unsigned = Buffer.from(JSON.stringify({ k: 'drive', h: 'x', t: { [IDS.google]: '1' }, f: {}, x: {} })).toString('base64url');
    await noIo(a.drive.search({ query: 'report', pageSize: 1, cursor: unsigned }));
  });
});

describe('Notion block and query cursors [MOCK Notion]', () => {
  it('are bound to store, workspace and parent block', async () => {
    const pageA = a.world.notionPageId;
    const r1 = await a.notion.getBlockChildren(READONLY_PRINCIPAL, IDS.notion, pageA, { pageSize: 1 });
    expect(r1.nextCursor).toBeTruthy();
    const r2 = await a.notion.getBlockChildren(READONLY_PRINCIPAL, IDS.notion, pageA, { pageSize: 1, cursor: r1.nextCursor! });
    expect(r2.blocks[0]!.id).not.toBe(r1.blocks[0]!.id);
    // Another namespace (same workspace id), another parent, or a raw upstream cursor: rejected before I/O.
    await noIo(b.notion.getBlockChildren(READONLY_PRINCIPAL, IDS.notion, pageA, { pageSize: 1, cursor: r1.nextCursor! }));
    await noIo(b.notion.getBlockChildren(READONLY_PRINCIPAL, IDS.notion, b.world.notionPageId, { pageSize: 1, cursor: r1.nextCursor! }));
    await noIo(a.notion.getBlockChildren(READONLY_PRINCIPAL, IDS.notion, r1.blocks[0]!.id, { pageSize: 1, cursor: r1.nextCursor! }));
    await noIo(a.notion.getBlockChildren(READONLY_PRINCIPAL, IDS.notion, pageA, { pageSize: 1, cursor: 'cursor-1' }));
    // getPageContent continues with the same sealed children cursor.
    const c1 = await a.notion.getPageContent(READONLY_PRINCIPAL, IDS.notion, pageA, { pageSize: 1 });
    const c2 = await a.notion.getPageContent(READONLY_PRINCIPAL, IDS.notion, pageA, { pageSize: 1, cursor: c1.nextCursor! });
    expect(c2.blocks[0]!.id).toBe(r2.blocks[0]!.id);
    await noIo(b.notion.getPageContent(READONLY_PRINCIPAL, IDS.notion, pageA, { pageSize: 1, cursor: c1.nextCursor! }));
    await noIo(a.notion.queryDataSource(READONLY_PRINCIPAL, IDS.notion, '0000dead000000000000000000000000', { cursor: c1.nextCursor! }));
  });
});
