// Drive operations against the MOCK Google upstream (in-memory fake). No live Google calls.
import { readdir } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { GoogleTokenProvider, registerGoogleAccount } from '../src/google/accounts.js';
import { DEFAULT_MAX_BYTES, DriveService } from '../src/google/drive.js';
import { DRIVE_READONLY_SCOPE } from '../src/google/oauth.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockGoogle, type MockGoogleAccount } from './support/mockGoogle.js';

let dirs: TempDirs;
let store: CredentialStore;
let google: MockGoogle;
let drive: DriveService;
let mockA: MockGoogleAccount;
let mockB: MockGoogleAccount;
let idA: string;
let idB: string;

const DOC = 'application/vnd.google-apps.document';
const SHEET = 'application/vnd.google-apps.spreadsheet';
const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 1, 2, 3, 255]);

async function register(acct: MockGoogleAccount, label: string) {
  const upstream = new Upstream(google.transport);
  const a = await registerGoogleAccount(store, upstream, {
    label,
    client: { clientId: dummySecret('CLIENT'), clientSecret: dummySecret('CLIENT-SECRET') },
    grant: {
      refreshToken: acct.refreshToken,
      accessToken: google.issueAccessToken(acct),
      expiresAt: Date.now() + 3600_000,
      scopes: [DRIVE_READONLY_SCOPE],
    },
  });
  return a.id;
}

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  google = new MockGoogle({ pageSize: 2 });
  mockA = google.addAccount('dummy.a@example.test', [
    { id: 'a1', name: 'Report alpha.txt', mimeType: 'text/plain', content: Buffer.from('alpha text') },
    { id: 'a2', name: 'Report beta', mimeType: DOC, exports: { 'text/markdown': Buffer.from('# Beta'), 'application/pdf': Buffer.from('%PDF-dummy') } },
    { id: 'a3', name: "Report it's", mimeType: 'image/png', content: png, parents: ['folderA'] },
  ]);
  mockB = google.addAccount('dummy.b@example.test', [
    { id: 'b1', name: 'Report budget', mimeType: SHEET, exports: { 'text/csv': Buffer.from('a,b\n1,2\n') } },
  ]);
  idA = await register(mockA, 'Private');
  idB = await register(mockB, 'Work');
  const upstream = new Upstream(google.transport);
  drive = new DriveService(store, upstream, new GoogleTokenProvider(store, upstream));
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('DriveService.search [mock Google]', () => {
  it('searches all accounts with provenance and a composite cursor', async () => {
    const p1 = await drive.search({ query: 'report' });
    expect(p1.results.map((r) => [r.accountId, r.accountLabel, r.id])).toEqual([
      [idA, 'Private', 'a1'],
      [idA, 'Private', 'a2'],
      [idB, 'Work', 'b1'],
    ]);
    expect(p1.results[0]!.accountEmail).toBe('dummy.a@example.test');
    expect(p1.hasMore).toBe(true);
    expect(p1.partial).toBe(false);
    const p2 = await drive.search({ query: 'report', cursor: p1.nextCursor! });
    expect(p2.results.map((r) => r.id)).toEqual(['a3']);
    expect(p2.hasMore).toBe(false);
    expect(p2.nextCursor).toBeNull();
  });

  it('restricts to one account when accountId is given', async () => {
    const res = await drive.search({ query: 'report', accountId: idB });
    expect(res.results.map((r) => r.id)).toEqual(['b1']);
    await expect(drive.search({ query: 'x', accountId: 'google-00000000' })).rejects.toThrow(/unknown google account/i);
  });

  it('rejects a cursor reused with a different query', async () => {
    const p1 = await drive.search({ query: 'report' });
    await expect(drive.search({ query: 'other', cursor: p1.nextCursor! })).rejects.toThrow(/cursor/i);
    await expect(drive.search({ query: 'report', cursor: 'garbage' })).rejects.toThrow(/cursor/i);
  });

  it('returns partial results when one account fails, without leaking secrets', async () => {
    google.failingEmails.add('dummy.b@example.test');
    const res = await drive.search({ query: 'report' });
    expect(res.partial).toBe(true);
    expect(res.results.every((r) => r.accountId === idA)).toBe(true);
    expect(res.errors).toEqual([{ accountId: idB, accountLabel: 'Work', message: expect.stringMatching(/HTTP 500/) }]);
    expect(JSON.stringify(res)).not.toContain(mockB.refreshToken);
  });

  it('retries a source that failed on an earlier page instead of silently dropping it', async () => {
    google.failingEmails.add('dummy.b@example.test');
    const p1 = await drive.search({ query: 'report' });
    expect(p1.partial).toBe(true);
    expect(p1.errors.map((e) => e.accountId)).toEqual([idB]);
    expect(p1.hasMore).toBe(true);
    google.failingEmails.clear();
    const p2 = await drive.search({ query: 'report', cursor: p1.nextCursor! });
    expect(p2.results.map((r) => r.id).sort()).toEqual(['a3', 'b1']);
    expect(p2.errors).toEqual([]);
    expect(p2.hasMore).toBe(false);
  });

  it('keeps reporting a persistently failing source on every page until it gives up', async () => {
    google.failingEmails.add('dummy.b@example.test');
    let page = await drive.search({ query: 'report' });
    const pages = [page];
    while (page.nextCursor && pages.length < 10) {
      page = await drive.search({ query: 'report', cursor: page.nextCursor });
      pages.push(page);
    }
    expect(page.nextCursor).toBeNull();
    expect(pages.length).toBeLessThan(10);
    for (const p of pages) {
      expect(p.partial).toBe(true);
      expect(p.errors.map((e) => e.accountId)).toContain(idB);
    }
    expect(page.errors.find((e) => e.accountId === idB)!.message).toMatch(/gave up/i);
  });

  it('escapes quotes in query text', async () => {
    const res = await drive.search({ query: "it's" });
    expect(res.results.map((r) => r.id)).toEqual(['a3']);
    const q = google.calls.filter((c) => c.url.pathname === '/drive/v3/files').at(-1)!.url.searchParams.get('q');
    expect(q).toContain("fullText contains 'it\\'s'");
    expect(q).toContain('trashed = false');
  });

  it('lists a folder only with an explicit account', async () => {
    await expect(drive.search({ folderId: 'folderA' })).rejects.toThrow(/accountId/);
    const res = await drive.search({ folderId: 'folderA', accountId: idA });
    expect(res.results.map((r) => r.id)).toEqual(['a3']);
  });
});

describe('DriveService content [mock Google]', () => {
  it('returns metadata with provenance and validates ids', async () => {
    const f = await drive.getFile(idA, 'a1');
    expect(f).toMatchObject({ accountId: idA, accountLabel: 'Private', id: 'a1', name: 'Report alpha.txt' });
    await expect(drive.getFile(idA, '../about')).rejects.toThrow(/invalid file id/i);
  });

  it('reads plain text and native Docs/Sheets as text', async () => {
    expect(await drive.readText(idA, 'a1', {})).toMatchObject({ encoding: 'utf-8', text: 'alpha text', mimeType: 'text/plain' });
    const doc = await drive.readText(idA, 'a2', {});
    expect(doc).toMatchObject({ text: '# Beta', mimeType: 'text/markdown', exportedFrom: DOC });
    expect(await drive.readText(idB, 'b1', {})).toMatchObject({ text: 'a,b\n1,2\n', mimeType: 'text/csv' });
  });

  it('refuses to read binary files as text', async () => {
    await expect(drive.readText(idA, 'a3', {})).rejects.toThrow(/drive_download_file/);
  });

  it('downloads binary content as base64 within the byte cap', async () => {
    const res = await drive.download(idA, 'a3', {});
    if (res.encoding !== 'base64') throw new Error('expected base64');
    expect(Buffer.from(res.data, 'base64')).toEqual(png);
    expect(res.bytes).toBe(png.length);
  });

  it('refuses files whose known size exceeds maxBytes without downloading', async () => {
    const before = google.calls.length;
    await expect(drive.download(idA, 'a3', { maxBytes: 4 })).rejects.toThrow(/exceeds/i);
    expect(google.calls.slice(before).some((c) => c.url.searchParams.get('alt') === 'media')).toBe(false);
  });

  it('defaults to ~48 KiB of content (client output limits) and allows an explicit larger maxBytes', async () => {
    expect(DEFAULT_MAX_BYTES).toBe(48 * 1024);
    mockA.files.push({ id: 'big', name: 'big.txt', mimeType: 'text/plain', content: Buffer.alloc(60 * 1024, 'a') });
    await expect(drive.readText(idA, 'big', {})).rejects.toThrow(/exceeds maxBytes \(49152\)/);
    const res = await drive.readText(idA, 'big', { maxBytes: 100_000 });
    expect(res.bytes).toBe(60 * 1024);
  });

  it('caps maxBytes at the hard limit', async () => {
    await expect(drive.download(idA, 'a3', { maxBytes: 50 * 1024 * 1024 })).rejects.toThrow(/maxBytes/);
  });

  it('downloading a native file points to export', async () => {
    await expect(drive.download(idA, 'a2', {})).rejects.toThrow(/drive_export_file/);
  });

  it('exports native files only to formats valid for their type', async () => {
    const pdf = await drive.exportFile(idA, 'a2', 'application/pdf', {});
    expect(pdf).toMatchObject({ encoding: 'base64', mimeType: 'application/pdf' });
    expect(Buffer.from((pdf as { data: string }).data, 'base64').toString()).toBe('%PDF-dummy');
    const csv = await drive.exportFile(idB, 'b1', 'text/csv', {});
    expect(csv).toMatchObject({ encoding: 'utf-8', text: 'a,b\n1,2\n' });
    const before = google.calls.length;
    await expect(drive.exportFile(idA, 'a2', 'text/csv', {})).rejects.toThrow(/not a supported export/i);
    expect(google.calls.slice(before).some((c) => c.url.pathname.endsWith('/export'))).toBe(false);
    await expect(drive.exportFile(idA, 'a1', 'application/pdf', {})).rejects.toThrow(/not a Google Workspace/i);
  });

  it('never writes downloaded content to the filesystem', async () => {
    const snapshot = async () => (await readdir(dirs.root, { recursive: true })).sort();
    const before = await snapshot();
    await drive.download(idA, 'a3', {});
    await drive.readText(idA, 'a2', {});
    await drive.exportFile(idA, 'a2', 'application/pdf', {});
    expect(await snapshot()).toEqual(before);
  });
});
