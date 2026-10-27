import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { makeTempDirs } from './support/fixtures.js';
let dirs: Awaited<ReturnType<typeof makeTempDirs>>;
let cursors: CredentialStore;
beforeAll(async () => { dirs = await makeTempDirs(); await initStore(dirs); cursors = await CredentialStore.open(dirs); });
afterAll(async () => { await dirs?.cleanup(); });
import { filesOperations } from '../src/microsoft/session/files.js';
import type { OperationContext, SessionHttpResponse } from '../src/microsoft/session/contracts.js';

const site = { id: 'ms-site-1234abcd', url: 'https://example.sharepoint.com/sites/team', kind: 'sharepoint' as const, driveIds: ['drive-1'] };
const scope = { siteId: site.id, driveId: 'drive-1' };
const objectId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const response = (body: unknown, status = 200): SessionHttpResponse => ({ status, headers: {}, body: Buffer.from(JSON.stringify(body)) });
function fixture(...responses: SessionHttpResponse[]) {
  const request = vi.fn().mockImplementation(async () => responses.shift() ?? response({}));
  const ctx: OperationContext = { request, cursors, sites: [site], identity: { tenantId: '11111111-2222-4333-8444-555555555555', objectId, kind: 'organization' } };
  return { ctx, request };
}
const run = (name: string, ctx: OperationContext, args: unknown) => filesOperations[`files.${name}`]!.run(ctx, args);

describe('Microsoft session files adapter', () => {
  it('denies every external operation outside selected sites and drives before I/O', async () => {
    const { ctx, request } = fixture();
    const valid: Record<string, object> = { listDrives: {}, listFiles: {}, search: { query: 'x' }, getFile: { itemId: 'item' }, download: { itemId: 'item' }, upload: { name: 'x', bodyBase64: '' }, createFolder: { name: 'x' }, updateFile: { itemId: 'item', name: 'x', etag: '"e"' }, trash: { itemId: 'item', etag: '"e"' } };
    for (const [key, operation] of Object.entries(filesOperations)) {
      if (operation.internalOnly) continue;
      const args = { ...valid[key.slice(6)], siteId: site.id, ...(key === 'files.listDrives' ? {} : { driveId: scope.driveId }) };
      await expect(operation.run(ctx, { ...args, siteId: 'ms-site-00000000' })).rejects.toThrow(/Select this/);
      if (key !== 'files.listDrives') await expect(operation.run(ctx, { ...args, driveId: 'other' })).rejects.toThrow(/Select this/);
    }
    expect(request).not.toHaveBeenCalled();
  });
  it('lists only saved drive IDs and strips provider secrets', async () => {
    const { ctx, request } = fixture(response({ id: 'drive-1', name: 'Documents', '@microsoft.graph.downloadUrl': 'SECRET' }));
    expect(JSON.stringify(await run('listDrives', ctx, { siteId: site.id }))).not.toContain('SECRET');
    expect(request.mock.calls[0]![0]).toMatchObject({ resource: 'sharepoint', siteId: site.id, path: '/_api/v2.0/drives/drive-1' });
    expect(request).toHaveBeenCalledTimes(1);
  });
  it('requires immutable identity before site-local discovery', async () => {
    const { ctx, request } = fixture(response({ d: { AadObjectId: { NameId: objectId }, Email: 'a@example.com' } }), response({ value: [{ id: 'new-drive', name: 'Docs' }] }));
    expect(filesOperations['files.probeSite']!.internalOnly).toBe(true);
    expect(await run('probeSite', ctx, { siteId: site.id })).toMatchObject({ drives: [{ id: 'new-drive' }] });
    expect(request.mock.calls[1]![0].path).toBe('/_api/v2.0/drives');
    for (const body of [{ Email: 'a@example.com' }, { AadObjectId: { NameId: 'another-user' } }]) {
      const bad = fixture(response(body));
      await expect(run('probeSite', bad.ctx, { siteId: site.id })).rejects.toThrow(/identity/i);
      expect(bad.request).toHaveBeenCalledTimes(1);
    }
  });
  it('lists files and binds pagination to site, drive, parent and query', async () => {
    const next = `${site.url}/_api/v2.0/drives/drive-1/root/children?$top=25&$skiptoken=next`;
    const { ctx, request } = fixture(response({ value: [{ id: 'item', name: 'x', '@microsoft.graph.downloadUrl': 'SECRET' }], '@odata.nextLink': next }), response({ value: [] }));
    const page = await run('listFiles', ctx, scope) as { cursor: string };
    expect(JSON.stringify(page)).not.toContain('SECRET');
    await run('listFiles', ctx, { ...scope, cursor: page.cursor });
    expect(request.mock.calls[1]![0]).toMatchObject({ path: '/_api/v2.0/drives/drive-1/root/children', query: { '$top': '25', '$skiptoken': 'next' } });
    await expect(run('listFiles', ctx, { ...scope, parentId: 'different', cursor: page.cursor })).rejects.toThrow(/cursor/i);
    await expect(run('search', ctx, { ...scope, query: 'different', cursor: page.cursor })).rejects.toThrow(/cursor/i);
    expect(request).toHaveBeenCalledTimes(2);
  });
  it.each(['https://evil.test/steal', `${site.url}/_api/v2.0/drives/other/root/children`, `${site.url}/_api/v2.0/drives/drive-1/root/children?$expand=permissions`, `${site.url}/_api/v2.0/drives/drive-1/root/children?$top=26`])('rejects hostile provider next link %s', async (next) => {
    const { ctx, request } = fixture(response({ value: [], '@odata.nextLink': next }));
    await expect(run('listFiles', ctx, scope)).rejects.toThrow(/cursor/i);
    expect(request).toHaveBeenCalledTimes(1);
  });
  it.each([
    { parentId: undefined, canonical: 'items(%27root%27)', original: 'root' },
    { parentId: 'folder-1', canonical: 'items(%27folder-1%27)', original: 'items/folder-1' },
  ])('continues canonical OData children pagination for $original on the original request path', async ({ parentId, canonical, original }) => {
    const next = `${site.url}/_api/v2.0/drives(%27drive-1%27)/${canonical}/children?$skiptoken=page%2Btwo%3D&$top=1`;
    const { ctx, request } = fixture(response({ value: [{ id: 'first' }], '@odata.nextLink': next }), response({ value: [{ id: 'second' }] }));
    const args = { ...scope, parentId, pageSize: 1 };
    const first = await run('listFiles', ctx, args) as { cursor: string };
    expect(await run('listFiles', ctx, { ...args, cursor: first.cursor })).toEqual({ items: [{ id: 'second' }] });
    expect(request.mock.calls[1]![0]).toMatchObject({ path: `/_api/v2.0/drives/drive-1/${original}/children`, query: { '$top': '1', '$skiptoken': 'page+two=' } });
    for (const changed of [{ parentId: 'other' }, { pageSize: 2 }, { driveId: 'drive-2' }]) {
      ctx.sites = [{ ...site, driveIds: ['drive-1', 'drive-2'] }];
      await expect(run('listFiles', ctx, { ...args, ...changed, cursor: first.cursor })).rejects.toMatchObject({ code: 'invalid_cursor' });
    }
    expect(request).toHaveBeenCalledTimes(2);
  });
  it.each([
    "drives(%27other%27)/items(%27root%27)/children?$skiptoken=next",
    "drives(%27drive-1%27)/items(%27other%27)/children?$skiptoken=next",
    "drives(%27drive-1%27)/items(%27root%27)/permissions?$skiptoken=next",
    "drives(%27drive-1%27)/items(%27root%27)/children/extra?$skiptoken=next",
    "drives(%2527drive-1%2527)/items(%27root%27)/children?$skiptoken=next",
    "drives(%27drive-1%27)/items(%27root%2fother%27)/children?$skiptoken=next",
    "drives(%27drive-1%27)/items(%27root%27%27)/children?$skiptoken=next",
    "drives(%27drive-1%27)/items(%27ROOT%27)/children?$skiptoken=next",
    "drives(%27drive-1%27)/items(%27root%27)/children?$skiptoken=one&$skiptoken=two",
    "drives(%27drive-1%27)/items(%27root%27)/children?$skiptoken=one&%24skiptoken=two",
    "drives(%27drive-1%27)/items(%27root%27)/children?$top=25&$top=25",
    "drives(%27drive-1%27)/items(%27root%27)/children?$expand=permissions",
    "drives(%27drive-1%27)/items(%27root%27)/children?$top=26",
    "drives(%27drive-1%27)/items(%27root%27)/children?$skiptoken=next#fragment",
  ])('rejects non-equivalent or unsafe canonical continuation %s', async (suffix) => {
    const { ctx, request } = fixture(response({ value: [], '@odata.nextLink': `${site.url}/_api/v2.0/${suffix}` }));
    await expect(run('listFiles', ctx, scope)).rejects.toMatchObject({ code: 'invalid_cursor' });
    expect(request).toHaveBeenCalledTimes(1);
  });
  it('matches canonical OData identifiers with escaped literal quotes exactly', async () => {
    const driveId = "drive'1";
    const parentId = "folder'1";
    const next = `${site.url}/_api/v2.0/drives(%27drive%27%271%27)/items(%27folder%27%271%27)/children?$skiptoken=next`;
    const { ctx, request } = fixture(response({ value: [], '@odata.nextLink': next }), response({ value: [] }));
    ctx.sites = [{ ...site, driveIds: [driveId] }];
    const args = { ...scope, driveId, parentId };
    const first = await run('listFiles', ctx, args) as { cursor: string };
    await run('listFiles', ctx, { ...args, cursor: first.cursor });
    expect(request.mock.calls[1]![0]).toMatchObject({ path: '/_api/v2.0/drives/drive%271/items/folder%271/children', query: { '$skiptoken': 'next' } });
    const bad = fixture(response({ value: [], '@odata.nextLink': next.replace('drive%27%271', 'drive%271') }));
    bad.ctx.sites = ctx.sites;
    await expect(run('listFiles', bad.ctx, args)).rejects.toMatchObject({ code: 'invalid_cursor' });
  });
  it('accepts the provider canonical b! drive spelling while retaining the encoded request path', async () => {
    const driveId = 'b!EXAMPLE_ab-12';
    const next = `${site.url}/_api/v2.0/drives(%27b!EXAMPLE_ab-12%27)/items(%27root%27)/children?$skiptoken=next&$top=1`;
    const { ctx, request } = fixture(response({ value: [{ id: 'first' }], '@odata.nextLink': next }), response({ value: [{ id: 'second' }] }));
    ctx.sites = [{ ...site, driveIds: [driveId] }];
    const args = { ...scope, driveId, pageSize: 1 };
    const first = await run('listFiles', ctx, args) as { cursor: string };
    expect(await run('listFiles', ctx, { ...args, cursor: first.cursor })).toEqual({ items: [{ id: 'second' }] });
    expect(request.mock.calls[1]![0]).toMatchObject({ path: '/_api/v2.0/drives/b%21EXAMPLE_ab-12/root/children', query: { '$skiptoken': 'next', '$top': '1' } });
    for (const changed of ['b%2521EXAMPLE_ab-12', 'b!EXAMPLE_ab-12%2fother', 'b!OTHER']) {
      const bad = fixture(response({ value: [], '@odata.nextLink': next.replace(driveId, changed) }));
      bad.ctx.sites = ctx.sites;
      await expect(run('listFiles', bad.ctx, args)).rejects.toMatchObject({ code: 'invalid_cursor' });
      expect(bad.request).toHaveBeenCalledTimes(1);
    }
  });
  it.each([
    'https://evil.test/sites/team',
    'https://example.sharepoint.com/sites/other',
    'https://user:pass@example.sharepoint.com/sites/team',
  ])('rejects canonical continuation outside the selected site at %s', async (base) => {
    const { ctx, request } = fixture(response({ value: [], '@odata.nextLink': `${base}/_api/v2.0/drives(%27drive-1%27)/items(%27root%27)/children?$skiptoken=next` }));
    await expect(run('listFiles', ctx, scope)).rejects.toMatchObject({ code: 'invalid_cursor' });
    expect(request).toHaveBeenCalledTimes(1);
  });
  it('escapes search literals and never allows injected query options', async () => {
    const { ctx, request } = fixture(response({ value: [] }));
    await run('search', ctx, { ...scope, query: "Bob's file" });
    expect(request.mock.calls[0]![0].path).toBe("/_api/v2.0/drives/drive-1/root/search(q='Bob%27%27s%20file')");
  });
  it('returns safe metadata and rejects remote-item cross-drive indirection', async () => {
    const good = fixture(response({ id: 'item', name: 'x', '@microsoft.graph.downloadUrl': 'SECRET' }));
    expect(JSON.stringify(await run('getFile', good.ctx, { ...scope, itemId: 'item' }))).not.toContain('SECRET');
    const bad = fixture(response({ id: 'item', remoteItem: { id: 'remote' } }));
    await expect(run('getFile', bad.ctx, { ...scope, itemId: 'item' })).rejects.toThrow(/remote/i);
  });
  it('downloads only provider URLs with bounds and returns bytes without preauth URL', async () => {
    const url = `${site.url}/download.aspx?token=SECRET`;
    const { ctx, request } = fixture(response({ id: 'item', name: 'x', size: 3, '@microsoft.graph.downloadUrl': url }), { status: 200, headers: {}, body: Buffer.from('abc') });
    expect(await run('download', ctx, { ...scope, itemId: 'item', maxBytes: 10 })).toMatchObject({ bodyBase64: 'YWJj', size: 3 });
    expect(request.mock.calls[1]![0]).toEqual({ resource: 'download', siteId: site.id, path: url, maxBytes: 10, responseType: 'bytes' });
    for (const metadata of [{ size: 11 }, { size: -1 }, { size: '3' }, {}]) {
      const bad = fixture(response({ id: 'item', ...metadata, '@microsoft.graph.downloadUrl': url }));
      await expect(run('download', bad.ctx, { ...scope, itemId: 'item', maxBytes: 10 })).rejects.toThrow();
      expect(bad.request).toHaveBeenCalledTimes(1);
    }
    const overflow = fixture(response({ id: 'item', size: 3, '@microsoft.graph.downloadUrl': url }), { status: 200, headers: {}, body: Buffer.alloc(11) });
    await expect(run('download', overflow.ctx, { ...scope, itemId: 'item', maxBytes: 10 })).rejects.toThrow(/size/i);
  });
  it('uploads without overwrite, creates folders, and requires exact ETags for updates/trash', async () => {
    const { ctx, request } = fixture(response({ id: 'new' }), response({ id: 'folder' }), response({ id: 'item' }), response({ id: 'item' }), response({}, 204));
    await run('upload', ctx, { ...scope, name: 'hello.txt', bodyBase64: 'YWJj', contentType: 'text/plain' });
    expect(request.mock.calls[0]![0]).toMatchObject({ method: 'PUT', bodyBase64: 'YWJj', query: { '@microsoft.graph.conflictBehavior': 'fail' }, headers: { 'Content-Type': 'text/plain' } });
    await run('createFolder', ctx, { ...scope, name: 'New' });
    expect(request.mock.calls[1]![0]).toMatchObject({ method: 'POST', body: { name: 'New', folder: {}, '@microsoft.graph.conflictBehavior': 'fail' } });
    await run('updateFile', ctx, { ...scope, itemId: 'item', etag: '"v1"', name: 'renamed.txt' });
    expect(request.mock.calls[2]![0]).toMatchObject({ method: 'PATCH', headers: { 'If-Match': '"v1"' }, body: { name: 'renamed.txt' } });
    await run('updateFile', ctx, { ...scope, itemId: 'item', etag: '"v2"', bodyBase64: 'YWJj', contentType: 'text/plain' });
    expect(request.mock.calls[3]![0]).toMatchObject({ method: 'PUT', headers: { 'If-Match': '"v2"' }, bodyBase64: 'YWJj' });
    await run('trash', ctx, { ...scope, itemId: 'item', etag: '"v3"' });
    expect(request.mock.calls[4]![0]).toMatchObject({ method: 'DELETE', path: '/_api/v2.0/drives/drive-1/items/item', headers: { 'If-Match': '"v3"' } });
  });
  it('rejects unsafe writes without I/O and never retries a failed write', async () => {
    const { ctx, request } = fixture(response({}, 412));
    for (const args of [{ name: '../secret', bodyBase64: '' }, { name: 'x', bodyBase64: '!!!!' }, { name: 'x', bodyBase64: '', url: 'https://evil.test' }, { name: 'x', bodyBase64: '', contentType: 'x\r\nInjected: yes' }]) await expect(run('upload', ctx, { ...scope, ...args })).rejects.toThrow();
    for (const args of [{ name: 'x' }, { name: 'x', etag: '*' }, { name: 'x', bodyBase64: 'YWJj', etag: '"v"' }, { etag: '"v"' }]) await expect(run('updateFile', ctx, { ...scope, itemId: 'item', ...args })).rejects.toThrow();
    await expect(run('trash', ctx, { ...scope, itemId: 'item', etag: '"v"', permanent: true })).rejects.toThrow();
    expect(request).not.toHaveBeenCalled();
    await expect(run('updateFile', ctx, { ...scope, itemId: 'item', etag: '"v"', name: 'x' })).rejects.toThrow();
    expect(request).toHaveBeenCalledTimes(1);
  });
  it('rejects untrusted download origins and URL credentials before byte requests', async () => {
    for (const url of ['https://evil.test/secret', 'http://example.sharepoint.com/secret', 'https://user:pass@example.sharepoint.com/secret', 'https://example.sharepoint.com/secret#fragment', 'not a URL']) {
      const { ctx, request } = fixture(response({ id: 'item', size: 3, '@microsoft.graph.downloadUrl': url }));
      await expect(run('download', ctx, { ...scope, itemId: 'item' })).rejects.toThrow(/download/i);
      expect(request).toHaveBeenCalledTimes(1);
    }
  });
  it('does not discover any drive when selection is empty', async () => {
    const { ctx, request } = fixture();
    ctx.sites = [{ ...site, driveIds: [] }];
    expect(await run('listDrives', ctx, { siteId: site.id })).toEqual({ siteId: site.id, drives: [] });
    expect(request).not.toHaveBeenCalled();
  });
  it('rejects cursor tampering and cross-account reuse before I/O', async () => {
    const next = `${site.url}/_api/v2.0/drives/drive-1/root/children?$skiptoken=next`;
    const { ctx, request } = fixture(response({ value: [], '@odata.nextLink': next }));
    const page = await run('listFiles', ctx, scope) as { cursor: string };
    await expect(run('listFiles', ctx, { ...scope, cursor: `x${page.cursor}` })).rejects.toThrow(/cursor/i);
    ctx.identity = { ...ctx.identity, objectId: 'bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee' };
    await expect(run('listFiles', ctx, { ...scope, cursor: page.cursor })).rejects.toThrow(/cursor/i);
    expect(request).toHaveBeenCalledTimes(1);
  });
  it('enforces content size and opaque path identifiers before I/O', async () => {
    const { ctx, request } = fixture();
    await expect(run('upload', ctx, { ...scope, name: 'x', bodyBase64: Buffer.alloc(10 * 1024 * 1024 + 1).toString('base64') })).rejects.toThrow();
    for (const itemId of ['..', '.', 'a/../../secret', 'a%2fsecret', 'a?expand=permissions', 'a\\secret']) await expect(run('getFile', ctx, { ...scope, itemId })).rejects.toThrow();
    for (const etag of ['*', '\"x\", *', '\"x\"\r\nInjected: yes']) await expect(run('trash', ctx, { ...scope, itemId: 'item', etag })).rejects.toThrow();
    expect(request).not.toHaveBeenCalled();
  });

  it.each([
    'drives/drive-1/root/children',
    'drives(%27drive-1%27)/items(%27root%27)/children',
  ])('continues pagination for %s after a fresh module and independent store reopen', async (path) => {
    const firstStore = await CredentialStore.open(dirs);
    const next = `${site.url}/_api/v2.0/${path}?$skiptoken=second-page`;
    const first = fixture(response({ value: [{ id: 'first' }], '@odata.nextLink': next }));
    first.ctx.cursors = firstStore;
    const page = await run('listFiles', first.ctx, scope) as { cursor: string };
    vi.resetModules();
    const freshModule = await import('../src/microsoft/session/files.js');
    const second = fixture(response({ value: [{ id: 'second' }] }));
    second.ctx.cursors = await CredentialStore.open(dirs);
    const result = await freshModule.filesOperations['files.listFiles']!.run(second.ctx, { ...scope, cursor: page.cursor });
    expect(result).toEqual({ items: [{ id: 'second' }] });
    expect(second.request.mock.calls[0]![0].query.$skiptoken).toBe('second-page');
  });
  it('requires the private persistent cursor codec only when pagination is needed', async () => {
    const next = `${site.url}/_api/v2.0/drives/drive-1/root/children?$skiptoken=next`;
    const paged = fixture(response({ value: [], '@odata.nextLink': next }));
    paged.ctx.cursors = undefined;
    await expect(run('listFiles', paged.ctx, scope)).rejects.toMatchObject({ code: 'bad_config' });
    const single = fixture(response({ value: [] })); single.ctx.cursors = undefined;
    expect(await run('listFiles', single.ctx, scope)).toEqual({ items: [] });
  });

});
