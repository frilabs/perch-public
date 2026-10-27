import { z } from 'zod';
import { PerchError } from '../../errors.js';
import { checkedJson, type OperationContext, type SessionHttpRequest, type SessionOperation, type SessionOperations } from './contracts.js';
import type { SelectedSite } from './model.js';

const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const id = z.string().min(1).max(512).regex(/^[^\s/\\?#%\u0000-\u001f]+$/).refine((v) => v !== '.' && v !== '..');
const siteId = z.string().regex(/^ms-site-[a-f0-9]{8}$/);
const scope = { siteId, driveId: id };
const name = z.string().min(1).max(255).regex(/^[^/\\:*?"<>|\u0000-\u001f]+$/).refine((v) => v.trim() === v && v !== '.' && v !== '..' && !v.endsWith('.'));
const etag = z.string().min(1).max(512).regex(/^(?:W\/)?"[^"\r\n]{1,500}"$/);
const contentType = z.string().min(3).max(200).regex(/^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+(?:;[\x20-\x7e]*)?$/).default('application/octet-stream');
const bodyBase64 = z.string().max(Math.ceil(MAX_FILE_BYTES / 3) * 4).refine((s) => /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s) && Buffer.from(s, 'base64').toString('base64') === s && Buffer.from(s, 'base64').length <= MAX_FILE_BYTES, 'Expected canonical base64 of at most 10 MiB');
const page = { pageSize: z.number().int().min(1).max(100).default(25), cursor: z.string().min(1).max(16_384).optional() };
const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const fail = (message: string, code = 'access_denied'): never => { throw new PerchError(message, code); };
function selectedSite(ctx: OperationContext, requested: string): SelectedSite {
  return ctx.sites.find((s) => s.id === requested) ?? fail('Select this SharePoint or OneDrive site before accessing its files.');
}
function selectedDrive(ctx: OperationContext, args: { siteId: string; driveId: string }): SelectedSite {
  const site = selectedSite(ctx, args.siteId);
  if (!site.driveIds.includes(args.driveId)) fail('Select this document library before accessing its files.');
  return site;
}
const drivePath = (driveId: string) => `/_api/v2.0/drives/${enc(driveId)}`;
const itemPath = (driveId: string, itemId: string) => `${drivePath(driveId)}/items/${enc(itemId)}`;
const parentPath = (driveId: string, parentId?: string) => parentId ? itemPath(driveId, parentId) : `${drivePath(driveId)}/root`;
async function json(ctx: OperationContext, site: SelectedSite, request: Omit<SessionHttpRequest, 'resource' | 'siteId'>): Promise<any> {
  return checkedJson(await ctx.request({ resource: 'sharepoint', siteId: site.id, maxBytes: MAX_JSON_BYTES, ...request }));
}
function metadata(raw: any, driveId?: string): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || typeof raw.id !== 'string') fail('Microsoft returned invalid file metadata.', 'invalid_response');
  if (raw.remoteItem) fail('Remote file references outside the selected library are not supported.');
  if (driveId && raw.parentReference?.driveId && raw.parentReference.driveId !== driveId) fail('Microsoft returned a file outside the selected library.');
  const result: Record<string, unknown> = {};
  for (const key of ['id', 'name', 'eTag', 'cTag', 'createdDateTime', 'lastModifiedDateTime', 'driveType']) if (typeof raw[key] === 'string') result[key] = raw[key];
  if (Number.isSafeInteger(raw.size) && raw.size >= 0) result.size = raw.size;
  if (raw.file && typeof raw.file === 'object') result.file = typeof raw.file.mimeType === 'string' ? { mimeType: raw.file.mimeType } : {};
  if (raw.folder && typeof raw.folder === 'object') result.folder = Number.isSafeInteger(raw.folder.childCount) ? { childCount: raw.folder.childCount } : {};
  if (raw.parentReference && typeof raw.parentReference.id === 'string') result.parentReference = { id: raw.parentReference.id, driveId };
  // Deliberately project fields: provider annotations can contain bearer download URLs.
  return result;
}
function canonicalChildrenPath(path: string): string | undefined {
  const match = /^\/_api\/v2\.0\/drives\/([^/]+)\/(?:root|items\/([^/]+))\/children$/.exec(path);
  if (!match) return undefined;
  // Construct the one observed OData alias from our validated path, never from
  // the provider URL. Quotes inside OData string literals must be doubled;
  // SharePoint preserves literal ! in canonical drive IDs (for example b!...).
  const literal = (encodedId: string) => `%27${enc(decodeURIComponent(encodedId).replace(/'/g, "''")).replace(/%21/g, '!')}%27`;
  return `/_api/v2.0/drives(${literal(match[1]!)})/items(${literal(match[2] ?? 'root')})/children`;
}
function nextQuery(next: string, site: SelectedSite, path: string, initial: Record<string, string>): Record<string, string> {
  try {
    const base = new URL(site.url);
    const url = new URL(next);
    const sitePath = base.pathname.replace(/\/$/, '');
    const canonical = canonicalChildrenPath(path);
    const matchesPath = url.pathname === `${sitePath}${path}` || (canonical !== undefined && url.pathname === `${sitePath}${canonical}`);
    if (url.origin !== base.origin || url.username || url.password || url.hash || !matchesPath) throw new Error();
    const query: Record<string, string> = {};
    for (const [key, value] of url.searchParams) {
      if (Object.hasOwn(query, key) || !['$top', '$skiptoken', '$skipToken'].includes(key) || value.length > 8192) throw new Error();
      if (key === '$top' && value !== initial.$top) throw new Error();
      query[key] = value;
    }
    return { ...initial, ...query };
  } catch { return fail('Microsoft pagination cursor is invalid or outside the selected resource.', 'invalid_cursor'); }
}
function binding(ctx: OperationContext, site: SelectedSite, path: string, query: Record<string, string>): string {
  return JSON.stringify([ctx.identity.tenantId, ctx.identity.objectId, site.id, site.url, path, query]);
}
function encodeCursor(ctx: OperationContext, scope: string, next: string): string {
  if (!ctx.cursors) return fail('Persistent cursor storage is required for Microsoft file pagination.', 'bad_config');
  return ctx.cursors.sealCursor(`microsoft-files:${scope}`, next);
}
function decodeCursor(ctx: OperationContext, cursor: string, scope: string): string {
  if (!ctx.cursors) return fail('Persistent cursor storage is required for Microsoft file pagination.', 'bad_config');
  try { return ctx.cursors.openCursor(`microsoft-files:${scope}`, cursor); }
  catch { return fail('Pagination cursor does not match this request; restart the listing.', 'invalid_cursor'); }
}
async function listing(ctx: OperationContext, site: SelectedSite, args: { driveId?: string; pageSize: number; cursor?: string }, path: string) {
  const initial = { '$top': String(args.pageSize) };
  const scope = binding(ctx, site, path, initial);
  const query = args.cursor ? nextQuery(decodeCursor(ctx, args.cursor, scope), site, path, initial) : initial;
  const result = await json(ctx, site, { path, query });
  if (!Array.isArray(result.value) || result.value.length > 100) fail('Microsoft returned an invalid file listing.', 'invalid_response');
  let cursor: string | undefined;
  if (result['@odata.nextLink'] !== undefined) {
    const next = result['@odata.nextLink'];
    if (typeof next !== 'string' || next.length > 8192) fail('Microsoft returned an invalid pagination cursor.', 'invalid_cursor');
    nextQuery(next, site, path, initial);
    cursor = encodeCursor(ctx, scope, next);
  }
  return { items: result.value.map((item: unknown) => metadata(item, args.driveId)), ...(cursor ? { cursor } : {}) };
}
function operation(schema: z.ZodObject<any>, mode: 'read' | 'write', description: string, run: SessionOperation['run'], internalOnly = false): SessionOperation {
  return { service: 'files', mode, description, schema, ...(internalOnly ? { internalOnly: true } : {}), run: async (ctx, args) => run(ctx, schema.parse(args)) };
}

export const filesOperations: SessionOperations = {
  'files.probeSite': operation(z.strictObject({ siteId }), 'read', 'Verify the session identity at a selected site and discover its libraries for local setup.', async (ctx, args) => {
    const site = selectedSite(ctx, args.siteId);
    // CSOM documents User.AadObjectId as UserIdInfo. REST availability is verified per site;
    // never substitute mutable Email/UserPrincipalName if the immutable ID is absent.
    // https://learn.microsoft.com/en-us/previous-versions/office/sharepoint-csom/mt829537(v=office.15)
    const result = await json(ctx, site, { path: '/_api/web/currentuser', query: { '$select': 'AadObjectId,Email,UserPrincipalName' } });
    const user = result.d ?? result;
    if (typeof user.AadObjectId?.NameId !== 'string' || user.AadObjectId.NameId.toLowerCase() !== ctx.identity.objectId.toLowerCase()) fail('SharePoint identity could not be verified against the connected Microsoft identity.', 'identity_mismatch');
    const found = await listing(ctx, site, { pageSize: 100 }, '/_api/v2.0/drives');
    return { siteId: site.id, drives: found.items, hasMore: Boolean(found.cursor) };
  }, true),
  'files.listDrives': operation(z.strictObject({ siteId }), 'read', 'List explicitly selected document libraries.', async (ctx, args) => {
    const site = selectedSite(ctx, args.siteId);
    const drives: Record<string, unknown>[] = [];
    for (const driveId of site.driveIds) {
      const raw = await json(ctx, site, { path: drivePath(driveId) });
      if (raw.id !== driveId) fail('Microsoft returned an unexpected document library.', 'invalid_response');
      drives.push(metadata(raw));
    }
    return { siteId: site.id, drives };
  }),
  'files.listFiles': operation(z.strictObject({ ...scope, parentId: id.optional(), ...page }), 'read', 'List files in a selected library folder.', async (ctx, args) => listing(ctx, selectedDrive(ctx, args), args, `${parentPath(args.driveId, args.parentId)}/children`)),
  'files.search': operation(z.strictObject({ ...scope, query: z.string().trim().min(1).max(500), ...page }), 'read', 'Search files within one selected library.', async (ctx, args) => listing(ctx, selectedDrive(ctx, args), args, `${drivePath(args.driveId)}/root/search(q='${enc(args.query.replace(/'/g, "''"))}')`)),
  'files.getFile': operation(z.strictObject({ ...scope, itemId: id }), 'read', 'Get safe file metadata from a selected library.', async (ctx, args) => {
    const site = selectedDrive(ctx, args);
    return metadata(await json(ctx, site, { path: itemPath(args.driveId, args.itemId) }), args.driveId);
  }),
  'files.download': operation(z.strictObject({ ...scope, itemId: id, maxBytes: z.number().int().min(1).max(MAX_FILE_BYTES).default(MAX_FILE_BYTES) }), 'read', 'Download a file up to 10 MiB as base64.', async (ctx, args) => {
    const site = selectedDrive(ctx, args);
    const raw = await json(ctx, site, { path: itemPath(args.driveId, args.itemId) });
    const file = metadata(raw, args.driveId);
    if (!Number.isSafeInteger(raw.size) || raw.size < 0 || raw.size > args.maxBytes || raw.folder) fail('File size is unavailable or exceeds the download size limit.', 'size_limit');
    const url = raw['@microsoft.graph.downloadUrl'];
    if (typeof url !== 'string' || url.length > 16_384) fail('Microsoft did not provide a usable file download.', 'invalid_response');
    try {
      const target = new URL(url);
      if (target.protocol !== 'https:' || target.origin !== new URL(site.url).origin || target.username || target.password || target.hash) throw new Error();
    } catch { fail('Microsoft returned a download URL outside the selected site origin.', 'access_denied'); }
    // Transport independently restricts origin, DNS, redirects and transmitted credentials.
    const download = await ctx.request({ resource: 'download', siteId: site.id, path: url, maxBytes: args.maxBytes, responseType: 'bytes' });
    if (download.status < 200 || download.status >= 300) checkedJson(download);
    if (download.body.length > args.maxBytes) fail('File exceeds the download size limit.', 'size_limit');
    return { ...file, size: download.body.length, bodyBase64: download.body.toString('base64') };
  }),
  'files.upload': operation(z.strictObject({ ...scope, parentId: id.optional(), name, bodyBase64, contentType }), 'write', 'Upload a new file up to 10 MiB, failing on name conflicts.', async (ctx, args) => {
    const site = selectedDrive(ctx, args);
    // https://learn.microsoft.com/en-us/graph/api/resources/driveitem#instance-attributes
    // PUT defaults to replacement, so conflictBehavior must be explicit in the URL.
    const raw = await json(ctx, site, { path: `${parentPath(args.driveId, args.parentId)}:/${enc(args.name)}:/content`, method: 'PUT', query: { '@microsoft.graph.conflictBehavior': 'fail' }, headers: { 'Content-Type': args.contentType }, bodyBase64: args.bodyBase64 });
    return metadata(raw, args.driveId);
  }),
  'files.createFolder': operation(z.strictObject({ ...scope, parentId: id.optional(), name }), 'write', 'Create a folder, failing on name conflicts.', async (ctx, args) => {
    const site = selectedDrive(ctx, args);
    return metadata(await json(ctx, site, { path: `${parentPath(args.driveId, args.parentId)}/children`, method: 'POST', body: { name: args.name, folder: {}, '@microsoft.graph.conflictBehavior': 'fail' } }), args.driveId);
  }),
  'files.updateFile': operation(z.strictObject({ ...scope, itemId: id, etag, name: name.optional(), bodyBase64: bodyBase64.optional(), contentType }).refine((a) => (a.name !== undefined) !== (a.bodyBase64 !== undefined), 'Provide exactly one of name or bodyBase64'), 'write', 'Rename a file or replace its content with an exact ETag precondition.', async (ctx, args) => {
    const site = selectedDrive(ctx, args);
    const path = itemPath(args.driveId, args.itemId);
    const headers = { 'If-Match': args.etag, 'Content-Type': args.bodyBase64 === undefined ? 'application/json' : args.contentType };
    const raw = await json(ctx, site, args.bodyBase64 === undefined ? { path, method: 'PATCH', headers, body: { name: args.name } } : { path: `${path}/content`, method: 'PUT', headers, bodyBase64: args.bodyBase64 });
    return metadata(raw, args.driveId);
  }),
  'files.trash': operation(z.strictObject({ ...scope, itemId: id, etag }), 'write', 'Move a file to the recycle bin with an exact ETag precondition.', async (ctx, args) => {
    const site = selectedDrive(ctx, args);
    // Graph DELETE moves driveItems to the recycle bin; permanentDelete is never exposed.
    await json(ctx, site, { path: itemPath(args.driveId, args.itemId), method: 'DELETE', headers: { 'If-Match': args.etag } });
    return { id: args.itemId, trashed: true };
  }),
};
