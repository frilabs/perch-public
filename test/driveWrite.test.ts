// Drive create/edit/share through the real MCP SDK client (in-memory transport) against the MOCK Google
// upstream (in-memory fake). Covers grants, provider scopes, idempotency, trash-only and audit. No live calls.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, removeClientGrant, type Principal } from '../src/auth/grants.js';
import { createPerchContext } from '../src/context.js';
import { registerGoogleAccount } from '../src/google/accounts.js';
import { DRIVE_READONLY_SCOPE, DRIVE_SCOPE } from '../src/google/oauth.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { createMcpServer, WRITE_TOOL_NAMES } from '../src/mcp/server.js';
import type { Capability } from '../src/store/credentialStore.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { isAllowedRoute, Upstream, type RouteCapability } from '../src/upstream.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockGoogle, parseMultipart, type MockGoogleAccount } from './support/mockGoogle.js';

let dirs: TempDirs;
let store: CredentialStore;
let google: MockGoogle;
let mockA: MockGoogleAccount;
let mockB: MockGoogleAccount;
let mockC: MockGoogleAccount;
/** A: connected with --allow-write; B: read-only at Google; C: writable but outside every grant used here. */
let idA: string;
let idB: string;
let idC: string;

const WRITE_TOOLS = [
  'drive_upload_file',
  'drive_create_folder',
  'drive_create_document',
  'drive_copy_file',
  'drive_share_file',
  'drive_add_comment',
  'drive_update_file_content',
  'drive_update_file',
  'drive_trash_file',
  'drive_restore_file',
  'drive_unshare_file',
];

async function register(acct: MockGoogleAccount, label: string, scopes: string[]) {
  const upstream = new Upstream(google.transport);
  const a = await registerGoogleAccount(store, upstream, {
    label,
    client: { clientId: dummySecret('CLIENT'), clientSecret: dummySecret('CLIENT-SECRET') },
    grant: { refreshToken: acct.refreshToken, accessToken: google.issueAccessToken(acct), expiresAt: Date.now() + 3600_000, scopes },
  });
  return a.id;
}

async function clientFor(principal: Principal) {
  const mcp = createMcpServer(createPerchContext(store, google.transport), principal);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await mcp.connect(b);
  const client = new Client({ name: 'drive-write-test', version: '0' });
  await client.connect(a);
  return client;
}

async function grant(capabilities: Capability[], accountIds: string[]) {
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
    return { isError: r.isError === true, body: JSON.parse(text) as Record<string, unknown> };
  } catch (err) {
    return { isError: true, body: { error: (err as Error).message } };
  }
}

const rid = () => `drive-test-${Math.random().toString(16).slice(2, 14)}`;
const b64 = (s: string | Buffer) => Buffer.from(s).toString('base64');

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  google = new MockGoogle();
  mockA = google.addAccount('dummy.a@example.test', [
    { id: 'a1', name: 'Report alpha.txt', mimeType: 'text/plain', content: Buffer.from('alpha text'), parents: ['folderA'] },
  ]);
  mockB = google.addAccount('dummy.b@example.test', [{ id: 'b1', name: 'Report budget.txt', mimeType: 'text/plain', content: Buffer.from('b') }]);
  mockC = google.addAccount('dummy.c@example.test', [{ id: 'c1', name: 'Report other.txt', mimeType: 'text/plain', content: Buffer.from('c') }]);
  idA = await register(mockA, 'Private', [DRIVE_SCOPE]);
  idB = await register(mockB, 'Work', [DRIVE_READONLY_SCOPE]);
  idC = await register(mockC, 'Other', [DRIVE_SCOPE]);
});

afterEach(async () => {
  await dirs.cleanup();
});

describe('Drive write tools: who gets them [MOCK Google]', () => {
  it('declares every write tool as a write tool', () => {
    for (const t of WRITE_TOOLS) expect(WRITE_TOOL_NAMES).toContain(t);
  });

  it('the read-only operator gets the read tools but no write tool', async () => {
    const client = await clientFor(READONLY_PRINCIPAL);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(['drive_search', 'drive_list_permissions', 'drive_list_comments']));
    for (const t of WRITE_TOOLS) expect(names).not.toContain(t);
  });

  it('a client with drive_read only gets Drive reads but no writes', async () => {
    const { principal } = await grant(['drive_read'], [idA]);
    const names = (await (await clientFor(principal)).listTools()).tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(['drive_search', 'drive_get_file', 'drive_list_permissions']));
    for (const t of WRITE_TOOLS) expect(names).not.toContain(t);
  });

  it('a client without drive_write is denied before any upstream call (direct service call)', async () => {
    const { principal } = await grant(['drive_read'], [idA]);
    const ctx = createPerchContext(store, google.transport);
    const before = google.calls.length;
    await expect(ctx.driveWrite.createFolder(principal, { accountId: idA, name: 'x', requestId: rid() })).rejects.toThrow(/drive_write/);
    await expect(ctx.driveWrite.setTrashed(principal, { accountId: idA, fileId: 'a1' }, true)).rejects.toThrow(/drive_write/);
    await expect(ctx.driveWrite.setTrashed(READONLY_PRINCIPAL, { accountId: idA, fileId: 'a1' }, true)).rejects.toThrow(/read-only/);
    expect(google.calls.length).toBe(before);
  });
});

describe('Drive client reads [MOCK Google]', () => {
  it('drive_search fans out only over the granted accounts', async () => {
    const { principal } = await grant(['drive_read'], [idA, idB]);
    const client = await clientFor(principal);
    const before = google.calls.length;
    const r = await call(client, 'drive_search', { query: 'report' });
    expect(r.isError).toBe(false);
    const ids = (r.body.results as Array<{ accountId: string; id: string }>).map((x) => x.accountId);
    expect(new Set(ids)).toEqual(new Set([idA, idB]));
    const tokenOfC = (auth: string | undefined) => [...google.accessTokens].some(([t, acct]) => acct === mockC && auth === `Bearer ${t}`);
    expect(google.calls.slice(before).some((c) => tokenOfC(c.headers.authorization))).toBe(false);
    const denied = await call(client, 'drive_get_file', { accountId: idC, fileId: 'c1' });
    expect(denied.isError).toBe(true);
    expect(String(denied.body.error)).toMatch(/not granted/);
    const listed = await call(client, 'perch_list_accounts', {});
    expect((listed.body.google as Array<{ accountId: string; canWrite: boolean }>).map((g) => [g.accountId, g.canWrite])).toEqual([
      [idA, true],
      [idB, false],
    ]);
  });

  it('lists permissions and comments (comments flagged as untrusted)', async () => {
    mockA.files[0]!.permissions = [{ id: '111', type: 'user', role: 'writer', emailAddress: 'x@example.test' }];
    mockA.files[0]!.comments = [{ id: 'c1', content: 'hello', author: { displayName: 'X' } }];
    const { principal } = await grant(['drive_read'], [idA]);
    const client = await clientFor(principal);
    const perms = await call(client, 'drive_list_permissions', { accountId: idA, fileId: 'a1' });
    expect(perms.body).toMatchObject({ accountId: idA, permissions: [{ id: '111', role: 'writer' }] });
    const comments = await call(client, 'drive_list_comments', { accountId: idA, fileId: 'a1' });
    expect(comments.body).toMatchObject({ comments: [{ content: 'hello' }], note: expect.stringMatching(/untrusted/) });
  });
});

describe('Drive writes [MOCK Google]', () => {
  let client: Client;
  beforeEach(async () => {
    client = await clientFor((await grant(['drive_read', 'drive_write'], [idA, idB])).principal);
  });

  it('uploads a file via multipart', async () => {
    const r = await call(client, 'drive_upload_file', { accountId: idA, name: 'notes.bin', mimeType: 'application/pdf', parentId: 'folderA', contentBase64: b64('%PDF-1'), requestId: rid() });
    expect(r.body).toMatchObject({ status: 'accepted', replayed: false, accountId: idA, id: expect.stringMatching(/^mock/) });
    const created = mockA.files.find((f) => f.id === r.body.id)!;
    expect(created).toMatchObject({ name: 'notes.bin', mimeType: 'application/pdf', parents: ['folderA'] });
    expect(created.content!.toString()).toBe('%PDF-1');
    const req = google.writes.at(-1)!;
    expect(req.url.pathname).toBe('/upload/drive/v3/files');
    expect(req.url.searchParams.get('uploadType')).toBe('multipart');
    expect(req.url.searchParams.get('supportsAllDrives')).toBe('true');
  });

  it('refuses content above 10 MiB and invalid base64 before any call', async () => {
    const before = google.writes.length;
    const big = await call(client, 'drive_upload_file', { accountId: idA, name: 'big', contentBase64: Buffer.alloc(10 * 1024 * 1024 + 1).toString('base64'), requestId: rid() });
    expect(big.isError).toBe(true);
    const bad = await call(client, 'drive_upload_file', { accountId: idA, name: 'bad', contentBase64: 'not base64!', requestId: rid() });
    expect(bad.isError).toBe(true);
    expect(google.writes.length).toBe(before);
  });

  it('creates a folder', async () => {
    const r = await call(client, 'drive_create_folder', { accountId: idA, name: 'Projects', requestId: rid() });
    expect(r.body).toMatchObject({ status: 'accepted', result: { mimeType: 'application/vnd.google-apps.folder', name: 'Projects' } });
  });

  it('creates Google documents, empty or converted from text/CSV', async () => {
    const doc = await call(client, 'drive_create_document', { accountId: idA, kind: 'doc', name: 'Memo', content: 'Hello', requestId: rid() });
    expect(doc.body).toMatchObject({ status: 'accepted' });
    const up = parseMultipart(google.writes.at(-1)!);
    expect(up.metadata).toMatchObject({ name: 'Memo', mimeType: 'application/vnd.google-apps.document' });
    expect(up.mediaType).toBe('text/plain');
    expect(up.media.toString()).toBe('Hello');
    await call(client, 'drive_create_document', { accountId: idA, kind: 'sheet', name: 'Table', content: 'a,b\n1,2\n', requestId: rid() });
    expect(parseMultipart(google.writes.at(-1)!).mediaType).toBe('text/csv');
    const slides = await call(client, 'drive_create_document', { accountId: idA, kind: 'slides', name: 'Deck', requestId: rid() });
    expect(slides.body).toMatchObject({ status: 'accepted', result: { mimeType: 'application/vnd.google-apps.presentation' } });
    expect(google.writes.at(-1)!.url.pathname).toBe('/drive/v3/files');
    const bad = await call(client, 'drive_create_document', { accountId: idA, kind: 'slides', name: 'Deck', content: 'x', requestId: rid() });
    expect(bad.isError).toBe(true);
  });

  it('replaces file content', async () => {
    const r = await call(client, 'drive_update_file_content', { accountId: idA, fileId: 'a1', contentBase64: b64('new text'), mimeType: 'text/plain' });
    expect(r.isError).toBe(false);
    expect(mockA.files[0]!.content!.toString()).toBe('new text');
    expect(google.writes.at(-1)!.method).toBe('PATCH');
    expect(google.writes.at(-1)!.url.searchParams.get('uploadType')).toBe('media');
  });

  it('renames and moves', async () => {
    mockA.files.push({ id: 'folderB', name: 'B', mimeType: 'application/vnd.google-apps.folder' });
    const r = await call(client, 'drive_update_file', { accountId: idA, fileId: 'a1', name: 'Renamed.txt', addParents: ['folderB'], removeParents: ['folderA'] });
    expect(r.body).toMatchObject({ accountId: idA, name: 'Renamed.txt', parents: ['folderB'] });
    expect((await call(client, 'drive_update_file', { accountId: idA, fileId: 'a1' })).isError).toBe(true);
  });

  it('refuses to move a file into another drive (that would hand it to a shared drive)', async () => {
    mockA.files.push({ id: 'sharedFolder', name: 'Team', mimeType: 'application/vnd.google-apps.folder', driveId: 'sd0001' });
    const writes = google.writes.length;
    const r = await call(client, 'drive_update_file', { accountId: idA, fileId: 'a1', addParents: ['sharedFolder'], removeParents: ['folderA'] });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toMatch(/another drive/);
    expect(google.writes.length).toBe(writes);
    expect(mockA.files[0]!.parents).toEqual(['folderA']);
  });

  it('copies a file', async () => {
    const r = await call(client, 'drive_copy_file', { accountId: idA, fileId: 'a1', name: 'Copy.txt', requestId: rid() });
    expect(r.body).toMatchObject({ status: 'accepted', result: { name: 'Copy.txt' } });
    expect(mockA.files).toHaveLength(2);
  });

  it('trashes and restores (trash only)', async () => {
    const t = await call(client, 'drive_trash_file', { accountId: idA, fileId: 'a1' });
    expect(t.body).toMatchObject({ trashed: true });
    expect(mockA.files[0]!.trashed).toBe(true);
    expect(google.writes.at(-1)).toMatchObject({ method: 'PATCH' });
    expect(JSON.parse(google.writes.at(-1)!.body!)).toEqual({ trashed: true });
    expect((await call(client, 'drive_search', { query: 'alpha', accountId: idA })).body.results).toEqual([]);
    const r = await call(client, 'drive_restore_file', { accountId: idA, fileId: 'a1' });
    expect(r.body).toMatchObject({ trashed: false });
    expect(google.calls.some((c) => c.method === 'DELETE' && /^\/drive\/v3\/files\/[^/]+$/.test(c.url.pathname))).toBe(false);
  });

  it('shares, lists and unshares', async () => {
    const s = await call(client, 'drive_share_file', { accountId: idA, fileId: 'a1', type: 'user', role: 'commenter', emailAddress: 'friend@example.test', sendNotificationEmail: false, requestId: rid() });
    expect(s.body).toMatchObject({ status: 'accepted', id: expect.stringMatching(/^\d+$/) });
    expect(google.writes.at(-1)!.url.searchParams.get('sendNotificationEmail')).toBe('false');
    const link = await call(client, 'drive_share_file', { accountId: idA, fileId: 'a1', type: 'anyone', role: 'reader', requestId: rid() });
    expect(link.body).toMatchObject({ status: 'accepted', id: 'anyoneWithLink' });
    const perms = await call(client, 'drive_list_permissions', { accountId: idA, fileId: 'a1' });
    expect((perms.body.permissions as unknown[]).length).toBe(2);
    const u = await call(client, 'drive_unshare_file', { accountId: idA, fileId: 'a1', permissionId: String(s.body.id) });
    expect(u.body).toMatchObject({ removed: true });
    expect(mockA.files[0]!.permissions!.map((x) => x.id)).toEqual(['anyoneWithLink']);
    // The permission id identifies the grantee: never in the ledger.
    const ledger = JSON.stringify(await new MailWorkflowLedger(store).read());
    expect(ledger).not.toContain(String(s.body.id));
  });

  it('never grants owner and validates share shapes before any call', async () => {
    const before = google.writes.length;
    for (const args of [
      { type: 'user', role: 'owner', emailAddress: 'x@example.test' },
      { type: 'user', role: 'reader' },
      { type: 'domain', role: 'reader', emailAddress: 'x@example.test' },
      { type: 'anyone', role: 'reader', sendNotificationEmail: true },
    ]) {
      expect((await call(client, 'drive_share_file', { accountId: idA, fileId: 'a1', ...args, requestId: rid() })).isError).toBe(true);
    }
    const ctx = createPerchContext(store, google.transport);
    const { principal } = await grant(['drive_write'], [idA]);
    await expect(ctx.driveWrite.share(principal, { accountId: idA, fileId: 'a1', type: 'user', role: 'owner', emailAddress: 'x@example.test', requestId: rid() })).rejects.toThrow(/never grants/);
    expect(google.writes.length).toBe(before);
  });

  it('adds a comment', async () => {
    const r = await call(client, 'drive_add_comment', { accountId: idA, fileId: 'a1', content: 'Looks good', requestId: rid() });
    expect(r.body).toMatchObject({ status: 'accepted', id: expect.stringMatching(/^AAAA/) });
    expect(mockA.files[0]!.comments![0]!.content).toBe('Looks good');
  });

  it('replays the same requestId without a second upload; changed payload conflicts', async () => {
    const args = { accountId: idA, name: 'once.txt', contentBase64: b64('one'), requestId: rid() };
    const first = await call(client, 'drive_upload_file', args);
    const again = await call(client, 'drive_upload_file', args);
    expect(again.body).toMatchObject({ status: 'accepted', replayed: true, id: first.body.id });
    expect(google.writes.length).toBe(1);
    const conflict = await call(client, 'drive_upload_file', { ...args, contentBase64: b64('two') });
    expect(conflict.isError).toBe(true);
    expect(String(conflict.body.error)).toMatch(/already used/);
    expect(google.writes.length).toBe(1);
  });

  it('maps 4xx to rejected and 5xx/transport failures to indeterminate, never retried', async () => {
    google.failWritesWith = 403;
    const rejected = { accountId: idA, name: 'r', requestId: rid() };
    expect((await call(client, 'drive_create_folder', rejected)).body).toMatchObject({ status: 'rejected' });
    google.failWritesWith = 503;
    expect((await call(client, 'drive_create_folder', { accountId: idA, name: 's', requestId: rid() })).body).toMatchObject({ status: 'indeterminate' });
    google.failWritesWith = undefined;
    google.dropWrites = true;
    const lost = { accountId: idA, name: 't', requestId: rid() };
    expect((await call(client, 'drive_create_folder', lost)).body).toMatchObject({ status: 'indeterminate' });
    google.dropWrites = false;
    const n = google.writes.length;
    expect((await call(client, 'drive_create_folder', lost)).body).toMatchObject({ status: 'indeterminate', replayed: true });
    expect((await call(client, 'drive_create_folder', rejected)).body).toMatchObject({ status: 'rejected', replayed: true });
    expect(google.writes.length).toBe(n);
  });

  it('fails with provider_scope_missing on a read-only Google connection, before any call', async () => {
    const before = google.writes.length;
    const create = await call(client, 'drive_create_folder', { accountId: idB, name: 'x', requestId: rid() });
    expect(create.isError).toBe(true);
    expect(String(create.body.error)).toMatch(/--allow-write/);
    const ctx = createPerchContext(store, google.transport);
    const { principal } = await grant(['drive_write'], [idB]);
    await expect(ctx.driveWrite.setTrashed(principal, { accountId: idB, fileId: 'b1' }, true)).rejects.toMatchObject({ code: 'provider_scope_missing' });
    expect((await call(client, 'drive_trash_file', { accountId: idB, fileId: 'b1' })).isError).toBe(true);
    expect(google.writes.length).toBe(before);
  });

  it('denies an account outside the grant without contacting Google', async () => {
    const before = google.calls.length;
    const r = await call(client, 'drive_create_folder', { accountId: idC, name: 'x', requestId: rid() });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/not granted/);
    expect((await call(client, 'drive_trash_file', { accountId: idC, fileId: 'c1' })).isError).toBe(true);
    expect(google.calls.length).toBe(before);
    expect(mockC.files[0]!.trashed).toBeUndefined();
  });

  it('fails closed after the grant is revoked on a live session', async () => {
    const { id, principal } = await grant(['drive_write'], [idA]);
    const live = await clientFor(principal);
    await removeClientGrant(store, id);
    const before = google.writes.length;
    expect((await call(live, 'drive_trash_file', { accountId: idA, fileId: 'a1' })).isError).toBe(true);
    expect((await call(live, 'drive_create_folder', { accountId: idA, name: 'x', requestId: rid() })).isError).toBe(true);
    expect(google.writes.length).toBe(before);
  });

  it('audits writes without names, content or e-mail addresses', async () => {
    await call(client, 'drive_upload_file', { accountId: idA, name: 'secret-name.txt', contentBase64: b64('secret content'), requestId: rid() });
    await call(client, 'drive_share_file', { accountId: idA, fileId: 'a1', type: 'user', role: 'reader', emailAddress: 'secret.person@example.test', requestId: rid() });
    await call(client, 'drive_update_file', { accountId: idA, fileId: 'a1', name: 'secret-rename.txt' });
    const ledger = await new MailWorkflowLedger(store).read();
    const writes = ledger.audit.filter((e) => e.type === 'drive_write');
    expect(writes.map((e) => e.outcome)).toEqual(['pending', 'accepted', 'pending', 'accepted']);
    expect(writes.every((e) => e.provider === 'drive' && e.accountId === idA)).toBe(true);
    expect(ledger.audit.filter((e) => e.type === 'drive_update_file').map((e) => e.outcome)).toEqual(['attempt', 'ok']);
    const dump = JSON.stringify(ledger);
    for (const secret of ['secret-name', 'secret content', b64('secret content'), 'secret.person', 'secret-rename']) expect(dump).not.toContain(secret);
  });
});

describe('Drive upstream allowlist', () => {
  const CAPS: RouteCapability[] = ['read', 'draft', 'send', 'calendar_write', 'slack_send', 'whatsapp_send', 'admin', 'notify', 'drive_write', 'notion_write', 'mail_modify'];

  it('never allows permanent delete, empty trash or permission updates for any capability', () => {
    for (const cap of CAPS) {
      expect(isAllowedRoute('drive', 'DELETE', '/drive/v3/files/a1', cap)).toBe(false);
      expect(isAllowedRoute('drive', 'DELETE', '/drive/v3/files/trash', cap)).toBe(false);
      expect(isAllowedRoute('drive', 'PATCH', '/drive/v3/files/trash', cap)).toBe(false);
      expect(isAllowedRoute('drive', 'POST', '/drive/v3/files/trash', cap)).toBe(false);
      expect(isAllowedRoute('drive', 'PATCH', '/drive/v3/files/a1/permissions/123', cap)).toBe(false);
      expect(isAllowedRoute('drive', 'DELETE', '/upload/drive/v3/files/a1', cap)).toBe(false);
    }
    expect(isAllowedRoute('drive', 'PATCH', '/drive/v3/files/a1', 'read')).toBe(false);
    expect(isAllowedRoute('drive', 'PATCH', '/drive/v3/files/a1', 'drive_write')).toBe(true);
  });

  it('refuses ownership transfer and the owner role before any I/O', async () => {
    const calls: unknown[] = [];
    const upstream = new Upstream(async (req) => {
      calls.push(req);
      return { status: 200, headers: {}, body: Buffer.from('{}') };
    });
    const base = { method: 'POST' as const, path: '/drive/v3/files/a1/permissions', capability: 'drive_write' as const };
    await expect(upstream.json('drive', { ...base, json: { type: 'user', role: 'owner', emailAddress: 'x@example.test' } })).rejects.toMatchObject({ code: 'route_not_allowed' });
    await expect(upstream.json('drive', { ...base, query: { transferOwnership: true }, json: { type: 'user', role: 'writer' } })).rejects.toMatchObject({ code: 'route_not_allowed' });
    await expect(upstream.json('drive', { method: 'DELETE', path: '/drive/v3/files/a1', capability: 'drive_write' })).rejects.toMatchObject({ code: 'route_not_allowed' });
    expect(calls).toHaveLength(0);
  });
});
