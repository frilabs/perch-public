// Luma via the official Luma MCP (docs/LUMA_SPEC.md §8) against a MOCK Luma MCP server and a MOCK OAuth
// server: onboarding (CIMD and DCR), the fixed tool list with pinned schemas, grants, idempotent writes,
// the blast head count, refresh failures and origin guards. Nothing reaches Luma; tokens are dummies.
import { readFile } from 'node:fs/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { createPerchContext, type PerchContext } from '../src/context.js';
import { guardedLumaFetch, LumaMcp } from '../src/luma/client.js';
import { discoverLumaAuth } from '../src/luma/oauth.js';
import { schemaHash } from '../src/luma/policy.js';
import { createMcpServer } from '../src/mcp/server.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { AUTH_ORIGIN, mockLumaAuth, startMockLuma, type MockLuma, type MockLumaAuth } from './support/mockLuma.js';

let dirs: TempDirs;
let store: CredentialStore;
let luma: MockLuma;
let auth: MockLumaAuth;
let env: Record<string, string>;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  luma = await startMockLuma();
  auth = mockLumaAuth(luma);
  env = { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root };
});
afterEach(async () => {
  await luma.close();
  await dirs.cleanup();
});

function io(): CliIo & { out: () => string; err: () => string } {
  let out = '';
  let err = '';
  return {
    env,
    stdout: (s) => (out += s),
    stderr: (s) => {
      err += s;
      // Act as the browser: follow the authorization URL straight to the loopback callback.
      const m = /(https:\/\/auth\.luma\.com\/oauth\/authorize\?\S+)/.exec(s);
      if (m) {
        const u = new URL(m[1]!);
        expect(u.searchParams.get('code_challenge_method')).toBe('S256');
        expect(u.searchParams.get('resource')).toBe('https://mcp.luma.com/');
        void fetch(`${u.searchParams.get('redirect_uri')}?code=luma-code-123&state=${encodeURIComponent(u.searchParams.get('state')!)}`);
      }
    },
    readSecret: async () => '',
    transport: auth.transport,
    lumaFetch: luma.fetch,
    out: () => out,
    err: () => err,
  };
}

async function addAccount(label = 'frilabs') {
  const x = io();
  const code = await runCli(['luma', 'add', '--label', label, '--timeout', '10'], x);
  expect(code, x.err()).toBe(0);
  return { out: x.out(), id: /Connected Luma account (luma-[a-f0-9]{8})/.exec(x.out())![1]! };
}

function context(): PerchContext {
  return createPerchContext(store, auth.transport, undefined, new LumaMcp(guardedLumaFetch(luma.fetch)));
}

async function mcpClient(ctx: PerchContext, principal: Principal) {
  await ctx.luma.refresh();
  const server = createMcpServer(ctx, principal);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b);
  const c = new Client({ name: 'test', version: '0' });
  await c.connect(a);
  return c;
}

const call = async (c: Client, name: string, args: Record<string, unknown>) => {
  const r = (await c.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text: string }> };
  return { isError: r.isError === true, json: JSON.parse(r.content[0]!.text) as Record<string, unknown> };
};

async function grant(caps: string[], accounts: string[]) {
  const tokenFile = `${dirs.root}/config/clients/${caps.join('_')}.token`;
  await createClientGrant(store, { label: 'Luma client', capabilities: caps as never, accountIds: accounts, tokenFile });
  return (await principalForClientToken(store, (await readFile(tokenFile, 'utf8')).trim()))!;
}

describe('onboarding', () => {
  it('also connects with the pasted browser address instead of the callback (login without a tunnel)', async () => {
    const x = io();
    let authUrl = '';
    let shown = '';
    const code = await runCli(['luma', 'add', '--label', 'pasted', '--timeout', '10'], {
      ...x,
      stderr: (s) => {
        shown += s;
        authUrl = /(https:\/\/auth\.luma\.com\/oauth\/authorize\?\S+)/.exec(s)?.[1] ?? authUrl;
      },
      readPastedUrl: async () => {
        const u = new URL(authUrl);
        return `${u.searchParams.get('redirect_uri')}?code=luma-code-123&state=${encodeURIComponent(u.searchParams.get('state')!)}`;
      },
    });
    expect(code, shown).toBe(0);
    // Live 2026-10-27: Luma's authorization_endpoint carries ?credential_type=personal (RFC 6749 §3.1).
    // Discovery must accept it and the login URL must keep it next to Perch's own parameters.
    const authz = new URL(authUrl);
    expect(authz.searchParams.get('credential_type')).toBe('personal');
    expect(authz.searchParams.get('response_type')).toBe('code');
    expect(authz.searchParams.get('code_challenge_method')).toBe('S256');
    expect(shown).toMatch(/This site can't be reached/);
    expect(x.out()).toMatch(/Connected Luma account luma-[a-f0-9]{8} "pasted"/);
  });

  it('connects via CIMD (no DCR offered), pins the allowlisted tool schemas and never offers delete/host tools', async () => {
    auth.dcr = false;
    const { out, id } = await addAccount();
    expect(out).toContain('via cimd');
    expect(out).toMatch(/Not offered by Luma: .*list_calendars/);
    const acc = (await store.read()).luma[0]!;
    expect(acc).toMatchObject({ id, email: 'operator@example.test', userId: 'usr-mock0001', clientId: 'https://frilabs.dev/perch/luma-client.json', registration: 'cimd' });
    const names = acc.tools.map((t) => t.name).sort();
    expect(names).toEqual(['create_blast', 'create_event', 'get_event', 'get_self', 'invite_guests', 'list_events', 'list_guests', 'update_event', 'update_guest_status']);
    expect(JSON.stringify(await store.read())).not.toContain('delete_event');
    expect(acc.tools.find((t) => t.name === 'get_event')!.hash).toBe(schemaHash(luma.tools.find((t) => t.name === 'get_event')!.inputSchema));
  });

  it('prefers Dynamic Client Registration when offered, for exactly the loopback redirect', async () => {
    const { out } = await addAccount();
    expect(out).toContain('via dcr');
    expect(auth.registered[0]).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/);
    expect((await store.read()).luma[0]!.clientId).toMatch(/^dcr-client-/);
  });

  it('refuses an authorization server outside luma.com / lu.ma before any request to it', async () => {
    auth.issuer = 'https://evil.example';
    const err = await rejection(discoverLumaAuth(new Upstream(auth.transport)));
    expect(err.message).toMatch(/outside luma\.com/);
    expect(auth.calls.some((c) => c.includes('evil.example'))).toBe(false);
  });

  it('accepts a query on the authorization endpoint but refuses a fragment', async () => {
    const ok = await discoverLumaAuth(new Upstream(auth.transport));
    expect(new URL(ok.authorizationEndpoint).searchParams.get('credential_type')).toBe('personal');
    const withFragment: typeof auth.transport = async (req) => {
      const res = await auth.transport(req);
      if (!req.url.pathname.endsWith('/oauth-authorization-server')) return res;
      const body = JSON.parse(Buffer.from(res.body).toString('utf8')) as Record<string, unknown>;
      return { ...res, body: Buffer.from(JSON.stringify({ ...body, authorization_endpoint: `${body.authorization_endpoint as string}#x` })) };
    };
    const err = await rejection(discoverLumaAuth(new Upstream(withFragment)));
    expect(err.message).toMatch(/authorization_endpoint must not carry a fragment/);
  });

  it('refuses a duplicate account', async () => {
    await addAccount();
    const x = io();
    expect(await runCli(['luma', 'add', '--label', 'again', '--timeout', '10'], x)).toBe(1);
    expect(x.err()).toMatch(/already connected/);
  });
});

describe('tools and rights', () => {
  let id: string;
  let ctx: PerchContext;
  beforeEach(async () => {
    id = (await addAccount()).id;
    ctx = context();
  });

  it('1: the read-only operator sees read tools only; delete/host tools never exist', async () => {
    const c = await mcpClient(ctx, READONLY_PRINCIPAL);
    const names = (await c.listTools()).tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(['luma_get_event', 'luma_list_events', 'luma_list_guests', 'luma_get_self']));
    expect(names.filter((n) => n.startsWith('luma_'))).not.toEqual(expect.arrayContaining(['luma_create_event']));
    expect(names.some((n) => /delete|host/.test(n))).toBe(false);
    const r = await call(c, 'luma_get_event', { event_id: 'evt-42' });
    expect(r.json).toMatchObject({ accountId: id, accountLabel: 'frilabs', result: { event: { api_id: 'evt-42' } } });
  });

  it('6: only fields Perch knows are passed to Luma (no Perch fields, no extras)', async () => {
    await ctx.luma.read(READONLY_PRINCIPAL, 'get_event', { event_id: 'evt-1', accountId: id, sneaky: 'x', requestId: 'r-12345678' });
    expect(luma.calls.at(-1)).toEqual(['get_event', { event_id: 'evt-1' }]);
  });

  it('1b: a changed schema blocks the tool until reviewed; a new field keeps it blocked', async () => {
    luma.tools = luma.tools.map((t) => (t.name === 'get_event' ? { ...t, inputSchema: { ...t.inputSchema, required: [] } } : t));
    const fresh = context();
    const err = await rejection(fresh.luma.read(READONLY_PRINCIPAL, 'get_event', { event_id: 'evt-1', accountId: id }));
    expect(err.message).toMatch(/changed or removed the tool get_event/);
    expect(luma.calls.some(([n]) => n === 'get_event')).toBe(false);
    const states = io();
    await runCli(['luma', 'tools', id], states);
    expect(states.out()).toMatch(/get_event\s+read\s+changed/);
    await runCli(['luma', 'tools', id, '--accept'], io());
    const again = context();
    await again.luma.read(READONLY_PRINCIPAL, 'get_event', { event_id: 'evt-1', accountId: id });
    // A new top-level field is never approved.
    luma.tools = luma.tools.map((t) => (t.name === 'get_event' ? { ...t, inputSchema: { ...t.inputSchema, properties: { event_id: { type: 'string' }, delete_after: { type: 'boolean' } } } } : t));
    const acc = io();
    await runCli(['luma', 'tools', id, '--accept'], acc);
    expect(acc.out()).toMatch(/still blocked: get_event \(unknown fields: delete_after/);
    const third = context();
    expect((await rejection(third.luma.read(READONLY_PRINCIPAL, 'get_event', { event_id: 'evt-1', accountId: id }))).message).toMatch(/not approved/);
  });

  it('2: writes need the matching grant, checked before any request to Luma', async () => {
    const events = await grant(['luma_read', 'luma_events'], [id]);
    const c = await mcpClient(ctx, events);
    const names = (await c.listTools()).tools.map((t) => t.name);
    expect(names).toContain('luma_create_event');
    expect(names).not.toContain('luma_invite_guests');
    expect(names).not.toContain('luma_create_blast');
    const before = luma.calls.length;
    const denied = await rejection(ctx.luma.write(events, 'invite_guests', { accountId: id, requestId: 'req-inv-0001', event_id: 'evt-1', guests: [{ email: 'a@example.test' }] }));
    expect(denied.message).toMatch(/luma_guests/);
    // update_event with email_guests needs luma_guests as well.
    const mail = await rejection(ctx.luma.write(events, 'update_event', { accountId: id, requestId: 'req-upd-0001', event_id: 'evt-1', email_guests: true }));
    expect(mail.message).toMatch(/luma_guests/);
    // feedback_email.enabled: true (Luma field added 2026-10-27) e-mails all guests: luma_guests too.
    const feedback = await rejection(ctx.luma.write(events, 'create_event', { accountId: id, requestId: 'req-fb-00001', name: 'x', start_at: '2026-11-01T18:00:00Z', timezone: 'Europe/Vienna', feedback_email: { enabled: true } }));
    expect(feedback.message).toMatch(/luma_guests/);
    expect(luma.calls.length).toBe(before);
    // The read-only operator can never write.
    expect((await rejection(ctx.luma.write(READONLY_PRINCIPAL, 'create_event', { accountId: id, requestId: 'req-op-00001', name: 'x', start_at: '2026-11-01T18:00:00Z', timezone: 'Europe/Vienna' }))).message).toMatch(/read-only/);
  });

  it('3: the same requestId executes once; different arguments under it fail before I/O', async () => {
    const events = await grant(['luma_events'], [id]);
    const c = await mcpClient(ctx, events);
    const args = { accountId: id, requestId: 'req-create-01', name: 'Perch Meetup', start_at: '2026-11-01T18:00:00Z', timezone: 'Europe/Vienna' };
    const first = await call(c, 'luma_create_event', args);
    expect(first.json).toMatchObject({ status: 'accepted', replayed: false, accountId: id, result: { event: { api_id: 'evt-new' } } });
    const again = await call(c, 'luma_create_event', args);
    expect(again.json).toMatchObject({ status: 'accepted', replayed: true });
    expect(luma.calls.filter(([n]) => n === 'create_event')).toHaveLength(1);
    const conflict = await call(c, 'luma_create_event', { ...args, name: 'Other' });
    expect(conflict.isError).toBe(true);
    expect(conflict.json.error).toMatch(/requestId/i);
    expect(luma.calls.filter(([n]) => n === 'create_event')).toHaveLength(1);
    const status = await call(c, 'luma_write_status', { accountId: id, requestId: 'req-create-01' });
    expect(status.json).toMatchObject({ status: 'accepted' });
  });

  it('an interrupted write is indeterminate and never retried', async () => {
    const events = await grant(['luma_events'], [id]);
    luma.dropNextCall = true;
    const args = { accountId: id, requestId: 'req-drop-0001', name: 'X', start_at: '2026-11-01T18:00:00Z', timezone: 'Europe/Vienna' };
    expect(await ctx.luma.write(events, 'create_event', args)).toMatchObject({ status: 'indeterminate' });
    expect(await ctx.luma.write(events, 'create_event', args)).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(luma.calls.filter(([n]) => n === 'create_event')).toHaveLength(1);
  });

  it('guest rules: no refunds through Perch, at most 50 invitations per call', async () => {
    const guests = await grant(['luma_guests'], [id]);
    const before = luma.calls.length;
    expect((await rejection(ctx.luma.write(guests, 'update_guest_status', { accountId: id, requestId: 'req-ref-00001', event_id: 'evt-1', guest_id: 'gst-1', status: 'declined', should_refund: true }))).message).toMatch(/never refunds/);
    const many = Array.from({ length: 51 }, (_, i) => ({ email: `g${i}@example.test` }));
    expect((await rejection(ctx.luma.write(guests, 'invite_guests', { accountId: id, requestId: 'req-inv-00051', event_id: 'evt-1', guests: many }))).message).toMatch(/At most 50/);
    expect(luma.calls.length).toBe(before);
    expect(await ctx.luma.write(guests, 'invite_guests', { accountId: id, requestId: 'req-inv-00002', event_id: 'evt-1', guests: many.slice(0, 2) })).toMatchObject({ status: 'accepted' });
  });

  it('4: a blast is sent only when confirmRecipientCount matches the counted guests', async () => {
    luma.guests.set('evt-1', [
      { api_id: 'gst-1', email: 'a@example.test', approval_status: 'approved' },
      { api_id: 'gst-2', email: 'b@example.test', approval_status: 'approved' },
      { api_id: 'gst-3', email: 'c@example.test', approval_status: 'approved' },
      { api_id: 'gst-4', email: 'd@example.test', approval_status: 'waitlist' },
    ]);
    const blast = await grant(['luma_blast'], [id]);
    const wrong = await ctx.luma.write(blast, 'create_blast', { accountId: id, requestId: 'req-blast-001', event_id: 'evt-1', content_md: 'Hi', recipient_groups: [{ status: 'approved' }], confirmRecipientCount: 4 });
    expect(wrong).toMatchObject({ status: 'rejected' });
    expect(wrong.detail).toMatch(/would reach 3 guest/);
    expect(luma.calls.some(([n]) => n === 'create_blast')).toBe(false);
    const both = await ctx.luma.write(blast, 'create_blast', {
      accountId: id,
      requestId: 'req-blast-002',
      event_id: 'evt-1',
      content_md: 'Hi',
      recipient_groups: [{ status: 'approved' }, { status: 'waitlist' }],
      confirmRecipientCount: 4,
    });
    expect(both).toMatchObject({ status: 'accepted' });
    expect(luma.calls.filter(([n]) => n === 'create_blast')).toHaveLength(1);
    expect((await rejection(ctx.luma.write(blast, 'create_blast', { accountId: id, requestId: 'req-blast-003', event_id: 'evt-1', content_md: 'Hi', recipient_groups: [{ status: 'approved' }] }))).message).toMatch(/confirmRecipientCount/);
    // Explicit audience only, no extra keys, never scheduled.
    expect((await rejection(ctx.luma.write(blast, 'create_blast', { accountId: id, requestId: 'req-blast-005', event_id: 'evt-1', content_md: 'Hi', confirmRecipientCount: 3 }))).message).toMatch(/recipient_groups is required/);
    expect((await rejection(ctx.luma.write(blast, 'create_blast', { accountId: id, requestId: 'req-blast-006', event_id: 'evt-1', content_md: 'Hi', recipient_groups: [{ status: 'approved', segment: 'all' }], confirmRecipientCount: 3 }))).message).toMatch(/only name status/);
    expect((await rejection(ctx.luma.write(blast, 'create_blast', { accountId: id, requestId: 'req-blast-007', event_id: 'evt-1', content_md: 'Hi', recipient_groups: [{ status: 'approved' }], scheduled_for: '2026-12-01T10:00:00Z', confirmRecipientCount: 3 }))).message).toMatch(/only immediately/);
    expect(
      (await rejection(ctx.luma.write(blast, 'create_blast', { accountId: id, requestId: 'req-blast-004', event_id: 'evt-1', content_md: 'Hi', recipient_groups: [{ status: 'approved', ticket_type_id: 'tt-1' }], confirmRecipientCount: 1 }))).message,
    ).toMatch(/ticket type/);
  });

  it('reads across two accounts with provenance', async () => {
    // A second account: the MOCK reports the same user, so give it another identity first.
    await store.update((d) => void (d.luma[0]!.userId = 'usr-other'));
    const second = (await addAccount('second')).id;
    const r = (await ctx.luma.read(READONLY_PRINCIPAL, 'list_events', {})) as { results: Array<{ accountId: string }> };
    expect(r.results.map((x) => x.accountId).sort()).toEqual([id, second].sort());
  });

  it('5: a revoked refresh token fails closed with a reconnect hint', async () => {
    auth.failRefresh = true;
    const fresh = context();
    const err = await rejection(fresh.luma.read(READONLY_PRINCIPAL, 'get_event', { event_id: 'evt-1', accountId: id }));
    expect(err.message).toMatch(/perch luma remove/);
  });

  it('status shows Luma accounts with a live check', async () => {
    const x = io();
    await runCli(['status', '--plain'], x);
    expect(x.out()).toMatch(/Luma\n {2}✓ luma-[a-f0-9]{8} {2}"frilabs" {2}operator@example\.test/);
  });
});

describe('origin guards', () => {
  it('7: the Luma fetch only reaches https://mcp.luma.com/ and never opens the SSE stream', async () => {
    const seen: string[] = [];
    const f = guardedLumaFetch(async (u) => {
      seen.push(String(u));
      return new Response('{}');
    });
    expect((await rejection(f('https://evil.example/mcp', { method: 'POST' }))).message).toMatch(/Blocked/);
    expect((await rejection(f('https://mcp.luma.com/other', { method: 'POST' }))).message).toMatch(/Blocked/);
    expect((await f('https://mcp.luma.com/', { method: 'GET' })).status).toBe(405);
    expect(seen).toEqual([]);
    expect(AUTH_ORIGIN).toBe('https://auth.luma.com');
  });
});

describe('regressions from the independent review', () => {
  let id: string;
  beforeEach(async () => {
    id = (await addAccount()).id;
  });

  it('a 401 from Luma drops the cached token and retries once (read)', async () => {
    const ctx = context();
    await ctx.luma.read(READONLY_PRINCIPAL, 'get_event', { event_id: 'evt-1', accountId: id });
    luma.validTokens.clear(); // Luma no longer accepts the cached access token
    const r = await ctx.luma.read(READONLY_PRINCIPAL, 'get_event', { event_id: 'evt-2', accountId: id });
    expect(r).toMatchObject({ result: { event: { api_id: 'evt-2' } } });
  });

  it('a write that fails with 401 before the tool call is "rejected", never indeterminate', async () => {
    const ctx = context();
    const events = await grant(['luma_events'], [id]);
    await ctx.luma.read(READONLY_PRINCIPAL, 'list_events', { accountId: id }); // warm token and tool cache
    luma.validTokens.clear();
    auth.failRefresh = true;
    const r = await ctx.luma.write(events, 'create_event', { accountId: id, requestId: 'req-401-00001', name: 'X', start_at: '2026-11-01T18:00:00Z', timezone: 'Europe/Vienna' });
    expect(r.status).toBe('rejected');
    expect(luma.calls.some(([n]) => n === 'create_event')).toBe(false);
  });

  it('nested fields outside the approved schema are refused at the MCP layer', async () => {
    const ctx = context();
    const guests = await grant(['luma_guests'], [id]);
    const c = await mcpClient(ctx, guests);
    const r = await call(c, 'luma_invite_guests', { accountId: id, requestId: 'req-nest-0001', event_id: 'evt-1', guests: [{ email: 'a@example.test', role: 'host' }] }).catch((e: Error) => ({ isError: true, json: { error: e.message } }));
    expect(r.isError).toBe(true);
    expect(luma.calls.some(([n]) => n === 'invite_guests')).toBe(false);
  });

  it('the blast count fails closed on more pages without a cursor', async () => {
    const ctx = context();
    luma.guests.set('evt-9', [{ api_id: 'g1', email: 'a@x.test', approval_status: 'approved' }]);
    const blast = await grant(['luma_blast'], [id]);
    // list_guests claims more pages but gives no cursor.
    const mcp = (ctx.luma as unknown as { mcp: { callTool: (...a: unknown[]) => Promise<unknown> } }).mcp;
    const real = mcp.callTool.bind(mcp);
    mcp.callTool = async (token: unknown, name: unknown, args: unknown) => (name === 'list_guests' ? { isError: false, data: { entries: [{ api_id: 'g1' }], has_more: true } } : real(token, name, args));
    const r = await ctx.luma.write(blast, 'create_blast', { accountId: id, requestId: 'req-page-0001', event_id: 'evt-9', content_md: 'Hi', recipient_groups: [{ status: 'approved' }], confirmRecipientCount: 1 });
    expect(r.status).toBe('rejected');
    expect(r.detail).toMatch(/no cursor/);
    expect(luma.calls.some(([n]) => n === 'create_blast')).toBe(false);
  });

  it('a schema change of a property NAMED description changes the pin', () => {
    const a = { type: 'object', properties: { description: { type: 'string' } } };
    const b = { type: 'object', properties: { description: { type: 'object', properties: { secret: { type: 'string' } } } } };
    expect(schemaHash(a)).not.toBe(schemaHash(b));
    expect(schemaHash({ ...a, description: 'doc' })).toBe(schemaHash(a));
  });

  it('approving calendar submissions e-mails third parties and needs luma_guests', async () => {
    const ctx = context();
    const events = await grant(['luma_events'], [id]);
    expect((await rejection(ctx.luma.write(events, 'approve_calendar_events', { accountId: id, requestId: 'req-appr-0001', calendar_id: 'cal-1', calendar_event_ids: ['evt-1'] }))).message).toMatch(/luma_guests/);
  });

  it('a fan-out read refuses a cursor without accountId', async () => {
    const ctx = context();
    expect((await rejection(ctx.luma.read(READONLY_PRINCIPAL, 'list_events', { cursor: 'abc' }))).message).toMatch(/cursor belongs to one/);
  });

  it('perch status reports changed tools as an error', async () => {
    luma.tools = luma.tools.map((t) => (t.name === 'get_event' ? { ...t, inputSchema: { ...t.inputSchema, required: [] } } : t));
    const x = io();
    await runCli(['status', '--plain'], x);
    expect(x.out()).toMatch(/Luma changed 1 approved tool\(s\) \(get_event\)/);
  });

  it('a principal only sees tools approved for its own accounts', async () => {
    const ctx = context();
    await ctx.luma.refresh();
    const none = await grant(['luma_read'], [id]);
    expect(ctx.luma.exposed(none).length).toBeGreaterThan(0);
    const other = { ...none, lumaAccounts: new Set(['luma-ffffffff']) } as Principal;
    expect(ctx.luma.exposed(other)).toEqual([]);
  });
});
