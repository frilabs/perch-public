// Real MCP SDK clients (local HTTP and in-memory transport) against the Calendar/Contacts tools:
// registration by capability, metadata visibility, operator read-only, mail-only clients unchanged,
// per-call grant revalidation without provider I/O. Google is the MOCK upstream; mail providers are stubs.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, removeClientGrant } from '../src/auth/grants.js';
import { createPerchContext, type PerchContext } from '../src/context.js';
import type { MailProviders } from '../src/mail/service.js';
import { generateHttpToken, startHttpServer, type RunningHttpServer } from '../src/mcp/http.js';
import { createMcpServer, TOOL_NAMES, WRITE_TOOL_NAMES } from '../src/mcp/server.js';
import { CredentialStore, initStore, type Capability } from '../src/store/credentialStore.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockGoogleProductivity, sampleEvents, type MockProdAccount } from './support/mockProductivity.js';
import { addDummyImap, addDummyProductivity } from './support/productivityFixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
let server: RunningHttpServer | undefined;
let globalToken: string;
let google: MockGoogleProductivity;
let a: MockProdAccount;
let mailCalls: string[];

// Grows with the mail organize milestone: folders/drafts listing (read) and sending an existing draft (send).
const PR2_MAIL_SEND_TOOLS = [
  'mail_forward',
  'mail_get_attachment',
  'mail_list_drafts',
  'mail_list_folders',
  'mail_read_message',
  'mail_reply',
  'mail_search',
  'mail_send',
  'mail_send_draft',
  'mail_send_status',
  'perch_list_accounts',
];
const CAL_TOOLS = ['calendar_get_event', 'calendar_list_calendars', 'calendar_list_events'];

function stubMail(): MailProviders {
  const p = {
    kind: 'imap',
    providerCapabilities: () => ({ draft: true, send: true }),
    search: async () => (mailCalls.push('search'), { items: [] }),
    read: async () => (mailCalls.push('read'), { messageId: 'x', truncated: false, attachments: [] }),
    getAttachment: async () => (mailCalls.push('att'), { attachmentId: '1', contentType: 'text/plain', size: 0, contentBase64: '' }),
    replyContext: async () => ({ references: [] }),
    createDraft: async () => (mailCalls.push('draft'), { draftId: 'd' }),
    send: async () => (mailCalls.push('send'), { status: 'accepted', detail: 'MOCK' }),
  };
  return { gmail: p, microsoft: p, imap: p } as unknown as MailProviders;
}

const context = (): PerchContext => createPerchContext(store, google.transport, stubMail());

async function grant(capabilities: Capability[], accountIds: string[]) {
  return createClientGrant(store, { label: `C ${capabilities.join(' ')}`, capabilities, accountIds, tokenFile: `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token` });
}

async function http(token: string) {
  const c = new Client({ name: 'prod-http', version: '0' });
  await c.connect(new StreamableHTTPClientTransport(new URL(server!.url), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  return c;
}

async function memory(token: string) {
  const mcp = createMcpServer(context(), (await principalForClientToken(store, token))!);
  const [x, y] = InMemoryTransport.createLinkedPair();
  await mcp.connect(y);
  const c = new Client({ name: 'prod-mem', version: '0' });
  await c.connect(x);
  return c;
}

async function call(c: Client, name: string, args: Record<string, unknown>) {
  try {
    const r = await c.callTool({ name, arguments: args });
    const text = (r.content as Array<{ text: string }>)[0]?.text ?? '';
    return { isError: r.isError === true, text, json: r.isError ? undefined : JSON.parse(text) };
  } catch (err) {
    return { isError: true, text: (err as Error).message, json: undefined };
  }
}

const names = async (c: Client) => (await c.listTools()).tools.map((t) => t.name).sort();
const googleCalls = () => google.calls.filter((r) => r.url.pathname.startsWith('/calendar/') || r.url.origin === 'https://people.googleapis.com');
const createArgs = (accountId = 'gprod-0000000a', extra: Record<string, unknown> = {}) => ({
  accountId,
  requestId: `req-${Math.random().toString(16).slice(2, 12)}`,
  summary: 'Dummy focus',
  start: { date: '2026-10-09' },
  end: { date: '2026-10-10' },
  ...extra,
});

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  google = new MockGoogleProductivity();
  mailCalls = [];
  a = google.addAccount('dummy.a@example.test', { contacts: [{ resourceName: 'people/c1', etag: 'e', names: [{ displayName: 'Dummy C' }] }] });
  a.calendars[0]!.events = sampleEvents();
  const b = google.addAccount('dummy.b@example.test');
  await addDummyImap(store, 'imap-0000000a');
  await addDummyProductivity(store, 'gprod-0000000a', { refreshToken: a.refreshToken, email: a.email, allowCalendarWrite: true });
  await addDummyProductivity(store, 'gprod-0000000b', { refreshToken: b.refreshToken, email: b.email, allowCalendarWrite: true });
  globalToken = generateHttpToken();
  server = await startHttpServer({ host: '127.0.0.1', port: 0, token: globalToken, context: context(), log: () => {} });
});
afterEach(async () => {
  await server?.close();
  server = undefined;
  await dirs.cleanup();
});

describe('operator (global token) stays read-only [MOCK Google]', () => {
  it('lists Calendar/Contacts read tools and metadata for all accounts, but no write tools', async () => {
    const c = await http(globalToken);
    const tools = await names(c);
    expect(tools).toEqual([...TOOL_NAMES].sort());
    for (const t of [...CAL_TOOLS, 'contacts_get', 'contacts_list']) expect(tools).toContain(t);
    for (const w of WRITE_TOOL_NAMES) expect(tools).not.toContain(w);
    const accounts = (await call(c, 'perch_list_accounts', {})).json;
    expect(accounts.googleProductivity.map((x: { accountId: string }) => x.accountId)).toEqual(['gprod-0000000a', 'gprod-0000000b']);
    expect(accounts.googleProductivity[0]).toMatchObject({ email: 'dummy.a@example.test', services: ['calendar', 'contacts'], granted: ['calendar_read', 'contacts_read'] });
    expect(JSON.stringify(accounts)).not.toMatch(/refresh|secret/i);
    const evs = (await call(c, 'calendar_list_events', { timeMin: '2026-10-01T00:00:00Z' })).json;
    expect(evs.results.length).toBeGreaterThan(0);
    const denied = await call(c, 'calendar_create_event', createArgs());
    expect(denied.isError).toBe(true);
    expect(google.calendarWrites()).toEqual([]);
    await c.close();
  });
});

describe('mail-only clients from the email milestone are unchanged', () => {
  it('get no Calendar/Contacts tools or metadata', async () => {
    const { token } = await grant(['read', 'send'], ['imap-0000000a']);
    const c = await http(token);
    expect(await names(c)).toEqual(PR2_MAIL_SEND_TOOLS);
    const listed = await call(c, 'perch_list_accounts', {});
    expect(Object.keys(listed.json).sort()).toEqual(['connection', 'mail']);
    expect(listed.text).not.toMatch(/gprod-|dummy\.a@|googleProductivity/);
    for (const [t, args] of [['calendar_list_events', {}], ['contacts_list', {}], ['calendar_create_event', createArgs()]] as const) {
      expect((await call(c, t, args)).isError, t).toBe(true);
    }
    expect(googleCalls()).toEqual([]);
    await c.close();
  });
});

describe('calendar/contacts client grants [MOCK Google]', () => {
  it('a calendar writer sees only calendar tools and its account; no mail, contacts, Drive or Notion', async () => {
    const { token } = await grant(['calendar_read', 'calendar_write'], ['gprod-0000000a']);
    const c = await http(token);
    expect(await names(c)).toEqual([...CAL_TOOLS, 'calendar_create_event', 'calendar_delete_event', 'calendar_update_event', 'perch_list_accounts'].sort());
    const listed = await call(c, 'perch_list_accounts', {});
    expect(Object.keys(listed.json).sort()).toEqual(['connection', 'googleProductivity']);
    expect(listed.json.googleProductivity).toEqual([
      expect.objectContaining({ accountId: 'gprod-0000000a', granted: ['calendar_read', 'calendar_write'], providerCapabilities: { calendarRead: true, calendarWrite: true } }),
    ]);
    expect(listed.text).not.toMatch(/gprod-0000000b|imap-0000000a|contactsRead/);
    const created = (await call(c, 'calendar_create_event', createArgs())).json;
    expect(created).toMatchObject({ status: 'created', accountId: 'gprod-0000000a' });
    expect((await call(c, 'calendar_create_event', createArgs('gprod-0000000b'))).text).toMatch(/not granted/i);
    for (const [t, args] of [['mail_search', {}], ['contacts_list', {}], ['drive_search', { query: 'x' }], ['notion_search', {}]] as const) {
      expect((await call(c, t, args)).isError, t).toBe(true);
    }
    expect(mailCalls).toEqual([]);
    expect(google.calendarWrites()).toHaveLength(1);
    await c.close();
  });

  it('calendar_update_event is only listed together with calendar_read', async () => {
    const { token } = await grant(['calendar_write'], ['gprod-0000000a']);
    const c = await http(token);
    expect(await names(c)).toEqual(['calendar_create_event', 'perch_list_accounts']);
    await c.close();
  });

  it('a contacts reader gets only contacts tools and contacts metadata', async () => {
    const { token } = await grant(['contacts_read'], ['gprod-0000000a']);
    const c = await http(token);
    expect(await names(c)).toEqual(['contacts_get', 'contacts_list', 'perch_list_accounts']);
    const listed = (await call(c, 'perch_list_accounts', {})).json;
    expect(listed.googleProductivity[0].providerCapabilities).toEqual({ contactsRead: true });
    const got = (await call(c, 'contacts_get', { accountId: 'gprod-0000000a', resourceName: 'people/c1' })).json;
    expect(got).toMatchObject({ accountId: 'gprod-0000000a', names: [{ displayName: 'Dummy C' }] });
    await c.close();
  });

  it('rejects invitations without calendar_invite and forbidden fields at the MCP boundary with an explicit reason and no write', async () => {
    const { token } = await grant(['calendar_read', 'calendar_write'], ['gprod-0000000a']);
    const c = await http(token);
    for (const [extra, re] of [
      [{ attendees: [{ email: 'guest@example.test' }] }, /calendar_invite/],
      [{ conferenceData: { createRequest: {} } }, /not supported/i],
      [{ colour: 'red' }, /unsupported field/i],
    ] as const) {
      const r = await call(c, 'calendar_create_event', createArgs('gprod-0000000a', extra));
      expect(r.isError).toBe(true);
      expect(r.text).toMatch(re);
    }
    expect(google.calendarWrites()).toEqual([]);
    await c.close();
  });

  it('calendar_invite adds calendar_respond_event; calendar_delete_event needs calendar_write and calendar_read; both are destructive', async () => {
    const { token } = await grant(['calendar_read', 'calendar_invite'], ['gprod-0000000a']);
    const c = await http(token);
    expect(await names(c)).toEqual([...CAL_TOOLS, 'calendar_respond_event', 'perch_list_accounts'].sort());
    const listed = (await call(c, 'perch_list_accounts', {})).json;
    expect(listed.googleProductivity[0].granted).toEqual(['calendar_invite', 'calendar_read']);
    await c.close();
    const { token: t2 } = await grant(['calendar_read', 'calendar_write', 'calendar_invite'], ['gprod-0000000a']);
    const c2 = await http(t2);
    const { tools } = await c2.listTools();
    for (const name of ['calendar_delete_event', 'calendar_respond_event']) {
      expect(tools.find((t) => t.name === name)!.annotations, name).toMatchObject({ destructiveHint: true, readOnlyHint: false });
    }
    expect(tools.find((t) => t.name === 'calendar_delete_event')!.description).toMatch(/permanent/i);
    const invited = (await call(c2, 'calendar_create_event', createArgs('gprod-0000000a', { attendees: ['guest@example.test'], addMeet: true }))).json;
    expect(invited).toMatchObject({ status: 'created', sendUpdates: 'all' });
    const deleted = (await call(c2, 'calendar_delete_event', { accountId: 'gprod-0000000a', calendarId: 'primary', eventId: invited.eventId })).json;
    expect(deleted).toMatchObject({ status: 'deleted', sendUpdates: 'all' });
    expect(google.calendarWrites().map((w) => w.method)).toEqual(['POST', 'DELETE']);
    await c2.close();
  });
});

describe('calendar write subset is private and silent at the MCP boundary [MOCK Google]', () => {
  it('advertises every visibility and useDefault=false, defaults guest-less events to private, and rejects calendar default reminders without a write', async () => {
    const { token } = await grant(['calendar_read', 'calendar_write'], ['gprod-0000000a']);
    const c = await http(token);
    const { tools } = await c.listTools();
    for (const name of ['calendar_create_event', 'calendar_update_event']) {
      const props = (tools.find((t) => t.name === name)!.inputSchema as { properties: Record<string, any> }).properties;
      expect(props.visibility.enum, name).toEqual(['default', 'public', 'private', 'confidential']);
      expect(props.sendUpdates.enum, name).toEqual(['all', 'externalOnly', 'none']);
      expect(props.attendees.maxItems, name).toBe(50);
      expect(props.recurrence.maxItems, name).toBe(5);
      expect(props.reminders.properties.useDefault, name).toMatchObject({ const: false });
    }
    for (const extra of [{ reminders: { useDefault: true } }, { visibility: 'secret' }]) {
      const r = await call(c, 'calendar_create_event', createArgs('gprod-0000000a', extra));
      expect(r.isError, JSON.stringify(extra)).toBe(true);
    }
    expect(google.calendarWrites()).toEqual([]);
    const created = (await call(c, 'calendar_create_event', createArgs())).json;
    expect(created.event).toMatchObject({ visibility: 'private', reminders: { useDefault: false, overrides: [] } });
    expect(created.detail).toMatch(/no invitations or updates were sent to anyone/i);
    await c.close();
  });
});

describe('grant revalidation on every call, without provider I/O', () => {
  it('persistent session: removal fails every Calendar/Contacts tool closed', async () => {
    const { client: g, token } = await grant(['calendar_read', 'calendar_write', 'contacts_read'], ['gprod-0000000a']);
    const c = await memory(token);
    expect((await call(c, 'calendar_list_calendars', {})).isError).toBe(false);
    google.calls.length = 0;
    await removeClientGrant(store, g.id);
    for (const [t, args] of [
      ['calendar_create_event', createArgs()],
      ['calendar_update_event', { accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002', etag: '"2"', summary: 'x' }],
      ['calendar_list_events', {}],
      ['calendar_get_event', { accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002' }],
      ['contacts_list', {}],
      ['contacts_get', { accountId: 'gprod-0000000a', resourceName: 'people/c1' }],
      ['perch_list_accounts', {}],
    ] as const) {
      const r = await call(c, t, args);
      expect(r.isError, t).toBe(true);
      expect(r.text, t).toMatch(/revoked/i);
    }
    expect(google.calls).toEqual([]);
    await c.close();
  });

  it('persistent session: narrowing calendar_write or the account denies on the next call', async () => {
    const { client: g, token } = await grant(['calendar_read', 'calendar_write'], ['gprod-0000000a', 'gprod-0000000b']);
    const c = await memory(token);
    await store.update((d) => {
      d.clients.find((x) => x.id === g.id)!.capabilities = ['calendar_read'];
    });
    expect((await call(c, 'calendar_create_event', createArgs())).text).toMatch(/not granted/i);
    await store.update((d) => {
      const x = d.clients.find((y) => y.id === g.id)!;
      x.capabilities = ['calendar_read', 'calendar_write'];
      x.accountIds = ['gprod-0000000b'];
    });
    expect((await call(c, 'calendar_get_event', { accountId: 'gprod-0000000a', calendarId: 'primary', eventId: 'evt0timed002' })).text).toMatch(/not granted/i);
    const cals = (await call(c, 'calendar_list_calendars', {})).json;
    expect(new Set(cals.results.map((r: { accountId: string }) => r.accountId))).toEqual(new Set(['gprod-0000000b']));
    expect(google.calendarWrites()).toEqual([]);
    await c.close();
  });

  it('HTTP: a removed calendar client token gets 401', async () => {
    const { client: g, token } = await grant(['calendar_read'], ['gprod-0000000a']);
    await removeClientGrant(store, g.id);
    await expect(http(token)).rejects.toThrow();
    expect(googleCalls()).toEqual([]);
  });
});
