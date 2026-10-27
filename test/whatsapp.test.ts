// WhatsApp via the MOCK GOWA bridge: origin rules, pairing, reads, sends (MCP), unlinking.
// No WhatsApp account or real bridge is contacted.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../src/audit/audit.js';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { createPerchContext } from '../src/context.js';
import { SendWorkflow } from '../src/mail/workflow.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { createMcpServer } from '../src/mcp/server.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { isAllowedRoute, Upstream, validateGowaOrigin } from '../src/upstream.js';
import {
  normalisePhone,
  pairWhatsappAccount,
  removeWhatsappAccount,
  setWhatsappInstance,
  whatsappDeviceStatus,
  WhatsappService,
} from '../src/whatsapp/whatsapp.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGowa, type MockWaDevice } from './support/mockGowa.js';

let dirs: TempDirs;
let store: CredentialStore;
let gowa: MockGowa;
let upstream: Upstream;
let service: WhatsappService;

const PERSON = '4366099999999@s.whatsapp.net';
const GROUP = '120363000000000001@g.us';

async function addPairedAccount(label: string, setup?: (d: MockWaDevice) => void): Promise<{ id: string; device: MockWaDevice }> {
  const account = await pairWhatsappAccount(store, upstream, { label, phone: '+43 660 1234567', sleep: async () => {}, onCode: () => {} });
  const device = gowa.devices.find((d) => d.id === account.deviceId)!;
  setup?.(device);
  return { id: account.id, device };
}

function fillChats(d: MockWaDevice) {
  d.chats.push(
    { jid: PERSON, name: 'Dummy Friend', last_message_time: '2026-10-10T10:00:00Z' },
    { jid: GROUP, name: 'Dummy Group', last_message_time: '2026-10-11T10:00:00Z' },
  );
  d.messages.push(
    { id: '3EB0AAAA00000001', chat_jid: PERSON, sender_jid: PERSON, sender_display_name: 'Dummy Friend', content: 'Dinner on Friday?', timestamp: '2026-10-10T09:00:00Z', is_from_me: false },
    { id: '3EB0AAAA00000002', chat_jid: PERSON, sender_jid: 'me@s.whatsapp.net', content: 'Yes, dinner works', timestamp: '2026-10-10T10:00:00Z', is_from_me: true },
    {
      id: '3EB0AAAA00000003',
      chat_jid: GROUP,
      sender_jid: PERSON,
      content: '',
      timestamp: '2026-10-11T10:00:00Z',
      is_from_me: false,
      media_type: 'image',
      filename: 'photo.jpg',
      url: 'http://127.0.0.1:3000/statics/media/secret-path.jpg',
    },
  );
}

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  gowa = new MockGowa();
  upstream = new Upstream(gowa.transport);
  await setWhatsappInstance(store, upstream, { url: gowa.origin, username: gowa.username, password: gowa.password });
  const ledger = new MailWorkflowLedger(store);
  service = new WhatsappService(store, upstream, new SendWorkflow(ledger), new AuditLog(ledger));
});

afterEach(async () => {
  await dirs.cleanup();
});

describe('GOWA origin [mock bridge]', () => {
  it('accepts loopback and Tailscale addresses with explicit port only', () => {
    expect(validateGowaOrigin('http://127.0.0.1:3000')).toBe('http://127.0.0.1:3000');
    expect(validateGowaOrigin('http://localhost:3000/')).toBe('http://localhost:3000');
    expect(validateGowaOrigin('http://[::1]:3000')).toBe('http://[::1]:3000');
    expect(validateGowaOrigin('https://100.101.102.103:3443')).toBe('https://100.101.102.103:3443');
    for (const bad of [
      'http://192.168.1.10:3000',
      'http://10.0.0.1:3000',
      'http://example.com:3000',
      'http://127.0.0.1',
      'http://127.0.0.1:3000/api',
      'http://user:pw@127.0.0.1:3000',
      'http://100.128.0.1:3000',
      'file:///etc/passwd',
      'http://0.0.0.0:3000',
      'http://100.100.100.100:3000',
    ]) {
      expect(() => validateGowaOrigin(bad), bad).toThrow(/GOWA URL/);
    }
  });

  it('stores the instance only after an authenticated request succeeded', async () => {
    const fresh = await makeTempDirs();
    await initStore({ dataDir: fresh.dataDir, keyFile: fresh.keyFile });
    const s = await CredentialStore.open({ dataDir: fresh.dataDir, keyFile: fresh.keyFile });
    expect((await rejection(setWhatsappInstance(s, upstream, { url: gowa.origin, username: 'perch', password: 'wrong' }))).message).toMatch(/401/);
    expect((await s.read()).whatsappInstance).toBeUndefined();
    await fresh.cleanup();
  });

  it('never lets an MCP-reachable route touch device management or other send endpoints', () => {
    expect(isAllowedRoute('gowa', 'POST', '/devices')).toBe(false);
    expect(isAllowedRoute('gowa', 'DELETE', '/devices/perch-0123456789abcdef')).toBe(false);
    expect(isAllowedRoute('gowa', 'POST', '/devices/perch-0123456789abcdef/login/code', 'whatsapp_send')).toBe(false);
    expect(isAllowedRoute('gowa', 'POST', '/send/message', 'whatsapp_send')).toBe(true);
    for (const p of ['/send/sticker', '/send/link', '/message/3EB0/revoke', '/message/3EB0/delete', '/group', '/user/my/contacts', '/app/logout', '/chat/1%40g.us/archive']) {
      expect(isAllowedRoute('gowa', 'POST', p, 'whatsapp_send')).toBe(false);
      expect(isAllowedRoute('gowa', 'GET', p)).toBe(false);
    }
    expect(isAllowedRoute('gowa', 'DELETE', '/devices/other-device', 'admin')).toBe(false);
    expect(isAllowedRoute('gowa', 'GET', '/devices/perch-0123456789abcdef')).toBe(false);
    expect(isAllowedRoute('gowa', 'GET', '/devices/perch-0123456789abcdef/status', 'admin')).toBe(true);
  });
});

describe('WhatsApp pairing [mock bridge]', () => {
  it('normalises phone numbers', () => {
    expect(normalisePhone('+43 660 123-4567')).toBe('436601234567');
    expect(normalisePhone('0043 660 1234567')).toBe('436601234567');
    expect(() => normalisePhone('0660 1234567')).toThrow(/international/);
  });

  it('pairs by code, waits for login and stores the device slot and JID', async () => {
    const codes: string[] = [];
    const account = await pairWhatsappAccount(store, upstream, { label: 'Private', phone: '+4366012345678', sleep: async () => {}, onCode: (c) => codes.push(c) });
    expect(codes).toEqual(['ABCD-1234']);
    expect(account).toMatchObject({ label: 'Private', jid: '4366012345678@s.whatsapp.net', displayName: 'Dummy Owner' });
    expect(account.deviceId).toMatch(/^perch-[a-f0-9]{16}$/);
    const codeCall = gowa.calls.find((c) => c.url.pathname.endsWith('/login/code'))!;
    expect(codeCall.url.searchParams.get('phone')).toBe('4366012345678');
    expect(await whatsappDeviceStatus(store, upstream)).toMatchObject([{ loggedIn: true, connected: true }]);
  });

  it('keeps polling through a transient bridge error instead of unlinking a paired device', async () => {
    const real = gowa.transport;
    let failed = false;
    const flaky = new Upstream(async (req) => {
      if (!failed && req.url.pathname.endsWith('/status')) {
        failed = true;
        throw new Error('MOCK: transient');
      }
      return real(req);
    });
    const account = await pairWhatsappAccount(store, flaky, { label: 'Flaky', phone: '+4366012345678', sleep: async () => {}, onCode: () => {} });
    expect(failed).toBe(true);
    expect(gowa.devices.map((d) => d.id)).toContain(account.deviceId);
  });

  it('removes the device slot again when pairing times out', async () => {
    gowa.devices.length = 0;
    const realAdd = gowa.addDevice.bind(gowa);
    gowa.addDevice = (id, opts) => realAdd(id, { ...opts, loginAfterPolls: 1_000_000 });
    const err = await rejection(pairWhatsappAccount(store, upstream, { label: 'X', phone: '+4366012345678', timeoutMs: 0, sleep: async () => {}, onCode: () => {} }));
    expect(err.message).toMatch(/timed out/);
    expect(gowa.devices).toHaveLength(0);
    expect((await store.read()).whatsapp).toHaveLength(0);
  });

  it('unlinks the device slot on remove (or keeps it on request)', async () => {
    const a = await addPairedAccount('A');
    const b = await addPairedAccount('B');
    expect(await removeWhatsappAccount(store, upstream, a.id)).toBe(true);
    expect(gowa.devices.map((d) => d.id)).toEqual([b.device.id]);
    expect(await removeWhatsappAccount(store, upstream, b.id, { keepDevice: true })).toBe(false);
    expect(gowa.devices.map((d) => d.id)).toEqual([b.device.id]);
    expect((await store.read()).whatsapp).toHaveLength(0);
  });
});

describe('WhatsApp reads [mock bridge]', () => {
  it('lists chats across accounts with provenance, always naming the device slot', async () => {
    const a = await addPairedAccount('Private', fillChats);
    const b = await addPairedAccount('Business', (d) => d.chats.push({ jid: '4366011111111@s.whatsapp.net', name: 'Customer', last_message_time: '2026-10-01T00:00:00Z' }));
    // A request without X-Device-Id would land on this foreign default device: it must never be used.
    gowa.addDevice('foreign-default', { chats: [{ jid: '4360000000000@s.whatsapp.net', name: 'NOT MINE', last_message_time: '2026-10-12T00:00:00Z' }] });
    gowa.defaultDeviceId = 'foreign-default';
    const r = await service.listChats(READONLY_PRINCIPAL, {});
    expect(r.results.map((c) => [c.accountId, c.chatJid, c.kind])).toEqual(
      expect.arrayContaining([
        [a.id, PERSON, 'person'],
        [a.id, GROUP, 'group'],
        [b.id, '4366011111111@s.whatsapp.net', 'person'],
      ]),
    );
    expect(JSON.stringify(r)).not.toContain('NOT MINE');
    for (const c of gowa.calls.filter((x) => x.url.pathname === '/chats' || x.url.pathname.startsWith('/chat/'))) expect(c.headers['x-device-id']).toMatch(/^perch-/);
  });

  it('reads messages with search and time window, media as metadata only, never media URLs', async () => {
    const a = await addPairedAccount('Private', fillChats);
    const all = await service.getMessages(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON });
    expect(all.messages.map((m) => m.text)).toEqual(['Yes, dinner works', 'Dinner on Friday?']);
    expect(all).toMatchObject({ chatName: 'Dummy Friend', accountId: a.id, accountLabel: 'Private' });
    const hit = await service.getMessages(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, query: 'friday' });
    expect(hit.messages.map((m) => m.messageId)).toEqual(['3EB0AAAA00000001']);
    const windowed = await service.getMessages(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, after: '2026-10-10T09:30:00+00:00' });
    expect(windowed.messages.map((m) => m.messageId)).toEqual(['3EB0AAAA00000002']);
    const media = await service.getMessages(READONLY_PRINCIPAL, { accountId: a.id, chatJid: GROUP });
    expect(media.messages[0]).toMatchObject({ mediaType: 'image', filename: 'photo.jpg' });
    expect(JSON.stringify(media)).not.toContain('secret-path');
  });

  it('drops rows of another chat that the bridge returns by mistake', async () => {
    const a = await addPairedAccount('Private', fillChats);
    gowa.leakForeignRows = true;
    const r = await service.getMessages(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON });
    expect(r.messages.every((m) => m.messageId !== '3EB0AAAA00000003')).toBe(true);
  });

  it('paginates with a cursor sealed to account, chat and filters', async () => {
    const a = await addPairedAccount('Private', fillChats);
    const p1 = await service.getMessages(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, pageSize: 1 });
    expect(p1.hasMore).toBe(true);
    const p2 = await service.getMessages(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, pageSize: 1, cursor: p1.nextCursor! });
    expect(p2.messages.map((m) => m.messageId)).toEqual(['3EB0AAAA00000001']);
    await expect(service.getMessages(READONLY_PRINCIPAL, { accountId: a.id, chatJid: GROUP, pageSize: 1, cursor: p1.nextCursor! })).rejects.toThrow(/cursor/i);
  });

  it('validates chat ids before any request', async () => {
    const a = await addPairedAccount('Private', fillChats);
    const calls = gowa.calls.length;
    for (const jid of ['status@broadcast', '../send/message', '123@newsletter', 'abc@s.whatsapp.net']) {
      await expect(service.getMessages(READONLY_PRINCIPAL, { accountId: a.id, chatJid: jid })).rejects.toThrow(/chatJid/);
    }
    expect(gowa.calls.length).toBe(calls);
  });

  it('searches the most recent chats and says that it is not a global search', async () => {
    const a = await addPairedAccount('Private', fillChats);
    const r = await service.search(READONLY_PRINCIPAL, { query: 'dinner' });
    expect(r.results.map((m) => [m.accountId, m.chatJid, m.messageId])).toEqual([
      [a.id, PERSON, '3EB0AAAA00000002'],
      [a.id, PERSON, '3EB0AAAA00000001'],
    ]);
    expect(r.chatsSearched).toBe(2);
    expect(r.note).toMatch(/not all chats/);
    const one = await service.search(READONLY_PRINCIPAL, { query: 'dinner', chatLimit: 1 });
    expect(one.results).toHaveLength(0); // the most recent chat is the group
  });
});

describe('whatsapp_send_message [mock bridge, MCP]', () => {
  async function clientFor(principal: Principal) {
    const mcp = createMcpServer(createPerchContext(store, gowa.transport), principal);
    const [x, y] = InMemoryTransport.createLinkedPair();
    await mcp.connect(y);
    const client = new Client({ name: 'wa-test', version: '0' });
    await client.connect(x);
    return client;
  }
  async function sender(accountIds: string[]) {
    const { token } = await createClientGrant(store, {
      label: 'Claude',
      capabilities: ['whatsapp_read', 'whatsapp_send'],
      accountIds,
      tokenFile: `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token`,
    });
    return clientFor((await principalForClientToken(store, token))!);
  }
  async function call(client: Client, name: string, args: Record<string, unknown>) {
    const r = await client.callTool({ name, arguments: args });
    return { isError: r.isError === true, body: JSON.parse((r.content as Array<{ text: string }>)[0]!.text) as Record<string, unknown> };
  }
  const rid = () => `wa-test-${Math.random().toString(16).slice(2, 14)}`;

  it('is not offered to the read-only global token', async () => {
    await addPairedAccount('Private', fillChats);
    const names = (await (await clientFor(READONLY_PRINCIPAL)).listTools()).tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(['whatsapp_list_chats', 'whatsapp_get_messages', 'whatsapp_search']));
    expect(names).not.toContain('whatsapp_send_message');
  });

  it('sends once per requestId from the chosen device and replays repeats', async () => {
    const a = await addPairedAccount('Private', fillChats);
    const client = await sender([a.id]);
    const args = { accountId: a.id, chatJid: PERSON, text: 'See you Friday', replyToMessageId: '3EB0AAAA00000001', requestId: rid() };
    const first = await call(client, 'whatsapp_send_message', args);
    expect(first.body).toMatchObject({ status: 'accepted', replayed: false, accountId: a.id, chatJid: PERSON });
    expect(first.body.messageId).toMatch(/^3EB0MOCK/);
    expect((await call(client, 'whatsapp_send_message', args)).body).toMatchObject({ status: 'accepted', replayed: true, messageId: first.body.messageId });
    expect(a.device.sent).toEqual([{ phone: PERSON, message: 'See you Friday', reply_message_id: '3EB0AAAA00000001' }]);
    const send = gowa.calls.find((c) => c.url.pathname === '/send/message')!;
    expect(send.headers['x-device-id']).toBe(a.device.id);
    expect(JSON.parse(send.body!)).not.toHaveProperty('scheduled_at');
    expect((await call(client, 'whatsapp_send_status', { accountId: a.id, requestId: args.requestId })).body).toMatchObject({ status: 'accepted', messageId: first.body.messageId });
  });

  it('denies accounts outside the grant and the global token before any request', async () => {
    const a = await addPairedAccount('Private', fillChats);
    const b = await addPairedAccount('Business', fillChats);
    const client = await sender([a.id]);
    const calls = gowa.calls.length;
    const r = await call(client, 'whatsapp_send_message', { accountId: b.id, chatJid: PERSON, text: 'x', requestId: rid() });
    expect(r.isError).toBe(true);
    expect(gowa.calls.length).toBe(calls);
    await expect(service.send(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, text: 'x', requestId: rid() })).rejects.toThrow(/read-only/);
    expect(gowa.calls.length).toBe(calls);
  });

  it('maps bridge failures: 4xx rejected, lost response and unconfirmed answers indeterminate', async () => {
    const a = await addPairedAccount('Private', fillChats);
    const client = await sender([a.id]);
    gowa.sendMode = { kind: 'http', status: 400 };
    expect((await call(client, 'whatsapp_send_message', { accountId: a.id, chatJid: PERSON, text: '1', requestId: rid() })).body.status).toBe('rejected');
    gowa.sendMode = { kind: 'throw' };
    const lost = { accountId: a.id, chatJid: PERSON, text: '2', requestId: rid() };
    expect((await call(client, 'whatsapp_send_message', lost)).body.status).toBe('indeterminate');
    gowa.sendMode = { kind: 'no_success' };
    expect((await call(client, 'whatsapp_send_message', { accountId: a.id, chatJid: PERSON, text: '3', requestId: rid() })).body.status).toBe('indeterminate');
    gowa.sendMode = { kind: 'ok' };
    expect((await call(client, 'whatsapp_send_message', lost)).body).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(a.device.sent).toHaveLength(0);
  });

  it('records body-free audit events', async () => {
    const a = await addPairedAccount('Private', fillChats);
    const client = await sender([a.id]);
    await call(client, 'whatsapp_send_message', { accountId: a.id, chatJid: PERSON, text: 'very private text', requestId: rid() });
    await call(client, 'whatsapp_get_messages', { accountId: a.id, chatJid: PERSON });
    const ledger = await new MailWorkflowLedger(store).read();
    expect(ledger.audit.filter((e) => e.provider === 'whatsapp').map((e) => [e.type, e.outcome])).toEqual([
      ['whatsapp_send_message', 'pending'],
      ['whatsapp_send_message', 'accepted'],
      ['whatsapp_get_messages', 'ok'],
    ]);
    const raw = JSON.stringify(ledger);
    expect(raw).not.toContain('very private text');
    expect(raw).not.toContain('4366099999999');
  });
});
