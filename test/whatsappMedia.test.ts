// WhatsApp media (send and download) via the MOCK GOWA bridge. No WhatsApp account or real bridge is contacted;
// passing tests are NOT evidence of a live integration.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../src/audit/audit.js';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import type { Capability } from '../src/store/credentialStore.js';
import { createPerchContext } from '../src/context.js';
import { SendWorkflow } from '../src/mail/workflow.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { createMcpServer } from '../src/mcp/server.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { isAllowedRoute, Upstream } from '../src/upstream.js';
import { MAX_WA_MEDIA_BASE64, MAX_WA_MEDIA_BYTES, multipartBody, pairWhatsappAccount, setWhatsappInstance, WhatsappService } from '../src/whatsapp/whatsapp.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGowa, parseMultipart, type MockWaDevice } from './support/mockGowa.js';

let dirs: TempDirs;
let store: CredentialStore;
let gowa: MockGowa;
let upstream: Upstream;
let service: WhatsappService;

const PERSON = '4366099999999@s.whatsapp.net';
const GROUP = '120363000000000001@g.us';
const PNG = Buffer.from('89504e470d0a1a0a0000000d49484452dummy-png-bytes', 'utf8');
const rid = () => `wa-media-${Math.random().toString(16).slice(2, 14)}`;

async function addPairedAccount(label: string, setup?: (d: MockWaDevice) => void): Promise<{ id: string; device: MockWaDevice }> {
  const account = await pairWhatsappAccount(store, upstream, { label, phone: '+43 660 1234567', sleep: async () => {}, onCode: () => {} });
  const device = gowa.devices.find((d) => d.id === account.deviceId)!;
  device.chats.push({ jid: PERSON, name: 'Dummy Friend', last_message_time: '2026-10-10T10:00:00Z' });
  setup?.(device);
  return { id: account.id, device };
}

async function clientFor(principal: Principal) {
  const mcp = createMcpServer(createPerchContext(store, gowa.transport), principal);
  const [x, y] = InMemoryTransport.createLinkedPair();
  await mcp.connect(y);
  const client = new Client({ name: 'wa-media-test', version: '0' });
  await client.connect(x);
  return client;
}

async function grant(capabilities: Capability[], accountIds: string[]): Promise<Principal> {
  const { token } = await createClientGrant(store, {
    label: 'Claude',
    capabilities,
    accountIds,
    tokenFile: `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token`,
  });
  return (await principalForClientToken(store, token))!;
}

async function call(client: Client, name: string, args: Record<string, unknown>) {
  const r = await client.callTool({ name, arguments: args });
  const text = (r.content as Array<{ text: string }>)[0]!.text;
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {
    body = { text };
  }
  return { isError: r.isError === true, body, text };
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

describe('WhatsApp media allowlist', () => {
  it('allows exactly the four media send routes for whatsapp_send and the download routes as reads', () => {
    for (const k of ['image', 'video', 'audio', 'file']) {
      expect(isAllowedRoute('gowa', 'POST', `/send/${k}`, 'whatsapp_send')).toBe(true);
      expect(isAllowedRoute('gowa', 'POST', `/send/${k}`)).toBe(false);
      expect(isAllowedRoute('gowa', 'GET', `/send/${k}`)).toBe(false);
    }
    expect(isAllowedRoute('gowa', 'GET', '/message/3EB0AAAA00000003/download')).toBe(true);
    expect(isAllowedRoute('gowa', 'GET', '/statics/media/4366099999999/2026-10-20/photo.jpg')).toBe(true);
    expect(isAllowedRoute('gowa', 'GET', '/statics/media/120363000000000001-1234567/2026-10-20/a_b-c.ogg')).toBe(true);
  });

  it('never allowlists revoke, delete, other message routes, other send routes or other static files', () => {
    const caps = ['read', 'whatsapp_send', 'admin'] as const;
    const paths = [
      '/message/3EB0AAAA00000003/revoke',
      '/message/3EB0AAAA00000003/delete',
      '/message/3EB0AAAA00000003/update',
      '/message/3EB0AAAA00000003/reaction',
      '/message/3EB0AAAA00000003/forward',
      '/message/3EB0AAAA0000000./download',
      '/message/../download',
      '/message/3EB0AAAA00000003/download/x',
      '/send/sticker',
      '/send/link',
      '/send/contact',
      '/send/location',
      '/send/poll',
      '/send/presence',
      '/send/chat-presence',
      '/send/schedules',
      '/send/image/x',
      '/statics/images/qrcode/scan-qr.png',
      '/statics/media/4366099999999/2026-10-20/../../config.json',
      '/statics/media/4366099999999/2026-10-20/.env',
      '/statics/media/4366099999999/2026-10-20/a/b.jpg',
      '/statics/media/abc/2026-10-20/a.jpg',
      '/statics/media/4366099999999/2026-10-20/a%2F..%2Fb',
    ];
    for (const p of paths) {
      for (const method of ['GET', 'POST', 'DELETE'] as const) {
        for (const cap of caps) expect(isAllowedRoute('gowa', method, p, cap), `${method} ${p} ${cap}`).toBe(false);
      }
    }
  });
});

describe('whatsapp_send_media [mock bridge, MCP]', () => {
  it('sends each kind as multipart with the documented field names, from the account device slot', async () => {
    const a = await addPairedAccount('Private');
    const client = await clientFor(await grant(['whatsapp_read', 'whatsapp_send'], [a.id]));
    const cases = [
      { kind: 'image', filename: 'photo.png', mimeType: 'image/png', caption: 'Look', replyToMessageId: '3EB0AAAA00000001' },
      { kind: 'video', filename: 'clip.mp4', caption: 'Clip' },
      { kind: 'audio', filename: 'note.ogg', mimeType: 'audio/ogg' },
      { kind: 'file', filename: 'Report (final).pdf', mimeType: 'application/pdf', caption: 'Report' },
    ] as const;
    for (const c of cases) {
      const r = await call(client, 'whatsapp_send_media', { accountId: a.id, chatJid: PERSON, contentBase64: PNG.toString('base64'), requestId: rid(), ...c });
      expect(r.body, c.kind).toMatchObject({ status: 'accepted', replayed: false, accountId: a.id, chatJid: PERSON, kind: c.kind });
      expect(r.body.messageId).toMatch(/^3EB0MEDIA/);
    }
    expect(gowa.mediaSent.map((s) => s.route)).toEqual(['image', 'video', 'audio', 'file']);
    const [image, video, audio, file] = gowa.mediaSent;
    expect(image!.fieldNames).toEqual(['phone', 'caption', 'reply_message_id', 'image']);
    expect(image!.fields).toEqual({ phone: PERSON, caption: 'Look', reply_message_id: '3EB0AAAA00000001' });
    expect(image!.file).toMatchObject({ name: 'image', filename: 'photo.png', contentType: 'image/png' });
    expect(image!.file!.data.equals(PNG)).toBe(true);
    expect(video!.fieldNames).toEqual(['phone', 'caption', 'video']);
    expect(video!.file).toMatchObject({ filename: 'clip.mp4', contentType: 'video/mp4' });
    expect(audio!.fieldNames).toEqual(['phone', 'audio']);
    expect(file!.fieldNames).toEqual(['phone', 'caption', 'file']);
    expect(file!.file).toMatchObject({ filename: 'Report (final).pdf', contentType: 'application/pdf' });
    for (const s of gowa.mediaSent) {
      expect(s.deviceId).toBe(a.device.id);
      for (const forbidden of ['image_url', 'video_url', 'audio_url', 'file_url', 'view_once', 'scheduled_at', 'timezone', 'recurrence', 'is_forwarded', 'duration', 'mentions', 'allow_reshare', 'compress', 'ptt']) {
        expect(s.fieldNames).not.toContain(forbidden);
      }
    }
    for (const c of gowa.calls.filter((x) => x.url.pathname.startsWith('/send/'))) {
      expect(c.headers['x-device-id']).toBe(a.device.id);
      expect(c.url.origin).toBe(gowa.origin);
      expect(c.body).toBeUndefined();
    }
  });

  it('is not offered to the read-only operator or to a client without whatsapp_send', async () => {
    const a = await addPairedAccount('Private');
    const operatorTools = (await (await clientFor(READONLY_PRINCIPAL)).listTools()).tools.map((t) => t.name);
    expect(operatorTools).toContain('whatsapp_download_media');
    expect(operatorTools).not.toContain('whatsapp_send_media');
    const reader = await grant(['whatsapp_read'], [a.id]);
    const readerTools = (await (await clientFor(reader)).listTools()).tools.map((t) => t.name);
    expect(readerTools).toContain('whatsapp_download_media');
    expect(readerTools).not.toContain('whatsapp_send_media');
    const calls = gowa.calls.length;
    const req = { accountId: a.id, chatJid: PERSON, kind: 'image' as const, filename: 'a.png', contentBase64: PNG.toString('base64'), requestId: rid() };
    expect((await rejection(service.sendMedia(reader, req))).message).toMatch(/whatsapp_send/);
    expect((await rejection(service.sendMedia(READONLY_PRINCIPAL, req))).message).toMatch(/read-only/);
    expect(gowa.calls.length).toBe(calls);
    expect(gowa.mediaSent).toHaveLength(0);
  });

  it('denies an account outside the grant before any request', async () => {
    const a = await addPairedAccount('Private');
    const b = await addPairedAccount('Business');
    const client = await clientFor(await grant(['whatsapp_read', 'whatsapp_send'], [a.id]));
    const calls = gowa.calls.length;
    const r = await call(client, 'whatsapp_send_media', { accountId: b.id, chatJid: PERSON, kind: 'image', filename: 'a.png', contentBase64: PNG.toString('base64'), requestId: rid() });
    expect(r.isError).toBe(true);
    expect(gowa.calls.length).toBe(calls);
  });

  it('validates size, kind, caption, mime type and file name before any request', async () => {
    const a = await addPairedAccount('Private');
    const p = await grant(['whatsapp_read', 'whatsapp_send'], [a.id]);
    const base = { accountId: a.id, chatJid: PERSON, kind: 'image' as const, filename: 'a.png', contentBase64: PNG.toString('base64') };
    const calls = gowa.calls.length;
    const tooBig = 'A'.repeat(MAX_WA_MEDIA_BASE64 + 4);
    const exactlyOver = Buffer.alloc(MAX_WA_MEDIA_BYTES + 1).toString('base64');
    const bad: Array<[Record<string, unknown>, RegExp]> = [
      [{ contentBase64: tooBig }, /exceeds/],
      [{ contentBase64: exactlyOver }, /exceeds/],
      [{ contentBase64: '' }, /required/],
      [{ contentBase64: 'not base64!' }, /base64/],
      [{ contentBase64: 'QUJD\nRA==' }, /base64/],
      [{ kind: 'sticker' }, /kind/],
      [{ kind: 'audio', filename: 'a.ogg', mimeType: 'audio/ogg', caption: 'x' }, /caption/],
      [{ mimeType: 'application/pdf' }, /image\//],
      [{ mimeType: 'image/png\r\nX-Evil: 1' }, /mimeType/],
      [{ filename: 'a"; name="phone' }, /filename/],
      [{ filename: 'line\r\nbreak.png' }, /filename/],
      [{ filename: '../etc/passwd' }, /filename/],
      [{ filename: '.hidden' }, /filename/],
      [{ chatJid: 'status@broadcast' }, /chatJid/],
      [{ replyToMessageId: '../x' }, /replyToMessageId/],
      [{ caption: 'x'.repeat(5000) }, /caption/],
    ];
    for (const [patch, re] of bad) {
      const err = await rejection(service.sendMedia(p, { ...base, ...patch, requestId: rid() } as never));
      expect(err.message, JSON.stringify(patch).slice(0, 80)).toMatch(re);
    }
    expect(gowa.calls.length).toBe(calls);
  });

  it('replays a repeated requestId and refuses the same requestId with other content', async () => {
    const a = await addPairedAccount('Private');
    const client = await clientFor(await grant(['whatsapp_read', 'whatsapp_send'], [a.id]));
    const args = { accountId: a.id, chatJid: PERSON, kind: 'file', filename: 'a.pdf', mimeType: 'application/pdf', contentBase64: PNG.toString('base64'), requestId: rid() };
    const first = await call(client, 'whatsapp_send_media', args);
    expect(first.body).toMatchObject({ status: 'accepted', replayed: false });
    expect((await call(client, 'whatsapp_send_media', args)).body).toMatchObject({ status: 'accepted', replayed: true, messageId: first.body.messageId });
    const other = await call(client, 'whatsapp_send_media', { ...args, contentBase64: Buffer.from('other bytes').toString('base64') });
    expect(other.isError).toBe(true);
    expect(other.text).toMatch(/idempotency_conflict|different/i);
    expect(gowa.mediaSent).toHaveLength(1);
    expect((await call(client, 'whatsapp_send_status', { accountId: a.id, requestId: args.requestId })).body).toMatchObject({ status: 'accepted', messageId: first.body.messageId });
  });

  it('maps bridge failures: 4xx rejected, lost response and unconfirmed answers indeterminate, never retried', async () => {
    const a = await addPairedAccount('Private');
    const client = await clientFor(await grant(['whatsapp_read', 'whatsapp_send'], [a.id]));
    const args = (n: string) => ({ accountId: a.id, chatJid: PERSON, kind: 'image', filename: `${n}.png`, contentBase64: PNG.toString('base64'), requestId: rid() });
    gowa.sendMode = { kind: 'http', status: 400 };
    expect((await call(client, 'whatsapp_send_media', args('1'))).body.status).toBe('rejected');
    gowa.sendMode = { kind: 'http', status: 502 };
    expect((await call(client, 'whatsapp_send_media', args('2'))).body.status).toBe('indeterminate');
    gowa.sendMode = { kind: 'throw' };
    const lost = args('3');
    expect((await call(client, 'whatsapp_send_media', lost)).body.status).toBe('indeterminate');
    gowa.sendMode = { kind: 'no_success' };
    expect((await call(client, 'whatsapp_send_media', args('4'))).body.status).toBe('indeterminate');
    gowa.sendMode = { kind: 'ok' };
    expect((await call(client, 'whatsapp_send_media', lost)).body).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(gowa.mediaSent).toHaveLength(0);
  });

  it('records audit events without file content, caption or chat id', async () => {
    const a = await addPairedAccount('Private', (d) => {
      d.media = { '3EB0AAAA00000003': { data: PNG, filename: 'photo.png', mimeType: 'image/png', mediaType: 'image', chatDigits: '4366099999999' } };
    });
    const client = await clientFor(await grant(['whatsapp_read', 'whatsapp_send'], [a.id]));
    const secret = Buffer.from('very private file content').toString('base64');
    await call(client, 'whatsapp_send_media', { accountId: a.id, chatJid: PERSON, kind: 'image', filename: 'secret-name.png', caption: 'very private caption', contentBase64: secret, requestId: rid() });
    await call(client, 'whatsapp_download_media', { accountId: a.id, chatJid: PERSON, messageId: '3EB0AAAA00000003' });
    const ledger = await new MailWorkflowLedger(store).read();
    expect(ledger.audit.filter((e) => e.provider === 'whatsapp').map((e) => [e.type, e.outcome])).toEqual([
      ['whatsapp_send_message', 'pending'],
      ['whatsapp_send_message', 'accepted'],
      ['whatsapp_download_media', 'ok'],
    ]);
    const raw = JSON.stringify(ledger);
    for (const s of ['very private', secret, 'secret-name', '4366099999999', PNG.toString('base64'), 'photo.png']) expect(raw).not.toContain(s);
  });
});

describe('whatsapp_download_media [mock bridge]', () => {
  const MEDIA_ID = '3EB0AAAA00000003';
  const withMedia = (extra: Partial<NonNullable<MockWaDevice['media']>[string]> = {}) => (d: MockWaDevice) => {
    d.media = { [MEDIA_ID]: { data: PNG, filename: 'photo.png', mimeType: 'image/png', mediaType: 'image', chatDigits: '4366099999999', ...extra } };
  };

  it('returns base64, mime type and filename, reading only from the bridge origin with the device slot', async () => {
    const a = await addPairedAccount('Private', withMedia());
    const client = await clientFor(READONLY_PRINCIPAL);
    const r = await call(client, 'whatsapp_download_media', { accountId: a.id, chatJid: PERSON, messageId: MEDIA_ID });
    expect(r.isError).toBe(false);
    expect(r.body).toMatchObject({ accountId: a.id, chatJid: PERSON, messageId: MEDIA_ID, mediaType: 'image', filename: 'photo.png', mimeType: 'image/png', size: PNG.length });
    expect(Buffer.from(String(r.body.contentBase64), 'base64').equals(PNG)).toBe(true);
    const dl = gowa.calls.find((c) => c.url.pathname === `/message/${MEDIA_ID}/download`)!;
    expect(dl.url.searchParams.get('phone')).toBe(PERSON);
    const file = gowa.calls.find((c) => c.url.pathname.startsWith('/statics/'))!;
    expect(file.url.href).toBe(`${gowa.origin}/statics/media/4366099999999/2026-10-20/photo.png`);
    for (const c of [dl, file]) {
      expect(c.headers['x-device-id']).toBe(a.device.id);
      expect(c.headers.authorization).toMatch(/^Basic /);
    }
  });

  it('is denied to a client without whatsapp_read and for accounts outside the grant, before any request', async () => {
    const a = await addPairedAccount('Private', withMedia());
    const b = await addPairedAccount('Business', withMedia());
    const calls = gowa.calls.length;
    const sendOnly = await grant(['whatsapp_send'], [a.id]);
    await expect(service.downloadMedia(sendOnly, { accountId: a.id, chatJid: PERSON, messageId: MEDIA_ID })).rejects.toThrow(/whatsapp_read/);
    const reader = await grant(['whatsapp_read'], [a.id]);
    await expect(service.downloadMedia(reader, { accountId: b.id, chatJid: PERSON, messageId: MEDIA_ID })).rejects.toThrow();
    expect(gowa.calls.length).toBe(calls);
  });

  it('refuses media larger than maxBytes instead of truncating, and checks limits before any request', async () => {
    const big = Buffer.alloc(60 * 1024, 7);
    const a = await addPairedAccount('Private', withMedia({ data: big }));
    expect((await rejection(service.downloadMedia(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, messageId: MEDIA_ID }))).message).toMatch(/larger than maxBytes/);
    expect(gowa.calls.some((c) => c.url.pathname.startsWith('/statics/'))).toBe(false);
    // The bridge under-reports the size: the read itself is capped and refused, never cut.
    a.device.media![MEDIA_ID]!.reportSize = 10;
    expect((await rejection(service.downloadMedia(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, messageId: MEDIA_ID }))).message).toMatch(/larger than maxBytes/);
    const ok = await service.downloadMedia(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, messageId: MEDIA_ID, maxBytes: 64 * 1024 });
    expect(ok.size).toBe(big.length);
    const calls = gowa.calls.length;
    for (const maxBytes of [0, -1, 1.5, MAX_WA_MEDIA_BYTES + 1]) {
      await expect(service.downloadMedia(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, messageId: MEDIA_ID, maxBytes })).rejects.toThrow(/maxBytes/);
    }
    for (const messageId of ['../x', '3EB0/../a', 'short', 'x'.repeat(65)]) {
      await expect(service.downloadMedia(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, messageId })).rejects.toThrow(/messageId/);
    }
    await expect(service.downloadMedia(READONLY_PRINCIPAL, { accountId: a.id, chatJid: 'status@broadcast', messageId: MEDIA_ID })).rejects.toThrow(/chatJid/);
    expect(gowa.calls.length).toBe(calls);
  });

  it('rejects hostile file locations and never reads from another host or path', async () => {
    const a = await addPairedAccount('Private', withMedia());
    const good = 'statics/media/4366099999999/2026-10-20/photo.png';
    const hostile: Array<{ file_path?: unknown; file_url?: unknown }> = [
      { file_path: '../../etc/passwd' },
      { file_path: '/etc/passwd' },
      { file_path: 'statics/media/4366099999999/2026-10-20/../../../storages/whatsapp.db' },
      { file_path: 'statics/images/qrcode/scan-qr.png' },
      { file_path: 'statics/media/4366099999999/2026-10-20/sub/photo.png' },
      { file_path: 'statics/media/4366099999999/2026-10-20/.env' },
      { file_path: 42 },
      { file_url: 'http://evil.example:3000/statics/media/4366099999999/2026-10-20/other.png', file_path: good },
      { file_url: `http://127.0.0.1:3000/${good}?x=1` },
      { file_url: `http://user:pw@127.0.0.1:3000/${good}` },
      { file_url: `file:///${good}` },
      { file_url: 'not a url' },
      {},
    ];
    for (const loc of hostile) {
      gowa.downloadLocation = loc;
      const err = await rejection(service.downloadMedia(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, messageId: MEDIA_ID }));
      expect(err.message, JSON.stringify(loc)).toMatch(/unexpected media location/);
    }
    expect(gowa.calls.some((c) => c.url.pathname.startsWith('/statics/') || c.url.origin !== gowa.origin)).toBe(false);
    // A URL naming another host only contributes its (allowlisted) path: the read still goes to the bridge origin.
    gowa.downloadLocation = { file_url: `http://evil.example:8080/${good}` };
    const r = await service.downloadMedia(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, messageId: MEDIA_ID });
    expect(r.size).toBe(PNG.length);
    expect(gowa.calls.filter((c) => c.url.pathname.startsWith('/statics/')).map((c) => c.url.origin)).toEqual([gowa.origin]);
  });

  it('falls back to a safe filename and generic mime type', async () => {
    const a = await addPairedAccount('Private', withMedia({ filename: 'we"ird\r\nname.png', mimeType: undefined, fileName: 'photo.png' }));
    const r = await service.downloadMedia(READONLY_PRINCIPAL, { accountId: a.id, chatJid: PERSON, messageId: MEDIA_ID });
    expect(r.filename).toBe('photo.png');
    expect(r.mimeType).toBe('application/octet-stream');
  });
});

describe('multipart body', () => {
  it('uses a random boundary that occurs in no part and round-trips', () => {
    const data = Buffer.from('----PerchFormBoundary inside the data');
    const body = multipartBody([['phone', PERSON]], { name: 'file', filename: 'a.bin', contentType: 'application/octet-stream', data });
    const boundary = /boundary=(.+)$/.exec(body.contentType)![1]!;
    expect(boundary).toMatch(/^----PerchFormBoundary[a-f0-9]{48}$/);
    const parts = parseMultipart(body.contentType, body.data);
    expect(parts.map((p) => p.name)).toEqual(['phone', 'file']);
    expect(parts[1]!.data.equals(data)).toBe(true);
    expect(() => multipartBody([['ph"one', 'x']], { name: 'file', filename: 'a', contentType: 'a/b', data })).toThrow(/multipart/);
    expect(() => multipartBody([], { name: 'file', filename: 'a\r\nb', contentType: 'a/b', data })).toThrow(/multipart/);
  });
});
