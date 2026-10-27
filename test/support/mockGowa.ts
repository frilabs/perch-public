/**
 * MOCK GOWA bridge (in-memory fake of the go-whatsapp-web-multidevice v9 REST routes Perch uses) for
 * tests only. Nothing here talks to WhatsApp or a real bridge; passing tests are NOT evidence of a live
 * integration.
 */
import { PerchError } from '../../src/errors.js';
import type { UpstreamRequest, UpstreamResponse, UpstreamTransport } from '../../src/upstream.js';

export interface MockWaMessage {
  id: string;
  chat_jid: string;
  sender_jid: string;
  sender_display_name?: string;
  content: string;
  timestamp: string;
  is_from_me: boolean;
  media_type?: string | null;
  filename?: string | null;
  url?: string | null;
}

/** One parsed multipart/form-data part (MOCK parser, enough for Perch's own bodies). */
export interface MockFormPart {
  name: string;
  filename?: string;
  contentType?: string;
  data: Buffer;
}

export interface MockMediaSend {
  route: 'image' | 'video' | 'audio' | 'file';
  deviceId: string | undefined;
  /** Field names in order of appearance. */
  fieldNames: string[];
  fields: Record<string, string>;
  file?: MockFormPart;
}

/** Parses multipart/form-data strictly by the boundary from the content type (MOCK). */
export function parseMultipart(contentType: string | undefined, body: Buffer): MockFormPart[] {
  const m = /^multipart\/form-data; boundary=([A-Za-z0-9'()+_,.\/:=?-]{1,70})$/.exec(contentType ?? '');
  if (!m) throw new Error(`MOCK GOWA: not multipart/form-data: ${contentType}`);
  const delim = Buffer.from(`--${m[1]}`);
  const parts: MockFormPart[] = [];
  let pos = body.indexOf(delim);
  if (pos !== 0) throw new Error('MOCK GOWA: body must start with the boundary');
  for (;;) {
    pos += delim.length;
    if (body.subarray(pos, pos + 2).toString() === '--') break;
    if (body.subarray(pos, pos + 2).toString() !== '\r\n') throw new Error('MOCK GOWA: malformed boundary line');
    pos += 2;
    const headerEnd = body.indexOf('\r\n\r\n', pos);
    const head = body.subarray(pos, headerEnd).toString('utf8');
    const next = body.indexOf(Buffer.concat([Buffer.from('\r\n'), delim]), headerEnd + 4);
    if (headerEnd < 0 || next < 0) throw new Error('MOCK GOWA: truncated part');
    const disp = /^Content-Disposition: form-data; name="([^"]+)"(?:; filename="([^"]+)")?$/m.exec(head);
    if (!disp) throw new Error('MOCK GOWA: part without form-data disposition');
    const ct = /^Content-Type: (.+)$/m.exec(head);
    parts.push({ name: disp[1]!, ...(disp[2] ? { filename: disp[2] } : {}), ...(ct ? { contentType: ct[1]! } : {}), data: body.subarray(headerEnd + 4, next) });
    pos = next + 2;
  }
  return parts;
}

export interface MockWaDevice {
  id: string;
  loggedIn: boolean;
  jid?: string;
  displayName?: string;
  chats: Array<{ jid: string; name: string; last_message_time: string; archived?: boolean }>;
  messages: MockWaMessage[];
  /** Media the bridge can "download" per message id: bytes and what /download reports. */
  media?: Record<string, { data: Buffer; filename: string; mimeType?: string; mediaType: string; chatDigits: string; fileName?: string; reportSize?: number }>;
  sent: Array<{ phone: string; message: string; reply_message_id?: string }>;
  /** Status polls until the device reports logged in (simulates the user entering the code). */
  loginAfterPolls?: number;
  polls: number;
}

const json = (status: number, body: unknown): UpstreamResponse => ({
  status,
  headers: { 'content-type': 'application/json' },
  body: Buffer.from(JSON.stringify(body)),
});
const ok = (results: unknown) => json(200, { code: 'SUCCESS', message: 'Success', results });

export class MockGowa {
  readonly calls: UpstreamRequest[] = [];
  readonly devices: MockWaDevice[] = [];
  /** The device GOWA would fall back to when no X-Device-Id header is sent. */
  defaultDeviceId: string | undefined;
  sendMode: { kind: 'ok' } | { kind: 'http'; status: number } | { kind: 'throw' } | { kind: 'no_success' } = { kind: 'ok' };
  /** Inject rows of another chat into message responses (a confused bridge). */
  leakForeignRows = false;
  readonly mediaSent: MockMediaSend[] = [];
  /** Overrides what /message/{id}/download reports as location (hostile bridge tests). */
  downloadLocation: { file_path?: unknown; file_url?: unknown } | undefined;
  /** Files served under /statics (path -> bytes); filled by /download. */
  readonly statics = new Map<string, { data: Buffer; contentType?: string }>();
  private msgCounter = 0;

  constructor(
    readonly origin = 'http://127.0.0.1:3000',
    readonly username = 'perch',
    readonly password = 'DUMMY-TEST-GOWA-PASSWORD',
  ) {}

  addDevice(id: string, opts: Partial<MockWaDevice> = {}): MockWaDevice {
    const d: MockWaDevice = { id, loggedIn: true, chats: [], messages: [], sent: [], polls: 0, ...opts };
    this.devices.push(d);
    return d;
  }

  readonly transport: UpstreamTransport = async (req) => {
    this.calls.push(req);
    if (req.url.origin !== this.origin) throw new Error(`MOCK GOWA: unexpected origin ${req.url.origin}`);
    const expected = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}`;
    if (req.headers.authorization !== expected) return json(401, { code: '401', message: 'Unauthorized access', results: null });
    const path = req.url.pathname;
    const q = req.url.searchParams;
    const deviceHeader = req.headers['x-device-id'];
    const device = (id: string | undefined) => this.devices.find((d) => d.id === (id ?? this.defaultDeviceId));

    if (req.method === 'GET' && path === '/devices') return ok(this.devices.map((d) => ({ id: d.id, state: d.loggedIn ? 'logged_in' : 'disconnected' })));
    if (req.method === 'POST' && path === '/devices') {
      const body = JSON.parse(req.body ?? '{}') as { device_id: string };
      this.addDevice(body.device_id, { loggedIn: false, loginAfterPolls: 2 });
      return ok({ id: body.device_id, state: 'disconnected' });
    }
    let m = /^\/devices\/([^/]+)(\/.*)?$/.exec(path);
    if (m) {
      const d = device(m[1]);
      if (!d) return json(404, { code: '404', message: 'Device not found', results: null });
      const sub = m[2] ?? '';
      if (req.method === 'POST' && sub === '/login/code') return ok({ device_id: d.id, pair_code: 'ABCD-1234' });
      if (req.method === 'GET' && sub === '/status') {
        d.polls++;
        if (!d.loggedIn && d.loginAfterPolls !== undefined && d.polls >= d.loginAfterPolls) {
          d.loggedIn = true;
          d.jid = '4366012345678@s.whatsapp.net';
          d.displayName = 'Dummy Owner';
        }
        return ok({ device_id: d.id, is_connected: d.loggedIn, is_logged_in: d.loggedIn });
      }
      if (req.method === 'GET' && sub === '') return ok({ id: d.id, jid: d.jid, display_name: d.displayName, state: d.loggedIn ? 'logged_in' : 'disconnected' });
      if (req.method === 'DELETE' && sub === '') {
        this.devices.splice(this.devices.indexOf(d), 1);
        return ok(null);
      }
      return json(404, { code: '404', message: 'not found', results: null });
    }

    const d = device(deviceHeader);
    if (!d) return json(400, { code: '400', message: 'device required', results: null });
    if (req.method === 'GET' && path === '/chats') {
      const search = (q.get('search') ?? '').toLowerCase();
      const archived = q.get('archived');
      const all = d.chats.filter((c) => (!search || c.name.toLowerCase().includes(search)) && (archived === null || String(c.archived ?? false) === archived));
      const limit = Number(q.get('limit') ?? 25);
      const offset = Number(q.get('offset') ?? 0);
      return ok({ data: all.slice(offset, offset + limit), pagination: { limit, offset, total: all.length } });
    }
    m = /^\/chat\/([^/]+)\/messages$/.exec(path);
    if (req.method === 'GET' && m) {
      const jid = decodeURIComponent(m[1]!);
      const chat = d.chats.find((c) => c.jid === jid);
      if (!chat) return json(404, { code: '404', message: 'Chat not found', results: null });
      const search = (q.get('search') ?? '').toLowerCase();
      const start = q.get('start_time');
      const end = q.get('end_time');
      let rows = d.messages
        .filter((x) => x.chat_jid === jid)
        .filter((x) => !search || x.content.toLowerCase().includes(search))
        .filter((x) => (!start || x.timestamp >= start) && (!end || x.timestamp <= end))
        .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      if (this.leakForeignRows) rows = [...rows, { ...d.messages.find((x) => x.chat_jid !== jid)! }];
      const limit = Number(q.get('limit') ?? 50);
      const offset = Number(q.get('offset') ?? 0);
      return ok({ data: rows.slice(offset, offset + limit), pagination: { limit, offset, total: rows.length }, chat_info: chat });
    }
    if (req.method === 'POST' && path === '/send/message') {
      if (this.sendMode.kind === 'throw') throw new Error('MOCK: connection reset after send');
      if (this.sendMode.kind === 'http') return json(this.sendMode.status, { code: String(this.sendMode.status), message: 'failed', results: null });
      if (this.sendMode.kind === 'no_success') return json(200, { code: 'PENDING', message: '?', results: {} });
      const body = JSON.parse(req.body ?? '{}') as { phone: string; message: string; reply_message_id?: string };
      d.sent.push(body);
      return ok({ message_id: `3EB0MOCK${String(++this.msgCounter).padStart(8, '0')}`, status: 'Message sent' });
    }
    m = /^\/send\/(image|video|audio|file)$/.exec(path);
    if (req.method === 'POST' && m) {
      if (this.sendMode.kind === 'throw') throw new Error('MOCK: connection reset after send');
      if (this.sendMode.kind === 'http') return json(this.sendMode.status, { code: String(this.sendMode.status), message: 'failed', results: null });
      if (this.sendMode.kind === 'no_success') return json(200, { code: 'PENDING', message: '?', results: {} });
      if (!req.bodyBytes) return json(400, { code: '400', message: 'multipart body required', results: null });
      const parts = parseMultipart(req.headers['content-type'], req.bodyBytes);
      const route = m[1] as MockMediaSend['route'];
      const fields: Record<string, string> = {};
      for (const p of parts) if (p.filename === undefined) fields[p.name] = p.data.toString('utf8');
      const file = parts.find((p) => p.filename !== undefined);
      if (!file || file.name !== route || !fields.phone) return json(400, { code: '400', message: 'file and phone required', results: null });
      this.mediaSent.push({ route, deviceId: deviceHeader, fieldNames: parts.map((p) => p.name), fields, file });
      return ok({ message_id: `3EB0MEDIA${String(++this.msgCounter).padStart(8, '0')}`, status: `Send ${route} success` });
    }
    m = /^\/message\/([^/]+)\/download$/.exec(path);
    if (req.method === 'GET' && m) {
      const media = d.media?.[m[1]!];
      if (!media || !q.get('phone')) return json(404, { code: '404', message: 'Message or media not found', results: null });
      const rel = `statics/media/${media.chatDigits}/2026-10-20/${media.fileName ?? media.filename}`;
      this.statics.set(`/${rel}`, { data: media.data, ...(media.mimeType ? { contentType: media.mimeType } : {}) });
      return ok({
        status: 'Media downloaded successfully',
        message_id: m[1],
        media_type: media.mediaType,
        filename: media.filename,
        ...(this.downloadLocation ?? { file_path: rel, file_url: `http://localhost:3000/${rel}` }),
        file_size: media.reportSize ?? media.data.length,
        ...(media.mimeType ? { mime_type: media.mimeType } : {}),
      });
    }
    if (req.method === 'GET' && path.startsWith('/statics/')) {
      const f = this.statics.get(path);
      if (!f) return json(404, { code: '404', message: 'not found', results: null });
      if (f.data.length > req.maxBytes) throw new PerchError(`Upstream response exceeds the ${req.maxBytes} byte limit`, 'response_too_large'); // as createFetchTransport does
      return { status: 200, headers: { 'content-type': f.contentType ?? 'application/octet-stream' }, body: f.data };
    }
    return json(404, { code: '404', message: 'not found', results: null });
  };
}
