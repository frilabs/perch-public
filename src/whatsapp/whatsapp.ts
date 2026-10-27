import { createHash, randomBytes } from 'node:crypto';
import { actorOf, type AuditLog } from '../audit/audit.js';
import { assertWhatsappCapability, currentPrincipal, type Principal } from '../auth/grants.js';
import { PerchError, safeMessage } from '../errors.js';
import { fanOut, type FanOutResult } from '../fanout.js';
import { newAccountId, validateLabel } from '../ids.js';
import type { SendWorkflow } from '../mail/workflow.js';
import { messageSendStatus, sendMessageIdempotently, type MessageSendResult, type MessageSendView } from '../messaging/send.js';
import type { CredentialStore, WhatsappAccount, WhatsappInstance } from '../store/credentialStore.js';
import { GOWA_DEVICE_ID, UpstreamError, validateGowaOrigin, WHATSAPP_JID, type CallOptions, type HttpMethod, type Upstream } from '../upstream.js';

/**
 * WhatsApp through a self-hosted GOWA bridge (go-whatsapp-web-multidevice, REST API v9; unofficial
 * linked-device protocol). Perch talks to exactly one GOWA instance per namespace, on loopback or a
 * Tailscale address only, with basic auth, and always names the device slot (X-Device-Id) it paired, so
 * a request can never fall back to GOWA's default device.
 *
 * MCP tools only reach the allowlisted read routes and, with a whatsapp_send grant, POST /send/message.
 * Pairing and unlinking (device slot routes) are local CLI operations (capability "admin").
 */

export const DEFAULT_WA_PAGE_SIZE = 50;
export const MAX_WA_PAGE_SIZE = 100;
export const DEFAULT_SEARCH_CHATS = 30;
export const MAX_SEARCH_CHATS = 100;
const SEARCH_HITS_PER_CHAT = 10;
const SEARCH_CONCURRENCY = 5;
export const MAX_WA_TEXT = 65_536;
export const DEFAULT_PAIR_TIMEOUT_MS = 180_000;
const PAIR_POLL_MS = 3_000;
const WA_MESSAGE_ID = /^[A-Za-z0-9]{8,64}$/;
const PROVIDER_ID = /^[A-Za-z0-9_-]{1,128}$/;

type Raw = Record<string, unknown>;

export interface AccountProvenance {
  accountId: string;
  accountLabel: string;
}

const basic = (i: WhatsappInstance) => `Basic ${Buffer.from(`${i.username}:${i.password}`, 'utf8').toString('base64')}`;
const jidPath = (jid: string) => jid.replace('@', '%40');

function jidOf(v: unknown, what = 'chatJid'): string {
  if (typeof v !== 'string' || !WHATSAPP_JID.test(v)) {
    throw new PerchError(`${what} must be a WhatsApp chat id from whatsapp_list_chats (…@s.whatsapp.net, …@lid or …@g.us)`, 'bad_argument');
  }
  return v;
}

function bounded(name: string, value: number | undefined, def: number, max: number): number {
  const n = value ?? def;
  if (!Number.isInteger(n) || n < 1 || n > max) throw new PerchError(`${name} must be between 1 and ${max}`, 'bad_argument');
  return n;
}

function timeOf(v: string | undefined, what: string): string | undefined {
  if (v === undefined) return undefined;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/.test(v) || !Number.isFinite(Date.parse(v))) {
    throw new PerchError(`${what} must be an RFC 3339 timestamp with offset, e.g. 2026-10-05T09:00:00+02:00`, 'bad_argument');
  }
  return new Date(Date.parse(v)).toISOString();
}

const str = (v: unknown, max = 2000) => (typeof v === 'string' && v ? v.slice(0, max) : undefined);

function toChat(c: Raw) {
  const jid = String(c.jid ?? '');
  return {
    chatJid: jid,
    kind: jid.endsWith('@g.us') ? 'group' : 'person',
    ...(str(c.name, 300) ? { name: str(c.name, 300) } : {}),
    ...(str(c.last_message_time, 40) ? { lastMessageTime: str(c.last_message_time, 40) } : {}),
    ...(typeof c.archived === 'boolean' ? { archived: c.archived } : {}),
  };
}

function toMessage(m: Raw) {
  let replyTo: string | undefined;
  if (typeof m.context_metadata === 'string') {
    try {
      const ctx = JSON.parse(m.context_metadata) as Raw;
      if (typeof ctx.replied_to_id === 'string' && WA_MESSAGE_ID.test(ctx.replied_to_id)) replyTo = ctx.replied_to_id;
    } catch {
      // ignore malformed metadata
    }
  }
  return {
    messageId: String(m.id ?? ''),
    ...(str(m.timestamp, 40) ? { time: str(m.timestamp, 40) } : {}),
    ...(str(m.sender_jid, 200) ? { sender: str(m.sender_jid, 200) } : {}),
    ...(str(m.sender_display_name, 300) ? { senderName: str(m.sender_display_name, 300) } : {}),
    fromMe: m.is_from_me === true,
    text: typeof m.content === 'string' ? m.content : '',
    ...(str(m.media_type, 40) ? { mediaType: str(m.media_type, 40) } : {}),
    ...(str(m.filename, 300) ? { filename: str(m.filename, 300) } : {}),
    ...(typeof m.file_length === 'number' ? { fileSize: m.file_length } : {}),
    ...(replyTo ? { replyToMessageId: replyTo } : {}),
  };
}

function results(body: Raw): unknown {
  if (body.code !== 'SUCCESS') throw new PerchError('The WhatsApp bridge reported a failure', 'upstream_error');
  return body.results;
}

async function call(upstream: Upstream, inst: WhatsappInstance, method: HttpMethod, path: string, opts: Partial<CallOptions> & { deviceId?: string } = {}): Promise<Raw> {
  if (opts.deviceId !== undefined && !GOWA_DEVICE_ID.test(opts.deviceId)) throw new PerchError('Invalid device slot', 'bad_argument');
  return upstream.json<Raw>('gowa', {
    ...opts,
    method,
    path,
    origin: inst.origin,
    headers: { authorization: basic(inst), ...(opts.deviceId ? { 'x-device-id': opts.deviceId } : {}) },
  });
}

async function instanceOf(store: CredentialStore): Promise<WhatsappInstance> {
  const inst = (await store.read()).whatsappInstance;
  if (!inst) throw new PerchError('No WhatsApp bridge configured. Run: perch whatsapp instance set --url http://127.0.0.1:3000', 'not_configured');
  return inst;
}

/** Stores the GOWA instance after one authenticated request (GET /devices) succeeded. */
/**
 * Checks a bridge without storing anything: validates the origin (loopback/Tailscale only) and calls
 * GET /devices with basic auth. Returns the probed instance and the number of device slots.
 */
export async function probeWhatsappInstance(upstream: Upstream, input: { url: string; username: string; password: string }): Promise<{ instance: WhatsappInstance; devices: number }> {
  const origin = validateGowaOrigin(input.url);
  const username = input.username.trim();
  if (!username || username.includes(':') || !input.password) throw new PerchError('GOWA username (without ":") and password are required', 'bad_argument');
  const now = new Date().toISOString();
  const instance: WhatsappInstance = { origin, username, password: input.password, createdAt: now, updatedAt: now };
  const list = results(await call(upstream, instance, 'GET', '/devices', { capability: 'admin' }));
  return { instance, devices: Array.isArray(list) ? list.length : 0 };
}

export async function setWhatsappInstance(store: CredentialStore, upstream: Upstream, input: { url: string; username: string; password: string }): Promise<{ origin: string; devices: number }> {
  const { instance, devices } = await probeWhatsappInstance(upstream, input);
  await store.update((data) => {
    data.whatsappInstance = { ...instance, createdAt: data.whatsappInstance?.createdAt ?? instance.createdAt };
  });
  return { origin: instance.origin, devices };
}

export function normalisePhone(raw: string): string {
  const digits = raw.replace(/[\s()./-]/g, '').replace(/^\+/, '').replace(/^00/, '');
  if (!/^[1-9][0-9]{6,19}$/.test(digits)) throw new PerchError('Phone number must be in international format, e.g. +4366012345678', 'bad_argument');
  return digits;
}

/**
 * Pairs a new linked device by pairing code: creates a Perch device slot in GOWA, asks GOWA for the code
 * (shown via onCode; the user enters it in WhatsApp > Linked devices > Link with phone number) and waits
 * until the slot is logged in. On failure or timeout the slot is removed again (best effort).
 */
export async function pairWhatsappAccount(
  store: CredentialStore,
  upstream: Upstream,
  input: { label: string; phone: string; timeoutMs?: number; sleep?: (ms: number) => Promise<void>; onCode: (code: string) => void },
): Promise<WhatsappAccount> {
  const label = validateLabel(input.label);
  const phone = normalisePhone(input.phone);
  const inst = await instanceOf(store);
  const sleep = input.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const deviceId = `perch-${randomBytes(8).toString('hex')}`;
  results(await call(upstream, inst, 'POST', '/devices', { capability: 'admin', json: { device_id: deviceId } }));
  const cleanup = () => call(upstream, inst, 'DELETE', `/devices/${deviceId}`, { capability: 'admin' }).catch(() => undefined);
  try {
    const login = results(await call(upstream, inst, 'POST', `/devices/${deviceId}/login/code`, { capability: 'admin', query: { phone } })) as Raw | undefined;
    const code = typeof login?.pair_code === 'string' && /^[A-Z0-9-]{4,16}$/.test(login.pair_code) ? login.pair_code : undefined;
    if (!code) throw new PerchError('The WhatsApp bridge returned no pairing code', 'upstream_bad_response');
    input.onCode(code);
    const deadline = Date.now() + (input.timeoutMs ?? DEFAULT_PAIR_TIMEOUT_MS);
    for (;;) {
      await sleep(PAIR_POLL_MS);
      // A transient poll failure must not unlink a device the user may just have paired: keep polling.
      const status = (await call(upstream, inst, 'GET', `/devices/${deviceId}/status`, { capability: 'admin' })
        .then(results)
        .catch(() => undefined)) as Raw | undefined;
      if (status?.is_logged_in === true) break;
      if (Date.now() >= deadline) throw new PerchError('Pairing timed out: the code was not entered in time. Nothing was stored; run the command again', 'pairing_timeout');
    }
    const info = (results(await call(upstream, inst, 'GET', `/devices/${deviceId}`, { capability: 'admin' })) ?? {}) as Raw;
    return await store.update((data) => {
      const now = new Date().toISOString();
      const account: WhatsappAccount = {
        id: newAccountId('whatsapp', data.whatsapp.map((a) => a.id)),
        label,
        deviceId,
        ...(str(info.jid, 200) ? { jid: str(info.jid, 200) } : {}),
        ...(str(info.display_name, 200) ? { displayName: str(info.display_name, 200) } : {}),
        createdAt: now,
        updatedAt: now,
      };
      data.whatsapp.push(account);
      return account;
    });
  } catch (err) {
    await cleanup();
    throw err;
  }
}

/**
 * Removes the account locally and (unless keepDevice) deletes its GOWA device slot, which unlinks the
 * device from the phone and clears its stored chats in GOWA. Returns whether the slot was deleted.
 */
export async function removeWhatsappAccount(store: CredentialStore, upstream: Upstream, id: string, opts: { keepDevice?: boolean } = {}): Promise<boolean> {
  const data = await store.read();
  const account = data.whatsapp.find((a) => a.id === id);
  if (!account) throw new PerchError(`Unknown WhatsApp account: ${id}`, 'unknown_account');
  let deleted = false;
  if (!opts.keepDevice && data.whatsappInstance) {
    deleted = await call(upstream, data.whatsappInstance, 'DELETE', `/devices/${account.deviceId}`, { capability: 'admin' }).then(
      () => true,
      () => false,
    );
  }
  await store.update((d) => {
    d.whatsapp = d.whatsapp.filter((a) => a.id !== id);
  });
  return deleted;
}

/** Connection state of each account's device slot (local CLI). */
export async function whatsappDeviceStatus(store: CredentialStore, upstream: Upstream): Promise<Array<{ account: WhatsappAccount; connected?: boolean; loggedIn?: boolean; error?: string }>> {
  const data = await store.read();
  if (!data.whatsapp.length) return [];
  const inst = await instanceOf(store);
  return Promise.all(
    data.whatsapp.map(async (account) => {
      try {
        const s = results(await call(upstream, inst, 'GET', `/devices/${account.deviceId}/status`, { capability: 'admin' })) as Raw | undefined;
        return { account, connected: s?.is_connected === true, loggedIn: s?.is_logged_in === true };
      } catch (err) {
        return { account, error: safeMessage(err) };
      }
    }),
  );
}

export type WhatsappMediaKind = 'image' | 'video' | 'audio' | 'file';
export const WHATSAPP_MEDIA_KINDS: readonly WhatsappMediaKind[] = ['image', 'video', 'audio', 'file'];
/** Largest media file Perch sends or downloads (decoded bytes). */
export const MAX_WA_MEDIA_BYTES = 16 * 1024 * 1024;
export const DEFAULT_WA_DOWNLOAD_BYTES = 48 * 1024;
/** Longest base64 text that can decode to MAX_WA_MEDIA_BYTES. */
export const MAX_WA_MEDIA_BASE64 = Math.ceil(MAX_WA_MEDIA_BYTES / 3) * 4;
export const MAX_WA_CAPTION = 4096;
const MEDIA_FILENAME = /^[A-Za-z0-9_][A-Za-z0-9 ._()+-]{0,199}$/;
const MIME_TYPE = /^[a-z]{1,30}\/[a-z0-9][a-z0-9.+-]{0,100}$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
/**
 * Files the bridge saved for a download: statics/media/<chat digits>/<YYYY-MM-DD>/<file name>. Nothing else
 * under the bridge's web root is ever read.
 */
const STATIC_MEDIA_PATH = /^\/statics\/media\/[0-9]{5,20}(?:-[0-9]{5,20})?\/[0-9]{4}-[0-9]{2}-[0-9]{2}\/[A-Za-z0-9_-][A-Za-z0-9._-]{0,199}$/;

export interface WhatsappMediaSendRequest {
  accountId: string;
  chatJid: string;
  kind: WhatsappMediaKind;
  filename: string;
  contentBase64: string;
  mimeType?: string;
  caption?: string;
  replyToMessageId?: string;
  requestId: string;
}

interface PreparedMedia {
  jid: string;
  kind: WhatsappMediaKind;
  filename: string;
  mimeType: string;
  caption?: string;
  replyToMessageId?: string;
  data: Buffer;
}

const DEFAULT_MIME: Record<WhatsappMediaKind, string> = { image: 'image/jpeg', video: 'video/mp4', audio: 'audio/mpeg', file: 'application/octet-stream' };

/** Local validation of a media send, before any I/O (size limit enforced on the base64 text before decoding). */
function prepareMedia(req: WhatsappMediaSendRequest): PreparedMedia {
  const jid = jidOf(req.chatJid);
  if (!WHATSAPP_MEDIA_KINDS.includes(req.kind)) throw new PerchError('kind must be image, video, audio or file', 'bad_argument');
  if (typeof req.filename !== 'string' || !MEDIA_FILENAME.test(req.filename)) {
    throw new PerchError('filename must be 1-200 characters of A-Z a-z 0-9 space . _ ( ) + - and must not start with a dot or space', 'bad_argument');
  }
  let mimeType = DEFAULT_MIME[req.kind];
  if (req.mimeType !== undefined) {
    if (typeof req.mimeType !== 'string' || !MIME_TYPE.test(req.mimeType)) throw new PerchError('mimeType must be a lowercase type/subtype such as image/png', 'bad_argument');
    mimeType = req.mimeType;
  }
  if (req.kind !== 'file' && !mimeType.startsWith(`${req.kind}/`)) throw new PerchError(`mimeType must be ${req.kind}/… for kind ${req.kind} (use kind "file" for other files)`, 'bad_argument');
  if (req.caption !== undefined) {
    if (req.kind === 'audio') throw new PerchError('WhatsApp audio messages have no caption', 'bad_argument');
    if (typeof req.caption !== 'string' || req.caption.length > MAX_WA_CAPTION) throw new PerchError(`caption must be at most ${MAX_WA_CAPTION} characters`, 'bad_argument');
  }
  if (req.replyToMessageId !== undefined && (typeof req.replyToMessageId !== 'string' || !WA_MESSAGE_ID.test(req.replyToMessageId))) {
    throw new PerchError('replyToMessageId must be a messageId from whatsapp_get_messages', 'bad_argument');
  }
  const b64 = req.contentBase64;
  if (typeof b64 !== 'string' || !b64) throw new PerchError('contentBase64 is required', 'bad_argument');
  if (b64.length > MAX_WA_MEDIA_BASE64) throw new PerchError(`The file exceeds ${MAX_WA_MEDIA_BYTES} bytes`, 'bad_argument');
  if (b64.length % 4 !== 0 || !BASE64.test(b64)) throw new PerchError('contentBase64 must be standard base64 (A-Z a-z 0-9 + /, padded)', 'bad_argument');
  const data = Buffer.from(b64, 'base64');
  if (data.length === 0) throw new PerchError('The file is empty', 'bad_argument');
  if (data.length > MAX_WA_MEDIA_BYTES) throw new PerchError(`The file exceeds ${MAX_WA_MEDIA_BYTES} bytes`, 'bad_argument');
  return {
    jid,
    kind: req.kind,
    filename: req.filename,
    mimeType,
    ...(req.caption ? { caption: req.caption } : {}),
    ...(req.replyToMessageId ? { replyToMessageId: req.replyToMessageId } : {}),
    data,
  };
}

/**
 * multipart/form-data body (RFC 7578) with text fields and one file part. The boundary is random and
 * re-drawn until it occurs in no part; names, filename and content type are validated by the caller (no
 * quotes, CR or LF can reach a header).
 */
export function multipartBody(fields: ReadonlyArray<readonly [string, string]>, file: { name: string; filename: string; contentType: string; data: Buffer }): { contentType: string; data: Buffer } {
  const headerSafe = /^[A-Za-z0-9 ._()+\/-]+$/;
  for (const v of [file.name, file.filename, file.contentType, ...fields.map(([n]) => n)]) {
    if (!headerSafe.test(v)) throw new PerchError('Invalid multipart header value', 'bad_argument');
  }
  let boundary: string;
  do boundary = `----PerchFormBoundary${randomBytes(24).toString('hex')}`;
  while (file.data.includes(boundary) || fields.some(([, v]) => v.includes(boundary)));
  const parts: Buffer[] = [];
  for (const [name, value] of fields) {
    parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`, 'utf8'));
  }
  parts.push(
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${file.name}"; filename="${file.filename}"\r\nContent-Type: ${file.contentType}\r\n\r\n`, 'utf8'),
    file.data,
    Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8'),
  );
  return { contentType: `multipart/form-data; boundary=${boundary}`, data: Buffer.concat(parts) };
}

/**
 * The path of a downloaded file on the bridge, from file_path (relative to its working directory) or the
 * path part of file_url. Only /statics/media/<chat>/<date>/<file> is accepted; the host of file_url is never
 * used (Perch reads from the configured bridge origin only), and both must agree when both are present.
 */
function staticMediaPath(r: Raw): string {
  const bad = () => new PerchError('The WhatsApp bridge returned an unexpected media location; refusing to read it', 'upstream_bad_response');
  const candidates: string[] = [];
  if (r.file_path !== undefined) {
    if (typeof r.file_path !== 'string') throw bad();
    candidates.push(`/${r.file_path.replace(/^\.\//, '')}`);
  }
  if (r.file_url !== undefined && r.file_url !== '') {
    if (typeof r.file_url !== 'string') throw bad();
    let url: URL;
    try {
      url = new URL(r.file_url);
    } catch {
      throw bad();
    }
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash) throw bad();
    candidates.push(url.pathname);
  }
  if (!candidates.length || candidates.some((c) => !STATIC_MEDIA_PATH.test(c) || c !== candidates[0])) throw bad();
  return candidates[0]!;
}

function safeFilename(v: unknown): string | undefined {
  return typeof v === 'string' && MEDIA_FILENAME.test(v) ? v : undefined;
}

function mimeOf(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const t = v.trim().toLowerCase();
  return MIME_TYPE.test(t) ? t : undefined;
}

const bindingParts = (a: WhatsappAccount, inst: WhatsappInstance) => ['whatsapp', a.id, a.deviceId, a.jid ?? '', inst.origin];

export interface WhatsappSendRequest {
  accountId: string;
  chatJid: string;
  text: string;
  replyToMessageId?: string;
  requestId: string;
}

export class WhatsappService {
  private readonly guard?: () => Promise<void>;

  constructor(
    private readonly store: CredentialStore,
    private readonly upstream: Upstream,
    private readonly workflow: SendWorkflow,
    private readonly audit: AuditLog,
    opts: { guard?: () => Promise<void> } = {},
  ) {
    this.guard = opts.guard;
  }

  private async account(id: unknown): Promise<{ account: WhatsappAccount; inst: WhatsappInstance }> {
    const data = await this.store.read();
    const account = typeof id === 'string' ? data.whatsapp.find((a) => a.id === id) : undefined;
    if (!account) throw new PerchError(`Unknown WhatsApp account: ${String(id)}`, 'unknown_account');
    if (!data.whatsappInstance) throw new PerchError('No WhatsApp bridge configured', 'not_configured');
    return { account, inst: data.whatsappInstance };
  }

  private async readable(p: Principal, id: unknown) {
    if (typeof id !== 'string') throw new PerchError('accountId is required', 'bad_argument');
    assertWhatsappCapability(p, id, 'whatsapp_read');
    return this.account(id);
  }

  private async readableAll(p: Principal, id: string | undefined): Promise<Array<{ account: WhatsappAccount; inst: WhatsappInstance }>> {
    if (id !== undefined) return [await this.readable(p, id)];
    if (!p.capabilities.has('whatsapp_read')) throw new PerchError('Capability "whatsapp_read" is not granted to this client', 'capability_denied');
    const data = await this.store.read();
    const accounts = data.whatsapp.filter((a) => p.whatsappAccounts === 'all' || p.whatsappAccounts.has(a.id));
    if (accounts.length && !data.whatsappInstance) throw new PerchError('No WhatsApp bridge configured', 'not_configured');
    return accounts.map((account) => ({ account, inst: data.whatsappInstance! }));
  }

  private prov(a: WhatsappAccount): AccountProvenance {
    return { accountId: a.id, accountLabel: a.label };
  }

  private async chatsPage(account: WhatsappAccount, inst: WhatsappInstance, q: { query?: string; archived?: boolean; limit: number; offset: number }) {
    const r = results(
      await call(this.upstream, inst, 'GET', '/chats', {
        deviceId: account.deviceId,
        query: { limit: q.limit, offset: q.offset, search: q.query || undefined, archived: q.archived },
      }),
    ) as { data?: Raw[]; pagination?: { total?: number } } | undefined;
    const chats = (r?.data ?? []).filter((c) => typeof c.jid === 'string' && WHATSAPP_JID.test(c.jid)).map(toChat);
    const total = typeof r?.pagination?.total === 'number' ? r.pagination.total : 0;
    return { chats, next: q.offset + q.limit < total && (r?.data?.length ?? 0) > 0 ? q.offset + q.limit : null };
  }

  /** Chats (people and groups) stored by the bridge, optionally filtered by name, across accounts. */
  async listChats(p: Principal, input: { accountId?: string; query?: string; archived?: boolean; pageSize?: number; cursor?: string }): Promise<FanOutResult<Raw>> {
    const pageSize = bounded('pageSize', input.pageSize, DEFAULT_WA_PAGE_SIZE, MAX_WA_PAGE_SIZE);
    const query = input.query?.trim().slice(0, 200);
    const targets = await this.readableAll(p, input.accountId);
    return fanOut<Raw>({
      kind: 'whatsapp-chats',
      queryKey: { a: input.accountId ?? null, q: query ?? null, ar: input.archived ?? null, pageSize },
      sources: targets.map((t) => t.account),
      seal: this.store,
      cursor: input.cursor,
      fetchPage: async (source, start) => {
        const t = targets.find((x) => x.account.id === source.id)!;
        const offset = start ? Number(start) : 0;
        if (!Number.isInteger(offset) || offset < 0) throw new PerchError('Invalid cursor', 'bad_cursor');
        const page = await this.chatsPage(t.account, t.inst, { query, archived: input.archived, limit: pageSize, offset });
        return { items: page.chats, next: page.next === null ? null : String(page.next) };
      },
    });
  }

  private async messagesPage(
    account: WhatsappAccount,
    inst: WhatsappInstance,
    jid: string,
    q: { query?: string; after?: string; before?: string; fromMe?: boolean; mediaOnly?: boolean; limit: number; offset: number },
  ) {
    const r = results(
      await call(this.upstream, inst, 'GET', `/chat/${jidPath(jid)}/messages`, {
        deviceId: account.deviceId,
        query: {
          limit: q.limit,
          offset: q.offset,
          search: q.query || undefined,
          start_time: q.after,
          end_time: q.before,
          is_from_me: q.fromMe,
          media_only: q.mediaOnly,
        },
      }),
    ) as { data?: Raw[]; pagination?: { total?: number }; chat_info?: Raw } | undefined;
    // Rows of another chat (a bridge bug or a confused route) are dropped, never shown under this chat.
    const messages = (r?.data ?? []).filter((m) => m.chat_jid === undefined || m.chat_jid === jid).map(toMessage);
    const total = typeof r?.pagination?.total === 'number' ? r.pagination.total : 0;
    return {
      messages,
      chatName: str(r?.chat_info?.name, 300),
      next: q.offset + q.limit < total && (r?.data?.length ?? 0) > 0 ? q.offset + q.limit : null,
    };
  }

  /** Messages of one chat as stored by the bridge, with optional text search and time window. */
  async getMessages(
    p: Principal,
    input: { accountId: string; chatJid: string; query?: string; after?: string; before?: string; fromMe?: boolean; mediaOnly?: boolean; pageSize?: number; cursor?: string },
  ) {
    const { account, inst } = await this.readable(p, input.accountId);
    const jid = jidOf(input.chatJid);
    const pageSize = bounded('pageSize', input.pageSize, DEFAULT_WA_PAGE_SIZE, MAX_WA_PAGE_SIZE);
    const after = timeOf(input.after, 'after');
    const before = timeOf(input.before, 'before');
    const query = input.query?.trim().slice(0, 200);
    const kind = `whatsapp-messages:${account.id}:${jid}:${JSON.stringify([query ?? null, after ?? null, before ?? null, input.fromMe ?? null, input.mediaOnly ?? null, pageSize])}`;
    const offset = input.cursor ? Number(this.store.openCursor(kind, input.cursor)) : 0;
    if (!Number.isInteger(offset) || offset < 0) throw new PerchError('Invalid cursor', 'bad_cursor');
    const page = await this.messagesPage(account, inst, jid, { query, after, before, fromMe: input.fromMe, mediaOnly: input.mediaOnly, limit: pageSize, offset });
    return {
      ...this.prov(account),
      chatJid: jid,
      ...(page.chatName ? { chatName: page.chatName } : {}),
      messages: page.messages,
      nextCursor: page.next === null ? null : this.store.sealCursor(kind, String(page.next)),
      hasMore: page.next !== null,
    };
  }

  /**
   * Text search over the most recently active chats (the bridge has no global message search): lists up to
   * chatLimit chats per account, newest activity first, and searches each of them.
   */
  async search(p: Principal, input: { query: string; accountId?: string; chatLimit?: number }) {
    const query = input.query?.trim().slice(0, 200);
    if (!query) throw new PerchError('query is required', 'bad_argument');
    const chatLimit = bounded('chatLimit', input.chatLimit, DEFAULT_SEARCH_CHATS, MAX_SEARCH_CHATS);
    const targets = await this.readableAll(p, input.accountId);
    const hits: Raw[] = [];
    const errors: Array<{ accountId: string; accountLabel: string; message: string }> = [];
    let chatsSearched = 0;
    for (const { account, inst } of targets) {
      try {
        const chats: Array<ReturnType<typeof toChat>> = [];
        let offset: number | null = 0;
        while (offset !== null && chats.length < MAX_SEARCH_CHATS * 3) {
          const page = await this.chatsPage(account, inst, { limit: MAX_WA_PAGE_SIZE, offset });
          chats.push(...page.chats);
          offset = page.next;
        }
        const recent = chats.sort((a, b) => String(b.lastMessageTime ?? '').localeCompare(String(a.lastMessageTime ?? ''))).slice(0, chatLimit);
        for (let i = 0; i < recent.length; i += SEARCH_CONCURRENCY) {
          await Promise.all(
            recent.slice(i, i + SEARCH_CONCURRENCY).map(async (chat) => {
              try {
                const page = await this.messagesPage(account, inst, chat.chatJid, { query, limit: SEARCH_HITS_PER_CHAT, offset: 0 });
                chatsSearched++;
                for (const m of page.messages) hits.push({ ...m, chatJid: chat.chatJid, ...(chat.name ? { chatName: chat.name } : {}), ...this.prov(account) });
              } catch (err) {
                errors.push({ ...this.prov(account), message: `${chat.chatJid}: ${safeMessage(err)}` });
              }
            }),
          );
        }
      } catch (err) {
        errors.push({ ...this.prov(account), message: safeMessage(err) });
      }
    }
    hits.sort((a, b) => String(b.time ?? '').localeCompare(String(a.time ?? '')));
    return {
      results: hits,
      chatsSearched,
      partial: errors.length > 0,
      errors,
      note:
        `Searched the ${chatLimit} most recently active chats per account (up to ${SEARCH_HITS_PER_CHAT} hits each), not all chats. ` +
        'The bridge only holds messages since pairing plus what the phone synced. Use whatsapp_get_messages with query for one chat.',
    };
  }

  private async stillAllowed(stale: Principal, accountId: string): Promise<void> {
    await this.guard?.();
    assertWhatsappCapability(await currentPrincipal(this.store, stale), accountId, 'whatsapp_send');
  }

  /** Sends a text message from the explicitly chosen account (idempotent per requestId). */
  async send(p: Principal, req: WhatsappSendRequest): Promise<MessageSendView & AccountProvenance & { chatJid?: string; messageId?: string }> {
    let account: WhatsappAccount | undefined;
    let jid = '';
    const view = await sendMessageIdempotently({
      workflow: this.workflow,
      audit: this.audit,
      actor: actorOf(p),
      provider: 'whatsapp',
      accountId: req?.accountId,
      prepare: async () => {
        await this.guard?.();
        if (typeof req?.accountId !== 'string') throw new PerchError('accountId is required', 'bad_argument');
        assertWhatsappCapability(p, req.accountId, 'whatsapp_send');
        const found = await this.account(req.accountId);
        account = found.account;
        jid = jidOf(req.chatJid);
        if (typeof req.text !== 'string' || !req.text.trim()) throw new PerchError('text must not be empty', 'bad_argument');
        if (req.text.length > MAX_WA_TEXT) throw new PerchError(`text exceeds ${MAX_WA_TEXT} characters`, 'bad_argument');
        if (req.replyToMessageId !== undefined && (typeof req.replyToMessageId !== 'string' || !WA_MESSAGE_ID.test(req.replyToMessageId))) {
          throw new PerchError('replyToMessageId must be a messageId from whatsapp_get_messages', 'bad_argument');
        }
        const canonical = JSON.stringify(['perch-whatsapp-send-v1', account.id, jid, req.text, req.replyToMessageId ?? null]);
        return { accountId: account.id, requestId: req.requestId, canonical, binding: bindingParts(account, found.inst) };
      },
      attempt: (binding) => this.attempt(p, req, jid, binding),
    });
    const { providerMessageId, ...rest } = view;
    return { ...this.prov(account!), ...rest, chatJid: jid, ...(providerMessageId ? { messageId: providerMessageId } : {}) };
  }

  private async attempt(p: Principal, req: WhatsappSendRequest, jid: string, binding: string): Promise<MessageSendResult> {
    return this.submit(p, req.accountId, binding, (current) =>
      call(this.upstream, current.inst, 'POST', '/send/message', {
        capability: 'whatsapp_send',
        deviceId: current.account.deviceId,
        json: { phone: jid, message: req.text, ...(req.replyToMessageId ? { reply_message_id: req.replyToMessageId } : {}) },
      }),
    );
  }

  /**
   * The single provider attempt of a send: re-checks the grant and the account binding immediately before
   * submitting, then maps the bridge's answer (4xx rejected; 5xx, transport errors and answers without
   * SUCCESS or with a schedule id indeterminate).
   */
  private async submit(
    p: Principal,
    accountId: string,
    binding: string,
    post: (current: { account: WhatsappAccount; inst: WhatsappInstance }) => Promise<Raw>,
  ): Promise<MessageSendResult> {
    const notSent = (detail: string, reason: MessageSendResult['reason']): MessageSendResult => ({ status: 'rejected', detail: `Not sent: ${detail}`, reason });
    try {
      await this.stillAllowed(p, accountId);
    } catch (err) {
      return notSent(err instanceof PerchError ? err.message : 'the request is no longer authorised', 'not_submitted_authorization');
    }
    const current = await this.account(accountId).catch(() => undefined);
    if (!current || (await this.workflow.binding(bindingParts(current.account, current.inst))) !== binding) {
      return notSent('the account or bridge changed since this requestId was first used', 'not_submitted_account_changed');
    }
    let body: Raw;
    try {
      body = await post(current);
    } catch (err) {
      if (err instanceof UpstreamError && err.status < 500) return notSent(`the bridge refused the request (HTTP ${err.status})`, 'provider_rejected');
      if (err instanceof PerchError && (err.code === 'route_not_allowed' || err.code === 'bad_argument')) return notSent(err.message, 'not_submitted_provider_precheck');
      return { status: 'indeterminate', detail: 'The request to the WhatsApp bridge failed after it may have been sent; the outcome is unknown.', reason: 'provider_unknown' };
    }
    const r = (body.results ?? {}) as Raw;
    if (body.code !== 'SUCCESS' || typeof r.schedule_id === 'string') {
      return { status: 'indeterminate', detail: 'The bridge answered without confirming the send; the outcome is unknown.', reason: 'provider_unknown' };
    }
    const id = typeof r.message_id === 'string' && PROVIDER_ID.test(r.message_id) ? r.message_id : undefined;
    return { status: 'accepted', detail: 'Sent to WhatsApp.', ...(id ? { providerMessageId: id } : {}), reason: 'provider_accepted' };
  }

  /**
   * Sends one media file (image, video, audio or document) from the explicitly chosen account, idempotent
   * per requestId. Perch builds the multipart body itself with the file bytes; URL-based media fields,
   * scheduling, view-once and forwarding flags are never sent.
   */
  async sendMedia(p: Principal, req: WhatsappMediaSendRequest): Promise<MessageSendView & AccountProvenance & { chatJid?: string; kind?: WhatsappMediaKind; messageId?: string }> {
    let account: WhatsappAccount | undefined;
    let media: PreparedMedia | undefined;
    const view = await sendMessageIdempotently({
      workflow: this.workflow,
      audit: this.audit,
      actor: actorOf(p),
      provider: 'whatsapp',
      accountId: req?.accountId,
      prepare: async () => {
        await this.guard?.();
        if (typeof req?.accountId !== 'string') throw new PerchError('accountId is required', 'bad_argument');
        assertWhatsappCapability(p, req.accountId, 'whatsapp_send');
        const found = await this.account(req.accountId);
        account = found.account;
        media = prepareMedia(req);
        const canonical = JSON.stringify([
          'perch-whatsapp-media-v1',
          account.id,
          media.jid,
          media.kind,
          media.filename,
          media.mimeType,
          media.caption ?? null,
          media.replyToMessageId ?? null,
          createHash('sha256').update(media.data).digest('hex'),
        ]);
        return { accountId: account.id, requestId: req.requestId, canonical, binding: bindingParts(account, found.inst) };
      },
      attempt: (binding) =>
        this.submit(p, req.accountId, binding, (current) => {
          const m = media!;
          const fields: Array<[string, string]> = [['phone', m.jid]];
          if (m.caption !== undefined) fields.push(['caption', m.caption]);
          if (m.replyToMessageId !== undefined) fields.push(['reply_message_id', m.replyToMessageId]);
          const body = multipartBody(fields, { name: m.kind, filename: m.filename, contentType: m.mimeType, data: m.data });
          return call(this.upstream, current.inst, 'POST', `/send/${m.kind}`, { capability: 'whatsapp_send', deviceId: current.account.deviceId, bytes: body });
        }),
    });
    const { providerMessageId, ...rest } = view;
    return {
      ...this.prov(account!),
      ...rest,
      ...(media ? { chatJid: media.jid, kind: media.kind } : {}),
      ...(providerMessageId ? { messageId: providerMessageId } : {}),
    };
  }

  /**
   * Downloads the media of one message: asks the bridge to save it (GET /message/{id}/download), then reads
   * the saved file from the SAME validated bridge origin under /statics/media/… only. Refuses (never
   * truncates) media larger than maxBytes.
   */
  async downloadMedia(p: Principal, input: { accountId: string; chatJid: string; messageId: string; maxBytes?: number }) {
    const { account, inst } = await this.readable(p, input?.accountId);
    const jid = jidOf(input.chatJid);
    if (typeof input.messageId !== 'string' || !WA_MESSAGE_ID.test(input.messageId)) {
      throw new PerchError('messageId must be a messageId from whatsapp_get_messages', 'bad_argument');
    }
    const maxBytes = bounded('maxBytes', input.maxBytes, DEFAULT_WA_DOWNLOAD_BYTES, MAX_WA_MEDIA_BYTES);
    const r = results(await call(this.upstream, inst, 'GET', `/message/${input.messageId}/download`, { deviceId: account.deviceId, query: { phone: jid } })) as Raw | undefined;
    if (!r || typeof r !== 'object') throw new PerchError('The WhatsApp bridge returned no media for this message', 'upstream_bad_response');
    if (r.message_id !== undefined && r.message_id !== input.messageId) throw new PerchError('The WhatsApp bridge returned media of another message', 'upstream_bad_response');
    const path = staticMediaPath(r);
    const tooLarge = (size: number | string) =>
      new PerchError(`The media is larger than maxBytes (${size} > ${maxBytes} bytes); nothing was returned. Retry with a higher maxBytes (up to ${MAX_WA_MEDIA_BYTES})`, 'response_too_large');
    if (typeof r.file_size === 'number' && r.file_size > maxBytes) throw tooLarge(r.file_size);
    let res;
    try {
      res = await this.upstream.raw('gowa', {
        method: 'GET',
        path,
        origin: inst.origin,
        maxBytes,
        headers: { authorization: basic(inst), 'x-device-id': account.deviceId, accept: '*/*' },
      });
    } catch (err) {
      if (err instanceof PerchError && err.code === 'response_too_large') throw tooLarge('more');
      throw err;
    }
    const filename = safeFilename(r.filename) ?? path.slice(path.lastIndexOf('/') + 1);
    const mimeType = mimeOf(r.mime_type) ?? mimeOf(res.headers['content-type']?.split(';')[0]) ?? 'application/octet-stream';
    return {
      ...this.prov(account),
      chatJid: jid,
      messageId: input.messageId,
      ...(str(r.media_type, 40) ? { mediaType: str(r.media_type, 40) } : {}),
      filename,
      mimeType,
      size: res.body.length,
      contentBase64: res.body.toString('base64'),
    };
  }

  async sendStatus(p: Principal, input: { accountId: string; requestId: string }) {
    if (typeof input?.accountId !== 'string') throw new PerchError('accountId is required', 'bad_argument');
    assertWhatsappCapability(p, input.accountId, 'whatsapp_send');
    const { account, inst } = await this.account(input.accountId);
    const { providerMessageId, ...rest } = await messageSendStatus(this.workflow, actorOf(p), account.id, input.requestId, bindingParts(account, inst));
    return { ...this.prov(account), ...rest, ...(providerMessageId ? { messageId: providerMessageId } : {}) };
  }

  async listAccounts(p: Principal) {
    const data = await this.store.read();
    return data.whatsapp
      .filter((a) => p.whatsappAccounts === 'all' || p.whatsappAccounts.has(a.id))
      .map((a) => ({
        accountId: a.id,
        label: a.label,
        ...(a.jid ? { jid: a.jid } : {}),
        ...(a.displayName ? { displayName: a.displayName } : {}),
        granted: [...p.capabilities].filter((c) => c.startsWith('whatsapp_')).sort(),
        connectedAt: a.createdAt,
      }));
  }
}
