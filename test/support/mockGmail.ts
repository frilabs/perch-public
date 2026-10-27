/**
 * MOCK Gmail upstream (Google OAuth token endpoint + Gmail API v1 subset) for tests only.
 * This is an in-memory fake of the HTTP API; nothing here talks to Google, and passing
 * tests that use it are NOT evidence of a live integration.
 */
import { randomBytes } from 'node:crypto';
import { PerchError } from '../../src/errors.js';
import type { UpstreamRequest, UpstreamResponse, UpstreamTransport } from '../../src/upstream.js';
import { dummySecret } from './fixtures.js';

export interface MockPart {
  partId: string;
  mimeType: string;
  filename?: string;
  headers?: Array<{ name: string; value: string }>;
  /** Decoded body content (leaf parts). */
  content?: Buffer;
  /** Serve the body via the attachments endpoint even if small (Gmail does this for big text parts too). */
  asAttachment?: boolean;
  parts?: MockPart[];
}

export interface MockMessage {
  id: string;
  threadId: string;
  internalDate: number;
  snippet: string;
  labelIds?: string[];
  payload: MockPart;
}

export interface MockGmailAccount {
  email: string;
  refreshToken: string;
  messages: MockMessage[];
  drafts: Array<{ id: string; raw: string; threadId?: string }>;
  sent: Array<{ raw: string; threadId?: string }>;
  /** Labels (labels.list); system labels are added by addAccount. */
  labels: Array<{ id: string; name: string; type: 'system' | 'user' }>;
  /** Drafts sent with drafts.send (draft id, raw). */
  sentDrafts: Array<{ id: string; raw: string }>;
}

export interface MockGmailOptions {
  grantedScope?: string;
  /** Refresh token returned by refresh_token grants (undefined = omit, Google's usual behaviour). */
  rotateRefreshTokenTo?: string;
  pageSize?: number;
}

/** How the next messages.send call behaves. */
export type SendBehaviour = { status: number; body?: unknown } | 'timeout' | 'unreachable';

const json = (status: number, body: unknown): UpstreamResponse => ({
  status,
  headers: { 'content-type': 'application/json' },
  body: Buffer.from(JSON.stringify(body)),
});

/** Builds a Gmail-style payload from a compact description (partIds assigned like Gmail: "", "0", "0.1"...). */
export function mime(
  mimeType: string,
  opts: { headers?: Record<string, string>; content?: string | Buffer; filename?: string; inline?: boolean; asAttachment?: boolean; parts?: MockPart[] } = {},
): MockPart {
  const headers = Object.entries(opts.headers ?? {}).map(([name, value]) => ({ name, value }));
  if (opts.filename) {
    headers.push({ name: 'Content-Disposition', value: `${opts.inline ? 'inline' : 'attachment'}; filename="${opts.filename}"` });
  }
  return {
    partId: '',
    mimeType,
    ...(opts.filename ? { filename: opts.filename } : {}),
    headers,
    ...(opts.content !== undefined ? { content: Buffer.isBuffer(opts.content) ? opts.content : Buffer.from(opts.content) } : {}),
    ...(opts.asAttachment ? { asAttachment: true } : {}),
    ...(opts.parts ? { parts: opts.parts } : {}),
  };
}

function assignPartIds(part: MockPart, id: string): void {
  part.partId = id;
  part.parts?.forEach((p, i) => assignPartIds(p, id === '' ? String(i) : `${id}.${i}`));
}

export class MockGmail {
  readonly calls: UpstreamRequest[] = [];
  readonly accounts: MockGmailAccount[] = [];
  readonly accessTokens = new Map<string, MockGmailAccount>();
  readonly revoked: string[] = [];
  /** Volatile attachment ids: re-issued on every messages.get, like Gmail's. */
  readonly attachmentIds = new Map<string, Buffer>();
  tokenCalls = 0;
  sendBehaviour: SendBehaviour = { status: 200 };

  constructor(public opts: MockGmailOptions = {}) {}

  addAccount(email: string, messages: MockMessage[] = []): MockGmailAccount {
    for (const m of messages) assignPartIds(m.payload, '');
    const labels = ['INBOX', 'SENT', 'DRAFT', 'TRASH', 'SPAM', 'STARRED', 'UNREAD', 'IMPORTANT'].map((id) => ({ id, name: id, type: 'system' as const }));
    const acct: MockGmailAccount = { email, refreshToken: dummySecret('GMAIL-REFRESH'), messages, drafts: [], sent: [], labels, sentDrafts: [] };
    this.accounts.push(acct);
    return acct;
  }

  issueAccessToken(account: MockGmailAccount): string {
    const t = dummySecret('GMAIL-ACCESS');
    this.accessTokens.set(t, account);
    return t;
  }

  /** Calls that reached the Gmail origin (excludes the OAuth token endpoint). */
  gmailCalls(): UpstreamRequest[] {
    return this.calls.filter((c) => c.url.origin === 'https://gmail.googleapis.com');
  }

  transport: UpstreamTransport = async (req) => {
    this.calls.push(req);
    const { origin, pathname } = req.url;
    if (origin === 'https://oauth2.googleapis.com') return this.oauth(req, pathname);
    if (origin === 'https://gmail.googleapis.com') return this.gmail(req, pathname);
    return json(404, { error: 'not_found' });
  };

  private oauth(req: UpstreamRequest, pathname: string): UpstreamResponse {
    const form = new URLSearchParams(req.body ?? '');
    if (pathname === '/revoke') {
      this.revoked.push(form.get('token') ?? '');
      return json(200, {});
    }
    this.tokenCalls++;
    if (form.get('grant_type') !== 'refresh_token') return json(400, { error: 'unsupported_grant_type' });
    const acct = this.accounts.find((a) => a.refreshToken === form.get('refresh_token'));
    if (!acct) return json(400, { error: 'invalid_grant' });
    if (this.opts.rotateRefreshTokenTo) acct.refreshToken = this.opts.rotateRefreshTokenTo;
    return json(200, {
      access_token: this.issueAccessToken(acct),
      expires_in: 3599,
      scope: this.opts.grantedScope ?? 'https://www.googleapis.com/auth/gmail.readonly',
      token_type: 'Bearer',
      ...(this.opts.rotateRefreshTokenTo ? { refresh_token: this.opts.rotateRefreshTokenTo } : {}),
    });
  }

  private gmail(req: UpstreamRequest, pathname: string): UpstreamResponse {
    const acct = this.accessTokens.get((req.headers.authorization ?? '').replace(/^Bearer /, ''));
    if (!acct) return json(401, { error: { code: 401, status: 'UNAUTHENTICATED', message: 'mock' } });
    const q = req.url.searchParams;
    const base = '/gmail/v1/users/me';
    if (pathname === `${base}/profile`) return json(200, { emailAddress: acct.email, messagesTotal: acct.messages.length });
    if (req.method === 'POST' && pathname === `${base}/drafts`) {
      const body = JSON.parse(req.body ?? '{}') as { message: { raw: string; threadId?: string } };
      const id = `r${randomBytes(4).toString('hex')}`;
      acct.drafts.push({ id, ...body.message });
      return json(200, { id, message: { id: `m${id}`, threadId: body.message.threadId ?? `t${id}`, labelIds: ['DRAFT'] } });
    }
    if (req.method === 'GET' && pathname === `${base}/labels`) return json(200, { labels: acct.labels });
    if (req.method === 'GET' && pathname === `${base}/drafts`) {
      const size = Number(q.get('maxResults') ?? 100);
      const start = Number(q.get('pageToken') ?? 0);
      const page = acct.drafts.slice(start, start + size);
      const next = start + size < acct.drafts.length ? String(start + size) : undefined;
      return json(200, { drafts: page.map((d) => ({ id: d.id, message: { id: `m${d.id}` } })), ...(next ? { nextPageToken: next } : {}) });
    }
    const draftGet = new RegExp(`^${base}/drafts/([^/]+)$`).exec(pathname);
    if (req.method === 'GET' && draftGet) {
      const d = acct.drafts.find((x) => x.id === draftGet[1]);
      if (!d) return json(404, { error: { code: 404, status: 'NOT_FOUND' } });
      return json(200, { id: d.id, message: { id: `m${d.id}`, internalDate: '1767225600000', payload: { mimeType: 'text/plain', headers: rawHeaders(d.raw) } } });
    }
    if (req.method === 'POST' && pathname === `${base}/drafts/send`) {
      const b = this.sendBehaviour;
      if (b === 'timeout') throw new PerchError('Upstream request timed out', 'upstream_timeout');
      if (b === 'unreachable') throw new Error('socket hang up');
      if (b.status >= 300) return json(b.status, b.body ?? { error: { code: b.status, status: 'FAILED_PRECONDITION' } });
      const { id } = JSON.parse(req.body ?? '{}') as { id?: string };
      const i = acct.drafts.findIndex((d) => d.id === id);
      if (i < 0) return json(404, { error: { code: 404, status: 'NOT_FOUND' } });
      const [d] = acct.drafts.splice(i, 1);
      acct.sentDrafts.push({ id: d!.id, raw: d!.raw });
      return json(200, { id: `s${randomBytes(4).toString('hex')}`, threadId: d!.threadId ?? 'tnew', labelIds: ['SENT'] });
    }
    const org = new RegExp(`^${base}/messages/([^/]+)/(modify|trash|untrash)$`).exec(pathname);
    if (req.method === 'POST' && org) {
      const m = acct.messages.find((x) => x.id === org[1]);
      if (!m) return json(404, { error: { code: 404, status: 'NOT_FOUND' } });
      let labels = new Set(m.labelIds ?? ['INBOX']);
      if (org[2] === 'modify') {
        const body = JSON.parse(req.body ?? '{}') as { addLabelIds?: string[]; removeLabelIds?: string[] };
        for (const l of body.addLabelIds ?? []) {
          if (!acct.labels.some((x) => x.id === l)) return json(400, { error: { code: 400, status: 'INVALID_ARGUMENT' } });
          labels.add(l);
        }
        for (const l of body.removeLabelIds ?? []) labels.delete(l);
      } else if (org[2] === 'trash') labels.add('TRASH');
      else labels.delete('TRASH');
      m.labelIds = [...labels];
      return json(200, { id: m.id, threadId: m.threadId, labelIds: m.labelIds });
    }
    if (req.method === 'POST' && pathname === `${base}/messages/send`) {
      const b = this.sendBehaviour;
      if (b === 'timeout') throw new PerchError('Upstream request timed out', 'upstream_timeout');
      if (b === 'unreachable') throw new Error('socket hang up');
      if (b.status >= 300) return json(b.status, b.body ?? { error: { code: b.status, status: 'FAILED_PRECONDITION' } });
      const body = JSON.parse(req.body ?? '{}') as { raw: string; threadId?: string };
      acct.sent.push(body);
      return json(200, { id: `s${randomBytes(4).toString('hex')}`, threadId: body.threadId ?? 'tnew', labelIds: ['SENT'] });
    }
    if (pathname === `${base}/messages`) {
      const term = (q.get('q') ?? '').toLowerCase();
      const hits = acct.messages.filter((m) => !term || m.snippet.toLowerCase().includes(term) || subjectOf(m).toLowerCase().includes(term));
      const size = Math.min(Number(q.get('maxResults') ?? 100), this.opts.pageSize ?? 100);
      const start = Number(q.get('pageToken') ?? 0);
      const page = hits.slice(start, start + size);
      const next = start + size < hits.length ? String(start + size) : undefined;
      return json(200, {
        ...(page.length ? { messages: page.map((m) => ({ id: m.id, threadId: m.threadId })) } : {}),
        resultSizeEstimate: hits.length,
        ...(next ? { nextPageToken: next } : {}),
      });
    }
    const att = new RegExp(`^${base}/messages/([^/]+)/attachments/([^/]+)$`).exec(pathname);
    if (att) {
      const data = this.attachmentIds.get(att[2]!);
      if (!data) return json(400, { error: { code: 400, status: 'INVALID_ARGUMENT' } });
      const body = { size: data.length, data: data.toString('base64url') };
      const res = json(200, body);
      // Mirrors the real transport's streamed size cap.
      if (res.body.length > req.maxBytes) throw new PerchError('Upstream response exceeds the limit', 'response_too_large');
      return res;
    }
    const get = new RegExp(`^${base}/messages/([^/]+)$`).exec(pathname);
    const msg = get && acct.messages.find((m) => m.id === get[1]);
    if (!msg) return json(404, { error: { code: 404, status: 'NOT_FOUND', errors: [{ reason: 'notFound' }] } });
    const format = q.get('format') ?? 'full';
    const common = {
      id: msg.id,
      threadId: msg.threadId,
      labelIds: msg.labelIds ?? ['INBOX'],
      snippet: msg.snippet,
      internalDate: String(msg.internalDate),
      sizeEstimate: 1000,
    };
    if (format === 'metadata') {
      return json(200, { ...common, payload: { mimeType: msg.payload.mimeType, headers: msg.payload.headers ?? [] } });
    }
    const res = json(200, { ...common, payload: this.render(msg.payload) });
    if (res.body.length > req.maxBytes) throw new PerchError('Upstream response exceeds the limit', 'response_too_large');
    return res;
  }

  private render(p: MockPart): unknown {
    const body: Record<string, unknown> = { size: p.content?.length ?? 0 };
    if (p.content && (p.filename || p.asAttachment)) {
      const aid = `ANGjd${randomBytes(24).toString('base64url')}`;
      this.attachmentIds.set(aid, p.content);
      body.attachmentId = aid;
    } else if (p.content) {
      body.data = p.content.toString('base64url');
    }
    return {
      partId: p.partId,
      mimeType: p.mimeType,
      filename: p.filename ?? '',
      headers: p.headers ?? [],
      body,
      ...(p.parts ? { parts: p.parts.map((c) => this.render(c)) } : {}),
    };
  }
}

/** Top-level headers of a raw RFC 5322 message (base64url, as stored by drafts.create). */
function rawHeaders(raw: string): Array<{ name: string; value: string }> {
  const text = Buffer.from(raw, 'base64url').toString('utf8');
  const head = text.split(/\r?\n\r?\n/)[0]!.replace(/\r?\n[ \t]+/g, ' ');
  return head
    .split(/\r?\n/)
    .map((l) => [l.slice(0, l.indexOf(':')), l.slice(l.indexOf(':') + 1).trim()] as const)
    .filter(([n]) => n)
    .map(([name, value]) => ({ name, value }));
}

function subjectOf(m: MockMessage): string {
  return m.payload.headers?.find((h) => h.name.toLowerCase() === 'subject')?.value ?? '';
}
