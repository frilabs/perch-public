/**
 * MOCK Google upstream (OAuth token endpoint + Drive v3 subset) for tests only.
 * This is an in-memory fake of the HTTP API; nothing here talks to Google, and passing
 * tests that use it are NOT evidence of a live integration.
 */
import { createHash } from 'node:crypto';
import { PerchError } from '../../src/errors.js';
import type { UpstreamRequest, UpstreamResponse, UpstreamTransport } from '../../src/upstream.js';
import { dummySecret } from './fixtures.js';

export interface MockDriveFile {
  id: string;
  name: string;
  mimeType: string;
  content?: Buffer;
  exports?: Record<string, Buffer>;
  parents?: string[];
  description?: string;
  trashed?: boolean;
  permissions?: MockPermission[];
  comments?: Array<{ id: string; content: string; author: { displayName: string } }>;
  /** Shared drive the file lives in (absent = My Drive). */
  driveId?: string;
}

export interface MockPermission {
  id: string;
  type: string;
  role: string;
  emailAddress?: string;
  domain?: string;
  allowFileDiscovery?: boolean;
}

export interface MockGoogleAccount {
  email: string;
  displayName: string;
  refreshToken: string;
  files: MockDriveFile[];
}

export interface MockGoogleOptions {
  /** Scope string returned by the token endpoint. */
  grantedScope?: string;
  /** Omit refresh_token from the authorization_code response. */
  omitRefreshToken?: boolean;
  /** Refresh token returned by refresh_token grants (undefined = omit, Google's usual behaviour). */
  rotateRefreshTokenTo?: string;
  pageSize?: number;
}

const json = (status: number, body: unknown): UpstreamResponse => ({
  status,
  headers: { 'content-type': 'application/json' },
  body: Buffer.from(JSON.stringify(body)),
});

export class MockGoogle {
  readonly calls: UpstreamRequest[] = [];
  readonly accounts: MockGoogleAccount[] = [];
  /** code -> pending authorization */
  readonly codes = new Map<string, { challenge: string; redirectUri: string; account: MockGoogleAccount }>();
  readonly accessTokens = new Map<string, MockGoogleAccount>();
  readonly revoked: string[] = [];
  tokenCalls = 0;
  /** Accounts (by email) whose Drive calls fail with HTTP 500, to exercise partial results. */
  failingEmails = new Set<string>();
  /** Drive write calls (anything but GET) that reached the mock. */
  writes: UpstreamRequest[] = [];
  /** When set, every Drive write answers with this HTTP status (after counting it). */
  failWritesWith?: number;
  /** When set, every Drive write throws (transport failure after submission). */
  dropWrites = false;
  private seq = 0;
  /** Runs while a refresh_token grant is "in flight" (to simulate concurrent store changes). */
  beforeRefreshResponse?: () => Promise<void>;

  constructor(public opts: MockGoogleOptions = {}) {}

  addAccount(email: string, files: MockDriveFile[] = []): MockGoogleAccount {
    const acct = { email, displayName: `Dummy ${email}`, refreshToken: dummySecret('GOOGLE-REFRESH'), files };
    this.accounts.push(acct);
    return acct;
  }

  /** Simulates the user approving consent in the browser for `account`; returns the auth code. */
  approve(authUrl: string, account: MockGoogleAccount): string {
    const u = new URL(authUrl);
    const code = dummySecret('AUTHCODE');
    this.codes.set(code, {
      challenge: u.searchParams.get('code_challenge')!,
      redirectUri: u.searchParams.get('redirect_uri')!,
      account,
    });
    return code;
  }

  issueAccessToken(account: MockGoogleAccount): string {
    const t = dummySecret('GOOGLE-ACCESS');
    this.accessTokens.set(t, account);
    return t;
  }

  transport: UpstreamTransport = async (req) => {
    this.calls.push(req);
    const { origin, pathname } = req.url;
    if (pathname === '/token' && new URLSearchParams(req.body ?? '').get('grant_type') === 'refresh_token') {
      await this.beforeRefreshResponse?.();
    }
    if (origin === 'https://oauth2.googleapis.com') return this.oauth(req, pathname);
    if (origin === 'https://www.googleapis.com') return this.drive(req, pathname);
    return json(404, { error: 'not_found' });
  };

  private oauth(req: UpstreamRequest, pathname: string): UpstreamResponse {
    const form = new URLSearchParams(req.body ?? '');
    if (pathname === '/revoke') {
      this.revoked.push(form.get('token') ?? '');
      return json(200, {});
    }
    this.tokenCalls++;
    const scope = this.opts.grantedScope ?? 'https://www.googleapis.com/auth/drive.readonly';
    if (form.get('grant_type') === 'authorization_code') {
      const pending = this.codes.get(form.get('code') ?? '');
      if (!pending) return json(400, { error: 'invalid_grant' });
      this.codes.delete(form.get('code')!);
      const verifier = form.get('code_verifier') ?? '';
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      if (challenge !== pending.challenge) return json(400, { error: 'invalid_grant', error_description: 'PKCE' });
      if (form.get('redirect_uri') !== pending.redirectUri) return json(400, { error: 'redirect_uri_mismatch' });
      return json(200, {
        access_token: this.issueAccessToken(pending.account),
        expires_in: 3599,
        scope,
        token_type: 'Bearer',
        ...(this.opts.omitRefreshToken ? {} : { refresh_token: pending.account.refreshToken }),
      });
    }
    if (form.get('grant_type') === 'refresh_token') {
      const acct = this.accounts.find((a) => a.refreshToken === form.get('refresh_token'));
      if (!acct) return json(400, { error: 'invalid_grant', error_description: 'Token has been expired or revoked.' });
      if (this.opts.rotateRefreshTokenTo) acct.refreshToken = this.opts.rotateRefreshTokenTo;
      return json(200, {
        access_token: this.issueAccessToken(acct),
        expires_in: 3599,
        scope,
        token_type: 'Bearer',
        ...(this.opts.rotateRefreshTokenTo ? { refresh_token: this.opts.rotateRefreshTokenTo } : {}),
      });
    }
    return json(400, { error: 'unsupported_grant_type' });
  }

  private drive(req: UpstreamRequest, pathname: string): UpstreamResponse {
    const auth = req.headers.authorization ?? '';
    const acct = this.accessTokens.get(auth.replace(/^Bearer /, ''));
    if (!acct) return json(401, { error: { code: 401, status: 'UNAUTHENTICATED', message: 'mock' } });
    if (this.failingEmails.has(acct.email)) return json(500, { error: { code: 500, status: 'INTERNAL' } });
    const q = req.url.searchParams;
    if (req.method !== 'GET') return this.driveWrite(req, pathname, acct);
    if (pathname === '/drive/v3/about') {
      return json(200, { user: { emailAddress: acct.email, displayName: acct.displayName } });
    }
    if (pathname === '/drive/v3/files') {
      let files = acct.files;
      const query = q.get('q') ?? '';
      if (query.includes('trashed = false')) files = files.filter((f) => !f.trashed);
      const parent = /'([^']+)' in parents/.exec(query)?.[1];
      if (parent) files = files.filter((f) => f.parents?.includes(parent));
      const term = /(?:fullText|name) contains '((?:[^'\\]|\\.)*)'/.exec(query)?.[1]?.replace(/\\(.)/g, '$1');
      if (term) files = files.filter((f) => f.name.toLowerCase().includes(term.toLowerCase()));
      const size = Math.min(Number(q.get('pageSize') ?? 100), this.opts.pageSize ?? 100);
      const start = Number(q.get('pageToken') ?? 0);
      const page = files.slice(start, start + size);
      const next = start + size < files.length ? String(start + size) : undefined;
      return json(200, { files: page.map((f) => this.meta(f)), ...(next ? { nextPageToken: next } : {}) });
    }
    const sub = /^\/drive\/v3\/files\/([^/]+)\/(permissions|comments)$/.exec(pathname);
    if (sub) {
      const f = acct.files.find((x) => x.id === sub[1]);
      if (!f) return json(404, { error: { code: 404, errors: [{ reason: 'notFound' }] } });
      return json(200, sub[2] === 'permissions' ? { permissions: f.permissions ?? [] } : { comments: f.comments ?? [] });
    }
    const m = /^\/drive\/v3\/files\/([^/]+)(\/export)?$/.exec(pathname);
    const file = m && acct.files.find((f) => f.id === m[1]);
    if (!m || !file) return json(404, { error: { code: 404, errors: [{ reason: 'notFound' }] } });
    if (m[2]) {
      const out = file.exports?.[q.get('mimeType') ?? ''];
      if (!out) return json(400, { error: { code: 400, errors: [{ reason: 'badRequest' }] } });
      return { status: 200, headers: { 'content-type': q.get('mimeType')! }, body: out };
    }
    if (q.get('alt') === 'media') {
      if (!file.content) return json(403, { error: { code: 403, errors: [{ reason: 'fileNotDownloadable' }] } });
      // Mirrors the real transport's streamed size cap.
      if (file.content.length > req.maxBytes) throw new PerchError('Upstream response exceeds the limit', 'response_too_large');
      return { status: 200, headers: { 'content-type': file.mimeType }, body: file.content };
    }
    return json(200, this.meta(file));
  }

  private driveWrite(req: UpstreamRequest, pathname: string, acct: MockGoogleAccount): UpstreamResponse {
    this.writes.push(req);
    if (this.dropWrites) throw new Error('connection reset (mock)');
    if (this.failWritesWith) return json(this.failWritesWith, { error: { code: this.failWritesWith, errors: [{ reason: 'mockFailure' }] } });
    const q = req.url.searchParams;
    const body = (): Record<string, unknown> => JSON.parse(req.body ?? '{}') as Record<string, unknown>;
    const notFound = json(404, { error: { code: 404, errors: [{ reason: 'notFound' }] } });
    const find = (id: string | undefined) => acct.files.find((f) => f.id === id);
    const newId = () => `mock${String(++this.seq).padStart(6, '0')}`;
    const add = (meta: Record<string, unknown>, content?: Buffer) => {
      const f: MockDriveFile = {
        id: newId(),
        name: String(meta.name ?? 'Untitled'),
        mimeType: String(meta.mimeType ?? 'application/octet-stream'),
        ...(content ? { content } : {}),
        ...(Array.isArray(meta.parents) ? { parents: meta.parents as string[] } : {}),
      };
      acct.files.push(f);
      return json(200, this.meta(f));
    };
    if (req.method === 'POST' && pathname === '/upload/drive/v3/files') {
      if (q.get('uploadType') !== 'multipart') return json(400, { error: { code: 400 } });
      const { metadata, media } = parseMultipart(req);
      return add(metadata, media);
    }
    const upload = /^\/upload\/drive\/v3\/files\/([^/]+)$/.exec(pathname);
    if (req.method === 'PATCH' && upload) {
      const f = find(upload[1]);
      if (!f) return notFound;
      f.content = req.bodyBytes;
      f.mimeType = req.headers['content-type'] ?? f.mimeType;
      return json(200, this.meta(f));
    }
    if (req.method === 'POST' && pathname === '/drive/v3/files') return add(body());
    const one = /^\/drive\/v3\/files\/([^/]+)$/.exec(pathname);
    if (req.method === 'PATCH' && one) {
      const f = find(one[1]);
      if (!f) return notFound;
      const b = body();
      if (typeof b.name === 'string') f.name = b.name;
      if (typeof b.description === 'string') f.description = b.description;
      if (typeof b.trashed === 'boolean') f.trashed = b.trashed;
      const addP = q.get('addParents')?.split(',') ?? [];
      const removeP = q.get('removeParents')?.split(',') ?? [];
      if (addP.length || removeP.length) f.parents = [...(f.parents ?? ['root']).filter((x) => !removeP.includes(x)), ...addP];
      return json(200, this.meta(f));
    }
    const copy = /^\/drive\/v3\/files\/([^/]+)\/copy$/.exec(pathname);
    if (req.method === 'POST' && copy) {
      const f = find(copy[1]);
      if (!f) return notFound;
      const b = body();
      return add({ name: b.name ?? `Copy of ${f.name}`, mimeType: f.mimeType, parents: b.parents ?? f.parents }, f.content);
    }
    const perms = /^\/drive\/v3\/files\/([^/]+)\/permissions(?:\/([^/]+))?$/.exec(pathname);
    if (perms) {
      const f = find(perms[1]);
      if (!f) return notFound;
      f.permissions ??= [];
      if (req.method === 'POST' && !perms[2]) {
        const b = body() as unknown as MockPermission;
        const perm = { ...b, id: b.type === 'anyone' ? 'anyoneWithLink' : String(10_000_000 + ++this.seq) };
        f.permissions.push(perm);
        return json(200, perm);
      }
      if (req.method === 'DELETE' && perms[2]) {
        const before = f.permissions.length;
        f.permissions = f.permissions.filter((x) => x.id !== perms[2]);
        return before === f.permissions.length ? notFound : { status: 204, headers: {}, body: Buffer.alloc(0) };
      }
    }
    const comments = /^\/drive\/v3\/files\/([^/]+)\/comments$/.exec(pathname);
    if (req.method === 'POST' && comments) {
      const f = find(comments[1]);
      if (!f) return notFound;
      const c = { id: `AAAA${newId()}`, content: String(body().content), author: { displayName: acct.displayName } };
      (f.comments ??= []).push(c);
      return json(200, { ...c, createdTime: '2026-01-01T00:00:00.000Z' });
    }
    return json(404, { error: { code: 404, errors: [{ reason: 'notFound' }] } });
  }

  private meta(f: MockDriveFile) {
    return {
      id: f.id,
      name: f.name,
      mimeType: f.mimeType,
      ...(f.content ? { size: String(f.content.length) } : {}),
      modifiedTime: '2026-01-01T00:00:00.000Z',
      parents: f.parents ?? ['root'],
      ...(f.trashed !== undefined ? { trashed: f.trashed } : {}),
      ...(f.driveId ? { driveId: f.driveId } : {}),
    };
  }
}

/** Parses Drive's multipart/related upload body (JSON metadata part, then media part). */
export function parseMultipart(req: UpstreamRequest): { metadata: Record<string, unknown>; media: Buffer; mediaType: string } {
  const boundary = /boundary=([^;]+)/.exec(req.headers['content-type'] ?? '')?.[1];
  const body = req.bodyBytes;
  if (!boundary || !body) throw new Error('mock: not a multipart body');
  const sep = Buffer.from(`--${boundary}\r\n`);
  const first = body.indexOf(sep);
  const second = body.indexOf(sep, first + sep.length);
  const end = body.lastIndexOf(Buffer.from(`\r\n--${boundary}--`));
  const part = (start: number, stop: number) => {
    const chunk = body.subarray(start, stop);
    const split = chunk.indexOf('\r\n\r\n');
    return { head: chunk.subarray(0, split).toString('utf8'), data: chunk.subarray(split + 4) };
  };
  const meta = part(first + sep.length, second);
  const media = part(second + sep.length, end);
  const metaText = meta.data.toString('utf8').replace(/\r\n$/, '');
  return { metadata: JSON.parse(metaText) as Record<string, unknown>, media: media.data, mediaType: /Content-Type: (.*)/.exec(media.head)?.[1] ?? '' };
}
