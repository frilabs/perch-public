/**
 * MOCK X API (OAuth 2.0 token/revoke, GET /2/users/me, POST /2/tweets) for tests only. Nothing here talks to X;
 * passing tests are NOT evidence of a live integration. Behaviour follows X's documentation as understood on
 * 2026-10-21: PKCE S256, public clients send client_id in the body, confidential clients use Basic auth, refresh
 * tokens rotate on every refresh and an invalid refresh token answers 400 invalid_request.
 */
import { createHash } from 'node:crypto';
import { PerchError } from '../../src/errors.js';
import type { UpstreamRequest, UpstreamResponse, UpstreamTransport } from '../../src/upstream.js';
import { dummySecret } from './fixtures.js';

export interface MockXUser {
  id: string;
  username: string;
  name: string;
}

export interface MockXClient {
  id: string;
  /** Confidential clients only. */
  secret?: string;
}

export type MockXFault = { status: number; body?: unknown } | 'timeout' | 'unreachable';

const json = (status: number, body: unknown): UpstreamResponse => ({ status, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(body)) });

export class MockX {
  readonly calls: UpstreamRequest[] = [];
  readonly users: MockXUser[] = [];
  readonly tokenRequests: Array<{ grant_type: string; auth: 'basic' | 'body'; verifierOk?: boolean; redirectOk?: boolean }> = [];
  readonly posted: Array<{ userId: string; body: unknown }> = [];
  readonly revoked: string[] = [];
  /** Faults for the next POST /2/tweets calls (in order). */
  postFaults: MockXFault[] = [];
  /** Scope the token endpoint reports (default: everything requested). */
  grantedScope: string | undefined;
  /** Set to false to omit refresh tokens (no offline.access). */
  issueRefreshTokens = true;
  private codes = new Map<string, { userId: string; clientId: string; redirectUri: string; challenge: string; scope: string }>();
  private access = new Map<string, string>();
  private refresh = new Map<string, { userId: string; clientId: string; scope: string }>();
  private seq = 0;

  constructor(readonly client: MockXClient = { id: dummySecret('x-client-id') }) {}

  addUser(username: string): MockXUser {
    const u = { id: String(1_000_000_000_000 + this.users.length * 7919), username, name: `Dummy ${username}` };
    this.users.push(u);
    return u;
  }

  /** The user approved the consent screen: returns the code the browser redirect would carry. */
  approve(authUrl: string, user: MockXUser): string {
    const u = new URL(authUrl);
    if (u.origin !== 'https://x.com' || u.pathname !== '/i/oauth2/authorize') throw new Error('MOCK: unexpected authorize URL');
    const q = u.searchParams;
    if (q.get('response_type') !== 'code' || q.get('code_challenge_method') !== 'S256' || !q.get('state')) throw new Error('MOCK: bad authorize parameters');
    if (q.get('client_id') !== this.client.id) throw new Error('MOCK: unknown client');
    const code = `code-${++this.seq}-${dummySecret('code')}`;
    this.codes.set(code, { userId: user.id, clientId: this.client.id, redirectUri: q.get('redirect_uri')!, challenge: q.get('code_challenge')!, scope: q.get('scope')! });
    return code;
  }

  /** Revokes every token of a user (as if the user removed the app at X). */
  revokeUser(userId: string): void {
    for (const [k, v] of this.refresh) if (v.userId === userId) this.refresh.delete(k);
    for (const [k, v] of this.access) if (v === userId) this.access.delete(k);
  }

  refreshTokensOf(userId: string): string[] {
    return [...this.refresh].filter(([, v]) => v.userId === userId).map(([k]) => k);
  }

  private issue(userId: string, clientId: string, scope: string) {
    const access = `x-access-${++this.seq}-${dummySecret('at')}`;
    this.access.set(access, userId);
    const refresh = this.issueRefreshTokens ? `x-refresh-${this.seq}-${dummySecret('rt')}` : undefined;
    if (refresh) this.refresh.set(refresh, { userId, clientId, scope });
    return { token_type: 'bearer', expires_in: 7200, access_token: access, scope: this.grantedScope ?? scope, ...(refresh ? { refresh_token: refresh } : {}) };
  }

  private clientAuth(req: UpstreamRequest, form: URLSearchParams): { ok: boolean; kind: 'basic' | 'body' } {
    const auth = req.headers.authorization;
    if (auth?.startsWith('Basic ')) {
      const [id, secret] = Buffer.from(auth.slice(6), 'base64').toString('utf8').split(':');
      return { ok: id === this.client.id && this.client.secret !== undefined && secret === this.client.secret, kind: 'basic' };
    }
    // Public client: client_id in the body, and only when the app has no secret.
    return { ok: form.get('client_id') === this.client.id && this.client.secret === undefined, kind: 'body' };
  }

  private token(req: UpstreamRequest): UpstreamResponse {
    if (req.headers['content-type'] !== 'application/x-www-form-urlencoded') return json(400, { error: 'invalid_request' });
    const form = new URLSearchParams(req.body ?? '');
    const auth = this.clientAuth(req, form);
    const grant = form.get('grant_type') ?? '';
    if (grant === 'authorization_code') {
      const c = this.codes.get(form.get('code') ?? '');
      const verifier = form.get('code_verifier') ?? '';
      const verifierOk = c !== undefined && createHash('sha256').update(verifier).digest('base64url') === c.challenge;
      const redirectOk = c !== undefined && form.get('redirect_uri') === c.redirectUri;
      this.tokenRequests.push({ grant_type: grant, auth: auth.kind, verifierOk, redirectOk });
      if (!auth.ok) return json(401, { error: 'unauthorized_client', error_description: 'Missing valid authorization header' });
      if (!c || !verifierOk || !redirectOk) return json(400, { error: 'invalid_request', error_description: 'Value passed for the authorization code was invalid.' });
      this.codes.delete(form.get('code')!);
      return json(200, this.issue(c.userId, c.clientId, c.scope));
    }
    if (grant === 'refresh_token') {
      this.tokenRequests.push({ grant_type: grant, auth: auth.kind });
      if (!auth.ok) return json(401, { error: 'unauthorized_client' });
      const rt = form.get('refresh_token') ?? '';
      const r = this.refresh.get(rt);
      if (!r) return json(400, { error: 'invalid_request', error_description: 'Value passed for the token was invalid.' });
      this.refresh.delete(rt); // rotation: the old refresh token is dead
      return json(200, this.issue(r.userId, r.clientId, r.scope));
    }
    return json(400, { error: 'unsupported_grant_type' });
  }

  private userOf(req: UpstreamRequest): string | undefined {
    const a = req.headers.authorization;
    return a?.startsWith('Bearer ') ? this.access.get(a.slice(7)) : undefined;
  }

  readonly transport: UpstreamTransport = async (req) => {
    this.calls.push(req);
    if (req.url.origin !== 'https://api.x.com') throw new Error(`MOCK X: unexpected origin ${req.url.origin}`);
    const path = req.url.pathname;
    if (req.method === 'POST' && path === '/2/oauth2/token') return this.token(req);
    if (req.method === 'POST' && path === '/2/oauth2/revoke') {
      const form = new URLSearchParams(req.body ?? '');
      const t = form.get('token') ?? '';
      this.refresh.delete(t);
      this.revoked.push(t);
      return json(200, { revoked: true });
    }
    if (req.method === 'GET' && path === '/2/users/me') {
      const uid = this.userOf(req);
      const u = this.users.find((x) => x.id === uid);
      if (!u) return json(401, { title: 'Unauthorized', type: 'about:blank', status: 401, detail: 'Unauthorized' });
      return json(200, { data: { id: u.id, name: u.name, username: u.username } });
    }
    if (req.method === 'POST' && path === '/2/tweets') {
      const uid = this.userOf(req);
      if (!uid) return json(401, { title: 'Unauthorized', status: 401, detail: 'Unauthorized' });
      const fault = this.postFaults.shift();
      if (fault === 'timeout') throw new PerchError('Upstream request timed out', 'upstream_timeout');
      if (fault === 'unreachable') throw new Error('MOCK: connection reset');
      if (fault) return json(fault.status, fault.body ?? { title: 'Error', status: fault.status, detail: 'MOCK refusal' });
      const body = JSON.parse(req.body ?? '{}') as { text?: string };
      this.posted.push({ userId: uid, body });
      const id = String(1_800_000_000_000_000_000n + BigInt(this.posted.length));
      return json(201, { data: { id, text: body.text, edit_history_tweet_ids: [id] } });
    }
    return json(404, { title: 'Not Found Error', status: 404 });
  };
}
