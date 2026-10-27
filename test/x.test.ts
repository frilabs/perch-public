// X connector (docs/X_SPEC.md): login (paste address, state, PKCE), users/me, re-add, refresh with
// rotation, posting through the real MCP SDK client, length rules, ledger replay/conflict, outcomes, grants and
// body-free audit. MOCK X only: no live X calls.
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { X_CLIENT_GUIDE } from '../src/cli/x.js';
import { createPerchContext } from '../src/context.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { createMcpServer } from '../src/mcp/server.js';
import { CredentialStore, type Capability } from '../src/store/credentialStore.js';
import { isAllowedRoute, Upstream } from '../src/upstream.js';
import { createXTokenProvider, X_OAUTH_REDIRECT_URI } from '../src/x/oauth.js';
import { assertPostableXText, X_MAX_WEIGHTED_LENGTH, xWeightedLength } from '../src/x/text.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockX, type MockXUser } from './support/mockX.js';

let dirs: TempDirs;
let out: string;
let err: string;
let prompts: string[];
let mock: MockX;

const clientFile = () => path.join(dirs.root, '.config', 'perch', 'x-client.json');
const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });

function io(answers: string[], secrets: string[], extra: Partial<CliIo> = {}): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root },
    stdout: (s) => void (out += s),
    stderr: (s) => void (err += s),
    transport: mock.transport,
    readSecret: async (p) => {
      prompts.push(`SECRET:${p}`);
      const s = secrets.shift();
      if (s === undefined) throw new Error(`MOCK: no secret left (prompt: ${p})`);
      return s;
    },
    readLine: async (p) => {
      prompts.push(p);
      const a = answers.shift();
      if (a === undefined) throw new Error(`MOCK: no more answers (prompt: ${p})`);
      return a;
    },
    ...extra,
  };
}

/** Scripted browser login: the pasted address carries the code the MOCK consent screen issued (after `bad` wrong ones). */
function loginIo(user: MockXUser, answers: string[], secrets: string[], bad: Array<(redirect: string, state: string) => string> = []): CliIo {
  let authUrl = '';
  return io(answers, secrets, {
    stderr: (s) => {
      err += s;
      authUrl = /https:\/\/x\.com\/i\/oauth2\/authorize\S+/.exec(s)?.[0] ?? authUrl;
    },
    readPastedUrl: async () => {
      const u = new URL(authUrl);
      const redirect = u.searchParams.get('redirect_uri')!;
      const state = u.searchParams.get('state')!;
      const next = bad.shift();
      if (next) return next(redirect, state);
      return `${redirect}?state=${state}&code=${mock.approve(authUrl, user)}`;
    },
  });
}

async function addAccount(user: MockXUser, label = 'Private'): Promise<string> {
  const secrets = mock.client.secret ? [mock.client.id, mock.client.secret] : [mock.client.id, ''];
  const code = await runCli(['x', 'add', '--label', label, '--timeout', '10'], loginIo(user, ['', ''], secrets));
  expect(code, err).toBe(0);
  return (await (await openStore()).read()).x.find((a) => a.userId === user.id)!.id;
}

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = '';
  err = '';
  prompts = [];
  mock = new MockX();
  expect(await runCli(['init'], io([], []))).toBe(0);
  out = '';
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('perch x add [MOCK X]', () => {
  it('guides the app setup, logs in via the pasted address (state + PKCE), stores the account; nothing secret is printed', async () => {
    const user = mock.addUser('dummy_operator');
    const cliIo = loginIo(user, ['', ''], [mock.client.id, '']);
    expect(await runCli(['x', 'add', '--label', 'Private', '--timeout', '10'], cliIo), err).toBe(0);
    expect(prompts[0]).toMatch(/Set it up now.*\[Y\/n\]/);
    expect(prompts[1]).toMatch(/^SECRET:OAuth 2\.0 Client ID/);
    expect(prompts[2]).toMatch(/^SECRET:OAuth 2\.0 Client Secret.*Enter if none/);
    expect(out).toContain(X_OAUTH_REDIRECT_URI);
    expect(out).toMatch(/"Read and write"/);
    expect(out).toMatch(/Native App/);
    // Authorization request: fixed endpoint, scopes, PKCE S256, state.
    const auth = new URL(/https:\/\/x\.com\/i\/oauth2\/authorize\S+/.exec(err)![0]);
    expect(auth.searchParams.get('scope')).toBe('tweet.read tweet.write users.read offline.access');
    expect(auth.searchParams.get('redirect_uri')).toBe('http://127.0.0.1:8771/x/callback');
    expect(auth.searchParams.get('code_challenge_method')).toBe('S256');
    expect(auth.searchParams.get('state')!.length).toBeGreaterThanOrEqual(40);
    // Public client: client_id in the body, the verifier matches the challenge.
    expect(mock.tokenRequests).toEqual([{ grant_type: 'authorization_code', auth: 'body', verifierOk: true, redirectOk: true }]);
    expect(JSON.parse(await readFile(clientFile(), 'utf8'))).toEqual({ client_id: mock.client.id });
    expect((await stat(clientFile())).mode & 0o777).toBe(0o600);
    const [a] = (await (await openStore()).read()).x;
    expect(a).toMatchObject({ label: 'Private', userId: user.id, username: 'dummy_operator', name: 'Dummy dummy_operator', clientId: mock.client.id });
    expect(a!.clientSecret).toBeUndefined();
    expect(a!.scopes).toContain('tweet.write');
    expect(out).toMatch(/Connected X account x-[a-f0-9]{8} "Private" \(@dummy_operator\)\./);
    expect(out).toMatch(/--allow x_read,x_post --account x-/);
    expect(out).toMatch(/billed/);
    const all = out + err;
    expect(all).not.toContain(a!.refreshToken);
    expect(all).not.toContain('x-access-');
    expect(out).not.toContain(mock.client.id); // only the shortened id; the full public id is part of the login URL
  });

  it('refuses a pasted address with a wrong state or port and keeps waiting for the right one', async () => {
    const user = mock.addUser('dummy_state');
    const cliIo = loginIo(user, ['', ''], [mock.client.id, ''], [
      (redirect) => `${redirect}?state=forged-state-value&code=stolen`,
      (redirect, state) => `${redirect.replace(':8771', ':8772')}?state=${state}&code=x`,
    ]);
    expect(await runCli(['x', 'add', '--label', 'P', '--timeout', '10'], cliIo), err).toBe(0);
    expect(err).toMatch(/state does not match/);
    expect(err).toMatch(/must use port 8771/);
    expect(mock.tokenRequests).toHaveLength(1);
    expect(err).not.toContain('stolen');
  });

  it('supports a confidential client (Basic auth at the token endpoint, secret stored 0600)', async () => {
    mock = new MockX({ id: 'DUMMY-x-confidential-client', secret: 'DUMMY-x-client-secret-value' });
    const user = mock.addUser('dummy_conf');
    const id = await addAccount(user);
    expect(mock.tokenRequests).toEqual([{ grant_type: 'authorization_code', auth: 'basic', verifierOk: true, redirectOk: true }]);
    const tokenCall = mock.calls.find((c) => c.url.pathname === '/2/oauth2/token')!;
    expect(new URLSearchParams(tokenCall.body).get('client_id')).toBeNull();
    expect(JSON.parse(await readFile(clientFile(), 'utf8'))).toEqual({ client_id: 'DUMMY-x-confidential-client', client_secret: 'DUMMY-x-client-secret-value' });
    const a = (await (await openStore()).read()).x.find((x) => x.id === id)!;
    expect(a.clientSecret).toBe('DUMMY-x-client-secret-value');
    expect(out + err).not.toContain('DUMMY-x-client-secret-value');
    // Refresh uses Basic auth as well.
    const tokens = createXTokenProvider(await openStore(), new Upstream(mock.transport));
    await tokens.getAccessToken(id);
    expect(mock.tokenRequests.at(-1)).toEqual({ grant_type: 'refresh_token', auth: 'basic' });
  });

  it('re-adding the same X user updates the account (same id); another user gets a new one', async () => {
    const user = mock.addUser('dummy_same');
    const first = await addAccount(user, 'First');
    const before = (await (await openStore()).read()).x[0]!;
    const again = await addAccount(user, 'Renamed');
    expect(again).toBe(first);
    const data = (await (await openStore()).read()).x;
    expect(data).toHaveLength(1);
    expect(data[0]).toMatchObject({ id: first, label: 'Renamed', createdAt: before.createdAt });
    expect(data[0]!.refreshToken).not.toBe(before.refreshToken);
    expect(out).toMatch(/Updated X account/);
    const other = await addAccount(mock.addUser('dummy_other'), 'Other');
    expect(other).not.toBe(first);
    expect((await (await openStore()).read()).x).toHaveLength(2);
  });

  it('refuses a login without tweet.write or without a refresh token', async () => {
    const user = mock.addUser('dummy_scope');
    mock.grantedScope = 'tweet.read users.read offline.access';
    expect(await runCli(['x', 'add', '--label', 'P', '--timeout', '10'], loginIo(user, ['', ''], [mock.client.id, '']))).toBe(1);
    expect(err).toMatch(/Read and write/);
    mock.grantedScope = undefined;
    mock.issueRefreshTokens = false;
    err = '';
    expect(await runCli(['x', 'add', '--label', 'P', '--timeout', '10'], loginIo(user, [''], []))).toBe(1);
    expect(err).toMatch(/offline\.access/);
    expect((await (await openStore()).read()).x).toHaveLength(0);
  });

  it('without a terminal and without a client file: a clear error; --port is refused (fixed redirect)', async () => {
    expect(await runCli(['x', 'add', '--label', 'P'], io([], [], { readLine: undefined }))).toBe(1);
    expect(err).toMatch(/perch x client setup/);
    expect(await runCli(['x', 'add', '--label', 'P', '--port', '9000'], io([], []))).toBe(1);
    expect(err).toMatch(/fixed port 8771/);
  });

  it('perch x client setup | show, list and remove --revoke', async () => {
    expect(await runCli(['x', 'client', 'setup'], io([], ['short', '', mock.client.id, '']))).toBe(0);
    expect(out).toMatch(/looks wrong.*Try again/);
    expect(out).toMatch(/Next: perch x add --label NAME/);
    out = '';
    expect(await runCli(['x', 'client', 'show'], io([], []))).toBe(0);
    expect(out).toMatch(/public \(no secret\)/);
    expect(out).toContain(X_OAUTH_REDIRECT_URI);
    expect(out).not.toContain(mock.client.id);
    const user = mock.addUser('dummy_list');
    const id = await addAccount(user);
    out = '';
    expect(await runCli(['x', 'list'], io([], []))).toBe(0);
    expect(out).toMatch(new RegExp(`${id}\\s+"Private"\\s+@dummy_list\\s+read\\+post`));
    const rt = (await (await openStore()).read()).x[0]!.refreshToken;
    expect(await runCli(['x', 'remove', id, '--revoke'], io([], []))).toBe(0);
    expect(out).toMatch(/revoked at X/);
    expect(mock.revoked).toEqual([rt]);
    expect((await (await openStore()).read()).x).toHaveLength(0);
  });

  it('the guide fits 80 columns', () => {
    for (const line of X_CLIENT_GUIDE.split('\n')) expect([...line].length, line).toBeLessThanOrEqual(80);
  });
});

describe('X token refresh [MOCK X]', () => {
  it('rotates the refresh token and persists it; a revoked login asks to reconnect', async () => {
    const user = mock.addUser('dummy_rot');
    const id = await addAccount(user);
    const store = await openStore();
    const rt0 = (await store.read()).x[0]!.refreshToken;
    const tokens = createXTokenProvider(store, new Upstream(mock.transport));
    const t1 = await tokens.getAccessToken(id);
    const rt1 = (await store.read()).x[0]!.refreshToken;
    expect(rt1).not.toBe(rt0);
    expect(mock.refreshTokensOf(user.id)).toEqual([rt1]);
    expect(mock.tokenRequests.at(-1)).toEqual({ grant_type: 'refresh_token', auth: 'body' });
    expect(await tokens.getAccessToken(id)).toBe(t1); // cached
    // A second process with the rotated token keeps working.
    const t2 = await createXTokenProvider(await openStore(), new Upstream(mock.transport)).getAccessToken(id);
    expect(t2).not.toBe(t1);
    mock.revokeUser(user.id);
    const e = await rejection(createXTokenProvider(await openStore(), new Upstream(mock.transport)).getAccessToken(id));
    expect(e).toMatchObject({ code: 'grant_invalid' });
    expect(e.message).toMatch(/perch x add --label <label>/);
    expect(e.message).not.toContain('x-refresh-');
  });
});

describe('weighted length', () => {
  it('counts plain text, URLs (23), emoji and CJK (2)', () => {
    expect(xWeightedLength('a'.repeat(280))).toBe(280);
    expect(xWeightedLength('Read https://example.com/a/very/long/path/that/is/much/longer/than/23/characters?x=1')).toBe(5 + 23);
    expect(xWeightedLength('see www.example.org.')).toBe(4 + 23 + 1);
    expect(xWeightedLength('frilabs.dev rocks')).toBe(23 + 6);
    expect(xWeightedLength('mail me: dummy@example.com')).toBe(26);
    expect(xWeightedLength('日本語')).toBe(6);
    expect(xWeightedLength('한국')).toBe(4);
    expect(xWeightedLength('ok 👍')).toBe(5);
    expect(xWeightedLength('👨‍👩‍👧‍👦')).toBe(2);
    expect(xWeightedLength('🇦🇹')).toBe(2);
    expect(xWeightedLength('Grüße – “quotes”')).toBe(16);
    expect(xWeightedLength('é')).toBe(1); // NFC: é
  });

  it('accepts exactly 280 and refuses 281, also with URLs and CJK', () => {
    expect(assertPostableXText('a'.repeat(X_MAX_WEIGHTED_LENGTH))).toHaveLength(280);
    expect(() => assertPostableXText('a'.repeat(281))).toThrow(/281 weighted characters/);
    expect(() => assertPostableXText('漢'.repeat(140))).not.toThrow();
    expect(() => assertPostableXText('漢'.repeat(141))).toThrow(/282 weighted/);
    const url = `https://example.com/${'p'.repeat(200)}`;
    expect(() => assertPostableXText(`${'a'.repeat(256)} ${url}`)).not.toThrow(); // 256 + 1 + 23 = 280
    expect(() => assertPostableXText(`${'a'.repeat(257)} ${url}`)).toThrow(/281/);
    expect(() => assertPostableXText('   ')).toThrow(/empty/);
    expect(() => assertPostableXText('a\u0000b')).toThrow(/control/);
  });
});

describe('x_post / x_post_status / x_status [MOCK X]', () => {
  let store: CredentialStore;
  let user: MockXUser;
  let id: string;
  let otherId: string;

  beforeEach(async () => {
    user = mock.addUser('dummy_poster');
    id = await addAccount(user);
    otherId = await addAccount(mock.addUser('dummy_second'), 'Second');
    store = await openStore();
    mock.calls.length = 0;
  });

  async function clientFor(principal: Principal) {
    const mcp = createMcpServer(createPerchContext(store, mock.transport), principal);
    const [a, b] = InMemoryTransport.createLinkedPair();
    await mcp.connect(b);
    const client = new Client({ name: 'x-test', version: '0' });
    await client.connect(a);
    return client;
  }

  async function grant(capabilities: Capability[], accountIds: string[]) {
    const { token } = await createClientGrant(store, { label: 'Codex', capabilities, accountIds, tokenFile: `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token` });
    return (await principalForClientToken(store, token))!;
  }

  async function call(client: Client, name: string, args: Record<string, unknown>) {
    try {
      const r = await client.callTool({ name, arguments: args });
      const text = (r.content as Array<{ text: string }>)[0]?.text ?? '';
      return { isError: r.isError === true, text, body: JSON.parse(text) as Record<string, unknown> };
    } catch (e) {
      return { isError: true, text: (e as Error).message, body: { error: (e as Error).message } };
    }
  }

  const rid = () => `x-test-${Math.random().toString(16).slice(2, 14)}`;
  const tweetCalls = () => mock.calls.filter((c) => c.url.pathname === '/2/tweets');

  it('the read-only global token sees x_status and perch_list_accounts, never the write tools', async () => {
    const client = await clientFor(READONLY_PRINCIPAL);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('x_status');
    expect(names).not.toContain('x_post');
    expect(names).not.toContain('x_post_status');
    const s = await call(client, 'x_status', { accountId: id });
    expect(s.body).toMatchObject({ accountId: id, username: '@dummy_poster', userId: user.id, canPost: true, profileUrl: 'https://x.com/dummy_poster' });
    expect(mock.calls).toHaveLength(0); // no X API call (nothing billed)
    const list = await call(client, 'perch_list_accounts', {});
    expect((list.body.x as unknown[]).length).toBe(2);
    expect(list.text).not.toMatch(/refresh|x-access-|clientId/);
  });

  it('posts once per requestId with the documented request shape; a repeat replays without posting', async () => {
    const client = await clientFor(await grant(['x_read', 'x_post'], [id]));
    const args = { accountId: id, text: 'Hello from Perch https://example.com/x', requestId: rid() };
    const first = await call(client, 'x_post', args);
    expect(first.isError, first.text).toBe(false);
    expect(first.body).toMatchObject({ status: 'accepted', replayed: false, accountId: id, username: '@dummy_poster' });
    expect(first.body.postId).toMatch(/^\d+$/);
    expect(first.body.url).toBe(`https://x.com/i/status/${first.body.postId}`);
    const [req] = tweetCalls();
    expect(req!.method).toBe('POST');
    expect(req!.url.toString()).toBe('https://api.x.com/2/tweets');
    expect(req!.headers['content-type']).toBe('application/json');
    expect(req!.headers.authorization).toMatch(/^Bearer x-access-/);
    expect(JSON.parse(req!.body!)).toEqual({ text: args.text });
    const again = await call(client, 'x_post', args);
    expect(again.body).toMatchObject({ status: 'accepted', replayed: true, postId: first.body.postId });
    expect(tweetCalls()).toHaveLength(1);
    const st = await call(client, 'x_post_status', { accountId: id, requestId: args.requestId });
    expect(st.body).toMatchObject({ status: 'accepted', operationId: first.body.operationId, postId: first.body.postId });
    expect(first.text).not.toContain('Hello from Perch');
    expect(st.text).not.toContain('Hello from Perch');
  });

  it('refuses a reused requestId with different text before any request (idempotency conflict)', async () => {
    const client = await clientFor(await grant(['x_post'], [id]));
    const requestId = rid();
    await call(client, 'x_post', { accountId: id, text: 'one', requestId });
    const r = await call(client, 'x_post', { accountId: id, text: 'two', requestId });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/already used/);
    expect(mock.posted).toHaveLength(1);
  });

  it('refuses an over-long post locally: no request, no send record', async () => {
    const client = await clientFor(await grant(['x_post'], [id]));
    const r = await call(client, 'x_post', { accountId: id, text: `${'b'.repeat(258)} https://example.com/${'q'.repeat(50)}`, requestId: rid() });
    expect(r.isError).toBe(true);
    expect(String(r.body.error)).toMatch(/282 weighted characters; X allows at most 280/);
    expect(String(r.body.error)).not.toContain('bbbb');
    expect(mock.calls).toHaveLength(0);
    expect((await new MailWorkflowLedger(store).read()).sends).toHaveLength(0);
  });

  it('HTTP 4xx = rejected (not posted); timeout, network error and 5xx = indeterminate; never retried', async () => {
    const client = await clientFor(await grant(['x_post'], [id]));
    const cases: Array<[MockX['postFaults'][number], string, RegExp]> = [
      [{ status: 403 }, 'rejected', /HTTP 403/],
      [{ status: 402 }, 'rejected', /credits/],
      [{ status: 429 }, 'rejected', /rate limited/],
      [{ status: 400 }, 'rejected', /HTTP 400/],
      ['timeout', 'indeterminate', /unknown/],
      ['unreachable', 'indeterminate', /unknown/],
      [{ status: 503 }, 'indeterminate', /unknown/],
      [{ status: 500 }, 'indeterminate', /unknown/],
    ];
    for (const [fault, status, detail] of cases) {
      mock.postFaults.push(fault);
      const before = tweetCalls().length;
      const args = { accountId: id, text: `case ${JSON.stringify(fault)}`, requestId: rid() };
      const r = await call(client, 'x_post', args);
      expect(r.body, JSON.stringify(fault)).toMatchObject({ status, replayed: false });
      expect(String(r.body.detail)).toMatch(detail);
      expect(tweetCalls().length - before).toBe(1); // exactly one attempt, no retry
      const replay = await call(client, 'x_post', args);
      expect(replay.body).toMatchObject({ status, replayed: true });
      expect(tweetCalls().length - before).toBe(1);
    }
    expect(mock.posted).toHaveLength(0);
  });

  it('a 401 from X is rejected with a reconnect hint and drops the cached token', async () => {
    const client = await clientFor(await grant(['x_post'], [id]));
    mock.postFaults.push({ status: 401 });
    const r = await call(client, 'x_post', { accountId: id, text: 'first', requestId: rid() });
    expect(r.body).toMatchObject({ status: 'rejected' });
    expect(String(r.body.detail)).toMatch(/perch x add --label <label>/);
    const refreshes = mock.tokenRequests.filter((t) => t.grant_type === 'refresh_token').length;
    const ok = await call(client, 'x_post', { accountId: id, text: 'second', requestId: rid() });
    expect(ok.body).toMatchObject({ status: 'accepted' });
    expect(mock.tokenRequests.filter((t) => t.grant_type === 'refresh_token').length).toBe(refreshes + 1);
  });

  it('a revoked login is rejected before anything is posted (reconnect hint)', async () => {
    const client = await clientFor(await grant(['x_post'], [id]));
    mock.revokeUser(user.id);
    const r = await call(client, 'x_post', { accountId: id, text: 'nope', requestId: rid() });
    expect(r.body).toMatchObject({ status: 'rejected' });
    expect(String(r.body.detail)).toMatch(/Re-authorise: run `perch x add --label <label>`/);
    expect(tweetCalls()).toHaveLength(0);
  });

  it('grants: x_read alone cannot post; another account is denied; grant shapes are validated', async () => {
    const reader = await clientFor(await grant(['x_read'], [id]));
    const names = (await reader.listTools()).tools.map((t) => t.name);
    expect(names).toContain('x_status');
    expect(names).not.toContain('x_post');
    const poster = await clientFor(await grant(['x_post'], [id]));
    expect((await poster.listTools()).tools.map((t) => t.name)).not.toContain('x_status');
    const denied = await call(poster, 'x_post', { accountId: otherId, text: 'not mine', requestId: rid() });
    expect(denied.isError).toBe(true);
    expect(String(denied.body.error)).toMatch(/not granted/);
    const deniedStatus = await call(reader, 'x_status', { accountId: otherId });
    expect(deniedStatus.isError).toBe(true);
    expect(mock.calls).toHaveLength(0);
    await expect(createClientGrant(store, { label: 'L', capabilities: ['x_post'], accountIds: ['imap-00000000'], tokenFile: `${dirs.root}/t1` })).rejects.toThrow();
    const noAccount = await rejection(createClientGrant(store, { label: 'L', capabilities: ['x_post', 'read'], accountIds: [id], tokenFile: `${dirs.root}/t2` }));
    expect(noAccount.message).toMatch(/mail account/);
    const wrongFamily = await rejection(createClientGrant(store, { label: 'L', capabilities: ['slack_send'], accountIds: [id], tokenFile: `${dirs.root}/t3` }));
    expect(wrongFamily.message).toMatch(/Slack/);
  });

  it('a full grant covers X; the operator principal is refused at the service even if called directly', async () => {
    const { token } = await createClientGrant(store, { label: 'Full', capabilities: [], accountIds: [], full: true, tokenFile: `${dirs.root}/full.token` });
    const full = await clientFor((await principalForClientToken(store, token))!);
    const r = await call(full, 'x_post', { accountId: otherId, text: 'full access', requestId: rid() });
    expect(r.body).toMatchObject({ status: 'accepted' });
    const ctx = createPerchContext(store, mock.transport);
    await expect(ctx.x.post(READONLY_PRINCIPAL, { accountId: id, text: 'x', requestId: rid() })).rejects.toMatchObject({ code: 'capability_denied' });
  });

  it('the audit trail and the ledger carry no token and no text; errors never echo the text', async () => {
    const client = await clientFor(await grant(['x_read', 'x_post'], [id]));
    const secretText = 'SECRET-POST-TEXT-do-not-log';
    await call(client, 'x_post', { accountId: id, text: secretText, requestId: rid() });
    mock.postFaults.push({ status: 403, body: { detail: `You are not allowed to create a Tweet with duplicate content: ${secretText}` } });
    const rejected = await call(client, 'x_post', { accountId: id, text: `${secretText} 2`, requestId: rid() });
    expect(rejected.text).not.toContain(secretText);
    const tooLong = await call(client, 'x_post', { accountId: id, text: `${secretText}${'z'.repeat(300)}`, requestId: rid() });
    expect(tooLong.text).not.toContain(secretText);
    await call(client, 'x_status', { accountId: id });
    const ledger = await new MailWorkflowLedger(store).read();
    const dump = JSON.stringify(ledger);
    expect(dump).not.toContain(secretText);
    expect(dump).not.toMatch(/x-access-|x-refresh-|Bearer/);
    const types = ledger.audit.map((e) => `${e.type}:${e.outcome}`);
    expect(types).toEqual(expect.arrayContaining(['x_post:accepted', 'x_post:rejected', 'x_post:invalid', 'x_status:ok']));
    expect(ledger.audit.filter((e) => e.type === 'x_post').every((e) => e.provider === 'x' && e.accountId === id)).toBe(true);
  });

  it('the upstream allowlist: posting needs the x_post tag; delete and other endpoints are never reachable', () => {
    expect(isAllowedRoute('x', 'POST', '/2/tweets', 'x_post')).toBe(true);
    expect(isAllowedRoute('x', 'POST', '/2/tweets')).toBe(false);
    expect(isAllowedRoute('x', 'POST', '/2/tweets', 'slack_send')).toBe(false);
    expect(isAllowedRoute('x', 'DELETE', '/2/tweets/123', 'x_post')).toBe(false);
    expect(isAllowedRoute('x', 'POST', '/2/users/123/likes', 'x_post')).toBe(false);
    expect(isAllowedRoute('x', 'POST', '/2/dm_conversations', 'x_post')).toBe(false);
    expect(isAllowedRoute('x', 'GET', '/2/users/me')).toBe(true);
    expect(isAllowedRoute('x', 'POST', '/2/oauth2/revoke')).toBe(false);
    expect(isAllowedRoute('x', 'POST', '/2/oauth2/revoke', 'admin')).toBe(true);
  });

  it('perch status lists X accounts with a live users/me check', async () => {
    out = '';
    expect(await runCli(['status', '--plain'], io([], []))).toBe(0);
    expect(out).toMatch(new RegExp(`✓ ${id}  "Private"  @dummy_poster  \\[x: read, post\\].*ok`));
    expect(mock.calls.some((c) => c.url.pathname === '/2/users/me')).toBe(true);
    mock.revokeUser(user.id);
    out = '';
    expect(await runCli(['status', '--plain'], io([], []))).toBe(1);
    expect(out).toMatch(/perch x add --label <label>/);
    out = '';
    await runCli(['status', '--json', '--no-check'], io([], []));
    expect(out).not.toMatch(/x-refresh-|x-access-/);
    out = '';
    await runCli(['status', '--no-check'], io([], [], { stdoutIsTTY: true, stdoutColumns: 80 }));
    const plain = out.replace(/\u001b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/── X ─/);
    expect(plain).toMatch(/☑ Private {2}@dummy_poster +not checked/);
    expect(plain).toMatch(/☑ read {3}☑ post/);
    // Commands are printed whole on purpose (copy & paste); every other line fits 80 columns.
    for (const line of plain.split('\n').filter((l) => !/^ +perch /.test(l))) expect([...line].length, line).toBeLessThanOrEqual(80);
  });
});
