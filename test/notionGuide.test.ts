// Notion guide before the token prompt, post-connect visibility hint and Notion OAuth (public integration):
// docs/SLACK_SESSION_NOTION_GUIDE_SPEC.md §2 and §4. MOCK only: the Notion API and its OAuth endpoint are mocks.
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runCli, type CliIo } from '../src/cli/run.js';
import { NotionService } from '../src/notion/notion.js';
import { NOTION_OAUTH_REDIRECT_URI } from '../src/notion/oauth.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { READONLY_PRINCIPAL } from '../src/auth/grants.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockNotion, mockId, type MockWorkspace } from './support/mockNotion.js';

let dirs: TempDirs;
let out: string;
let err: string;
let prompts: string[];
let mock: MockNotion;

const clientFile = () => path.join(dirs.root, '.config', 'perch', 'notion-client.json');
const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
const GUIDE_MARK = 'https://www.notion.so/profile/integrations';

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

function addPages(ws: MockWorkspace, n: number) {
  for (let i = 0; i < n; i++) ws.pages.push({ id: mockId(), title: `Dummy page ${i}` });
}

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = '';
  err = '';
  prompts = [];
  mock = new MockNotion();
  expect(await runCli(['init'], io([], []))).toBe(0);
  out = '';
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('perch notion add: guide before the hidden prompt', () => {
  it('asks token vs OAuth, shows the steps, then the hidden prompt; the token is never printed', async () => {
    const ws = mock.addWorkspace('A');
    expect(await runCli(['notion', 'add', '--label', 'Personal'], io(['', ''], [ws.token]))).toBe(0);
    expect(prompts[0]).toMatch(/\[t\]oken.*\[o\]auth.*\[T\/o\]/);
    expect(out).toMatch(/no owner rights needed/);
    expect(out).toContain(GUIDE_MARK);
    expect(out).toMatch(/New integration/);
    expect(out).toMatch(/Internal/);
    expect(out).toMatch(/Read content, Update content, Insert content/);
    expect(out).toMatch(/Read comments, Insert comments/);
    expect(out).toMatch(/Internal Integration Secret/);
    expect(out).toMatch(/ntn_/);
    expect(out).toMatch(/Connections → Perch/);
    expect(out).toMatch(/only workspace owners/);
    expect(prompts[1]).toMatch(/Press Enter/);
    expect(prompts[2]).toMatch(/^SECRET:Notion Internal Integration Secret/);
    expect(out.indexOf(GUIDE_MARK)).toBeLessThan(out.indexOf('Connected Notion workspace'));
    expect(out + err).not.toContain(ws.token);
  });

  it('--skip-guide (and --internal) goes straight to the token prompt', async () => {
    const ws = mock.addWorkspace('A');
    expect(await runCli(['notion', 'add', '--label', 'X', '--internal', '--skip-guide'], io([], [ws.token]))).toBe(0);
    expect(out).not.toContain(GUIDE_MARK);
    expect(prompts).toEqual([expect.stringMatching(/^SECRET:/)]);
  });

  it('asks [y/N] when a workspace is already connected', async () => {
    const a = mock.addWorkspace('A');
    const b = mock.addWorkspace('B');
    const c = mock.addWorkspace('C');
    expect(await runCli(['notion', 'add', '--label', 'A', '--internal', '--skip-guide'], io([], [a.token]))).toBe(0);
    out = '';
    prompts = [];
    expect(await runCli(['notion', 'add', '--label', 'B', '--internal'], io([''], [b.token]))).toBe(0);
    expect(prompts[0]).toMatch(/Show the steps .*\[y\/N\]/);
    expect(out).not.toContain(GUIDE_MARK);
    prompts = [];
    expect(await runCli(['notion', 'add', '--label', 'C', '--internal'], io(['y', ''], [c.token]))).toBe(0);
    expect(out).toContain(GUIDE_MARK);
    expect(prompts.map((p) => p.slice(0, 7))).toEqual(['Show th', 'Press E', 'SECRET:']);
  });

  it('without a terminal: no question, no guide, the masked prompt fails as before', async () => {
    const noTty = io([], []);
    delete noTty.readLine;
    noTty.readSecret = async () => {
      throw new Error('no TTY');
    };
    expect(await runCli(['notion', 'add', '--label', 'X'], noTty)).toBe(1);
    expect(out).not.toContain(GUIDE_MARK);
    expect(prompts).toEqual([]);
  });
});

describe('post-connect visibility hint (one small search call)', () => {
  it('no shared page yet → hint where to share', async () => {
    const ws = mock.addWorkspace('A');
    expect(await runCli(['notion', 'add', '--label', 'X', '--internal', '--skip-guide'], io([], [ws.token]))).toBe(0);
    expect(out).toMatch(/No page shared yet: open a page in Notion, ••• → Connections → Perch/);
    const searches = mock.calls.filter((c) => c.url.pathname === '/v1/search');
    expect(searches).toHaveLength(1);
    expect(JSON.parse(searches[0]!.body!)).toEqual({ page_size: 10 });
  });

  it('counts what it sees; "at least" when there are more', async () => {
    const a = mock.addWorkspace('A');
    addPages(a, 2);
    expect(await runCli(['notion', 'add', '--label', 'A', '--internal', '--skip-guide'], io([], [a.token]))).toBe(0);
    expect(out).toMatch(/Perch can see 2 page\(s\)\/data source\(s\)/);
    out = '';
    const b = mock.addWorkspace('B');
    addPages(b, 12);
    expect(await runCli(['notion', 'add', '--label', 'B', '--internal', '--skip-guide'], io([], [b.token]))).toBe(0);
    expect(out).toMatch(/Perch can see at least 10 page\(s\)/);
  });

  it('a failing search does not fail the add (no hint line)', async () => {
    const ws = mock.addWorkspace('A');
    const transport = mock.transport;
    const failingSearch: CliIo['transport'] = async (req) =>
      req.url.pathname === '/v1/search' ? { status: 500, headers: {}, body: Buffer.from('{}') } : transport(req);
    expect(await runCli(['notion', 'add', '--label', 'X', '--internal', '--skip-guide'], io([], [ws.token], { transport: failingSearch }))).toBe(0);
    expect(out).toMatch(/Connected Notion workspace/);
    expect(out).not.toMatch(/No page shared|Perch can see/);
  });
});

/** Scripted OAuth login: the pasted address carries the code the MOCK consent screen issued. */
function oauthIo(ws: MockWorkspace, answers: string[], secrets: string[]): CliIo {
  let authUrl = '';
  return io(answers, secrets, {
    stderr: (s) => {
      err += s;
      authUrl = /https:\/\/api\.notion\.com\/v1\/oauth\/authorize\S+/.exec(s)?.[0] ?? authUrl;
    },
    readPastedUrl: async () => {
      const u = new URL(authUrl);
      return `${u.searchParams.get('redirect_uri')}?code=${mock.approve(authUrl, ws)}&state=${u.searchParams.get('state')}`;
    },
  });
}

describe('perch notion add --oauth (public integration)', () => {
  it('guides the client setup when missing, logs in, stores authMode oauth; nothing secret is printed', async () => {
    const ws = mock.addWorkspace('Team');
    addPages(ws, 1);
    const cliIo = oauthIo(ws, ['o', ''], [mock.oauthClient.id, mock.oauthClient.secret]);
    expect(await runCli(['notion', 'add', '--label', 'Team', '--timeout', '10'], cliIo)).toBe(0);
    expect(prompts[0]).toMatch(/\[T\/o\]/);
    expect(prompts[1]).toMatch(/Set it up now.*\[Y\/n\]/);
    expect(prompts[2]).toMatch(/^SECRET:OAuth Client ID/);
    expect(prompts[3]).toMatch(/^SECRET:OAuth Client Secret/);
    expect(out).toContain(NOTION_OAUTH_REDIRECT_URI);
    expect(out).toMatch(/"Public"/);
    expect(out).toMatch(/Any workspace/);
    expect(err).toMatch(/owner=user/);
    const file = await readFile(clientFile(), 'utf8');
    expect(JSON.parse(file)).toEqual({ client_id: mock.oauthClient.id, client_secret: mock.oauthClient.secret });
    expect((await stat(clientFile())).mode & 0o777).toBe(0o600);
    const [stored] = (await (await openStore()).read()).notion;
    expect(stored).toMatchObject({ label: 'Team', authMode: 'oauth', oauthWorkspaceId: ws.workspaceId, tokenOwner: { id: ws.owner.id } });
    expect(stored!.refreshToken).toBeUndefined();
    expect(stored!.clientSecret).toBeUndefined();
    expect(mock.tokenRequests).toEqual([{ grant_type: 'authorization_code', basicOk: true }]);
    expect(out).toMatch(/Connected Notion workspace notion-[a-f0-9]{8} as "Team" \(Dummy workspace .*\) via OAuth\./);
    expect(out).toMatch(/Perch can see 1 page/);
    const all = out + err;
    expect(all).not.toContain(mock.oauthClient.secret);
    expect(all).not.toContain(stored!.token);
  });

  it('the same Notion workspace again updates the record (same id), no duplicate', async () => {
    const ws = mock.addWorkspace('Team');
    expect(await runCli(['notion', 'add', '--label', 'Team', '--oauth', '--timeout', '10'], oauthIo(ws, [''], [mock.oauthClient.id, mock.oauthClient.secret]))).toBe(0);
    const first = (await (await openStore()).read()).notion[0]!;
    out = '';
    expect(await runCli(['notion', 'add', '--label', 'Team 2', '--oauth', '--timeout', '10'], oauthIo(ws, [''], []))).toBe(0);
    const all = (await (await openStore()).read()).notion;
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ id: first.id, label: 'Team 2', createdAt: first.createdAt });
    expect(all[0]!.token).not.toBe(first.token);
    expect(out).toMatch(/^Updated Notion workspace/m);
  });

  it('with refresh tokens: stored with the client, refreshed on use, rotation persisted', async () => {
    mock.oauthIssuesRefreshTokens = true;
    const ws = mock.addWorkspace('Team');
    addPages(ws, 1);
    expect(await runCli(['notion', 'add', '--label', 'Team', '--oauth', '--timeout', '10'], oauthIo(ws, [''], [mock.oauthClient.id, mock.oauthClient.secret]))).toBe(0);
    const store = await openStore();
    const before = (await store.read()).notion[0]!;
    expect(before).toMatchObject({ authMode: 'oauth', clientId: mock.oauthClient.id, clientSecret: mock.oauthClient.secret });
    expect(before.refreshToken).toBe(mock.issuedRefreshTokens[0]);
    expect(out).toMatch(/via OAuth \(refreshing token\)/);
    for (const rt of mock.issuedRefreshTokens) expect(out + err).not.toContain(rt);

    const service = new NotionService(store, new Upstream(mock.transport));
    const res = await service.search(READONLY_PRINCIPAL, {});
    expect(res.results).toHaveLength(1);
    expect(mock.tokenRequests.map((r) => r.grant_type)).toEqual(['authorization_code', 'refresh_token']);
    const after = (await store.read()).notion[0]!;
    expect(after.refreshToken).toBe(mock.issuedRefreshTokens[1]);
    // Cached: a second call does not refresh again.
    await service.search(READONLY_PRINCIPAL, {});
    expect(mock.tokenRequests).toHaveLength(2);
  });

  it('an existing client file is used without the guide', async () => {
    const ws = mock.addWorkspace('Team');
    expect(await runCli(['notion', 'client', 'setup'], io([], [mock.oauthClient.id, mock.oauthClient.secret]))).toBe(0);
    expect(out).toMatch(/Next: perch notion add --oauth/);
    out = '';
    prompts = [];
    expect(await runCli(['notion', 'add', '--label', 'T', '--oauth', '--timeout', '10'], oauthIo(ws, [''], []))).toBe(0);
    expect(out).not.toContain('Notion OAuth client (once per');
    expect(prompts).toEqual([expect.stringMatching(/^Use the stored Notion OAuth client \(cccccccc…\)\? \[Y\/n\] $/)]);
    // A second workspace reuses the same client; "n" walks through the setup again and replaces it.
    const other = mock.addWorkspace('Other');
    prompts = [];
    out = '';
    expect(await runCli(['notion', 'add', '--label', 'O', '--oauth', '--timeout', '10'], oauthIo(other, ['n'], [mock.oauthClient.id, mock.oauthClient.secret]))).toBe(0);
    expect(out).toContain('Notion OAuth client (once per');
    expect((await (await openStore()).read()).notion).toHaveLength(2);
  });

  it('perch setup: the Notion step asks token vs OAuth and runs the same flow', async () => {
    const ws = mock.addWorkspace('Setup');
    // google, microsoft, imap n; notion y → label → [T/o] o → stored client? (none: set up now Y) …
    const cliIo = oauthIo(ws, ['n', 'n', 'n', 'y', 'Team', 'o', '', 'n', 'n', 'n', 'n'], [mock.oauthClient.id, mock.oauthClient.secret]);
    await runCli(['setup'], cliIo);
    expect(prompts.some((p) => /\[t\]oken.*\[o\]auth/.test(p))).toBe(true);
    expect((await (await openStore()).read()).notion[0]).toMatchObject({ authMode: 'oauth', label: 'Team' });
  });

  it('without a terminal and without a client file: clear error, nothing stored', async () => {
    const noTty = io([], []);
    delete noTty.readLine;
    expect(await runCli(['notion', 'add', '--label', 'T', '--oauth'], noTty)).toBe(1);
    expect(err).toMatch(/perch notion client setup/);
    expect((await (await openStore()).read()).notion).toHaveLength(0);
  });

  it('--oauth and --internal together are a usage error', async () => {
    expect(await runCli(['notion', 'add', '--label', 'T', '--oauth', '--internal'], io([], []))).toBe(2);
  });
});

describe('perch notion client setup | show', () => {
  it('show without a file, setup stores 0600, show prints only a shortened id; replace asks [y/N]', async () => {
    expect(await runCli(['notion', 'client', 'show'], io([], []))).toBe(0);
    expect(out).toMatch(/No usable Notion OAuth client/);
    out = '';
    expect(await runCli(['notion', 'client', 'setup'], io([], ['short', 'x', mock.oauthClient.id, mock.oauthClient.secret]))).toBe(0);
    expect(out).toMatch(/looks wrong.*Try again/);
    expect((await stat(clientFile())).mode & 0o777).toBe(0o600);
    out = '';
    expect(await runCli(['notion', 'client', 'show'], io([], []))).toBe(0);
    expect(out).toContain(NOTION_OAUTH_REDIRECT_URI);
    expect(out).not.toContain(mock.oauthClient.id);
    expect(out).not.toContain(mock.oauthClient.secret);
    out = '';
    expect(await runCli(['notion', 'client', 'setup'], io([''], []))).toBe(0);
    expect(out).toMatch(/Kept the existing client/);
  });
});

describe('upstream allowlist', () => {
  it('the OAuth token endpoint is reachable only with the internal admin tag', async () => {
    const up = new Upstream(mock.transport);
    await expect(up.json('notion', { method: 'POST', path: '/v1/oauth/token', json: {} })).rejects.toMatchObject({ code: 'route_not_allowed' });
    await expect(
      up.json('notion', { method: 'POST', path: '/v1/oauth/token', json: {}, capability: 'notion_write' }),
    ).rejects.toMatchObject({ code: 'route_not_allowed' });
  });
});
