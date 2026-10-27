/**
 * MOCK Notion API (in-memory fake of the 2026-03-11 endpoints Perch uses: reads, page/block writes, comments) for tests only.
 * Nothing here talks to Notion; passing tests are NOT evidence of a live integration.
 */
import type { UpstreamRequest, UpstreamResponse, UpstreamTransport } from '../../src/upstream.js';
import { dummySecret } from './fixtures.js';

export const NOTION_VERSION = '2026-03-11';

export interface MockBlock {
  id: string;
  text: string;
  type?: string;
  inTrash?: boolean;
  children?: MockBlock[];
}

export interface MockPage {
  id: string;
  title: string;
  blocks?: MockBlock[];
  inTrash?: boolean;
  parentId?: string;
  properties?: Record<string, unknown>;
  icon?: unknown;
  cover?: unknown;
}

export interface MockComment {
  id: string;
  discussionId: string;
  parentId: string;
  text: string;
}

export interface MockWorkspace {
  token: string;
  owner: { id: string; name: string };
  pages: MockPage[];
  dataSources: Array<{ id: string; title: string; rows: Array<{ id: string; title: string; properties?: Record<string, unknown> }> }>;
  comments: MockComment[];
  databases: Array<{ id: string; title: string; dataSourceIds: string[] }>;
  /** Notion's workspace_id (OAuth token responses). */
  workspaceId: string;
  /** Access tokens issued through the MOCK OAuth endpoint (accepted like the internal token). */
  oauthTokens: Set<string>;
}

let counter = 0;
/** Deterministic, obviously fake Notion-style ids (32 hex chars). */
export function mockId(): string {
  counter++;
  return `0000dead${String(counter).padStart(24, '0')}`;
}

const json = (status: number, body: unknown): UpstreamResponse => ({
  status,
  headers: { 'content-type': 'application/json' },
  body: Buffer.from(JSON.stringify(body)),
});

const richText = (s: string) => [{ type: 'text', plain_text: s, text: { content: s } }];

function paginate<T>(items: T[], startCursor: string | null | undefined, pageSize: number) {
  const start = startCursor ? Number(startCursor.replace('cursor-', '')) : 0;
  const page = items.slice(start, start + pageSize);
  const more = start + pageSize < items.length;
  return { page, next_cursor: more ? `cursor-${start + pageSize}` : null, has_more: more };
}

export class MockNotion {
  readonly calls: UpstreamRequest[] = [];
  readonly workspaces: MockWorkspace[] = [];
  failingTokens = new Set<string>();
  /** Next requests answer 429; each entry is the Retry-After header value (null = no header). */
  rateLimitQueue: Array<string | null> = [];
  /** Every distinct request is rate limited this many times before it succeeds. */
  rateLimitEachRequest = 0;
  private rateLimited = new Map<string, number>();
  /** Block ids whose children endpoint fails with HTTP 500. */
  failingBlockIds = new Set<string>();
  /** Tokens without the "Update/Insert content" capabilities: writes answer 403 restricted_resource. */
  restrictedTokens = new Set<string>();
  /** When set, every write (POST/PATCH except search/query) answers with this HTTP status. */
  failWritesWith: number | null = null;
  /** Count of write requests that reached the mock. */
  writes = 0;

  addWorkspace(name: string): MockWorkspace {
    const ws: MockWorkspace = {
      token: dummySecret('NOTION-PAT'),
      owner: { id: mockId(), name: `Dummy owner ${name}` },
      pages: [],
      dataSources: [],
      databases: [],
      comments: [],
      workspaceId: `${mockId().slice(0, 8)}-0000-4000-8000-${mockId().slice(-12)}`,
      oauthTokens: new Set(),
    };
    this.workspaces.push(ws);
    return ws;
  }

  /** MOCK public integration (OAuth). */
  readonly oauthClient = { id: `${'c'.repeat(8)}-mock-client-id`, secret: dummySecret('NOTION-OAUTH-SECRET') };
  /** Whether token responses carry refresh_token/expires_in (newer Notion) or not (non-expiring tokens). */
  oauthIssuesRefreshTokens = false;
  private oauthCodes = new Map<string, { ws: MockWorkspace; redirectUri: string }>();
  private refreshTokens = new Map<string, MockWorkspace>();
  readonly tokenRequests: Array<{ grant_type?: unknown; basicOk: boolean }> = [];
  /** Refresh tokens handed out so far (for "never printed" checks). */
  readonly issuedRefreshTokens: string[] = [];

  /** The user approved the consent screen for `ws`: returns the code the browser redirect would carry. */
  approve(authUrl: string, ws: MockWorkspace): string {
    const u = new URL(authUrl);
    if (u.origin + u.pathname !== 'https://api.notion.com/v1/oauth/authorize') throw new Error('MOCK: wrong authorize URL');
    if (u.searchParams.get('client_id') !== this.oauthClient.id || u.searchParams.get('owner') !== 'user') throw new Error('MOCK: bad authorize params');
    const code = dummySecret('NOTION-CODE');
    this.oauthCodes.set(code, { ws, redirectUri: u.searchParams.get('redirect_uri')! });
    return code;
  }

  private issue(ws: MockWorkspace) {
    const access = dummySecret('NOTION-OAUTH-ACCESS');
    ws.oauthTokens.add(access);
    const refresh = this.oauthIssuesRefreshTokens ? dummySecret('NOTION-REFRESH') : undefined;
    if (refresh) {
      this.refreshTokens.set(refresh, ws);
      this.issuedRefreshTokens.push(refresh);
    }
    return {
      access_token: access,
      token_type: 'bearer',
      bot_id: mockId(),
      workspace_id: ws.workspaceId,
      workspace_name: `Dummy workspace ${ws.owner.name}`,
      owner: { type: 'user', user: { object: 'user', id: ws.owner.id, name: ws.owner.name, type: 'person' } },
      ...(refresh ? { refresh_token: refresh, expires_in: 3600 } : {}),
    };
  }

  private oauthToken(req: UpstreamRequest): UpstreamResponse {
    const expected = `Basic ${Buffer.from(`${this.oauthClient.id}:${this.oauthClient.secret}`).toString('base64')}`;
    const body = req.body ? (JSON.parse(req.body) as Record<string, unknown>) : {};
    const basicOk = req.headers.authorization === expected;
    this.tokenRequests.push({ grant_type: body.grant_type, basicOk });
    if (!basicOk) return json(401, { error: 'invalid_client' });
    if (body.grant_type === 'authorization_code') {
      const c = this.oauthCodes.get(String(body.code));
      if (!c || c.redirectUri !== body.redirect_uri) return json(400, { error: 'invalid_grant' });
      this.oauthCodes.delete(String(body.code));
      return json(200, this.issue(c.ws));
    }
    if (body.grant_type === 'refresh_token') {
      const ws = this.refreshTokens.get(String(body.refresh_token));
      if (!ws) return json(400, { error: 'invalid_grant' });
      this.refreshTokens.delete(String(body.refresh_token)); // rotation
      return json(200, this.issue(ws));
    }
    return json(400, { error: 'unsupported_grant_type' });
  }

  private findBlocks(ws: MockWorkspace, id: string): MockBlock[] | undefined {
    const page = ws.pages.find((p) => p.id === id);
    if (page) return page.blocks ?? [];
    const walk = (blocks: MockBlock[]): MockBlock[] | undefined => {
      for (const b of blocks) {
        if (b.id === id) return b.children ?? [];
        const found = b.children && walk(b.children);
        if (found) return found;
      }
      return undefined;
    };
    for (const p of ws.pages) {
      const found = walk(p.blocks ?? []);
      if (found) return found;
    }
    return undefined;
  }

  private findBlock(ws: MockWorkspace, id: string): MockBlock | undefined {
    const walk = (blocks: MockBlock[]): MockBlock | undefined => {
      for (const b of blocks) {
        if (b.id === id) return b;
        const found = b.children && walk(b.children);
        if (found) return found;
      }
      return undefined;
    };
    for (const p of ws.pages) {
      const found = walk(p.blocks ?? []);
      if (found) return found;
    }
    return undefined;
  }

  private pageJson(page: MockPage) {
    return {
      object: 'page',
      id: page.id,
      url: `https://www.notion.so/${page.id}`,
      in_trash: page.inTrash === true,
      last_edited_time: '2026-10-20T10:00:00.000Z',
      properties: { ...(page.properties ?? {}), Name: { type: 'title', title: richText(page.title) } },
      ...(page.icon ? { icon: page.icon } : {}),
    };
  }

  /** Write endpoints (POST /v1/pages, PATCH pages/blocks, comments); null when the request is not one. */
  private write(ws: MockWorkspace, req: UpstreamRequest, body: Record<string, unknown>): UpstreamResponse | null {
    const p = req.url.pathname;
    const isWrite =
      (req.method === 'POST' && (p === '/v1/pages' || p === '/v1/comments')) || req.method === 'PATCH' || req.method === 'DELETE';
    if (!isWrite) {
      if (req.method === 'GET' && p === '/v1/comments') {
        const blockId = req.url.searchParams.get('block_id') ?? '';
        const items = ws.comments.filter((c) => c.parentId === blockId);
        const { page, next_cursor, has_more } = paginate(items, req.url.searchParams.get('start_cursor'), Number(req.url.searchParams.get('page_size') ?? 100));
        return json(200, {
          object: 'list',
          results: page.map((c) => ({ object: 'comment', id: c.id, discussion_id: c.discussionId, parent: { type: 'page_id', page_id: c.parentId }, rich_text: richText(c.text) })),
          next_cursor,
          has_more,
        });
      }
      return null;
    }
    this.writes++;
    if (this.restrictedTokens.has(ws.token)) return json(403, { object: 'error', code: 'restricted_resource', message: 'mock' });
    if (this.failWritesWith !== null) return json(this.failWritesWith, { object: 'error', code: 'internal_server_error', message: 'mock' });
    if (req.method === 'DELETE') return json(405, { object: 'error', code: 'invalid_request', message: 'mock' });
    const textOf = (rt: unknown) =>
      Array.isArray(rt) ? rt.map((t: { text?: { content?: string } }) => t.text?.content ?? '').join('') : '';
    const toBlock = (b: Record<string, unknown>): MockBlock => {
      const type = String(b.type ?? Object.keys(b).find((k) => k !== 'object' && k !== 'type') ?? 'paragraph');
      const data = (b[type] ?? {}) as { rich_text?: unknown; children?: Array<Record<string, unknown>> };
      return { id: mockId(), type, text: textOf(data.rich_text), ...(data.children ? { children: data.children.map(toBlock) } : {}) };
    };
    if (p === '/v1/pages') {
      const parent = body.parent as { page_id?: string; data_source_id?: string };
      const props = (body.properties ?? {}) as Record<string, { title?: unknown }>;
      const titleProp = Object.values(props).find((x) => x && Array.isArray(x.title));
      const title = titleProp ? textOf(titleProp.title) : '';
      if (parent.data_source_id) {
        const ds = ws.dataSources.find((d) => d.id === parent.data_source_id);
        if (!ds) return json(404, { object: 'error', code: 'object_not_found' });
        const row = { id: mockId(), title, properties: props };
        ds.rows.push(row);
        return json(200, { object: 'page', id: row.id, in_trash: false, parent: { type: 'data_source_id', data_source_id: ds.id } });
      }
      if (!parent.page_id || !ws.pages.some((x) => x.id === parent.page_id)) return json(404, { object: 'error', code: 'object_not_found' });
      const page: MockPage = {
        id: mockId(),
        title,
        parentId: parent.page_id,
        blocks: ((body.children ?? []) as Array<Record<string, unknown>>).map(toBlock),
        ...(body.icon ? { icon: body.icon } : {}),
      };
      ws.pages.push(page);
      return json(200, this.pageJson(page));
    }
    if (p === '/v1/comments') {
      const parent = body.parent as { page_id?: string } | undefined;
      const discussion = body.discussion_id as string | undefined;
      const parentId = parent?.page_id ?? ws.comments.find((c) => c.discussionId === discussion)?.parentId;
      if (!parentId) return json(404, { object: 'error', code: 'object_not_found' });
      const c: MockComment = { id: mockId(), discussionId: discussion ?? mockId(), parentId, text: textOf(body.rich_text) };
      ws.comments.push(c);
      return json(200, { object: 'comment', id: c.id, discussion_id: c.discussionId });
    }
    let m = /^\/v1\/pages\/([^/]+)$/.exec(p);
    if (m) {
      const page = ws.pages.find((x) => x.id === m![1]);
      if (!page) return json(404, { object: 'error', code: 'object_not_found' });
      if (typeof body.in_trash === 'boolean') page.inTrash = body.in_trash;
      if (body.properties) page.properties = { ...(page.properties ?? {}), ...(body.properties as Record<string, unknown>) };
      if ('icon' in body) page.icon = body.icon;
      if ('cover' in body) page.cover = body.cover;
      return json(200, this.pageJson(page));
    }
    m = /^\/v1\/blocks\/([^/]+)\/children$/.exec(p);
    if (m) {
      const target = this.findBlocks(ws, m[1]!);
      if (!target) return json(404, { object: 'error', code: 'object_not_found' });
      const added = ((body.children ?? []) as Array<Record<string, unknown>>).map(toBlock);
      const page = ws.pages.find((x) => x.id === m![1]);
      const block = page ? undefined : this.findBlock(ws, m[1]!);
      const list = page ? (page.blocks ??= []) : (block!.children ??= []);
      const after = typeof body.after === 'string' ? list.findIndex((b) => b.id === body.after) : -1;
      list.splice(after >= 0 ? after + 1 : list.length, 0, ...added);
      return json(200, { object: 'list', results: added.map((b) => ({ object: 'block', id: b.id, type: b.type })), next_cursor: null, has_more: false });
    }
    m = /^\/v1\/blocks\/([^/]+)$/.exec(p);
    if (m) {
      const block = this.findBlock(ws, m[1]!);
      if (!block) return json(404, { object: 'error', code: 'object_not_found' });
      if (typeof body.in_trash === 'boolean') block.inTrash = body.in_trash;
      const type = Object.keys(body).find((k) => k !== 'in_trash');
      if (type) {
        block.type = type;
        block.text = textOf((body[type] as { rich_text?: unknown }).rich_text);
      }
      return json(200, { object: 'block', id: block.id, type: block.type ?? 'paragraph', in_trash: block.inTrash === true });
    }
    return json(404, { object: 'error', code: 'invalid_request_url' });
  }

  transport: UpstreamTransport = async (req) => {
    this.calls.push(req);
    if (req.url.origin !== 'https://api.notion.com') return json(404, {});
    if (req.headers['notion-version'] !== NOTION_VERSION) {
      return json(400, { object: 'error', code: 'missing_version', message: 'mock' });
    }
    if (req.url.pathname === '/v1/oauth/token' && req.method === 'POST') return this.oauthToken(req);
    const ws = this.workspaces.find(
      (w) => `Bearer ${w.token}` === req.headers.authorization || [...w.oauthTokens].some((t) => `Bearer ${t}` === req.headers.authorization),
    );
    if (!ws) return json(401, { object: 'error', code: 'unauthorized', message: 'mock' });
    if (this.failingTokens.has(ws.token)) return json(503, { object: 'error', code: 'service_unavailable' });
    const limited = (retryAfter: string | null): UpstreamResponse => ({
      ...json(429, { object: 'error', code: 'rate_limited', message: 'mock' }),
      headers: { 'content-type': 'application/json', ...(retryAfter !== null ? { 'retry-after': retryAfter } : {}) },
    });
    if (this.rateLimitQueue.length) return limited(this.rateLimitQueue.shift()!);
    if (this.rateLimitEachRequest) {
      const key = `${req.method} ${req.url} ${req.body ?? ''}`;
      const n = this.rateLimited.get(key) ?? 0;
      if (n < this.rateLimitEachRequest) {
        this.rateLimited.set(key, n + 1);
        return limited('1');
      }
    }
    const body = req.body ? (JSON.parse(req.body) as Record<string, unknown>) : {};
    const p = req.url.pathname;
    const qp = req.url.searchParams;
    const written = this.write(ws, req, body);
    if (written) return written;

    if (p === '/v1/users/me') return json(200, { object: 'user', id: ws.owner.id, name: ws.owner.name, type: 'person' });
    if (p === '/v1/search') {
      const query = String(body.query ?? '').toLowerCase();
      const filter = (body.filter as { value?: string } | undefined)?.value;
      const items = [
        ...ws.pages.map((x) => ({
          object: 'page',
          id: x.id,
          url: `https://www.notion.so/${x.id}`,
          properties: { Name: { type: 'title', title: richText(x.title) } },
        })),
        ...ws.dataSources.map((x) => ({ object: 'data_source', id: x.id, title: richText(x.title) })),
      ].filter((x) => (!filter || x.object === filter) && JSON.stringify(x).toLowerCase().includes(query));
      const { page, next_cursor, has_more } = paginate(items, body.start_cursor as string, Number(body.page_size ?? 100));
      return json(200, { object: 'list', results: page, next_cursor, has_more });
    }
    let m = /^\/v1\/pages\/([^/]+)$/.exec(p);
    if (m) {
      const page = ws.pages.find((x) => x.id === m![1]);
      return page
        ? json(200, { object: 'page', id: page.id, properties: { Name: { type: 'title', title: richText(page.title) } } })
        : json(404, { object: 'error', code: 'object_not_found' });
    }
    m = /^\/v1\/blocks\/([^/]+)\/children$/.exec(p);
    if (m) {
      if (this.failingBlockIds.has(m[1]!)) return json(500, { object: 'error', code: 'internal_server_error' });
      const blocks = this.findBlocks(ws, m[1]!);
      if (!blocks) return json(404, { object: 'error', code: 'object_not_found' });
      const { page, next_cursor, has_more } = paginate(blocks, qp.get('start_cursor'), Number(qp.get('page_size') ?? 100));
      return json(200, {
        object: 'list',
        results: page.map((b) => ({
          object: 'block',
          id: b.id,
          type: 'paragraph',
          has_children: (b.children?.length ?? 0) > 0,
          paragraph: { rich_text: richText(b.text) },
        })),
        next_cursor,
        has_more,
      });
    }
    m = /^\/v1\/databases\/([^/]+)$/.exec(p);
    if (m) {
      const db = ws.databases.find((x) => x.id === m![1]);
      return db
        ? json(200, {
            object: 'database',
            id: db.id,
            title: richText(db.title),
            data_sources: db.dataSourceIds.map((id) => ({ id, name: ws.dataSources.find((d) => d.id === id)?.title })),
          })
        : json(404, { object: 'error', code: 'object_not_found' });
    }
    m = /^\/v1\/data_sources\/([^/]+)(\/query)?$/.exec(p);
    if (m) {
      const ds = ws.dataSources.find((x) => x.id === m![1]);
      if (!ds) return json(404, { object: 'error', code: 'object_not_found' });
      if (!m[2]) return json(200, { object: 'data_source', id: ds.id, title: richText(ds.title), properties: {} });
      const { page, next_cursor, has_more } = paginate(ds.rows, body.start_cursor as string, Number(body.page_size ?? 100));
      return json(200, {
        object: 'list',
        results: page.map((r) => ({ object: 'page', id: r.id, properties: { Name: { type: 'title', title: richText(r.title) } } })),
        next_cursor,
        has_more,
      });
    }
    return json(404, { object: 'error', code: 'invalid_request_url' });
  };
}
