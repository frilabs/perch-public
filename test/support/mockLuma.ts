// MOCK Luma: an MCP server on 127.0.0.1 that serves Luma-like tools with JSON schemas (shapes taken from the
// official Luma MCP tool list), plus a MOCK OAuth authorization server behind the Upstream transport. Nothing
// here talks to Luma; every token is generated dummy data.
import { randomBytes } from 'node:crypto';
import { createServer, type Server as HttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { FetchLike } from '../../src/luma/client.js';
import type { UpstreamRequest, UpstreamResponse, UpstreamTransport } from '../../src/upstream.js';

const D7 = 'http://json-schema.org/draft-07/schema#';
const str = (description?: string) => ({ type: 'string', ...(description ? { description } : {}) });

export function lumaTools(): Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> {
  return [
    { name: 'get_self', description: 'Get the authenticated user.', inputSchema: { type: 'object', properties: {} } },
    {
      name: 'list_events',
      description: 'List events you are hosting or attending. Paginated.',
      inputSchema: { $schema: D7, type: 'object', properties: { after: { type: 'string', format: 'date-time' }, cursor: str(), limit: { type: 'integer', minimum: 1, maximum: 50 }, period: { type: 'string', enum: ['future', 'past'] } } },
    },
    { name: 'get_event', description: 'Get information for an event.', inputSchema: { $schema: D7, type: 'object', properties: { event_id: str('Event ID, evt-') }, required: ['event_id'] } },
    {
      name: 'list_guests',
      description: 'List guests of an event you manage. Paginated.',
      inputSchema: {
        $schema: D7,
        type: 'object',
        properties: { approval_status: { type: 'string', enum: ['approved', 'session', 'pending_approval', 'invited', 'declined', 'waitlist'] }, cursor: str(), event_id: str(), limit: { type: 'integer' }, query: str() },
        required: ['event_id'],
      },
    },
    {
      name: 'create_event',
      description: 'Create an event on a calendar you manage.',
      inputSchema: {
        $schema: D7,
        type: 'object',
        properties: {
          calendar_id: str(),
          name: str(),
          start_at: { type: 'string', format: 'date-time' },
          timezone: str(),
          cover_url: { type: 'string', format: 'starts_with', pattern: '^https:\\/\\/images\\.lumacdn\\.com\\/.*' },
          visibility: { type: 'string', enum: ['public', 'members-only', 'private'] },
          // Added by Luma, live 2026-10-27.
          feedback_email: { type: 'object', properties: { enabled: { type: 'boolean' }, delay: str() }, required: ['enabled'] },
        },
        required: ['name', 'start_at', 'timezone'],
      },
    },
    {
      name: 'update_event',
      description: 'Update an event you manage.',
      inputSchema: { $schema: D7, type: 'object', properties: { event_id: str(), name: str(), email_guests: { type: 'boolean' } }, required: ['event_id'] },
    },
    {
      name: 'invite_guests',
      description: 'Email invites to up to 100 guests.',
      inputSchema: {
        $schema: D7,
        type: 'object',
        properties: {
          event_id: str(),
          guests: { type: 'array', minItems: 1, maxItems: 100, items: { type: 'object', properties: { email: { type: 'string', format: 'email' }, name: { type: ['string', 'null'] } }, required: ['email'] } },
          message: { type: 'string', maxLength: 200 },
        },
        required: ['event_id', 'guests'],
      },
    },
    {
      name: 'update_guest_status',
      description: 'Approve, decline, waitlist a guest.',
      inputSchema: {
        $schema: D7,
        type: 'object',
        properties: { event_id: str(), guest_id: str(), status: { type: 'string', enum: ['approved', 'declined', 'pending_approval', 'waitlist'] }, should_refund: { type: 'boolean' }, send_email: { type: 'boolean' } },
        required: ['event_id', 'guest_id', 'status'],
      },
    },
    {
      name: 'create_blast',
      description: 'Email a message to the guests of an event you manage.',
      inputSchema: {
        $schema: D7,
        type: 'object',
        properties: {
          content_md: { type: 'string', minLength: 1 },
          event_id: str(),
          recipient_groups: { type: 'array', minItems: 1, items: { type: 'object', properties: { status: { type: 'string', enum: ['approved', 'checked_in', 'pending_approval', 'waitlist', 'invited'] }, ticket_type_id: { type: ['string', 'null'] } }, required: ['status'] } },
          subject: { anyOf: [{ type: 'string', maxLength: 200 }, { type: 'null' }] },
        },
        required: ['event_id', 'content_md'],
      },
    },
    // Never passed through by Perch:
    { name: 'delete_event', description: 'Delete an event.', inputSchema: { type: 'object', properties: { event_id: str() }, required: ['event_id'] } },
    { name: 'add_host', description: 'Add a co-host.', inputSchema: { type: 'object', properties: { event_id: str(), email: str() }, required: ['event_id', 'email'] } },
  ];
}

export interface MockLuma {
  origin: string;
  /** Every tools/call: [tool, args]. */
  calls: Array<[string, Record<string, unknown>]>;
  tools: ReturnType<typeof lumaTools>;
  /** Guests per event and status. */
  guests: Map<string, Array<{ api_id: string; email: string; approval_status: string }>>;
  validTokens: Set<string>;
  /** Make the next tools/call throw a transport-level failure (connection dropped after receipt). */
  dropNextCall: boolean;
  fetch: FetchLike;
  close(): Promise<void>;
}

export async function startMockLuma(): Promise<MockLuma> {
  const state = {
    calls: [] as Array<[string, Record<string, unknown>]>,
    tools: lumaTools(),
    guests: new Map<string, Array<{ api_id: string; email: string; approval_status: string }>>(),
    validTokens: new Set<string>(),
    dropNextCall: false,
  };
  const build = () => {
    const s = new Server({ name: 'mock-luma', version: '0' }, { capabilities: { tools: {} } });
    s.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: state.tools }));
    s.setRequestHandler(CallToolRequestSchema, async (req) => {
      const name = req.params.name;
      const args = (req.params.arguments ?? {}) as Record<string, unknown>;
      state.calls.push([name, args]);
      const ok = (v: unknown) => ({ content: [{ type: 'text', text: JSON.stringify(v) }] });
      if (name === 'get_self') return ok({ user: { api_id: 'usr-mock0001', name: 'Mock Operator', email: 'operator@example.test' } });
      if (name === 'list_events') return ok({ entries: [{ api_id: 'evt-1', name: 'Mock event' }], has_more: false });
      if (name === 'get_event') return args.event_id === 'evt-missing' ? { isError: true, content: [{ type: 'text', text: 'Event not found' }] } : ok({ event: { api_id: args.event_id } });
      if (name === 'list_guests') {
        const all = (state.guests.get(String(args.event_id)) ?? []).filter((g) => !args.approval_status || g.approval_status === args.approval_status);
        const start = args.cursor ? Number(args.cursor) : 0;
        const page = all.slice(start, start + 2);
        const next = start + 2 < all.length ? String(start + 2) : undefined;
        return ok({ entries: page.map((g) => ({ guest: g })), has_more: next !== undefined, ...(next ? { next_cursor: next } : {}) });
      }
      if (name === 'create_event') return ok({ event: { api_id: 'evt-new', name: args.name } });
      if (name === 'create_blast') return ok({ blast: { api_id: 'blast-1', status: 'scheduled' } });
      return ok({ ok: true, tool: name });
    });
    return s;
  };
  const http: HttpServer = createServer(async (req, res) => {
    const auth = String(req.headers.authorization ?? '');
    const token = auth.replace(/^Bearer /, '');
    if (!state.validTokens.has(token)) {
      res.writeHead(401, { 'www-authenticate': 'Bearer resource_metadata="https://mcp.luma.com/.well-known/oauth-protected-resource"' }).end();
      return;
    }
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : undefined;
    if (state.dropNextCall && body?.method === 'tools/call') {
      state.dropNextCall = false;
      state.calls.push([String(body.params?.name), body.params?.arguments ?? {}]);
      req.socket.destroy();
      return;
    }
    const server = build();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  });
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  const mock: MockLuma = {
    origin,
    ...state,
    get dropNextCall() {
      return state.dropNextCall;
    },
    set dropNextCall(v: boolean) {
      state.dropNextCall = v;
    },
    fetch: (input, init) => {
      const u = new URL(typeof input === 'string' ? input : input.toString());
      return fetch(`${origin}${u.pathname}${u.search}`, init);
    },
    close: () =>
      new Promise((r) => {
        http.closeAllConnections();
        http.close(() => r());
      }),
  };
  // keep arrays shared with the server state
  mock.calls = state.calls;
  mock.guests = state.guests;
  mock.validTokens = state.validTokens;
  Object.defineProperty(mock, 'tools', { get: () => state.tools, set: (v) => (state.tools = v) });
  return mock;
}

export const AUTH_ORIGIN = 'https://auth.luma.com';

export interface MockLumaAuth {
  transport: UpstreamTransport;
  calls: string[];
  /** CIMD supported. */
  cimd: boolean;
  /** Dynamic Client Registration offered (Perch prefers it, Spec §3). */
  dcr: boolean;
  registered: string[];
  /** Refresh tokens currently valid (rotated on use). */
  refreshTokens: Set<string>;
  failRefresh: boolean;
  /** Override the issuer the protected resource metadata names. */
  issuer: string;
}

/** OAuth metadata + token endpoint; issues access tokens that the MOCK MCP server accepts. */
export function mockLumaAuth(mcp: MockLuma): MockLumaAuth {
  const json = (status: number, body: unknown): UpstreamResponse => ({ status, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(body)) });
  const a: MockLumaAuth = {
    calls: [],
    cimd: true,
    dcr: true,
    registered: [],
    refreshTokens: new Set(),
    failRefresh: false,
    issuer: AUTH_ORIGIN,
    transport: async (req: UpstreamRequest) => {
      a.calls.push(`${req.method} ${req.url.origin}${req.url.pathname}`);
      const path = `${req.url.origin}${req.url.pathname}`;
      if (path === 'https://mcp.luma.com/.well-known/oauth-protected-resource') {
        return json(200, { resource: 'https://mcp.luma.com/', authorization_servers: [a.issuer], scopes_supported: ['mcp'] });
      }
      if (path === `${AUTH_ORIGIN}/.well-known/oauth-authorization-server`) {
        return json(200, {
          issuer: AUTH_ORIGIN,
          authorization_endpoint: `${AUTH_ORIGIN}/oauth/authorize?credential_type=personal`,
          token_endpoint: `${AUTH_ORIGIN}/oauth/token`,
          ...(a.dcr ? { registration_endpoint: `${AUTH_ORIGIN}/oauth/register` } : {}),
          revocation_endpoint: `${AUTH_ORIGIN}/oauth/revoke`,
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['none'],
          scopes_supported: ['mcp', 'offline_access'],
          ...(a.cimd ? { client_id_metadata_document_supported: true } : {}),
        });
      }
      if (path === `${AUTH_ORIGIN}/oauth/register` && req.method === 'POST') {
        const id = `dcr-client-${randomBytes(4).toString('hex')}`;
        a.registered.push(JSON.parse(req.body ?? '{}').redirect_uris?.[0]);
        return json(201, { client_id: id });
      }
      if (path === `${AUTH_ORIGIN}/oauth/token` && req.method === 'POST') {
        const form = new URLSearchParams(req.body ?? '');
        const issue = () => {
          const access = `luma-at-${randomBytes(12).toString('hex')}`;
          const refresh = `luma-rt-${randomBytes(12).toString('hex')}`;
          mcp.validTokens.add(access);
          a.refreshTokens.add(refresh);
          return json(200, { access_token: access, refresh_token: refresh, expires_in: 3600, token_type: 'Bearer', scope: 'mcp offline_access' });
        };
        if (form.get('grant_type') === 'authorization_code') {
          if (!form.get('code_verifier') || form.get('resource') !== 'https://mcp.luma.com/') return json(400, { error: 'invalid_request' });
          return issue();
        }
        if (form.get('grant_type') === 'refresh_token') {
          const rt = form.get('refresh_token') ?? '';
          if (a.failRefresh || !a.refreshTokens.has(rt)) return json(400, { error: 'invalid_grant' });
          a.refreshTokens.delete(rt);
          return issue();
        }
      }
      if (path === `${AUTH_ORIGIN}/oauth/revoke`) return json(200, {});
      return json(404, { error: 'not_found' });
    },
  };
  return a;
}
