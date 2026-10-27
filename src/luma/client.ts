import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport, StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { PerchError } from '../errors.js';
import { PERCH_VERSION } from '../version.js';
import { LUMA_MCP_URL } from './oauth.js';

/**
 * MCP client towards the official Luma MCP server. All traffic goes through `guardedLumaFetch`: only
 * https://mcp.luma.com/ (the MCP endpoint), never a redirect, a hard timeout and a response size cap. Tests inject a fetch
 * that serves a MOCK Luma server; production uses the global fetch behind the same guard.
 */
export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

export const LUMA_TIMEOUT_MS = 30_000;
export const LUMA_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

export function guardedLumaFetch(base: FetchLike = (i, init) => fetch(i, init)): FetchLike {
  return async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input.toString());
    if (url.toString().split('?')[0] !== LUMA_MCP_URL) throw new PerchError('Blocked a Luma request outside https://mcp.luma.com/', 'route_not_allowed');
    // Perch needs no server-initiated messages: the optional standalone SSE stream (GET) is never opened.
    if ((init?.method ?? 'GET').toUpperCase() === 'GET') return new Response(null, { status: 405 });
    const signal = init?.signal ? AbortSignal.any([init.signal, AbortSignal.timeout(LUMA_TIMEOUT_MS)]) : AbortSignal.timeout(LUMA_TIMEOUT_MS);
    let res: Response;
    try {
      res = await base(url, { ...init, redirect: 'error', signal });
    } catch (err) {
      if (err instanceof PerchError) throw err;
      throw new PerchError('Luma MCP server unreachable or timed out', 'upstream_unreachable');
    }
    // Read the body with a cap (MCP over HTTP answers each request; SSE streams end with the response).
    const reader = res.body?.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > LUMA_MAX_RESPONSE_BYTES) {
          await reader.cancel().catch(() => {});
          throw new PerchError('Luma response exceeds the size limit', 'response_too_large');
        }
        chunks.push(value);
      }
    }
    return new Response(chunks.length || res.body ? Buffer.concat(chunks) : null, { status: res.status, statusText: res.statusText, headers: res.headers });
  };
}

export interface LumaTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface LumaCallResult {
  isError: boolean;
  /** Text content joined (Luma answers with JSON text); parsed when it is JSON. */
  data: unknown;
}

/** One MCP session per operation (initialize, work, close): no long-lived state towards Luma. */
export class LumaMcp {
  constructor(private readonly fetchImpl: FetchLike = guardedLumaFetch()) {}

  /**
   * Errors: `luma_unauthorized` (HTTP 401: nothing was processed), `luma_not_sent` (failed before the work
   * request was sent, e.g. during initialize), `luma_failed` (failed after it may have been processed).
   */
  private async session<T>(accessToken: string, fn: (c: Client) => Promise<T>): Promise<T> {
    const transport = new StreamableHTTPClientTransport(new URL(LUMA_MCP_URL), {
      fetch: this.fetchImpl,
      requestInit: { headers: { authorization: `Bearer ${accessToken}` } },
    });
    const client = new Client({ name: 'perch', version: PERCH_VERSION });
    let connected = false;
    try {
      await client.connect(transport);
      connected = true;
      return await fn(client);
    } catch (err) {
      if (err instanceof PerchError && err.code !== 'upstream_unreachable') throw err;
      if (err instanceof StreamableHTTPError && err.code === 401) throw new PerchError('Luma rejected the access token', 'luma_unauthorized');
      if (!connected) throw new PerchError('Could not reach the Luma MCP server; nothing was sent', 'luma_not_sent');
      throw new PerchError('The Luma MCP request failed', 'luma_failed');
    } finally {
      await client.close().catch(() => {});
    }
  }

  async listTools(accessToken: string): Promise<LumaTool[]> {
    return this.session(accessToken, async (c) => {
      const out: LumaTool[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < 10; page++) {
        const r = await c.listTools(cursor ? { cursor } : {});
        for (const t of r.tools) out.push({ name: t.name, ...(t.description ? { description: t.description.slice(0, 4000) } : {}), inputSchema: t.inputSchema as Record<string, unknown> });
        if (!r.nextCursor) break;
        cursor = r.nextCursor;
      }
      return out;
    });
  }

  async callTool(accessToken: string, name: string, args: Record<string, unknown>): Promise<LumaCallResult> {
    return this.session(accessToken, async (c) => {
      const r = (await c.callTool({ name, arguments: args })) as { isError?: boolean; content?: Array<{ type: string; text?: string }>; structuredContent?: unknown };
      const text = (r.content ?? [])
        .filter((x) => x.type === 'text' && typeof x.text === 'string')
        .map((x) => x.text)
        .join('\n');
      let data: unknown = r.structuredContent ?? text;
      if (r.structuredContent === undefined) {
        try {
          data = JSON.parse(text);
        } catch {
          data = text;
        }
      }
      return { isError: r.isError === true, data };
    });
  }
}
