import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { PerchError } from '../errors.js';
import { validateCimdOrigin, type Upstream } from '../upstream.js';
import type { OAuthState, Registration } from './state.js';

/**
 * OAuth clients of the public access (Spec §4). A client id only identifies a client; it never yields a
 * token by itself (tokens come only from a confirmed pairing).
 *
 * - CIMD: the client_id is an https URL. Built in are Claude's documents under https://claude.ai/oauth/… and
 *   https://claude.com/oauth/… (Claude Code's is https://claude.ai/oauth/claude-code-client-metadata); the
 *   official Codex document is https://chatgpt.com/oauth/codex/client.json. The operator may add exact URLs. Any other URL fails before network I/O.
 * - DCR (RFC 7591): only while a pairing window is open; the registration lives in that window only.
 * - Pre-registered: created locally (perch oauth client add).
 */
export const CODEX_CIMD = 'https://chatgpt.com/oauth/codex/client.json';
export const BUILTIN_CIMD = /^https:\/\/(?:claude\.(?:ai|com)\/oauth\/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*|chatgpt\.com\/oauth\/codex\/client\.json)$/;
/** Redirect hosts accepted for Claude's own documents (the hosted callback may move to claude.com). */
const CLAUDE_REDIRECT_HOSTS = new Set(['claude.ai', 'claude.com']);
const CIMD_CACHE_MS = 60 * 60 * 1000;
const CIMD_MAX_BYTES = 64 * 1024;
/** Spec §4: a metadata document must arrive within 5 s. */
const CIMD_TIMEOUT_MS = 5000;

export interface ResolvedClient {
  clientId: string;
  /** Shown on the consent page and in the terminal; for CIMD the host of the client_id URL. */
  displayName: string;
  /** Self-asserted name from the metadata (masked for display). */
  clientName: string;
  registration: Registration;
  redirectUris: string[];
}

/** Display-safe text: printable ASCII subset, bounded. */
export function maskText(s: string, max = 60): string {
  const t = s.replace(/[^A-Za-z0-9 ._:@()+-]/g, '').trim().slice(0, max);
  return t || 'unnamed client';
}

/** Validates a redirect URI for registration: https without fragment, or http loopback. */
export function validRedirectUri(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.hash || u.username || u.password || raw.length > 512) return false;
  if (u.protocol === 'https:') return /^[a-z0-9.-]+$/i.test(u.hostname) && !u.hostname.endsWith('.localhost');
  if (u.protocol === 'http:') return isLoopbackHost(u.hostname);
  return false;
}

const isLoopbackHost = (h: string) => h === '127.0.0.1' || h === '[::1]' || h === 'localhost';

/**
 * Exact match, except that loopback http URIs ignore the port (RFC 8252 §7.3; also for `localhost`, which
 * Claude Code declares). Scheme, host, path and query must match exactly.
 */
export function redirectMatches(registered: string, requested: string): boolean {
  if (registered === requested) return true;
  let a: URL;
  let b: URL;
  try {
    a = new URL(registered);
    b = new URL(requested);
  } catch {
    return false;
  }
  if (a.protocol !== 'http:' || b.protocol !== 'http:' || !isLoopbackHost(a.hostname)) return false;
  return a.hostname === b.hostname && a.pathname === b.pathname && a.search === b.search && !b.hash && !b.username && !b.password;
}

export const redirectHost = (uri: string) => {
  try {
    return new URL(uri).hostname;
  } catch {
    return '?';
  }
};

const CimdSchema = z.object({
  client_id: z.string(),
  client_name: z.string().max(200).optional(),
  redirect_uris: z.array(z.string()).min(1).max(10),
  token_endpoint_auth_method: z.string().optional(),
});

export interface DcrRegistration {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  createdAt: number;
}

export class ClientResolver {
  private readonly cache = new Map<string, { at: number; client: ResolvedClient }>();

  constructor(private readonly upstream: Upstream) {}

  /** True if `clientId` is a CIMD URL Perch may fetch (built in or added by the operator). No I/O. */
  static isAllowedCimd(clientId: string, state: OAuthState): boolean {
    return BUILTIN_CIMD.test(clientId) || state.cimdUrls.includes(clientId);
  }

  /**
   * Resolves a client id: pre-registered, DCR (only from the given window registrations), or an
   * allowlisted CIMD URL (fetched with fixed limits). Unknown ids throw before any network I/O.
   */
  async resolve(clientId: string, state: OAuthState, dcr: ReadonlyMap<string, DcrRegistration>): Promise<ResolvedClient> {
    const pre = state.preClients.find((c) => c.id === clientId);
    if (pre) return { clientId, displayName: maskText(pre.name), clientName: maskText(pre.name), registration: 'preregistered', redirectUris: pre.redirectUris };
    const reg = dcr.get(clientId);
    if (reg) return { clientId, displayName: maskText(reg.clientName), clientName: maskText(reg.clientName), registration: 'dcr', redirectUris: reg.redirectUris };
    if (!ClientResolver.isAllowedCimd(clientId, state)) throw new PerchError('Unknown OAuth client', 'unknown_oauth_client');
    const hit = this.cache.get(clientId);
    if (hit && Date.now() - hit.at < CIMD_CACHE_MS) return hit.client;
    const client = await this.fetchCimd(clientId);
    this.cache.set(clientId, { at: Date.now(), client });
    return client;
  }

  private async fetchCimd(clientId: string): Promise<ResolvedClient> {
    const url = new URL(clientId);
    const origin = validateCimdOrigin(clientId);
    if (url.search || url.hash || url.pathname.length > 200) throw new PerchError('Client metadata URL must not have a query or fragment', 'unknown_oauth_client');
    let doc: unknown;
    try {
      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new PerchError('timeout', 'upstream_timeout')), CIMD_TIMEOUT_MS);
      });
      try {
        doc = await Promise.race([this.upstream.json('cimd', { method: 'GET', path: url.pathname, origin, maxBytes: CIMD_MAX_BYTES }), timeout]);
      } finally {
        clearTimeout(timer);
      }
    } catch {
      throw new PerchError('The client metadata document could not be fetched', 'client_metadata_unavailable');
    }
    const parsed = CimdSchema.safeParse(doc);
    if (!parsed.success || parsed.data.client_id !== clientId) throw new PerchError('Invalid client metadata document', 'client_metadata_invalid');
    if (parsed.data.token_endpoint_auth_method !== undefined && parsed.data.token_endpoint_auth_method !== 'none') {
      throw new PerchError('Only public clients (token_endpoint_auth_method "none") are supported', 'client_metadata_invalid');
    }
    const builtin = BUILTIN_CIMD.test(clientId);
    const redirectUris = parsed.data.redirect_uris.filter((u) => {
      if (!validRedirectUri(u)) return false;
      const h = new URL(u);
      if (h.protocol === 'http:') return true; // loopback (native clients such as Claude Code)
      // Non-loopback redirects must stay on the client's own site (Claude's documents: claude.ai/claude.com).
      return builtin && clientId !== CODEX_CIMD ? CLAUDE_REDIRECT_HOSTS.has(h.hostname) : h.origin === origin;
    });
    if (!redirectUris.length) throw new PerchError('The client metadata document lists no acceptable redirect URI', 'client_metadata_invalid');
    return {
      clientId,
      displayName: url.hostname,
      clientName: maskText(parsed.data.client_name ?? url.hostname),
      registration: 'cimd',
      redirectUris,
    };
  }
}

/** Strict RFC 7591 registration body (Spec §4): only client_name and redirect_uris are used. */
export function parseDcrRequest(body: unknown): { clientName: string; redirectUris: string[] } {
  const bad = (why: string) => new PerchError(why, 'invalid_client_metadata');
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw bad('Registration must be a JSON object');
  const b = body as Record<string, unknown>;
  const uris = b.redirect_uris;
  if (!Array.isArray(uris) || uris.length < 1 || uris.length > 5 || !uris.every((u) => typeof u === 'string' && validRedirectUri(u))) {
    throw bad('redirect_uris must list 1 to 5 https URLs without fragment or http loopback URLs');
  }
  const method = b.token_endpoint_auth_method;
  if (method !== undefined && method !== 'none') throw bad('Only public clients (token_endpoint_auth_method "none") are supported');
  const name = typeof b.client_name === 'string' ? b.client_name : 'unnamed client';
  return { clientName: maskText(name), redirectUris: [...new Set(uris as string[])] };
}

export const newDcrClientId = () => `dcr-${randomBytes(8).toString('hex')}`;
export const newPreClientId = () => `pc-${randomBytes(8).toString('hex')}`;
