import { z } from 'zod';
import { PerchError } from '../../errors.js';
import type { SessionHttpRequest } from './contracts.js';
import type { MicrosoftIdentity, SelectedSite } from './model.js';

export interface SessionTransportConfig {
  outlookOrigin: string;
  chatBase: string;
  csaBase: string;
  substrateOrigin?: string;
  graphOrigin?: string;
  sites: readonly SelectedSite[];
}
export interface ResolvedSessionRequest {
  url: string;
  method: NonNullable<SessionHttpRequest['method']>;
  headers: Record<string, string>;
  body?: unknown;
  bodyBase64?: string;
  maxBytes: number;
  responseType: 'json' | 'bytes';
  /** The browser executor must enforce these values, including every redirect hop. */
  redirect: 'error';
  credentials: 'include' | 'omit';
  sendAuthorization: boolean;
}
const GRAPH_CHANNEL_PATH = /^\/v1\.0\/teams\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\/channels$/i;
const MAX_BYTES = 10 * 1024 * 1024;
const requestSchema = z.strictObject({
  resource: z.enum(['outlook', 'chat', 'csa', 'substrate', 'graph', 'sharepoint', 'download']),
  path: z.string().min(1).max(24_000),
  method: z.enum(['GET', 'POST', 'PATCH', 'PUT', 'DELETE']).default('GET'),
  query: z.record(z.string(), z.string()).optional(),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.unknown().optional(), bodyBase64: z.string().max(Math.ceil(MAX_BYTES / 3) * 4).optional(),
  siteId: z.string().regex(/^ms-site-[a-f0-9]{8}$/).optional(),
  maxBytes: z.number().int().min(1).max(MAX_BYTES).default(4 * 1024 * 1024),
  responseType: z.enum(['json', 'bytes']).default('json'),
});
const deny = (message = 'Microsoft session request is outside the allowed transport policy.'): never => { throw new PerchError(message, 'access_denied'); };
const controls = /[\u0000-\u0020\u007f]/;
/** Validate before URL parsing, which would otherwise normalize dot segments away. */
function safePath(path: string, allowOpaqueSlash = false): string {
  if (!path.startsWith('/') || path.startsWith('//') || /[\\?#\u0000-\u0020\u007f]/.test(path) || /%(?![a-fA-F0-9]{2})/.test(path)) return deny();
  if (!allowOpaqueSlash && /%2f/i.test(path)) return deny();
  let decoded: string;
  try { decoded = decodeURIComponent(path); } catch { return deny(); }
  // Opaque Outlook IDs may contain encoded '/', but no decoded routing syntax or
  // second encoding layer may turn an adapter path into a different endpoint.
  if (/[\\?#%\u0000-\u001f\u007f]/.test(decoded) || decoded.includes('//') || decoded.split('/').some((s) => s === '.' || s === '..')) return deny();
  return path;
}
function secureUrl(value: string): URL {
  if (value.length > 24_000 || controls.test(value) || value.includes('\\')) return deny();
  const raw = value.match(/^https:\/\/([^/?#]+)([^?#]*)(?:\?[^#]*)?(?:#.*)?$/);
  if (!raw) return deny();
  safePath(raw[2] || '/');
  let url: URL;
  try { url = new URL(value); } catch { return deny(); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash) return deny();
  return url;
}
function origin(value: string, hosts: readonly string[]): string {
  const url = secureUrl(value);
  if (!hosts.includes(url.hostname) || (url.pathname !== '/' && url.pathname !== '') || url.search) return deny();
  return url.origin;
}
function teamsBase(value: string, kind: 'chatsvc' | 'csa'): string {
  const url = secureUrl(value);
  if (!['teams.microsoft.com', 'teams.cloud.microsoft'].includes(url.hostname) || url.search || !new RegExp(`^/api/${kind}/[a-z][a-z0-9-]{0,31}/?$`).test(url.pathname)) return deny();
  return `${url.origin}${url.pathname.replace(/\/$/, '')}`;
}
export function normalizeSelectedSiteUrl(value: string): string {
  const url = secureUrl(value);
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.sharepoint\.(?:com|de)$/.test(url.hostname) || url.search || url.pathname.length > 2048) return deny('Selected site must be a direct HTTPS SharePoint site URL.');
  return `${url.origin}${url.pathname.replace(/\/$/, '')}`;
}
function selected(config: SessionTransportConfig, id: string | undefined): { site: SelectedSite; base: string } {
  if (!id) return deny('A selected site ID is required for file requests.');
  const matches = config.sites.filter((site) => site.id === id);
  if (matches.length !== 1) return deny('The requested file site is not uniquely selected.');
  const site = matches[0]!;
  return { site, base: normalizeSelectedSiteUrl(site.url) };
}
function permittedPath(resource: SessionHttpRequest['resource'], path: string, method: string): boolean {
  switch (resource) {
    case 'outlook': return /^(?:\/api\/v2\.0\/me)(?:\/|$)/.test(path) && ['GET', 'POST', 'PATCH'].includes(method);
    case 'chat': return /^\/v1\/users\/ME(?:\/|$)/.test(path) && ['GET', 'POST'].includes(method);
    case 'csa': return path === '/api/v3/teams/users/me' && method === 'GET';
    case 'substrate': return (path === '/searchservice/api/v2/query' && method === 'POST') || (/^\/AllFiles\/api\/users\('[^/]*'\)\/AllShared$/.test(path) && method === 'GET');
    case 'graph': return (['/v1.0/me', '/v1.0/me/drives', '/v1.0/me/followedSites', '/v1.0/sites', '/v1.0/me/joinedTeams'].includes(path) || GRAPH_CHANNEL_PATH.test(path)) && method === 'GET';
    case 'sharepoint': {
      if (path === '/_api/web/currentuser' || path === '/_api/v2.0/drives') return method === 'GET';
      const drive = '/_api/v2\\.0/drives/[^/]+';
      if (new RegExp(`^${drive}$`).test(path)) return method === 'GET';
      if (new RegExp(`^${drive}/(?:root|items/[^/]+)$`).test(path)) return ['GET', 'PATCH', 'DELETE'].includes(method);
      if (new RegExp(`^${drive}/(?:root|items/[^/]+)/children$`).test(path)) return ['GET', 'POST'].includes(method);
      if (new RegExp(`^${drive}/items/[^/]+/content$`).test(path)) return method === 'PUT';
      if (new RegExp(`^${drive}/(?:root|items/[^/]+):/[^/]+:/content$`).test(path)) return method === 'PUT';
      return new RegExp(`^${drive}/root/search\\(q='[^/]*'\\)$`).test(path) && method === 'GET';
    }
    case 'download': return false;
  }
}
const queryKeys: Record<SessionHttpRequest['resource'], readonly string[]> = {
  outlook: ['$top', '$select', '$search', '$filter', '$orderby', '$skip', '$skiptoken', 'startDateTime', 'endDateTime'],
  chat: ['view', 'pageSize', 'startTime', 'endTime', 'syncState'],
  csa: ['isPrefetch', 'enableMembershipSummary'],
  substrate: ['ThreadId', 'ItemTypes', 'PageSize', '$skiptoken'],
  graph: ['$select', '$top', '$skiptoken', '$skipToken', 'search'],
  sharepoint: ['$select', '$top', '$skiptoken', '$skipToken', '@microsoft.graph.conflictBehavior'],
  download: [],
};
function headers(input: Record<string, string> | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  const seen = new Set<string>();
  for (const [key, value] of Object.entries(input ?? {})) {
    const lower = key.toLowerCase();
    if (seen.has(lower) || !['accept', 'content-type', 'if-match', 'prefer', 'x-ms-client-version'].includes(lower) || value.length > 2048 || /[\u0000-\u001f\u007f]/.test(value)) return deny('Unsafe headers are not allowed in a session request.');
    seen.add(lower); result[key] = value;
  }
  return result;
}
/** Pure routing policy. DNS/private-address rejection and redirect blocking also
 * belong in the executor; this helper does not make any network requests. */
export function resolveSessionRequest(config: SessionTransportConfig, request: SessionHttpRequest): ResolvedSessionRequest {
  const parsed = requestSchema.safeParse(request);
  if (!parsed.success) return deny('Invalid or unbounded Microsoft session request.');
  const input = parsed.data;
  const outputHeaders = headers(input.headers);
  if ((input.body !== undefined && input.bodyBase64 !== undefined) || (input.method === 'GET' && (input.body !== undefined || input.bodyBase64 !== undefined))) return deny();
  if (input.bodyBase64 !== undefined && (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(input.bodyBase64) || Buffer.from(input.bodyBase64, 'base64').toString('base64') !== input.bodyBase64 || Buffer.from(input.bodyBase64, 'base64').length > MAX_BYTES)) return deny('Invalid or oversized binary request body.');
  if (input.body !== undefined) {
    try { const serialized = JSON.stringify(input.body); if (serialized === undefined || Buffer.byteLength(serialized) > MAX_BYTES) return deny(); }
    catch { return deny('Invalid or oversized JSON request body.'); }
  }
  let url: URL;
  if (input.resource === 'download') {
    const { base } = selected(config, input.siteId);
    url = secureUrl(input.path);
    const site = new URL(base);
    const sitePath = site.pathname.replace(/\/$/, '');
    const paths = [`${sitePath}/_layouts/15/download.aspx`, `${sitePath}/download.aspx`, '/_layouts/15/download.aspx'];
    if (url.origin !== site.origin || !paths.includes(url.pathname) || input.method !== 'GET' || input.query || Object.keys(outputHeaders).length) return deny('Download URL or request is outside the selected site policy.');
  } else {
    safePath(input.path, input.resource === 'outlook');
    if (!permittedPath(input.resource, input.path, input.method)) return deny();
    let base: string;
    switch (input.resource) {
      case 'outlook': base = origin(config.outlookOrigin, ['outlook.office.com', 'outlook.live.com', 'outlook.cloud.microsoft']); break;
      case 'chat': base = teamsBase(config.chatBase, 'chatsvc'); break;
      case 'csa': base = teamsBase(config.csaBase, 'csa'); break;
      case 'substrate': base = origin(config.substrateOrigin ?? 'https://substrate.office.com', ['substrate.office.com']); break;
      case 'graph': base = origin(config.graphOrigin ?? 'https://graph.microsoft.com', ['graph.microsoft.com']); break;
      case 'sharepoint': base = selected(config, input.siteId).base; break;
    }
    url = new URL(`${base}${input.path}`);
    const entries = Object.entries(input.query ?? {});
    if (entries.length > 32) return deny();
    if (input.resource === 'graph' && (input.path === '/v1.0/me/joinedTeams' || GRAPH_CHANNEL_PATH.test(input.path))) {
      let hasToken = false;
      for (const [key, value] of entries) {
        if (key === '$select' && GRAPH_CHANNEL_PATH.test(input.path) && value === 'id,displayName,description,membershipType') continue;
        if (!['$skiptoken', '$skipToken'].includes(key) || hasToken || !value || value.length > 8000) return deny();
        hasToken = true;
      }
    }
    for (const [key, value] of entries) {
      if (!queryKeys[input.resource].includes(key) || value.length > 16_384 || /[\u0000-\u001f\u007f]/.test(value)) return deny();
      url.searchParams.set(key, value);
    }
  }
  if (url.href.length > 32_768) return deny();
  return { url: url.href, method: input.method, headers: outputHeaders,
    ...(input.body !== undefined ? { body: input.body } : {}), ...(input.bodyBase64 !== undefined ? { bodyBase64: input.bodyBase64 } : {}),
    maxBytes: input.maxBytes, responseType: input.responseType, redirect: 'error',
    credentials: input.resource === 'download' ? 'omit' : 'include', sendAuthorization: input.resource !== 'download' };
}

export interface ParsedSessionToken {
  identity: MicrosoftIdentity;
  expiresAt: number;
  audience: string;
  signatureVerified: false;
}
export interface SessionTokenParseOptions { expected?: MicrosoftIdentity; nowSeconds?: number; audiences?: readonly string[] }
/** Decode only a token already observed at a trusted browser API. This does NOT
 * authenticate a JWT or verify its signature. The caller must confirm the same
 * immutable identity against the service API before registering/using a session.
 * https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference
 */
export function parseUnverifiedSessionToken(token: string, options: SessionTokenParseOptions = {}): ParsedSessionToken {
  const invalid = (): never => { throw new PerchError('Microsoft session token does not contain a usable immutable identity.', 'identity_mismatch'); };
  let claims: Record<string, unknown>;
  try {
    if (typeof token !== 'string' || token.length > 65_536) return invalid();
    const segments = token.split('.');
    if (segments.length !== 3 || segments.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) return invalid();
    const header = JSON.parse(Buffer.from(segments[0]!, 'base64url').toString('utf8'));
    if (!header || typeof header !== 'object' || !['RS256', 'PS256'].includes(header.alg)) return invalid();
    const parsed: unknown = JSON.parse(Buffer.from(segments[1]!, 'base64url').toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return invalid();
    claims = parsed as Record<string, unknown>;
  } catch { return invalid(); }
  if (!z.string().uuid().safeParse(claims.tid).success || !z.string().uuid().safeParse(claims.oid).success || typeof claims.aud !== 'string' || !claims.aud || claims.aud.length > 2048 || controls.test(claims.aud)) return invalid();
  const now = options.nowSeconds ?? Date.now() / 1000;
  if (!Number.isFinite(now) || typeof claims.exp !== 'number' || !Number.isSafeInteger(claims.exp) || claims.exp <= now || (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || !Number.isSafeInteger(claims.nbf) || claims.nbf > now))) throw new PerchError('Microsoft session token is expired or not yet valid.', 'reauth_required');
  const tenantId = (claims.tid as string).toLowerCase();
  const objectId = (claims.oid as string).toLowerCase();
  if (options.expected && (options.expected.tenantId.toLowerCase() !== tenantId || options.expected.objectId.toLowerCase() !== objectId)) return invalid();
  if (options.audiences && !options.audiences.includes(claims.aud)) throw new PerchError('Microsoft session token has an unexpected audience.', 'access_denied');
  return { identity: { tenantId, objectId, kind: tenantId === '9188040d-6c67-4c5b-b112-36a304b66dad' ? 'personal' : 'organization' }, expiresAt: claims.exp, audience: claims.aud, signatureVerified: false };
}
