import { PerchError } from '../../errors.js';
import { newAccountId } from '../../ids.js';
import { checkedJson, type SessionHttp } from './contracts.js';
import type { SelectedSite } from './model.js';
import { normalizeSelectedSiteUrl } from './policy.js';

export interface DiscoverySource {
  source: 'onedrive' | 'followed' | 'search';
  status: 'complete' | 'partial' | 'unavailable';
  code?: string;
}
const sources = [
  { source: 'onedrive', path: '/v1.0/me/drives', query: {} },
  { source: 'followed', path: '/v1.0/me/followedSites', query: {} },
  { source: 'search', path: '/v1.0/sites', query: { search: '*' } },
] as const;
const fail = (): never => { throw new PerchError('Invalid Microsoft discovery response.', 'invalid_response'); };

/** Accept site roots from API metadata, never sharing links, guessed tenants or query strings. */
function siteRoot(raw: unknown, drive: boolean): string {
  if (typeof raw !== 'string') return fail();
  const normalized = normalizeSelectedSiteUrl(raw); // validate raw dot segments before URL normalization
  const url = new URL(normalized);
  if (drive) {
    const personal = url.pathname.match(/^\/personal\/[^/]+(?:\/|$)/);
    if (personal) url.pathname = personal[0].replace(/\/$/, '');
    else if (!/^\/(?:sites|teams)\/[^/]+$/.test(url.pathname) && url.pathname !== '/') return fail();
  }
  if (url.pathname.includes('/_') || /\/Forms\//i.test(url.pathname)) return fail();
  return normalizeSelectedSiteUrl(url.href);
}
function nextQuery(raw: unknown, path: string, initial: Record<string, string>): Record<string, string> {
  if (typeof raw !== 'string' || raw.length > 16_384 || /[\\\u0000-\u0020]/.test(raw)) return fail();
  const url = new URL(raw);
  if (url.origin !== 'https://graph.microsoft.com' || url.username || url.password || url.hash || url.pathname !== path) return fail();
  const query: Record<string, string> = { ...initial };
  const seen = new Set<string>();
  for (const [key, value] of url.searchParams) {
    if (seen.has(key) || !['$top', '$skiptoken', '$skipToken', 'search'].includes(key) || !value || value.length > 8192 || /[\u0000-\u001f]/.test(value)) return fail();
    if ((key === '$top' || key === 'search') && value !== initial[key]) return fail();
    seen.add(key); query[key] = value;
  }
  if (!seen.has('$skiptoken') && !seen.has('$skipToken')) return fail();
  return query;
}

/** Only called after the worker has verified the signed-in identity. No new consent or token refresh. */
export async function discoverSessionSites(request: SessionHttp, existing: readonly SelectedSite[], now = Date.now): Promise<{ sites: SelectedSite[]; sources: DiscoverySource[] }> {
  const sites = structuredClone([...existing]);
  const results: DiscoverySource[] = [];
  const deadline = now() + 45_000;
  for (const entry of sources) {
    const status: DiscoverySource = { source: entry.source, status: 'complete' };
    results.push(status);
    const initial: Record<string, string> = { '$top': '100', ...entry.query };
    let query = initial;
    const seen = new Set<string>();
    try {
      for (let page = 0; page < 5; page++) {
        if (now() >= deadline || sites.length >= 100) { status.status = 'partial'; status.code = 'discovery_limit'; break; }
        const key = JSON.stringify(query);
        if (seen.has(key)) { status.status = 'partial'; status.code = 'repeated_page'; break; }
        seen.add(key);
        const data = checkedJson(await request({ resource: 'graph', path: entry.path, query, maxBytes: 2 * 1024 * 1024 }));
        if (!Array.isArray(data.value) || data.value.length > 100) fail();
        for (const item of data.value) {
          try {
            const url = siteRoot(item?.sharepointIds?.siteUrl ?? item?.webUrl, entry.source === 'onedrive' && !item?.sharepointIds?.siteUrl);
            if (sites.some(s => s.url === url)) continue;
            if (sites.length >= 100) { status.status = 'partial'; status.code = 'discovery_limit'; break; }
            sites.push({ id: newAccountId('ms-site', sites.map(s => s.id)), url, kind: new URL(url).hostname.includes('-my.sharepoint.') ? 'onedrive' : 'sharepoint', driveIds: [], autoDiscoverLibraries: true,
              ...(typeof item.displayName === 'string' && item.displayName.length <= 300 && !/[\u0000-\u001f]/.test(item.displayName) ? { displayName: item.displayName } : {}) });
          } catch { status.status = 'partial'; status.code = 'unsupported_site'; }
        }
        if (!data['@odata.nextLink']) break;
        query = nextQuery(data['@odata.nextLink'], entry.path, initial);
        if (page === 4) { status.status = 'partial'; status.code = 'discovery_limit'; }
      }
    } catch (error) {
      if (error instanceof PerchError && error.code === 'identity_mismatch') throw error;
      status.status = seen.size > 1 || (error instanceof PerchError && error.code === 'invalid_response') ? 'partial' : 'unavailable';
      status.code = error instanceof PerchError ? error.code : 'invalid_response';
    }
  }
  return { sites, sources: results };
}
