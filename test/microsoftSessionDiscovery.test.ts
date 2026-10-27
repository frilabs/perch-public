import { describe, expect, it } from 'vitest';
import { discoverSessionSites } from '../src/microsoft/session/discovery.js';
import { resolveSessionRequest } from '../src/microsoft/session/policy.js';
import type { SessionHttp, SessionHttpRequest } from '../src/microsoft/session/contracts.js';

const response = (body: unknown, status = 200) => ({ status, headers: {}, body: Buffer.from(JSON.stringify(body)) });
const site = 'https://tenant.sharepoint.com/sites/Team';
const own = 'https://tenant-my.sharepoint.com/personal/self_example_org';
const config = { outlookOrigin: 'https://outlook.office.com', csaBase: '', chatBase: '', sites: [] };
describe('authenticated session site discovery', () => {
  it('collects own drive and accessible sites, deduplicates and preserves stored identities', async () => {
    const calls: SessionHttpRequest[] = [];
    const request: SessionHttp = async r => { calls.push(r); resolveSessionRequest(config, r);
      if (r.path === '/v1.0/me/drives') return response({ value: [{ webUrl: `${own}/Documents`, sharepointIds: { siteUrl: own } }] });
      return response({ value: [{ webUrl: site, displayName: 'Team' }] });
    };
    const previous = { id: 'ms-site-12345678', url: site, kind: 'sharepoint' as const, driveIds: ['chosen'] };
    const result = await discoverSessionSites(request, [previous]);
    expect(result.sites).toHaveLength(2);
    expect(result.sites[0]).toEqual(previous);
    expect(result.sites[1]).toMatchObject({ url: own, kind: 'onedrive', driveIds: [] });
    expect(result.sources.every(s => s.status === 'complete')).toBe(true);
    expect(calls.every(r => !r.method || r.method === 'GET')).toBe(true);
    expect(calls.map(r => r.path)).not.toContain('/v1.0/me/drive'); // no implicit OneDrive provisioning
  });
  it('continues other sources after denial and excludes unsafe or ambiguous site URLs', async () => {
    const result = await discoverSessionSites(async r => r.path === '/v1.0/me/drives' ? response({}, 403) : response({ value: [
      { webUrl: site }, { webUrl: 'https://tenant.sharepoint.com.evil.test/sites/Team' },
      { webUrl: 'https://tenant.sharepoint.com/sites/Team?secret=hidden' },
      { webUrl: 'https://tenant.sharepoint.com/sites/Team/../Other' },
    ] }), []);
    expect(result.sites.map(s => s.url)).toEqual([site]);
    expect(result.sources[0]).toMatchObject({ status: 'unavailable', code: 'access_denied' });
    expect(JSON.stringify(result)).not.toContain('secret=hidden');
    expect(result.sources.some(s => s.status === 'partial')).toBe(true);
  });
  it('follows only same-endpoint bounded cursors and reports repeated pages as partial', async () => {
    const requests: SessionHttpRequest[] = [];
    const result = await discoverSessionSites(async r => {
      requests.push(r);
      return response({ value: [{ webUrl: site }], '@odata.nextLink': `https://graph.microsoft.com${r.path}?$skiptoken=next` });
    }, []);
    expect(requests).toHaveLength(6);
    expect(result.sources.every(s => s.status === 'partial')).toBe(true);
    expect(result.sites).toHaveLength(1);
  });
  it.each(['https://evil.test/v1.0/me/drives?$skiptoken=x', 'https://graph.microsoft.com/v1.0/users?$skiptoken=x', 'https://graph.microsoft.com/v1.0/me/drives?$skiptoken=a&$skiptoken=b'])('does not follow unsafe nextLink %s', async next => {
    let calls = 0;
    const result = await discoverSessionSites(async () => { calls++; return response({ value: [], '@odata.nextLink': next }); }, []);
    expect(calls).toBe(3);
    expect(result.sources.every(s => s.status === 'partial')).toBe(true);
  });
  it('never swallows an identity mismatch', async () => {
    const { PerchError } = await import('../src/errors.js');
    await expect(discoverSessionSites(async () => { throw new PerchError('Wrong account', 'identity_mismatch'); }, [])).rejects.toMatchObject({ code: 'identity_mismatch' });
  });
  it('limits sites and pages and reports truncation rather than promising all resources', async () => {
    const result = await discoverSessionSites(async () => response({ value: Array.from({ length: 100 }, (_, i) => ({ webUrl: `https://tenant.sharepoint.com/sites/T${i}` })), '@odata.nextLink': 'https://graph.microsoft.com/v1.0/me/drives?$skiptoken=next' }), []);
    expect(result.sites).toHaveLength(100);
    expect(result.sources.every(s => s.status === 'partial')).toBe(true);
  });
  it('only expands fixed read-only discovery routes', () => {
    for (const path of ['/v1.0/me/drives', '/v1.0/me/followedSites', '/v1.0/sites']) {
      expect(() => resolveSessionRequest(config, { resource: 'graph', path })).not.toThrow();
      expect(() => resolveSessionRequest(config, { resource: 'graph', path, method: 'POST' })).toThrow();
    }
    expect(() => resolveSessionRequest(config, { resource: 'graph', path: '/v1.0/users' })).toThrow();
  });
});
