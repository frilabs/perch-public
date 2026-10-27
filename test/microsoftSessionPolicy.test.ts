import { describe, expect, it } from 'vitest';
import { normalizeSelectedSiteUrl, parseUnverifiedSessionToken, resolveSessionRequest, type SessionTransportConfig } from '../src/microsoft/session/policy.js';
import type { SessionHttpRequest } from '../src/microsoft/session/contracts.js';
const identity = { tenantId: '11111111-2222-4333-8444-555555555555', objectId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', kind: 'organization' as const };
const site = { id: 'ms-site-1234abcd', url: 'https://tenant.sharepoint.com/sites/team', kind: 'sharepoint' as const, driveIds: ['drive'] };
const config: SessionTransportConfig = { outlookOrigin: 'https://outlook.office.com', chatBase: 'https://teams.microsoft.com/api/chatsvc/emea', csaBase: 'https://teams.microsoft.com/api/csa/emea', sites: [site] };
const resolve = (request: SessionHttpRequest, overrides: Partial<SessionTransportConfig> = {}) => resolveSessionRequest({ ...config, ...overrides }, request);
const encode = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
const token = (claims: Record<string, unknown> = {}, header: unknown = { alg: 'RS256' }) => `${encode(header)}.${encode({ tid: identity.tenantId, oid: identity.objectId, aud: 'https://graph.microsoft.com', exp: 2000, ...claims })}.c2lnbmF0dXJl`;

describe('Microsoft session request policy', () => {
  it('resolves fixed resource origins and preserves query values as data', () => {
    expect(resolve({ resource: 'outlook', path: '/api/v2.0/me/messages/id%2Fpart', query: { '$search': 'x&url=https://evil.test' } })).toMatchObject({ url: 'https://outlook.office.com/api/v2.0/me/messages/id%2Fpart?%24search=x%26url%3Dhttps%3A%2F%2Fevil.test', method: 'GET', redirect: 'error', credentials: 'include', sendAuthorization: true, maxBytes: 4 * 1024 * 1024, responseType: 'json' });
    expect(resolve({ resource: 'chat', path: '/v1/users/ME/conversations' }).url).toBe('https://teams.microsoft.com/api/chatsvc/emea/v1/users/ME/conversations');
    expect(resolve({ resource: 'csa', path: '/api/v3/teams/users/me' }).url).toBe('https://teams.microsoft.com/api/csa/emea/api/v3/teams/users/me');
    expect(resolve({ resource: 'substrate', path: '/searchservice/api/v2/query', method: 'POST' }).url).toBe('https://substrate.office.com/searchservice/api/v2/query');
    expect(resolve({ resource: 'graph', path: '/v1.0/me' }).url).toBe('https://graph.microsoft.com/v1.0/me');
  });
  it.each(['https://evil.test', 'https://outlook.office.com.evil.test', 'https://sub.outlook.office.com', 'https://outlook.office.com:8443', 'https://user@outlook.office.com', 'http://outlook.office.com', 'https://outlook.office.com/?x=y', 'https://outlook.office.com/#x', 'https://outlook.office.com./'])('rejects untrusted Outlook origin %s', (outlookOrigin) => {
    expect(() => resolve({ resource: 'outlook', path: '/api/v2.0/me' }, { outlookOrigin })).toThrow();
  });
  it.each(['https://teams.microsoft.com/api/chatsvc/emea/../amer', 'https://evil.test/api/chatsvc/emea', 'https://teams.microsoft.com/api/csa/emea', 'https://teams.microsoft.com/api/chatsvc/emea?url=evil', 'https://teams.microsoft.com/api/chatsvc/emea/extra', 'https://teams.microsoft.com/api/chatsvc/%65mea'])('rejects unsafe discovered chat base %s', (chatBase) => {
    expect(() => resolve({ resource: 'chat', path: '/v1/users/ME/conversations' }, { chatBase })).toThrow();
  });
  it.each(['https://evil.test/x', '//evil.test/x', '/api/v2.0/me/../users/other', '/api/v2.0/me/%2e%2e/users', '/api/v2.0/me/%252e%252e/users', '/api/v2.0/me/a%2f..%2f..%2fusers', '/api/v2.0/me/a%5cb', '/api/v2.0/me/a?url=https://evil.test', '/api/v2.0/me/a%3furl=evil', '/api/v2.0/me/a#x', '/api/v2.0/me/a%23x', '/api/v2.0/me/a\r\nb', '/api/v2.0/users/other', '/api/v2.0/meevil', '/api/v2.0/me//messages'])('rejects path confusion %s', (path) => {
    expect(() => resolve({ resource: 'outlook', path })).toThrow();
  });
  it('permits only the named service endpoints, methods and query keys', () => {
    for (const request of [{ resource: 'graph', path: '/v1.0/users' }, { resource: 'graph', path: '/v1.0/me', method: 'POST' }, { resource: 'csa', path: '/api/v3/teams/users/other' }, { resource: 'chat', path: '/v1/users/OTHER/conversations' }, { resource: 'outlook', path: '/api/v2.0/me', query: { url: 'https://evil.test' } }, { resource: 'outlook', path: '/api/v2.0/me', query: { '$batch': 'x' } }] as SessionHttpRequest[]) expect(() => resolve(request)).toThrow();
  });
  it('normalizes selected SharePoint hosts without accepting unsafe site URLs', () => {
    expect(normalizeSelectedSiteUrl(`${site.url}/`)).toBe(site.url);
    expect(normalizeSelectedSiteUrl('https://tenant-my.sharepoint.de/personal/user')).toBe('https://tenant-my.sharepoint.de/personal/user');
    for (const url of ['https://sharepoint.com', 'https://tenant.sharepoint.com.evil.test/sites/a', 'http://tenant.sharepoint.com/sites/a', 'https://user@tenant.sharepoint.com/sites/a', 'https://tenant.sharepoint.com:444/sites/a', `${site.url}?x=y`, `${site.url}#x`, 'https://tenant.sharepoint.com/sites/../other', 'https://tenant.sharepoint.com/sites/%2e%2e/other', 'https://tenant.sharepoint.com/sites/%252e%252e/other']) expect(() => normalizeSelectedSiteUrl(url)).toThrow();
    expect(resolve({ resource: 'sharepoint', siteId: site.id, path: '/_api/v2.0/drives/drive/root/children' }).url).toBe(`${site.url}/_api/v2.0/drives/drive/root/children`);
    expect(() => resolve({ resource: 'sharepoint', siteId: 'unknown', path: '/_api/v2.0/drives' })).toThrow();
    expect(() => resolve({ resource: 'sharepoint', path: '/_api/v2.0/drives' })).toThrow();
    expect(() => resolve({ resource: 'sharepoint', siteId: site.id, path: '/_api/v2.0/drives/drive/items/item/permanentDelete', method: 'POST' })).toThrow();
  });
  it('rejects encoded separators that disguise file or chat endpoints', () => {
    for (const request of [
      { resource: 'sharepoint', siteId: site.id, path: '/_api/v2.0/drives/drive/items/item%2fpermissions' },
      { resource: 'chat', path: '/v1/users/ME/conversations/id%2fproperties' },
    ] as SessionHttpRequest[]) expect(() => resolve(request)).toThrow();
  });
  it('restricts preauthenticated downloads and strips all session credentials', () => {
    const request: SessionHttpRequest = { resource: 'download', siteId: site.id, path: `${site.url}/_layouts/15/download.aspx?UniqueId=abc&tempauth=secret`, maxBytes: 100, responseType: 'bytes' };
    expect(resolve(request)).toMatchObject({ url: request.path, method: 'GET', headers: {}, redirect: 'error', credentials: 'omit', sendAuthorization: false, maxBytes: 100, responseType: 'bytes' });
    for (const path of ['https://other.sharepoint.com/_layouts/15/download.aspx?token=x', `${site.url}/evil.aspx?redirect=x`, `${site.url}/_layouts/15/download.aspx#secret`, 'https://user:pass@tenant.sharepoint.com/_layouts/15/download.aspx', `${site.url}/_layouts/15/../redirect.aspx`]) expect(() => resolve({ ...request, path })).toThrow();
    expect(() => resolve({ ...request, method: 'POST' })).toThrow();
    expect(() => resolve({ ...request, query: { url: 'https://evil.test' } })).toThrow();
    expect(() => resolve({ ...request, headers: { Authorization: 'Bearer SECRET' } })).toThrow();
  });
  it('permits bounded adapter headers and bodies but rejects transport overrides', () => {
    expect(resolve({ resource: 'outlook', path: '/api/v2.0/me/messages/id', method: 'PATCH', headers: { 'If-Match': '"v1"', 'Content-Type': 'application/json', Prefer: 'outlook.timezone="UTC"' }, body: { IsRead: true } })).toMatchObject({ body: { IsRead: true } });
    for (const headers of [{ Authorization: 'Bearer secret' }, { Cookie: 'secret' }, { Host: 'evil.test' }, { 'X-HTTP-Method-Override': 'DELETE' }, { 'Content-Type': 'x\r\nInjected: yes' }, { Accept: 'a', accept: 'b' }] as Array<Record<string, string>>) expect(() => resolve({ resource: 'outlook', path: '/api/v2.0/me', headers })).toThrow();
    for (const maxBytes of [0, -1, 10 * 1024 * 1024 + 1, Infinity, 1.5]) expect(() => resolve({ resource: 'outlook', path: '/api/v2.0/me', maxBytes })).toThrow();
    expect(() => resolve({ resource: 'outlook', path: '/api/v2.0/me', method: 'POST', body: {}, bodyBase64: '' })).toThrow();
    expect(() => resolve({ resource: 'outlook', path: '/api/v2.0/me', method: 'POST', bodyBase64: '!!!!' })).toThrow();
    expect(() => resolve({ resource: 'outlook', path: '/api/v2.0/me', body: {} })).toThrow();
  });
});

describe('unverified Microsoft token identity parsing', () => {
  it('parses immutable identity and explicitly does not assert signature verification', () => {
    expect(parseUnverifiedSessionToken(token(), { nowSeconds: 1000, expected: identity, audiences: ['https://graph.microsoft.com'] })).toEqual({ identity, audience: 'https://graph.microsoft.com', expiresAt: 2000, signatureVerified: false });
    expect(parseUnverifiedSessionToken(token({ tid: '9188040d-6c67-4c5b-b112-36a304b66dad' }), { nowSeconds: 1000 }).identity.kind).toBe('personal');
  });
  it('rejects missing, malformed, expired and mismatched identities without email fallback', () => {
    for (const claims of [{ tid: undefined }, { oid: undefined, email: 'a@example.com', preferred_username: 'a@example.com' }, { tid: 'not-a-guid' }, { oid: 'not-a-guid' }, { exp: undefined }, { exp: 1000 }, { exp: '2000' }, { nbf: 1100 }, { aud: undefined }, { aud: ['https://graph.microsoft.com'] }]) expect(() => parseUnverifiedSessionToken(token(claims), { nowSeconds: 1000 })).toThrow();
    expect(() => parseUnverifiedSessionToken(token({ oid: 'bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee' }), { nowSeconds: 1000, expected: identity })).toThrow(/identity/i);
    expect(() => parseUnverifiedSessionToken(token(), { nowSeconds: 1000, audiences: ['other'] })).toThrow(/audience/i);
    expect(() => parseUnverifiedSessionToken(token({}, { alg: 'none' }), { nowSeconds: 1000 })).toThrow();
    for (const value of ['opaque-token-secret', 'a.b.c', `${token()}.extra`, `${encode({ alg: 'RS256' })}.${encode({})}.`]) {
      expect(() => parseUnverifiedSessionToken(value, { nowSeconds: 1000 })).toThrow();
      try { parseUnverifiedSessionToken(value, { nowSeconds: 1000 }); } catch (error) { expect(String(error)).not.toContain(value); }
    }
  });
});


describe('Graph channel listing route policy', () => {
  const path = '/v1.0/teams/33333333-3333-4333-8333-333333333333/channels';
  it('permits only exact GET routes and fixed selection with one bounded paging token', () => {
    expect(resolve({ resource: 'graph', path: '/v1.0/me/joinedTeams' }).url).toBe('https://graph.microsoft.com/v1.0/me/joinedTeams');
    expect(resolve({ resource: 'graph', path, query: { '$select': 'id,displayName,description,membershipType', '$skiptoken': 'opaque=' } }).url).toContain('/channels?');
    for (const input of [
      { path, method: 'POST' }, { path: path.replace('channels', 'allChannels') }, { path: `${path}/19:channel/messages` },
      { path: path.replace('33333333-3333-4333-8333-333333333333', 'not-a-uuid') },
      { path: '/v1.0/me/joinedTeams', query: { '$select': 'id' } }, { path: '/v1.0/me/joinedTeams', query: { '$top': '100' } },
      { path, query: { '$select': 'id,email' } }, { path, query: { search: 'anything' } },
      { path, query: { '$skiptoken': 'a', '$skipToken': 'b' } }, { path, query: { '$skiptoken': '' } },
      { path, query: { '$skiptoken': 'x'.repeat(8001) } },
    ]) expect(() => resolve({ resource: 'graph', ...input } as SessionHttpRequest)).toThrow();
  });
});
