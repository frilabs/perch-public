import { expect, it } from 'vitest';
import { BrowserSessionTransport } from '../src/microsoft/session/browserTransport.js';
import type { BrowserEvent, SessionProtocol } from '../src/microsoft/sessionBrowser.js';
const identity = { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', kind: 'organization' as const };
const site = { id: 'ms-site-1234abcd', url: 'https://tenant.sharepoint.com/sites/team', kind: 'sharepoint' as const, driveIds: ['drive'] };
const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = (oid = identity.objectId, claims: object = {}) => [encode({ alg: 'RS256' }), encode({ tid: identity.tenantId, oid, exp: Math.floor(Date.now() / 1000) + 3600, aud: 'https://outlook.office.com', ...claims }), 'signature'].join('.');
const skype = (oid = identity.objectId) => [encode({ alg: 'RS256' }), encode({ tid: identity.tenantId, skypeid: `orgid:${oid}`, exp: Math.floor(Date.now() / 1000) + 3600 }), 'signature'].join('.');
function harness(replies: Array<{ status?: number; body: unknown }> = [], bootstrap?: unknown, rawBootstrap?: () => Promise<unknown>) {
  const observers=new Set<(e:BrowserEvent)=>void>();const observer=(e:BrowserEvent)=>{for(const fn of observers)fn(e);};
  const calls: any[] = [], payloads: any[] = [], origins = new Map<string, string>(); let serial = 0;
  const protocol: SessionProtocol = { onEvent(fn) { observers.add(fn); return () => { observers.delete(fn); }; }, async call(method, params, sessionId) {
    calls.push({ method, params, sessionId });
    if (method === 'Target.createTarget') { const targetId = `target${++serial}`; observer({ method: 'Target.attachedToTarget', params: { sessionId: `page${serial}`, targetInfo: { targetId, type: 'page' }, waitingForDebugger: true } }); return { targetId }; }
    if (method === 'Network.getResponseBody') return rawBootstrap ? await rawBootstrap() : {body:JSON.stringify(bootstrap),base64Encoded:false};
    if (method === 'Target.attachToTarget') return { sessionId: `page${serial}` };
    if (method === 'Page.navigate') origins.set(sessionId!, new URL(String(params?.url)).origin);
    if (method === 'Runtime.evaluate') {
      if (String(params?.expression).includes('PerchDisabledChannel')) return { result: { value: true } };
      if (params?.expression === 'location.origin') return { result: { value: origins.get(sessionId!) } };
      const payload = JSON.parse(String(params?.expression).match(/\}\)\((\{[\s\S]*\})\)$/)![1]!); if(payload.url){const u=new URL(payload.url);u.searchParams.delete('__perch_request');payload.url=u.href;} payloads.push(payload);
      const reply = replies.shift() ?? { body: { Id: 'mailbox', EmailAddress: 'test@example.test' } };
      return { result: { value: { status: reply.status ?? 200, headers: {}, body: Buffer.from(JSON.stringify(reply.body)).toString('base64') } } };
    }
    return {};
  } };
  return { protocol, calls, payloads, emit: (e: BrowserEvent) => observer(e), capture(url: string, headers: object, sessionId = 'page1') { observer({ method: 'Network.requestWillBeSent', sessionId, params: { requestId: `r${calls.length}`, request: { url, headers } } }); } };
}
it('bootstraps the Microsoft session through sign-in rather than the product landing page', async () => {
  const h = harness(); const t = new BrowserSessionTransport(h.protocol, [], identity, { waitMs: 1 });
  await t.open('graph');
  expect(h.calls.find(c => c.method === 'Page.navigate')?.params.url).toBe('https://www.microsoft365.com/signin');
});
it('refreshes Teams application-local auth state before navigation without clearing sign-in cookies or other services', async () => {
  const h = harness(); const t = new BrowserSessionTransport(h.protocol, [site], identity, { waitMs: 1 });
  for (const service of ['mail', 'calendar', 'graph'] as const) await t.open(service);
  await t.open('files', site.id);
  expect(h.calls.filter(c => c.method.startsWith('Storage.clear'))).toEqual([]);
  await t.open('teams'); await t.open('teams');
  const resets = h.calls.filter(c => c.method === 'Storage.clearDataForOrigin');
  expect(resets.map(c => c.params)).toEqual([
    { origin: 'https://teams.microsoft.com', storageTypes: 'local_storage' },
    { origin: 'https://teams.cloud.microsoft', storageTypes: 'local_storage' },
  ]);
  const navigate = h.calls.findIndex(c => c.method === 'Page.navigate' && c.params.url === 'https://teams.microsoft.com/v2/');
  expect(resets.every(c => h.calls.indexOf(c) < navigate)).toBe(true);
  expect(h.calls.some(c => /clearBrowserCookies|deleteCookies/.test(c.method))).toBe(false);
  t.close();
});
it('does not navigate or mark Teams open when refreshing its local auth state fails', async () => {
  const h = harness(); const call = h.protocol.call.bind(h.protocol);
  h.protocol.call = async (method, params, sid) => {
    if (method === 'Storage.clearDataForOrigin') throw Error('reset failed');
    return call(method, params, sid);
  };
  const t = new BrowserSessionTransport(h.protocol, [], identity, { waitMs: 1 });
  await expect(t.open('teams')).rejects.toThrow();
  await expect(t.open('teams')).rejects.toThrow();
  expect(h.calls.some(c => c.method === 'Page.navigate')).toBe(false);
  t.close();
});
it('uses only target-bound headers and rejects account switching before a fetch', async () => {
  const h = harness(); const t = new BrowserSessionTransport(h.protocol, [], identity, { waitMs: 1 });
  await t.open('mail');
  h.capture('https://outlook.office.com/owa/service.svc', { Authorization: `Bearer ${jwt()}` }, 'other');
  await expect(t.request({ resource: 'outlook', path: '/api/v2.0/me' })).rejects.toMatchObject({ code: 'reauth_required' });
  h.capture('https://outlook.office.com/owa/service.svc', { Authorization: `Bearer ${jwt()}` });
  expect((await t.request({ resource: 'outlook', path: '/api/v2.0/me' })).status).toBe(200);
  h.capture('https://outlook.office.com/owa/service.svc', { Authorization: `Bearer ${jwt('33333333-3333-4333-8333-333333333333')}` });
  const before = h.calls.length;
  await expect(t.request({ resource: 'outlook', path: '/api/v2.0/me' })).rejects.toMatchObject({ code: 'identity_mismatch' });
  expect(h.calls).toHaveLength(before); t.close();
});
it('keeps provider URLs and tokens out of transport errors', async () => {
  const h = harness(); const t = new BrowserSessionTransport(h.protocol, [], identity, { waitMs: 1 }); await t.open('mail');
  await expect(t.request({ resource: 'outlook', path: 'https://evil.test/' })).rejects.toThrow();
  expect(h.payloads).toHaveLength(0); t.close();
});
it('handles ExtraInfo before request and publishes metadata only after API acceptance', async () => {
  const h = harness(); const t = new BrowserSessionTransport(h.protocol, [], undefined, { waitMs: 1 }); await t.open('mail');
  h.emit({ method: 'Network.requestWillBeSentExtraInfo', sessionId: 'page1', params: { requestId: 'reverse', headers: { Authorization: `Bearer ${jwt(undefined, { preferred_username: 'user@example.com', name: 'Example User' })}` } } });
  h.emit({ method: 'Network.requestWillBeSent', sessionId: 'page1', params: { requestId: 'reverse', request: { url: 'https://outlook.cloud.microsoft/owa/service.svc', headers: {} } } });
  expect(t.identity).toBeUndefined(); expect(t.metadata).toEqual({});
  await t.request({ resource: 'outlook', path: '/api/v2.0/me' });
  expect(t.metadata).toEqual({ email: 'user@example.com', displayName: 'Example User' });
  expect(h.payloads[0]).toMatchObject({ url: 'https://outlook.cloud.microsoft/api/v2.0/me', credentials: 'omit', headers: { Accept: 'application/json' } });
});
it('captures Skype-only chat auth against saved immutable identity and discovered region', async () => {
  const h = harness(); const t = new BrowserSessionTransport(h.protocol, [], identity, { waitMs: 1 }); await t.open('teams');
  expect(t.config.chatBase).toBe('');
  h.capture('https://teams.cloud.microsoft/api/chatsvc/amer/v1/users/ME/conversations', { Authentication: `skypetoken=${skype()}` });
  await t.request({ resource: 'chat', path: '/v1/users/ME/conversations' });
  expect(h.payloads[0]).toMatchObject({ url: 'https://teams.cloud.microsoft/api/chatsvc/amer/v1/users/ME/conversations', headers: { Authentication: `skypetoken=${skype()}` }, credentials: 'omit' });
  expect(h.payloads[0].headers.Authorization).toBeUndefined();
});
it('requires an accepted Entra API first when onboarding with Skype-only traffic', async () => {
  const h = harness(); const t = new BrowserSessionTransport(h.protocol, [], undefined, { waitMs: 1 }); await t.open('teams');
  h.capture('https://teams.microsoft.com/api/chatsvc/emea/v1/users/ME/conversations', { Authentication: `skypetoken=${skype()}` });
  await expect(t.request({ resource: 'chat', path: '/v1/users/ME/conversations' })).rejects.toMatchObject({ code: 'identity_unverified' });
  expect(h.payloads).toHaveLength(0);
  h.capture('https://teams.microsoft.com/api/csa/emea/api/v3/teams/users/me', { Authorization: `Bearer ${jwt()}` });
  await t.request({ resource: 'csa', path: '/api/v3/teams/users/me' });
  await t.request({ resource: 'chat', path: '/v1/users/ME/conversations' });
  expect(t.identity).toEqual(identity);
});
it('probes cookie identity and obtains a private digest before each SharePoint write', async () => {
  const h = harness([{ body: { AadObjectId: { NameId: identity.objectId } } }, { body: { d: { GetContextWebInformation: { FormDigestValue: 'private-digest' } } } }, { body: { id: 'new' } }]);
  const t = new BrowserSessionTransport(h.protocol, [site], identity, { waitMs: 1 }); await t.open('files', site.id);
  await t.request({ resource: 'sharepoint', siteId: site.id, path: '/_api/v2.0/drives/drive/root/children', method: 'POST', body: { name: 'new', folder: {} } });
  expect(h.payloads).toHaveLength(3);
  expect(h.payloads[0].url).toContain('/_api/web/currentuser');
  expect(h.payloads[1]).toMatchObject({ url: `${site.url}/_api/contextinfo`, method: 'POST', credentials: 'include' });
  expect(h.payloads[2]).toMatchObject({ headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-RequestDigest': 'private-digest' } });
});
it('stops SharePoint writes on identity mismatch or a failed digest, without a mutation retry', async () => {
  for (const replies of [[{ body: { AadObjectId: { NameId: 'other' } } }], [{ body: { AadObjectId: { NameId: identity.objectId } } }, { status: 403, body: {} }], [{ body: { AadObjectId: { NameId: identity.objectId } } }, { body: { FormDigestValue: '' } }]]) {
    const h = harness(replies); const t = new BrowserSessionTransport(h.protocol, [site], identity, { waitMs: 1 }); await t.open('files', site.id);
    await expect(t.request({ resource: 'sharepoint', siteId: site.id, path: '/_api/v2.0/drives/drive/items/item', method: 'DELETE' })).rejects.toThrow();
    expect(h.payloads.some((p) => p.method === 'DELETE')).toBe(false);
  }
});
it('preflights header identity before a mutation and adds JSON defaults', async () => {
  const h = harness([{ body: { Id: 'mailbox' } }, { body: { Id: 'new' } }]); const t = new BrowserSessionTransport(h.protocol, [], identity, { waitMs: 1 }); await t.open('mail');
  h.capture('https://outlook.office.com/owa/service.svc', { Authorization: `Bearer ${jwt()}` });
  await t.request({ resource: 'outlook', path: '/api/v2.0/me/messages', method: 'POST', body: { Subject: 'hello' } });
  expect(h.payloads).toHaveLength(2); expect(h.payloads[0].method).toBe('GET');
  expect(h.payloads[1].headers['Content-Type']).toBe('application/json');
  const bad = harness([{ status: 401, body: {} }]); const expired = new BrowserSessionTransport(bad.protocol, [], identity, { waitMs: 1 }); await expired.open('mail');
  bad.capture('https://outlook.office.com/owa/service.svc', { Authorization: `Bearer ${jwt()}` });
  await expect(expired.request({ resource: 'outlook', path: '/api/v2.0/me/messages', method: 'POST', body: {} })).rejects.toThrow();
  expect(bad.payloads).toHaveLength(1);
});
it('never injects cookies or session headers into a preauthenticated download', async () => {
  const h = harness(); const t = new BrowserSessionTransport(h.protocol, [site], identity, { waitMs: 1 }); await t.open('files', site.id);
  await t.request({ resource: 'download', siteId: site.id, path: `${site.url}/_layouts/15/download.aspx?tempauth=secret`, responseType: 'bytes' });
  expect(h.payloads[0]).toMatchObject({ credentials: 'omit', headers: {} });
  expect(h.calls.find((c) => c.method === 'Runtime.evaluate' && c.params.expression !== 'location.origin' && !c.params.expression.includes('PerchDisabledChannel')).params.expression).toContain("redirect:'error'");
});

it('rejects untrusted selected-site URLs before navigation', async () => {
  const h = harness(); const t = new BrowserSessionTransport(h.protocol, [{ ...site, url: 'https://evil.test/private' }], identity, { waitMs: 1 });
  await expect(t.open('files', site.id)).rejects.toThrow();
  expect(h.calls).toHaveLength(0);
});

it('preserves both observed CSA bearer and Skype credentials only for the same identity', async () => {
  const h = harness(); const t = new BrowserSessionTransport(h.protocol, [], identity, { waitMs: 1 }); await t.open('teams');
  const authorization = `Bearer ${jwt()}`, authentication = `skypetoken=${skype()}`;
  h.capture('https://teams.microsoft.com/api/csa/emea/api/v3/teams/users/me', { Authorization: authorization, Authentication: authentication });
  await t.request({ resource: 'csa', path: '/api/v3/teams/users/me' });
  expect(h.payloads[0].headers).toMatchObject({ Authorization: authorization, Authentication: authentication });
  const bad = harness(); const mixed = new BrowserSessionTransport(bad.protocol, [], identity, { waitMs: 1 }); await mixed.open('teams');
  bad.capture('https://teams.microsoft.com/api/csa/emea/api/v3/teams/users/me', { Authorization: authorization, Authentication: `skypetoken=${skype('33333333-3333-4333-8333-333333333333')}` });
  await expect(mixed.request({ resource: 'csa', path: '/api/v3/teams/users/me' })).rejects.toMatchObject({ code: 'identity_mismatch' });
  expect(bad.payloads).toHaveLength(0);
});
it('guards background workers before resuming them and bypasses serviceworker interception for page requests',async()=>{
 const h=harness();const t=new BrowserSessionTransport(h.protocol,[],identity,{waitMs:1});await t.open('mail');
 expect(h.calls).toContainEqual(expect.objectContaining({method:'Network.setBypassServiceWorker',params:{bypass:true}}));
 h.emit({method:'Target.attachedToTarget',params:{sessionId:'worker1',targetInfo:{type:'service_worker',targetId:'worker-target'}}});
 await new Promise(r=>setImmediate(r));
 const block=h.calls.findIndex(c=>c.method==='Network.setBlockedURLs'&&c.sessionId==='worker1');const resume=h.calls.findIndex(c=>c.method==='Runtime.runIfWaitingForDebugger'&&c.sessionId==='worker1');expect(block).toBeGreaterThan(-1);expect(resume).toBeGreaterThan(block);
 expect(h.calls[block].params.urlPatterns).toEqual(expect.arrayContaining([{urlPattern:'http://*:*/*',block:true},{urlPattern:'https://*:*/*',block:true}]));
 expect(h.calls.some(c=>c.method==='Fetch.enable'&&c.sessionId==='worker1')).toBe(false);t.close();
});

function teamsBootstrap(h: ReturnType<typeof harness>, sessionId = 'page1', responseUrl = 'https://teams.microsoft.com/api/authsvc/v1.0/authz', status = 200) {
 h.emit({method:'Network.requestWillBeSent',sessionId,params:{requestId:'bootstrap',request:{url:'https://teams.microsoft.com/api/authsvc/v1.0/authz',method:'POST',headers:{}}}});
 h.emit({method:'Network.responseReceived',sessionId,params:{requestId:'bootstrap',response:{url:responseUrl,status}}});
 h.emit({method:'Network.loadingFinished',sessionId,params:{requestId:'bootstrap',encodedDataLength:2000}});
}
it('uses the Teams web auth response and its verified regional route when the app emits no chat request', async()=>{
 const h=harness([{body:{conversations:[]}}],{tokens:{skypeToken:skype()},regionGtms:{chatServiceAfd:'https://teams.microsoft.com/api/chatsvc/uk',chatSvcAggAfd:'https://teams.microsoft.com/api/csa/uk'}});
 const t=new BrowserSessionTransport(h.protocol,[],identity,{waitMs:1});await t.open('teams');teamsBootstrap(h);await new Promise(r=>setImmediate(r));
 expect((await t.request({resource:'chat',path:'/v1/users/ME/conversations'})).status).toBe(200);
 expect(h.payloads[0]).toMatchObject({url:'https://teams.microsoft.com/api/chatsvc/uk/v1/users/ME/conversations',headers:{Authentication:`skypetoken=${skype()}`}});t.close();
});
it('rejects unbound, redirected, failed or foreign-account Teams bootstrap responses',async()=>{
 for(const bad of ['target','redirect','status','identity','route']){
  const h=harness([],{tokens:{skypeToken:skype(bad==='identity'?'33333333-3333-4333-8333-333333333333':undefined)},regionGtms:{chatServiceAfd:bad==='route'?'https://evil.example/api/chatsvc/uk':'https://teams.microsoft.com/api/chatsvc/uk'}});
  const t=new BrowserSessionTransport(h.protocol,[],identity,{waitMs:1});await t.open('teams');teamsBootstrap(h,bad==='target'?'other':'page1',bad==='redirect'?'https://evil.example/auth':'https://teams.microsoft.com/api/authsvc/v1.0/authz',bad==='status'?401:200);await new Promise(r=>setImmediate(r));
  await expect(t.request({resource:'chat',path:'/v1/users/ME/conversations'})).rejects.toThrow();expect(h.payloads).toHaveLength(0);t.close();
 }
});

it('validates bounded bootstrap bodies, supports base64, and requires Entra identity',async()=>{
 const body={tokens:{skypeToken:skype()},regionGtms:{chatServiceAfd:'https://teams.microsoft.com/api/chatsvc/uk'}};
 for(const mode of ['base64','malformed','oversized','expired','unverified']){
  const data=mode==='expired'?{...body,tokens:{skypeToken:jwt(undefined,{skypeid:`orgid:${identity.objectId}`,exp:1})}}:body;
  const h=harness([],undefined,async()=>({body:mode==='base64'?Buffer.from(JSON.stringify(data)).toString('base64'):mode==='malformed'?'{':mode==='oversized'?'x'.repeat(1024*1024+1):JSON.stringify(data),base64Encoded:mode==='base64'}));
  const t=new BrowserSessionTransport(h.protocol,[],mode==='unverified'?undefined:identity,{waitMs:1});await t.open('teams');teamsBootstrap(h);await new Promise(r=>setImmediate(r));
  const request=t.request({resource:'chat',path:'/v1/users/ME/conversations'});
  if(mode==='base64')await expect(request).resolves.toMatchObject({status:200});
  else{await expect(request).rejects.toMatchObject({code:mode==='unverified'?'identity_unverified':'reauth_required'});expect(h.payloads).toHaveLength(0);}
  t.close();
 }
});
it('does not revive credentials when closed during bootstrap response retrieval',async()=>{
 let finish!:(value:unknown)=>void;
 const h=harness([],undefined,()=>new Promise(resolve=>{finish=resolve;}));
 const t=new BrowserSessionTransport(h.protocol,[],identity,{waitMs:1});await t.open('teams');teamsBootstrap(h);t.close();
 finish({body:JSON.stringify({tokens:{skypeToken:skype()},regionGtms:{chatServiceAfd:'https://teams.microsoft.com/api/chatsvc/uk'}})});await new Promise(r=>setImmediate(r));
 expect(t.config.chatBase).toBe('');await expect(t.request({resource:'chat',path:'/v1/users/ME/conversations'})).rejects.toMatchObject({code:'browser_failed'});expect(h.payloads).toHaveLength(0);
});
it('opens the same-session Microsoft 365 page lazily for Teams Graph reads',async()=>{
 const h=harness([{body:{id:identity.objectId}}]);const t=new BrowserSessionTransport(h.protocol,[],identity,{waitMs:20});await t.open('teams');
 const pending=expect(t.request({resource:'graph',path:'/v1.0/me'})).resolves.toMatchObject({status:200});
 await new Promise(r=>setImmediate(r));
 h.capture('https://graph.microsoft.com/v1.0/me',{Authorization:`Bearer ${jwt(undefined,{aud:'https://graph.microsoft.com'})}`},'page2');
 await pending;
 expect(h.calls.filter(c=>c.method==='Page.navigate').map(c=>c.params.url)).toEqual(['https://teams.microsoft.com/v2/','https://www.microsoft365.com/signin']);
 await t.request({resource:'graph',path:'/v1.0/me'});
 expect(h.calls.filter(c=>c.method==='Target.createTarget')).toHaveLength(2);t.close();
});
