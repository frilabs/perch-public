import { afterEach, describe, expect, it, vi } from 'vitest';
import { runInNewContext } from 'node:vm';
import { createSessionRequestGuard } from '../src/microsoft/session/requestGuard.js';
import type { BrowserEvent, SessionProtocol } from '../src/microsoft/sessionBrowser.js';

function harness() {
  const listeners = new Set<(event: BrowserEvent) => void>();
  const call = vi.fn(async (_method: string, _params?: Record<string, unknown>, _sessionId?: string): Promise<any> => (_method === 'Runtime.evaluate' ? { result: { value: true } } : {}));
  const protocol: SessionProtocol = { call, onEvent(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; } };
  let next = 0;
  async function paused(url: string, method: string, sessionId = 'page', details: Record<string, unknown> = {}, resourceType = 'XHR') {
    const requestId = `request-${++next}`;
    for (const listener of listeners) listener({ method: 'Fetch.requestPaused', sessionId, params: { requestId, resourceType, request: { url, method, ...details } } });
    await Promise.resolve(); await Promise.resolve();
    return call.mock.calls.filter((args) => args[1]?.requestId === requestId);
  }
  return { protocol, call, paused, listeners };
}
const endpoint = 'https://outlook.office.com/api/v2.0/me/messages/item?%24select=Id';
afterEach(() => vi.useRealTimers());
describe('worker background request guard', () => {
  it('installs WebSocket scheme blocking before request interception and fails closed at either Network command', async () => {
    const h = harness(); await createSessionRequestGuard(h.protocol, 'page');
    expect(h.call.mock.calls.slice(0, 2)).toEqual([
      ['Network.enable', {}, 'page'],
      ['Network.setBlockedURLs', { urlPatterns: [{ urlPattern: 'ws://*:*/*', block: true }, { urlPattern: 'wss://*:*/*', block: true }] }, 'page'],
    ]);
    for (const failedMethod of ['Network.enable', 'Network.setBlockedURLs', 'Page.enable', 'Page.addScriptToEvaluateOnNewDocument', 'Runtime.evaluate']) {
      const failed = harness();
      failed.call.mockImplementation(async method => { if (method === failedMethod) throw Error('secret failure'); return method === 'Runtime.evaluate' ? { result: { value: true } } : {}; });
      await expect(createSessionRequestGuard(failed.protocol, 'page')).rejects.toThrow('Could not install');
      expect(failed.listeners.size).toBe(0);
      expect(failed.call.mock.calls.some(([method]) => method === 'Fetch.enable')).toBe(false);
    }
  });
  it('locks WebSocket constructors before page scripts and before paused workers resume', async () => {
    for (const worker of [false, true]) {
      const h = harness(); const guard = await createSessionRequestGuard(h.protocol, 'page', [], { worker });
      const evaluate = h.call.mock.calls.find(([method]) => method === 'Runtime.evaluate');
      expect(evaluate).toBeDefined();
      const realm = { WebSocket: function NativeSocket() {}, WebTransport: function NativeTransport() {}, WebSocketStream: function NativeStream() {}, DOMException };
      runInNewContext(String(evaluate![1]!.expression), realm);
      for (const name of ['WebSocket', 'WebTransport', 'WebSocketStream'] as const) {
        expect(() => Reflect.construct(realm[name], [])).toThrow('disabled');
        expect(Object.getOwnPropertyDescriptor(realm, name)).toMatchObject({ writable: false, configurable: false });
      }
      if (worker) {
        expect(h.call.mock.calls.some(([method]) => method === 'Fetch.enable')).toBe(false);
        expect(h.call).toHaveBeenCalledWith('Network.setBlockedURLs', { urlPatterns: [
          { urlPattern: 'ws://*:*/*', block: true }, { urlPattern: 'wss://*:*/*', block: true },
          { urlPattern: 'http://*:*/*', block: true }, { urlPattern: 'https://*:*/*', block: true },
        ] }, 'page');
        expect(() => guard.prepare({ url: endpoint, method: 'POST' })).toThrow();
      } else expect(h.call.mock.calls.findIndex(([method]) => method === 'Runtime.evaluate')).toBeLessThan(h.call.mock.calls.findIndex(([method]) => method === 'Fetch.enable'));
      const pageScript = h.call.mock.calls.find(([method]) => method === 'Page.addScriptToEvaluateOnNewDocument');
      if (worker) expect(pageScript).toBeUndefined();
      else expect(pageScript?.[1]?.source).toBe(evaluate![1]!.expression);
    }
  });
  it('registers paused page and iframe lockdown without evaluating a missing execution context', async () => {
    const h = harness();
    h.call.mockImplementation(async method => { if (method === 'Runtime.evaluate') throw Error('context not yet created'); return {}; });
    await createSessionRequestGuard(h.protocol, 'child', [], { waitingForDebugger: true });
    expect(h.call).toHaveBeenCalledWith('Page.addScriptToEvaluateOnNewDocument', { source: expect.stringContaining('PerchDisabledChannel'), runImmediately: true }, 'child');
    expect(h.call).toHaveBeenCalledWith('Page.enable', {}, 'child');
    expect(h.call.mock.calls.findIndex(([method]) => method === 'Page.enable')).toBeLessThan(h.call.mock.calls.findIndex(([method]) => method === 'Page.addScriptToEvaluateOnNewDocument'));
    expect(h.call.mock.calls.some(([method]) => method === 'Runtime.evaluate')).toBe(false);
    expect(h.call).toHaveBeenCalledWith('Fetch.enable', expect.any(Object), 'child');
  });
  it('is idempotent when inherited frame injection and target initialization both run', async () => {
    const h = harness(); await createSessionRequestGuard(h.protocol, 'page');
    const script = String(h.call.mock.calls.find(([method]) => method === 'Runtime.evaluate')![1]!.expression);
    const realm = { WebSocket: function NativeSocket() {}, DOMException };
    expect(runInNewContext(script, realm)).toBe(true);
    const first = realm.WebSocket;
    expect(runInNewContext(script, realm)).toBe(true);
    expect(realm.WebSocket).toBe(first);
    expect(() => Reflect.construct(realm.WebSocket, [])).toThrow('disabled');
  });
  it('fails closed when lockdown evaluation returns an exception', async () => {
    const h = harness(); h.call.mockImplementation(async method => method === 'Runtime.evaluate' ? { exceptionDetails: { text: 'private information' } } : {});
    await expect(createSessionRequestGuard(h.protocol, 'page')).rejects.toThrow('Could not install');
    expect(h.listeners.size).toBe(0);
    expect(h.call.mock.calls.some(([method]) => method === 'Fetch.enable')).toBe(false);
  });
  it('installs request-stage interception before returning and denies background mutations', async () => {
    const h = harness(); await createSessionRequestGuard(h.protocol, 'page');
    expect(h.call).toHaveBeenCalledWith('Fetch.enable', { patterns: [{ urlPattern: 'http://*', requestStage: 'Request' }, { urlPattern: 'https://*', requestStage: 'Request' }] }, 'page');
    for (const method of ['GET', 'HEAD', 'OPTIONS']) expect((await h.paused(endpoint, method))[0]?.[0]).toBe('Fetch.continueRequest');
    for (const method of ['POST', 'PATCH', 'PUT', 'DELETE']) expect((await h.paused(endpoint, method))[0]?.[0]).toBe('Fetch.failRequest');
    expect(await h.paused(endpoint, 'POST', 'other')).toEqual([]);
  });
  it('allows authentication POSTs only on exact HTTPS login hosts and the Teams auth endpoint', async () => {
    const h = harness(); await createSessionRequestGuard(h.protocol, 'page', ['sso.example.org', 'teams.microsoft.com', 'tenant.sharepoint.com', 'outlook.office.com', 'graph.microsoft.com']);
    for (const url of ['https://login.microsoftonline.com/common/oauth2/token', 'https://login.live.com/post.srf', 'https://account.live.com/a', 'https://sso.example.org/saml', 'https://teams.microsoft.com/api/authsvc/v1.0/authz', 'https://teams.cloud.microsoft/api/authsvc/v1.0/authz']) expect((await h.paused(url, 'POST'))[0]?.[0]).toBe('Fetch.continueRequest');
    for (const url of ['http://login.live.com/a', 'https://login.live.com.evil.test/a', 'https://login.live.com:444/a', 'https://user@login.live.com/a', 'https://tenant.sharepoint.com/_api/items', 'https://graph.microsoft.com/v1.0/me', 'https://teams.microsoft.com/api/presence', 'https://teams.microsoft.com/api/authsvc/v1.0/authz/extra', endpoint]) expect((await h.paused(url, 'POST'))[0]?.[0]).toBe('Fetch.failRequest');
  });
  it('permits login bridge authentication but keeps CDN and lookalike POSTs blocked', async () => {
    const h = harness(); await createSessionRequestGuard(h.protocol, 'page');
    expect((await h.paused('https://login.microsoft.com/common/bridge/fido', 'POST'))[0]?.[0]).toBe('Fetch.continueRequest');
    for (const url of ['http://login.microsoft.com/common/bridge/fido', 'https://login.microsoft.com.evil.test/common/bridge/fido', 'https://res.public.onecdn.static.microsoft/asset']) {
      expect((await h.paused(url, 'POST'))[0]?.[0]).toBe('Fetch.failRequest');
    }
  });
  it('strips a typed ticket for OPTIONS and exactly one binary PUT without changing query or body', async () => {
    const h = harness(); const guard = await createSessionRequestGuard(h.protocol, 'page');
    const ticket = guard.prepare({ url: endpoint, method: 'PUT' });
    expect(new URL(ticket.url).searchParams.get('__perch_request')).toMatch(/^[a-f0-9]{64}$/);
    for (const method of ['OPTIONS', 'PUT']) {
      const calls = await h.paused(ticket.url, method);
      expect(calls).toHaveLength(1);
      expect(calls[0]).toEqual(['Fetch.continueRequest', { requestId: expect.any(String), url: endpoint }, 'page']);
    }
    expect((await h.paused(ticket.url, 'PUT'))[0]?.[0]).toBe('Fetch.failRequest');
    ticket.release(); ticket.release();
  });
  it('binds tickets to exact target and intended method; unknown, duplicate and canceled tickets cannot bypass', async () => {
    const h = harness(); const guard = await createSessionRequestGuard(h.protocol, 'page');
    const ticket = guard.prepare({ url: endpoint, method: 'PATCH' });
    for (const [url, method] of [[ticket.url.replace('/item?', '/other?'), 'PATCH'], [ticket.url, 'DELETE'], [`${ticket.url}&__perch_request=extra`, 'PATCH'], [`${endpoint}&__perch_request=unknown`, 'GET']]) expect((await h.paused(url!, method!))[0]?.[0]).toBe('Fetch.failRequest');
    ticket.release();
    expect((await h.paused(ticket.url, 'PATCH'))[0]?.[0]).toBe('Fetch.failRequest');
    const read = guard.prepare({ url: endpoint, method: 'GET' });
    expect((await h.paused(read.url, 'GET'))[0]?.[1]?.url).toBe(endpoint);
  });
  it('consumes synchronously under concurrent events and rejects malformed background requests', async () => {
    const h = harness(); const guard = await createSessionRequestGuard(h.protocol, 'page');
    const ticket = guard.prepare({ url: endpoint, method: 'PATCH' });
    const [first, second] = await Promise.all([h.paused(ticket.url, 'PATCH'), h.paused(ticket.url, 'PATCH')]);
    expect(first[0]?.[0]).toBe('Fetch.continueRequest');
    expect(second[0]?.[0]).toBe('Fetch.failRequest');
    for (const url of ['not a url', 'data:text/plain,a', 'https://outlook.office.com/a#secret']) expect((await h.paused(url, 'GET'))[0]?.[0]).toBe('Fetch.failRequest');
    expect((await h.paused(endpoint, 'TRACE'))[0]?.[0]).toBe('Fetch.failRequest');
    const signed = 'https://tenant.sharepoint.com/_layouts/15/download.aspx?sig=a%2Bb%20c&x=%7E';
    const download = guard.prepare({ url: signed, method: 'GET' });
    expect((await h.paused(download.url, 'GET'))[0]?.[1]?.url).toBe(signed);
  });
  it('expires tickets at ten seconds and bounds the outstanding set to 64', async () => {
    vi.useFakeTimers(); vi.setSystemTime(1000);
    const h = harness(); const guard = await createSessionRequestGuard(h.protocol, 'page');
    const tickets = Array.from({ length: 64 }, () => guard.prepare({ url: endpoint, method: 'PATCH' }));
    expect(new Set(tickets.map(t => t.url)).size).toBe(64);
    expect(() => guard.prepare({ url: endpoint, method: 'PATCH' })).toThrow();
    vi.setSystemTime(11_000);
    expect((await h.paused(tickets[0]!.url, 'PATCH'))[0]?.[0]).toBe('Fetch.failRequest');
    expect(() => guard.prepare({ url: endpoint, method: 'PATCH' })).not.toThrow();
  });
  it('fails closed if continuation fails and removes its listener on close without disabling interception', async () => {
    const h = harness(); const guard = await createSessionRequestGuard(h.protocol, 'page');
    const ticket = guard.prepare({ url: endpoint, method: 'POST' });
    h.call.mockImplementation(async (method) => { if (method === 'Fetch.continueRequest') throw Error('detached'); return {}; });
    expect((await h.paused(ticket.url, 'POST')).map(c => c[0])).toEqual(['Fetch.continueRequest', 'Fetch.failRequest']);
    guard.close(); guard.close();
    expect(h.listeners.size).toBe(0);
    expect(() => guard.prepare({ url: endpoint, method: 'GET' })).toThrow();
    expect(h.call.mock.calls.some(c => c[0] === 'Fetch.disable')).toBe(false);
  });
  it('cleans listener on install error and rejects invalid caller URLs/methods without leaking values', async () => {
    const h = harness(); h.call.mockRejectedValueOnce(Error('private details'));
    await expect(createSessionRequestGuard(h.protocol, 'page')).rejects.toThrow('Could not install');
    expect(h.listeners.size).toBe(0);
    const guard = await createSessionRequestGuard(h.protocol, 'page');
    for (const url of [`${endpoint}&__perch_request=existing`, 'https://user:secret@outlook.office.com/a', 'https://outlook.office.com/a#secret', 'http://outlook.office.com/a']) expect(() => guard.prepare({ url, method: 'GET' })).toThrow();
    expect(() => guard.prepare({ url: endpoint, method: 'TRACE' })).toThrow();
  });
});
it('rejects new service worker registration before page scripts and keeps lockdown idempotent',async()=>{
 const h=harness();await createSessionRequestGuard(h.protocol,'page',[],{waitingForDebugger:true});
 const script=String(h.call.mock.calls.find(c=>c[0]==='Page.addScriptToEvaluateOnNewDocument')![1]!.source);
 let registered=0;class Container{async register(){registered++;return{};}}
 const realm={ServiceWorkerContainer:Container,DOMException};
 expect(runInNewContext(script,realm)).toBe(true);
 expect(runInNewContext(script,realm)).toBe(true);
 await expect(new Container().register()).rejects.toMatchObject({name:'SecurityError'});
 expect(registered).toBe(0);
 expect(Object.getOwnPropertyDescriptor(Container.prototype,'register')).toMatchObject({configurable:false,writable:false});
});

it('allows only the document form-post callback that completes Microsoft 365 SSO', async () => {
 const h=harness();await createSessionRequestGuard(h.protocol,'page');
 const form={postData:'code=auth-code&id_token=id-token&state=state&session_state=session&correlation_id=correlation'};
 const allowed=await h.paused('https://m365.cloud.microsoft/landingv2','POST','page',form,'Document');
 expect(allowed[0]?.[0]).toBe('Fetch.continueRequest');
 for(const [url,body,type] of [
 ['https://m365.cloud.microsoft/landingv2',form,'XHR'],
 ['https://m365.cloud.microsoft/landingv2', {postData:'code=code&state=state&delete=1'},'Document'],
 ['https://m365.cloud.microsoft/landingv2',{postData:'code=code&code=other&state=state'},'Document'],
 ['https://m365.cloud.microsoft/landingv2',{postData:'state=state'},'Document'],
 ['https://m365.cloud.microsoft/landingv2/other',form,'Document'],
 ['https://m365.cloud.microsoft.evil.example/landingv2',form,'Document'],
 ] as const)expect((await h.paused(url,'POST','page',body,type))[0]?.[0]).toBe('Fetch.failRequest');
});
it('allows only encrypted SharePoint sign-in form returns, never API writes',async()=>{
 const h=harness();await createSessionRequestGuard(h.protocol,'page');
 const form={postData:'ear_jwe=encrypted-auth-response&state=state'};
 for(const host of ['tenant.sharepoint.com','tenant-my.sharepoint.com','tenant.sharepoint.de'])expect((await h.paused(`https://${host}/_forms/default.aspx`,'POST','page',form,'Document'))[0]?.[0]).toBe('Fetch.continueRequest');
 for(const [url,data,type] of [
 ['https://tenant.sharepoint.com/_forms/default.aspx',form,'XHR'],
 ['https://tenant.sharepoint.com/_forms/default.aspx?next=other',form,'Document'],
 ['https://tenant.sharepoint.com/_forms/default.aspx',{postData:'ear_jwe=one&ear_jwe=two&state=state'},'Document'],
 ['https://tenant.sharepoint.com/_forms/default.aspx',{postData:'ear_jwe=one&state=state&delete=1'},'Document'],
 ['https://tenant.sharepoint.com/_forms/default.aspx',{postData:'state=state'},'Document'],
 ['https://tenant.sharepoint.com/_api/items',form,'Document'],
 ['https://tenant.sharepoint.com.evil.test/_forms/default.aspx',form,'Document'],
 ['https://extra.tenant.sharepoint.com/_forms/default.aspx',form,'Document'],
 ] as const)expect((await h.paused(url,'POST','page',data,type))[0]?.[0]).toBe('Fetch.failRequest');
});
