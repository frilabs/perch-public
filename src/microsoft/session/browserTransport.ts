import { getSessionTargetGuards, type SessionTargetGuards } from './targetGuards.js';
import { MICROSOFT_SIGN_IN_URL } from './login.js';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import { PerchError } from '../../errors.js';
import type { BrowserEvent, SessionProtocol } from '../sessionBrowser.js';
import type { MicrosoftIdentity, MicrosoftService, SelectedSite } from './model.js';
import { checkedJson, type SessionHttpRequest, type SessionHttpResponse, type SessionResource } from './contracts.js';
import { normalizeSelectedSiteUrl, parseUnverifiedSessionToken, resolveSessionRequest, type ResolvedSessionRequest, type SessionTransportConfig } from './policy.js';

type Metadata = { email?: string; displayName?: string };
type Captured = { headers: Record<string, string>; identity: MicrosoftIdentity; expiresAt: number; kind: 'bearer' | 'skype'; metadata: Metadata };
const sameIdentity = (a: MicrosoftIdentity, b: MicrosoftIdentity) => a.tenantId.toLowerCase() === b.tenantId.toLowerCase() && a.objectId.toLowerCase() === b.objectId.toLowerCase();
function claims(token: string): Record<string, unknown> {
  if (token.length > 65_536) throw new Error();
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) throw new Error();
  const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString());
  if (!['RS256', 'PS256'].includes(header?.alg)) throw new Error();
  const value = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString());
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
  return value;
}
function tokenMetadata(token: string): Metadata {
  const value = claims(token), result: Metadata = {};
  const email = value.email ?? value.preferred_username ?? value.upn;
  if (z.string().email().max(320).safeParse(email).success) result.email = email as string;
  if (typeof value.name === 'string' && value.name.length <= 300 && !/[\u0000-\u001f]/.test(value.name)) result.displayName = value.name;
  return result;
}
function skypeCredential(value: string): Captured {
  const decoded = claims(value);
  const objectId = typeof decoded.skypeid === 'string' ? decoded.skypeid.match(/^orgid:([a-fA-F0-9-]+)$/)?.[1] : undefined;
  if (!z.string().uuid().safeParse(decoded.tid).success || !z.string().uuid().safeParse(objectId).success || typeof decoded.exp !== 'number' || !Number.isSafeInteger(decoded.exp) || decoded.exp <= Date.now() / 1000 || (decoded.nbf !== undefined && (typeof decoded.nbf !== 'number' || decoded.nbf > Date.now() / 1000))) throw new Error();
  return { headers: { Authentication: `skypetoken=${value}` }, identity: { tenantId: (decoded.tid as string).toLowerCase(), objectId: objectId!.toLowerCase(), kind: 'organization' }, expiresAt: decoded.exp, kind: 'skype', metadata: {} };
}
/** Credentials and CDP stay in the worker. The parent receives typed operation results only. */
export class BrowserSessionTransport {
  private tabs = new Map<string, string>();
  private targetGuards?: SessionTargetGuards;
  private closed=false;
  private resources = new Map<SessionResource, Captured>();
  private requests = new Map<string, { url: string; sessionId: string; method?: string }>();
  private bootstrapResponses = new Set<string>();
  private extraHeaders = new Map<string, unknown>();
  private mismatch = false;
  private dispose: () => void;
  private verifiedIdentity?: MicrosoftIdentity;
  private verifiedMetadata: Metadata = {};
  readonly config: SessionTransportConfig;
  constructor(private protocol: SessionProtocol, private sites: readonly SelectedSite[], private expected?: MicrosoftIdentity, private options: { waitMs?: number; beforeMutation?: () => Promise<void> } = {}) {
    this.config = { outlookOrigin: 'https://outlook.office.com', chatBase: '', csaBase: '', sites };
    this.dispose = protocol.onEvent((e) => this.observe(e));
  }
  close(): void { this.closed=true;this.targetGuards?.close();this.dispose(); this.resources.clear(); this.requests.clear(); this.extraHeaders.clear(); this.bootstrapResponses.clear(); }
  get identity(): MicrosoftIdentity | undefined { return this.verifiedIdentity; }
  get metadata(): Readonly<Metadata> { return { ...this.verifiedMetadata }; }
  private assertIdentity(identity?: MicrosoftIdentity): void {
    const expected = this.expected ?? this.verifiedIdentity;
    if(this.closed)throw new PerchError('Microsoft background request protection failed.','browser_failed');
    this.targetGuards?.assertHealthy();
    if (this.mismatch || (identity && expected && !sameIdentity(expected, identity))) {
      this.mismatch = true; this.resources.clear();
      throw new PerchError('The server browser changed Microsoft accounts. Reconnect the original account.', 'identity_mismatch');
    }
  }
  private resource(url: URL): SessionResource | undefined {
    if (['outlook.office.com', 'outlook.cloud.microsoft', 'outlook.live.com'].includes(url.hostname)) return 'outlook';
    if (['teams.microsoft.com', 'teams.cloud.microsoft'].includes(url.hostname)) {
      const match = url.pathname.match(/^\/api\/(chatsvc|csa)\/([a-z][a-z0-9-]{0,31})(?:\/|$)/);
      if (match) return match[1] === 'chatsvc' ? 'chat' : 'csa';
    }
    if (url.hostname === 'substrate.office.com') return 'substrate';
    if (url.hostname === 'graph.microsoft.com') return 'graph';
    return undefined;
  }
  private observe(e: BrowserEvent): void {
    if (!e.sessionId || ![...this.tabs.values()].includes(e.sessionId)) return;
    const p = e.params, key = `${e.sessionId}:${p?.requestId}`;
    if (e.method === 'Network.requestWillBeSent' && p?.request) {
      if (this.requests.size >= 500) this.requests.delete(this.requests.keys().next().value!);
      this.requests.set(key, { url: p.request.url, sessionId: e.sessionId, method: p.request.method });
      this.capture(p.request.url, p.request.headers);
      const extra = this.extraHeaders.get(key);
      if (extra) { this.capture(p.request.url, extra); this.extraHeaders.delete(key); }
    } else if (e.method === 'Network.responseReceived') {
      const request = this.requests.get(key);
      if (request?.method === 'POST' && ['https://teams.microsoft.com/api/authsvc/v1.0/authz', 'https://teams.cloud.microsoft/api/authsvc/v1.0/authz'].includes(request.url) && p.response?.url === request.url && p.response?.status === 200 && this.bootstrapResponses.size < 8) this.bootstrapResponses.add(key);
    } else if (e.method === 'Network.loadingFinished' || e.method === 'Network.loadingFailed') {
      const bootstrap = this.bootstrapResponses.delete(key);
      if (bootstrap && e.method === 'Network.loadingFinished' && typeof p.encodedDataLength === 'number' && p.encodedDataLength < 1024 * 1024) void this.captureTeamsBootstrap(e.sessionId, p.requestId);
    } else if (e.method === 'Network.requestWillBeSentExtraInfo') {
      // CDP explicitly permits ExtraInfo to arrive before requestWillBeSent.
      const request = this.requests.get(key);
      if (request) this.capture(request.url, p.headers);
      else { if (this.extraHeaders.size >= 500) this.extraHeaders.delete(this.extraHeaders.keys().next().value!); this.extraHeaders.set(key, p.headers); }
    }
  }
  /** Consume only the successful auth response generated by our owned Teams tab. */
  private async captureTeamsBootstrap(sessionId: string, requestId: string): Promise<void> {
    try {
      const response = await this.protocol.call('Network.getResponseBody', { requestId }, sessionId);
      if (typeof response.body !== 'string' || response.body.length > 1024 * 1024) return;
      const data = JSON.parse(response.base64Encoded ? Buffer.from(response.body, 'base64').toString('utf8') : response.body);
      const credential = skypeCredential(data?.tokens?.skypeToken);
      const chatBase = data?.regionGtms?.chatServiceAfd;
      if (typeof chatBase !== 'string') return;
      // Reuse the operation policy: no arbitrary regional host or token destination.
      resolveSessionRequest({ ...this.config, chatBase }, { resource: 'chat', path: '/v1/users/ME/conversations' });
      this.assertIdentity(credential.identity);
      this.config.chatBase = chatBase;
      this.resources.set('chat', credential);
    } catch { /* Missing/expired bootstrap remains unavailable; an identity mismatch stays latched. */ }
  }
  private capture(rawUrl: unknown, rawHeaders: unknown): void {
    if (typeof rawUrl !== 'string' || !rawHeaders || typeof rawHeaders !== 'object') return;
    let url: URL; try { url = new URL(rawUrl); } catch { return; }
    if (url.protocol !== 'https:' || url.username || url.password || url.port) return;
    const resource = this.resource(url); if (!resource) return;
    const headers = Object.fromEntries(Object.entries(rawHeaders).filter((x): x is [string, string] => typeof x[1] === 'string').map(([k, v]) => [k.toLowerCase(), v]));
    let captured: Captured;
    try {
      const skypeHeader = headers.authentication ?? (headers.authorization?.startsWith('skypetoken=') ? headers.authorization : undefined);
      if (resource === 'chat' && skypeHeader?.startsWith('skypetoken=')) captured = skypeCredential(skypeHeader.slice(11));
      else {
        const auth = headers.authorization; if (!auth?.startsWith('Bearer ')) return;
        const token = parseUnverifiedSessionToken(auth.slice(7));
        captured = { headers: { Authorization: auth }, identity: token.identity, expiresAt: token.expiresAt, kind: 'bearer', metadata: tokenMetadata(auth.slice(7)) };
        if (resource === 'csa' && skypeHeader?.startsWith('skypetoken=')) {
          const skype = skypeCredential(skypeHeader.slice(11));
          if (!sameIdentity(captured.identity, skype.identity)) { this.mismatch = true; this.resources.clear(); return; }
          captured.headers.Authentication = skype.headers.Authentication!;
          captured.expiresAt = Math.min(captured.expiresAt, skype.expiresAt);
        }
      }
    } catch { return; }
    try { this.assertIdentity(captured.identity); } catch { return; }
    this.resources.set(resource, captured);
    // Pin routing to the same observed request as the captured credential.
    if (resource === 'outlook') this.config.outlookOrigin = url.origin;
    if (resource === 'chat' || resource === 'csa') this.config[resource === 'chat' ? 'chatBase' : 'csaBase'] = `${url.origin}${url.pathname.match(/^\/api\/(?:chatsvc|csa)\/[a-z][a-z0-9-]{0,31}/)![0]}`;
  }
  async open(service: MicrosoftService | 'graph', siteId?: string): Promise<void> {
    const key = service === 'calendar' ? 'mail' : service === 'files' ? `site:${siteId}` : service;
    if (this.tabs.has(key)) return;
    const site = service === 'files' ? this.sites.find((s) => s.id === siteId) : undefined;
    if (service === 'files' && !site) throw new PerchError('Select this SharePoint site locally first.', 'resource_denied');
    const url = service === 'teams' ? 'https://teams.microsoft.com/v2/' : service === 'mail' || service === 'calendar' ? 'https://outlook.office.com/mail/' : site ? normalizeSelectedSiteUrl(site.url) : MICROSOFT_SIGN_IN_URL;
    this.targetGuards ??= await getSessionTargetGuards(this.protocol);
    if (this.closed) this.targetGuards.close();
    this.assertIdentity();
    const { sessionId } = await this.targetGuards.createPage();
    if (service === 'teams') {
      // A warm Teams localStorage cache can skip the auth bootstrap while its
      // background worker is intentionally restricted. Refresh only this app's
      // local state in Perch's dedicated profile; retain cookies and Microsoft SSO.
      for (const origin of ['https://teams.microsoft.com', 'https://teams.cloud.microsoft']) {
        await this.protocol.call('Storage.clearDataForOrigin', { origin, storageTypes: 'local_storage' }, sessionId);
      }
    }
    this.tabs.set(key, sessionId);
    await this.protocol.call('Network.setBypassServiceWorker',{bypass:true},sessionId);
    await this.protocol.call('Network.enable', {}, sessionId);
    await this.protocol.call('Page.enable', {}, sessionId);
    await this.protocol.call('Page.navigate', { url }, sessionId);
  }
  private tab(resource: SessionResource, siteId?: string): string | undefined {
    return this.tabs.get(resource === 'outlook' ? 'mail' : resource === 'sharepoint' || resource === 'download' ? `site:${siteId}` : resource === 'graph' ? 'graph' : 'teams');
  }
  private async waitForSite(tab: string, origin: string): Promise<void> {
    const until = Date.now() + (this.options.waitMs ?? 30_000);
    do {
      this.assertIdentity();
      try { const state = await this.protocol.call('Runtime.evaluate', { expression: 'location.origin', returnByValue: true }, tab); if (state.result?.value === origin) return; } catch { /* navigation can destroy the old execution context */ }
      if (Date.now() >= until) break;
      await delay(Math.min(100, Math.max(1, until - Date.now())));
    } while (true);
    throw new PerchError('The selected SharePoint site is not signed in or has not finished loading.', 'reauth_required');
  }
  private async preflight(input: SessionHttpRequest, tab: string): Promise<string | undefined> {
    if (input.resource === 'sharepoint') {
      const identity = this.expected ?? this.verifiedIdentity;
      if (!identity) throw new PerchError('Confirm the Microsoft identity before writing files.', 'identity_unverified');
      const result = checkedJson(await this.request({ resource: 'sharepoint', siteId: input.siteId, path: '/_api/web/currentuser', query: { '$select': 'AadObjectId' } }));
      const user = result.d ?? result;
      if (typeof user.AadObjectId?.NameId !== 'string' || user.AadObjectId.NameId.toLowerCase() !== identity.objectId.toLowerCase()) { this.mismatch = true; this.assertIdentity(); }
      const site = this.sites.find((s) => s.id === input.siteId)!;
      // Cookie-authenticated SharePoint writes require a form digest. This fixed
      // credential-management endpoint is private and absent from operation policy.
      const response = await this.perform(tab, { url: `${normalizeSelectedSiteUrl(site.url)}/_api/contextinfo`, method: 'POST', headers: { Accept: 'application/json;odata=nometadata' }, maxBytes: 64 * 1024, responseType: 'json', redirect: 'error', credentials: 'include', sendAuthorization: false });
      const data = checkedJson(response);
      const digest = data.FormDigestValue ?? data.GetContextWebInformation?.FormDigestValue ?? data.d?.GetContextWebInformation?.FormDigestValue;
      if (typeof digest !== 'string' || !digest || digest.length > 8192 || /[\r\n\u0000]/.test(digest)) throw new PerchError('SharePoint did not provide a usable request digest.', 'invalid_response');
      return digest;
    }
    const probes: Partial<Record<SessionResource, string>> = { outlook: '/api/v2.0/me', chat: '/v1/users/ME/conversations' };
    const path = probes[input.resource];
    if (!path) throw new PerchError('No identity preflight is available for this mutation.', 'identity_unverified');
    checkedJson(await this.request({ resource: input.resource, path, maxBytes: 4 * 1024 * 1024 }));
    return undefined;
  }
  async request(input: SessionHttpRequest): Promise<SessionHttpResponse> {
    this.assertIdentity();
    // Teams channel enumeration uses the same Microsoft 365 web session.
    if (input.resource === 'graph' && !this.tabs.has('graph')) await this.open('graph');
    const tab = this.tab(input.resource, input.siteId);
    if (!tab) throw new PerchError('Microsoft service has not been opened in this session.', 'reauth_required');
    const needsHeader = !['sharepoint', 'download'].includes(input.resource);
    const until = Date.now() + (this.options.waitMs ?? 30_000);
    let credential = this.resources.get(input.resource);
    while (needsHeader && (!credential || credential.expiresAt <= Date.now() / 1000 + 10) && Date.now() < until && !this.mismatch) {
      await delay(Math.min(100, Math.max(1, until - Date.now()))); credential = this.resources.get(input.resource);
    }
    this.assertIdentity(credential?.identity);
    if (needsHeader && (!credential || credential.expiresAt <= Date.now() / 1000 + 10)) throw new PerchError('No usable Microsoft web session. Run perch microsoft reconnect GROUP_ID.', 'reauth_required');
    if (credential?.kind === 'skype' && !this.expected && !this.verifiedIdentity) throw new PerchError('Verify an Entra-backed Microsoft service before accepting Skype chat credentials.', 'identity_unverified');
    const resolved = resolveSessionRequest(this.config, input);
    if (input.resource === 'sharepoint' || input.resource === 'download') await this.waitForSite(tab, new URL(resolved.url).origin);
    const mutation = resolved.method !== 'GET' && input.resource !== 'substrate';
    const digest = mutation ? await this.preflight(input, tab) : undefined;
    this.assertIdentity(credential?.identity);
    const headers = { ...resolved.headers, ...(needsHeader ? credential!.headers : {}) };
    if (input.resource !== 'download') {
      if (!Object.keys(headers).some((key) => key.toLowerCase() === 'accept')) headers.Accept = 'application/json';
      if (resolved.body !== undefined && !Object.keys(headers).some((key) => key.toLowerCase() === 'content-type')) headers['Content-Type'] = 'application/json';
    }
    if (digest) headers['X-RequestDigest'] = digest;
    // Header-authenticated API requests omit ambient cookies: API acceptance must
    // concern this credential, and Graph/Substrate CORS need not allow credentials.
    if (mutation) await this.options.beforeMutation?.();
    const response = await this.perform(tab, { ...resolved, headers, credentials: needsHeader ? 'omit' : resolved.credentials });
    if (credential && response.status >= 200 && response.status < 300) {
      this.assertIdentity(credential.identity);
      this.verifiedIdentity = credential.identity;
      if (credential.kind === 'bearer') this.verifiedMetadata = { ...this.verifiedMetadata, ...credential.metadata };
    }
    return response;
  }
  private async perform(tab: string, request: ResolvedSessionRequest): Promise<SessionHttpResponse> {
    this.assertIdentity();
    const guard=this.targetGuards?.guard(tab);if(!guard)throw new PerchError('Microsoft request guard is unavailable.','browser_failed');
    const ticket=request.method==='GET'?undefined:guard.prepare(request);
    const payload = { url: ticket?.url??request.url, method: request.method, headers: request.headers, body: request.body, bodyBase64: request.bodyBase64, maxBytes: request.maxBytes, credentials: request.credentials };
    // JSON quoting prevents request strings from becoming executable code.
    const expression = `(async(p)=>{
      const ctl=new AbortController(),timer=setTimeout(()=>ctl.abort(),8000);
      try {
        let body=p.bodyBase64===undefined?(p.body===undefined?undefined:JSON.stringify(p.body)):Uint8Array.from(atob(p.bodyBase64),c=>c.charCodeAt(0));
        const response=await fetch(p.url,{method:p.method,headers:p.headers,body,credentials:p.credentials,redirect:'error',signal:ctl.signal});
        const declared=Number(response.headers.get('content-length'));if(declared>p.maxBytes)throw Error('too_large');
        const reader=response.body?.getReader(),chunks=[];let size=0;
        if(reader)for(;;){const item=await reader.read();if(item.done)break;size+=item.value.length;if(size>p.maxBytes){await reader.cancel();throw Error('too_large');}chunks.push(item.value);}
        let binary='';for(const chunk of chunks)for(let i=0;i<chunk.length;i+=32768)binary+=String.fromCharCode(...chunk.subarray(i,i+32768));
        return {status:response.status,headers:Object.fromEntries(['content-type','etag','content-range'].map(k=>[k,response.headers.get(k)||''])),body:btoa(binary)};
      }catch(e){return {failure:e?.message==='too_large'?'response_too_large':'browser_request_failed'};}finally{clearTimeout(timer);}
    })(${JSON.stringify(payload)})`;
    const result = await this.protocol.call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, tab).finally(()=>ticket?.release());
    const value = result?.result?.value;
    if (result.exceptionDetails || !value || value.failure) throw new PerchError('Microsoft browser request failed or exceeded its response limit.', value?.failure === 'response_too_large' ? 'response_too_large' : 'browser_request_failed');
    if (!Number.isInteger(value.status) || typeof value.body !== 'string' || value.body.length > Math.ceil(request.maxBytes * 4 / 3) + 4) throw new PerchError('Invalid browser response.', 'invalid_response');
    const body = Buffer.from(value.body, 'base64');
    if (body.length > request.maxBytes) throw new PerchError('Microsoft response is too large.', 'response_too_large');
    return { status: value.status, headers: value.headers ?? {}, body };
  }
}
