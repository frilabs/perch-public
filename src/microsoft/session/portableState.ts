import { isIP } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import { PerchError } from '../../errors.js';
import type { SessionProtocol } from '../sessionBrowser.js';

export const PORTABLE_STATE_MAX_BYTES = 8 * 1024 * 1024;
const DOMAINS = ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'microsoft365.com', 'cloud.microsoft'];
export function portableAllowedDomains(): string[] { return [...DOMAINS]; }
function hostname(value: string): string {
  const host = value.toLowerCase();
  if (host.length > 253 || !host.includes('.') || isIP(host) || !host.split('.').every(p => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p)) || isIP(new URL(`https://${host}`).hostname) || /(?:^|\.)(?:local|localhost|internal|invalid|onion)$|(?:^|\.)home\.arpa$/.test(host)) throw Error('hostname');
  return host;
}
export function portableAllowedHosts(hosts: string[] = []): string[] {
  try { if (hosts.length > 64) throw Error('limit'); return [...new Set(hosts.map(hostname))]; }
  catch { throw new PerchError('Use at most 64 exact public Microsoft login hostnames.', 'bad_config'); }
}
function permitted(host: string, extras: string[]) { return extras.includes(host) || DOMAINS.some(root => host === root || host.endsWith(`.${root}`)); }
function origin(value: string, extras: string[]) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash || url.pathname !== '/' || value !== url.origin || !permitted(hostname(url.hostname), extras)) throw Error('origin');
  return url.origin;
}
const entry = z.object({ name: z.string().max(4096), value: z.string().max(65_536) }).strict();
const cookie = z.object({
  name: z.string().min(1).max(1024).refine(v => !/[\x00-\x20\x7f;=]/.test(v)),
  value: z.string().max(16_384).refine(v => !/[\x00-\x1f\x7f]/.test(v)),
  domain: z.string().min(1).max(254), path: z.string().startsWith('/').max(4096).refine(v => !/[\x00-\x1f\x7f]/.test(v)),
  secure: z.boolean(), httpOnly: z.boolean(), sameSite: z.enum(['Strict', 'Lax', 'None']).optional(),
  expires: z.number().finite().min(-1).max(253402300799).optional(),
  partitionKey: z.object({ topLevelSite: z.string().max(1024), hasCrossSiteAncestor: z.boolean() }).strict().optional(),
}).strict();
const schema = z.object({ version: z.literal(1), cookies: z.array(cookie).max(500), origins: z.array(z.object({
  origin: z.string().max(1024), localStorage: z.array(entry).max(500), sessionStorage: z.array(entry).max(500),
}).strict()).max(64) }).strict();
export type PortableState = z.infer<typeof schema>;
export function parsePortableState(value: unknown, hosts: string[] = []): PortableState {
  try {
    const extras = portableAllowedHosts(hosts);
    const serialized = JSON.stringify(value);
    if (!serialized || Buffer.byteLength(serialized) > PORTABLE_STATE_MAX_BYTES) throw Error('size');
    const state = schema.parse(value);
    for (const c of state.cookies) {
      const host = hostname(c.domain.replace(/^\./, ''));
      if (!permitted(host, extras) || (c.domain.startsWith('.') && extras.includes(host) && !DOMAINS.some(root => host === root || host.endsWith(`.${root}`)))) throw Error('cookie domain');
      if (c.partitionKey) origin(c.partitionKey.topLevelSite, extras);
    }
    const origins = new Set<string>();
    for (const o of state.origins) {
      origin(o.origin, extras);
      if (origins.has(o.origin)) throw Error('duplicate origin');
      origins.add(o.origin);
      for (const entries of [o.localStorage, o.sessionStorage]) if (new Set(entries.map(e => e.name)).size !== entries.length) throw Error('duplicate storage key');
    }
    return state;
  } catch { throw new PerchError('Invalid Microsoft session transfer. No account was changed.', 'invalid_session_transfer'); }
}

/** Caller supplies a fresh staged browser and closes it before real identity probes. */
export async function importPortableState(browser: { protocol: SessionProtocol; mainSessionId: string }, state: PortableState): Promise<void> {
  const { protocol, mainSessionId } = browser;
  let expected = '', failure = false;
  const remove = protocol.onEvent(event => {
    if (event.sessionId !== mainSessionId || event.method !== 'Fetch.requestPaused') return;
    const id = event.params?.requestId;
    if (typeof id !== 'string') return;
    const ownDocument = expected && event.params?.resourceType === 'Document' && event.params?.request?.url === `${expected}/`;
    void protocol.call(ownDocument ? 'Fetch.fulfillRequest' : 'Fetch.failRequest', ownDocument ? {
      requestId: id, responseCode: 200,
      responseHeaders: [{ name: 'Content-Type', value: 'text/html' }, { name: 'Content-Security-Policy', value: "default-src 'none'" }],
      body: Buffer.from('<!doctype html><title>Perch session import</title>').toString('base64'),
    } : { requestId: id, errorReason: 'BlockedByClient' }, mainSessionId).catch(() => { failure = true; });
  });
  try {
    await protocol.call('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] }, mainSessionId);
    await protocol.call('Storage.setCookies', { cookies: state.cookies.map(({ expires, ...rest }) => ({ ...rest, ...(expires !== undefined && expires >= 0 ? { expires } : {}) })) });
    for (const o of state.origins) {
      expected = o.origin;
      await protocol.call('Page.navigate', { url: `${expected}/` }, mainSessionId);
      let ready = false;
      for (let attempt = 0; attempt < 50; attempt++) {
        const result = await protocol.call('Runtime.evaluate', { expression: `location.origin===${JSON.stringify(expected)}&&document.readyState==='complete'`, returnByValue: true }, mainSessionId);
        if (result.result?.value === true) { ready = true; break; }
        await delay(100);
      }
      if (!ready || failure) throw Error('document');
      const result = await protocol.call('Runtime.evaluate', { expression: `(()=>{const state=${JSON.stringify(o)};if(location.origin!==state.origin)return false;for(const e of state.localStorage)localStorage.setItem(e.name,e.value);for(const e of state.sessionStorage)sessionStorage.setItem(e.name,e.value);return true})()`, returnByValue: true }, mainSessionId);
      if (result.exceptionDetails || result.result?.value !== true) throw Error('storage');
    }
    if (failure) throw Error('interception');
  } catch { throw new PerchError('Could not import Microsoft session. The previous account is unchanged.', 'session_import_failed'); }
  finally { remove(); /* Keep Fetch paused until the caller closes this temporary browser. */ }
}
