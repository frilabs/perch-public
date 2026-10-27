import { expect, it } from 'vitest';
import { importPortableState, parsePortableState, portableAllowedDomains, portableAllowedHosts } from '../src/microsoft/session/portableState.js';
import type { BrowserEvent } from '../src/microsoft/sessionBrowser.js';

const state = () => ({ version: 1, cookies: [{ name: 'session', value: 'DUMMY-SECRET', domain: '.login.microsoftonline.com', path: '/', secure: true, httpOnly: true, expires: -1, sameSite: 'None' }], origins: [{ origin: 'https://login.microsoftonline.com', localStorage: [{ name: 'cache', value: 'DUMMY-CACHE' }], sessionStorage: [] }] });

it('accepts only portable Microsoft state and preserves cookie attributes', () => {
  expect(parsePortableState(state())).toEqual(state());
  expect(portableAllowedDomains()).toContain('microsoftonline.com');
  expect(portableAllowedHosts(['SSO.example.org'])).toEqual(['sso.example.org']);
  const s = state(); s.cookies[0]!.domain = 'sso.example.org'; s.origins = [];
  expect(() => parsePortableState(s)).toThrow();
  expect(parsePortableState(s, ['sso.example.org']).cookies).toHaveLength(1);
});

it('rejects unrelated hosts, lookalikes, public suffixes, private origins and secret-bearing errors', () => {
  for (const domain of ['evil.test', 'login.microsoftonline.com.evil.test', 'com', '127.0.0.1', '.sso.example.org']) {
    const s = state(); s.cookies[0]!.domain = domain;
    expect(() => parsePortableState(s)).toThrow(/Invalid Microsoft session transfer/);
  }
  for (const origin of ['http://login.microsoftonline.com', 'https://login.microsoftonline.com:444', 'https://user:password@login.microsoftonline.com', 'https://login.microsoftonline.com/path', 'https://login.microsoftonline.com/?secret=hidden', 'https://127.0.0.1']) {
    const s = state(); s.origins[0]!.origin = origin;
    try { parsePortableState(s); throw new Error('accepted invalid origin'); }
    catch (e) { expect(String(e)).not.toMatch(/DUMMY|password|hidden/); expect(String(e)).toContain('Invalid Microsoft session transfer'); }
  }
  expect(() => portableAllowedHosts(['*.example.org'])).toThrow();
  expect(() => portableAllowedHosts(['127.0.0.1'])).toThrow();
});

it('bounds payloads and rejects malformed cookie and storage fields', () => {
  for (const change of [
    { cookies: Array.from({ length: 501 }, () => state().cookies[0]) },
    { cookies: [{ ...state().cookies[0], value: 'x'.repeat(20_000) }] },
    { cookies: [{ ...state().cookies[0], name: 'bad\nname' }] },
    { cookies: [{ ...state().cookies[0], partitionKey: { topLevelSite: 'http://127.0.0.1', hasCrossSiteAncestor: false } }] },
    { origins: [{ ...state().origins[0], localStorage: [{ name: 'key', value: 'x'.repeat(70_000) }] }] },
    { password: 'DUMMY-SECRET' }, { version: 2 },
  ]) expect(() => parsePortableState({ ...state(), ...change })).toThrow(/Invalid Microsoft session transfer/);
});

it('imports cookies before origin storage and never loads remote content for storage restoration', async () => {
  const listeners = new Set<(e: BrowserEvent) => void>();
  const calls: Array<{ method: string; params: any }> = [];
  const browser = { mainSessionId: 'main', protocol: {
    onEvent(fn: (e: BrowserEvent) => void) { listeners.add(fn); return () => listeners.delete(fn); },
    async call(method: string, params: any = {}) {
      calls.push({ method, params });
      if (method === 'Page.navigate') for (const fn of listeners) fn({ sessionId: 'main', method: 'Fetch.requestPaused', params: { requestId: 'doc', resourceType: 'Document', request: { url: params.url } } });
      return { result: { value: true } };
    },
  } };
  await importPortableState(browser, parsePortableState(state()));
  const cookies = calls.find(c => c.method === 'Storage.setCookies')!;
  expect(cookies.params.cookies[0]).not.toHaveProperty('expires');
  expect(cookies.params.cookies[0]).toMatchObject({ domain: '.login.microsoftonline.com', httpOnly: true, secure: true, sameSite: 'None' });
  expect(calls.findIndex(c => c.method === 'Storage.setCookies')).toBeLessThan(calls.findIndex(c => c.method === 'Page.navigate'));
  expect(calls.some(c => c.method === 'Fetch.fulfillRequest')).toBe(true);
  expect(calls.some(c => c.method === 'Fetch.continueRequest')).toBe(false);
  expect(calls.some(c => c.method === 'Fetch.disable')).toBe(false);
  const expression = calls.findLast(c => c.method === 'Runtime.evaluate')!.params.expression;
  expect(expression).toContain('localStorage.setItem');
  expect(expression).toContain('location.origin');
});
