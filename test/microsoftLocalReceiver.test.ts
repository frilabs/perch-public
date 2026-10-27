import { afterEach, expect, it } from 'vitest';
import { startLocalSessionReceiver } from '../src/microsoft/localSessionReceiver.js';
import { request } from 'node:http';
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { for (const close of cleanups.splice(0)) await close(); });
const state = { version: 1, cookies: [{ name: 'session', value: 'DUMMY-SECRET', domain: 'login.microsoftonline.com', path: '/', secure: true, httpOnly: true }], origins: [] };
async function fixture(timeoutMs = 60000) {
  const receiver = await startLocalSessionReceiver({ port: 0, timeoutMs, label: 'Test', helperSource: '/* fixed helper */' });
  cleanups.push(receiver.close);
  return { ...receiver, base: `http://127.0.0.1:${receiver.port}`, headers: { Authorization: `Bearer ${receiver.token}`, 'Content-Type': 'application/json' } };
}
it('serves only fixed helper source publicly and requires a Bearer token for metadata and upload', async () => {
  const f = await fixture();
  expect(await (await fetch(`${f.base}/helper.mjs`)).text()).toBe('/* fixed helper */');
  expect((await fetch(`${f.base}/session`)).status).toBe(401);
  expect((await fetch(`${f.base}/session`, { headers: { Authorization: 'Bearer wrong' } })).status).toBe(401);
  const meta = await (await fetch(`${f.base}/session`, { headers: f.headers })).json();
  expect(meta).toMatchObject({ version: 1, label: 'Test', allowedDomains: expect.arrayContaining(['microsoftonline.com']), allowedHosts: [] });
  expect(JSON.stringify(meta)).not.toContain(f.token);
  expect((await fetch(`${f.base}/session`, { method: 'POST', headers: f.headers, body: JSON.stringify(state) })).status).toBe(200);
  expect(await f.done).toEqual(state);
});
it('rejects browser origins, cookies, rebinding hosts and state from unrelated sites', async () => {
  const f = await fixture();
  expect((await fetch(`${f.base}/session`, { headers: { ...f.headers, Origin: 'https://evil.test' } })).status).toBe(403);
  expect((await fetch(`${f.base}/session`, { headers: { Cookie: `token=${f.token}` } })).status).toBe(401);
  const rebound = await new Promise(resolve => { const r = request(`${f.base}/session`, { headers: { ...f.headers, Host: 'evil.test' } }, res => { res.resume(); resolve(res.statusCode); }); r.end(); });
  expect(rebound).toBe(403);
  const result = await fetch(`${f.base}/session`, { method: 'POST', headers: f.headers, body: JSON.stringify({ ...state, cookies: [{ ...state.cookies[0], domain: 'evil.test' }] }) });
  expect(result.status).toBe(400); expect(await result.text()).not.toContain('DUMMY-SECRET');
});
it('rejects oversized input without echoing any payload', async () => {
  const f = await fixture();
  const result = await new Promise<{ status?: number; body: string }>((resolve, reject) => {
    const req = request(`${f.base}/session`, { method: 'POST', headers: { ...f.headers, 'Content-Length': 9 * 1024 * 1024 } }, res => {
      let body = ''; res.on('data', chunk => { body += chunk; }); res.on('end', () => resolve({ status: res.statusCode, body }));
    }); req.on('error', reject); req.end('DUMMY-SECRET');
  });
  expect(result.status).toBe(413); expect(result.body).not.toContain('DUMMY');
});
it('accepts only one concurrent state upload', async () => {
  const f = await fixture();
  const results = await Promise.allSettled([1, 2].map(() => fetch(`${f.base}/session`, { method: 'POST', headers: f.headers, body: JSON.stringify(state) })));
  expect(results.filter(r => r.status === 'fulfilled' && r.value.status === 200)).toHaveLength(1);
  expect(await f.done).toEqual(state);
});
it('expires and supports authenticated cancellation without accepting state', async () => {
  const short = await fixture(30); expect(await short.done).toBeUndefined();
  const f = await fixture();
  expect((await fetch(`${f.base}/cancel`, { method: 'POST', headers: f.headers, body: '{}' })).status).toBe(200);
  expect(await f.done).toBeUndefined();
  await f.close(); await f.close();
});
