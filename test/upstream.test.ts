// Uses a local MOCK HTTP server (fake upstream) and in-memory MOCK transports. No live services.
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createFetchTransport, Upstream, type UpstreamRequest } from '../src/upstream.js';
import { dummySecret, rejection } from './support/fixtures.js';

let server: Server;
let base: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.url === '/big') {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(Buffer.alloc(4096, 1));
    } else if (req.url === '/small') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    } else if (req.url === '/redirect') {
      res.writeHead(302, { location: '/small' });
      res.end();
    } else if (req.url === '/hang') {
      // never respond
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => {
  server.closeAllConnections();
  await new Promise((r) => server.close(r));
});

const get = (url: string, maxBytes = 1024): UpstreamRequest => ({
  method: 'GET',
  url: new URL(url),
  headers: {},
  maxBytes,
});

describe('fetch transport [mock upstream server]', () => {
  it('returns small bodies', async () => {
    const t = createFetchTransport({ timeoutMs: 2000 });
    const res = await t(get(`${base}/small`));
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body.toString())).toEqual({ ok: true });
  });

  it('aborts responses larger than maxBytes', async () => {
    const t = createFetchTransport({ timeoutMs: 2000 });
    await expect(t(get(`${base}/big`, 1024))).rejects.toMatchObject({ code: 'response_too_large' });
  });

  it('times out', async () => {
    const t = createFetchTransport({ timeoutMs: 150 });
    await expect(t(get(`${base}/hang`))).rejects.toMatchObject({ code: 'upstream_timeout' });
  });

  it('does not follow redirects', async () => {
    const t = createFetchTransport({ timeoutMs: 2000 });
    await expect(t(get(`${base}/redirect`))).rejects.toMatchObject({ code: 'upstream_unreachable' });
  });
});

describe('Upstream route allowlist and error sanitising [mock transport]', () => {
  function recordingUpstream(response: { status: number; body: string }) {
    const calls: UpstreamRequest[] = [];
    const up = new Upstream(async (req) => {
      calls.push(req);
      return { status: response.status, headers: { 'content-type': 'application/json' }, body: Buffer.from(response.body) };
    });
    return { up, calls };
  }

  it('builds URLs only on the fixed production origin', async () => {
    const { up, calls } = recordingUpstream({ status: 200, body: '{}' });
    await up.json('notion', { method: 'GET', path: '/v1/users/me', headers: { authorization: 'Bearer x' } });
    expect(calls[0]!.url.origin).toBe('https://api.notion.com');
    await up.json('drive', { method: 'GET', path: '/drive/v3/files', query: { q: "name contains 'a'" } });
    expect(calls[1]!.url.origin).toBe('https://www.googleapis.com');
    expect(calls[1]!.url.searchParams.get('q')).toBe("name contains 'a'");
  });

  it.each([
    ['notion', 'PATCH', '/v1/pages/0123456789abcdef0123456789abcdef'],
    ['notion', 'POST', '/v1/pages'],
    ['notion', 'DELETE', '/v1/blocks/0123456789abcdef0123456789abcdef'],
    ['notion', 'PATCH', '/v1/blocks/0123456789abcdef0123456789abcdef/children'],
    ['notion', 'POST', '/v1/comments'],
    ['notion', 'GET', '/v1/users'],
    ['notion', 'GET', '/v1/pages/../users'],
    ['drive', 'POST', '/drive/v3/files'],
    ['drive', 'PATCH', '/drive/v3/files/abc'],
    ['drive', 'DELETE', '/drive/v3/files/abc'],
    ['drive', 'GET', '/upload/drive/v3/files'],
    ['oauth', 'GET', '/token'],
  ] as const)('rejects %s %s %s before any network call', async (service, method, p) => {
    const { up, calls } = recordingUpstream({ status: 200, body: '{}' });
    await expect(up.json(service, { method: method as 'GET', path: p })).rejects.toMatchObject({
      code: 'route_not_allowed',
    });
    expect(calls).toHaveLength(0);
  });

  it('sanitises error bodies: keeps only status and a safe code', async () => {
    const leaked = dummySecret('LEAK');
    const { up } = recordingUpstream({
      status: 404,
      body: JSON.stringify({ object: 'error', code: 'object_not_found', message: `secret ${leaked}` }),
    });
    const err = await rejection(up.json('notion', { method: 'GET', path: '/v1/pages/0123456789abcdef0123456789abcdef' }));
    expect(err.message).toContain('404');
    expect(err.message).toContain('object_not_found');
    expect(err.message).not.toContain(leaked);
  });

  it('drops unsafe error codes and maps Google error shapes', async () => {
    const leaked = dummySecret('LEAK');
    const { up } = recordingUpstream({ status: 400, body: JSON.stringify({ error: `bad ${leaked}` }) });
    const err = await rejection(up.json('oauth', { method: 'POST', path: '/token', form: { a: 'b' } }));
    expect(err.message).not.toContain(leaked);
    const g = recordingUpstream({
      status: 403,
      body: JSON.stringify({ error: { code: 403, message: leaked, errors: [{ reason: 'insufficientPermissions' }] } }),
    });
    const err2 = await rejection(g.up.json('drive', { method: 'GET', path: '/drive/v3/files/abc' }));
    expect(err2.message).toContain('insufficientPermissions');
    expect(err2.message).not.toContain(leaked);
  });

  it('wraps unknown transport failures generically', async () => {
    const leaked = dummySecret('LEAK');
    const up = new Upstream(async () => {
      throw new Error(`socket hang up ${leaked}`);
    });
    const err = await rejection(up.json('notion', { method: 'GET', path: '/v1/users/me' }));
    expect(err.message).not.toContain(leaked);
    expect(err.message).toMatch(/notion/i);
  });

  it('rejects non-JSON success bodies in json()', async () => {
    const { up } = recordingUpstream({ status: 200, body: '<html>' });
    await expect(up.json('notion', { method: 'GET', path: '/v1/users/me' })).rejects.toMatchObject({
      code: 'upstream_bad_response',
    });
  });
});
