// Fixed-origin, capability-tagged allowlist for the mail providers. MOCK transport only.
import { describe, expect, it } from 'vitest';
import { Upstream, type UpstreamRequest } from '../src/upstream.js';
import { rejection } from './support/fixtures.js';

function recorder(status = 200, body: unknown = {}) {
  const calls: UpstreamRequest[] = [];
  const upstream = new Upstream(async (req) => {
    calls.push(req);
    return { status, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(body)) };
  });
  return { calls, upstream };
}

describe('mail upstream allowlist [MOCK transport]', () => {
  it('uses the fixed origin for Gmail', async () => {
    const { calls, upstream } = recorder();
    await upstream.json('gmail', { method: 'GET', path: '/gmail/v1/users/me/profile' });
    expect(calls.map((c) => c.url.origin)).toEqual([
      'https://gmail.googleapis.com',
    ]);
  });

  it('requires the matching capability tag for draft and send routes', async () => {
    const { calls, upstream } = recorder();
    const send = { method: 'POST' as const, path: '/gmail/v1/users/me/messages/send', json: { raw: 'x' } };
    expect((await rejection(upstream.json('gmail', send))).message).toMatch(/non-allowlisted/i);
    expect((await rejection(upstream.json('gmail', { ...send, capability: 'draft' }))).message).toMatch(/non-allowlisted/i);
    await upstream.json('gmail', { ...send, capability: 'send' });
    const draft = { method: 'POST' as const, path: '/gmail/v1/users/me/drafts', json: { message: { raw: 'x' } } };
    expect((await rejection(upstream.json('gmail', draft))).message).toMatch(/non-allowlisted/i);
    await upstream.json('gmail', { ...draft, capability: 'draft' });
    // A read route cannot be "upgraded" either.
    expect((await rejection(upstream.json('gmail', { method: 'GET', path: '/gmail/v1/users/me/profile', capability: 'send' }))).message).toMatch(
      /non-allowlisted/i,
    );
    expect(calls).toHaveLength(2);
  });

  it('blocks arbitrary Graph paths, other users and bad tenants before any I/O', async () => {
    const { calls, upstream } = recorder();
    for (const path of ['/v1.0/users/victim@example.test/messages', '/beta/me/messages', '/v1.0/me/messages/abc/move', '//evil.example/x']) {
      expect((await rejection(upstream.json('graph', { method: 'GET', path }))).message).toMatch(/non-allowlisted/i);
    }
    expect((await rejection(upstream.json('graph', { method: 'POST', path: '/v1.0/me/sendMail' }))).message).toMatch(/non-allowlisted/i);
    expect(
      (await rejection(upstream.json('msauth', { method: 'POST', path: '/evil.example%2F..%2F/oauth2/v2.0/token' }))).message,
    ).toMatch(/non-allowlisted/i);
    expect(calls).toHaveLength(0);
  });

  it('rejects the retired OAuth identity and Graph mail routes before I/O', async () => {
    const { calls, upstream } = recorder();
    for (const capability of ['read', 'draft', 'send', 'mail_modify', 'admin'] as const) {
      await expect(upstream.json('graph', { method: 'GET', path: '/v1.0/me', capability })).rejects.toThrow(/non-allowlisted/i);
      await expect(upstream.json('graph', { method: 'POST', path: '/v1.0/me/sendMail', capability })).rejects.toThrow(/non-allowlisted/i);
      await expect(upstream.json('msauth', { method: 'POST', path: '/common/oauth2/v2.0/token', capability })).rejects.toThrow(/non-allowlisted/i);
    }
    expect(calls).toHaveLength(0);
  });
});
