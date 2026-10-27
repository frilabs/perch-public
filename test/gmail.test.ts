// Gmail provider adapter and account onboarding against the MOCK Gmail upstream (in-memory fake).
// No live Google calls; passing tests here are NOT evidence of a live integration.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  GMAIL_COMPOSE_SCOPE,
  GMAIL_READONLY_SCOPE,
  GMAIL_SEND_SCOPE,
  createGmailTokenProvider,
  gmailScopesFor,
  registerGmailAccount,
  removeGmailAccount,
} from '../src/mail/gmailAccounts.js';
import { GmailProvider } from '../src/mail/gmail.js';
import { CredentialStore, initStore, type GmailAccount } from '../src/store/credentialStore.js';
import { ACCEPTED_NOTE, INDETERMINATE_NOTE } from '../src/mail/types.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGmail, mime, type SendBehaviour, type MockGmailAccount, type MockMessage } from './support/mockGmail.js';

let dirs: TempDirs;
let store: CredentialStore;
let gmail: MockGmail;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  gmail = new MockGmail();
});
afterEach(async () => {
  await dirs.cleanup();
});

const client = { clientId: dummySecret('CLIENT'), clientSecret: dummySecret('CLIENT-SECRET') };

async function register(acct: MockGmailAccount, label: string, scopes: string[] = [GMAIL_READONLY_SCOPE]): Promise<GmailAccount> {
  return registerGmailAccount(store, new Upstream(gmail.transport), {
    label,
    client,
    grant: { refreshToken: acct.refreshToken, accessToken: gmail.issueAccessToken(acct), expiresAt: Date.now() + 3600_000, scopes },
  });
}

describe('gmailScopesFor', () => {
  it('always requests gmail.readonly and adds send/compose only on explicit opt-in', () => {
    expect(GMAIL_READONLY_SCOPE).toBe('https://www.googleapis.com/auth/gmail.readonly');
    expect(GMAIL_SEND_SCOPE).toBe('https://www.googleapis.com/auth/gmail.send');
    expect(GMAIL_COMPOSE_SCOPE).toBe('https://www.googleapis.com/auth/gmail.compose');
    expect(gmailScopesFor({})).toEqual([GMAIL_READONLY_SCOPE]);
    expect(gmailScopesFor({ send: true })).toEqual([GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]);
    expect(gmailScopesFor({ drafts: true })).toEqual([GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE]);
    // compose already covers sending; gmail.send is not requested on top of it.
    expect(gmailScopesFor({ send: true, drafts: true })).toEqual([GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE]);
  });
});

describe('registerGmailAccount / removeGmailAccount [MOCK Gmail]', () => {
  it('stores the account with the profile-reported email and granted scopes', async () => {
    const a = await register(gmail.addAccount('dummy.a@example.test'), 'Private', [GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]);
    expect(a.id).toMatch(/^gmail-[a-f0-9]{8}$/);
    expect(a.email).toBe('dummy.a@example.test');
    expect(a.scopes).toEqual([GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]);
    const profileCall = gmail.gmailCalls()[0]!;
    expect(profileCall.url.pathname).toBe('/gmail/v1/users/me/profile');
    expect((await store.read()).gmail.map((g) => [g.id, g.label])).toEqual([[a.id, 'Private']]);
  });

  it('rejects a second grant for the same mailbox (case-insensitive)', async () => {
    const acct = gmail.addAccount('Dummy.A@example.test');
    await register(acct, 'One');
    acct.email = 'dummy.a@EXAMPLE.test';
    await expect(register(acct, 'Two')).rejects.toThrow(/already connected/i);
    expect((await store.read()).gmail).toHaveLength(1);
  });

  it('removes locally and optionally revokes at Google', async () => {
    const acct = gmail.addAccount('dummy.a@example.test');
    const a = await register(acct, 'One');
    await removeGmailAccount(store, new Upstream(gmail.transport), a.id, { revoke: true });
    expect((await store.read()).gmail).toHaveLength(0);
    expect(gmail.revoked).toEqual([acct.refreshToken]);
    await expect(removeGmailAccount(store, new Upstream(gmail.transport), a.id, {})).rejects.toThrow(/unknown gmail account/i);
  });
});

describe('createGmailTokenProvider [MOCK token endpoint at oauth2.googleapis.com]', () => {
  it('refreshes via /token and persists a rotated refresh token', async () => {
    const acct = gmail.addAccount('dummy.a@example.test');
    const a = await register(acct, 'A');
    const rotated = dummySecret('GMAIL-REFRESH-ROTATED');
    gmail.opts.rotateRefreshTokenTo = rotated;
    const provider = createGmailTokenProvider(store, new Upstream(gmail.transport));
    const token = await provider.getAccessToken(a.id);
    expect(gmail.accessTokens.get(token)).toBe(acct);
    const tokenCall = gmail.calls.at(-1)!;
    expect(tokenCall.url.href).toBe('https://oauth2.googleapis.com/token');
    expect(new URLSearchParams(tokenCall.body).get('client_id')).toBe(client.clientId);
    const other = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    expect((await other.read()).gmail[0]!.refreshToken).toBe(rotated);
  });

  it('invalid_grant yields a gmail reconnect hint without the label or any token', async () => {
    const acct = gmail.addAccount('dummy.a@example.test');
    const a = await register(acct, 'Evil "$(touch x)"');
    const stored = acct.refreshToken;
    acct.refreshToken = dummySecret('REVOKED-ELSEWHERE');
    const err = await rejection(createGmailTokenProvider(store, new Upstream(gmail.transport)).getAccessToken(a.id));
    expect(err.message).toContain(`perch gmail remove ${a.id}`);
    expect(err.message).toContain('perch google add --label <label> --services gmail');
    expect(err.message).not.toContain('$(touch x)');
    expect(err.message).not.toContain(stored);
  });
});

const T0 = Date.UTC(2026, 8, 1, 10, 0, 0);

function plainMessage(id: string, subject: string, extra: Partial<MockMessage> = {}): MockMessage {
  return {
    id,
    threadId: `t-${id}`,
    internalDate: T0 + Number(id.replace(/\D/g, '') || 0) * 60_000,
    snippet: `snippet of ${subject}`,
    payload: mime('text/plain', {
      headers: {
        From: '"Dummy Sender" <sender@example.test>',
        To: 'dummy.a@example.test, "Other, Person" <other@example.test>',
        Subject: subject,
        Date: 'Tue, 1 Sep 2026 10:00:00 +0000',
      },
      content: `Body of ${subject}`,
    }),
    ...extra,
  };
}

async function setup(messages: MockMessage[], scopes: string[] = [GMAIL_READONLY_SCOPE]) {
  const mock = gmail.addAccount('dummy.a@example.test', messages);
  const account = await register(mock, 'Private', scopes);
  const upstream = new Upstream(gmail.transport);
  const tokens = createGmailTokenProvider(store, upstream);
  return { mock, account, provider: new GmailProvider(upstream, tokens), tokens };
}

describe('GmailProvider.search [MOCK Gmail]', () => {
  it('maps metadata to provenance-free summaries and paginates with nextPageToken', async () => {
    gmail.opts.pageSize = 2;
    const { provider, account } = await setup([plainMessage('m1', 'Invoice one'), plainMessage('m2', 'Invoice two'), plainMessage('m3', 'Invoice three'), plainMessage('m4', 'Other')]);
    const before = gmail.gmailCalls().length;
    const p1 = await provider.search(account, { query: 'invoice', pageSize: 10 }, undefined);
    expect(p1.items).toEqual([
      {
        messageId: 'm1',
        threadId: 't-m1',
        from: '"Dummy Sender" <sender@example.test>',
        to: ['dummy.a@example.test', '"Other, Person" <other@example.test>'],
        subject: 'Invoice one',
        date: new Date(T0 + 60_000).toISOString(),
        snippet: 'snippet of Invoice one',
      },
      expect.objectContaining({ messageId: 'm2', subject: 'Invoice two' }),
    ]);
    expect(p1.next).toBe('2');
    const calls = gmail.gmailCalls().slice(before);
    const list = calls[0]!.url;
    expect(list.pathname).toBe('/gmail/v1/users/me/messages');
    expect(list.searchParams.get('q')).toBe('invoice');
    expect(list.searchParams.get('maxResults')).toBe('10');
    expect(calls[1]!.url.searchParams.get('format')).toBe('metadata');
    expect(calls.every((c) => /^Bearer DUMMY-TEST-GMAIL-ACCESS-/.test(c.headers.authorization ?? ''))).toBe(true);
    const p2 = await provider.search(account, { query: 'invoice', pageSize: 10 }, p1.next!);
    expect(p2.items.map((i) => i.messageId)).toEqual(['m3']);
    expect(p2.next).toBeUndefined();
    expect(gmail.gmailCalls().at(-2)!.url.searchParams.get('pageToken')).toBe('2');
  });

  it('returns an empty page when nothing matches', async () => {
    const { provider, account } = await setup([plainMessage('m1', 'Hello')]);
    expect(await provider.search(account, { query: 'nomatch', pageSize: 5 }, undefined)).toEqual({ items: [] });
  });
});

const pdf = Buffer.from('%PDF-1.4 dummy pdf bytes \x00\x01\x02\xff', 'latin1');
const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 1, 2, 3, 255]);

function richMessage(): MockMessage {
  return {
    id: 'rich1',
    threadId: 'thr-rich',
    internalDate: T0,
    snippet: 'Hello there',
    payload: mime('multipart/mixed', {
      headers: {
        From: 'sender@example.test',
        To: 'dummy.a@example.test',
        Cc: 'c1@example.test, "C Two" <c2@example.test>',
        'Reply-To': 'replies@example.test',
        Subject: 'Quarterly report',
        Date: 'Tue, 1 Sep 2026 10:00:00 +0000',
        'Message-ID': '<msg-2@example.test>',
        'In-Reply-To': '<msg-1@example.test>',
        References: '<msg-0@example.test>\r\n <msg-1@example.test>',
      },
      parts: [
        mime('multipart/alternative', {
          parts: [mime('text/plain', { content: 'Plain body ✓' }), mime('text/html', { content: '<p>HTML body</p>' })],
        }),
        mime('text/plain', { filename: 'notes.txt', content: 'attached text, not the body' }),
        mime('application/pdf', { filename: 'report.pdf', content: pdf }),
        mime('image/png', { filename: 'logo.png', content: png, inline: true }),
      ],
    }),
  };
}

describe('GmailProvider.read [MOCK Gmail]', () => {
  it('returns the text/plain body, threading headers and attachment metadata keyed by partId', async () => {
    const { provider, account } = await setup([richMessage()]);
    const msg = await provider.read(account, 'rich1', { maxBytes: 4096 });
    expect(gmail.gmailCalls().at(-1)!.url.searchParams.get('format')).toBe('full');
    expect(msg).toMatchObject({
      messageId: 'rich1',
      threadId: 'thr-rich',
      from: 'sender@example.test',
      to: ['dummy.a@example.test'],
      cc: ['c1@example.test', '"C Two" <c2@example.test>'],
      replyTo: ['replies@example.test'],
      subject: 'Quarterly report',
      date: new Date(T0).toISOString(),
      internetMessageId: '<msg-2@example.test>',
      inReplyTo: '<msg-1@example.test>',
      references: ['<msg-0@example.test>', '<msg-1@example.test>'],
      text: 'Plain body ✓',
      textSource: 'text/plain',
      truncated: false,
    });
    expect(msg.attachments).toEqual([
      { attachmentId: '1', filename: 'notes.txt', contentType: 'text/plain', size: 27 },
      { attachmentId: '2', filename: 'report.pdf', contentType: 'application/pdf', size: pdf.length },
      { attachmentId: '3', filename: 'logo.png', contentType: 'image/png', size: png.length, inline: true },
    ]);
  });

  it('derives text from HTML when there is no text/plain part', async () => {
    const html =
      '<html><head><style>p{color:red}</style><script>alert("x")</script></head>' +
      '<body><p>Hello&nbsp;&amp; welcome</p><p>Line&lt;2&gt; &quot;q&quot; &#39;s&#39; &#x263A;</p>bye<br>now</body></html>';
    const { provider, account } = await setup([
      { id: 'h1', threadId: 't', internalDate: T0, snippet: '', payload: mime('text/html', { headers: { Subject: 'H' }, content: html }) },
    ]);
    const msg = await provider.read(account, 'h1', { maxBytes: 4096 });
    expect(msg.textSource).toBe('text/html');
    expect(msg.text).toBe('Hello & welcome\nLine<2> "q" \'s\' ☺\nbye\nnow');
    expect(msg.text).not.toMatch(/color|alert/);
  });

  it('truncates the text at maxBytes on a UTF-8 boundary', async () => {
    const { provider, account } = await setup([
      { id: 'u1', threadId: 't', internalDate: T0, snippet: '', payload: mime('text/plain', { content: 'ä'.repeat(100) }) },
    ]);
    const msg = await provider.read(account, 'u1', { maxBytes: 11 });
    expect(msg.truncated).toBe(true);
    expect(msg.text).toBe('ä'.repeat(5));
    const full = await provider.read(account, 'u1', { maxBytes: 200 });
    expect(full.truncated).toBe(false);
    expect(full.text).toBe('ä'.repeat(100));
  });

  it('fetches a large text body served via attachmentId', async () => {
    const big = 'line\n'.repeat(50);
    const { provider, account } = await setup([
      { id: 'big1', threadId: 't', internalDate: T0, snippet: '', payload: mime('text/plain', { content: big, asAttachment: true }) },
    ]);
    const msg = await provider.read(account, 'big1', { maxBytes: 4096 });
    expect(msg.text).toBe(big);
    expect(msg.attachments).toEqual([]);
    expect(gmail.gmailCalls().at(-1)!.url.pathname).toMatch(/^\/gmail\/v1\/users\/me\/messages\/big1\/attachments\//);
  });

  it('rejects malformed message ids before any network call', async () => {
    const { provider, account } = await setup([]);
    const before = gmail.calls.length;
    const err = await rejection(provider.read(account, '../drafts', { maxBytes: 100 }));
    expect((err as { code?: string }).code).toBe('bad_argument');
    expect(gmail.calls.length).toBe(before);
  });
});

describe('GmailProvider.getAttachment [MOCK Gmail]', () => {
  // Bytes chosen so base64 contains '+' and '/' (base64url would use '-' and '_').
  const binary = Buffer.concat([pdf, Buffer.from([0xfb, 0xef, 0xff, 0xfe, 0x3e, 0x3f])]);
  function withBinary(): MockMessage {
    const m = richMessage();
    m.payload.parts![2] = mime('application/pdf', { filename: 'report.pdf', content: binary });
    return m;
  }

  it('fetches by partId with a fresh Gmail attachment id and returns standard base64', async () => {
    const { provider, account } = await setup([withBinary()]);
    const a1 = await provider.getAttachment(account, 'rich1', '2', { maxBytes: 1024 });
    expect(a1).toEqual({
      attachmentId: '2',
      filename: 'report.pdf',
      contentType: 'application/pdf',
      size: binary.length,
      contentBase64: binary.toString('base64'),
    });
    expect(a1.contentBase64).toMatch(/[+/]/);
    const dl = gmail.gmailCalls().at(-1)!;
    expect(dl.url.pathname).toMatch(/^\/gmail\/v1\/users\/me\/messages\/rich1\/attachments\/ANGjd/);
    expect(dl.maxBytes).toBe(Math.ceil((binary.length * 4) / 3) + 64 * 1024);
    // Gmail attachment ids change between messages.get calls; the partId stays valid.
    const a2 = await provider.getAttachment(account, 'rich1', '2', { maxBytes: 1024 });
    expect(a2.contentBase64).toBe(a1.contentBase64);
    expect(gmail.gmailCalls().at(-1)!.url.pathname).not.toBe(dl.url.pathname);
  });

  it('rejects an attachment over maxBytes before downloading it', async () => {
    const { provider, account } = await setup([withBinary()]);
    const before = gmail.gmailCalls().length;
    const err = await rejection(provider.getAttachment(account, 'rich1', '2', { maxBytes: binary.length - 1 }));
    expect((err as { code?: string }).code).toBe('attachment_too_large');
    const calls = gmail.gmailCalls().slice(before);
    expect(calls.map((c) => c.url.pathname)).toEqual(['/gmail/v1/users/me/messages/rich1']);
  });

  it('reports unknown and malformed part ids', async () => {
    const { provider, account } = await setup([withBinary()]);
    expect(((await rejection(provider.getAttachment(account, 'rich1', '9.9', { maxBytes: 1024 }))) as { code?: string }).code).toBe('not_found');
    const before = gmail.calls.length;
    expect(((await rejection(provider.getAttachment(account, 'rich1', 'ANGjd/x', { maxBytes: 1024 }))) as { code?: string }).code).toBe('bad_argument');
    expect(gmail.calls.length).toBe(before);
  });
});

describe('GmailProvider.replyContext / providerCapabilities [MOCK Gmail]', () => {
  it("returns the message's own Message-ID, References, subject and threadId from metadata", async () => {
    const { provider, account } = await setup([richMessage()]);
    expect(await provider.replyContext(account, 'rich1')).toEqual({
      internetMessageId: '<msg-2@example.test>',
      references: ['<msg-0@example.test>', '<msg-1@example.test>'],
      subject: 'Quarterly report',
      threadId: 'thr-rich',
    });
    expect(gmail.gmailCalls().at(-1)!.url.searchParams.get('format')).toBe('metadata');
  });

  it('returns an empty references list for a message without threading headers', async () => {
    const { provider, account } = await setup([plainMessage('m1', 'Hi')]);
    expect(await provider.replyContext(account, 'm1')).toEqual({ references: [], subject: 'Hi', threadId: 't-m1' });
  });

  it('derives draft/send capability from the granted scopes', async () => {
    const provider = new GmailProvider(new Upstream(gmail.transport), { getAccessToken: async () => 'unused' });
    const acct = (scopes: string[]) => ({ scopes }) as GmailAccount;
    expect(provider.providerCapabilities(acct([GMAIL_READONLY_SCOPE]))).toEqual({ draft: false, send: false, modify: false });
    expect(provider.providerCapabilities(acct([GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]))).toEqual({ draft: false, send: true, modify: false });
    expect(provider.providerCapabilities(acct([GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE]))).toEqual({ draft: true, send: true, modify: false });
    expect(provider.kind).toBe('gmail');
  });
});

// Bytes that encode to '+' and '/' in standard base64, so base64url must differ.
const RAW = Buffer.concat([Buffer.from('From: dummy.a@example.test\r\nTo: x@example.test\r\nSubject: Hi\r\n\r\n'), Buffer.from([0xfb, 0xff, 0xbf])]);
const outgoing = (threadId?: string) => ({ raw: RAW, envelope: { from: 'dummy.a@example.test', to: ['x@example.test'] }, ...(threadId ? { threadId } : {}) });

describe('GmailProvider.createDraft [MOCK Gmail]', () => {
  it('posts raw as base64url with threadId under the draft capability', async () => {
    const { provider, account, mock } = await setup([], [GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE]);
    const res = await provider.createDraft(account, outgoing('thr-1'));
    expect(res).toEqual({ draftId: mock.drafts[0]!.id, messageId: `m${mock.drafts[0]!.id}`, threadId: 'thr-1' });
    expect(mock.drafts[0]!.raw).toBe(RAW.toString('base64url'));
    expect(mock.drafts[0]!.raw).not.toMatch(/[+/=]/);
    expect(mock.drafts[0]!.threadId).toBe('thr-1');
    const call = gmail.gmailCalls().at(-1)!;
    expect([call.method, call.url.pathname]).toEqual(['POST', '/gmail/v1/users/me/drafts']);
    expect(JSON.parse(call.body!)).toEqual({ message: { raw: RAW.toString('base64url'), threadId: 'thr-1' } });
  });

  it('the drafts route is unreachable without the draft capability tag', async () => {
    const before = gmail.calls.length;
    const err = await rejection(new Upstream(gmail.transport).raw('gmail', { method: 'POST', path: '/gmail/v1/users/me/drafts', json: { message: { raw: 'x' } } }));
    expect((err as { code?: string }).code).toBe('route_not_allowed');
    expect(gmail.calls.length).toBe(before);
  });

  it('refuses locally without gmail.compose (read-only or send-only grants)', async () => {
    const { provider, account } = await setup([], [GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]);
    const before = gmail.calls.length;
    const err = await rejection(provider.createDraft(account, outgoing()));
    expect((err as { code?: string }).code).toBe('capability_denied');
    expect(gmail.calls.length).toBe(before);
  });
});

describe('GmailProvider.send [MOCK Gmail]', () => {
  const sendCalls = () => gmail.calls.filter((c) => c.url.pathname === '/gmail/v1/users/me/messages/send');

  it('accepted: posts {raw, threadId} once under the send capability', async () => {
    const { provider, account, mock } = await setup([], [GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]);
    const res = await provider.send(account, outgoing('thr-9'));
    expect(res.status).toBe('accepted');
    expect(res.providerMessageId).toMatch(/^s[0-9a-f]{8}$/);
    expect(res.detail).toBe(ACCEPTED_NOTE);
    expect(mock.sent).toEqual([{ raw: RAW.toString('base64url'), threadId: 'thr-9' }]);
    expect(sendCalls()).toHaveLength(1);
    expect(sendCalls()[0]!.method).toBe('POST');
  });

  it('works with gmail.compose instead of gmail.send', async () => {
    const { provider, account } = await setup([], [GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE]);
    expect((await provider.send(account, outgoing())).status).toBe('accepted');
  });

  const cases: Array<[string, SendBehaviour, 'rejected' | 'indeterminate']> = [
    ['HTTP 400', { status: 400 }, 'rejected'],
    ['HTTP 403', { status: 403, body: { error: { code: 403, errors: [{ reason: 'insufficientPermissions' }] } } }, 'rejected'],
    ['HTTP 429', { status: 429, body: { error: { code: 429, status: 'RESOURCE_EXHAUSTED' } } }, 'rejected'],
    ['HTTP 500', { status: 500 }, 'indeterminate'],
    ['HTTP 503', { status: 503 }, 'indeterminate'],
    ['transport timeout', 'timeout', 'indeterminate'],
    ['connection lost', 'unreachable', 'indeterminate'],
  ];
  for (const [name, behaviour, status] of cases) {
    it(`${name} -> ${status}, exactly one send call, never retried`, async () => {
      const { provider, account, mock } = await setup([], [GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]);
      gmail.sendBehaviour = behaviour;
      const res = await provider.send(account, outgoing());
      expect(res.status).toBe(status);
      expect(res.providerMessageId).toBeUndefined();
      if (status === 'indeterminate') expect(res.detail).toBe(INDETERMINATE_NOTE);
      else expect(res.detail).toMatch(new RegExp(`not sent.*HTTP ${(behaviour as { status: number }).status}`, 'i'));
      expect(sendCalls()).toHaveLength(1);
      expect(mock.sent).toHaveLength(0);
    });
  }

  it('refuses locally without gmail.send/gmail.compose: no token fetch, no call', async () => {
    const { provider, account } = await setup([]);
    const before = gmail.calls.length;
    const err = await rejection(provider.send(account, outgoing()));
    expect((err as { code?: string }).code).toBe('capability_denied');
    expect(gmail.calls.length).toBe(before);
  });

  it('throws (no send attempt) when the access token cannot be obtained', async () => {
    const { account } = await setup([], [GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]);
    const provider = new GmailProvider(new Upstream(gmail.transport), {
      getAccessToken: async () => {
        throw new Error('token endpoint down');
      },
    });
    await expect(provider.send(account, outgoing())).rejects.toThrow(/token endpoint down/);
    expect(sendCalls()).toHaveLength(0);
  });

  it('the send route is unreachable without the send capability tag', async () => {
    const err = await rejection(new Upstream(gmail.transport).raw('gmail', { method: 'POST', path: '/gmail/v1/users/me/messages/send', json: { raw: 'x' }, capability: 'draft' }));
    expect((err as { code?: string }).code).toBe('route_not_allowed');
    expect(sendCalls()).toHaveLength(0);
  });
});

describe('GmailProvider secrets hygiene [MOCK Gmail]', () => {
  it('never puts access or refresh tokens into errors or send details', async () => {
    const { provider, account, mock, tokens } = await setup([richMessage()], [GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]);
    const access = await tokens.getAccessToken(account.id);
    const texts: string[] = [];
    texts.push((await rejection(provider.read(account, 'missing1', { maxBytes: 100 }))).message);
    texts.push((await rejection(provider.getAttachment(account, 'rich1', '2', { maxBytes: 1 }))).message);
    texts.push((await rejection(provider.createDraft(account, outgoing()))).message);
    gmail.sendBehaviour = { status: 400, body: { error: { code: 400, message: `echo ${access}` } } };
    texts.push((await provider.send(account, outgoing())).detail);
    gmail.sendBehaviour = { status: 500 };
    texts.push((await provider.send(account, outgoing())).detail);
    for (const t of texts) {
      expect(t).not.toContain(access);
      expect(t).not.toContain(mock.refreshToken);
      expect(t).not.toMatch(/DUMMY-TEST/);
    }
  });

  it('invalidates the cached access token when Gmail answers 401 (no automatic retry)', async () => {
    const { account } = await setup([richMessage()]);
    const invalidated: string[] = [];
    const provider = new GmailProvider(new Upstream(gmail.transport), {
      getAccessToken: async () => 'DUMMY-TEST-UNKNOWN-ACCESS',
      invalidate: (id) => invalidated.push(id),
    });
    const before = gmail.gmailCalls().length;
    const err = await rejection(provider.read(account, 'rich1', { maxBytes: 100 }));
    expect(err.message).toMatch(/HTTP 401/);
    expect(err.message).not.toContain('DUMMY-TEST-UNKNOWN-ACCESS');
    expect(invalidated).toEqual([account.id]);
    expect(gmail.gmailCalls().length - before).toBe(1);
  });
});
