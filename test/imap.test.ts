// IMAP provider logic against the MOCK ImapSession (in-memory fake), plus the imapflow adapter
// against a MOCK imapflow client and real local TLS servers on 127.0.0.1. No real mail server
// is contacted; all credentials are generated dummies.
import { beforeAll, describe, expect, it } from 'vitest';
import { PerchError } from '../src/errors.js';
import { ImapMailProvider, ImapflowSession, decodeImapMessageId, encodeImapMessageId, openImapflowSession } from '../src/mail/imap.js';
import type { SmtpSender } from '../src/mail/smtp.js';
import type { ImapAccount } from '../src/store/credentialStore.js';
import { dummySecret, rejection } from './support/fixtures.js';
import { MockImapSession, textMessage, type MockMailbox } from './support/mockImap.js';
import { makeSelfSignedCert, runtimeSupportsTls11, startMockImapServer, startTlsServer, type TestCert } from './support/tlsCert.js';

export function dummyImapAccount(over: Partial<ImapAccount> = {}): ImapAccount {
  return {
    id: 'imap-0a1b2c3d',
    label: 'GMX dummy',
    email: 'dummy.me@gmx.at',
    username: 'dummy.me@gmx.at',
    password: dummySecret('IMAP-PASSWORD'),
    preset: 'gmx',
    imap: { host: 'imap.gmx.net', port: 993 },
    smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
    allowDrafts: false,
    allowSend: false,
    createdAt: '2026-10-05T00:00:00.000Z',
    updatedAt: '2026-10-05T00:00:00.000Z',
    ...over,
  };
}

function setup(mailboxes: Record<string, MockMailbox>) {
  const session = new MockImapSession(new Map(Object.entries(mailboxes)));
  const sessions: MockImapSession[] = [];
  const provider = new ImapMailProvider({
    sessionFactory: async () => {
      sessions.push(session);
      return session;
    },
  });
  return { session, sessions, provider };
}

const inbox = (n: number, uidValidity = '1700000001'): MockMailbox => ({
  uidValidity,
  messages: Array.from({ length: n }, (_, i) => textMessage(i + 1, { text: `Body of dummy message ${i + 1}` })),
});

describe('IMAP message ids', () => {
  it('round-trips mailbox, UIDVALIDITY and UID', () => {
    const id = encodeImapMessageId('INBOX/Ünterordner', '1700000001', 42);
    expect(id).toMatch(/^imap:[A-Za-z0-9_-]+:1700000001:42$/);
    expect(decodeImapMessageId(id)).toEqual({ mailbox: 'INBOX/Ünterordner', uidValidity: '1700000001', uid: 42 });
  });

  it('rejects malformed ids strictly', () => {
    const good = encodeImapMessageId('INBOX', '7', 3);
    const bad = [
      '',
      'imap:SU5CT1g:7',
      'imap:SU5CT1g:7:0',
      'imap:SU5CT1g:0:3',
      'imap:SU5CT1g:07:3',
      'imap:SU5CT1g:7:4294967296',
      'imap:SU5CT1g:4294967296:3',
      'imap:SU5CT1g=:7:3',
      'imap:SU5CT1g+:7:3',
      'gmail:SU5CT1g:7:3',
      `${good}:1`,
      `imap:${Buffer.from('a\nb').toString('base64url')}:7:3`,
      'imap::7:3',
      'imap:SU5CT1h:7:3', // non-canonical base64url
    ];
    for (const id of bad) expect(() => decodeImapMessageId(id), id).toThrow(PerchError);
    expect(decodeImapMessageId(good).uid).toBe(3);
  });
});

describe('ImapMailProvider.search [MOCK ImapSession]', () => {
  it('opens the folder read-only, returns newest first and pages with a UIDVALIDITY-bound cursor', async () => {
    const { session, provider } = setup({ INBOX: inbox(5) });
    const acct = dummyImapAccount();
    const p1 = await provider.search(acct, { pageSize: 2 }, undefined);
    expect(p1.items.map((m) => m.messageId)).toEqual([encodeImapMessageId('INBOX', '1700000001', 5), encodeImapMessageId('INBOX', '1700000001', 4)]);
    expect(p1.items[0]).toMatchObject({ folder: 'INBOX', subject: 'Dummy subject 5', from: 'Dummy Sender <dummy.sender@example.test>', to: ['dummy.me@gmx.at'], hasAttachments: false });
    expect(p1.items[0]!.date).toMatch(/^2026-09-\d\dT10:00:00.000Z$/);
    expect(p1.next).toBe('1700000001:4');
    const p2 = await provider.search(acct, { pageSize: 2 }, p1.next!);
    expect(p2.items.map((m) => decodeImapMessageId(m.messageId).uid)).toEqual([3, 2]);
    const p3 = await provider.search(acct, { pageSize: 2 }, p2.next!);
    expect(p3.items.map((m) => decodeImapMessageId(m.messageId).uid)).toEqual([1]);
    expect(p3.next).toBeNull();
    expect(session.opens.every((o) => o.mailbox === 'INBOX' && o.readOnly)).toBe(true);
    expect(session.opens).toHaveLength(3);
    expect(session.released).toBe(3);
    expect(session.loggedOut).toBe(3);
  });

  it('uses a text query, a custom folder and flags attachments', async () => {
    const { session, provider } = setup({
      INBOX: inbox(1),
      'Archiv/2026': {
        uidValidity: '9',
        messages: [
          textMessage(10, { subject: 'Rechnung Oktober', text: 'dummy', attachment: { filename: 'r.pdf', content: Buffer.from('%PDF-dummy') } }),
          textMessage(11, { subject: 'Other', text: 'nothing' }),
        ],
      },
    });
    const page = await provider.search(dummyImapAccount(), { pageSize: 10, query: 'rechnung', folder: 'Archiv/2026' }, undefined);
    expect(page.items).toHaveLength(1);
    expect(page.items[0]).toMatchObject({ folder: 'Archiv/2026', subject: 'Rechnung Oktober', hasAttachments: true });
    expect(session.opens).toEqual([{ mailbox: 'Archiv/2026', readOnly: true }]);
  });

  it('rejects a cursor from another UIDVALIDITY and malformed cursors/folders', async () => {
    const mb = inbox(3);
    const { provider } = setup({ INBOX: mb });
    const acct = dummyImapAccount();
    const p1 = await provider.search(acct, { pageSize: 1 }, undefined);
    mb.uidValidity = '1700000002';
    expect(await rejection(provider.search(acct, { pageSize: 1 }, p1.next!))).toMatchObject({ code: 'bad_cursor' });
    for (const c of ['x', '1:2:3', '1700000002:', ':5', '1700000002:0']) {
      expect(await rejection(provider.search(acct, { pageSize: 1 }, c)), c).toMatchObject({ code: 'bad_cursor' });
    }
    for (const folder of ['', 'a\nb', 'x'.repeat(201)]) {
      expect(await rejection(provider.search(acct, { pageSize: 1, folder }, undefined)), JSON.stringify(folder)).toMatchObject({ code: 'bad_argument' });
    }
  });

  it('releases the lock and logs out when the session fails', async () => {
    const { session, provider } = setup({ INBOX: inbox(2) });
    session.failOn = { op: 'search', err: new Error('MOCK: connection lost') };
    await rejection(provider.search(dummyImapAccount(), { pageSize: 5 }, undefined));
    expect(session.released).toBe(1);
    expect(session.loggedOut).toBe(1);
  });
});

describe('ImapMailProvider.read / getAttachment / replyContext [MOCK ImapSession]', () => {
  const pdf = Buffer.alloc(3000, 0x41);
  const mailbox = (): MockMailbox => ({
    uidValidity: '55',
    messages: [
      textMessage(1, { text: 'Grüße aus Wien – ein Text mit Umlauten.', attachment: { filename: 'Rechnung.pdf', content: pdf } }),
      textMessage(2, { html: '<html><head><style>p{color:red}</style><script>x()</script></head><body><p>Hallo&nbsp;<b>Welt</b> &amp; Co</p><p>Zweiter&#33;</p></body></html>' }),
      textMessage(3, { text: 'ä'.repeat(100) }),
    ],
  });
  const id = (uid: number, uv = '55') => encodeImapMessageId('INBOX', uv, uid);

  it('reads text/plain, headers and lists attachments', async () => {
    const { session, provider } = setup({ INBOX: mailbox() });
    const m = await provider.read(dummyImapAccount(), id(1), { maxBytes: 4096 });
    expect(m).toMatchObject({
      messageId: id(1),
      folder: 'INBOX',
      subject: 'Dummy subject 1',
      text: 'Grüße aus Wien – ein Text mit Umlauten.',
      textSource: 'text/plain',
      truncated: false,
      internetMessageId: '<dummy-1@example.test>',
      inReplyTo: '<parent-1@example.test>',
      references: ['<root@example.test>', '<parent-1@example.test>'],
    });
    expect(m.attachments).toEqual([{ attachmentId: '2', filename: 'Rechnung.pdf', contentType: 'application/pdf', size: 4000, inline: false }]);
    expect(session.opens).toEqual([{ mailbox: 'INBOX', readOnly: true }]);
    expect(session.downloads).toEqual([{ uid: 1, part: '1', maxBytes: 4097 }]);
    expect(session.released).toBe(1);
    expect(session.loggedOut).toBe(1);
  });

  it('falls back to text/html converted to text', async () => {
    const { provider } = setup({ INBOX: mailbox() });
    const m = await provider.read(dummyImapAccount(), id(2), { maxBytes: 4096 });
    expect(m.textSource).toBe('text/html');
    expect(m.text).toBe('Hallo Welt & Co\nZweiter!');
  });

  it('truncates at maxBytes on a UTF-8 boundary', async () => {
    const { provider } = setup({ INBOX: mailbox() });
    const m = await provider.read(dummyImapAccount(), id(3), { maxBytes: 11 });
    expect(m.truncated).toBe(true);
    expect(m.text).toBe('ä'.repeat(5));
  });

  it('reports stale ids when UIDVALIDITY changed, and unknown messages', async () => {
    const { session, provider } = setup({ INBOX: mailbox() });
    const acct = dummyImapAccount();
    for (const call of [
      () => provider.read(acct, id(1, '54'), { maxBytes: 100 }),
      () => provider.getAttachment(acct, id(1, '54'), '2', { maxBytes: 100000 }),
      () => provider.replyContext(acct, id(1, '54')),
    ]) {
      const err = await rejection(call());
      expect(err).toMatchObject({ code: 'stale_message_id' });
      expect(err.message).toMatch(/search again/i);
    }
    expect(await rejection(provider.read(acct, id(99), { maxBytes: 100 }))).toMatchObject({ code: 'not_found' });
    expect(session.downloads).toEqual([]);
    expect(session.released).toBe(4);
    expect(session.loggedOut).toBe(4);
  });

  it('returns attachments, bounded before download and never truncated', async () => {
    const { session, provider } = setup({ INBOX: mailbox() });
    const acct = dummyImapAccount();
    const a = await provider.getAttachment(acct, id(1), '2', { maxBytes: 3000 });
    expect(a).toEqual({ attachmentId: '2', filename: 'Rechnung.pdf', contentType: 'application/pdf', size: 3000, contentBase64: pdf.toString('base64') });
    expect(session.downloads.at(-1)).toEqual({ uid: 1, part: '2', maxBytes: 3001 });
    expect(session.opens.every((o) => o.readOnly)).toBe(true);

    const before = session.downloads.length;
    expect(await rejection(provider.getAttachment(acct, id(1), '2', { maxBytes: 2999 }))).toMatchObject({ code: 'attachment_too_large' });
    expect(session.downloads.length).toBe(before); // refused from the size estimate, nothing downloaded

    expect(await rejection(provider.getAttachment(acct, id(1), '1', { maxBytes: 3000 }))).toMatchObject({ code: 'not_found' });
    expect(await rejection(provider.getAttachment(acct, id(1), '../1', { maxBytes: 3000 }))).toMatchObject({ code: 'bad_argument' });
  });

  it('errors instead of truncating when the server sends more than the estimate', async () => {
    const mb = mailbox();
    // BODYSTRUCTURE under-reports: the decoded content is larger than the estimate.
    mb.messages[0]!.parts!['2'] = Buffer.alloc(5000, 0x42);
    const { provider } = setup({ INBOX: mb });
    expect(await rejection(provider.getAttachment(dummyImapAccount(), id(1), '2', { maxBytes: 3500 }))).toMatchObject({ code: 'attachment_too_large' });
  });

  it('returns reply context from the message headers', async () => {
    const { provider } = setup({ INBOX: mailbox() });
    expect(await provider.replyContext(dummyImapAccount(), id(1))).toEqual({
      internetMessageId: '<dummy-1@example.test>',
      references: ['<root@example.test>', '<parent-1@example.test>'],
      subject: 'Dummy subject 1',
    });
  });
});

describe('ImapMailProvider drafts and send [MOCK ImapSession]', () => {
  const raw = Buffer.from('From: dummy.me@gmx.at\r\nTo: dummy.to@example.test\r\nBcc: dummy.bcc@example.test\r\nSubject: Draft\r\n\r\nHi\r\n');
  const mail = { raw, envelope: { from: 'dummy.me@gmx.at', to: ['dummy.to@example.test', 'dummy.bcc@example.test'] } };

  it('reports capabilities from the onboarding opt-ins', () => {
    const { provider } = setup({});
    expect(provider.kind).toBe('imap');
    expect(provider.providerCapabilities(dummyImapAccount())).toEqual({ draft: false, send: false, modify: false });
    expect(provider.providerCapabilities(dummyImapAccount({ allowDrafts: true, allowSend: true }))).toEqual({ draft: true, send: true, modify: false });
  });

  it('refuses drafts without allowDrafts, without connecting', async () => {
    const { sessions, provider } = setup({ Entwürfe: { uidValidity: '3', messages: [], specialUse: '\\Drafts' } });
    expect(await rejection(provider.createDraft(dummyImapAccount(), mail))).toMatchObject({ code: 'not_permitted' });
    expect(sessions).toHaveLength(0);
  });

  it('appends drafts to the \\Drafts special-use mailbox with \\Draft and \\Seen', async () => {
    const { session, provider } = setup({ INBOX: inbox(1), Entwürfe: { uidValidity: '3', messages: [], specialUse: '\\Drafts' } });
    const d = await provider.createDraft(dummyImapAccount({ allowDrafts: true }), mail);
    expect(session.appended).toEqual([{ mailbox: 'Entwürfe', raw, flags: ['\\Draft', '\\Seen'] }]);
    expect(d.draftId).toBe(encodeImapMessageId('Entwürfe', '3', 1));
    expect(session.loggedOut).toBe(1);
  });

  it('uses the configured drafts mailbox, falls back to "Drafts" and copes without UIDPLUS', async () => {
    const { session, provider } = setup({ Drafts: { uidValidity: '4', messages: [] }, Custom: { uidValidity: '5', messages: [] } });
    session.uidPlus = false;
    expect((await provider.createDraft(dummyImapAccount({ allowDrafts: true }), mail)).draftId).toBe('appended');
    expect(session.appended[0]!.mailbox).toBe('Drafts');
    await provider.createDraft(dummyImapAccount({ allowDrafts: true, draftsMailbox: 'Custom' }), mail);
    expect(session.appended[1]!.mailbox).toBe('Custom');
  });

  it('refuses sending without allowSend and delegates to the SMTP sender otherwise', async () => {
    const sent: unknown[] = [];
    const smtp = { send: async (...args: unknown[]) => (sent.push(args), { status: 'accepted', detail: 'MOCK' }) } as unknown as SmtpSender;
    const provider = new ImapMailProvider({ sessionFactory: async () => { throw new Error('must not connect'); }, smtp });
    expect(await rejection(provider.send(dummyImapAccount(), mail))).toMatchObject({ code: 'not_permitted' });
    expect(sent).toHaveLength(0);
    const acct = dummyImapAccount({ allowSend: true });
    // The Sent copy cannot be filed (no IMAP session): still accepted, sentCopy false, and SMTP is never called again.
    const r = await provider.send(acct, mail);
    expect(r).toMatchObject({ status: 'accepted', sentCopy: false });
    expect(r.detail).toMatch(/no copy could be filed in the Sent folder/);
    expect(sent).toEqual([[acct, raw, mail.envelope]]);
    // Sent copy turned off: no IMAP connection is attempted at all.
    expect(await provider.send({ ...acct, sentCopy: false }, mail)).toMatchObject({ status: 'accepted', sentCopy: false });
    expect(sent).toHaveLength(2);
  });
});

describe('ImapflowSession adapter [MOCK imapflow client]', () => {
  it('maps the session calls to read-only EXAMINE locks and UID-based commands', async () => {
    const log: Array<[string, ...unknown[]]> = [];
    const client = {
      mailbox: false as unknown,
      async getMailboxLock(path: string, opts: unknown) {
        log.push(['getMailboxLock', path, opts]);
        client.mailbox = { path, uidValidity: 77n };
        return { path, release: () => log.push(['release']) };
      },
      async search(q: unknown, opts: unknown) {
        log.push(['search', q, opts]);
        return [3, 1, 2];
      },
      async *fetch(range: unknown, q: unknown, opts: unknown) {
        log.push(['fetch', range, q, opts]);
        yield { seq: 1, uid: 1, envelope: { subject: 's' } };
      },
      async fetchOne(range: unknown, q: unknown, opts: unknown) {
        log.push(['fetchOne', range, q, opts]);
        return { seq: 1, uid: 1, size: 10, headers: Buffer.from('Message-ID: <a@b>\r\n') };
      },
      async download(range: unknown, part: unknown, opts: unknown) {
        log.push(['download', range, part, opts]);
        const { Readable } = await import('node:stream');
        return { meta: {}, content: Readable.from([Buffer.from('abc'), Buffer.from('def')]) };
      },
      async list() {
        return [{ path: 'INBOX' }, { path: 'Entwürfe', specialUse: '\\Drafts' }];
      },
      async append(path: unknown, raw: unknown, flags: unknown) {
        log.push(['append', path, raw, flags]);
        return { destination: path, uid: 9, uidValidity: 77n };
      },
      async logout() {
        log.push(['logout']);
      },
      close() {
        log.push(['close']);
      },
    };
    const s = new ImapflowSession(client as never);
    const lock = await s.openReadonly('INBOX');
    expect(lock.uidValidity).toBe('77');
    expect(await s.search({ all: true })).toEqual([3, 1, 2]);
    expect(await s.search({ text: 'x' })).toEqual([3, 1, 2]);
    expect(await s.fetchSummaries([1, 2])).toHaveLength(1);
    expect((await s.fetchMessage(1))?.size).toBe(10);
    expect((await s.download(1, '1', 4))?.toString()).toBe('abcd');
    lock.release();
    expect(await s.draftsMailbox()).toBe('Entwürfe');
    expect(await s.append('Entwürfe', Buffer.from('x'), ['\\Draft'])).toEqual({ uid: 9, uidValidity: '77' });
    await s.logout();
    expect(log).toEqual([
      ['getMailboxLock', 'INBOX', { readOnly: true }],
      ['search', { all: true }, { uid: true }],
      ['search', { text: 'x' }, { uid: true }],
      ['fetch', '1,2', { uid: true, envelope: true, internalDate: true, bodyStructure: true }, { uid: true }],
      ['fetchOne', '1', { uid: true, envelope: true, internalDate: true, bodyStructure: true, size: true, headers: ['message-id', 'in-reply-to', 'references'] }, { uid: true }],
      ['download', '1', '1', { uid: true, maxBytes: 4 }],
      ['release'],
      ['append', 'Entwürfe', Buffer.from('x'), ['\\Draft']],
      ['logout'],
    ]);
  });
});

describe('openImapflowSession over real TLS on 127.0.0.1', () => {
  let cert: TestCert;
  let otherCert: TestCert;
  beforeAll(async () => {
    cert = await makeSelfSignedCert('localhost');
    otherCert = await makeSelfSignedCert('other.example.test');
  });
  const local = (port: number, password?: string) =>
    dummyImapAccount({ imap: { host: 'localhost', port }, ...(password ? { password } : {}) });

  it('logs in to a server whose certificate is trusted via the test-only CA hook', async () => {
    const acct = local(0);
    const srv = await startMockImapServer(cert, { user: acct.username, pass: acct.password });
    try {
      const s = await openImapflowSession({ ...acct, imap: { host: 'localhost', port: srv.port } }, { testOnlyTlsTrust: { ca: cert.cert } });
      await s.logout();
      expect(srv.log.logins).toEqual([acct.username]);
      expect(srv.log.commands).toContain('LOGOUT');
    } finally {
      await srv.close();
    }
  });

  it('maps a failed login to a sanitised imap_auth error', async () => {
    const srv = await startMockImapServer(cert, { user: 'dummy.me@gmx.at', pass: dummySecret('RIGHT') });
    try {
      const acct = local(srv.port, dummySecret('WRONG-PASSWORD'));
      const err = await rejection(openImapflowSession(acct, { testOnlyTlsTrust: { ca: cert.cert } }));
      expect(err).toMatchObject({ code: 'imap_auth', message: 'IMAP login failed (check app password / IMAP access enabled)' });
      expect(err.message).not.toContain(acct.password);
    } finally {
      await srv.close();
    }
  });

  it('refuses an untrusted self-signed certificate before sending anything', async () => {
    const srv = await startTlsServer({ ...cert });
    try {
      const err = await rejection(openImapflowSession(local(srv.port)));
      expect(err).toBeInstanceOf(PerchError);
      expect(err).toMatchObject({ code: 'imap_tls' });
      expect(srv.state.tcpConnections).toBe(1);
      expect(srv.state.secureConnections).toBe(0);
      expect(srv.state.received).toEqual([]);
    } finally {
      await srv.close();
    }
  });

  it('refuses a trusted certificate issued for another hostname', async () => {
    const srv = await startTlsServer({ ...otherCert });
    try {
      const err = await rejection(openImapflowSession(local(srv.port), { testOnlyTlsTrust: { ca: otherCert.cert } }));
      expect(err).toMatchObject({ code: 'imap_tls' });
      expect(srv.state.received).toEqual([]);
    } finally {
      await srv.close();
    }
  });

  it('refuses a server limited to TLS 1.1', async (ctx) => {
    if (!(await runtimeSupportsTls11(cert))) {
      ctx.skip('This Node/OpenSSL runtime cannot negotiate TLS 1.1 at all, so the refusal cannot be exercised');
    }
    const srv = await startTlsServer({ ...cert, minVersion: 'TLSv1.1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT@SECLEVEL=0' });
    try {
      const err = await rejection(openImapflowSession(local(srv.port), { testOnlyTlsTrust: { ca: cert.cert } }));
      expect(err).toMatchObject({ code: 'imap_tls' });
      expect(srv.state.secureConnections).toBe(0);
    } finally {
      await srv.close();
    }
  });

  it('refuses IP literals and bad ports before connecting', async () => {
    expect(await rejection(openImapflowSession(dummyImapAccount({ imap: { host: '127.0.0.1', port: 993 } })))).toMatchObject({ code: 'bad_argument' });
    expect(await rejection(openImapflowSession(dummyImapAccount({ imap: { host: 'localhost', port: 0 } })))).toMatchObject({ code: 'bad_argument' });
  });
});
