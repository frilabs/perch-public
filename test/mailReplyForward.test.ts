// mail_reply / mail_forward (docs/MAIL_CALENDAR_SLACK_SPEC.md §1) end to end over the real adapters and the MOCK
// Gmail upstreams and MOCK ImapSession/SMTP (in-memory fakes), plus the IMAP Sent copy. No live provider is
// contacted; passing tests are not evidence of live provider behaviour.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { createPerchContext } from '../src/context.js';
import type { PerchError } from '../src/errors.js';
import { MAX_BODY_BYTES, MAX_RECIPIENTS } from '../src/mail/compose.js';
import { GmailProvider } from '../src/mail/gmail.js';
import { GMAIL_COMPOSE_SCOPE, GMAIL_READONLY_SCOPE } from '../src/mail/gmailAccounts.js';
import { encodeImapMessageId, imapSentCopyEnabled, ImapMailProvider, sentMailboxOf } from '../src/mail/imap.js';
import { deriveReplyRecipients, forwardBody, forwardSubject, quoteReply, replySubject, threadingFor } from '../src/mail/replyForward.js';
import { MailService, type MailProviders, type SendOutcome } from '../src/mail/service.js';
import type { SmtpSender } from '../src/mail/smtp.js';
import { ACCEPTED_NOTE, INDETERMINATE_NOTE, type SendResult } from '../src/mail/types.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { createMcpServer, WRITE_TOOL_NAMES } from '../src/mcp/server.js';
import { CredentialStore, initStore, type Capability, type StoreData } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGmail, mime, type MockGmailAccount } from './support/mockGmail.js';
import { MockImapSession, textMessage } from './support/mockImap.js';

let dirs: TempDirs;
let store: CredentialStore;
let gmail: MockGmail;
let ga: MockGmailAccount;
let imap: MockImapSession;
let imapSessions: number;
let smtpCalls: Array<{ raw: Buffer; envelope: { from: string; to: string[] } }>;
let smtpResult: SendResult;
let service: MailService;

const GMAIL = 'gmail-0000000a';
const IMAP = 'imap-0000000c';
const OWN = { gmail: 'me@gmail.example.test', imap: 'me@gmx.example.test' } as const;
const now = new Date().toISOString();
const PDF = Buffer.from('%PDF-1.4 dummy report');
const BODY = 'Line one of the plan\nLine two of the plan';

async function seed() {
  await store.update((d: StoreData) => {
    d.gmail.push({
      id: GMAIL, label: 'Gmail', email: OWN.gmail, clientId: dummySecret('C'), clientSecret: dummySecret('S'),
      refreshToken: dummySecret('RT'), scopes: [GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE], createdAt: now, updatedAt: now,
    });
    d.imap.push({
      id: IMAP, label: 'GMX', email: OWN.imap, username: OWN.imap, password: dummySecret('PW'),
      imap: { host: 'imap.gmx.net', port: 993 }, smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
      allowDrafts: true, allowSend: true, allowModify: false, createdAt: now, updatedAt: now,
    });
  });
}

function build() {
  gmail = new MockGmail();
  ga = gmail.addAccount(OWN.gmail, [
    {
      id: 'orig1', threadId: 't-orig', internalDate: 1767225600000, snippet: 'plan', labelIds: ['INBOX'],
      payload: mime('multipart/mixed', {
        headers: {
          From: 'Alice Sender <alice@example.test>',
          'Reply-To': 'replies@example.test',
          To: `Me <${OWN.gmail}>, bob@example.test`,
          Cc: `carol@example.test, Bob <BOB@example.test>, ${OWN.gmail}`,
          Subject: 'Quarterly plan',
          'Message-ID': '<orig-1@example.test>',
          References: '<root@example.test>',
        },
        parts: [mime('text/plain', { content: BODY }), mime('application/pdf', { filename: 'report.pdf', content: PDF })],
      }),
    },
  ]);
  const gToken = gmail.issueAccessToken(ga);
  const orig = textMessage(1, { subject: 'Quarterly plan', text: BODY, from: 'alice@example.test', attachment: { filename: 'report.pdf', content: PDF } });
  orig.envelope = {
    ...orig.envelope,
    replyTo: [{ address: 'replies@example.test' }],
    to: [{ name: 'Me', address: OWN.imap }, { address: 'bob@example.test' }],
    cc: [{ address: 'carol@example.test' }, { name: 'Bob', address: 'BOB@example.test' }, { address: OWN.imap }],
  };
  orig.headers = 'Message-ID: <orig-1@example.test>\r\nReferences: <root@example.test>\r\n\r\n';
  imap = new MockImapSession(
    new Map(
      Object.entries({
        INBOX: { uidValidity: '11', messages: [orig] },
        Drafts: { uidValidity: '12', specialUse: '\\Drafts', messages: [] },
        Sent: { uidValidity: '13', specialUse: '\\Sent', messages: [] },
      }),
    ),
  );
  imapSessions = 0;
  smtpCalls = [];
  smtpResult = { status: 'accepted', detail: ACCEPTED_NOTE };
  const smtp = {
    send: async (_a: unknown, raw: Buffer, envelope: { from: string; to: string[] }) => (smtpCalls.push({ raw, envelope }), smtpResult),
  } as unknown as SmtpSender;
  const providers: MailProviders = {
    gmail: new GmailProvider(new Upstream(gmail.transport), { getAccessToken: async () => gToken }),
    imap: new ImapMailProvider({ sessionFactory: async () => (imapSessions++, imap), smtp }),
  };
  service = new MailService(store, providers);
}

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  await seed();
  build();
});
afterEach(async () => {
  await dirs.cleanup();
});

async function client(capabilities: Capability[], accountIds: string[]): Promise<Principal> {
  const { token } = await createClientGrant(store, {
    label: 'Replier',
    capabilities,
    accountIds,
    tokenFile: `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token`,
  });
  return (await principalForClientToken(store, token))!;
}

const code = async (p: Promise<unknown>) => ((await rejection(p)) as PerchError).code;
const ledger = () => new MailWorkflowLedger(store).read();

/** Unfolded top-level headers of a raw message (lower-case names). */
function headers(raw: string): Map<string, string> {
  const head = raw.split(/\r?\n\r?\n/)[0]!.replace(/\r?\n[ \t]+/g, ' ');
  const map = new Map<string, string>();
  for (const line of head.split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i > 0) map.set(line.slice(0, i).toLowerCase(), line.slice(i + 1).trim());
  }
  return map;
}
const addrs = (v: string | undefined) => (v ? [...v.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/g)].map((m) => m[0].toLowerCase()) : []);

interface Kind {
  name: 'gmail' | 'imap';
  accountId: string;
  messageId: string;
  /** Raw MIME of the last created draft / last submitted message. */
  lastDraft: () => string;
  lastSent: () => string | undefined;
  sentCount: () => number;
  io: () => number;
  loseNextSend: () => void;
}

const KINDS: Kind[] = [
  {
    name: 'gmail',
    accountId: GMAIL,
    messageId: 'orig1',
    lastDraft: () => Buffer.from(ga.drafts.at(-1)!.raw, 'base64url').toString('utf8'),
    lastSent: () => (ga.sent.length ? Buffer.from(ga.sent.at(-1)!.raw, 'base64url').toString('utf8') : undefined),
    sentCount: () => ga.sent.length,
    io: () => gmail.gmailCalls().length,
    loseNextSend: () => {
      gmail.sendBehaviour = 'unreachable';
    },
  },
  {
    name: 'imap',
    accountId: IMAP,
    messageId: encodeImapMessageId('INBOX', '11', 1),
    lastDraft: () => imap.appended.filter((a) => a.mailbox === 'Drafts').at(-1)!.raw.toString('utf8'),
    lastSent: () => smtpCalls.at(-1)?.raw.toString('utf8'),
    sentCount: () => smtpCalls.length,
    io: () => imapSessions + smtpCalls.length,
    loseNextSend: () => {
      smtpResult = { status: 'indeterminate', detail: INDETERMINATE_NOTE };
    },
  },
];

describe('reply/forward helpers (pure)', () => {
  const original = {
    from: 'Alice <alice@example.test>',
    replyTo: ['replies@example.test'],
    to: ['Me <me@example.test>', 'bob@example.test'],
    cc: ['carol@example.test', 'Bob <BOB@example.test>', 'me@example.test'],
  };

  it('answers Reply-To, else From; replyAll adds To and Cc without the own address and without duplicates', () => {
    expect(deriveReplyRecipients(original, 'ME@example.test', false)).toEqual({ to: ['replies@example.test'], cc: [], skipped: 0 });
    expect(deriveReplyRecipients({ ...original, replyTo: [] }, 'me@example.test', false).to).toEqual(['Alice <alice@example.test>']);
    expect(deriveReplyRecipients(original, 'me@example.test', true)).toEqual({ to: ['replies@example.test', 'bob@example.test'], cc: ['carol@example.test'], skipped: 0 });
  });

  it('a reply to one\'s own message goes to its To; malformed and hostile entries are skipped or sanitised', () => {
    expect(deriveReplyRecipients({ from: 'me@example.test', to: ['x@example.test'] }, 'me@example.test', false).to).toEqual(['x@example.test']);
    const r = deriveReplyRecipients(
      { from: '"Evil\r\nBcc: victim@example.test" <evil@example.test>', to: ['not an address', 'a@b'], cc: ['ok@example.test'] },
      'me@example.test',
      true,
    );
    // The injected line break is gone; the rest is only a display name (one mailbox, evil@example.test).
    expect(r.to).toEqual(['Evil Bcc: victim@example.test <evil@example.test>']);
    expect(r.to[0]).not.toMatch(/[\r\n]/);
    expect(r.cc).toEqual(['ok@example.test']);
    expect(r.skipped).toBe(2);
    expect(() => deriveReplyRecipients({ from: 'me@example.test' }, 'me@example.test', false)).toThrow(/no usable sender/);
  });

  it(`refuses more than ${MAX_RECIPIENTS} derived recipients instead of cutting them`, () => {
    const to = Array.from({ length: MAX_RECIPIENTS + 1 }, (_, i) => `r${i}@example.test`);
    expect(() => deriveReplyRecipients({ from: 'a@example.test', to }, 'me@example.test', true)).toThrow(expect.objectContaining({ code: 'too_many_recipients' }));
  });

  it('prefixes Re:/Fwd: once, threads with the well-formed ids only, and caps the quote at MAX_BODY_BYTES', () => {
    expect(replySubject('Plan')).toBe('Re: Plan');
    expect(replySubject('RE: Plan')).toBe('RE: Plan');
    expect(replySubject('AW: Plan')).toBe('AW: Plan');
    expect(replySubject(undefined)).toBe('Re:');
    expect(forwardSubject('Plan')).toBe('Fwd: Plan');
    expect(forwardSubject('Fw: Plan')).toBe('Fw: Plan');
    expect(forwardSubject('Re: Plan')).toBe('Fwd: Re: Plan');
    expect(replySubject('Plan\r\nBcc: x@example.test')).not.toMatch(/[\r\n]/);
    expect(threadingFor({ internetMessageId: '<id@x>', references: ['<root@x>', 'junk', '<id@x>'] }, true)).toEqual({ inReplyTo: '<id@x>', references: ['<root@x>', '<id@x>'] });
    expect(threadingFor({ internetMessageId: 'broken', references: [] }, true)).toEqual({ references: [] });
    expect(threadingFor({ internetMessageId: '<id@x>', references: [] }, false)).toEqual({ references: ['<id@x>'] });
    const q = quoteReply({ from: 'a@example.test', date: '2026-01-02T00:00:00Z', text: 'x\n'.repeat(MAX_BODY_BYTES), truncated: false }, 'Thanks');
    expect(Buffer.byteLength(q)).toBeLessThanOrEqual(MAX_BODY_BYTES);
    expect(q.startsWith('Thanks\n\nOn ')).toBe(true);
    expect(q).toMatch(/> x\n> x/);
    expect(q).toMatch(/quoted text truncated\]$/);
    const f = forwardBody({ from: 'a@example.test', subject: 'S', to: ['b@example.test'], text: 'body', truncated: false }, 'FYI');
    expect(f).toMatch(/^FYI\n\n---------- Forwarded message ---------\nFrom: a@example.test\nDate: .*\nSubject: S\nTo: b@example.test\n\nbody$/);
  });
});

describe('Gmail reply recipient comment parsing (MOCK provider)', () => {
  it.each(['From', 'Reply-To'])('ignores nested comment addresses in %s', async (header) => {
    const sourceHeaders = ga.messages[0]!.payload.headers!;
    sourceHeaders.splice(0, sourceHeaders.length, ...sourceHeaders.filter((h) => h.name !== 'Reply-To'));
    const value = 'Victim (x(y) <evil@example.test>) <victim@example.test>';
    if (header === 'From') sourceHeaders.find((h) => h.name === 'From')!.value = value;
    else sourceHeaders.push({ name: header, value });
    const p = await client(['read', 'draft'], [GMAIL]);
    const result = await service.reply(p, { accountId: GMAIL, messageId: 'orig1', text: 'Reply safely.' });
    expect(result.to).toEqual(['Victim <victim@example.test>']);
    const raw = Buffer.from(ga.drafts.at(-1)!.raw, 'base64url').toString('utf8');
    expect(addrs(headers(raw).get('to'))).toEqual(['victim@example.test']);
    expect(ga.sent).toHaveLength(0);
  });
});

describe.each(KINDS)('mail_reply / mail_forward [$name, MOCK provider]', (k) => {
  it('reply: a draft to Reply-To with In-Reply-To/References, "Re: " subject and the quoted original', async () => {
    const p = await client(['read', 'draft'], [k.accountId]);
    const r = await service.reply(p, { accountId: k.accountId, messageId: k.messageId, text: 'Sounds good.' });
    expect(r).toMatchObject({ accountId: k.accountId, provider: k.name, sent: false, to: ['replies@example.test'], cc: [], subject: 'Re: Quarterly plan' });
    const raw = k.lastDraft();
    const h = headers(raw);
    expect(addrs(h.get('to'))).toEqual(['replies@example.test']);
    expect(h.has('cc')).toBe(false);
    expect(h.get('subject')).toBe('Re: Quarterly plan');
    expect(h.get('in-reply-to')).toBe('<orig-1@example.test>');
    expect(h.get('references')).toBe('<root@example.test> <orig-1@example.test>');
    expect(addrs(h.get('from'))).toEqual([OWN[k.name]]);
    expect(raw).toContain('Sounds good.');
    expect(raw).toMatch(/> Line one of the plan/);
    if (k.name === 'gmail') expect(ga.drafts.at(-1)!.threadId).toBe('t-orig');
    // No attachments on a reply.
    expect(raw).not.toContain('report.pdf');
  });

  it('replyAll: original To and Cc without the own address, deduplicated; extra recipients and Bcc are added', async () => {
    const p = await client(['read', 'draft'], [k.accountId]);
    const r = await service.reply(p, {
      accountId: k.accountId, messageId: k.messageId, replyAll: true, text: 'All of you', cc: ['carol@example.test', 'dave@example.test'], bcc: ['hidden@example.test'],
    });
    expect(r.to!.map((a) => a.toLowerCase())).toEqual(['replies@example.test', 'bob@example.test']);
    expect(r.cc).toEqual(['carol@example.test', 'dave@example.test']);
    expect(r.bcc).toEqual(['hidden@example.test']);
    const h = headers(k.lastDraft());
    expect(addrs(h.get('to'))).toEqual(['replies@example.test', 'bob@example.test']);
    expect(addrs(h.get('cc'))).toEqual(['carol@example.test', 'dave@example.test']);
    expect(addrs(h.get('to')).concat(addrs(h.get('cc')))).not.toContain(OWN[k.name]);
  });

  it('drops a Bcc that is already a derived To/Cc recipient (case-insensitive address)', async () => {
    const p = await client(['read', 'draft'], [k.accountId]);
    const r = await service.reply(p, {
      accountId: k.accountId, messageId: k.messageId, replyAll: true, text: 'All of you', cc: ['carol@example.test'],
      bcc: ['Bob <BOB@example.test>', 'Carol@Example.test', 'hidden@example.test'],
    });
    expect(r.bcc).toEqual(['hidden@example.test']);
    const f = await service.forward(p, { accountId: k.accountId, messageId: k.messageId, to: ['Eve <eve@example.test>'], bcc: ['EVE@example.test', 'x@example.test'], text: 'FYI' });
    expect(f.bcc).toEqual(['x@example.test']);
  });

  it('forward: a draft with the original attachment, a forward block and "Fwd: "; inline parts are counted, not attached', async () => {
    const p = await client(['read', 'draft'], [k.accountId]);
    const r = await service.forward(p, { accountId: k.accountId, messageId: k.messageId, to: ['Eve <eve@example.test>'], text: 'FYI' });
    expect(r).toMatchObject({ to: ['Eve <eve@example.test>'], subject: 'Fwd: Quarterly plan', attachments: 1, omittedInlineAttachments: 0 });
    const raw = k.lastDraft();
    const h = headers(raw);
    expect(addrs(h.get('to'))).toEqual(['eve@example.test']);
    expect(h.get('subject')).toBe('Fwd: Quarterly plan');
    expect(h.has('in-reply-to')).toBe(false);
    expect(h.get('references')).toBe('<root@example.test> <orig-1@example.test>');
    expect(raw).toContain('---------- Forwarded message ---------');
    expect(raw).toContain('report.pdf');
    expect(raw).toContain(PDF.toString('base64'));
    expect(raw).not.toContain('logo.png');
    // Without attachments on request.
    const bare = await service.forward(p, { accountId: k.accountId, messageId: k.messageId, to: ['eve@example.test'], includeAttachments: false });
    expect(bare.attachments).toBe(0);
    expect(k.lastDraft()).not.toContain('report.pdf');
  });

  it('send: true sends once per requestId: replay without provider I/O, conflict on other input, indeterminate on a lost response', async () => {
    const p = await client(['read', 'send'], [k.accountId]);
    const req = { accountId: k.accountId, messageId: k.messageId, replyAll: true, text: 'Confirmed', bcc: ['hidden@example.test'], send: true, requestId: 'reply-send-0001' };
    const first = (await service.reply(p, req)) as SendOutcome;
    expect(first).toMatchObject({ status: 'accepted', requestState: 'accepted', replayed: false, sent: true, subject: 'Re: Quarterly plan' });
    expect(first.detail.startsWith(ACCEPTED_NOTE)).toBe(true);
    expect(k.sentCount()).toBe(1);
    const wire = k.lastSent()!;
    expect(headers(wire).get('in-reply-to')).toBe('<orig-1@example.test>');
    if (k.name === 'imap') {
      // Bcc never on the wire, but in the envelope.
      expect(wire).not.toMatch(/^bcc:/im);
      expect(wire).not.toContain('hidden@example.test');
      expect(smtpCalls[0]!.envelope.to).toEqual(['replies@example.test', 'bob@example.test', 'carol@example.test', 'hidden@example.test']);
    }
    if (k.name === 'gmail') expect(ga.sent.at(-1)!.threadId).toBe('t-orig');
    const io = k.io();
    const replay = await service.reply(p, req);
    expect(replay).toMatchObject({ status: 'accepted', replayed: true, operationId: first.operationId });
    expect(await code(service.reply(p, { ...req, text: 'Changed' }))).toBe('idempotency_conflict');
    expect(await code(service.forward(p, { accountId: k.accountId, messageId: k.messageId, to: ['eve@example.test'], send: true, requestId: 'reply-send-0001' }))).toBe('idempotency_conflict');
    expect(await code(service.send(p, { accountId: k.accountId, to: ['x@example.test'], subject: 'x', text: 'Confirmed', requestId: 'reply-send-0001' }))).toBe('idempotency_conflict');
    expect(k.io()).toBe(io);
    expect(k.sentCount()).toBe(1);
    k.loseNextSend();
    const fwd = { accountId: k.accountId, messageId: k.messageId, to: ['eve@example.test'], send: true, requestId: 'fwd-send-0002' };
    expect(await service.forward(p, fwd)).toMatchObject({ status: 'indeterminate', replayed: false });
    expect(await service.forward(p, fwd)).toMatchObject({ status: 'indeterminate', replayed: true });
    expect((await ledger()).sends.map((s) => s.state)).toEqual(['accepted', 'indeterminate']);
  });

  it('capabilities: draft needs "draft"+"read", send needs "send"+"read"+requestId; denied before any provider I/O', async () => {
    const base = { accountId: k.accountId, messageId: k.messageId, text: 'x' };
    const before = k.io();
    expect(await code(service.reply(READONLY_PRINCIPAL, base))).toBe('capability_denied');
    expect(await code(service.reply(await client(['read', 'send'], [k.accountId]), base))).toBe('capability_denied');
    expect(await code(service.reply(await client(['read', 'draft'], [k.accountId]), { ...base, send: true, requestId: 'cap-check-0001' }))).toBe('capability_denied');
    expect(await code(service.reply(await client(['draft', 'send'], [k.accountId]), base))).toBe('capability_denied');
    expect(await code(service.forward(await client(['send'], [k.accountId]), { ...base, to: ['e@example.test'], send: true, requestId: 'cap-check-0002' }))).toBe('capability_denied');
    const sender = await client(['read', 'draft', 'send'], [k.accountId]);
    expect(await code(service.reply(sender, { ...base, send: true }))).toBe('bad_argument');
    expect(await code(service.reply(sender, { ...base, requestId: 'cap-check-0003' }))).toBe('bad_argument');
    expect(await code(service.reply(sender, { ...base, text: '' }))).toBe('bad_argument');
    expect(await code(service.forward(sender, { ...base, to: [] }))).toBe('bad_argument');
    expect(await code(service.forward(sender, { ...base, to: ['bad\r\nBcc: x@example.test'] }))).toBe('bad_argument');
    expect(await code(service.reply(sender, { ...base, bcc: ['not-an-address'], send: true, requestId: 'cap-check-0004' }))).toBe('bad_argument');
    expect(k.io()).toBe(before);
    expect((await ledger()).sends).toEqual([]);
  });

  it('audits reply/forward without ids, addresses, subjects or bodies', async () => {
    const p = await client(['read', 'draft', 'send'], [k.accountId]);
    await service.reply(p, { accountId: k.accountId, messageId: k.messageId, text: 'Secret reply text' });
    await service.forward(p, { accountId: k.accountId, messageId: k.messageId, to: ['eve@example.test'], send: true, requestId: 'audit-fwd-0001' });
    const l = await ledger();
    const json = JSON.stringify(l);
    for (const s of [k.messageId, 'audit-fwd-0001', 'eve@example.test', 'replies@example.test', 'Quarterly plan', 'Secret reply text', 'report.pdf']) expect(json).not.toContain(s);
    expect(l.audit.map((e) => [e.type, e.outcome])).toEqual([
      ['mail_reply', 'attempt'],
      ['mail_reply', 'ok'],
      ['mail_send', 'pending'],
      ['mail_send', 'accepted'],
    ]);
  });
});

describe('forward attachment limits [MOCK providers]', () => {
  it('more than 10 attachments: error, nothing created; send: true is rejected without a submission', async () => {
    const parts = [mime('text/plain', { content: 'see files' }), ...Array.from({ length: 11 }, (_, i) => mime('text/plain', { filename: `f${i}.txt`, content: `file ${i}` }))];
    ga.messages.push({ id: 'many', threadId: 't2', internalDate: 1767225600000, snippet: 'f', payload: mime('multipart/mixed', { headers: { From: 'a@example.test', Subject: 'Files' }, parts }) });
    // addAccount assigns part ids only for the initial messages.
    const assign = (part: (typeof parts)[number], id: string) => {
      part.partId = id;
      part.parts?.forEach((c, i) => assign(c, id === '' ? String(i) : `${id}.${i}`));
    };
    assign(ga.messages.at(-1)!.payload, '');
    const p = await client(['read', 'draft', 'send'], [GMAIL]);
    const err = (await rejection(service.forward(p, { accountId: GMAIL, messageId: 'many', to: ['eve@example.test'] }))) as PerchError;
    expect(err.code).toBe('too_many_attachments');
    expect(err.message).toMatch(/11 attachments.*limit of 10.*includeAttachments: false/);
    expect(ga.drafts).toHaveLength(0);
    const sent = (await service.forward(p, { accountId: GMAIL, messageId: 'many', to: ['eve@example.test'], send: true, requestId: 'too-many-0001' })) as SendOutcome;
    expect(sent).toMatchObject({ status: 'rejected', replayed: false });
    expect(sent.detail).toMatch(/limit of 10/);
    expect(ga.sent).toHaveLength(0);
    // includeAttachments: false still works.
    expect(await service.forward(p, { accountId: GMAIL, messageId: 'many', to: ['eve@example.test'], includeAttachments: false })).toMatchObject({ attachments: 0 });
  });

  it('more than 10 MiB of attachments: error with a clear message, never a forward without them', async () => {
    const big = textMessage(2, { subject: 'Big', text: 'big file', attachment: { filename: 'big.bin', content: Buffer.alloc(10 * 1024 * 1024 + 1, 1) } });
    imap.mailboxes.get('INBOX')!.messages.push(big);
    const p = await client(['read', 'draft'], [IMAP]);
    const err = (await rejection(service.forward(p, { accountId: IMAP, messageId: encodeImapMessageId('INBOX', '11', 2), to: ['eve@example.test'] }))) as PerchError;
    expect(err.code).toBe('attachments_too_large');
    expect(err.message).toMatch(/larger than 10485760 bytes.*Nothing was created or sent/);
    expect(imap.appended).toHaveLength(0);
  });
});

describe('IMAP Sent copy [MOCK ImapSession/SMTP]', () => {
  const sendReq = { accountId: IMAP, to: ['friend@example.test'], bcc: ['hidden@example.test'], subject: 'Hello', text: 'Body', requestId: 'sent-copy-0001' };

  it('files a copy (with Bcc, \\Seen) in Sent after an accepted send; the wire copy has no Bcc; same Message-ID', async () => {
    const p = await client(['send'], [IMAP]);
    const r = await service.send(p, sendReq);
    expect(r).toMatchObject({ status: 'accepted', sentCopy: true });
    expect(r.detail).toMatch(/^Accepted by the provider.*A copy was filed in "Sent"\./);
    const copy = imap.appended.find((a) => a.mailbox === 'Sent')!;
    expect(copy.flags).toEqual(['\\Seen']);
    expect(headers(copy.raw.toString()).get('bcc')).toBe('hidden@example.test');
    const wire = smtpCalls[0]!.raw.toString();
    expect(wire).not.toContain('hidden@example.test');
    expect(headers(wire).get('message-id')).toBe(headers(copy.raw.toString()).get('message-id'));
    expect(smtpCalls).toHaveLength(1);
  });

  it('also for replies and forwards sent with send: true', async () => {
    const p = await client(['read', 'send'], [IMAP]);
    const r = await service.forward(p, { accountId: IMAP, messageId: encodeImapMessageId('INBOX', '11', 1), to: ['eve@example.test'], send: true, requestId: 'sent-copy-fwd-1' });
    expect(r).toMatchObject({ status: 'accepted', sentCopy: true });
    expect(imap.mailboxes.get('Sent')!.messages).toHaveLength(1);
  });

  it('a failing APPEND keeps the result accepted with sentCopy: false and never resubmits over SMTP; replay stays accepted', async () => {
    imap.failOn = { op: 'append', err: new Error('MOCK: over quota') };
    const p = await client(['send'], [IMAP]);
    const r = await service.send(p, sendReq);
    expect(r).toMatchObject({ status: 'accepted', requestState: 'accepted', sentCopy: false });
    expect(r.detail).toMatch(/NOT sent again/);
    expect(smtpCalls).toHaveLength(1);
    expect(await service.send(p, sendReq)).toMatchObject({ status: 'accepted', replayed: true });
    expect(smtpCalls).toHaveLength(1);
  });

  it('per-account opt-out (--no-sent-copy) and SMTP servers that file sent mail themselves get no copy', async () => {
    await store.update((d) => {
      d.imap[0]!.sentCopy = false;
    });
    const p = await client(['send'], [IMAP]);
    const r = await service.send(p, sendReq);
    expect(r).toMatchObject({ status: 'accepted', sentCopy: false });
    expect(imap.appended).toHaveLength(0);
    expect(imapSessions).toBe(0);
    const acct = (smtp: string, sentCopy?: boolean) => ({ smtp: { host: smtp, port: 465, security: 'tls' as const }, ...(sentCopy !== undefined ? { sentCopy } : {}) });
    expect(imapSentCopyEnabled(acct('mail.gmx.net'))).toBe(true);
    expect(imapSentCopyEnabled(acct('smtp.gmail.com'))).toBe(false);
    expect(imapSentCopyEnabled(acct('smtp.office365.com'))).toBe(false);
    expect(imapSentCopyEnabled(acct('smtp.gmail.com', true))).toBe(true);
    expect(imapSentCopyEnabled(acct('mail.gmx.net', false))).toBe(false);
  });

  it('finds Sent by special-use, else by common names; never a \\Noselect box', () => {
    expect(sentMailboxOf([{ path: 'INBOX' }, { path: 'Gesendet', specialUse: '\\Sent' }, { path: 'Sent' }])).toBe('Gesendet');
    expect(sentMailboxOf([{ path: 'INBOX' }, { path: 'sent items' }])).toBe('sent items');
    expect(sentMailboxOf([{ path: 'Sent', flags: ['\\Noselect'] }, { path: 'Gesendet' }])).toBe('Gesendet');
    expect(sentMailboxOf([{ path: 'INBOX' }])).toBeUndefined();
  });

  it('without any Sent folder: still accepted, sentCopy: false', async () => {
    imap.mailboxes.delete('Sent');
    const p = await client(['send'], [IMAP]);
    expect(await service.send(p, sendReq)).toMatchObject({ status: 'accepted', sentCopy: false });
    expect(smtpCalls).toHaveLength(1);
  });
});

describe('mail_reply / mail_forward MCP tools [MOCK providers]', () => {
  const memory = async (principal: Principal) => {
    const mcp = createMcpServer({ ...createPerchContext(store, gmail.transport), mail: service }, principal);
    const [a, b] = InMemoryTransport.createLinkedPair();
    await mcp.connect(b);
    const c = new Client({ name: 'mem', version: '0' });
    await c.connect(a);
    return c;
  };
  const names = async (p: Principal) => (await (await memory(p)).listTools()).tools.map((t) => t.name);

  it('are offered only to grants with "read" and "draft" or "send"', async () => {
    expect(WRITE_TOOL_NAMES).toEqual(expect.arrayContaining(['mail_reply', 'mail_forward']));
    expect(await names(READONLY_PRINCIPAL)).not.toContain('mail_reply');
    expect(await names(await client(['read'], [IMAP]))).not.toContain('mail_reply');
    expect(await names(await client(['draft', 'send'], [IMAP]))).not.toContain('mail_forward');
    expect(await names(await client(['read', 'draft'], [IMAP]))).toEqual(expect.arrayContaining(['mail_reply', 'mail_forward']));
    const tools = (await (await memory(await client(['read', 'send'], [IMAP]))).listTools()).tools;
    const reply = tools.find((t) => t.name === 'mail_reply')!;
    expect(reply.annotations).toMatchObject({ destructiveHint: true });
    expect(reply.description).toMatch(/untrusted/);
    expect(reply.description).toMatch(/BEFORE send: true, show the user the exact recipients/);
    expect(reply.inputSchema.required).toEqual(expect.arrayContaining(['accountId', 'messageId', 'text']));
    expect(tools.find((t) => t.name === 'mail_forward')!.inputSchema.required).toEqual(expect.arrayContaining(['accountId', 'messageId', 'to']));
  });

  it('drafts a reply through MCP with one body-free attempt/ok pair', async () => {
    const c = await memory(await client(['read', 'draft'], [IMAP]));
    const r = await c.callTool({ name: 'mail_reply', arguments: { accountId: IMAP, messageId: encodeImapMessageId('INBOX', '11', 1), text: 'Thanks' } });
    expect(r.isError).not.toBe(true);
    expect(JSON.parse((r.content as Array<{ text: string }>)[0]!.text)).toMatchObject({ provider: 'imap', to: ['replies@example.test'], sent: false });
    expect((await ledger()).audit.map((e) => [e.type, e.outcome])).toEqual([
      ['mail_reply', 'attempt'],
      ['mail_reply', 'ok'],
    ]);
  });
});
