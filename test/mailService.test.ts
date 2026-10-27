// MailService: authorization order, provenance, reply threading and fan-out over MOCK providers.
// The providers here are in-memory fakes; nothing talks to Gmail or an IMAP/SMTP server.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { PerchError } from '../src/errors.js';
import { MailService, type MailProviders } from '../src/mail/service.js';
import type { MailProvider, OutgoingMime } from '../src/mail/types.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
let store: CredentialStore;

interface Call {
  op: string;
  accountId: string;
  mail?: OutgoingMime;
}

type ReplyCtx = Awaited<ReturnType<MailProvider<unknown>['replyContext']>>;
const DEFAULT_REPLY_CTX: ReplyCtx = { internetMessageId: '<orig@example.test>', references: ['<root@example.test>'], subject: 'Plans', threadId: 'T1' };
/** What the MOCK upstream reports as the original's threading headers (tests may override). */
let replyCtx: ReplyCtx;

/** MOCK provider: records calls, returns canned data. */
function fakeProvider<A extends { id: string }>(kind: 'gmail' | 'microsoft' | 'imap', caps: { draft: boolean; send: boolean }, calls: Call[]): MailProvider<A> {
  return {
    kind,
    providerCapabilities: () => caps,
    search: async (a) => {
      calls.push({ op: 'search', accountId: a.id });
      return { items: [{ messageId: `${a.id}-m1`, subject: 'Hello' }] };
    },
    read: async (a, id) => {
      calls.push({ op: 'read', accountId: a.id });
      return { messageId: id, subject: 'Hello', truncated: false, attachments: [] };
    },
    getAttachment: async (a, _id, att) => {
      calls.push({ op: 'attachment', accountId: a.id });
      return { attachmentId: att, contentType: 'text/plain', size: 2, contentBase64: 'aGk=' };
    },
    replyContext: async (a) => {
      calls.push({ op: 'replyContext', accountId: a.id });
      return replyCtx;
    },
    createDraft: async (a, mail) => {
      calls.push({ op: 'draft', accountId: a.id, mail });
      return { draftId: 'D1' };
    },
    send: async (a, mail) => {
      calls.push({ op: 'send', accountId: a.id, mail });
      return { status: 'accepted', detail: 'accepted (MOCK)' };
    },
  };
}

let calls: Call[];
let service: MailService;

async function seed() {
  const now = new Date().toISOString();
  await store.update((d) => {
    d.gmail.push({
      id: 'gmail-0000000a',
      label: 'Private Gmail',
      email: 'me@gmail.example.test',
      clientId: dummySecret('C'),
      clientSecret: dummySecret('S'),
      refreshToken: dummySecret('RT'),
      scopes: [],
      createdAt: now,
      updatedAt: now,
    });
    d.imap.push({
      id: 'imap-0000000b',
      label: 'GMX',
      email: 'me@gmx.example.test',
      username: 'me@gmx.example.test',
      password: dummySecret('PW'),
      imap: { host: 'imap.gmx.net', port: 993 },
      smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
      allowDrafts: true,
      allowSend: true,
      createdAt: now,
      updatedAt: now,
    });
  });
}

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  calls = [];
  replyCtx = DEFAULT_REPLY_CTX;
  const providers: MailProviders = {
    // Gmail account in this fixture was granted read-only scopes.
    gmail: fakeProvider('gmail', { draft: false, send: false }, calls),
    imap: fakeProvider('imap', { draft: true, send: true }, calls),
  };
  service = new MailService(store, providers);
  await seed();
});
afterEach(async () => {
  await dirs.cleanup();
});

async function client(capabilities: Array<'read' | 'draft' | 'send'>, accountIds: string[]): Promise<Principal> {
  const { token } = await createClientGrant(store, {
    label: 'Test client',
    capabilities,
    accountIds,
    tokenFile: `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token`,
  });
  return (await principalForClientToken(store, token))!;
}

// requestId: the idempotency key every send needs (mail workflow milestone); drafts ignore it.
const outgoing = { to: ['friend@example.test'], subject: 'Hi', text: 'Body', requestId: 'mail-service-test-0001' };

describe('MailService [MOCK providers]', () => {
  it('lists accounts with provenance and what this principal may do', async () => {
    const list = await service.listAccounts(READONLY_PRINCIPAL);
    expect(list).toEqual([
      expect.objectContaining({ accountId: 'gmail-0000000a', provider: 'gmail', accountLabel: 'Private Gmail', granted: ['read'] }),
      expect.objectContaining({ accountId: 'imap-0000000b', provider: 'imap', accountLabel: 'GMX', granted: ['read'] }),
    ]);
    expect(JSON.stringify(list)).not.toMatch(/DUMMY-TEST/);
  });

  it('searches all readable accounts for the read-only operator and labels provenance', async () => {
    const res = await service.search(READONLY_PRINCIPAL, {});
    expect(res.results.map((r) => [r.accountId, r.accountLabel, r.provider])).toEqual([
      ['gmail-0000000a', 'Private Gmail', 'gmail'],
      ['imap-0000000b', 'GMX', 'imap'],
    ]);
  });

  it('restricts a client to its granted accounts', async () => {
    const p = await client(['read'], ['imap-0000000b']);
    const res = await service.search(p, {});
    expect(res.results.map((r) => r.accountId)).toEqual(['imap-0000000b']);
    await expect(service.read(p, { accountId: 'gmail-0000000a', messageId: 'x' })).rejects.toThrow(/not granted/i);
    expect(calls.filter((c) => c.accountId === 'gmail-0000000a')).toEqual([]);
  });

  it('denies drafts and sends on the read-only principal before any provider call', async () => {
    expect((await rejection(service.send(READONLY_PRINCIPAL, { accountId: 'imap-0000000b', ...outgoing }))).message).toMatch(/read-only/i);
    expect((await rejection(service.createDraft(READONLY_PRINCIPAL, { accountId: 'imap-0000000b', ...outgoing }))).message).toMatch(
      /read-only/i,
    );
    expect(calls).toEqual([]);
  });

  it('requires the provider-side capability (scope) in addition to the client grant', async () => {
    const p = await client(['send', 'draft'], ['gmail-0000000a']);
    expect((await rejection(service.send(p, { accountId: 'gmail-0000000a', ...outgoing }))).message).toMatch(/was not authorised to send/i);
    expect((await rejection(service.createDraft(p, { accountId: 'gmail-0000000a', ...outgoing }))).message).toMatch(/drafts/i);
    expect(calls).toEqual([]);
  });

  it('sends from the explicitly chosen account only and reports provider status with provenance', async () => {
    const p = await client(['send'], ['imap-0000000b']);
    expect((await rejection(service.send(p, { accountId: 'imap-0000000b', from: 'other@example.test', ...outgoing }))).message).toMatch(
      /must match/i,
    );
    const res = await service.send(p, { accountId: 'imap-0000000b', ...outgoing, bcc: ['hidden@example.test'] });
    expect(res).toMatchObject({ status: 'accepted', accountId: 'imap-0000000b', accountLabel: 'GMX', provider: 'imap', from: 'me@gmx.example.test' });
    const sent = calls.find((c) => c.op === 'send')!.mail!;
    expect(sent.envelope).toEqual({ from: 'me@gmx.example.test', to: ['friend@example.test', 'hidden@example.test'] });
    // IMAP/SMTP: Bcc travels in the envelope only.
    expect(sent.raw.toString()).not.toMatch(/^Bcc:/m);
    expect(sent.raw.toString()).toMatch(/^From: me@gmx\.example\.test/m);
  });

  it('threads replies with In-Reply-To/References and a Re: subject', async () => {
    // Reply threading reads the original message, so it needs "read" in addition to "draft".
    const p = await client(['read', 'draft'], ['imap-0000000b']);
    await service.createDraft(p, { accountId: 'imap-0000000b', to: ['friend@example.test'], text: 'Answer', replyToMessageId: 'imap:x' });
    const draft = calls.find((c) => c.op === 'draft')!.mail!;
    const raw = draft.raw.toString();
    expect(raw).toMatch(/^In-Reply-To: <orig@example\.test>\r?$/m);
    expect(raw).toMatch(/^References: <root@example\.test> <orig@example\.test>\r?$/m);
    expect(raw).toMatch(/^Subject: Re: Plans\r?$/m);
    expect(draft.threadId).toBe('T1');
  });

  it('rejects unknown accounts for the operator, and gives a client no account-existence oracle', async () => {
    await expect(service.search(READONLY_PRINCIPAL, { accountId: 'gmail-deadbeef' })).rejects.toThrow(/unknown mail account/i);
    const p = await client(['send'], ['imap-0000000b']);
    // A client gets the same capability_denied for an id that does not exist and for one that exists but is not granted.
    const missing = await rejection(service.send(p, { accountId: 'imap-deadbeef', ...outgoing }));
    const ungranted = await rejection(service.send(p, { accountId: 'gmail-0000000a', ...outgoing }));
    expect((missing as PerchError).code).toBe('capability_denied');
    expect((ungranted as PerchError).code).toBe('capability_denied');
    expect(missing.message.replace('imap-deadbeef', 'X')).toBe(ungranted.message.replace('gmail-0000000a', 'X'));
    expect(calls).toEqual([]);
  });

  it('lists only the granted mail accounts to a client (no other ids, labels or addresses)', async () => {
    const p = await client(['read'], ['imap-0000000b']);
    const list = await service.listAccounts(p);
    expect(list.map((a) => a.accountId)).toEqual(['imap-0000000b']);
    expect(list[0]).toMatchObject({ granted: ['read'], email: 'me@gmx.example.test' });
    const json = JSON.stringify(list);
    expect(json).not.toContain('gmail-0000000a');
    expect(json).not.toContain('me@gmail.example.test');
    expect(json).not.toContain('Private Gmail');
  });
});

describe('reply context needs "read" [MOCK providers]', () => {
  const reply = { accountId: 'imap-0000000b', to: ['me-attacker@example.test'], text: 'x', replyToMessageId: 'imap:SU5CT1g:1:7', requestId: 'mail-service-reply-0001' };

  it('denies a send-only grant before any provider I/O (no subject leak through "Re: …")', async () => {
    const p = await client(['send'], ['imap-0000000b']);
    const err = await rejection(service.send(p, reply));
    expect((err as PerchError).code).toBe('capability_denied');
    expect(err.message).toMatch(/read/);
    expect(calls).toEqual([]);
  });

  it('denies a draft-only grant before any provider I/O', async () => {
    const p = await client(['draft'], ['imap-0000000b']);
    const err = await rejection(service.createDraft(p, reply));
    expect((err as PerchError).code).toBe('capability_denied');
    expect(calls).toEqual([]);
  });

  it('still allows explicit caller-supplied threading ids without "read"', async () => {
    const p = await client(['send'], ['imap-0000000b']);
    await service.send(p, { accountId: 'imap-0000000b', ...outgoing, inReplyTo: '<a@example.test>', references: ['<a@example.test>'] });
    expect(calls.map((c) => c.op)).toEqual(['send']);
  });
});

describe('reply threading with malformed upstream ids [MOCK providers]', () => {
  it('drops invalid upstream Message-IDs/References instead of failing the reply', async () => {
    replyCtx = { internetMessageId: 'no-brackets@x', references: ['<a@b>', 'garbage', '<c@d>', '<x y@z>'], subject: 'Plans' };
    const p = await client(['read', 'draft'], ['imap-0000000b']);
    await service.createDraft(p, { accountId: 'imap-0000000b', to: ['friend@example.test'], text: 'Answer', replyToMessageId: 'imap:x' });
    const raw = calls.find((c) => c.op === 'draft')!.mail!.raw.toString();
    expect(raw).toMatch(/^References: <a@b> <c@d>\r?$/m);
    expect(raw).not.toMatch(/^In-Reply-To:/m);
    expect(raw).toMatch(/^Subject: Re: Plans\r?$/m);
  });

  it('keeps a valid upstream Message-ID as In-Reply-To and appends it to the sanitised References', async () => {
    replyCtx = { internetMessageId: '<orig@example.test>', references: ['bad', '<root@example.test>'], subject: 'Plans' };
    const p = await client(['read', 'draft'], ['imap-0000000b']);
    await service.createDraft(p, { accountId: 'imap-0000000b', to: ['friend@example.test'], text: 'Answer', replyToMessageId: 'imap:x' });
    const raw = calls.find((c) => c.op === 'draft')!.mail!.raw.toString();
    expect(raw).toMatch(/^In-Reply-To: <orig@example\.test>\r?$/m);
    expect(raw).toMatch(/^References: <root@example\.test> <orig@example\.test>\r?$/m);
  });

  it('keeps caller-supplied threading ids strict', async () => {
    const p = await client(['read', 'draft'], ['imap-0000000b']);
    const err = await rejection(
      service.createDraft(p, { accountId: 'imap-0000000b', ...outgoing, references: ['garbage'], replyToMessageId: 'imap:x' }),
    );
    expect((err as PerchError).code).toBe('bad_argument');
    expect(calls.filter((c) => c.op === 'draft')).toEqual([]);
    await expect(service.createDraft(p, { accountId: 'imap-0000000b', ...outgoing, inReplyTo: 'no-brackets@x' })).rejects.toThrow(
      /Message-ID/,
    );
  });
});
