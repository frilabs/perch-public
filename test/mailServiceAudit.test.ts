// Direct MailService calls (outside MCP) are audited by the service itself with body-free fields, a draft
// write fails closed when its audit attempt cannot be persisted, a draft re-checks the full sender binding
// after the reply lookup, and the store's ledger marker is durably persisted before any ledger write
// (never trusted from an in-memory cache). MOCK providers only.
import { readFile, rm, writeFile } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, type Principal } from '../src/auth/grants.js';
import type { PerchError } from '../src/errors.js';
import { MailService, type MailProviders } from '../src/mail/service.js';
import type { MailProvider } from '../src/mail/types.js';
import { initMailWorkflowLedger, ledgerFilePath, MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
let calls: string[];
let replyHook: () => Promise<void>;
let service: MailService;
let p: Principal;
let clientId: string;

const ACCOUNT = 'imap-0000000d';
const REPLY_TO = 'imap:SU5CT1g:1:7';
const MARK = { messageId: 'imap:SU5CT1g:1:4242', attachmentId: 'att-secret-9', query: 'needle-query-text' };

function fakeProvider<A extends { id: string }>(kind: 'gmail' | 'microsoft' | 'imap'): MailProvider<A> {
  return {
    kind,
    providerCapabilities: () => ({ draft: true, send: true }),
    search: async () => {
      calls.push('search');
      return { items: [] };
    },
    read: async (_a, id) => {
      calls.push('read');
      return { messageId: id, truncated: false, attachments: [] };
    },
    getAttachment: async () => {
      calls.push('getAttachment');
      return { attachmentId: '1', contentType: 'text/plain', size: 0, contentBase64: '' };
    },
    replyContext: async () => {
      calls.push('replyContext');
      await replyHook();
      return { internetMessageId: '<orig@example.test>', references: [], subject: 'Plans' };
    },
    createDraft: async () => {
      calls.push('createDraft');
      return { draftId: 'provider-draft-id-XYZ' };
    },
    send: async () => {
      calls.push('send');
      return { status: 'accepted', providerMessageId: 'gmailid_ABC123', detail: 'MOCK accepted' };
    },
  };
}

const providers = (): MailProviders => ({ gmail: fakeProvider('gmail'), imap: fakeProvider('imap') });
const ledger = () => new MailWorkflowLedger(store).read();
const audit = async () => (await ledger()).audit;
const code = async (promise: Promise<unknown>) => ((await rejection(promise)) as PerchError).code;
const draft = (over: Record<string, unknown> = {}) => ({ accountId: ACCOUNT, to: ['rcpt@example.test'], subject: 'Hi', text: 'Body', ...over });

/** A second store instance on the same files whose writes fail (e.g. disk full, read-only store.enc). */
async function failingStore(): Promise<CredentialStore> {
  const s = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  s.update = async () => {
    throw new Error('injected store write failure');
  };
  return s;
}

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  calls = [];
  replyHook = async () => {};
  const now = new Date().toISOString();
  await store.update((d) => {
    d.imap.push({
      id: ACCOUNT,
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
  service = new MailService(store, providers());
  const { token, client } = await createClientGrant(store, {
    label: 'Audit client',
    capabilities: ['read', 'draft', 'send'],
    accountIds: [ACCOUNT],
    tokenFile: `${dirs.root}/config/clients/audit.token`,
  });
  p = (await principalForClientToken(store, token))!;
  clientId = client.id;
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('direct MailService calls are audited by the service [MOCK providers]', () => {
  it('records one body-free event per direct read, attachment, search, account list, draft and status call', async () => {
    await service.read(p, { accountId: ACCOUNT, messageId: MARK.messageId });
    await service.getAttachment(p, { accountId: ACCOUNT, messageId: MARK.messageId, attachmentId: MARK.attachmentId });
    await service.search(p, { query: MARK.query, accountId: ACCOUNT });
    await service.listAccounts(p);
    await service.createDraft(p, draft());
    await service.send(p, { ...draft(), requestId: 'audit-request-0001' });
    await service.sendStatus(p, { accountId: ACCOUNT, requestId: 'audit-request-0001' });
    const actor = { kind: 'client', clientId };
    const rows = (await audit()).map((e) => [e.type, e.outcome, e.accountId ?? null, e.provider ?? null, e.actor]);
    expect(rows).toEqual([
      ['mail_read_message', 'ok', ACCOUNT, 'imap', actor],
      ['mail_get_attachment', 'ok', ACCOUNT, 'imap', actor],
      ['mail_search', 'ok', ACCOUNT, 'imap', actor],
      ['mail_list_accounts', 'ok', null, null, actor],
      ['mail_create_draft', 'attempt', ACCOUNT, 'imap', actor],
      ['mail_create_draft', 'ok', ACCOUNT, 'imap', actor],
      ['mail_send', 'pending', ACCOUNT, 'imap', actor],
      ['mail_send', 'accepted', ACCOUNT, 'imap', actor],
      ['mail_send_status', 'ok', ACCOUNT, 'imap', actor],
    ]);
    const evs = await audit();
    expect(evs[4]!.operationId).toBe(evs[5]!.operationId);
    const plain = JSON.stringify(await ledger());
    for (const secret of [MARK.messageId, MARK.attachmentId, MARK.query, 'provider-draft-id-XYZ', 'me@gmx.example.test', 'rcpt@example.test', 'GMX', 'audit-request-0001']) {
      expect(plain).not.toContain(secret);
    }
  });

  it('records denied and failed direct reads with fixed codes only', async () => {
    expect(await code(service.read(p, { accountId: 'imap-000000ff', messageId: MARK.messageId }))).toBe('capability_denied');
    expect(await code(service.read(p, { accountId: ACCOUNT, messageId: MARK.messageId, maxBytes: 0 }))).toBe('bad_argument');
    const rows = (await audit()).map((e) => [e.type, e.outcome, e.accountId ?? null, e.code ?? null]);
    expect(rows).toEqual([
      ['mail_read_message', 'denied', 'imap-000000ff', 'capability_denied'],
      ['mail_read_message', 'invalid', ACCOUNT, 'bad_argument'],
    ]);
  });

  it('withholds a direct read result when its audit record cannot be written', async () => {
    await rm(ledgerFilePath(dirs.dataDir));
    expect(await code(service.read(p, { accountId: ACCOUNT, messageId: MARK.messageId }))).toBe('audit_unavailable');
    expect(await code(service.sendStatus(p, { accountId: ACCOUNT, requestId: 'audit-request-0001' }))).toBe('ledger_missing');
  });

  it('never writes a direct draft when the ledger is missing or corrupt (audit attempt fails closed first)', async () => {
    const file = ledgerFilePath(dirs.dataDir);
    const raw = await readFile(file, 'utf8');
    await writeFile(file, raw.slice(0, -8) + 'AAAAAAAA');
    expect(await code(service.createDraft(p, draft()))).toBe('ledger_corrupt');
    await rm(file);
    expect(await code(service.createDraft(p, draft()))).toBe('ledger_missing');
    expect(await code(service.createDraft(p, draft({ subject: undefined, replyToMessageId: REPLY_TO })))).toBe('ledger_missing');
    expect(calls).toEqual([]);
  });
});

describe('a draft re-checks the full sender binding after the reply lookup [MOCK providers]', () => {
  const during = async (change: () => Promise<void>) => {
    replyHook = change;
    expect(await code(service.createDraft(p, draft({ subject: undefined, replyToMessageId: REPLY_TO })))).toBe('account_changed');
    expect(calls).toEqual(['replyContext']);
  };
  it('refuses when the IMAP password is substituted during the reply lookup', async () => {
    await during(() => store.update((d) => void (d.imap[0]!.password = dummySecret('OTHER'))));
  });
  it('refuses when the IMAP/SMTP server is substituted during the reply lookup', async () => {
    await during(() => store.update((d) => void (d.imap[0]!.imap.host = 'imap.attacker.example.test')));
  });
  it('refuses when the account is removed and re-added with the same id and address', async () => {
    await during(() => store.update((d) => void (d.imap[0]!.createdAt = new Date(Date.now() + 5000).toISOString())));
  });
});

describe('the ledger marker is durably persisted before any ledger write [MOCK providers]', () => {
  it('refuses a fresh send (no claim, no provider I/O) when the missing marker cannot be persisted', async () => {
    const other = await failingStore();
    await store.update((d) => void delete d.mailWorkflowLedger);
    const s = new MailService(other, providers());
    expect(await rejection(s.send(p, { ...draft(), requestId: 'marker-request-0001' }))).toBeTruthy();
    expect(calls).toEqual([]);
    expect((await ledger()).sends).toEqual([]);
  });

  it('re-checks the persisted marker on every write (no in-memory cache after the marker was removed)', async () => {
    const other = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    const s = new MailService(other, providers());
    expect((await s.send(p, { ...draft(), requestId: 'marker-request-0002' })).status).toBe('accepted');
    await store.update((d) => void delete d.mailWorkflowLedger);
    other.update = async () => {
      throw new Error('injected store write failure');
    };
    expect(await rejection(s.send(p, { ...draft(), requestId: 'marker-request-0003' }))).toBeTruthy();
    expect(calls.filter((c) => c === 'send')).toHaveLength(1);
    expect((await ledger()).sends).toHaveLength(1);
  });

  it('backfills the marker before the first write of an unmarked existing ledger, so init can never reset it', async () => {
    await store.update((d) => void delete d.mailWorkflowLedger);
    expect((await service.send(p, { ...draft(), requestId: 'marker-request-0004' })).status).toBe('accepted');
    expect((await store.read()).mailWorkflowLedger).toBeDefined();
    await rm(ledgerFilePath(dirs.dataDir));
    expect(await code(initMailWorkflowLedger(store))).toBe('ledger_missing');
  });

  it('does not mark a namespace whose ledger is missing (init stays possible for pre-ledger namespaces)', async () => {
    await store.update((d) => void delete d.mailWorkflowLedger);
    await rm(ledgerFilePath(dirs.dataDir));
    expect(await code(service.send(p, { ...draft(), requestId: 'marker-request-0005' }))).toBe('ledger_missing');
    expect((await store.read()).mailWorkflowLedger).toBeUndefined();
    expect(await initMailWorkflowLedger(store)).toBe(true);
    expect(calls).toEqual([]);
  });
});
