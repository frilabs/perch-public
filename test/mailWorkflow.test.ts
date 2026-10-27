// Durable idempotent mail send workflow (MailService.send + mail-workflow.enc) over MOCK providers.
// Nothing talks to Gmail or an IMAP/SMTP server; every secret is generated dummy data.
import { chmod } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, currentPrincipal, principalForClientToken, type Principal } from '../src/auth/grants.js';
import { PerchError } from '../src/errors.js';
import { MailService, type MailProviders } from '../src/mail/service.js';
import type { MailProvider, OutgoingMime, SendResult } from '../src/mail/types.js';
import { MailWorkflowLedger, MAX_SEND_RECORDS } from '../src/mail/workflowLedger.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
let calls: Array<{ op: string; accountId: string; mail?: OutgoingMime }>;
/** What the MOCK provider does when asked to send (tests replace it). */
let sendImpl: (mail: OutgoingMime) => Promise<SendResult>;
let replyHook: () => Promise<void>;

const ACCOUNT = 'imap-0000000b';
const MARK = {
  text: 'BODY-MARKER-7f3a9c',
  subject: 'SUBJECT-MARKER-91c2',
  to: 'rcpt-marker-55@example.test',
  bcc: 'bcc-marker-66@example.test',
  file: 'ATTACH-NAME-MARKER.pdf',
  content: Buffer.from('ATTACH-CONTENT-MARKER').toString('base64'),
  requestId: 'REQ-MARKER-0001',
};

function fakeProvider<A extends { id: string }>(kind: 'gmail' | 'microsoft' | 'imap'): MailProvider<A> {
  return {
    kind,
    providerCapabilities: (a) => ({ draft: true, send: (a as unknown as { allowSend?: boolean }).allowSend !== false }),
    search: async () => ({ items: [] }),
    read: async (_a, id) => ({ messageId: id, truncated: false, attachments: [] }),
    getAttachment: async () => ({ attachmentId: '1', contentType: 'text/plain', size: 0, contentBase64: '' }),
    replyContext: async (a) => {
      calls.push({ op: 'replyContext', accountId: a.id });
      await replyHook();
      return { internetMessageId: '<orig@example.test>', references: [], subject: 'Plans' };
    },
    createDraft: async () => ({ draftId: 'D1' }),
    send: async (a, mail) => {
      calls.push({ op: 'send', accountId: a.id, mail });
      return sendImpl(mail);
    },
  };
}

const providers = (): MailProviders => ({ gmail: fakeProvider('gmail'), imap: fakeProvider('imap') });
const newService = async (s?: CredentialStore) => new MailService(s ?? (await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile })), providers());
const sends = () => calls.filter((c) => c.op === 'send');
const accepted = async (): Promise<SendResult> => ({ status: 'accepted', providerMessageId: 'gmailid_ABC123', detail: 'MOCK accepted' });

async function seed(s: CredentialStore, email = 'me@gmx.example.test') {
  const now = new Date().toISOString();
  await s.update((d) => {
    d.imap.push({
      id: ACCOUNT,
      label: 'LABEL-MARKER GMX',
      email,
      username: email,
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

async function client(s: CredentialStore, capabilities: Array<'read' | 'draft' | 'send'>, accountIds = [ACCOUNT]): Promise<Principal> {
  const { token } = await createClientGrant(s, {
    label: 'Workflow client',
    capabilities,
    accountIds,
    tokenFile: `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token`,
  });
  return (await principalForClientToken(s, token))!;
}

const request = (over: Record<string, unknown> = {}) => ({
  accountId: ACCOUNT,
  requestId: MARK.requestId,
  to: [MARK.to],
  bcc: [MARK.bcc],
  subject: MARK.subject,
  text: MARK.text,
  attachments: [{ filename: MARK.file, contentType: 'application/pdf', contentBase64: MARK.content }],
  ...over,
});

let service: MailService;
let p: Principal;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  calls = [];
  sendImpl = accepted;
  replyHook = async () => {};
  await seed(store);
  service = new MailService(store, providers());
  p = await client(store, ['read', 'send']);
});
afterEach(async () => {
  await chmod(dirs.dataDir, 0o700).catch(() => {});
  await dirs.cleanup();
});

const ledgerData = async () => new MailWorkflowLedger(await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile })).read();

describe('idempotent mail send workflow [MOCK providers]', () => {
  it('requires a bounded, opaque requestId before any provider I/O or send record', async () => {
    for (const requestId of [undefined, '', 'short', 'has space 123', 'a'.repeat(129), 'line\nbreak12', 'semi;colon12', 'ümlaut-12345']) {
      const err = await rejection(service.send(p, request({ requestId }) as never));
      expect((err as PerchError).code, String(requestId)).toBe('bad_argument');
      expect(err.message).toMatch(/requestId/);
      expect(err.message).not.toContain('line\nbreak');
    }
    expect(calls).toEqual([]);
    const data = await ledgerData();
    expect(data.sends).toEqual([]);
    expect(data.audit.map((e) => [e.type, e.outcome, e.code])).toEqual(Array(8).fill(['mail_send', 'invalid', 'bad_argument']));
  });

  it('persists the pending record before the single provider attempt and replays the cached result without I/O', async () => {
    let pendingSeen: unknown;
    sendImpl = async () => {
      pendingSeen = (await ledgerData()).sends.map((s) => s.state);
      return accepted();
    };
    const first = await service.send(p, request({ replyToMessageId: 'imap:SU5CT1g:1:7', subject: undefined }));
    expect(pendingSeen).toEqual(['pending']);
    expect(first).toMatchObject({ status: 'accepted', replayed: false, requestState: 'accepted', accountId: ACCOUNT, provider: 'imap' });
    expect(first.operationId).toMatch(/^op-[a-f0-9]{24}$/);
    expect(first.detail).toMatch(/not proof of delivery/i);
    const again = await service.send(p, request({ replyToMessageId: 'imap:SU5CT1g:1:7', subject: undefined }));
    expect(again).toMatchObject({ status: 'accepted', replayed: true, requestState: 'accepted', operationId: first.operationId });
    expect(again.detail).toMatch(/not sent again/i);
    expect(again.detail).toMatch(/not proof of delivery/i);
    // The replay neither re-fetched the reply context nor recomposed/resubmitted.
    expect(calls.map((c) => c.op)).toEqual(['replyContext', 'send']);
    const data = await ledgerData();
    expect(data.audit.map((e) => [e.type, e.outcome])).toEqual([
      ['mail_send', 'pending'],
      ['mail_send', 'accepted'],
      ['mail_send', 'replayed'],
    ]);
  });

  it('submits exactly once for concurrent duplicates in one service instance', async () => {
    sendImpl = async () => {
      await new Promise((r) => setTimeout(r, 50));
      return accepted();
    };
    const results = await Promise.all(Array.from({ length: 8 }, () => service.send(p, request())));
    expect(sends()).toHaveLength(1);
    expect(results.filter((r) => !r.replayed)).toHaveLength(1);
    for (const r of results.filter((x) => x.replayed)) expect(['indeterminate', 'accepted']).toContain(r.status);
    expect((await ledgerData()).sends).toHaveLength(1);
  });

  it('submits exactly once across separate store and service instances sharing the ledger', async () => {
    sendImpl = async () => {
      await new Promise((r) => setTimeout(r, 50));
      return accepted();
    };
    const services = await Promise.all([0, 1, 2, 3].map(() => newService()));
    const results = await Promise.all(services.flatMap((s) => [s.send(p, request()), s.send(p, request())]));
    expect(sends()).toHaveLength(1);
    expect(results.filter((r) => !r.replayed)).toHaveLength(1);
    // A pending duplicate is reported as unknown (never as a new send); afterwards the stored result is replayed.
    expect(results.filter((r) => r.replayed && r.requestState === 'pending').every((r) => r.status === 'indeterminate')).toBe(true);
    expect((await (await newService()).send(p, request())).status).toBe('accepted');
  });

  it('fails a changed payload under the same key before any provider I/O (including reply lookup)', async () => {
    await service.send(p, request());
    const before = calls.length;
    for (const change of [
      { text: 'other body' },
      { to: ['someone.else@example.test'] },
      { bcc: [] },
      { subject: 'other' },
      { attachments: [] },
      { replyToMessageId: 'imap:SU5CT1g:1:8' },
      { html: '<p>x</p>' },
    ]) {
      const err = await rejection(service.send(p, request(change)));
      expect((err as PerchError).code, JSON.stringify(change)).toBe('idempotency_conflict');
      expect(err.message).not.toContain(MARK.text);
    }
    expect(calls.length).toBe(before);
    const data = await ledgerData();
    expect(data.sends).toHaveLength(1);
    expect(data.audit.filter((e) => e.outcome === 'conflict')).toHaveLength(7);
  });

  it('treats a provider rejection (e.g. network loss before acceptance) as terminal and never resubmits', async () => {
    sendImpl = async () => ({ status: 'rejected', detail: 'Not sent: smtp.invalid.example:465 connect failed (MOCK)' });
    const r = await service.send(p, request());
    expect(r).toMatchObject({ status: 'rejected', replayed: false });
    const again = await service.send(p, request());
    expect(again).toMatchObject({ status: 'rejected', replayed: true, requestState: 'rejected' });
    expect(again.detail).toMatch(/new requestId/i);
    expect(sends()).toHaveLength(1);
    expect(JSON.stringify(await ledgerData())).not.toContain('smtp.invalid');
  });

  it('keeps a lost response after upstream acceptance indeterminate and never resubmits', async () => {
    sendImpl = async () => ({ status: 'indeterminate', detail: 'lost (MOCK)' });
    expect(await service.send(p, request())).toMatchObject({ status: 'indeterminate', requestState: 'indeterminate' });
    const again = await service.send(p, request());
    expect(again).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(again.detail).toMatch(/Sent folder/);
    expect(sends()).toHaveLength(1);
  });

  it('classifies an adapter crash as indeterminate and a pre-submission refusal as rejected', async () => {
    sendImpl = async () => {
      throw new Error('socket hang up after write (MOCK)');
    };
    expect(await service.send(p, request({ requestId: 'crash-0000001' }))).toMatchObject({ status: 'indeterminate' });
    sendImpl = async () => {
      throw new PerchError('Not sent: message too large (MOCK)', 'message_too_large');
    };
    expect(await service.send(p, request({ requestId: 'precheck-0001' }))).toMatchObject({ status: 'rejected' });
    const reasons = (await ledgerData()).sends.map((s) => [s.state, s.reason]);
    expect(reasons).toEqual([
      ['indeterminate', 'adapter_error'],
      ['rejected', 'not_submitted_provider_precheck'],
    ]);
    expect(sends()).toHaveLength(2);
  });

  it('reports acceptance as indeterminate when the outcome cannot be persisted, and the durable pending survives a restart', async () => {
    sendImpl = async () => {
      await chmod(dirs.dataDir, 0o500); // finalization write will fail
      return accepted();
    };
    const r = await service.send(p, request());
    expect(r).toMatchObject({ status: 'indeterminate', replayed: false });
    expect(r.detail).toMatch(/could not be recorded/i);
    await chmod(dirs.dataDir, 0o700);
    expect((await ledgerData()).sends.map((s) => s.state)).toEqual(['pending']);
    const restarted = await newService();
    const again = await restarted.send(p, request());
    expect(again).toMatchObject({ status: 'indeterminate', replayed: true, requestState: 'pending' });
    expect(await restarted.sendStatus(p, { accountId: ACCOUNT, requestId: MARK.requestId })).toMatchObject({ status: 'indeterminate', requestState: 'pending' });
    expect(sends()).toHaveLength(1);
  });

  it('never resends a request whose process died after the claim (hard pending after restart)', async () => {
    sendImpl = () => new Promise<SendResult>(() => {}); // the "process" hangs/crashes mid-attempt
    void service.send(p, request());
    for (let i = 0; i < 100 && sends().length === 0; i++) await new Promise((r) => setTimeout(r, 10));
    expect(sends()).toHaveLength(1);
    sendImpl = accepted;
    const restarted = await newService();
    for (let i = 0; i < 3; i++) {
      expect(await restarted.send(p, request())).toMatchObject({ status: 'indeterminate', replayed: true, requestState: 'pending' });
    }
    expect(sends()).toHaveLength(1);
  });

  it('fails closed when the sender account is replaced between the claim and the submission', async () => {
    replyHook = async () => {
      await store.update((d) => {
        d.imap[0]!.email = 'attacker@example.test';
        d.imap[0]!.username = 'attacker@example.test';
      });
    };
    const r = await service.send(p, request({ replyToMessageId: 'imap:SU5CT1g:1:7' }));
    expect(r).toMatchObject({ status: 'rejected', replayed: false });
    expect(sends()).toHaveLength(0);
    expect((await ledgerData()).sends.map((s) => s.reason)).toEqual(['not_submitted_account_changed']);
  });

  it('refuses to replay or report a result after the sender account identity changed', async () => {
    await service.send(p, request());
    await store.update((d) => void (d.imap[0]!.password = dummySecret('PW2')));
    expect(await rejection(service.send(p, request()))).toMatchObject({ code: 'account_changed' });
    expect(await rejection(service.sendStatus(p, { accountId: ACCOUNT, requestId: MARK.requestId }))).toMatchObject({ code: 'account_changed' });
    expect(sends()).toHaveLength(1);
  });

  it('re-checks grant, account and provider scope before revealing a cached result', async () => {
    await service.send(p, request({ replyToMessageId: 'imap:SU5CT1g:1:7', subject: undefined }));
    const grantId = p.clientId!;
    // Narrowed grant: read removed (reply needs read), then send removed.
    await store.update((d) => void (d.clients.find((c) => c.id === grantId)!.capabilities = ['send']));
    let cur = await currentPrincipal(store, p);
    expect(await rejection(service.send(cur, request({ replyToMessageId: 'imap:SU5CT1g:1:7', subject: undefined })))).toMatchObject({ code: 'capability_denied' });
    await store.update((d) => void (d.clients.find((c) => c.id === grantId)!.capabilities = ['read']));
    cur = await currentPrincipal(store, p);
    expect(await rejection(service.sendStatus(cur, { accountId: ACCOUNT, requestId: MARK.requestId }))).toMatchObject({ code: 'capability_denied' });
    // Revoked grant: currentPrincipal itself fails (the MCP runner calls it before every tool).
    await store.update((d) => void (d.clients = d.clients.filter((c) => c.id !== grantId)));
    expect(await rejection(currentPrincipal(store, p))).toMatchObject({ code: 'grant_revoked' });
    // Provider opt-in withdrawn: even the replay is refused.
    const q = await client(store, ['read', 'send']);
    await service.send(q, request({ requestId: 'other-key-001' }));
    await store.update((d) => void (d.imap[0]!.allowSend = false));
    expect(await rejection(service.send(q, request({ requestId: 'other-key-001' })))).toMatchObject({ code: 'provider_scope_missing' });
    expect(calls.filter((c) => c.op === 'send')).toHaveLength(2);
  });

  it('scopes keys to the client, the account and the namespace', async () => {
    await service.send(p, request());
    const other = await client(store, ['read', 'send']);
    // Another client cannot read the first client's status, and its own same-named key is independent.
    expect(await rejection(service.sendStatus(other, { accountId: ACCOUNT, requestId: MARK.requestId }))).toMatchObject({ code: 'unknown_request' });
    expect(await service.send(other, request())).toMatchObject({ status: 'accepted', replayed: false });
    expect(sends()).toHaveLength(2);

    // A second namespace with the SAME account id, grant id and request id uses only its own provider.
    const B = await makeTempDirs();
    try {
      await initStore({ dataDir: B.dataDir, keyFile: B.keyFile }, { namespace: 'user-0123456789abcdef' });
      const storeB = await CredentialStore.open({ dataDir: B.dataDir, keyFile: B.keyFile }, { namespace: 'user-0123456789abcdef' });
      await seed(storeB, 'b@gmx.example.test');
      const pb = await client(storeB, ['read', 'send']);
      await storeB.update((d) => void (d.clients[0]!.id = p.clientId!));
      const pbSame = await currentPrincipal(storeB, { ...pb, clientId: p.clientId! });
      const callsB: typeof calls = [];
      const bProviders = providers();
      bProviders.imap = { ...bProviders.imap, send: async (a, mail) => (callsB.push({ op: 'send', accountId: a.id, mail }), accepted()) };
      const serviceB = new MailService(storeB, bProviders);
      expect(await rejection(serviceB.sendStatus(pbSame, { accountId: ACCOUNT, requestId: MARK.requestId }))).toMatchObject({ code: 'unknown_request' });
      expect(await serviceB.send(pbSame, request())).toMatchObject({ status: 'accepted', replayed: false });
      expect(callsB).toHaveLength(1);
      expect(callsB[0]!.mail!.envelope.from).toBe('b@gmx.example.test');
      expect(sends()).toHaveLength(2);
      const keysA = (await ledgerData()).sends.map((s) => s.key);
      const keysB = (await new MailWorkflowLedger(storeB).read()).sends.map((s) => s.key);
      expect(keysA).not.toContain(keysB[0]);
    } finally {
      await B.cleanup();
    }
  });

  it('writes only body-free, recipient-free, credential-free fields to the decrypted ledger', async () => {
    await service.send(p, request());
    sendImpl = async () => ({ status: 'accepted', providerMessageId: `<id.${MARK.to}>`, detail: `accepted for ${MARK.to} (MOCK)` });
    const r = await service.send(p, request({ requestId: 'second-key-01', html: `<b>${MARK.text}</b>` }));
    expect(r.status).toBe('accepted');
    const data = await ledgerData();
    const json = JSON.stringify(data);
    const secrets = (await store.read()).imap[0]!.password;
    for (const marker of [MARK.text, MARK.subject, MARK.to, MARK.bcc, MARK.file, MARK.content, MARK.requestId, 'second-key-01', 'LABEL-MARKER', 'me@gmx.example.test', secrets, 'MOCK']) {
      expect(json, marker).not.toContain(marker);
    }
    // Opaque provider ids are kept; anything carrying an address or host is dropped.
    expect(data.sends.map((s) => s.providerMessageId)).toEqual(['gmailid_ABC123', undefined]);
  });

  it('refuses new sends before provider I/O when the ledger is full', async () => {
    const ledger = new MailWorkflowLedger(store);
    await ledger.transact((d) => {
      for (let i = 0; i < MAX_SEND_RECORDS; i++) {
        d.sends.push({
          key: i.toString(16).padStart(64, '0'),
          fp: 'b'.repeat(64),
          binding: 'c'.repeat(64),
          operationId: `op-${i.toString(16).padStart(24, '0')}`,
          accountId: ACCOUNT,
          provider: 'imap',
          actor: { kind: 'client', clientId: p.clientId! },
          state: 'accepted',
          attempt: 'd'.repeat(32),
          createdAt: new Date().toISOString(),
        });
      }
    });
    expect(await rejection(service.send(p, request()))).toMatchObject({ code: 'ledger_full' });
    expect(calls).toEqual([]);
  });

  it('fails closed before provider I/O when the ledger is missing or corrupt', async () => {
    const { rm, writeFile } = await import('node:fs/promises');
    const file = `${dirs.dataDir}/mail-workflow.enc`;
    await writeFile(file, 'corrupt', { mode: 0o600 });
    expect((await rejection(service.send(p, request()))).message).toMatch(/ledger/i);
    await rm(file);
    expect(await rejection(service.send(p, request()))).toMatchObject({ code: 'ledger_missing' });
    expect(calls).toEqual([]);
  });
});
