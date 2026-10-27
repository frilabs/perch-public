// MailService is its own authorization boundary: every direct call re-resolves the client grant from the
// store and runs the namespace guard, and a claimed send re-checks both (plus capability, provider scope and
// sender identity) immediately before the provider call, after the reply lookup. MOCK providers only.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, tokenSha256, type Principal } from '../src/auth/grants.js';
import { PerchError } from '../src/errors.js';
import { MailService, type MailProviders } from '../src/mail/service.js';
import type { MailProvider, SendResult } from '../src/mail/types.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
let calls: string[];
let replyHook: () => Promise<void>;
let guardError: PerchError | null;
let service: MailService;
let p: Principal;

const ACCOUNT = 'imap-0000000c';
const REPLY_TO = 'imap:SU5CT1g:1:7';

function fakeProvider<A extends { id: string }>(kind: 'gmail' | 'microsoft' | 'imap'): MailProvider<A> {
  return {
    kind,
    providerCapabilities: (a) => ({ draft: true, send: (a as unknown as { allowSend?: boolean }).allowSend !== false }),
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
      return { draftId: 'D1' };
    },
    send: async (): Promise<SendResult> => {
      calls.push('send');
      return { status: 'accepted', providerMessageId: 'gmailid_ABC123', detail: 'MOCK accepted' };
    },
  };
}

const providers = (): MailProviders => ({ gmail: fakeProvider('gmail'), imap: fakeProvider('imap') });
const guard = async () => {
  if (guardError) throw guardError;
};
const sends = () => calls.filter((c) => c === 'send').length;
const request = (over: Record<string, unknown> = {}) => ({ accountId: ACCOUNT, requestId: 'authz-request-0001', to: ['rcpt@example.test'], subject: 'Hi', text: 'Body', ...over });
const ledger = () => new MailWorkflowLedger(store).read();
const code = async (promise: Promise<unknown>) => ((await rejection(promise)) as PerchError).code;

async function grant(capabilities: Array<'read' | 'draft' | 'send'>): Promise<{ principal: Principal; clientId: string }> {
  const { token, client } = await createClientGrant(store, {
    label: 'Authz client',
    capabilities,
    accountIds: [ACCOUNT],
    tokenFile: `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token`,
  });
  return { principal: (await principalForClientToken(store, token))!, clientId: client.id };
}

const revokeAll = () => store.update((d) => void (d.clients = []));
const setCaps = (caps: Array<'read' | 'draft' | 'send'>) => store.update((d) => void d.clients.forEach((c) => (c.capabilities = caps)));
const setAllowSend = (allowSend: boolean) => store.update((d) => void (d.imap[0]!.allowSend = allowSend));

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  calls = [];
  replyHook = async () => {};
  guardError = null;
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
  service = new MailService(store, providers(), undefined, { guard });
  p = (await grant(['read', 'draft', 'send'])).principal;
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('MailService re-validates the caller on every direct call [MOCK providers]', () => {
  it('denies a stale principal replay and status after the grant was revoked, without I/O', async () => {
    expect((await service.send(p, request())).status).toBe('accepted');
    await revokeAll();
    expect(await code(service.send(p, request()))).toBe('grant_revoked');
    expect(await code(service.sendStatus(p, { accountId: ACCOUNT, requestId: 'authz-request-0001' }))).toBe('grant_revoked');
    expect(sends()).toBe(1);
    const audit = (await ledger()).audit.filter((e) => e.type === 'mail_send');
    expect(audit.at(-1)).toMatchObject({ outcome: 'denied', code: 'grant_revoked' });
  });

  it('denies a stale principal whose token was replaced (same client id) or whose send capability was removed', async () => {
    expect((await service.send(p, request())).status).toBe('accepted');
    await store.update((d) => void (d.clients[0]!.tokenSha256 = tokenSha256('replacement-token')));
    expect(await code(service.send(p, request()))).toBe('grant_revoked');
    expect(await code(service.sendStatus(p, { accountId: ACCOUNT, requestId: 'authz-request-0001' }))).toBe('grant_revoked');
    const fresh = (await grant(['read', 'send'])).principal;
    expect((await service.send(fresh, request({ requestId: 'authz-request-0002' }))).status).toBe('accepted');
    await setCaps(['read']);
    expect(await code(service.send(fresh, request({ requestId: 'authz-request-0002' })))).toBe('capability_denied');
    expect(await code(service.sendStatus(fresh, { accountId: ACCOUNT, requestId: 'authz-request-0002' }))).toBe('capability_denied');
    expect(sends()).toBe(2);
  });

  it('withholds send status once the provider send permission was withdrawn', async () => {
    expect((await service.send(p, request())).status).toBe('accepted');
    await setAllowSend(false);
    expect(await code(service.sendStatus(p, { accountId: ACCOUNT, requestId: 'authz-request-0001' }))).toBe('provider_scope_missing');
    expect(await code(service.send(p, request()))).toBe('provider_scope_missing');
    expect(sends()).toBe(1);
  });

  it('runs the namespace guard before any ledger write or provider I/O', async () => {
    guardError = new PerchError('user removed', 'user_inactive');
    expect(await code(service.send(p, request()))).toBe('user_inactive');
    expect(await code(service.sendStatus(p, { accountId: ACCOUNT, requestId: 'authz-request-0001' }))).toBe('user_inactive');
    expect(await code(service.read(p, { accountId: ACCOUNT, messageId: REPLY_TO }))).toBe('user_inactive');
    expect(calls).toEqual([]);
    expect((await ledger()).sends).toEqual([]);
  });

  it('denies reads, attachments, search, account lists and drafts to a revoked stale principal (no audit bypass)', async () => {
    await revokeAll();
    expect(await code(service.read(p, { accountId: ACCOUNT, messageId: REPLY_TO }))).toBe('grant_revoked');
    expect(await code(service.getAttachment(p, { accountId: ACCOUNT, messageId: REPLY_TO, attachmentId: '1' }))).toBe('grant_revoked');
    expect(await code(service.search(p, {}))).toBe('grant_revoked');
    expect(await code(service.listAccounts(p))).toBe('grant_revoked');
    expect(await code(service.createDraft(p, { accountId: ACCOUNT, to: ['rcpt@example.test'], subject: 'Hi', text: 'Body' }))).toBe('grant_revoked');
    expect(calls).toEqual([]);
  });
});

describe('a claimed send re-checks authorization after the reply lookup, right before submission [MOCK providers]', () => {
  const during = async (change: () => Promise<void>) => {
    replyHook = change;
    const out = await service.send(p, request({ requestId: 'authz-reply-0001', replyToMessageId: REPLY_TO, subject: undefined }));
    expect(calls).toEqual(['replyContext']);
    expect(out).toMatchObject({ status: 'rejected', requestState: 'rejected', replayed: false });
    const record = (await ledger()).sends[0]!;
    expect(record.state).toBe('rejected');
    return record;
  };

  it('does not submit when the grant is revoked during the reply lookup', async () => {
    expect((await during(revokeAll)).reason).toBe('not_submitted_authorization');
  });

  it('does not submit when the grant is narrowed (no read for the reply, or no send) during the reply lookup', async () => {
    expect((await during(() => setCaps(['send']))).reason).toBe('not_submitted_authorization');
  });

  it('does not submit when the send capability is removed during the reply lookup', async () => {
    expect((await during(() => setCaps(['read']))).reason).toBe('not_submitted_authorization');
  });

  it('does not submit when the user is deactivated (namespace guard) during the reply lookup', async () => {
    expect((await during(async () => void (guardError = new PerchError('user removed', 'user_inactive')))).reason).toBe('not_submitted_authorization');
  });

  it('does not submit when the provider send permission is withdrawn during the reply lookup', async () => {
    expect((await during(() => setAllowSend(false))).reason).toBe('not_submitted_provider_precheck');
  });

  it('does not submit when the sender account is replaced during the reply lookup', async () => {
    const record = await during(() => store.update((d) => void (d.imap[0]!.email = 'other@gmx.example.test')));
    expect(record.reason).toBe('not_submitted_account_changed');
  });

  it('never resubmits a key whose attempt was stopped by authorization, even after the grant is restored', async () => {
    const { principal } = await grant(['read', 'send']);
    p = principal;
    replyHook = () => setCaps(['send']);
    await service.send(p, request({ requestId: 'authz-reply-0002', replyToMessageId: REPLY_TO, subject: undefined }));
    replyHook = async () => {};
    await setCaps(['read', 'send']);
    const again = await service.send(p, request({ requestId: 'authz-reply-0002', replyToMessageId: REPLY_TO, subject: undefined }));
    expect(again).toMatchObject({ status: 'rejected', replayed: true });
    expect(sends()).toBe(0);
  });
});
