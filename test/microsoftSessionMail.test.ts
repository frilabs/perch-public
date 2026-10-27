import { describe, expect, it } from 'vitest';
import { composeForProvider, validateOutgoing } from '../src/mail/compose.js';
import { MicrosoftSessionMailProvider } from '../src/microsoft/session/mailProvider.js';
import type { SessionMailAccount } from '../src/microsoft/session/model.js';
import type { OutgoingMime } from '../src/mail/types.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { MailService, type MailProviders } from '../src/mail/service.js';
import { createDeviceGrant, principalFromGrant, READONLY_PRINCIPAL } from '../src/auth/grants.js';
import { MicrosoftSessionGroupSchema } from '../src/microsoft/session/model.js';
import { makeTempDirs } from './support/fixtures.js';
import { PerchError } from '../src/errors.js';

const account: SessionMailAccount = {
  id: 'msmail-11111111', groupId: 'mgroup-11111111', label: 'Microsoft', email: 'self@example.test', createdAt: '2026-10-26T00:00:00Z', updatedAt: '2026-10-26T00:00:00Z',
  identity: { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', kind: 'organization' }, revision: '12345678', allowDrafts: true, allowSend: true, allowModify: true,
  caller: { kind: 'client', clientId: 'client-11111111', tokenSha256: 'a'.repeat(64) },
};
const valid = () => validateOutgoing({ to: ['Friend <friend@example.test>'], cc: ['cc@example.test'], bcc: ['private@example.test'], subject: 'Hello', text: 'Plain', html: '<p>HTML</p>', attachments: [{ filename: 'file.txt', contentBase64: 'aGk=' }] }, account.email);
function setup(responses: unknown[] = []) {
  const calls: { accountId: string; operation: string; args: any; options: any }[] = [];
  const provider = new MicrosoftSessionMailProvider(async (accountId, operation, args, options) => { calls.push({ accountId, operation, args, options }); return responses.shift(); });
  return { calls, provider };
}

describe('Microsoft session mail provider', () => {
  it('retains validated structured content alongside MIME without reparsing headers', async () => {
    const composed = await composeForProvider(valid(), 'api', 'thread', 'source');
    expect(composed).toMatchObject({ sourceMessageId: 'source', structured: { subject: 'Hello', text: 'Plain', html: '<p>HTML</p>', to: ['friend@example.test'], cc: ['cc@example.test'], bcc: ['private@example.test'], attachments: [{ filename: 'file.txt', contentType: 'application/octet-stream', contentBase64: 'aGk=' }] } });
    expect(composed.raw.toString()).toContain('Bcc: private@example.test');
  });
  it('dispatches draft and send using structured fields and source message id only', async () => {
    const f = setup([{ draftId: 'draft' }, { status: 'accepted', detail: 'accepted' }]);
    const composed = await composeForProvider(valid(), 'api', undefined, 'original');
    expect(await f.provider.createDraft(account, composed)).toEqual({ draftId: 'draft' });
    await f.provider.send(account, composed);
    expect(f.calls.map((c) => c.operation)).toEqual(['mail.createDraft', 'mail.send']);
    expect(f.calls[0]).toMatchObject({ accountId: account.id, args: { sourceMessageId: 'original', to: ['friend@example.test'], bcc: ['private@example.test'] } });
    expect(f.calls[0]!.args).not.toHaveProperty('raw');
    expect(f.calls[0]!.args).not.toHaveProperty('from');
    expect(f.calls[0]!.options).toEqual({ caller: account.caller, expectedRevision: account.revision });
    const rawOnly: OutgoingMime = { raw: Buffer.from('To: injected@example.test'), envelope: { from: account.email, to: ['injected@example.test'] } };
    await expect(f.provider.send(account, rawOnly)).rejects.toThrow(/structured/i);
    expect(f.calls).toHaveLength(2);
  });
  it('refuses writes without trusted caller context before dispatch', async () => {
    const f = setup();
    await expect(f.provider.send({ ...account, caller: undefined }, await composeForProvider(valid(), 'api'))).rejects.toThrow(/caller|principal|grant/i);
    expect(f.calls).toHaveLength(0);
  });
  it('maps all mail operations to fixed dispatcher operations and keeps normalized values', async () => {
    const summary = { messageId: 'm', subject: 'Original', date: '2026-10-26T00:00:00Z', to: ['to@example.test'] };
    const f = setup([{ items: [summary], next: 'cursor' }, { ...summary, internetMessageId: '<m@example.test>', references: ['<root@example.test>'], truncated: false, attachments: [] }, { attachmentId: 'a', contentType: 'text/plain', size: 2, contentBase64: 'aGk=' }, { items: [summary] }, { messageId: 'm' }, { messageId: 'new' }, { messageId: 'trash' }, { messageId: 'restore' }, { status: 'accepted', detail: 'accepted' }]);
    expect(await f.provider.search(account, { query: 'hello', pageSize: 5 }, 'cursor')).toEqual({ items: [summary], next: 'cursor' });
    expect(await f.provider.replyContext(account, 'm')).toMatchObject({ internetMessageId: '<m@example.test>', subject: 'Original', references: ['<root@example.test>'] });
    await f.provider.getAttachment(account, 'm', 'a', { maxBytes: 50 });
    expect(await f.provider.listDrafts(account, { pageSize: 5 }, undefined)).toMatchObject({ items: [{ draftId: 'm', messageId: 'm', subject: 'Original' }] });
    await f.provider.markMessage(account, 'm', { read: false, starred: true });
    await f.provider.moveMessage(account, 'm', { archive: true });
    await f.provider.trashMessage(account, 'new');
    await f.provider.restoreMessage(account, 'trash');
    await f.provider.sendDraft(account, 'draft');
    expect(f.calls.map((c) => c.operation)).toEqual(['mail.search', 'mail.read', 'mail.attachment', 'mail.search', 'mail.mark', 'mail.move', 'mail.trash', 'mail.restore', 'mail.sendDraft']);
    expect(f.calls[3]!.args).toEqual({ folder: 'drafts', pageSize: 5 });
  });
  it('checks write opt-ins and refuses all writes before dispatch when absent', async () => {
    const f = setup(); const readOnly = { ...account, allowDrafts: false, allowSend: false, allowModify: false };
    expect(f.provider.providerCapabilities(readOnly)).toEqual({ draft: false, send: false, modify: false });
    expect(f.provider.canSendDraft(readOnly)).toBe(false);
    const composed = await composeForProvider(valid(), 'api');
    for (const action of [() => f.provider.createDraft(readOnly, composed), () => f.provider.send(readOnly, composed), () => f.provider.sendDraft(readOnly, 'd'), () => f.provider.markMessage(readOnly, 'm', { read: true }), () => f.provider.moveMessage(readOnly, 'm', { archive: true }), () => f.provider.trashMessage(readOnly, 'm'), () => f.provider.restoreMessage(readOnly, 'm')]) await expect(action()).rejects.toThrow(/enabled|permission|allow/i);
    expect(f.calls).toHaveLength(0);
  });
  it('follows bounded folder pagination and children without dropping hierarchy', async () => {
    const f = setup([{ items: [{ folderId: 'root', name: 'Parent', role: 'other', childFolderCount: 1 }], next: 'next' }, { items: [{ folderId: 'second', name: 'Second', role: 'other' }] }, { items: [{ folderId: 'child', name: 'Child', role: 'other' }] }]);
    expect((await f.provider.listFolders(account)).map((x) => x.folderId)).toEqual(['root', 'second', 'child']);
    expect(f.calls[1]!.args).toMatchObject({ cursor: 'next' });
    expect(f.calls[2]!.args).toMatchObject({ parentId: 'root' });
  });
});

async function serviceFixture(action: (f: { store: CredentialStore; service: MailService; calls: { operation: string; args: any; options: any }[]; mutateOnRead: (fn: () => Promise<void>) => void; failSend: (error: Error) => void }) => Promise<void>) {
  const dirs = await makeTempDirs();
  try {
    await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    const group = MicrosoftSessionGroupSchema.parse({ id: account.groupId, email: account.email, label: account.label, profileId: 'ms-session-0123456789abcdef01234567', identity: account.identity, members: { mail: account.id, teams: 'msteams-11111111', calendar: 'mscalendar-11111111', files: 'msfiles-11111111' }, services: Object.fromEntries(['mail', 'teams', 'calendar', 'files'].map((key) => [key, { enabled: key === 'mail', write: true, invite: false, status: 'ready' }])), sites: [], createdAt: account.createdAt, updatedAt: account.updatedAt, revision: account.revision });
    await store.update((d) => { (d.microsoftSessions ??= []).push(group); });
    const calls: { operation: string; args: any; options: any }[] = [];
    let onRead: (() => Promise<void>) | undefined;
    let sendError: Error | undefined;
    const provider = new MicrosoftSessionMailProvider(async (_accountId, operation, args, options) => {
      calls.push({ operation, args, options });
      if (operation === 'mail.read') {
        await onRead?.();
        return { messageId: 'original', from: 'sender@example.test', to: [account.email], subject: 'Original', text: 'Original body', internetMessageId: '<original@example.test>', references: [], attachments: [], truncated: false };
      }
      if (operation === 'mail.createDraft') return { draftId: 'draft' };
      if (operation === 'mail.send') { if (sendError) throw sendError; return { status: 'accepted', detail: 'accepted' }; }
      return { items: [] };
    });
    const providers = { microsoftSession: provider } as unknown as MailProviders;
    const service = new MailService(store, providers);
    await action({ store, service, calls, mutateOnRead: (fn) => { onRead = fn; }, failSend: (error) => { sendError = error; } });
  } finally { await dirs.cleanup(); }
}

describe('MailService session integration', () => {
  it('lists session mail accounts and denies writes by the readonly principal', async () => serviceFixture(async ({ service, calls }) => {
    expect(await service.listAccounts(READONLY_PRINCIPAL)).toEqual([expect.objectContaining({ accountId: account.id, provider: 'microsoftSession', providerCapabilities: expect.objectContaining({ draft: true, send: true, modify: true }) })]);
    await expect(service.createDraft(READONLY_PRINCIPAL, { accountId: account.id, to: ['friend@example.test'], subject: 'X', text: 'Y' })).rejects.toThrow(/read.only/i);
    expect(calls).toHaveLength(0);
  }));
  it('carries source ids for direct and derived replies but not forwards', async () => serviceFixture(async ({ store, service, calls }) => {
    const principal = principalFromGrant(await createDeviceGrant(store, { label: 'Mail', capabilities: ['read', 'draft', 'send'], accountIds: [account.id] }));
    await service.createDraft(principal, { accountId: account.id, replyToMessageId: 'original', to: ['sender@example.test'], text: 'Reply' });
    await service.reply(principal, { accountId: account.id, messageId: 'original', text: 'Reply' });
    await service.forward(principal, { accountId: account.id, messageId: 'original', text: 'Forward', to: ['friend@example.test'] });
    const drafts = calls.filter((c) => c.operation === 'mail.createDraft');
    expect(drafts.map((c) => c.args.sourceMessageId)).toEqual(['original', 'original', undefined]);
    expect(drafts[1]!.args.text).toContain('Original body');
    expect(calls.every((call) => call.options.caller.clientId === principal.clientId && call.options.caller.tokenSha256 === principal.tokenSha256)).toBe(true);
    expect(JSON.stringify((await store.read()).microsoftSessions)).not.toContain('caller');
  }));
  it('detects identity and revision changes after reply reads before a write', async () => serviceFixture(async ({ store, service, calls, mutateOnRead }) => {
    const principal = principalFromGrant(await createDeviceGrant(store, { label: 'Mail', capabilities: ['read', 'draft', 'send'], accountIds: [account.id] }));
    mutateOnRead(async () => { await store.update((d) => { d.microsoftSessions![0]!.revision = 'abcdef12'; }); });
    await expect(service.createDraft(principal, { accountId: account.id, replyToMessageId: 'original', to: ['sender@example.test'], text: 'Reply' })).rejects.toThrow(/account|changed/i);
    expect(calls.map((c) => c.operation)).toEqual(['mail.read']);
  }));
  it('sends once through the shared ledger and replays without dispatch', async () => serviceFixture(async ({ store, service, calls }) => {
    const principal = principalFromGrant(await createDeviceGrant(store, { label: 'Mail', capabilities: ['read', 'send'], accountIds: [account.id] }));
    const request = { accountId: account.id, to: ['friend@example.test'], subject: 'Hello', text: 'Body', requestId: 'session-mail-send-0001' };
    expect(await service.send(principal, request)).toMatchObject({ status: 'accepted', provider: 'microsoftSession', replayed: false });
    expect(await service.send(principal, request)).toMatchObject({ status: 'accepted', replayed: true });
    expect(calls.map((c) => c.operation)).toEqual(['mail.send']);
    expect(calls[0]!.options).toEqual({ caller: { kind: principal.kind, clientId: principal.clientId, tokenSha256: principal.tokenSha256 }, expectedRevision: account.revision });
  }));
  it('attaches the readonly caller to fan-out reads', async () => serviceFixture(async ({ service, calls }) => {
    await service.search(READONLY_PRINCIPAL, {});
    expect(calls[0]!.options).toEqual({ caller: { kind: 'operator_readonly' }, expectedRevision: account.revision });
  }));
  it.each(['partial_write', 'browser_request_failed', 'browser_timeout', 'unexpected_worker_error'])('records %s after session dispatch as indeterminate and never retries', async (code) => serviceFixture(async ({ store, service, calls, failSend }) => {
    const principal = principalFromGrant(await createDeviceGrant(store, { label: 'Mail', capabilities: ['send'], accountIds: [account.id] }));
    failSend(new PerchError('Reply draft created-draft may exist.', code));
    const request = { accountId: account.id, to: ['friend@example.test'], subject: 'Hello', text: 'Body', requestId: 'session-mail-unknown-0001' };
    expect(await service.send(principal, request)).toMatchObject({ status: 'indeterminate', replayed: false });
    expect(await service.send(principal, request)).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(calls).toHaveLength(1);
  }));
});
