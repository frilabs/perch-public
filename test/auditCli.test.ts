// Local admin CLI for the audit trail and the mail workflow ledger (`perch audit list`,
// `perch mail-workflow list|resolve|prune|init`), per namespace. Sends use a MOCK provider; nothing is sent.
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, type Principal } from '../src/auth/grants.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { MailService, type MailProviders } from '../src/mail/service.js';
import type { MailProvider, SendResult } from '../src/mail/types.js';
import { pruneSends } from '../src/mail/workflow.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
let out: string[];
let err: string[];
let sendCount: number;
let sendImpl: () => Promise<SendResult>;

const MARK = { text: 'BODY-MARKER-cli', subject: 'SUBJECT-MARKER-cli', to: 'rcpt-marker-cli@example.test', requestId: 'REQ-MARKER-cli-1' };

function io(env: Record<string, string> = {}): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root, ...env },
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    readSecret: async () => dummySecret('APP-PASSWORD'),
    imapVerify: async () => {},
    transport: async () => {
      throw new Error('MOCK: no upstream expected');
    },
  };
}

async function cli(args: string[], env: Record<string, string> = {}) {
  out = [];
  err = [];
  const code = await runCli(args, io(env));
  return { code, out: out.join(''), err: err.join('') };
}

const rootStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });

function service(store: CredentialStore) {
  const p: MailProvider<unknown> = {
    kind: 'imap',
    providerCapabilities: () => ({ draft: true, send: true }),
    search: async () => ({ items: [] }),
    read: async () => ({ messageId: 'x', truncated: false, attachments: [] }),
    getAttachment: async () => ({ attachmentId: '1', contentType: 'text/plain', size: 0, contentBase64: '' }),
    replyContext: async () => ({ references: [] }),
    createDraft: async () => ({ draftId: 'd' }),
    send: async () => {
      sendCount++;
      return sendImpl();
    },
  };
  return new MailService(store, { gmail: p, microsoft: p, imap: p } as unknown as MailProviders);
}

let principal: Principal;
let clientId: string;
const req = (requestId: string) => ({ accountId: 'imap-0000000a', requestId, to: [MARK.to], subject: MARK.subject, text: MARK.text });

beforeEach(async () => {
  dirs = await makeTempDirs();
  const init = await cli(['init']);
  expect(init.code, init.err).toBe(0);
  expect(init.out).toMatch(/Created mail workflow ledger/);
  sendCount = 0;
  sendImpl = async () => ({ status: 'accepted', detail: 'MOCK' });
  const add = await cli(['imap', 'add', '--label', 'LABEL-MARKER', '--email', 'owner@gmx.at', '--allow-send']);
  expect(add.code, add.err).toBe(0);
  const store = await rootStore();
  const accountId = (await store.read()).imap[0]!.id;
  await store.update((d) => void (d.imap[0]!.id = 'imap-0000000a'));
  expect(accountId).toMatch(/^imap-/);
  const tokenFile = path.join(dirs.root, 'config', 'clients', 'cli.token');
  const { client, token } = await createClientGrant(store, { label: 'CLI client', capabilities: ['send'], accountIds: ['imap-0000000a'], tokenFile });
  clientId = client.id;
  principal = (await principalForClientToken(store, token))!;
});
afterEach(async () => {
  await dirs.cleanup();
});

/** One accepted send and one send left pending by a "crashed" attempt. */
async function seedSends() {
  const store = await rootStore();
  await service(store).send(principal, req('accepted-key-01'));
  sendImpl = () => new Promise(() => {});
  void service(store).send(principal, req(MARK.requestId));
  const ledger = new MailWorkflowLedger(store);
  // The pending record is persisted BEFORE the provider call, so also wait for the (hanging) attempt itself.
  for (let i = 0; i < 200 && (sendCount < 2 || !(await ledger.read()).sends.some((s) => s.state === 'pending')); i++) await new Promise((r) => setTimeout(r, 10));
  const sends = (await ledger.read()).sends;
  return { accepted: sends.find((s) => s.state === 'accepted')!.operationId, pending: sends.find((s) => s.state === 'pending')!.operationId };
}

const noMarkers = (s: string) => {
  for (const m of [...Object.values(MARK), 'LABEL-MARKER', 'owner@gmx.at', 'CLI client', 'DUMMY-TEST']) expect(s, m).not.toContain(m);
};

describe('perch audit / perch mail-workflow (local admin, per namespace)', () => {
  it('lists audit events with safe fields only, filtered by client, account and limit', async () => {
    await seedSends();
    const r = await cli(['audit', 'list']);
    expect(r.code, r.err).toBe(0);
    expect(r.out).toMatch(/namespace root/);
    expect(r.out).toMatch(new RegExp(`mail_send\\s+pending\\s+client ${clientId}\\s+imap-0000000a \\(imap\\)`));
    expect(r.out).toMatch(/mail_send\s+accepted\s+.*provider_accepted/);
    noMarkers(r.out + r.err);
    const byClient = await cli(['audit', 'list', '--client', clientId, '--limit', '1']);
    expect(byClient.out.trim().split('\n').filter((l) => l.startsWith('  '))).toHaveLength(1);
    expect((await cli(['audit', 'list', '--client', 'client-ffffffff'])).out).toMatch(/\(none\)/);
    expect((await cli(['audit', 'list', '--account', 'imap-0000000a'])).out).toMatch(/mail_send/);
    for (const bad of [['--limit', '0'], ['--limit', 'x'], ['--client', 'evil\nline'], ['--account', 'a b']]) {
      expect((await cli(['audit', 'list', ...bad])).code, bad.join(' ')).toBe(2);
    }
  });

  it('lists send records (accepted is not delivered; pending is unknown and never resent)', async () => {
    const { accepted, pending } = await seedSends();
    const r = await cli(['mail-workflow', 'list']);
    expect(r.code, r.err).toBe(0);
    expect(r.out).toMatch(/not proof of delivery/);
    expect(r.out).toContain(`${accepted}  accepted`);
    expect(r.out).toContain(`${pending}  pending`);
    noMarkers(r.out + r.err);
    const onlyPending = await cli(['mail-workflow', 'list', '--state', 'pending']);
    expect(onlyPending.out).toContain(pending);
    expect(onlyPending.out).not.toContain(accepted);
    expect((await cli(['mail-workflow', 'list', '--state', 'sent'])).code).toBe(2);
  });

  it('records a human-verified outcome for a pending send without ever sending or freeing the key', async () => {
    const { accepted, pending } = await seedSends();
    expect(sendCount).toBe(2);
    expect((await cli(['mail-workflow', 'resolve', pending, '--outcome', 'maybe'])).code).toBe(2);
    expect((await cli(['mail-workflow', 'resolve', pending])).code).toBe(2);
    const r = await cli(['mail-workflow', 'resolve', pending, '--outcome', 'not-sent']);
    expect(r.code, r.err).toBe(0);
    expect(r.out).toMatch(/not sent/);
    expect(r.out).toMatch(/new requestId/);
    const again = await cli(['mail-workflow', 'resolve', pending, '--outcome', 'sent']);
    expect(again.code).toBe(1);
    expect(again.err).toMatch(/already resolved/);
    const done = await cli(['mail-workflow', 'resolve', accepted, '--outcome', 'not-sent']);
    expect(done.code).toBe(1);
    expect((await cli(['mail-workflow', 'resolve', 'op-000000000000000000000000', '--outcome', 'sent'])).code).toBe(1);
    // The client still gets "unknown" plus the admin's note, and nothing is sent again.
    sendImpl = async () => ({ status: 'accepted', detail: 'MOCK' });
    const replay = await service(await rootStore()).send(principal, req(MARK.requestId));
    expect(replay).toMatchObject({ status: 'indeterminate', replayed: true, requestState: 'pending', manualResolution: 'not_sent' });
    expect(sendCount).toBe(2);
    const events = (await new MailWorkflowLedger(await rootStore()).read()).audit.filter((e) => e.type === 'workflow_resolve');
    expect(events.map((e) => [e.actor.kind, e.outcome, e.code])).toEqual([['local_admin', 'resolved', 'not_sent']]);
  });

  it('never forgets a used requestId: prune is refused and an accepted key still replays without a resend', async () => {
    const { accepted, pending } = await seedSends();
    const before = (await new MailWorkflowLedger(await rootStore()).read()).sends;
    const future = new Date(Date.now() + 86_400_000).toISOString();
    for (const args of [['mail-workflow', 'prune', '--before', future], ['mail-workflow', 'prune', '--before', '2099-01-01'], ['mail-workflow', 'prune']]) {
      const r = await cli(args);
      expect(r.code, args.join(' ')).toBe(1);
      expect(r.err).toMatch(/never forgotten/);
    }
    expect(await rejection(pruneSends(new MailWorkflowLedger(await rootStore()), new Date('2099-01-01')))).toMatchObject({ code: 'prune_unsupported' });
    const after = (await new MailWorkflowLedger(await rootStore()).read()).sends;
    expect(after).toEqual(before);
    expect(after.map((s) => s.operationId)).toEqual(expect.arrayContaining([accepted, pending]));
    // A resolved record is not freed either.
    await cli(['mail-workflow', 'resolve', pending, '--outcome', 'sent']);
    expect((await cli(['mail-workflow', 'prune', '--before', future])).code).toBe(1);
    const count = sendCount;
    const replay = await service(await rootStore()).send(principal, req('accepted-key-01'));
    expect(replay).toMatchObject({ status: 'accepted', requestState: 'accepted', replayed: true });
    expect(sendCount).toBe(count);
  });

  it('initialises a missing ledger only on explicit request and never overwrites one', async () => {
    const exists = await cli(['mail-workflow', 'init']);
    expect(exists.code).toBe(1);
    expect(exists.err).toMatch(/already exists/);
    await rm(path.join(dirs.dataDir, 'mail-workflow.enc'));
    const missing = await cli(['audit', 'list']);
    expect(missing.code).toBe(1);
    expect(missing.err).toMatch(/missing/);
    // `perch init` on an existing store does not silently recreate it.
    expect((await cli(['init'])).out).toMatch(/mail workflow ledger is missing/i);
    expect((await cli(['audit', 'list'])).code).toBe(1);
    // This namespace had a ledger: explicit init refuses to reset it (restore from backup instead).
    const refused = await cli(['mail-workflow', 'init']);
    expect(refused.code).toBe(1);
    expect(refused.err).toMatch(/restore/i);
    expect((await cli(['audit', 'list'])).code).toBe(1);
    // Only a store from before the ledger existed (no initialised marker) gets one, exactly once.
    await (await rootStore()).update((d) => void delete d.mailWorkflowLedger);
    const created = await cli(['mail-workflow', 'init']);
    expect(created.code, created.err).toBe(0);
    expect((await cli(['audit', 'list'])).out).toMatch(/\(none\)/);
    await rm(path.join(dirs.dataDir, 'mail-workflow.enc'));
    expect((await cli(['mail-workflow', 'init'])).code).toBe(1);
  });

});
