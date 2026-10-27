// MailService organize + send-draft paths end to end over the real adapters and the MOCK Gmail upstreams and
// MOCK ImapSession/SMTP (in-memory fakes): grants, provider permissions, the idempotent send workflow, body-free
// audit, and the MCP tool surface. No live provider is contacted.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant, principalForClientToken, READONLY_PRINCIPAL, type Principal } from '../src/auth/grants.js';
import { createPerchContext } from '../src/context.js';
import type { PerchError } from '../src/errors.js';
import { GmailProvider } from '../src/mail/gmail.js';
import { GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE } from '../src/mail/gmailAccounts.js';
import { ImapMailProvider, encodeImapMessageId } from '../src/mail/imap.js';
import { MailService, type MailProviders } from '../src/mail/service.js';
import type { SmtpSender } from '../src/mail/smtp.js';
import { ACCEPTED_NOTE, INDETERMINATE_NOTE, type SendResult } from '../src/mail/types.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { createMcpServer, TOOL_NAMES, WRITE_TOOL_NAMES } from '../src/mcp/server.js';
import { CredentialStore, initStore, type Capability, type StoreData } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGmail, mime } from './support/mockGmail.js';
import { MockImapSession, textMessage } from './support/mockImap.js';

let dirs: TempDirs;
let store: CredentialStore;
let gmail: MockGmail;
let imap: MockImapSession;
let imapSessions: number;
let smtpCalls: Array<{ raw: Buffer; envelope: { from: string; to: string[] } }>;
let smtpResult: SendResult;
let service: MailService;
let providers: MailProviders;

const GMAIL = 'gmail-0000000a';
const IMAP = 'imap-0000000c';
const now = new Date().toISOString();

const SECRET_CONTENT = ['Secret subject', 'friend@example.test', 'hidden@example.test'];
const DRAFT_MIME = (from: string) =>
  `From: ${from}\r\nTo: friend@example.test\r\nBcc: hidden@example.test\r\nSubject: Secret subject\r\n\r\nSecret body\r\n`;

async function seed() {
  await store.update((d: StoreData) => {
    d.gmail.push({
      id: GMAIL, label: 'Gmail', email: 'me@gmail.example.test', clientId: dummySecret('C'), clientSecret: dummySecret('S'),
      refreshToken: dummySecret('RT'), scopes: [GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE], createdAt: now, updatedAt: now,
    });
    d.imap.push({
      id: IMAP, label: 'GMX', email: 'me@gmx.example.test', username: 'me@gmx.example.test', password: dummySecret('PW'),
      imap: { host: 'imap.gmx.net', port: 993 }, smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
      allowDrafts: true, allowSend: true, allowModify: true, createdAt: now, updatedAt: now,
    });
  });
}

function build() {
  gmail = new MockGmail();
  const ga = gmail.addAccount('me@gmail.example.test', [
    { id: 'msg1', threadId: 't1', internalDate: 1767225600000, snippet: 'x', labelIds: ['INBOX'], payload: mime('text/plain', { headers: { Subject: 'Secret subject' }, content: 'Secret body' }) },
  ]);
  ga.drafts.push({ id: 'r-111', raw: Buffer.from(DRAFT_MIME('me@gmail.example.test')).toString('base64url') });
  ga.drafts.push({ id: 'r-222', raw: Buffer.from(DRAFT_MIME('me@gmail.example.test')).toString('base64url') });
  const gToken = gmail.issueAccessToken(ga);
  imap = new MockImapSession(
    new Map(
      Object.entries({
        INBOX: { uidValidity: '11', messages: [textMessage(1, { subject: 'Secret subject', text: 'Secret body' })] },
        Drafts: {
          uidValidity: '12',
          specialUse: '\\Drafts',
          messages: [
            { uid: 1, source: Buffer.from(DRAFT_MIME('me@gmx.example.test')) },
            { uid: 2, source: Buffer.from(DRAFT_MIME('me@gmx.example.test')) },
          ],
        },
        Sent: { uidValidity: '13', specialUse: '\\Sent', messages: [] },
        Trash: { uidValidity: '14', specialUse: '\\Trash', messages: [] },
        Archive: { uidValidity: '15', specialUse: '\\Archive', messages: [] },
      }),
    ),
  );
  imapSessions = 0;
  smtpCalls = [];
  smtpResult = { status: 'accepted', detail: ACCEPTED_NOTE };
  const smtp = {
    send: async (_a: unknown, raw: Buffer, envelope: { from: string; to: string[] }) => (smtpCalls.push({ raw, envelope }), smtpResult),
  } as unknown as SmtpSender;
  providers = {
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
    label: 'Organizer',
    capabilities,
    accountIds,
    tokenFile: `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token`,
  });
  return (await principalForClientToken(store, token))!;
}

const code = async (p: Promise<unknown>) => ((await rejection(p)) as PerchError).code;
const audit = async () => (await new MailWorkflowLedger(store).read()).audit;
const ledgerSends = async () => (await new MailWorkflowLedger(store).read()).sends;

interface Kind {
  name: 'gmail' | 'imap';
  accountId: string;
  messageId: string;
  folderId: string;
  drafts: [string, string];
  /** Provider I/O so far (upstream calls / IMAP sessions + SMTP submissions). */
  io: () => number;
  /** Provider-side effect of sent drafts. */
  sentCount: () => number;
  loseNextSend: () => void;
  dropPermission: (d: StoreData) => void;
}

const KINDS: Kind[] = [
  {
    name: 'gmail',
    accountId: GMAIL,
    messageId: 'msg1',
    folderId: 'SPAM',
    drafts: ['r-111', 'r-222'],
    io: () => gmail.gmailCalls().length,
    sentCount: () => gmail.accounts[0]!.sentDrafts.length,
    loseNextSend: () => {
      gmail.sendBehaviour = 'unreachable';
    },
    dropPermission: (d) => {
      d.gmail[0]!.scopes = [GMAIL_READONLY_SCOPE];
    },
  },
  {
    name: 'imap',
    accountId: IMAP,
    messageId: encodeImapMessageId('INBOX', '11', 1),
    folderId: 'Archive',
    drafts: [encodeImapMessageId('Drafts', '12', 1), encodeImapMessageId('Drafts', '12', 2)],
    io: () => imapSessions + smtpCalls.length,
    sentCount: () => smtpCalls.length,
    loseNextSend: () => {
      smtpResult = { status: 'indeterminate', detail: INDETERMINATE_NOTE };
    },
    dropPermission: (d) => {
      d.imap[0]!.allowModify = false;
      d.imap[0]!.allowSend = false;
    },
  },
];

describe.each(KINDS)('MailService organize [$name, MOCK provider]', (k) => {
  it('lists folders and drafts for read grants and the read-only operator', async () => {
    const p = await client(['read'], [k.accountId]);
    const folders = await service.listFolders(p, { accountId: k.accountId });
    expect(folders).toMatchObject({ accountId: k.accountId, provider: k.name });
    expect(folders.folders.some((f) => f.role === 'inbox')).toBe(true);
    const drafts = await service.listDrafts(READONLY_PRINCIPAL, { accountId: k.accountId });
    expect(drafts.drafts.map((d) => d.draftId)).toEqual(expect.arrayContaining([...k.drafts]));
    expect(drafts.hasMore).toBe(false);
  });

  it('marks, moves, archives, trashes and restores with a "modify" grant', async () => {
    const p = await client(['read', 'modify'], [k.accountId]);
    expect(await service.markMessage(p, { accountId: k.accountId, messageId: k.messageId, read: true, starred: true })).toMatchObject({ accountId: k.accountId });
    const moved = await service.moveMessage(p, { accountId: k.accountId, messageId: k.messageId, folderId: k.folderId });
    const archived = await service.moveMessage(p, { accountId: k.accountId, messageId: moved.messageId ?? k.messageId, ...(k.name === 'imap' ? { folderId: 'INBOX' } : { archive: true }) });
    const trashed = await service.trashMessage(p, { accountId: k.accountId, messageId: archived.messageId ?? k.messageId });
    const restored = await service.restoreMessage(p, { accountId: k.accountId, messageId: trashed.messageId ?? k.messageId });
    expect(restored).toMatchObject({ accountId: k.accountId, provider: k.name });
    expect(restored.messageId).toBeTruthy();
    const rows = (await audit()).filter((e) => e.type.startsWith('mail_') && e.type !== 'mail_list_accounts').map((e) => [e.type, e.outcome]);
    expect(rows).toEqual([
      ['mail_mark_message', 'attempt'],
      ['mail_mark_message', 'ok'],
      ['mail_move_message', 'attempt'],
      ['mail_move_message', 'ok'],
      ['mail_move_message', 'attempt'],
      ['mail_move_message', 'ok'],
      ['mail_trash_message', 'attempt'],
      ['mail_trash_message', 'ok'],
      ['mail_restore_message', 'attempt'],
      ['mail_restore_message', 'ok'],
    ]);
  });

  it('denies before any provider call: read-only operator, no modify grant, another account, no provider permission', async () => {
    const other = KINDS.find((x) => x !== k)!;
    const req = { accountId: k.accountId, messageId: k.messageId };
    const before = k.io();
    expect(await code(service.trashMessage(READONLY_PRINCIPAL, req))).toBe('capability_denied');
    expect(await code(service.trashMessage(await client(['read', 'draft', 'send'], [k.accountId]), req))).toBe('capability_denied');
    expect(await code(service.markMessage(await client(['modify'], [other.accountId]), { ...req, read: true }))).toBe('capability_denied');
    expect(await code(service.listFolders(await client(['modify'], [k.accountId]), { accountId: k.accountId }))).toBe('capability_denied');
    expect(await code(service.sendDraft(await client(['read', 'modify'], [k.accountId]), { accountId: k.accountId, draftId: k.drafts[0], requestId: 'req-denied-0001' }))).toBe(
      'capability_denied',
    );
    await store.update(k.dropPermission);
    const p = await client(['modify', 'send'], [k.accountId]);
    for (const call of [
      () => service.markMessage(p, { ...req, read: true }),
      () => service.moveMessage(p, { ...req, archive: true }),
      () => service.trashMessage(p, req),
      () => service.restoreMessage(p, req),
    ]) {
      const err = await rejection(call());
      expect(err).toMatchObject({ code: 'provider_scope_missing' });
      expect(err.message).toContain('--allow-modify');
    }
    expect(await code(service.sendDraft(p, { accountId: k.accountId, draftId: k.drafts[0], requestId: 'req-denied-0002' }))).toBe('provider_scope_missing');
    expect(k.io()).toBe(before);
    expect(await ledgerSends()).toEqual([]);
    const denied = (await audit()).filter((e) => e.outcome === 'denied').map((e) => e.type);
    expect(denied).toEqual(expect.arrayContaining(['mail_trash_message', 'mail_mark_message', 'mail_list_folders', 'mail_send_draft']));
  });

  it('sends a draft once per requestId: replay, payload conflict, indeterminate on a lost response', async () => {
    const p = await client(['send'], [k.accountId]);
    const first = await service.sendDraft(p, { accountId: k.accountId, draftId: k.drafts[0], requestId: 'draft-send-0001' });
    expect(first).toMatchObject({ status: 'accepted', requestState: 'accepted', replayed: false, accountId: k.accountId, provider: k.name });
    expect(first.detail.startsWith(ACCEPTED_NOTE)).toBe(true);
    expect(k.sentCount()).toBe(1);
    const io = k.io();
    const replay = await service.sendDraft(p, { accountId: k.accountId, draftId: k.drafts[0], requestId: 'draft-send-0001' });
    expect(replay).toMatchObject({ status: 'accepted', replayed: true, operationId: first.operationId });
    expect(await code(service.sendDraft(p, { accountId: k.accountId, draftId: k.drafts[1], requestId: 'draft-send-0001' }))).toBe('idempotency_conflict');
    // A mail_send under the same key is a different payload, too.
    expect(await code(service.send(p, { accountId: k.accountId, to: ['friend@example.test'], subject: 'x', text: 'y', requestId: 'draft-send-0001' }))).toBe('idempotency_conflict');
    expect(k.io()).toBe(io);
    k.loseNextSend();
    const lost = await service.sendDraft(p, { accountId: k.accountId, draftId: k.drafts[1], requestId: 'draft-send-0002' });
    expect(lost).toMatchObject({ status: 'indeterminate', requestState: 'indeterminate', replayed: false });
    const again = await service.sendDraft(p, { accountId: k.accountId, draftId: k.drafts[1], requestId: 'draft-send-0002' });
    expect(again).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(await service.sendStatus(p, { accountId: k.accountId, requestId: 'draft-send-0002' })).toMatchObject({ requestState: 'indeterminate' });
    expect((await ledgerSends()).map((s) => s.state)).toEqual(['accepted', 'indeterminate']);
  });

  it('audits organize and send-draft calls without ids, folders, subjects or addresses', async () => {
    const p = await client(['read', 'modify', 'send'], [k.accountId]);
    await service.listFolders(p, { accountId: k.accountId });
    await service.listDrafts(p, { accountId: k.accountId });
    await service.markMessage(p, { accountId: k.accountId, messageId: k.messageId, read: true });
    await service.sendDraft(p, { accountId: k.accountId, draftId: k.drafts[0], requestId: 'audit-draft-0001' });
    const ledger = JSON.stringify(await new MailWorkflowLedger(store).read());
    for (const s of [k.messageId, k.drafts[0], k.folderId, 'audit-draft-0001', ...SECRET_CONTENT]) expect(ledger).not.toContain(s);
    const types = (await audit()).map((e) => e.type);
    expect(types).toEqual(['mail_list_folders', 'mail_list_drafts', 'mail_mark_message', 'mail_mark_message', 'mail_send', 'mail_send']);
  });
});

describe('IMAP send-draft keeps Bcc off the wire [MOCK ImapSession/SMTP]', () => {
  it('submits without the Bcc header but with the Bcc recipient in the envelope, then files the draft in Sent', async () => {
    const p = await client(['send'], [IMAP]);
    await service.sendDraft(p, { accountId: IMAP, draftId: encodeImapMessageId('Drafts', '12', 1), requestId: 'imap-bcc-0001' });
    expect(smtpCalls[0]!.envelope.to).toEqual(['friend@example.test', 'hidden@example.test']);
    expect(smtpCalls[0]!.raw.toString()).not.toMatch(/bcc|hidden/i);
    expect(imap.mailboxes.get('Sent')!.messages).toHaveLength(1);
    expect(imap.mailboxes.get('Drafts')!.messages.map((m) => m.uid)).toEqual([2]);
  });
});

describe('mail organize MCP tools [MOCK providers]', () => {
  const memory = async (principal: Principal) => {
    const mcp = createMcpServer({ ...createPerchContext(store, gmail.transport), mail: service }, principal);
    const [a, b] = InMemoryTransport.createLinkedPair();
    await mcp.connect(b);
    const c = new Client({ name: 'mem', version: '0' });
    await c.connect(a);
    return c;
  };

  it('offers read tools to the operator and organize/send-draft tools only to matching grants', async () => {
    expect(TOOL_NAMES).toEqual(expect.arrayContaining(['mail_list_folders', 'mail_list_drafts']));
    expect(WRITE_TOOL_NAMES).toEqual(expect.arrayContaining(['mail_mark_message', 'mail_move_message', 'mail_trash_message', 'mail_restore_message', 'mail_send_draft']));
    const names = async (p: Principal) => (await (await memory(p)).listTools()).tools.map((t) => t.name);
    const op = await names(READONLY_PRINCIPAL);
    expect(op).toEqual(expect.arrayContaining(['mail_list_folders', 'mail_list_drafts']));
    expect(op).not.toContain('mail_trash_message');
    expect(op).not.toContain('mail_send_draft');
    const modify = await names(await client(['modify'], [IMAP]));
    expect(modify.filter((n) => n.startsWith('mail_')).sort()).toEqual(['mail_mark_message', 'mail_move_message', 'mail_restore_message', 'mail_trash_message']);
    const tools = (await (await memory(await client(['modify', 'send'], [IMAP]))).listTools()).tools;
    expect(tools.find((t) => t.name === 'mail_trash_message')!.annotations).toMatchObject({ destructiveHint: true });
    expect(tools.find((t) => t.name === 'mail_send_draft')!.annotations).toMatchObject({ destructiveHint: true });
    expect(tools.find((t) => t.name === 'mail_send_draft')!.inputSchema.required).toEqual(expect.arrayContaining(['requestId', 'draftId', 'accountId']));
  });

  it('runs a trash through MCP with exactly one body-free attempt/ok pair (no double audit by the runner)', async () => {
    const c = await memory(await client(['modify'], [IMAP]));
    const r = await c.callTool({ name: 'mail_trash_message', arguments: { accountId: IMAP, messageId: encodeImapMessageId('INBOX', '11', 1) } });
    expect(r.isError).not.toBe(true);
    expect(JSON.parse((r.content as Array<{ text: string }>)[0]!.text)).toMatchObject({ provider: 'imap', folderId: 'Trash' });
    expect((await audit()).map((e) => [e.type, e.outcome])).toEqual([
      ['mail_trash_message', 'attempt'],
      ['mail_trash_message', 'ok'],
    ]);
  });
});
