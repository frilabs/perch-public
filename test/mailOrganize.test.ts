// Organizing mail and sending existing drafts: the upstream allowlist and the Gmail and IMAP adapters against the MOCK
// Gmail upstreams and the MOCK ImapSession (in-memory fakes). No live provider is contacted; passing tests
// here are NOT evidence of a live integration.
import { describe, expect, it } from 'vitest';
import { prepareDraftForSmtp } from '../src/mail/draftMime.js';
import { GmailProvider } from '../src/mail/gmail.js';
import { GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE, gmailScopesFor } from '../src/mail/gmailAccounts.js';
import { ImapMailProvider, ImapflowSession, encodeImapMessageId } from '../src/mail/imap.js';
import type { SmtpSender } from '../src/mail/smtp.js';
import { ACCEPTED_NOTE, INDETERMINATE_NOTE, type SendResult } from '../src/mail/types.js';
import type { GmailAccount, ImapAccount } from '../src/store/credentialStore.js';
import { isAllowedRoute, Upstream, type RouteCapability } from '../src/upstream.js';
import { dummySecret, rejection } from './support/fixtures.js';
import { MockGmail, mime } from './support/mockGmail.js';
import { MockImapSession, textMessage, type MockMailbox } from './support/mockImap.js';

const ALL_CAPS: RouteCapability[] = ['read', 'draft', 'send', 'calendar_write', 'slack_send', 'whatsapp_send', 'admin', 'notify', 'drive_write', 'notion_write', 'mail_modify'];
const now = '2026-10-20T00:00:00.000Z';

describe('mail organize routes in the upstream allowlist [MOCK transport]', () => {
  it('reaches modify routes only with the mail_modify tag and draft sends only with send', () => {
    const gm = '/gmail/v1/users/me';
    for (const op of ['modify', 'trash', 'untrash']) {
      expect(isAllowedRoute('gmail', 'POST', `${gm}/messages/abc/${op}`, 'mail_modify')).toBe(true);
      expect(isAllowedRoute('gmail', 'POST', `${gm}/messages/abc/${op}`)).toBe(false);
      expect(isAllowedRoute('gmail', 'POST', `${gm}/messages/abc/${op}`, 'send')).toBe(false);
    }
    expect(isAllowedRoute('gmail', 'POST', `${gm}/drafts/send`, 'send')).toBe(true);
    expect(isAllowedRoute('gmail', 'POST', `${gm}/drafts/send`, 'draft')).toBe(false);
    expect(isAllowedRoute('gmail', 'GET', `${gm}/labels`)).toBe(true);
    expect(isAllowedRoute('gmail', 'GET', `${gm}/drafts`)).toBe(true);
    expect(isAllowedRoute('gmail', 'GET', `${gm}/drafts/r123`)).toBe(true);
    expect(isAllowedRoute('graph', 'PATCH', '/v1.0/me/messages/AAMk%2F1', 'mail_modify')).toBe(false);
    expect(isAllowedRoute('graph', 'POST', '/v1.0/me/messages/AAMk1/move', 'mail_modify')).toBe(false);
    expect(isAllowedRoute('graph', 'POST', '/v1.0/me/messages/AAMk1/move')).toBe(false);
    expect(isAllowedRoute('graph', 'POST', '/v1.0/me/messages/AAMk1/send', 'send')).toBe(false);
    expect(isAllowedRoute('graph', 'POST', '/v1.0/me/messages/AAMk1/send', 'mail_modify')).toBe(false);
    expect(isAllowedRoute('graph', 'GET', '/v1.0/me/mailFolders')).toBe(false);
  });

  it('never reaches permanent deletion, emptying the trash, filters or forwarding rules, under any tag', async () => {
    const gm = '/gmail/v1/users/me';
    const blocked: Array<['gmail' | 'graph', 'GET' | 'POST' | 'PATCH' | 'DELETE', string]> = [
      ['gmail', 'DELETE', `${gm}/messages/abc`],
      ['gmail', 'DELETE', `${gm}/drafts/r123`],
      ['gmail', 'DELETE', `${gm}/threads/abc`],
      ['gmail', 'DELETE', `${gm}/labels/Label_1`],
      ['gmail', 'POST', `${gm}/messages/batchDelete`],
      ['gmail', 'POST', `${gm}/messages/batchModify`],
      ['gmail', 'POST', `${gm}/messages/abc/delete`],
      ['gmail', 'POST', `${gm}/threads/abc/trash`],
      ['gmail', 'POST', `${gm}/labels`],
      ['gmail', 'POST', `${gm}/settings/filters`],
      ['gmail', 'POST', `${gm}/settings/forwardingAddresses`],
      ['gmail', 'PATCH', `${gm}/settings/autoForwarding`],
      ['gmail', 'POST', `${gm}/messages/import`],
      ['gmail', 'POST', `${gm}/messages`],
      ['graph', 'DELETE', '/v1.0/me/messages/AAMk1'],
      ['graph', 'POST', '/v1.0/me/messages/AAMk1/permanentDelete'],
      ['graph', 'DELETE', '/v1.0/me/mailFolders/deleteditems'],
      ['graph', 'POST', '/v1.0/me/mailFolders/deleteditems/permanentDelete'],
      ['graph', 'DELETE', '/v1.0/me/mailFolders/deleteditems/messages/AAMk1'],
      ['graph', 'POST', '/v1.0/me/mailFolders/inbox/messageRules'],
      ['graph', 'POST', '/v1.0/me/mailFolders'],
      ['graph', 'PATCH', '/v1.0/me/mailFolders/inbox'],
      ['graph', 'POST', '/v1.0/me/messages/AAMk1/forward'],
      ['graph', 'POST', '/v1.0/me/messages/AAMk1/copy'],
    ];
    for (const [service, method, path] of blocked) {
      for (const cap of ALL_CAPS) expect(isAllowedRoute(service, method, path, cap), `${service} ${method} ${path} ${cap}`).toBe(false);
    }
    const calls: unknown[] = [];
    const upstream = new Upstream(async (req) => (calls.push(req), { status: 200, headers: {}, body: Buffer.from('{}') }));
    for (const [service, method, path] of blocked) {
      const err = await rejection(upstream.json(service, { method, path, capability: 'mail_modify' }));
      expect(err).toMatchObject({ code: 'route_not_allowed' });
    }
    expect(calls).toHaveLength(0);
  });
});

describe('provider opt-ins for organizing', () => {
  it('requests gmail.modify only with --allow-modify', () => {
    expect(GMAIL_MODIFY_SCOPE).toBe('https://www.googleapis.com/auth/gmail.modify');
    expect(gmailScopesFor({ modify: true })).toEqual([GMAIL_READONLY_SCOPE, GMAIL_MODIFY_SCOPE]);
    expect(gmailScopesFor({ drafts: true, modify: true })).toEqual([GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE]);
    expect(gmailScopesFor({})).not.toContain(GMAIL_MODIFY_SCOPE);
  });
});

// ---- Gmail -------------------------------------------------------------------------------------------------

function gmailAccount(scopes: string[]): GmailAccount {
  return {
    id: 'gmail-0000000a', label: 'Gmail', email: 'dummy.me@example.test', clientId: dummySecret('C'), clientSecret: dummySecret('S'),
    refreshToken: dummySecret('RT'), scopes, createdAt: now, updatedAt: now,
  };
}

function gmailSetup() {
  const gmail = new MockGmail();
  const acct = gmail.addAccount('dummy.me@example.test', [
    { id: 'msg1', threadId: 't1', internalDate: 1767225600000, snippet: 'hello', labelIds: ['INBOX', 'UNREAD'], payload: mime('text/plain', { headers: { Subject: 'Hello' }, content: 'Hi' }) },
  ]);
  acct.labels.push({ id: 'Label_7', name: 'Projekte', type: 'user' });
  const raw = Buffer.from('From: dummy.me@example.test\r\nTo: friend@example.test\r\nSubject: Draft one\r\n\r\nBody\r\n').toString('base64url');
  acct.drafts.push({ id: 'r-111', raw });
  const token = gmail.issueAccessToken(acct);
  const provider = new GmailProvider(new Upstream(gmail.transport), { getAccessToken: async () => token });
  const message = () => acct.messages[0]!;
  return { gmail, acct, provider, message };
}

const GMAIL_FULL = [GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE];

describe('GmailProvider organize [MOCK Gmail]', () => {
  it('lists labels with roles and drafts with subject/to', async () => {
    const { provider } = gmailSetup();
    const folders = await provider.listFolders(gmailAccount([GMAIL_READONLY_SCOPE]));
    expect(folders).toContainEqual({ folderId: 'INBOX', name: 'INBOX', role: 'inbox', type: 'system' });
    expect(folders).toContainEqual({ folderId: 'TRASH', name: 'TRASH', role: 'trash', type: 'system' });
    expect(folders).toContainEqual({ folderId: 'Label_7', name: 'Projekte', role: 'other', type: 'user' });
    const drafts = await provider.listDrafts(gmailAccount([GMAIL_READONLY_SCOPE]), { pageSize: 10 }, undefined);
    expect(drafts.items).toEqual([{ draftId: 'r-111', messageId: 'mr-111', subject: 'Draft one', to: ['friend@example.test'], date: '2026-01-01T00:00:00.000Z' }]);
    expect(drafts.next).toBeNull();
  });

  it('marks read/unread and starred via labels.modify', async () => {
    const { provider, message, gmail } = gmailSetup();
    const a = gmailAccount(GMAIL_FULL);
    await provider.markMessage(a, 'msg1', { read: true, starred: true });
    expect(message().labelIds).toEqual(['INBOX', 'STARRED']);
    await provider.markMessage(a, 'msg1', { read: false, starred: false });
    expect(message().labelIds).toEqual(['INBOX', 'UNREAD']);
    const modify = gmail.gmailCalls().filter((c) => c.url.pathname.endsWith('/modify'));
    expect(JSON.parse(modify[0]!.body!)).toEqual({ addLabelIds: ['STARRED'], removeLabelIds: ['UNREAD'] });
  });

  it('moves to a label (removing INBOX), archives, trashes and restores', async () => {
    const { provider, message } = gmailSetup();
    const a = gmailAccount(GMAIL_FULL);
    expect(await provider.moveMessage(a, 'msg1', { folderId: 'Label_7' })).toEqual({ messageId: 'msg1', folderId: 'Label_7' });
    expect(message().labelIds).toEqual(['UNREAD', 'Label_7']);
    await provider.moveMessage(a, 'msg1', { folderId: 'INBOX' });
    expect(message().labelIds).toContain('INBOX');
    expect(await provider.moveMessage(a, 'msg1', { archive: true })).toEqual({ messageId: 'msg1', folderId: 'ARCHIVE' });
    expect(message().labelIds).not.toContain('INBOX');
    expect(await provider.trashMessage(a, 'msg1')).toEqual({ messageId: 'msg1', folderId: 'TRASH' });
    expect(message().labelIds).toContain('TRASH');
    await provider.restoreMessage(a, 'msg1');
    expect(message().labelIds).not.toContain('TRASH');
  });

  it('refuses TRASH as a move target, bad label ids and organizing without gmail.modify, before any call', async () => {
    const { provider, gmail } = gmailSetup();
    expect(await rejection(provider.moveMessage(gmailAccount(GMAIL_FULL), 'msg1', { folderId: 'TRASH' }))).toMatchObject({ code: 'bad_argument' });
    expect(await rejection(provider.moveMessage(gmailAccount(GMAIL_FULL), 'msg1', { folderId: '../x' }))).toMatchObject({ code: 'bad_argument' });
    const ro = gmailAccount([GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE]);
    for (const p of [() => provider.markMessage(ro, 'msg1', { read: true }), () => provider.trashMessage(ro, 'msg1'), () => provider.restoreMessage(ro, 'msg1'), () => provider.moveMessage(ro, 'msg1', { archive: true })]) {
      const err = await rejection(p());
      expect(err).toMatchObject({ code: 'provider_scope_missing' });
      expect(err.message).toContain('--allow-modify');
    }
    expect(gmail.gmailCalls()).toHaveLength(0);
  });

  it('sends a draft with drafts.send only with the compose opt-in, never with gmail.send or gmail.modify alone', async () => {
    const { provider, acct, gmail } = gmailSetup();
    expect(provider.canSendDraft(gmailAccount([GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]))).toBe(false);
    // Organizing (--allow-modify) must not open a send path.
    expect(provider.canSendDraft(gmailAccount([GMAIL_READONLY_SCOPE, GMAIL_MODIFY_SCOPE]))).toBe(false);
    expect(await rejection(provider.sendDraft(gmailAccount([GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE]), 'r-111'))).toMatchObject({ code: 'provider_scope_missing' });
    expect(gmail.gmailCalls()).toHaveLength(0);
    const r = await provider.sendDraft(gmailAccount([GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE]), 'r-111');
    expect(r).toMatchObject({ status: 'accepted', detail: ACCEPTED_NOTE });
    expect(r.providerMessageId).toMatch(/^s[0-9a-f]+$/);
    expect(acct.sentDrafts.map((d) => d.id)).toEqual(['r-111']);
    expect(JSON.parse(gmail.gmailCalls().at(-1)!.body!)).toEqual({ id: 'r-111' });
  });

  it('classifies drafts.send outcomes: 4xx rejected, lost response indeterminate', async () => {
    const { provider, gmail } = gmailSetup();
    const a = gmailAccount(GMAIL_FULL);
    expect((await provider.sendDraft(a, 'r-unknown')).status).toBe('rejected');
    gmail.sendBehaviour = 'unreachable';
    expect(await provider.sendDraft(a, 'r-111')).toEqual({ status: 'indeterminate', detail: INDETERMINATE_NOTE });
  });
});

// ---- IMAP ----------------------------------------------------------------------------------------------------

function imapAccount(over: Partial<ImapAccount> = {}): ImapAccount {
  return {
    id: 'imap-0a1b2c3d', label: 'GMX dummy', email: 'dummy.me@gmx.at', username: 'dummy.me@gmx.at', password: dummySecret('IMAP-PASSWORD'),
    imap: { host: 'imap.gmx.net', port: 993 }, smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
    allowDrafts: true, allowSend: true, allowModify: true, createdAt: now, updatedAt: now, ...over,
  };
}

const DRAFT_RAW = Buffer.from(
  'From: Dummy Me <dummy.me@gmx.at>\r\nTo: friend@example.test\r\nCc: "Two, Second" <two@example.test>\r\n' +
    'Bcc: hidden.one@example.test,\r\n hidden.two@example.test\r\nSubject: Draft\r\nMessage-ID: <draft-1@gmx.at>\r\n\r\nHi\r\nBcc: not-a-header@example.test\r\n',
);

function imapMailboxes(): Record<string, MockMailbox> {
  return {
    INBOX: { uidValidity: '11', messages: [textMessage(1, { text: 'Hello' }), textMessage(2, { text: 'Second' })] },
    Entwürfe: { uidValidity: '12', specialUse: '\\Drafts', messages: [{ uid: 5, source: DRAFT_RAW, flags: ['\\Draft', '\\Seen'] }] },
    Gesendet: { uidValidity: '13', specialUse: '\\Sent', messages: [] },
    Gelöscht: { uidValidity: '14', specialUse: '\\Trash', messages: [] },
    Archiv: { uidValidity: '15', specialUse: '\\Archive', messages: [] },
    Projekte: { uidValidity: '16', messages: [] },
    '[Root]': { uidValidity: '17', messages: [], listFlags: ['\\Noselect'] },
  };
}

function imapSetup(results: SendResult[] = [{ status: 'accepted', detail: ACCEPTED_NOTE }]) {
  const session = new MockImapSession(new Map(Object.entries(imapMailboxes())));
  let sessions = 0;
  const smtpCalls: Array<{ raw: Buffer; envelope: { from: string; to: string[] } }> = [];
  const smtp = {
    send: async (_a: ImapAccount, raw: Buffer, envelope: { from: string; to: string[] }) => {
      smtpCalls.push({ raw, envelope });
      return results.shift() ?? { status: 'accepted', detail: ACCEPTED_NOTE };
    },
  } as unknown as SmtpSender;
  const provider = new ImapMailProvider({
    sessionFactory: async () => {
      sessions++;
      return session;
    },
    smtp,
  });
  const box = (name: string) => session.mailboxes.get(name)!;
  return { session, provider, smtpCalls, box, sessions: () => sessions };
}

const inboxId = (uid: number) => encodeImapMessageId('INBOX', '11', uid);
const draftId = encodeImapMessageId('Entwürfe', '12', 5);

describe('ImapMailProvider organize [MOCK ImapSession]', () => {
  it('lists selectable mailboxes with special-use roles and the drafts of the \\Drafts mailbox', async () => {
    const { provider } = imapSetup();
    const folders = await provider.listFolders(imapAccount({ allowModify: false }));
    expect(folders.map((f) => [f.folderId, f.role])).toEqual([
      ['INBOX', 'inbox'],
      ['Entwürfe', 'drafts'],
      ['Gesendet', 'sent'],
      ['Gelöscht', 'trash'],
      ['Archiv', 'archive'],
      ['Projekte', 'other'],
    ]);
    const drafts = await provider.listDrafts(imapAccount(), { pageSize: 10 }, undefined);
    expect(drafts.items.map((d) => d.draftId)).toEqual([draftId]);
  });

  it('sets and clears \\Seen / \\Flagged on a writable (SELECTed) mailbox', async () => {
    const { provider, session, box } = imapSetup();
    await provider.markMessage(imapAccount(), inboxId(1), { read: true, starred: true });
    expect(box('INBOX').messages[0]!.flags).toEqual(['\\Seen', '\\Flagged']);
    await provider.markMessage(imapAccount(), inboxId(1), { read: false });
    expect(box('INBOX').messages[0]!.flags).toEqual(['\\Flagged']);
    expect(session.opens.every((o) => o.readOnly === false)).toBe(true);
  });

  it('refuses to move a message into the drafts folder (it could then be re-sent as a draft)', async () => {
    const { provider, box } = imapSetup();
    expect(await rejection(provider.moveMessage(imapAccount(), inboxId(1), { folderId: 'Entwürfe' }))).toMatchObject({ code: 'not_permitted' });
    expect(box('Entwürfe').messages).toHaveLength(1);
    expect(box('INBOX').messages).toHaveLength(2);
  });

  it('moves, archives (\\Archive or a named folder), trashes to \\Trash and restores to INBOX with new ids', async () => {
    const { provider, box } = imapSetup();
    const a = imapAccount();
    const moved = await provider.moveMessage(a, inboxId(1), { folderId: 'Projekte' });
    expect(moved).toEqual({ messageId: encodeImapMessageId('Projekte', '16', 1), folderId: 'Projekte' });
    const archived = await provider.moveMessage(a, moved.messageId!, { archive: true });
    expect(archived.folderId).toBe('Archiv');
    const named = await provider.moveMessage(a, inboxId(2), { archive: true, folderId: 'Projekte' });
    expect(named.folderId).toBe('Projekte');
    expect(await rejection(provider.restoreMessage(a, archived.messageId!))).toMatchObject({ code: 'not_in_trash' });
    const trashed = await provider.trashMessage(a, archived.messageId!);
    expect(trashed.messageId).toBe(encodeImapMessageId('Gelöscht', '14', 1));
    expect(box('Gelöscht').messages).toHaveLength(1);
    const restored = await provider.restoreMessage(a, trashed.messageId!);
    expect(restored.folderId).toBe('INBOX');
    expect(box('Gelöscht').messages).toHaveLength(0);
    expect(box('INBOX').messages.map((m) => m.envelope?.subject)).toContain('Dummy subject 1');
  });

  it('refuses unknown/\\Noselect targets, servers without MOVE/UIDPLUS, missing \\Trash, and organizing without the opt-in', async () => {
    const { provider, session, sessions } = imapSetup();
    const a = imapAccount();
    expect(await rejection(provider.moveMessage(a, inboxId(1), { folderId: 'Nope' }))).toMatchObject({ code: 'bad_folder' });
    expect(await rejection(provider.moveMessage(a, inboxId(1), { folderId: '[Root]' }))).toMatchObject({ code: 'bad_folder' });
    session.moveExt = false;
    expect(await rejection(provider.trashMessage(a, inboxId(1)))).toBeInstanceOf(Error);
    expect(session.mailboxes.get('INBOX')!.messages).toHaveLength(2);
    session.moveExt = true;
    session.mailboxes.delete('Gelöscht');
    expect(await rejection(provider.trashMessage(a, inboxId(1)))).toMatchObject({ code: 'no_trash_folder' });
    const before = sessions();
    const off = imapAccount({ allowModify: false });
    for (const p of [() => provider.markMessage(off, inboxId(1), { read: true }), () => provider.moveMessage(off, inboxId(1), { archive: true }), () => provider.trashMessage(off, inboxId(1)), () => provider.restoreMessage(off, inboxId(1))]) {
      const err = await rejection(p());
      expect(err).toMatchObject({ code: 'provider_scope_missing' });
      expect(err.message).toContain('--allow-modify');
    }
    expect(sessions()).toBe(before);
  });

  it('sends a draft over SMTP with the envelope from To/Cc/Bcc, WITHOUT the Bcc header, then files it in \\Sent', async () => {
    const { provider, smtpCalls, box, session } = imapSetup();
    const r = await provider.sendDraft(imapAccount(), draftId);
    expect(r.status).toBe('accepted');
    expect(r.detail.startsWith(ACCEPTED_NOTE)).toBe(true);
    expect(r.detail).toContain('Gesendet');
    expect(smtpCalls).toHaveLength(1);
    const sent = smtpCalls[0]!;
    expect(sent.envelope).toEqual({ from: 'dummy.me@gmx.at', to: ['friend@example.test', 'two@example.test', 'hidden.one@example.test', 'hidden.two@example.test'] });
    const text = sent.raw.toString('latin1');
    const [head, body] = [text.slice(0, text.indexOf('\r\n\r\n')), text.slice(text.indexOf('\r\n\r\n'))];
    expect(head).not.toMatch(/bcc|hidden/i);
    expect(head).toContain('Cc: "Two, Second" <two@example.test>');
    // The body is transmitted byte for byte (a "Bcc:" line in the body is content, not a header).
    expect(body).toBe('\r\n\r\nHi\r\nBcc: not-a-header@example.test\r\n');
    expect(box('Entwürfe').messages).toHaveLength(0);
    expect(box('Gesendet').messages).toHaveLength(1);
    expect(box('Gesendet').messages[0]!.flags).toEqual(['\\Seen']);
    expect(session.flagChanges).toEqual([{ uid: 5, add: ['\\Seen'], remove: ['\\Draft'] }]);
  });

  it.each(['To', 'Cc', 'Bcc'])('ignores nested comment addresses in stored draft %s when deriving the SMTP envelope', async (header) => {
    const { provider, smtpCalls, box } = imapSetup();
    box('Entwürfe').messages[0]!.source = Buffer.from(
      `From: dummy.me@gmx.at\r\n${header}: Victim (x(y) <evil@example.test>) <victim@example.test>\r\nSubject: Safe recipient\r\n\r\nHello`,
    );
    expect((await provider.sendDraft(imapAccount(), draftId)).status).toBe('accepted');
    expect(smtpCalls).toHaveLength(1);
    expect(smtpCalls[0]!.envelope.to).toEqual(['victim@example.test']);
  });

  it('leaves the draft in place when SMTP did not accept it, and reports a filing failure without changing the outcome', async () => {
    const rejected = imapSetup([{ status: 'rejected', detail: 'Not sent: the server rejected all recipients' }]);
    expect((await rejected.provider.sendDraft(imapAccount(), draftId)).status).toBe('rejected');
    expect(rejected.box('Entwürfe').messages).toHaveLength(1);
    const unknown = imapSetup([{ status: 'indeterminate', detail: INDETERMINATE_NOTE }]);
    expect(await unknown.provider.sendDraft(imapAccount(), draftId)).toEqual({ status: 'indeterminate', detail: INDETERMINATE_NOTE });
    expect(unknown.box('Entwürfe').messages).toHaveLength(1);
    // Without MOVE/UIDPLUS the draft stays and a copy is APPENDed to Sent instead (one SMTP submission only).
    const copied = imapSetup();
    copied.session.moveExt = false;
    const c = await copied.provider.sendDraft(imapAccount(), draftId);
    expect(c).toMatchObject({ status: 'accepted', sentCopy: true });
    expect(c.detail).toMatch(/copy was filed in "Gesendet".*still in the drafts folder/);
    expect(copied.box('Gesendet').messages).toHaveLength(1);
    expect(copied.box('Entwürfe').messages).toHaveLength(1);
    expect(copied.smtpCalls).toHaveLength(1);
    // With Sent copies turned off for the account, no APPEND fallback: reported, outcome unchanged.
    const unfiled = imapSetup();
    unfiled.session.moveExt = false;
    const r = await unfiled.provider.sendDraft(imapAccount({ sentCopy: false }), draftId);
    expect(r).toMatchObject({ status: 'accepted', sentCopy: false });
    expect(r.detail).toMatch(/could not be moved to the Sent folder/);
    expect(unfiled.box('Gesendet').messages).toHaveLength(0);
    // APPEND failing too: still accepted, never resubmitted.
    const failing = imapSetup();
    failing.session.moveExt = false;
    failing.session.failOn = { op: 'append', err: new Error('MOCK: quota') };
    const f = await failing.provider.sendDraft(imapAccount(), draftId);
    expect(f).toMatchObject({ status: 'accepted', sentCopy: false });
    expect(failing.smtpCalls).toHaveLength(1);
  });

  it('refuses before SMTP: no allowSend, not in the drafts folder, a foreign From address, a stale id', async () => {
    const { provider, smtpCalls, box } = imapSetup();
    expect(await rejection(provider.sendDraft(imapAccount({ allowSend: false }), draftId))).toMatchObject({ code: 'not_permitted' });
    expect(await rejection(provider.sendDraft(imapAccount(), inboxId(1)))).toMatchObject({ code: 'not_a_draft' });
    expect(await rejection(provider.sendDraft(imapAccount(), encodeImapMessageId('Entwürfe', '99', 5)))).toMatchObject({ code: 'stale_message_id' });
    box('Entwürfe').messages[0]!.source = Buffer.from('From: someone.else@example.test\r\nTo: friend@example.test\r\n\r\nHi\r\n');
    expect(await rejection(provider.sendDraft(imapAccount(), draftId))).toMatchObject({ code: 'bad_argument' });
    expect(smtpCalls).toHaveLength(0);
  });
});

describe('ImapflowSession organize adapter [MOCK imapflow client]', () => {
  function client(caps: string[]) {
    const log: Array<[string, ...unknown[]]> = [];
    const c = {
      capabilities: new Map(caps.map((k) => [k, true])),
      mailbox: false as unknown,
      async getMailboxLock(path: string, opts: unknown) {
        log.push(['lock', path, opts]);
        c.mailbox = { path, uidValidity: 9n, readOnly: false };
        return { path, release: () => log.push(['release']) };
      },
      async messageFlagsAdd(range: unknown, flags: unknown, opts: unknown) {
        log.push(['add', range, flags, opts]);
        return true;
      },
      async messageFlagsRemove(range: unknown, flags: unknown, opts: unknown) {
        log.push(['remove', range, flags, opts]);
        return true;
      },
      async messageMove(range: unknown, dest: unknown, opts: unknown) {
        log.push(['move', range, dest, opts]);
        return { path: 'INBOX', destination: dest, uidValidity: 21n, uidMap: new Map([[4, 40]]) };
      },
      async messageDelete() {
        log.push(['DELETE']);
        return true;
      },
      async list() {
        return [{ path: 'INBOX', name: 'INBOX', flags: new Set(['\\HasNoChildren']) }, { path: 'Trash', name: 'Trash', specialUse: '\\Trash', flags: new Set() }];
      },
    };
    return { c, log, s: new ImapflowSession(c as never) };
  }

  it('SELECTs read-write, uses UID STORE and UID MOVE and reports the COPYUID mapping', async () => {
    const { s, log } = client(['MOVE']);
    const lock = await s.openWritable('INBOX');
    expect(lock.uidValidity).toBe('9');
    await s.setFlags(4, ['\\Seen'], ['\\Flagged']);
    expect(await s.move(4, 'Trash')).toEqual({ uid: 40, uidValidity: '21' });
    expect(log).toEqual([
      ['lock', 'INBOX', { readOnly: false }],
      ['add', '4', ['\\Seen'], { uid: true }],
      ['remove', '4', ['\\Flagged'], { uid: true }],
      ['move', '4', 'Trash', { uid: true }],
    ]);
    expect(await s.listMailboxes()).toEqual([
      { path: 'INBOX', name: 'INBOX', flags: ['\\HasNoChildren'] },
      { path: 'Trash', name: 'Trash', specialUse: '\\Trash', flags: [] },
    ]);
  });

  it('refuses to move on a server with neither MOVE nor UIDPLUS (no plain EXPUNGE), and never deletes', async () => {
    const { s, log } = client([]);
    expect(await rejection(s.move(4, 'Trash'))).toMatchObject({ code: 'imap_move_unsupported' });
    expect(log.some(([op]) => op === 'move' || op === 'DELETE')).toBe(false);
    const uidplus = client(['UIDPLUS']);
    expect(await uidplus.s.move(4, 'Trash')).toEqual({ uid: 40, uidValidity: '21' });
  });
});

describe('prepareDraftForSmtp', () => {
  it('drops every Bcc/Resent-Bcc field with its continuation lines and keeps everything else byte for byte', () => {
    const raw = Buffer.from('From: a@example.test\nBCC: x@example.test,\n\ty@example.test\nTo: b@example.test\nResent-Bcc: z@example.test\nSubject: S\n\nBody\n');
    const r = prepareDraftForSmtp(raw, 'a@example.test');
    expect(r.raw.toString()).toBe('From: a@example.test\nTo: b@example.test\nSubject: S\n\nBody\n');
    expect(r.envelope).toEqual({ from: 'a@example.test', to: ['b@example.test', 'x@example.test', 'y@example.test'] });
  });

  it('refuses drafts without recipients, without a header separator or with several From addresses', () => {
    expect(() => prepareDraftForSmtp(Buffer.from('From: a@example.test\r\nSubject: S\r\n\r\nx'), 'a@example.test')).toThrow(/no recipients/);
    expect(() => prepareDraftForSmtp(Buffer.from('From: a@example.test'), 'a@example.test')).toThrow(/separator/);
    expect(() => prepareDraftForSmtp(Buffer.from('From: a@example.test, c@example.test\r\nTo: b@example.test\r\n\r\nx'), 'a@example.test')).toThrow(/From/);
  });
});
