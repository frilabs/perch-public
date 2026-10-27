// MOCK upstream "worlds": every store (tag A, B, ...) gets its own in-memory Drive, Notion, Gmail,
// IMAP/SMTP and Calendar/Contacts fakes, and is seeded with the SAME (colliding) account ids. Every upstream request is logged with the tag of
// the world that received it, so a test can prove which store's credentials an operation used, and that
// a denied operation caused no provider I/O at all. Nothing here talks to a real provider; every secret is
// generated dummy data.
import { createPerchContext, type PerchContext } from '../../src/context.js';
import { ImapMailProvider } from '../../src/mail/imap.js';
import { createMailProviders } from '../../src/mail/providers.js';
import type { SmtpSender } from '../../src/mail/smtp.js';
import { GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE } from '../../src/mail/gmailAccounts.js';
import type { CredentialStore } from '../../src/store/credentialStore.js';
import { Upstream, type UpstreamTransport } from '../../src/upstream.js';
import { dummySecret } from './fixtures.js';
import { MockGmail, mime } from './mockGmail.js';
import { MockGoogle } from './mockGoogle.js';
import { MockImapSession, textMessage, type MockMailbox } from './mockImap.js';
import { mockId, MockNotion } from './mockNotion.js';
import { MockGoogleProductivity, SCOPE } from './mockProductivity.js';

/** The colliding account ids every namespace uses. */
export const IDS = {
  google: 'google-0000000a',
  notion: 'notion-0000000a',
  gmail: 'gmail-0000000a',
  microsoft: 'microsoft-0000000a',
  imap: 'imap-0000000a',
  gprod: 'gprod-0000000a',
} as const;

export interface World {
  tag: string;
  drive: MockGoogle;
  notion: MockNotion;
  gmail: MockGmail;
  prod: MockGoogleProductivity;
  imapSessions: MockImapSession[];
  mailboxes: Map<string, MockMailbox>;
  smtpSent: string[];
  notionPageId: string;
  /** Every upstream request this world received ("<origin><path>"). */
  calls: string[];
}

/** Global ordered log of "<tag> <what>" for every provider request of every world. */
export type IoLog = string[];

export function createWorld(tag: string, io: IoLog): World {
  const drive = new MockGoogle();
  drive.addAccount(`drive.${tag}@example.test`, [
    { id: 'file0001', name: `report ${tag} one`, mimeType: 'text/plain', content: Buffer.from(`drive secret of ${tag}`) },
    { id: 'file0002', name: `report ${tag} two`, mimeType: 'application/pdf', content: Buffer.from(`pdf of ${tag}`) },
  ]);
  const notion = new MockNotion();
  const ws = notion.addWorkspace(`ws ${tag}`);
  const notionPageId = mockId();
  ws.pages.push({
    id: notionPageId,
    title: `Plan ${tag}`,
    blocks: [1, 2, 3].map((n) => ({ id: mockId(), text: `block ${n} of ${tag}` })),
  });
  const gmail = new MockGmail({ grantedScope: `${GMAIL_READONLY_SCOPE} ${GMAIL_SEND_SCOPE}` });
  gmail.addAccount(`gmail.${tag}@example.test`, [
    {
      id: 'm1',
      threadId: 't-m1',
      internalDate: Date.UTC(2026, 8, 1),
      snippet: `snippet ${tag}`,
      payload: mime('multipart/mixed', {
        headers: { From: 'sender@example.test', To: `gmail.${tag}@example.test`, Subject: `gmail ${tag}`, 'Message-ID': `<m1.${tag}@example.test>` },
        parts: [mime('text/plain', { content: `gmail body of ${tag}` }), mime('text/plain', { filename: 'a.txt', content: `gmail attachment of ${tag}` })],
      }),
    },
  ]);
  const prod = new MockGoogleProductivity();
  prod.pageSize = 10;
  const email = `prod.${tag}@example.test`;
  prod.addAccount(email, {
    calendars: [
      {
        id: email,
        summary: email,
        timeZone: 'Europe/Vienna',
        accessRole: 'owner',
        primary: true,
        events: [1, 2, 3].map((n) => ({
          id: `evt${tag.toLowerCase()}0000${n}`,
          etag: `"${n}"`,
          status: 'confirmed',
          summary: `event ${n} of ${tag}`,
          start: { dateTime: `2026-10-0${n + 5}T09:00:00Z` },
          end: { dateTime: `2026-10-0${n + 5}T10:00:00Z` },
          organizer: { email, self: true },
        })),
      },
    ],
    contacts: [1, 2, 3].map((n) => ({ resourceName: `people/c${n}`, etag: `"${n}"`, names: [{ displayName: `contact ${n} of ${tag}` }] })),
  });
  const mailboxes = new Map<string, MockMailbox>([
    ['INBOX', { uidValidity: '1', messages: [textMessage(7, { subject: `imap ${tag}`, text: `imap body of ${tag}`, attachment: { filename: 'i.txt', content: Buffer.from(`imap attachment of ${tag}`), type: 'text/plain' } })] }],
    ['Drafts', { uidValidity: '2', messages: [], specialUse: '\\Drafts' }],
  ]);
  const world: World = { tag, drive, notion, gmail, prod, imapSessions: [], mailboxes, smtpSent: [], notionPageId, calls: [] };
  return world;
}

/** Routes one world's upstream requests to its fakes and logs them with the world's tag. */
export function worldTransport(w: World, io: IoLog): UpstreamTransport {
  return async (req) => {
    const what = `${req.url.origin}${req.url.pathname}`;
    w.calls.push(what);
    io.push(`${w.tag} ${what}`);
    const o = req.url.origin;
    if (o === 'https://oauth2.googleapis.com') {
      const rt = new URLSearchParams(req.body ?? '').get('refresh_token');
      if (w.gmail.accounts.some((a) => a.refreshToken === rt)) return w.gmail.transport(req);
      if (w.prod.accounts.some((a) => a.refreshToken === rt)) return w.prod.transport(req);
      return w.drive.transport(req);
    }
    if (o === 'https://www.googleapis.com') return req.url.pathname.startsWith('/drive/') ? w.drive.transport(req) : w.prod.transport(req);
    if (o === 'https://gmail.googleapis.com') return w.gmail.transport(req);
    if (o === 'https://people.googleapis.com' || o === 'https://openidconnect.googleapis.com') return w.prod.transport(req);
    if (o === 'https://api.notion.com') return w.notion.transport(req);
    throw new Error(`MOCK: unexpected upstream ${o}`);
  };
}

/** Seeds `store` with the colliding account ids, bound to this world's fake credentials. */
export async function seedWorld(store: CredentialStore, w: World): Promise<void> {
  const now = new Date().toISOString();
  const label = (k: string) => `${k} of ${w.tag}`;
  await store.update((d) => {
    d.google.push({
      id: IDS.google,
      label: label('Drive'),
      email: w.drive.accounts[0]!.email,
      clientId: dummySecret('CLIENT'),
      clientSecret: dummySecret('CLIENT-SECRET'),
      refreshToken: w.drive.accounts[0]!.refreshToken,
      scopes: ['https://www.googleapis.com/auth/drive.readonly'],
      createdAt: now,
      updatedAt: now,
    });
    d.notion.push({ id: IDS.notion, label: label('Notion'), token: w.notion.workspaces[0]!.token, createdAt: now, updatedAt: now });
    d.gmail.push({
      id: IDS.gmail,
      label: label('Gmail'),
      email: w.gmail.accounts[0]!.email,
      clientId: dummySecret('CLIENT'),
      clientSecret: dummySecret('CLIENT-SECRET'),
      refreshToken: w.gmail.accounts[0]!.refreshToken,
      scopes: [GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE],
      createdAt: now,
      updatedAt: now,
    });
    d.microsoft.push({
      id: IDS.microsoft,
      label: label('Outlook'),
      email: `legacy.${w.tag}@example.test`,
      tenant: 'common',
      clientId: dummySecret('MS-CLIENT'),
      refreshToken: dummySecret('LEGACY-RETIRED-MS'),
      scopes: ['User.Read', 'Mail.Read'],
      createdAt: now,
      updatedAt: now,
    });
    d.imap.push({
      id: IDS.imap,
      label: label('GMX'),
      email: `imap.${w.tag}@example.test`,
      username: `imap.${w.tag}@example.test`,
      password: dummySecret('PW'),
      imap: { host: 'imap.gmx.net', port: 993 },
      smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
      allowDrafts: true,
      allowSend: true,
      createdAt: now,
      updatedAt: now,
    });
    const p = w.prod.accounts[0]!;
    d.googleProductivity.push({
      id: IDS.gprod,
      label: label('Calendar'),
      email: p.email,
      sub: p.sub,
      clientId: dummySecret('CLIENT'),
      clientSecret: dummySecret('CLIENT-SECRET'),
      refreshToken: p.refreshToken,
      scopes: ['openid', SCOPE.email, SCOPE.calendarRead, SCOPE.contactsRead, SCOPE.calendarOwned],
      services: ['calendar', 'contacts'],
      allowCalendarWrite: true,
      createdAt: now,
      updatedAt: now,
    });
  });
}

/** A context whose store uses the transport and IMAP/SMTP fakes of world `w`. */
export function worldContext(store: CredentialStore, w: World, io: IoLog): PerchContext {
  {
    const transport = worldTransport(w, io);
    const smtp = {
      send: async (_a: unknown, raw: Buffer) => {
        io.push(`${w.tag} smtp`);
        w.smtpSent.push(raw.toString('utf8'));
        return { status: 'accepted', detail: 'MOCK accepted' };
      },
    } as unknown as SmtpSender;
    const imap = new ImapMailProvider({
      sessionFactory: async () => {
        io.push(`${w.tag} imap`);
        const session = new MockImapSession(w.mailboxes);
        w.imapSessions.push(session);
        return session;
      },
      smtp,
    });
    return createPerchContext(store, transport, { ...createMailProviders(store, new Upstream(transport)), imap });
  }
}
