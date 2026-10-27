// Dummy store entries for Calendar/Contacts tests. Every secret is generated dummy data.
import type { CredentialStore } from '../../src/store/credentialStore.js';
import { dummySecret } from './fixtures.js';

export const CAL_RO = 'https://www.googleapis.com/auth/calendar.readonly';
export const CAL_OWNED = 'https://www.googleapis.com/auth/calendar.events.owned';
export const CONTACTS_RO = 'https://www.googleapis.com/auth/contacts.readonly';
export const EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email';

export async function addDummyImap(store: CredentialStore, id: string) {
  const now = new Date().toISOString();
  await store.update((d) => {
    d.imap.push({
      id,
      label: `GMX ${id}`,
      email: `${id}@example.test`,
      username: `${id}@example.test`,
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

export interface DummyProductivityOptions {
  services?: Array<'calendar' | 'contacts'>;
  allowCalendarWrite?: boolean;
  scopes?: string[];
  refreshToken?: string;
  email?: string;
}

/** Adds a Google productivity account directly (onboarding is tested separately). */
export async function addDummyProductivity(store: CredentialStore, id: string, opts: DummyProductivityOptions = {}) {
  const now = new Date().toISOString();
  const services = opts.services ?? ['calendar', 'contacts'];
  const write = opts.allowCalendarWrite ?? false;
  const scopes = opts.scopes ?? [
    'openid',
    EMAIL_SCOPE,
    ...(services.includes('calendar') ? [CAL_RO] : []),
    ...(services.includes('contacts') ? [CONTACTS_RO] : []),
    ...(write ? [CAL_OWNED] : []),
  ];
  await store.update((d) => {
    d.googleProductivity.push({
      id,
      label: `Productivity ${id}`,
      email: opts.email ?? `${id}@example.test`,
      sub: `1${id.replace(/\D/g, '')}`,
      clientId: dummySecret('CLIENT'),
      clientSecret: dummySecret('CLIENT-SECRET'),
      refreshToken: opts.refreshToken ?? dummySecret('RT'),
      scopes,
      services,
      allowCalendarWrite: write,
      createdAt: now,
      updatedAt: now,
    });
  });
}
