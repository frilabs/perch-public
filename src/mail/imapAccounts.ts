import { PerchError } from '../errors.js';
import { newAccountId, validateLabel } from '../ids.js';
import type { CredentialStore, ImapAccount } from '../store/credentialStore.js';
import { openImapflowSession, validateFolder } from './imap.js';
import { resolveServers, type SmtpSecurity, type TestOnlyTlsTrust } from './imapPresets.js';
import { SmtpSender } from './smtp.js';

/**
 * Onboarding for generic IMAP + SMTP accounts (e.g. GMX). The account is verified with a real
 * login BEFORE anything is stored, so a wrong app password never leaves a dead account behind.
 * The password is stored only in the encrypted credential store and never appears in errors.
 */

export interface AddImapAccountInput {
  label: string;
  email: string;
  /** Login name; defaults to the email address (GMX logs in with the address). */
  username?: string;
  password: string;
  preset?: string;
  imapHost?: string;
  imapPort?: number;
  smtpHost?: string;
  smtpPort?: number;
  smtpSecurity?: SmtpSecurity;
  /** IMAP has no OAuth scopes: drafts and sending are explicit opt-ins. */
  allowDrafts: boolean;
  allowSend: boolean;
  /** Organizing (flags, move/archive, trash/restore); default false. */
  allowModify?: boolean;
  draftsMailbox?: string;
  /** false = never file a copy of sent mail in the Sent folder (`--no-sent-copy`); absent = automatic (see imapSentCopyEnabled). */
  sentCopy?: boolean;
}

export type ImapVerifier = (account: ImapAccount) => Promise<void>;

const bad = (msg: string) => new PerchError(msg, 'bad_argument');

/** Removes the password from a message even if a server or verifier echoed it back. */
function scrub(message: string, password: string): string {
  return password ? message.split(password).join('[redacted]') : message;
}

function validatePassword(p: unknown): string {
  // CR/LF/NUL would break IMAP LOGIN / SASL framing; the length cap bounds what we store.
  if (typeof p !== 'string' || !p || p.length > 1024 || /[\r\n\u0000]/.test(p)) {
    throw bad('password must be 1-1024 characters without line breaks');
  }
  return p;
}

function validateUsername(u: string): string {
  if (!u || u.length > 320 || /[\u0000-\u001f\u007f]/.test(u)) throw bad('username must be 1-320 printable characters');
  return u;
}

export async function addImapAccount(store: CredentialStore, input: AddImapAccountInput, verify: ImapVerifier): Promise<ImapAccount> {
  const password = validatePassword(input?.password);
  const label = validateLabel(input.label);
  if (typeof input.allowDrafts !== 'boolean' || typeof input.allowSend !== 'boolean') {
    throw bad('allowDrafts and allowSend must be true or false');
  }
  if (input.allowModify !== undefined && typeof input.allowModify !== 'boolean') throw bad('allowModify must be true or false');
  if (input.sentCopy !== undefined && typeof input.sentCopy !== 'boolean') throw bad('sentCopy must be true or false');
  const servers = resolveServers({
    email: input.email,
    ...(input.preset !== undefined ? { preset: input.preset } : {}),
    ...(input.imapHost !== undefined ? { imapHost: input.imapHost } : {}),
    ...(input.imapPort !== undefined ? { imapPort: input.imapPort } : {}),
    ...(input.smtpHost !== undefined ? { smtpHost: input.smtpHost } : {}),
    ...(input.smtpPort !== undefined ? { smtpPort: input.smtpPort } : {}),
    ...(input.smtpSecurity !== undefined ? { smtpSecurity: input.smtpSecurity } : {}),
  });
  const email = input.email.trim();
  const username = validateUsername(input.username?.trim() || email);
  const draftsMailbox = input.draftsMailbox !== undefined ? validateFolder(input.draftsMailbox) : undefined;

  const sameMailbox = (a: ImapAccount) => a.email.toLowerCase() === email.toLowerCase() && a.imap.host === servers.imap.host;
  const assertNew = (accounts: ImapAccount[]) => {
    const dup = accounts.find(sameMailbox);
    if (dup) {
      throw new PerchError(`${email} on ${servers.imap.host} is already connected as ${dup.id} ("${dup.label}"). Remove it first.`, 'duplicate_account');
    }
  };
  const existing = (await store.read()).imap;
  assertNew(existing);

  const now = new Date().toISOString();
  const account: ImapAccount = {
    id: newAccountId('imap', existing.map((a) => a.id)),
    label,
    email,
    username,
    password,
    ...(servers.preset ? { preset: servers.preset } : {}),
    imap: servers.imap,
    smtp: servers.smtp,
    allowDrafts: input.allowDrafts,
    allowSend: input.allowSend,
    allowModify: input.allowModify === true,
    ...(draftsMailbox !== undefined ? { draftsMailbox } : {}),
    ...(input.sentCopy !== undefined ? { sentCopy: input.sentCopy } : {}),
    createdAt: now,
    updatedAt: now,
  };

  try {
    await verify(account);
  } catch (err) {
    if (err instanceof PerchError) throw new PerchError(scrub(err.message, password), err.code);
    throw new PerchError('Account verification failed (check server settings, app password and that IMAP access is enabled)', 'verify_failed');
  }

  return store.update((data) => {
    // Re-check under the store lock: another process may have added it during verification.
    assertNew(data.imap);
    if (data.imap.some((a) => a.id === account.id)) account.id = newAccountId('imap', data.imap.map((a) => a.id));
    data.imap.push(account);
    return account;
  });
}

/** Deletes the account and its stored password locally. App passwords are revoked at the provider. */
export async function removeImapAccount(store: CredentialStore, id: string): Promise<void> {
  await store.update((data) => {
    const i = data.imap.findIndex((a) => a.id === id);
    if (i < 0) throw new PerchError(`Unknown IMAP account: ${id}`, 'unknown_account');
    data.imap.splice(i, 1);
  });
}

/**
 * Default verifier: real IMAP login + logout and, only if sending is allowed, an SMTP login
 * (no message is sent). Errors are the sanitised PerchErrors of the session/sender.
 */
export async function verifyImapAccount(account: ImapAccount, opts: { testOnlyTlsTrust?: TestOnlyTlsTrust } = {}): Promise<void> {
  const session = await openImapflowSession(account, opts);
  await session.logout();
  if (account.allowSend) await new SmtpSender(opts).verify(account);
}
