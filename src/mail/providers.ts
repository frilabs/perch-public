import type { RefreshingTokenProvider } from '../oauth/tokenProvider.js';
import type { CredentialStore, GmailAccount } from '../store/credentialStore.js';
import type { Upstream } from '../upstream.js';
import { GmailProvider } from './gmail.js';
import { createGmailTokenProvider } from './gmailAccounts.js';
import { ImapMailProvider } from './imap.js';
import type { MailProviders } from './service.js';
import { MicrosoftSessionMailProvider, type MicrosoftSessionDispatch } from '../microsoft/session/mailProvider.js';

/**
 * Production mail adapters: Gmail over the fixed-origin Upstream, Microsoft browser sessions, IMAP/SMTP over TLS. `tokens`
 * shares the namespace's token providers (status checks reuse them, so refresh-token rotation never races).
 */
export function createMailProviders(
  store: CredentialStore,
  upstream: Upstream,
  tokens: { gmail: RefreshingTokenProvider<GmailAccount> } = {
    gmail: createGmailTokenProvider(store, upstream),
  },
  sessionDispatch?: MicrosoftSessionDispatch,
): MailProviders {
  return {
    gmail: new GmailProvider(upstream, tokens.gmail),
    imap: new ImapMailProvider(),
    ...(sessionDispatch ? { microsoftSession: new MicrosoftSessionMailProvider(sessionDispatch) } : {}),
  };
}
