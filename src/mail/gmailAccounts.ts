import type { AuthorizationResult, GoogleClientCredentials } from '../google/oauth.js';
import { ownClient, refreshAccessToken, revokeToken } from '../google/oauth.js';
import { detachGroupMember, revokeSeparateGrant, sharedGoogleLogin, sharedRevokeRefused, type SharedGrantHolder } from '../google/groupStore.js';
import { PerchError } from '../errors.js';
import { newAccountId, validateLabel } from '../ids.js';
import { RefreshingTokenProvider, type SharedTokenSource } from '../oauth/tokenProvider.js';
import type { CredentialStore, GmailAccount } from '../store/credentialStore.js';
import { UpstreamError, type Upstream } from '../upstream.js';

/**
 * Gmail OAuth scopes (https://developers.google.com/workspace/gmail/api/auth/scopes):
 * gmail.readonly (restricted) is always requested; gmail.send (sensitive) and gmail.compose
 * (restricted; drafts + send) only on explicit opt-in, so a read-only grant can never send.
 */
export const GMAIL_READONLY_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
export const GMAIL_SEND_SCOPE = 'https://www.googleapis.com/auth/gmail.send';
export const GMAIL_COMPOSE_SCOPE = 'https://www.googleapis.com/auth/gmail.compose';
/**
 * gmail.modify (restricted): labels, read/unread, archive, trash and untrash; never permanent deletion
 * (that needs the full https://mail.google.com/ scope, which Perch never requests). Opt-in only.
 */
export const GMAIL_MODIFY_SCOPE = 'https://www.googleapis.com/auth/gmail.modify';

export function gmailScopesFor(opts: { send?: boolean; drafts?: boolean; modify?: boolean }): string[] {
  const scopes = [GMAIL_READONLY_SCOPE];
  // compose includes sending, so gmail.send would only widen the consent screen.
  if (opts.drafts) scopes.push(GMAIL_COMPOSE_SCOPE);
  else if (opts.send) scopes.push(GMAIL_SEND_SCOPE);
  if (opts.modify) scopes.push(GMAIL_MODIFY_SCOPE);
  return scopes;
}

/** The mailbox address the grant belongs to (gmail.readonly covers users.getProfile). */
export async function fetchGmailIdentity(upstream: Upstream, accessToken: string): Promise<{ email: string }> {
  const profile = await upstream.json<{ emailAddress?: unknown }>('gmail', {
    method: 'GET',
    path: '/gmail/v1/users/me/profile',
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (typeof profile.emailAddress !== 'string' || !profile.emailAddress) {
    throw new PerchError('Gmail did not report the mailbox address', 'gmail_identity');
  }
  return { email: profile.emailAddress };
}

/** Stores a freshly authorised grant as a new Gmail account (one grant per mailbox). */
export async function registerGmailAccount(
  store: CredentialStore,
  upstream: Upstream,
  input: { label: string; client: GoogleClientCredentials; grant: AuthorizationResult; draftsOnly?: boolean },
): Promise<GmailAccount> {
  const label = validateLabel(input.label);
  const { email } = await fetchGmailIdentity(upstream, input.grant.accessToken);
  return store.update((data) => {
    const dup = data.gmail.find((g) => g.email.toLowerCase() === email.toLowerCase());
    if (dup) {
      throw new PerchError(
        dup.groupId
          ? `Gmail account ${email} is already connected as ${dup.id} in group ${dup.groupId}. To change its permissions run perch google add for the same account (updates the group).`
          : `Gmail account ${email} is already connected as ${dup.id} ("${dup.label}"). Remove it first to re-authorise.`,
        'duplicate_account',
      );
    }
    const now = new Date().toISOString();
    const account: GmailAccount = {
      id: newAccountId('gmail', data.gmail.map((g) => g.id)),
      label,
      email,
      clientId: input.client.clientId,
      clientSecret: input.client.clientSecret,
      refreshToken: input.grant.refreshToken,
      scopes: input.grant.scopes,
      ...(input.draftsOnly ? { draftsOnly: true } : {}),
      createdAt: now,
      updatedAt: now,
    };
    data.gmail.push(account);
    return account;
  });
}

/**
 * Removes the account locally. With `revoke`, also revokes the grant at Google first; refused while another stored
 * login of the same Google account uses the same OAuth client (Google revokes the whole grant), unless `force`.
 * A member of a Google account group only leaves its group (the shared login stays for the other services;
 * revoking it is refused).
 */
export async function removeGmailAccount(
  store: CredentialStore,
  upstream: Upstream,
  id: string,
  opts: { revoke?: boolean; force?: boolean },
): Promise<{ revoked: boolean; alsoRevoked?: SharedGrantHolder[]; groupId?: string; groupRemoved?: boolean }> {
  const data = await store.read();
  const account = data.gmail.find((g) => g.id === id);
  if (!account) throw new PerchError(`Unknown Gmail account: ${id}`, 'unknown_account');
  if (account.groupId) {
    if (opts.revoke) throw sharedRevokeRefused(id, account.groupId);
    const r = await store.update((data) => detachGroupMember(data, 'gmail', id));
    return { revoked: false, groupId: r.groupId, groupRemoved: r.groupRemoved };
  }
  const { revoked, alsoRevoked } = await revokeSeparateGrant(upstream, data, account, opts);
  await store.update((data) => {
    data.gmail = data.gmail.filter((g) => g.id !== id);
  });
  return { revoked, ...(alsoRevoked.length ? { alsoRevoked } : {}) };
}

/** In-memory access tokens for Gmail accounts; refresh-token rotation is persisted under the store lock. */
export function createGmailTokenProvider(
  store: CredentialStore,
  upstream: Upstream,
  now: () => number = Date.now,
  group?: SharedTokenSource,
): RefreshingTokenProvider<GmailAccount> {
  return new RefreshingTokenProvider<GmailAccount>(
    store,
    {
      name: 'Gmail',
      list: (d) => d.gmail,
      refresh: (a, rt) => refreshAccessToken(upstream, ownClient(a), rt),
      // The label is user-supplied, so the command only ever contains the generated id.
      reconnect: (id) => `\`perch gmail remove ${id}\`, then \`perch google add --label <label> --services gmail\``,
      shared: sharedGoogleLogin(store, upstream, group),
    },
    now,
  );
}
