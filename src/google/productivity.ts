import { PerchError } from '../errors.js';
import { newAccountId, validateLabel } from '../ids.js';
import type { PasteRedirect } from '../oauth/loopback.js';
import { RefreshingTokenProvider, type SharedTokenSource } from '../oauth/tokenProvider.js';
import { detachGroupMember, revokeSeparateGrant, sharedGoogleLogin, sharedRevokeRefused, type SharedGrantHolder } from './groupStore.js';
import type { CredentialStore, GoogleProductivityAccount } from '../store/credentialStore.js';
import { UpstreamError, type Upstream } from '../upstream.js';
import {
  ownClient,
  refreshAccessToken,
  revokeToken,
  runLoopbackAuthorization,
  type AuthorizationResult,
  type GoogleClientCredentials,
  type GoogleTokenResponse,
} from './oauth.js';

/**
 * Google Calendar/Contacts grant, separate from the Drive and Gmail grants.
 *
 * Scopes (https://developers.google.com/workspace/calendar/api/auth,
 * https://developers.google.com/people/api/rest/v1/people.connections/list):
 * - calendar.readonly: calendarList.list, events.list/get;
 * - contacts.readonly: people.connections.list, people.get;
 * - calendar.events.owned (only with --allow-calendar-write): "See, create, change, and delete events
 *   on Google calendars you own". It is the narrowest scope that events.insert and events.patch accept
 *   (their reference pages list calendar, calendar.events, calendar.app.created, calendar.events.owned),
 *   and Perch only writes private events on calendars the user owns anyway.
 * Identity: `openid email` (https://developers.google.com/identity/openid-connect/openid-connect);
 * Google reports `email` back as https://www.googleapis.com/auth/userinfo.email.
 */
export const CALENDAR_READONLY_SCOPE = 'https://www.googleapis.com/auth/calendar.readonly';
export const CALENDAR_EVENTS_OWNED_SCOPE = 'https://www.googleapis.com/auth/calendar.events.owned';
export const CONTACTS_READONLY_SCOPE = 'https://www.googleapis.com/auth/contacts.readonly';
export const OPENID_SCOPE = 'openid';
export const EMAIL_SCOPE = 'email';
export const USERINFO_EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email';

export const PRODUCTIVITY_SERVICES = ['calendar', 'contacts'] as const;
export type ProductivityService = (typeof PRODUCTIVITY_SERVICES)[number];

const SERVICE_SCOPE: Record<ProductivityService, string> = {
  calendar: CALENDAR_READONLY_SCOPE,
  contacts: CONTACTS_READONLY_SCOPE,
};

export interface ProductivityRequest {
  services: ProductivityService[];
  allowCalendarWrite: boolean;
}

/** Explicit, de-duplicated service selection in canonical order. */
export function parseServices(list: string[]): ProductivityService[] {
  const wanted = new Set(list.map((s) => s.trim()).filter(Boolean));
  for (const s of wanted) {
    if (!(PRODUCTIVITY_SERVICES as readonly string[]).includes(s)) throw new PerchError(`Unknown service: ${s} (use calendar, contacts)`, 'bad_argument');
  }
  const out = PRODUCTIVITY_SERVICES.filter((s) => wanted.has(s));
  if (!out.length) throw new PerchError('Select at least one service: --services calendar,contacts', 'bad_argument');
  return out;
}

export function productivityScopesFor(req: ProductivityRequest): string[] {
  const services = parseServices(req.services);
  if (req.allowCalendarWrite && !services.includes('calendar')) {
    throw new PerchError('--allow-calendar-write needs the calendar service (--services calendar)', 'bad_argument');
  }
  return [OPENID_SCOPE, EMAIL_SCOPE, ...services.map((s) => SERVICE_SCOPE[s]), ...(req.allowCalendarWrite ? [CALENDAR_EVENTS_OWNED_SCOPE] : [])];
}

const scopeMissing = (scope: string) =>
  new PerchError(`The ${scope} permission was not granted. Retry and tick every requested checkbox on the consent screen.`, 'oauth_scope_missing');

/** Validates the authorization_code response: refresh token, identity scopes and every selected service scope. */
export function assertProductivityGrant(tok: GoogleTokenResponse, req: ProductivityRequest): AuthorizationResult {
  const wanted = productivityScopesFor(req);
  if (!tok.access_token) throw new PerchError('Google did not return an access token', 'oauth_incomplete');
  if (!tok.refresh_token) {
    throw new PerchError(
      'Google did not return a refresh token. Remove Perch under https://myaccount.google.com/permissions and retry.',
      'oauth_no_refresh_token',
    );
  }
  const granted = (tok.scope ?? '').split(/\s+/).filter(Boolean);
  for (const scope of wanted) {
    if (scope === EMAIL_SCOPE) {
      if (!granted.includes(EMAIL_SCOPE) && !granted.includes(USERINFO_EMAIL_SCOPE)) throw scopeMissing('email');
    } else if (!granted.includes(scope)) throw scopeMissing(scope);
  }
  return { refreshToken: tok.refresh_token, accessToken: tok.access_token, expiresAt: Date.now() + (tok.expires_in ?? 0) * 1000, scopes: granted };
}

export interface ProductivityAuthOptions extends ProductivityRequest {
  client: GoogleClientCredentials;
  upstream: Upstream;
  port?: number;
  timeoutMs?: number;
  loginHint?: string;
  onAuthUrl: (url: string) => void;
  paste?: PasteRedirect;
}

/** Desktop-app OAuth through the shared loopback (127.0.0.1, state, PKCE S256), separate grant. */
export function runProductivityAuthorization(opts: ProductivityAuthOptions): Promise<AuthorizationResult> {
  const req = { services: opts.services, allowCalendarWrite: opts.allowCalendarWrite };
  return runLoopbackAuthorization({
    client: opts.client,
    upstream: opts.upstream,
    scopes: productivityScopesFor(req),
    verify: (tok) => assertProductivityGrant(tok, req),
    onAuthUrl: opts.onAuthUrl,
    ...(opts.paste ? { paste: opts.paste } : {}),
    ...(opts.port !== undefined ? { port: opts.port } : {}),
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    ...(opts.loginHint ? { loginHint: opts.loginHint } : {}),
  });
}

/**
 * Account identity from the fixed userinfo endpoint (https://openidconnect.googleapis.com/v1/userinfo,
 * the `userinfo_endpoint` of Google's discovery document). The email must be verified; `sub` is the
 * stable account id Google recommends over the email.
 */
export async function fetchVerifiedIdentity(upstream: Upstream, accessToken: string): Promise<{ sub: string; email: string }> {
  const info = await upstream.json<{ sub?: unknown; email?: unknown; email_verified?: unknown }>('openid', {
    method: 'GET',
    path: '/v1/userinfo',
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (typeof info.sub !== 'string' || !/^[0-9A-Za-z_-]{1,255}$/.test(info.sub)) {
    throw new PerchError('Google did not report a valid account id (sub)', 'google_identity');
  }
  if (typeof info.email !== 'string' || info.email.length < 3 || info.email.length > 320 || /[\s\u0000-\u001f]/.test(info.email)) {
    throw new PerchError('Google did not report the account email', 'google_identity');
  }
  if (info.email_verified !== true) throw new PerchError('Google did not report a verified email for this account; refusing to connect it', 'google_identity');
  return { sub: info.sub, email: info.email };
}

/** Stores a freshly authorised grant as a new productivity account (one grant per Google account). */
export async function registerProductivityAccount(
  store: CredentialStore,
  upstream: Upstream,
  input: { label: string; client: GoogleClientCredentials; grant: AuthorizationResult } & ProductivityRequest,
): Promise<GoogleProductivityAccount> {
  const label = validateLabel(input.label);
  const services = parseServices(input.services);
  productivityScopesFor({ services, allowCalendarWrite: input.allowCalendarWrite });
  const identity = await fetchVerifiedIdentity(upstream, input.grant.accessToken);
  return store.update((data) => {
    const dup = data.googleProductivity.find((a) => a.sub === identity.sub || a.email.toLowerCase() === identity.email.toLowerCase());
    if (dup) {
      throw new PerchError(
        dup.groupId
          ? `Google account ${identity.email} is already connected for Calendar/Contacts as ${dup.id} in group ${dup.groupId}. To change its services or permissions run perch google add for the same account (updates the group).`
          : `Google account ${identity.email} is already connected for Calendar/Contacts as ${dup.id}. Remove it first to re-authorise with other services.`,
        'duplicate_account',
      );
    }
    const now = new Date().toISOString();
    const account: GoogleProductivityAccount = {
      id: newAccountId('gprod', data.googleProductivity.map((a) => a.id)),
      label,
      email: identity.email,
      sub: identity.sub,
      clientId: input.client.clientId,
      clientSecret: input.client.clientSecret,
      refreshToken: input.grant.refreshToken,
      scopes: input.grant.scopes,
      services,
      allowCalendarWrite: input.allowCalendarWrite,
      createdAt: now,
      updatedAt: now,
    };
    data.googleProductivity.push(account);
    return account;
  });
}

/**
 * Removes the account locally. With `revoke`, also revokes the grant at Google first; refused while another stored
 * login of the same Google account uses the same OAuth client (Google revokes the whole grant), unless `force`.
 * A member of a Google account group only leaves its group (the shared login stays for the other services;
 * revoking it is refused).
 */
export async function removeProductivityAccount(
  store: CredentialStore,
  upstream: Upstream,
  id: string,
  opts: { revoke?: boolean; force?: boolean },
): Promise<{ revoked: boolean; alsoRevoked?: SharedGrantHolder[]; groupId?: string; groupRemoved?: boolean }> {
  const data = await store.read();
  const account = data.googleProductivity.find((a) => a.id === id);
  if (!account) throw new PerchError(`Unknown Google productivity account: ${id}`, 'unknown_account');
  if (account.groupId) {
    if (opts.revoke) throw sharedRevokeRefused(id, account.groupId);
    const r = await store.update((data) => detachGroupMember(data, 'googleProductivity', id));
    return { revoked: false, groupId: r.groupId, groupRemoved: r.groupRemoved };
  }
  const { revoked, alsoRevoked } = await revokeSeparateGrant(upstream, data, account, opts);
  await store.update((data) => {
    data.googleProductivity = data.googleProductivity.filter((a) => a.id !== id);
  });
  return { revoked, ...(alsoRevoked.length ? { alsoRevoked } : {}) };
}

export interface ProductivityCapabilities {
  calendarRead: boolean;
  contactsRead: boolean;
  calendarWrite: boolean;
}

/**
 * What the upstream grant allows. Needs the onboarding selection AND the scope Google granted at
 * onboarding AND, when known, the scope Google reported with the current access token (`liveScopes`).
 */
export function productivityCapabilities(account: GoogleProductivityAccount, liveScopes?: string[]): ProductivityCapabilities {
  const has = (scope: string) => account.scopes.includes(scope) && (liveScopes === undefined || liveScopes.includes(scope));
  return {
    calendarRead: account.services.includes('calendar') && has(CALENDAR_READONLY_SCOPE),
    contactsRead: account.services.includes('contacts') && has(CONTACTS_READONLY_SCOPE),
    calendarWrite: account.services.includes('calendar') && account.allowCalendarWrite && has(CALENDAR_EVENTS_OWNED_SCOPE),
  };
}

/** In-memory access tokens; refresh is single-flight, rotation persisted under the store lock, fail closed. */
export function createProductivityTokenProvider(
  store: CredentialStore,
  upstream: Upstream,
  now: () => number = Date.now,
  group?: SharedTokenSource,
): RefreshingTokenProvider<GoogleProductivityAccount> {
  return new RefreshingTokenProvider<GoogleProductivityAccount>(
    store,
    {
      name: 'Google Calendar/Contacts',
      list: (d) => d.googleProductivity,
      refresh: (a, rt) => refreshAccessToken(upstream, ownClient(a), rt),
      // The label is user-supplied, so the command only ever contains the generated id.
      reconnect: (id) => `\`perch google-productivity remove ${id}\`, then \`perch google add --label <label> --services calendar,contacts\``,
      shared: sharedGoogleLogin(store, upstream, group),
    },
    now,
  );
}
