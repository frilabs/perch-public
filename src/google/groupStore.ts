import { PerchError } from '../errors.js';
import { RefreshingTokenProvider, type SharedTokenSource } from '../oauth/tokenProvider.js';
import type { CredentialStore, GoogleAccountGroup, StoreData } from '../store/credentialStore.js';
import { UpstreamError, type Upstream } from '../upstream.js';
import { refreshAccessToken, revokeToken } from './oauth.js';

/**
 * Storage side of Google account groups (docs/GOOGLE_UNIFIED_SPEC.md): the shared login and its token provider,
 * and removing single members. Kept free of scope constants so the per-family modules (Drive, Gmail,
 * Calendar/Contacts) can import it without import cycles.
 */

/** Store sections that can hold members of a Google account group. */
export type GoogleMemberSection = 'google' | 'gmail' | 'googleProductivity';

export interface GoogleGroupMembers {
  drive?: StoreData['google'][number];
  gmail?: StoreData['gmail'][number];
  productivity?: StoreData['googleProductivity'][number];
}

export function groupMembers(data: StoreData, groupId: string): GoogleGroupMembers {
  const drive = data.google.find((a) => a.groupId === groupId);
  const gmail = data.gmail.find((a) => a.groupId === groupId);
  const productivity = data.googleProductivity.find((a) => a.groupId === groupId);
  return { ...(drive ? { drive } : {}), ...(gmail ? { gmail } : {}), ...(productivity ? { productivity } : {}) };
}

/** Services a group currently connects, in canonical order. */
export function groupServices(data: StoreData, groupId: string): Array<'drive' | 'gmail' | 'calendar' | 'contacts'> {
  const m = groupMembers(data, groupId);
  return [
    ...(m.drive ? (['drive'] as const) : []),
    ...(m.gmail ? (['gmail'] as const) : []),
    ...(m.productivity?.services.includes('calendar') ? (['calendar'] as const) : []),
    ...(m.productivity?.services.includes('contacts') ? (['contacts'] as const) : []),
  ];
}

/** The group with id `id`, or the group a member account `id` belongs to. */
export function findGroup(data: StoreData, id: string): GoogleAccountGroup | undefined {
  const direct = data.googleGroups.find((g) => g.id === id);
  if (direct) return direct;
  const member = [...data.google, ...data.gmail, ...data.googleProductivity].find((a) => a.id === id);
  return member?.groupId ? data.googleGroups.find((g) => g.id === member.groupId) : undefined;
}

const hasMembers = (data: StoreData, groupId: string) => Object.keys(groupMembers(data, groupId)).length > 0;

/**
 * Removes one member (or, for a Calendar/Contacts record, one of its two services) from its group inside a
 * store update. A group without members is removed with it, so no orphaned login stays stored. Never revokes:
 * revoking the shared login would disconnect every other service of the group.
 */
export function detachGroupMember(
  data: StoreData,
  section: GoogleMemberSection,
  id: string,
  service?: 'calendar' | 'contacts',
): { groupId: string; removedAccount: boolean; groupRemoved: boolean } {
  const list = data[section] as Array<{ id: string; groupId?: string }>;
  const member = list.find((a) => a.id === id);
  if (!member?.groupId) throw new PerchError(`${id} is not part of a Google account group`, 'unknown_account');
  const groupId = member.groupId;
  let removedAccount = true;
  if (section === 'googleProductivity' && service) {
    const p = data.googleProductivity.find((a) => a.id === id)!;
    const rest = p.services.filter((s) => s !== service);
    if (rest.length) {
      p.services = rest;
      if (service === 'calendar') p.allowCalendarWrite = false;
      p.updatedAt = new Date().toISOString();
      removedAccount = false;
    }
  }
  if (removedAccount) {
    if (section === 'google') data.google = data.google.filter((a) => a.id !== id);
    else if (section === 'gmail') data.gmail = data.gmail.filter((a) => a.id !== id);
    else data.googleProductivity = data.googleProductivity.filter((a) => a.id !== id);
  }
  const groupRemoved = !hasMembers(data, groupId);
  if (groupRemoved) data.googleGroups = data.googleGroups.filter((g) => g.id !== groupId);
  return { groupId, removedAccount, groupRemoved };
}

/** Error for revoking through a single member: the login is shared by the whole group. */
export function sharedRevokeRefused(id: string, groupId: string): PerchError {
  return new PerchError(
    `${id} shares its Google login with the other services of group ${groupId}; revoking it would disconnect all of them. ` +
      `Remove only this service without --revoke, or remove the whole group: perch google remove ${groupId} --revoke`,
    'bad_argument',
  );
}

/** A stored record whose Google login a revoke would end too. */
export interface SharedGrantHolder {
  id: string;
  label: string;
  email: string;
}

/**
 * Google's revoke endpoint ends the WHOLE grant of an OAuth client for a Google account, not just one refresh token:
 * every other stored login of the same Google account (same `sub`, or the same e-mail where a record has no `sub`)
 * through the same OAuth client id dies with it. Returns those other records (groups and separately connected
 * accounts), excluding `self` (the record being removed) and the members of group `selfGroupId`.
 */
export function sharedGrantHolders(
  data: StoreData,
  identity: { sub?: string; email: string },
  clientId: string,
  self: { id: string; selfGroupId?: string },
): SharedGrantHolder[] {
  const sameIdentity = (r: { sub?: string; email: string }) =>
    identity.sub && r.sub ? r.sub === identity.sub : r.email.toLowerCase() === identity.email.toLowerCase();
  const out: SharedGrantHolder[] = [];
  for (const g of data.googleGroups) {
    if (g.id !== self.id && g.id !== self.selfGroupId && g.clientId === clientId && sameIdentity(g)) out.push({ id: g.id, label: g.label, email: g.email });
  }
  const separate: Array<{ id: string; label: string; email: string; sub?: string; groupId?: string; clientId?: string }> = [
    ...data.google,
    ...data.gmail,
    ...data.googleProductivity,
  ];
  for (const a of separate) {
    if (a.groupId || a.id === self.id || a.clientId !== clientId || !sameIdentity(a)) continue;
    out.push({ id: a.id, label: a.label, email: a.email });
  }
  return out;
}

/** Refusal of a revoke that would also end the login of `holders` (override with --force). */
export function revokeWouldAffectOthers(id: string, holders: readonly SharedGrantHolder[]): PerchError {
  return new PerchError(
    `Revoking the Google login of ${id} would also end access for ${holders.map((h) => `${h.id} ("${h.label}", ${h.email})`).join(', ')}: ` +
      'Google revokes the whole grant of the OAuth client for that Google account. ' +
      `Remove ${id} without --revoke, or add --force to revoke anyway (those accounts then need to be connected again).`,
    'revoke_shared',
  );
}

/**
 * `--revoke` of a separately connected Google account (perch google|gmail|google-productivity remove): refused while
 * another stored login of the same Google account and OAuth client exists, unless `force`. An already invalid token
 * (400) counts as not revoked; removal still proceeds.
 */
export async function revokeSeparateGrant(
  upstream: Upstream,
  data: StoreData,
  account: { id: string; email: string; sub?: string; clientId?: string; refreshToken?: string },
  opts: { revoke?: boolean; force?: boolean },
): Promise<{ revoked: boolean; alsoRevoked: SharedGrantHolder[] }> {
  if (!opts.revoke || !account.refreshToken || !account.clientId) return { revoked: false, alsoRevoked: [] };
  const alsoRevoked = sharedGrantHolders(data, account, account.clientId, { id: account.id });
  if (alsoRevoked.length && !opts.force) throw revokeWouldAffectOthers(account.id, alsoRevoked);
  try {
    await revokeToken(upstream, account.refreshToken);
    return { revoked: true, alsoRevoked };
  } catch (err) {
    if (!(err instanceof UpstreamError && err.status === 400)) throw err;
    return { revoked: false, alsoRevoked };
  }
}

/**
 * Hint after a group (and its stored login) disappeared locally without a revoke: the grant itself stays valid at
 * Google. The group is gone, so the one-step alternative is named for next time.
 */
export function grantStillValidHint(groupId: string): string {
  return (
    `The Google grant of ${groupId} is still valid at Google; revoke it at https://myaccount.google.com/permissions if Perch no longer needs it ` +
    `(next time \`perch google remove ${groupId} --revoke\` removes and revokes in one step).\n`
  );
}

/**
 * Token provider for the shared logins. Same guarantees as every other provider: access tokens only in memory,
 * single-flight refresh per group and refresh token, rotation persisted under the store lock, fail closed when the
 * group was removed or re-authorised meanwhile, invalid_grant reported for the whole group.
 */
export function createGoogleGroupTokenProvider(
  store: CredentialStore,
  upstream: Upstream,
  now: () => number = Date.now,
): RefreshingTokenProvider<GoogleAccountGroup> {
  return new RefreshingTokenProvider<GoogleAccountGroup>(
    store,
    {
      name: 'Google',
      list: (d) => d.googleGroups,
      refresh: (g, refreshToken) => refreshAccessToken(upstream, g, refreshToken),
      // The label is user-supplied, so the command never contains it.
      reconnect: (id) => `\`perch google add --label <label>\` for the same Google account (renews the login of group ${id} for all of its services)`,
    },
    now,
  );
}

const registry = new WeakMap<CredentialStore, WeakMap<Upstream, RefreshingTokenProvider<GoogleAccountGroup>>>();

/**
 * The one group token provider per store and upstream. Drive, Gmail and Calendar/Contacts providers built on the
 * same store and upstream (as in createPerchContext) therefore share one cache and one in-flight refresh per group.
 */
export function googleGroupTokens(store: CredentialStore, upstream: Upstream): RefreshingTokenProvider<GoogleAccountGroup> {
  let byUpstream = registry.get(store);
  if (!byUpstream) registry.set(store, (byUpstream = new WeakMap()));
  let p = byUpstream.get(upstream);
  if (!p) byUpstream.set(upstream, (p = createGoogleGroupTokenProvider(store, upstream)));
  return p;
}

/** `shared` option of the per-family token providers: members of a group use the group's login. */
export function sharedGoogleLogin(store: CredentialStore, upstream: Upstream, source?: SharedTokenSource) {
  return { of: (a: { groupId?: string }) => a.groupId, source: source ?? googleGroupTokens(store, upstream) };
}
