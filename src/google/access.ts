import { PerchError } from '../errors.js';
import { GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE } from '../mail/gmailAccounts.js';
import type { CredentialStore, GoogleAccountGroup, StoreData } from '../store/credentialStore.js';
import { GOOGLE_SERVICES, GOOGLE_SERVICE_TITLES, type GoogleGroupRequest, type GoogleService } from './group.js';
import { findGroup, groupMembers } from './groupStore.js';
import { DRIVE_READONLY_SCOPE, DRIVE_SCOPE } from './oauth.js';
import { CALENDAR_EVENTS_OWNED_SCOPE, CALENDAR_READONLY_SCOPE, CONTACTS_READONLY_SCOPE } from './productivity.js';

/**
 * Per-service rights of a Google account group (docs/GOOGLE_UNIFIED_SPEC.md, Nachtrag 2026-10-21): what each service
 * may do now, derived from the member records (scopes and opt-ins; the same fields the tools check), and the
 * `perch google access` changes. Granting needs a Google login for the same group; revoking is local (the member
 * drops the scopes/opt-in, so Perch's tools stop using them; the grant at Google stays until the next login).
 *
 * Write per service: Drive `drive`; Gmail drafts + send + organize (gmail.compose + gmail.modify); Calendar
 * `allowCalendarWrite` + calendar.events.owned (own events and invitations). Contacts are read-only in Perch.
 */

export interface ServiceRight {
  name: string;
  enabled: boolean;
  detail: string;
}

export interface ServiceAccess {
  service: GoogleService;
  /** Member account id; undefined when the group does not connect the service. */
  memberId?: string;
  rights: ServiceRight[];
  /** Write state: every write right on, some, none; 'n/a' for Contacts (read-only service). */
  write: 'full' | 'partial' | 'none' | 'n/a';
}

/** Services that have write access in Perch. */
export const WRITABLE_SERVICES: readonly GoogleService[] = ['drive', 'gmail', 'calendar'];

function writeState(rights: ServiceRight[]): ServiceAccess['write'] {
  const w = rights.filter((r) => r.name !== 'read');
  if (!w.length) return 'n/a';
  const on = w.filter((r) => r.enabled).length;
  return on === w.length ? 'full' : on ? 'partial' : 'none';
}

/** Rights of every Google service of group `groupId`, in canonical order (unconnected services without rights). */
export function groupAccess(data: StoreData, groupId: string): ServiceAccess[] {
  const m = groupMembers(data, groupId);
  const out: ServiceAccess[] = [];
  for (const service of GOOGLE_SERVICES) {
    let memberId: string | undefined;
    let rights: ServiceRight[] = [];
    if (service === 'drive' && m.drive) {
      memberId = m.drive.id;
      rights = [
        { name: 'read', enabled: true, detail: 'search, read, export files' },
        { name: 'write', enabled: m.drive.scopes.includes(DRIVE_SCOPE), detail: 'create, edit, share, trash' },
      ];
    } else if (service === 'gmail' && m.gmail) {
      const s = m.gmail.scopes;
      memberId = m.gmail.id;
      rights = [
        { name: 'read', enabled: true, detail: 'read, search mail' },
        { name: 'drafts', enabled: s.includes(GMAIL_COMPOSE_SCOPE), detail: 'create and change drafts' },
        { name: 'send', enabled: !m.gmail.draftsOnly && (s.includes(GMAIL_COMPOSE_SCOPE) || s.includes(GMAIL_SEND_SCOPE)), detail: 'send mail' },
        { name: 'organize', enabled: !m.gmail.draftsOnly && s.includes(GMAIL_MODIFY_SCOPE), detail: 'labels, archive, trash' },
      ];
    } else if ((service === 'calendar' || service === 'contacts') && m.productivity?.services.includes(service)) {
      const p = m.productivity;
      memberId = p.id;
      rights =
        service === 'calendar'
          ? [
              { name: 'read', enabled: p.scopes.includes(CALENDAR_READONLY_SCOPE), detail: 'read calendars and events' },
              { name: 'write', enabled: p.allowCalendarWrite && p.scopes.includes(CALENDAR_EVENTS_OWNED_SCOPE), detail: 'own events, invitations' },
            ]
          : [{ name: 'read', enabled: p.scopes.includes(CONTACTS_READONLY_SCOPE), detail: 'read contacts' }];
    }
    out.push({ service, ...(memberId ? { memberId } : {}), rights, write: memberId ? writeState(rights) : 'none' });
  }
  return out;
}

/** The command that changes one service of a group. */
export function accessCommand(groupId: string, service: GoogleService, change: 'write' | 'read-only' | 'add'): string {
  return change === 'add' ? `perch google access ${groupId} --add ${service}` : `perch google access ${groupId} --service ${service} --${change}`;
}

/**
 * The login request that keeps every connected service of the group as it is and applies `change` to `service`
 * (add it, or give it write access). The union of all scopes the group needs, so the new refresh token covers all.
 */
export function accessRequest(data: StoreData, groupId: string, service: GoogleService, write: boolean): GoogleGroupRequest {
  const access = groupAccess(data, groupId);
  const now = (s: GoogleService) => access.find((a) => a.service === s)!;
  const on = (s: GoogleService, right: string) => now(s).rights.some((r) => r.name === right && r.enabled);
  const req: GoogleGroupRequest = {
    services: GOOGLE_SERVICES.filter((s) => s === service || now(s).memberId),
    driveWrite: on('drive', 'write'),
    gmail: { drafts: on('gmail', 'drafts'), send: on('gmail', 'send'), modify: on('gmail', 'organize') },
    calendarWrite: on('calendar', 'write'),
  };
  if (write) {
    if (service === 'drive') req.driveWrite = true;
    if (service === 'gmail') req.gmail = { drafts: true, send: true, modify: true };
    if (service === 'calendar') req.calendarWrite = true;
  }
  return req;
}

/** Restrict an existing compose grant locally; false means OAuth must first grant drafts. */
export async function restrictGmailToDrafts(store: CredentialStore, groupId: string): Promise<boolean> {
  return store.update((data) => {
    if (!data.googleGroups.some(g => g.id === groupId)) throw new PerchError('Google account group changed meanwhile', 'account_changed');
    const gmail = groupMembers(data, groupId).gmail;
    if (!gmail) throw notConnected(groupId, 'gmail');
    if (!gmail.scopes.includes(GMAIL_COMPOSE_SCOPE)) return false;
    gmail.draftsOnly = true;
    gmail.updatedAt = new Date().toISOString();
    return true;
  });
}

/** Refusal for a separately connected account (own login, no group): name the commands that do apply. */
function separateAccountError(data: StoreData, id: string): PerchError | undefined {
  const legacy = data.google.find((a) => a.id === id && !a.groupId)
    ? { remove: `perch google remove ${id}`, how: 'reconnect it with the wanted --allow-write' }
    : data.gmail.find((a) => a.id === id && !a.groupId)
      ? { remove: `perch gmail remove ${id}`, how: 'perch gmail add --label NAME [--allow-drafts] [--allow-send] [--allow-modify]' }
      : data.googleProductivity.find((a) => a.id === id && !a.groupId)
        ? { remove: `perch google-productivity remove ${id}`, how: 'perch google-productivity add --label NAME --services calendar,contacts [--allow-calendar-write]' }
        : undefined;
  if (!legacy) return undefined;
  return new PerchError(
    `${id} is connected separately (its own login, not a Google account group), so perch google access does not apply. ` +
      `Change its permissions with its own commands (${legacy.remove}, then ${legacy.how}), or re-add it as a group: ` +
      `${legacy.remove}, then perch google add --label NAME (one login for Drive, Gmail, Calendar and Contacts).`,
    'bad_argument',
  );
}

/** The group behind a group id or member id; a clear error for separate accounts and unknown ids. */
export function resolveAccessGroup(data: StoreData, id: string): GoogleAccountGroup {
  const group = findGroup(data, id);
  if (group) return group;
  throw separateAccountError(data, id) ?? new PerchError(`Unknown Google account group or account: ${id} (perch google list shows the ids)`, 'unknown_account');
}

/** Refusals that need no store change: write on Contacts. */
export function assertWritable(service: GoogleService): void {
  if (!WRITABLE_SERVICES.includes(service)) {
    throw new PerchError(
      `${GOOGLE_SERVICE_TITLES[service]} are read-only in Perch (contacts.readonly); there is no write access to grant.`,
      'bad_argument',
    );
  }
}

const without = (scopes: readonly string[], drop: readonly string[]) => scopes.filter((s) => !drop.includes(s));

/**
 * Takes the write rights of one service away, locally and without a login: the member drops the write scopes (and
 * Calendar its opt-in), so Perch's tools refuse writes at once. Returns false when there was nothing to take away.
 */
export async function revokeServiceWrite(store: CredentialStore, groupId: string, service: GoogleService): Promise<boolean> {
  assertWritable(service);
  return store.update((d) => {
    const group = d.googleGroups.find((g) => g.id === groupId);
    if (!group) throw new PerchError(`Google account group ${groupId} was removed meanwhile`, 'account_changed');
    const m = groupMembers(d, groupId);
    const now = new Date().toISOString();
    if (service === 'drive') {
      if (!m.drive) throw notConnected(groupId, service);
      if (!m.drive.scopes.includes(DRIVE_SCOPE)) return false;
      let scopes = without(m.drive.scopes, [DRIVE_SCOPE]);
      // Read keeps working through the granted drive.readonly; record it when the member had only `drive`.
      if (!scopes.includes(DRIVE_READONLY_SCOPE) && group.scopes.includes(DRIVE_READONLY_SCOPE)) scopes = [DRIVE_READONLY_SCOPE, ...scopes];
      Object.assign(m.drive, { scopes, updatedAt: now });
      return true;
    }
    if (service === 'gmail') {
      if (!m.gmail) throw notConnected(groupId, service);
      const write = [GMAIL_COMPOSE_SCOPE, GMAIL_SEND_SCOPE, GMAIL_MODIFY_SCOPE];
      if (!m.gmail.scopes.some((s) => write.includes(s))) return false;
      Object.assign(m.gmail, { scopes: without(m.gmail.scopes, write), updatedAt: now });
      if (!m.gmail.scopes.includes(GMAIL_READONLY_SCOPE) && group.scopes.includes(GMAIL_READONLY_SCOPE)) m.gmail.scopes.unshift(GMAIL_READONLY_SCOPE);
      return true;
    }
    const p = m.productivity;
    if (!p?.services.includes('calendar')) throw notConnected(groupId, service);
    if (!p.allowCalendarWrite && !p.scopes.includes(CALENDAR_EVENTS_OWNED_SCOPE)) return false;
    Object.assign(p, { allowCalendarWrite: false, scopes: without(p.scopes, [CALENDAR_EVENTS_OWNED_SCOPE]), updatedAt: now });
    return true;
  });
}

export function notConnected(groupId: string, service: GoogleService): PerchError {
  return new PerchError(
    `${groupId} does not connect ${GOOGLE_SERVICE_TITLES[service]}. Add it: ${accessCommand(groupId, service, 'add')}`,
    'bad_argument',
  );
}
