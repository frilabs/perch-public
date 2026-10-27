import { assertProductivityCapability, type Principal } from '../auth/grants.js';
import { PerchError } from '../errors.js';
import type { CredentialStore, GoogleProductivityAccount, ProductivityCapability } from '../store/credentialStore.js';
import {
  CALENDAR_EVENTS_OWNED_SCOPE,
  CALENDAR_READONLY_SCOPE,
  CONTACTS_READONLY_SCOPE,
  productivityCapabilities,
  type ProductivityCapabilities,
} from './productivity.js';

export interface ProductivityTokenSource {
  getAccessToken(id: string): Promise<string>;
  lastGrantedScopes?(id: string): string[] | undefined;
  invalidate?(id: string): void;
}

type Need = keyof ProductivityCapabilities;

const NEED: Record<ProductivityCapability, Need> = {
  calendar_read: 'calendarRead',
  calendar_write: 'calendarWrite',
  // Invitations use the same Google permission as other event writes (calendar.events.owned).
  calendar_invite: 'calendarWrite',
  contacts_read: 'contactsRead',
};

const SCOPE_OF: Record<Need, string> = {
  calendarRead: CALENDAR_READONLY_SCOPE,
  contactsRead: CONTACTS_READONLY_SCOPE,
  calendarWrite: CALENDAR_EVENTS_OWNED_SCOPE,
};

/** Members of a Google account group are updated in place by re-adding the account; separate ones are replaced. */
const reconnect = (a: { id: string; groupId?: string }, opt: string) =>
  a.groupId
    ? `perch google add --label <label> ${opt} (updates group ${a.groupId}, same account ids)`
    : `perch google-productivity remove ${a.id}, then perch google add --label <label> ${opt}`;

function notConnected(a: { id: string; groupId?: string }, need: Need): PerchError {
  if (need === 'calendarWrite') {
    return new PerchError(
      `Account ${a.id} was not authorised for calendar writes at Google. Reconnect: ${reconnect(a, '--services calendar --allow-calendar-write')}`,
      'provider_scope_missing',
    );
  }
  const service = need === 'calendarRead' ? 'calendar' : 'contacts';
  return new PerchError(`Account ${a.id} is not connected for ${service}. Reconnect: ${reconnect(a, `--services ${service}`)}`, 'provider_scope_missing');
}

/**
 * Authorization for Calendar/Contacts, always before provider I/O and in this order:
 * 1. the principal holds the capability for the account (a client cannot tell an ungranted id from a
 *    nonexistent one), 2. the account exists, 3. the onboarding selection plus the scope Google granted
 *    allow it, 4. right before the request, the scopes Google reported with the current access token.
 */
export class ProductivityAccess {
  constructor(
    private readonly store: CredentialStore,
    private readonly tokens: ProductivityTokenSource,
  ) {}

  async account(principal: Principal, accountId: string, cap: ProductivityCapability): Promise<GoogleProductivityAccount> {
    assertProductivityCapability(principal, accountId, cap);
    const account = (await this.store.read()).googleProductivity.find((a) => a.id === accountId);
    if (!account) throw new PerchError(`Unknown Google productivity account: ${accountId}`, 'unknown_account');
    if (!productivityCapabilities(account)[NEED[cap]]) throw notConnected(account, NEED[cap]);
    return account;
  }

  /** Accounts a fan-out covers: granted to the principal for `cap` and connected for that service. */
  async readable(principal: Principal, cap: ProductivityCapability): Promise<GoogleProductivityAccount[]> {
    if (!principal.capabilities.has(cap)) return [];
    return (await this.store.read()).googleProductivity.filter(
      (a) =>
        (principal.productivityAccounts === 'all' || principal.productivityAccounts.has(a.id)) && productivityCapabilities(a)[NEED[cap]],
    );
  }

  /** Bearer header for `account`; fails closed if Google no longer reports the needed scope. */
  async authHeaders(account: GoogleProductivityAccount, cap: ProductivityCapability): Promise<Record<string, string>> {
    const token = await this.tokens.getAccessToken(account.id);
    const live = this.tokens.lastGrantedScopes?.(account.id);
    const need = NEED[cap];
    if (!productivityCapabilities(account, live)[need]) {
      throw new PerchError(
        `Google no longer reports the ${SCOPE_OF[need]} permission for ${account.id}; no request was made. Reconnect: ` +
          reconnect(account, need === 'calendarWrite' ? '--services calendar --allow-calendar-write' : `--services ${need === 'calendarRead' ? 'calendar' : 'contacts'}`),
        'provider_scope_missing',
      );
    }
    return { authorization: `Bearer ${token}` };
  }

  invalidate(accountId: string): void {
    this.tokens.invalidate?.(accountId);
  }
}

export function bounded(name: string, value: number | undefined, def: number, max: number): number {
  const n = value ?? def;
  if (!Number.isInteger(n) || n < 1 || n > max) throw new PerchError(`${name} must be between 1 and ${max}`, 'bad_argument');
  return n;
}

/**
 * Account metadata for perch_list_accounts. The operator sees every account (read-only grants); a client
 * sees only the accounts in its grant, and per account only the services its capabilities cover.
 */
export async function listProductivityAccounts(store: CredentialStore, principal: Principal) {
  const operator = principal.kind === 'operator_readonly';
  const caps = (['calendar_read', 'calendar_write', 'calendar_invite', 'contacts_read'] as const).filter((c) => principal.capabilities.has(c));
  const visible = (id: string) => principal.productivityAccounts === 'all' || principal.productivityAccounts.has(id);
  return (await store.read()).googleProductivity.filter((a) => visible(a.id)).map((a) => {
    const provider = productivityCapabilities(a);
    const shown = operator ? (Object.keys(provider) as Need[]) : caps.map((c) => NEED[c]);
    const services = a.services.filter((s) => operator || (s === 'calendar' ? caps.some((c) => c.startsWith('calendar')) : caps.includes('contacts_read')));
    return {
      accountId: a.id,
      label: a.label,
      email: a.email,
      provider: 'google' as const,
      services,
      providerCapabilities: Object.fromEntries(shown.map((k) => [k, provider[k]])),
      granted: [...caps].sort(),
      ...(operator ? { scopes: a.scopes } : {}),
      connectedAt: a.createdAt,
    };
  });
}
