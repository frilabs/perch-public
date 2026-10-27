import type { Principal } from '../auth/grants.js';
import { PerchError } from '../errors.js';
import { fanOut, type FanOutResult } from '../fanout.js';
import type { CredentialStore, GoogleProductivityAccount } from '../store/credentialStore.js';
import { UpstreamError, type Upstream } from '../upstream.js';
import { provenance, type Provenance } from './calendar.js';
import { bounded, ProductivityAccess, type ProductivityTokenSource } from './productivityAccess.js';

/**
 * Google People API v1, read-only (https://developers.google.com/people/api/rest/v1/people.connections/list,
 * https://developers.google.com/people/api/rest/v1/people/get). `personFields` is required by Google;
 * Perch accepts only an allowlisted subset and reads contact sources only (READ_SOURCE_TYPE_CONTACT).
 * There is no search: contacts_list pages through every contact.
 */

export const PERSON_FIELDS = [
  'names',
  'nicknames',
  'emailAddresses',
  'phoneNumbers',
  'organizations',
  'addresses',
  'birthdays',
  'biographies',
  'urls',
  'relations',
  'events',
  'memberships',
  'metadata',
] as const;
export type PersonField = (typeof PERSON_FIELDS)[number];
export const DEFAULT_PERSON_FIELDS: PersonField[] = ['names', 'emailAddresses', 'phoneNumbers', 'organizations'];
export const SORT_ORDERS = ['LAST_MODIFIED_ASCENDING', 'LAST_MODIFIED_DESCENDING', 'FIRST_NAME_ASCENDING', 'LAST_NAME_ASCENDING'] as const;
export const DEFAULT_CONTACTS_PAGE_SIZE = 50;
/** Google allows up to 1000 per page; Perch keeps tool output bounded. */
export const MAX_CONTACTS_PAGE_SIZE = 100;
/** Contact resource names only; never people/me or Google account ids (profile lookups). */
const CONTACT_RESOURCE = /^people\/c[0-9]{1,30}$/;

export type Contact = { resourceName: string; etag?: string } & Partial<Record<PersonField, unknown>>;

function personFields(list: string[] | undefined): PersonField[] {
  const fields = list ?? DEFAULT_PERSON_FIELDS;
  if (!fields.length) throw new PerchError('personFields must name at least one field', 'bad_argument');
  for (const f of fields) {
    if (!(PERSON_FIELDS as readonly string[]).includes(f)) throw new PerchError(`Unsupported personFields value: ${f} (use ${PERSON_FIELDS.join(', ')})`, 'bad_argument');
  }
  return [...new Set(fields)] as PersonField[];
}

function toContact(p: Record<string, unknown>, fields: PersonField[]): Contact {
  const out: Contact = { resourceName: String(p.resourceName) };
  if (typeof p.etag === 'string') out.etag = p.etag;
  for (const f of fields) if (p[f] !== undefined) out[f] = p[f];
  return out;
}

export class ContactsService {
  private readonly access: ProductivityAccess;

  constructor(
    private readonly store: CredentialStore,
    private readonly upstream: Upstream,
    tokens: ProductivityTokenSource,
  ) {
    this.access = new ProductivityAccess(store, tokens);
  }

  private async call<T>(account: GoogleProductivityAccount, path: string, query: Record<string, string | number | undefined>): Promise<T> {
    const headers = await this.access.authHeaders(account, 'contacts_read');
    try {
      return await this.upstream.json<T>('people', { method: 'GET', path, query, headers });
    } catch (err) {
      if (err instanceof UpstreamError && err.status === 401) this.access.invalidate(account.id);
      throw err;
    }
  }

  async list(
    principal: Principal,
    opts: { accountId?: string; personFields?: string[]; sortOrder?: string; pageSize?: number; cursor?: string },
  ): Promise<FanOutResult<Contact & Provenance>> {
    const fields = personFields(opts.personFields);
    const pageSize = bounded('pageSize', opts.pageSize, DEFAULT_CONTACTS_PAGE_SIZE, MAX_CONTACTS_PAGE_SIZE);
    if (opts.sortOrder !== undefined && !(SORT_ORDERS as readonly string[]).includes(opts.sortOrder)) {
      throw new PerchError(`sortOrder must be one of ${SORT_ORDERS.join(', ')}`, 'bad_argument');
    }
    const targets = opts.accountId ? [await this.access.account(principal, opts.accountId, 'contacts_read')] : await this.access.readable(principal, 'contacts_read');
    const byId = new Map(targets.map((a) => [a.id, a]));
    return fanOut({
      kind: 'contacts',
      queryKey: { f: fields, s: pageSize, o: opts.sortOrder ?? '', a: opts.accountId ?? '*' },
      sources: targets.map((a) => ({ id: a.id, label: a.label })),
      seal: this.store,
      ...(opts.cursor ? { cursor: opts.cursor } : {}),
      fetchPage: async (source, cursor) => {
        const account = byId.get(source.id)!;
        // Google requires every other parameter to match the first call when a pageToken is sent.
        const res = await this.call<{ connections?: Array<Record<string, unknown>>; nextPageToken?: string }>(account, '/v1/people/me/connections', {
          personFields: fields.join(','),
          pageSize,
          sources: 'READ_SOURCE_TYPE_CONTACT',
          sortOrder: opts.sortOrder,
          pageToken: cursor,
        });
        const items = (res.connections ?? [])
          .filter((p) => typeof p.resourceName === 'string')
          .map((p) => ({ ...provenance(account), ...toContact(p, fields) }));
        return { items, ...(res.nextPageToken ? { next: res.nextPageToken } : {}) };
      },
    });
  }

  async get(principal: Principal, opts: { accountId: string; resourceName: string; personFields?: string[] }): Promise<Contact & Provenance> {
    if (!CONTACT_RESOURCE.test(opts.resourceName)) {
      throw new PerchError('resourceName must be a contact resource name like people/c123 (from contacts_list)', 'bad_argument');
    }
    const fields = personFields(opts.personFields);
    const account = await this.access.account(principal, opts.accountId, 'contacts_read');
    const p = await this.call<Record<string, unknown>>(account, `/v1/${opts.resourceName}`, { personFields: fields.join(','), sources: 'READ_SOURCE_TYPE_CONTACT' });
    return { ...provenance(account), ...toContact({ ...p, resourceName: opts.resourceName }, fields) };
  }
}
