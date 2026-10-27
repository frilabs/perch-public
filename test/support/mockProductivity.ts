/**
 * MOCK Google upstream for the Calendar/Contacts milestone: OAuth token endpoint, OpenID Connect
 * userinfo, Calendar v3 subset (calendarList, events list/get/insert/patch/delete, Meet createRequest,
 * attendeesOmitted response patches) and People v1 subset
 * (connections.list, people.get). In-memory fake of the documented HTTP API shapes; nothing here
 * talks to Google, and passing tests that use it are NOT evidence of a live integration.
 */
import { createHash } from 'node:crypto';
import type { UpstreamRequest, UpstreamResponse, UpstreamTransport } from '../../src/upstream.js';
import { dummySecret } from './fixtures.js';

export const SCOPE = {
  calendarRead: 'https://www.googleapis.com/auth/calendar.readonly',
  calendarOwned: 'https://www.googleapis.com/auth/calendar.events.owned',
  contactsRead: 'https://www.googleapis.com/auth/contacts.readonly',
  email: 'https://www.googleapis.com/auth/userinfo.email',
} as const;

export type MockEvent = Record<string, unknown> & { id: string; etag: string; status: string };

export interface MockCalendar {
  id: string;
  summary: string;
  timeZone: string;
  accessRole: 'owner' | 'writer' | 'reader' | 'freeBusyReader';
  primary?: boolean;
  events: MockEvent[];
}

export interface MockPerson {
  resourceName: string;
  etag: string;
  names?: Array<{ displayName?: string; givenName?: string; familyName?: string }>;
  emailAddresses?: Array<{ value: string; type?: string }>;
  phoneNumbers?: Array<{ value: string; type?: string }>;
  organizations?: Array<{ name?: string; title?: string }>;
  biographies?: Array<{ value: string }>;
}

export interface MockProdAccount {
  sub: string;
  email: string;
  emailVerified: boolean;
  refreshToken: string;
  calendars: MockCalendar[];
  contacts: MockPerson[];
}

/** A one-shot fault injected for the next request matching `match`. */
export interface Fault {
  match: (req: UpstreamRequest) => boolean;
  /** 'network' throws after recording the call (outcome unknown to the client). */
  mode: 'network' | 'status';
  status?: number;
  body?: unknown;
  /** Apply the write before failing (simulates a lost response after a committed write). */
  commitFirst?: boolean;
}

const json = (status: number, body: unknown): UpstreamResponse => ({
  status,
  headers: { 'content-type': 'application/json' },
  body: Buffer.from(JSON.stringify(body)),
});
const gErr = (status: number, reason: string) => json(status, { error: { code: status, message: `MOCK ${reason}`, errors: [{ reason, message: 'MOCK detail' }] } });

let etagCounter = 1000;
const nextEtag = () => `"${++etagCounter}"`;

export class MockGoogleProductivity {
  readonly calls: UpstreamRequest[] = [];
  readonly accounts: MockProdAccount[] = [];
  readonly codes = new Map<string, { challenge: string; redirectUri: string; account: MockProdAccount; scope: string }>();
  readonly accessTokens = new Map<string, { account: MockProdAccount; scope: string }>();
  readonly revoked: string[] = [];
  faults: Fault[] = [];
  /** Scope string the token endpoint reports; default = everything that was requested. */
  grantedScopeOverride?: string;
  /** Scope string reported by refresh_token grants (simulates a later partial revocation). */
  refreshScopeOverride?: string;
  omitRefreshToken = false;
  pageSize = 2;

  addAccount(email: string, opts: Partial<Omit<MockProdAccount, 'email'>> = {}): MockProdAccount {
    const acct: MockProdAccount = {
      sub: opts.sub ?? String(100000000000000000000n + BigInt(this.accounts.length + 1)),
      email,
      emailVerified: opts.emailVerified ?? true,
      refreshToken: opts.refreshToken ?? dummySecret('PROD-REFRESH'),
      calendars: opts.calendars ?? [{ id: email, summary: email, timeZone: 'Europe/Vienna', accessRole: 'owner', primary: true, events: [] }],
      contacts: opts.contacts ?? [],
    };
    this.accounts.push(acct);
    return acct;
  }

  approve(authUrl: string, account: MockProdAccount): string {
    const u = new URL(authUrl);
    const code = dummySecret('AUTHCODE');
    this.codes.set(code, {
      challenge: u.searchParams.get('code_challenge')!,
      redirectUri: u.searchParams.get('redirect_uri')!,
      account,
      scope: u.searchParams.get('scope')!,
    });
    return code;
  }

  /** Issues an access token as if `scope` had been granted (Google echoes `email` as userinfo.email). */
  issueAccessToken(account: MockProdAccount, scope: string): string {
    const t = dummySecret('PROD-ACCESS');
    this.accessTokens.set(t, { account, scope });
    return t;
  }

  calendarWrites(): UpstreamRequest[] {
    return this.calls.filter((c) => c.url.pathname.startsWith('/calendar/') && c.method !== 'GET');
  }

  transport: UpstreamTransport = async (req) => {
    this.calls.push(req);
    const i = this.faults.findIndex((f) => f.match(req));
    const fault = i >= 0 ? this.faults.splice(i, 1)[0] : undefined;
    if (fault && !fault.commitFirst) return this.fail(fault);
    const res = this.route(req);
    if (fault) return this.fail(fault);
    return res;
  };

  private fail(f: Fault): UpstreamResponse {
    if (f.mode === 'network') throw new Error('MOCK socket hang up');
    return json(f.status ?? 500, f.body ?? { error: { code: f.status ?? 500, message: 'MOCK', errors: [{ reason: 'backendError' }] } });
  }

  private route(req: UpstreamRequest): UpstreamResponse {
    const { origin, pathname } = req.url;
    if (origin === 'https://oauth2.googleapis.com') return this.oauth(req, pathname);
    const auth = this.accessTokens.get((req.headers.authorization ?? '').replace(/^Bearer /, ''));
    if (!auth) return json(401, { error: { code: 401, status: 'UNAUTHENTICATED', message: 'MOCK' } });
    if (origin === 'https://openidconnect.googleapis.com' && pathname === '/v1/userinfo') {
      if (!/(^| )(email|https:\/\/www\.googleapis\.com\/auth\/userinfo\.email)( |$)/.test(auth.scope)) return json(401, { error: 'invalid_request' });
      return json(200, { sub: auth.account.sub, email: auth.account.email, email_verified: auth.account.emailVerified });
    }
    if (origin === 'https://www.googleapis.com' && pathname.startsWith('/calendar/v3/')) return this.calendar(req, pathname, auth);
    if (origin === 'https://people.googleapis.com') return this.people(req, pathname, auth);
    return json(404, { error: { code: 404, errors: [{ reason: 'notFound' }] } });
  }

  private oauth(req: UpstreamRequest, pathname: string): UpstreamResponse {
    const form = new URLSearchParams(req.body ?? '');
    if (pathname === '/revoke') {
      this.revoked.push(form.get('token') ?? '');
      return json(200, {});
    }
    if (form.get('grant_type') === 'authorization_code') {
      const pending = this.codes.get(form.get('code') ?? '');
      if (!pending) return json(400, { error: 'invalid_grant' });
      this.codes.delete(form.get('code')!);
      const challenge = createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url');
      if (challenge !== pending.challenge) return json(400, { error: 'invalid_grant' });
      if (form.get('redirect_uri') !== pending.redirectUri) return json(400, { error: 'redirect_uri_mismatch' });
      // Google reports `email` as the userinfo.email URL.
      const scope = this.grantedScopeOverride ?? pending.scope.replace(/(^| )email( |$)/, `$1${SCOPE.email}$2`);
      return json(200, {
        access_token: this.issueAccessToken(pending.account, scope),
        expires_in: 3599,
        scope,
        token_type: 'Bearer',
        id_token: 'MOCK.ID.TOKEN',
        ...(this.omitRefreshToken ? {} : { refresh_token: pending.account.refreshToken }),
      });
    }
    if (form.get('grant_type') === 'refresh_token') {
      const acct = this.accounts.find((a) => a.refreshToken === form.get('refresh_token'));
      if (!acct) return json(400, { error: 'invalid_grant' });
      const scope = this.refreshScopeOverride ?? `openid ${SCOPE.email} ${SCOPE.calendarRead} ${SCOPE.contactsRead} ${SCOPE.calendarOwned}`;
      return json(200, { access_token: this.issueAccessToken(acct, scope), expires_in: 3599, scope, token_type: 'Bearer' });
    }
    return json(400, { error: 'unsupported_grant_type' });
  }

  private calendar(req: UpstreamRequest, pathname: string, auth: { account: MockProdAccount; scope: string }): UpstreamResponse {
    const has = (s: string) => auth.scope.split(' ').includes(s);
    const q = req.url.searchParams;
    const acct = auth.account;
    if (pathname === '/calendar/v3/users/me/calendarList') {
      if (!has(SCOPE.calendarRead)) return gErr(403, 'insufficientPermissions');
      const size = Math.min(Number(q.get('maxResults') ?? 100), this.pageSize);
      const start = Number(q.get('pageToken') ?? 0);
      const items = acct.calendars.slice(start, start + size).map((c) => ({
        kind: 'calendar#calendarListEntry',
        id: c.id,
        summary: c.summary,
        timeZone: c.timeZone,
        accessRole: c.accessRole,
        ...(c.primary ? { primary: true } : {}),
        etag: '"mock"',
      }));
      const next = start + size < acct.calendars.length ? String(start + size) : undefined;
      return json(200, { kind: 'calendar#calendarList', items, ...(next ? { nextPageToken: next } : {}) });
    }
    const m = /^\/calendar\/v3\/calendars\/([^/]+)\/events(?:\/([^/]+))?$/.exec(pathname);
    if (!m) return gErr(404, 'notFound');
    const calId = decodeURIComponent(m[1]!);
    const cal = calId === 'primary' ? acct.calendars.find((c) => c.primary) : acct.calendars.find((c) => c.id === calId);
    if (!cal) return gErr(404, 'notFound');
    const eventId = m[2];
    if (req.method === 'GET') {
      if (!has(SCOPE.calendarRead) && !has(SCOPE.calendarOwned)) return gErr(403, 'insufficientPermissions');
      if (eventId) {
        const ev = cal.events.find((e) => e.id === eventId);
        return ev ? json(200, ev) : gErr(404, 'notFound');
      }
      if (q.get('orderBy') === 'startTime' && q.get('singleEvents') !== 'true') return gErr(400, 'badRequest');
      const startOf = (e: MockEvent) => {
        const s = e.start as { date?: string; dateTime?: string };
        return Date.parse(s.dateTime ?? `${s.date}T00:00:00Z`);
      };
      const endOf = (e: MockEvent) => {
        const s = e.end as { date?: string; dateTime?: string };
        return Date.parse(s.dateTime ?? `${s.date}T00:00:00Z`);
      };
      let list = cal.events.filter((e) => e.status !== 'cancelled' || q.get('showDeleted') === 'true');
      const tMin = q.get('timeMin');
      const tMax = q.get('timeMax');
      if (tMin) list = list.filter((e) => endOf(e) > Date.parse(tMin));
      if (tMax) list = list.filter((e) => startOf(e) < Date.parse(tMax));
      const term = q.get('q');
      if (term) list = list.filter((e) => String(e.summary ?? '').toLowerCase().includes(term.toLowerCase()));
      list = [...list].sort((a, b) => startOf(a) - startOf(b));
      const size = Math.min(Number(q.get('maxResults') ?? 250), this.pageSize);
      const start = Number(q.get('pageToken') ?? 0);
      const items = list.slice(start, start + size);
      const next = start + size < list.length ? String(start + size) : undefined;
      return json(200, { kind: 'calendar#events', timeZone: cal.timeZone, accessRole: cal.accessRole, items, ...(next ? { nextPageToken: next } : {}) });
    }
    if (!has(SCOPE.calendarOwned)) return gErr(403, 'insufficientPermissions');
    if (cal.accessRole !== 'owner') return gErr(403, 'forbidden');
    const body = JSON.parse(req.body ?? '{}') as Record<string, unknown>;
    // Google ignores conferenceData unless conferenceDataVersion=1; a createRequest yields a Meet link.
    const conference = (ev: Record<string, unknown>) => {
      const cd = body.conferenceData as { createRequest?: { requestId?: string } } | undefined;
      delete ev.conferenceData;
      if (q.get('conferenceDataVersion') === '1' && cd?.createRequest?.requestId) {
        const code = createHash('sha256').update(cd.createRequest.requestId).digest('hex').slice(0, 10);
        ev.hangoutLink = `https://meet.google.com/${code}`;
        ev.conferenceData = { conferenceId: code, createRequest: { ...cd.createRequest, status: { statusCode: 'success' } }, entryPoints: [{ entryPointType: 'video', uri: ev.hangoutLink }] };
      }
    };
    if (req.method === 'DELETE' && eventId) {
      const i = cal.events.findIndex((e) => e.id === eventId);
      if (i < 0) return gErr(404, 'notFound');
      if (cal.events[i]!.status === 'cancelled') return gErr(410, 'deleted');
      const ifMatch = req.headers['if-match'];
      if (ifMatch !== undefined && ifMatch !== cal.events[i]!.etag) return gErr(412, 'conditionNotMet');
      cal.events.splice(i, 1);
      return { status: 204, headers: {}, body: Buffer.alloc(0) };
    }
    if (req.method === 'POST' && !eventId) {
      const id = typeof body.id === 'string' ? body.id : `mock${(++etagCounter).toString(32)}`;
      if (cal.events.some((e) => e.id === id)) return gErr(409, 'duplicate');
      const ev: MockEvent = {
        kind: 'calendar#event',
        ...body,
        id,
        etag: nextEtag(),
        status: 'confirmed',
        htmlLink: `https://www.google.com/calendar/event?eid=${id}`,
        created: '2026-10-05T10:00:00.000Z',
        updated: '2026-10-05T10:00:00.000Z',
        creator: { email: acct.email, self: true },
        organizer: { email: cal.id, self: true },
        iCalUID: `${id}@google.com`,
      };
      conference(ev);
      cal.events.push(ev);
      return json(200, ev);
    }
    if (req.method === 'PATCH' && eventId) {
      const ev = cal.events.find((e) => e.id === eventId);
      if (!ev) return gErr(404, 'notFound');
      const ifMatch = req.headers['if-match'];
      if (ifMatch !== undefined && ifMatch !== ev.etag) return gErr(412, 'conditionNotMet');
      // Google patch semantics: nested objects are merged field by field, arrays are replaced
      // (https://developers.google.com/workspace/calendar/api/guides/performance#patch).
      const hadConference = ev.conferenceData;
      if (body.attendeesOmitted === true && Array.isArray(body.attendees)) {
        // Only the given entries change (matched by email); the rest of the guest list stays.
        const list = Array.isArray(ev.attendees) ? (ev.attendees as Array<Record<string, unknown>>) : [];
        for (const a of body.attendees as Array<Record<string, unknown>>) {
          const cur = list.find((x) => String(x.email).toLowerCase() === String(a.email).toLowerCase());
          if (!cur) return gErr(403, 'forbiddenForNonOrganizer');
          Object.assign(cur, a);
        }
        delete body.attendees;
        delete body.attendeesOmitted;
      }
      for (const [k, v] of Object.entries(body)) {
        const cur = (ev as Record<string, unknown>)[k];
        const isObj = (x: unknown) => !!x && typeof x === 'object' && !Array.isArray(x);
        (ev as Record<string, unknown>)[k] = isObj(v) && isObj(cur) ? { ...(cur as object), ...(v as object) } : v;
      }
      if (body.conferenceData !== undefined) conference(ev);
      else if (hadConference) ev.conferenceData = hadConference;
      Object.assign(ev, { etag: nextEtag(), updated: '2026-10-05T11:00:00.000Z' });
      return json(200, ev);
    }
    return gErr(400, 'badRequest');
  }

  private people(req: UpstreamRequest, pathname: string, auth: { account: MockProdAccount; scope: string }): UpstreamResponse {
    if (!auth.scope.split(' ').includes(SCOPE.contactsRead)) return json(403, { error: { code: 403, status: 'PERMISSION_DENIED', message: 'MOCK' } });
    const q = req.url.searchParams;
    const fields = q.get('personFields');
    if (!fields) return json(400, { error: { code: 400, status: 'INVALID_ARGUMENT', message: 'MOCK personFields required' } });
    const pick = (p: MockPerson) => {
      const out: Record<string, unknown> = { resourceName: p.resourceName, etag: p.etag };
      for (const f of fields.split(',')) if (f in p) out[f] = (p as unknown as Record<string, unknown>)[f];
      return out;
    };
    if (pathname === '/v1/people/me/connections') {
      const size = Math.min(Number(q.get('pageSize') ?? 100), this.pageSize);
      const start = Number(q.get('pageToken') ?? 0);
      const list = auth.account.contacts;
      const next = start + size < list.length ? String(start + size) : undefined;
      return json(200, {
        connections: list.slice(start, start + size).map(pick),
        totalItems: list.length,
        ...(next ? { nextPageToken: next } : {}),
      });
    }
    const m = /^\/v1\/(people\/c[0-9]+)$/.exec(pathname);
    const person = m && auth.account.contacts.find((p) => p.resourceName === m[1]);
    if (!person) return json(404, { error: { code: 404, status: 'NOT_FOUND', message: 'MOCK' } });
    return json(200, pick(person));
  }
}

/** All-day and timed events used across tests (dummy data). */
export function sampleEvents(): MockEvent[] {
  return [
    {
      id: 'evt0allday01',
      etag: '"1"',
      status: 'confirmed',
      summary: 'Dummy all-day',
      start: { date: '2026-10-06' },
      end: { date: '2026-10-07' },
      organizer: { email: 'dummy.a@example.test', self: true },
    },
    {
      id: 'evt0timed002',
      etag: '"2"',
      status: 'confirmed',
      summary: 'Dummy timed',
      start: { dateTime: '2026-10-06T09:00:00+02:00', timeZone: 'Europe/Vienna' },
      end: { dateTime: '2026-10-06T10:00:00+02:00', timeZone: 'Europe/Vienna' },
      organizer: { email: 'dummy.a@example.test', self: true },
    },
    {
      id: 'evt0guests03',
      etag: '"3"',
      status: 'confirmed',
      summary: 'Dummy meeting with guests',
      start: { dateTime: '2026-10-07T15:00:00Z' },
      end: { dateTime: '2026-10-07T16:00:00Z' },
      organizer: { email: 'dummy.a@example.test', self: true },
      attendees: [
        { email: 'dummy.a@example.test', self: true, responseStatus: 'accepted' },
        { email: 'guest@example.test', responseStatus: 'needsAction' },
      ],
    },
  ];
}
