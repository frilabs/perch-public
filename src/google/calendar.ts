import type { Principal } from '../auth/grants.js';
import { PerchError } from '../errors.js';
import { fanOut, type FanOutResult } from '../fanout.js';
import type { CredentialStore, GoogleProductivityAccount } from '../store/credentialStore.js';
import { UpstreamError, type CallOptions, type Upstream } from '../upstream.js';
import { assertTimestamp, assertTimeZone } from './calendarTime.js';
import {
  assertOwnEvent,
  buildCreateBody,
  guestsOf,
  parseCreateInput,
  parseDeleteInput,
  parseRespondInput,
  parseUpdateInput,
  planPatch,
  SINGLE_OCCURRENCE_REFUSED,
  type SendUpdates,
} from './calendarWrite.js';
import { bounded, ProductivityAccess, type ProductivityTokenSource } from './productivityAccess.js';

/**
 * Google Calendar v3 (https://developers.google.com/workspace/calendar/api/v3/reference):
 * calendarList.list (maxResults default 100, max 250), events.list (default 250, max 2500; orderBy
 * startTime only with singleEvents=true; timeMin/timeMax RFC 3339 with offset), events.get.
 */

export const DEFAULT_CALENDAR_PAGE_SIZE = 25;
export const MAX_CALENDAR_PAGE_SIZE = 100;
/** Descriptions are free text (may contain HTML); bounded per event in tool output. */
export const MAX_DESCRIPTION_CHARS = 8192;
const MAX_ATTENDEES_SHOWN = 50;

const CALENDAR_ID = /^(?=.{1,255}$)[A-Za-z0-9._+#-]+(?:@[A-Za-z0-9._-]+)?$/;
/** Same shape as the Upstream allowlist: base32hex plus optional recurring-instance suffix. */
const EVENT_ID = /^(?!import$|quickAdd$|watch$)[a-v0-9]{5,1024}(?:_[0-9]{8}(?:T[0-9]{6}Z)?)?$/;

export function checkCalendarId(id: string): string {
  if (!CALENDAR_ID.test(id) || id.includes('..')) throw new PerchError('Invalid calendar id (use primary or an id from calendar_list_calendars)', 'bad_argument');
  return id;
}

export function checkEventId(id: string): string {
  if (!EVENT_ID.test(id)) throw new PerchError('Invalid event id (use an eventId returned by Perch)', 'bad_argument');
  return id;
}

export const eventsPath = (calendarId: string) => `/calendar/v3/calendars/${encodeURIComponent(checkCalendarId(calendarId))}/events`;
export const eventPath = (calendarId: string, eventId: string) => `${eventsPath(calendarId)}/${checkEventId(eventId)}`;

export interface EventTime {
  date?: string;
  dateTime?: string;
  timeZone?: string;
}

interface Person {
  email?: string;
  displayName?: string;
  self?: boolean;
}

export interface GoogleEvent {
  id?: string;
  etag?: string;
  status?: string;
  summary?: string;
  description?: string;
  location?: string;
  htmlLink?: string;
  created?: string;
  updated?: string;
  start?: EventTime;
  end?: EventTime;
  recurringEventId?: string;
  originalStartTime?: EventTime;
  organizer?: Person;
  creator?: Person;
  attendees?: Array<Person & { responseStatus?: string; optional?: boolean; organizer?: boolean; resource?: boolean; comment?: string; additionalGuests?: number }>;
  recurrence?: unknown;
  conferenceData?: unknown;
  eventType?: string;
  visibility?: string;
  transparency?: string;
  hangoutLink?: string;
  reminders?: { useDefault?: boolean; overrides?: Array<{ method?: string; minutes?: number }> };
}

export interface CalendarEvent {
  calendarId: string;
  eventId: string;
  etag?: string;
  status?: string;
  summary?: string;
  description?: string;
  descriptionTruncated?: true;
  location?: string;
  allDay: boolean;
  start?: EventTime;
  end?: EventTime;
  /** All-day events: end.date is the day after the last day (exclusive). */
  endExclusive?: true;
  calendarTimeZone?: string;
  htmlLink?: string;
  created?: string;
  updated?: string;
  recurringEventId?: string;
  /** RRULE/EXDATE/RDATE lines of a series (the series event itself, not its expanded occurrences). */
  recurrence?: string[];
  originalStartTime?: EventTime;
  organizer?: Person;
  creator?: Person;
  attendees?: Array<Record<string, unknown>>;
  attendeesOmitted?: number;
  eventType?: string;
  visibility?: string;
  transparency?: string;
  hangoutLink?: string;
  reminders?: GoogleEvent['reminders'];
}

const str = (v: unknown) => (typeof v === 'string' ? v : undefined);

function time(t: EventTime | undefined): EventTime | undefined {
  if (!t || typeof t !== 'object') return undefined;
  const out: EventTime = {};
  if (str(t.date)) out.date = t.date!;
  if (str(t.dateTime)) out.dateTime = t.dateTime!;
  if (str(t.timeZone)) out.timeZone = t.timeZone!;
  return out;
}

function person(p: Person | undefined): Person | undefined {
  if (!p || typeof p !== 'object') return undefined;
  const out: Person = {};
  if (str(p.email)) out.email = p.email!;
  if (str(p.displayName)) out.displayName = p.displayName!;
  if (p.self === true) out.self = true;
  return out;
}

/** Normalised event: start/end exactly as Google sent them, plus allDay/endExclusive and bounded text. */
export function toEvent(e: GoogleEvent, calendarId: string, calendarTimeZone?: string): CalendarEvent {
  const start = time(e.start);
  const allDay = !!start?.date && !start.dateTime;
  const out: CalendarEvent = { calendarId, eventId: str(e.id) ?? '', allDay };
  const copy = ['etag', 'status', 'summary', 'location', 'htmlLink', 'created', 'updated', 'recurringEventId', 'eventType', 'visibility', 'transparency', 'hangoutLink'] as const;
  for (const k of copy) if (str(e[k])) out[k] = e[k]!;
  if (str(e.description)) {
    out.description = e.description!.length > MAX_DESCRIPTION_CHARS ? e.description!.slice(0, MAX_DESCRIPTION_CHARS) : e.description!;
    if (e.description!.length > MAX_DESCRIPTION_CHARS) out.descriptionTruncated = true;
  }
  if (start) out.start = start;
  if (Array.isArray(e.recurrence)) out.recurrence = e.recurrence.filter((l): l is string => typeof l === 'string').slice(0, 10).map((l) => l.slice(0, 1000));
  const end = time(e.end);
  if (end) out.end = end;
  if (allDay) out.endExclusive = true;
  if (calendarTimeZone) out.calendarTimeZone = calendarTimeZone;
  const ost = time(e.originalStartTime);
  if (ost) out.originalStartTime = ost;
  const organizer = person(e.organizer);
  if (organizer) out.organizer = organizer;
  const creator = person(e.creator);
  if (creator) out.creator = creator;
  if (Array.isArray(e.attendees)) {
    out.attendees = e.attendees.slice(0, MAX_ATTENDEES_SHOWN).map((a) => {
      const r: Record<string, unknown> = { ...person(a) };
      if (str(a.responseStatus)) r.responseStatus = a.responseStatus;
      if (a.optional === true) r.optional = true;
      if (a.organizer === true) r.organizer = true;
      if (a.resource === true) r.resource = true;
      return r;
    });
    if (e.attendees.length > MAX_ATTENDEES_SHOWN) out.attendeesOmitted = e.attendees.length - MAX_ATTENDEES_SHOWN;
  }
  if (e.reminders && typeof e.reminders === 'object') out.reminders = e.reminders;
  return out;
}

export interface CalendarSummary {
  calendarId: string;
  summary?: string;
  description?: string;
  timeZone?: string;
  accessRole?: string;
  primary?: true;
}

export interface Provenance {
  accountId: string;
  accountLabel: string;
  email: string;
  provider: 'google';
}

export const provenance = (a: GoogleProductivityAccount): Provenance => ({ accountId: a.id, accountLabel: a.label, email: a.email, provider: 'google' });

export interface ListEventsOptions {
  accountId?: string;
  calendarId?: string;
  timeMin?: string;
  timeMax?: string;
  query?: string;
  timeZone?: string;
  pageSize?: number;
  cursor?: string;
}

const ACCEPTED_NOTE = 'Accepted by Google; that is not a sync or delivery confirmation for other devices or guests.';

/** What Google was asked to send, for the result detail. */
function notifyNote(guests: boolean, sendUpdates: SendUpdates): string {
  if (!guests) return `No invitations or updates were sent to anyone (no guests; sendUpdates=none). Reminders are popup-only. ${ACCEPTED_NOTE}`;
  if (sendUpdates === 'none') return `Guests were NOT notified (sendUpdates=none); their calendars may be out of date. ${ACCEPTED_NOTE}`;
  return `Google was asked to email ${sendUpdates === 'all' ? 'all guests' : 'guests outside your organisation (externalOnly)'} (sendUpdates=${sendUpdates}). ${ACCEPTED_NOTE}`;
}

export interface CreateEventResult extends Provenance {
  status: 'created' | 'conflict' | 'rejected' | 'indeterminate';
  requestId: string;
  calendarId: string;
  eventId: string;
  sendUpdates: SendUpdates;
  event?: CalendarEvent;
  detail: string;
}

export interface UpdateEventResult extends Provenance {
  status: 'updated' | 'precondition_failed' | 'rejected' | 'indeterminate';
  calendarId: string;
  eventId: string;
  sendUpdates?: SendUpdates;
  event?: CalendarEvent;
  currentEtag?: string;
  detail: string;
}

export interface DeleteEventResult extends Provenance {
  status: 'deleted' | 'not_found' | 'precondition_failed' | 'rejected' | 'indeterminate';
  calendarId: string;
  eventId: string;
  sendUpdates?: SendUpdates;
  currentEtag?: string;
  detail: string;
}

export interface RespondEventResult extends Provenance {
  status: 'responded' | 'precondition_failed' | 'rejected' | 'indeterminate';
  calendarId: string;
  eventId: string;
  response: string;
  sendUpdates: SendUpdates;
  event?: CalendarEvent;
  detail: string;
}

const INDETERMINATE =
  'Outcome unknown (network error, timeout or Google server error after the request was sent); Perch did not retry. ';

type WriteOutcome = { ok: true; body: Buffer } | { ok: false; status: number; message: string } | { ok: false; status: 'unknown' };

/** Splits `<base64url timeMin>.<fan-out cursor>`; an explicit timeMin must match the cursor's. */
function splitEventsCursor(cursor: string | undefined, explicit: string | undefined): { timeMin: string; inner?: string } {
  if (!cursor) return { timeMin: explicit ?? new Date().toISOString() };
  const m = /^([A-Za-z0-9_-]{1,200})\.([A-Za-z0-9_~-]+)$/.exec(cursor);
  const timeMin = m ? Buffer.from(m[1]!, 'base64url').toString('utf8') : '';
  if (!m || (explicit !== undefined && explicit !== timeMin)) throw new PerchError('Cursor does not belong to this query; repeat the same arguments', 'bad_cursor');
  return { timeMin, inner: m[2]! };
}

/** Calendar operations with provenance; every call is authorised before any provider I/O. */
export class CalendarService {
  protected readonly access: ProductivityAccess;

  constructor(
    protected readonly store: CredentialStore,
    protected readonly upstream: Upstream,
    tokens: ProductivityTokenSource,
  ) {
    this.access = new ProductivityAccess(store, tokens);
  }

  /** Authorised JSON call; a 401 drops the cached access token (never retried here). */
  protected async call<T>(account: GoogleProductivityAccount, cap: 'calendar_read' | 'calendar_write', opts: Omit<CallOptions, 'headers'>, extra: Record<string, string> = {}): Promise<T> {
    const headers = { ...(await this.access.authHeaders(account, cap)), ...extra };
    try {
      return await this.upstream.json<T>('calendar', { ...opts, headers });
    } catch (err) {
      if (err instanceof UpstreamError && err.status === 401) this.access.invalidate(account.id);
      throw err;
    }
  }

  private async targets(principal: Principal, accountId: string | undefined): Promise<GoogleProductivityAccount[]> {
    return accountId ? [await this.access.account(principal, accountId, 'calendar_read')] : this.access.readable(principal, 'calendar_read');
  }

  async listCalendars(principal: Principal, opts: { accountId?: string; pageSize?: number; cursor?: string }): Promise<FanOutResult<CalendarSummary & Provenance>> {
    const pageSize = bounded('pageSize', opts.pageSize, DEFAULT_CALENDAR_PAGE_SIZE, MAX_CALENDAR_PAGE_SIZE);
    const targets = await this.targets(principal, opts.accountId);
    const byId = new Map(targets.map((a) => [a.id, a]));
    return fanOut({
      kind: 'calendars',
      queryKey: { s: pageSize, a: opts.accountId ?? '*' },
      sources: targets.map((a) => ({ id: a.id, label: a.label })),
      seal: this.store,
      ...(opts.cursor ? { cursor: opts.cursor } : {}),
      fetchPage: async (source, cursor) => {
        const account = byId.get(source.id)!;
        const res = await this.call<{ items?: Array<Record<string, unknown>>; nextPageToken?: string }>(account, 'calendar_read', {
          method: 'GET',
          path: '/calendar/v3/users/me/calendarList',
          query: { maxResults: pageSize, pageToken: cursor },
        });
        const items = (res.items ?? []).filter((c) => typeof c.id === 'string').map((c) => {
          const out: CalendarSummary & Provenance = { ...provenance(account), calendarId: c.id as string };
          for (const k of ['summary', 'description', 'timeZone', 'accessRole'] as const) if (str(c[k])) out[k] = c[k] as string;
          if (c.primary === true) out.primary = true;
          return out;
        });
        return { items, ...(res.nextPageToken ? { next: res.nextPageToken } : {}) };
      },
    });
  }

  async listEvents(principal: Principal, opts: ListEventsOptions): Promise<FanOutResult<CalendarEvent & Provenance>> {
    const pageSize = bounded('pageSize', opts.pageSize, DEFAULT_CALENDAR_PAGE_SIZE, MAX_CALENDAR_PAGE_SIZE);
    if (opts.calendarId !== undefined && !opts.accountId) throw new PerchError('calendarId requires accountId', 'bad_argument');
    const calendarId = checkCalendarId(opts.calendarId ?? 'primary');
    // Without timeMin, events.list starts at the beginning of time; Perch lists upcoming events by default.
    // Google requires identical parameters on every page, so the effective timeMin travels in the cursor.
    const { timeMin, inner } = splitEventsCursor(opts.cursor, opts.timeMin);
    const min = assertTimestamp('timeMin', timeMin);
    if (opts.timeMax !== undefined && assertTimestamp('timeMax', opts.timeMax) <= min) throw new PerchError('timeMax must be after timeMin', 'bad_argument');
    if (opts.timeZone !== undefined) assertTimeZone('timeZone', opts.timeZone);
    if (opts.query !== undefined && opts.query.length > 500) throw new PerchError('query must be at most 500 characters', 'bad_argument');
    const targets = await this.targets(principal, opts.accountId);
    const byId = new Map(targets.map((a) => [a.id, a]));
    const page = await fanOut({
      kind: 'events',
      // timeMin is part of the query: a default "now" is fixed into the cursor's first page.
      queryKey: { c: calendarId, a: opts.accountId ?? '*', s: pageSize, q: opts.query ?? '', tz: opts.timeZone ?? '', min: timeMin, max: opts.timeMax ?? '' },
      sources: targets.map((a) => ({ id: a.id, label: a.label })),
      seal: this.store,
      ...(inner ? { cursor: inner } : {}),
      fetchPage: async (source, cursor) => {
        const account = byId.get(source.id)!;
        const res = await this.call<{ items?: GoogleEvent[]; nextPageToken?: string; timeZone?: string }>(account, 'calendar_read', {
          method: 'GET',
          path: eventsPath(calendarId),
          query: {
            singleEvents: true,
            orderBy: 'startTime',
            maxResults: pageSize,
            pageToken: cursor,
            // Google requires all other parameters to stay identical across pages.
            timeMin,
            timeMax: opts.timeMax,
            q: opts.query || undefined,
            timeZone: opts.timeZone,
          },
        });
        const tz = str(res.timeZone);
        const items = (res.items ?? []).map((e) => ({ ...provenance(account), ...toEvent(e, calendarId, tz) }));
        return { items, ...(res.nextPageToken ? { next: res.nextPageToken } : {}) };
      },
    });
    return { ...page, nextCursor: page.nextCursor && `${Buffer.from(timeMin).toString('base64url')}.${page.nextCursor}` };
  }

  async getEvent(principal: Principal, opts: { accountId: string; calendarId: string; eventId: string; timeZone?: string }): Promise<CalendarEvent & Provenance> {
    const path = eventPath(opts.calendarId, opts.eventId);
    if (opts.timeZone !== undefined) assertTimeZone('timeZone', opts.timeZone);
    const account = await this.access.account(principal, opts.accountId, 'calendar_read');
    const e = await this.call<GoogleEvent>(account, 'calendar_read', { method: 'GET', path, ...(opts.timeZone ? { query: { timeZone: opts.timeZone } } : {}) });
    return { ...provenance(account), ...toEvent(e, opts.calendarId) };
  }

  /**
   * Exactly one request, never retried: after a lost response Perch cannot know whether Google applied
   * it. Failures before the request reaches the transport (validation, grant, token, allowlist) throw.
   * `cap` is the route tag: calendar_write (no guests involved, sendUpdates=none) or calendar_invite.
   */
  private async write(
    account: GoogleProductivityAccount,
    cap: 'calendar_write' | 'calendar_invite',
    opts: Omit<CallOptions, 'headers' | 'capability'>,
    extra: Record<string, string> = {},
  ): Promise<WriteOutcome> {
    const headers = { ...(await this.access.authHeaders(account, cap)), ...extra };
    try {
      const res = await this.upstream.raw('calendar', { ...opts, headers, capability: cap });
      return { ok: true, body: res.body };
    } catch (err) {
      if (err instanceof PerchError && err.code === 'route_not_allowed') throw err;
      if (err instanceof UpstreamError && err.status >= 400 && err.status < 500) {
        if (err.status === 401) this.access.invalidate(account.id);
        return { ok: false, status: err.status, message: err.message };
      }
      return { ok: false, status: 'unknown' };
    }
  }

  /** calendar_invite for this account, with the reason in the denial. */
  private async requireInvite(principal: Principal, accountId: string, why: string): Promise<void> {
    try {
      await this.access.account(principal, accountId, 'calendar_invite');
    } catch (err) {
      if (err instanceof PerchError && err.code === 'capability_denied') throw new PerchError(`${err.message}. ${why} Nothing was sent or changed.`, 'capability_denied');
      throw err;
    }
  }

  /** The existing event (calendar_read), for checks before any write. */
  private async existing(principal: Principal, account: GoogleProductivityAccount, calendarId: string, eventId: string): Promise<GoogleEvent> {
    await this.access.account(principal, account.id, 'calendar_read');
    return this.call<GoogleEvent>(account, 'calendar_read', { method: 'GET', path: eventPath(calendarId, eventId) });
  }

  /**
   * events.insert with a requestId-derived event id. Without guests: sendUpdates=none and calendar_write.
   * With guests: calendar_invite as well, sendUpdates as given (default all). addMeet adds a Meet request
   * (conferenceDataVersion=1) whose request id is derived from requestId too. Idempotency: the same
   * (accountId, calendarId as given, requestId) always yields the same id, so a manual retry after an
   * indeterminate outcome either creates the event once or gets 409 ("conflict"). Google notes that id
   * collisions may not always be detected at creation time, so "created" twice is not impossible.
   */
  async createEvent(principal: Principal, raw: Record<string, unknown>): Promise<CreateEventResult> {
    const input = parseCreateInput(raw);
    const account = await this.access.account(principal, input.accountId, 'calendar_write');
    const guests = input.attendees.length > 0;
    if (guests) await this.requireInvite(principal, account.id, 'Events with attendees (invitations) need calendar_invite.');
    const body = buildCreateBody(input);
    const base = { ...provenance(account), requestId: input.requestId, calendarId: input.calendarId, eventId: body.id, sendUpdates: input.sendUpdates };
    const query = { sendUpdates: input.sendUpdates, ...(input.addMeet ? { conferenceDataVersion: 1 } : {}) };
    const out = await this.write(account, guests ? 'calendar_invite' : 'calendar_write', { method: 'POST', path: eventsPath(input.calendarId), query, json: body });
    if (out.ok) {
      const event = parseEventBody(out.body);
      return { ...base, status: 'created', ...(event ? { event: toEvent(event, input.calendarId) } : {}), detail: `Created. ${notifyNote(guests, input.sendUpdates)}` };
    }
    if (out.status === 409) {
      return {
        ...base,
        status: 'conflict',
        detail:
          'An event with this requestId already exists in this calendar (an earlier call, possibly one whose response was lost, created it; ' +
          'ids of deleted events stay taken). Nothing new was created and nobody was invited again. Inspect it with calendar_get_event; use a new requestId for a different event.',
      };
    }
    if (out.status === 'unknown') {
      return {
        ...base,
        status: 'indeterminate',
        detail:
          `${INDETERMINATE}Check with calendar_get_event using this eventId, or call calendar_create_event again with the same requestId and calendarId: ` +
          'it then either creates the event once or reports conflict (no second invitation).',
      };
    }
    return { ...base, status: 'rejected', detail: `Not created: ${out.message}` };
  }

  /**
   * events.patch with the caller's ETag in If-Match, for events (or whole series) the user organises.
   * Needs calendar_write and calendar_read (the existing event is checked first and the updated event is
   * returned), plus calendar_invite whenever the event has guests before or after the change (also with
   * sendUpdates none). sendUpdates defaults to all when guests are involved, otherwise none.
   */
  async updateEvent(principal: Principal, raw: Record<string, unknown>): Promise<UpdateEventResult> {
    const input = parseUpdateInput(raw);
    const account = await this.access.account(principal, input.accountId, 'calendar_write');
    const path = eventPath(input.calendarId, input.eventId);
    const base = { ...provenance(account), calendarId: input.calendarId, eventId: input.eventId };
    const existing = await this.existing(principal, account, input.calendarId, input.eventId);
    if (existing.etag !== input.etag) {
      return {
        ...base,
        status: 'precondition_failed',
        ...(str(existing.etag) ? { currentEtag: existing.etag } : {}),
        detail: 'The event changed since you read it (etag mismatch); nothing was changed. Read it again and reapply your change.',
      };
    }
    assertOwnEvent(existing);
    const plan = planPatch(input, existing);
    const sendUpdates: SendUpdates = plan.guestsInvolved ? (input.sendUpdates ?? 'all') : 'none';
    // Any write to an event that has guests (before or after the change) needs calendar_invite, even with
    // sendUpdates "none": guests see the changed time, recurrence, Meet link or their permissions anyway.
    // calendar_write alone only covers events without guests.
    const invite = plan.guestsInvolved;
    if (invite) {
      await this.requireInvite(
        principal,
        account.id,
        plan.changesGuests
          ? 'Changing the guest list needs calendar_invite.'
          : 'Changing an event that has guests needs calendar_invite, also with sendUpdates "none" (calendar_write alone only covers events without guests).',
      );
    }
    const query = { sendUpdates, ...(plan.addsMeet ? { conferenceDataVersion: 1 } : {}) };
    const out = await this.write(account, invite ? 'calendar_invite' : 'calendar_write', { method: 'PATCH', path, query, json: plan.body }, { 'if-match': input.etag });
    const withSend = { ...base, sendUpdates };
    if (out.ok) {
      const event = parseEventBody(out.body);
      return { ...withSend, status: 'updated', ...(event ? { event: toEvent(event, input.calendarId) } : {}), detail: `Updated. ${notifyNote(plan.guestsInvolved, sendUpdates)}` };
    }
    if (out.status === 412) {
      return { ...withSend, status: 'precondition_failed', detail: 'The event changed just before the update (HTTP 412); nothing was changed. Read it again and reapply.' };
    }
    if (out.status === 'unknown') {
      return {
        ...withSend,
        status: 'indeterminate',
        detail: `${INDETERMINATE}Read the event with calendar_get_event: a new etag with your values means it was applied; the old etag means it was not.`,
      };
    }
    return { ...withSend, status: 'rejected', detail: `Not updated: ${out.message}` };
  }

  /**
   * events.delete: PERMANENT deletion (not a trash) of an event or a whole series the user organises.
   * Single occurrences are refused. The current etag is always sent as If-Match (the caller's, if given,
   * must match first). Events with guests need calendar_invite; sendUpdates defaults to all for them
   * (Google then emails a cancellation), otherwise none.
   */
  async deleteEvent(principal: Principal, raw: Record<string, unknown>): Promise<DeleteEventResult> {
    const input = parseDeleteInput(raw);
    const account = await this.access.account(principal, input.accountId, 'calendar_write');
    const path = eventPath(input.calendarId, input.eventId);
    const base = { ...provenance(account), calendarId: input.calendarId, eventId: input.eventId };
    const existing = await this.existing(principal, account, input.calendarId, input.eventId);
    if (input.etag !== undefined && existing.etag !== input.etag) {
      return {
        ...base,
        status: 'precondition_failed',
        ...(str(existing.etag) ? { currentEtag: existing.etag } : {}),
        detail: 'The event changed since you read it (etag mismatch); nothing was deleted. Read it again and decide again.',
      };
    }
    if (existing.status === 'cancelled') {
      return { ...base, status: 'not_found', detail: 'Google reports the event as already deleted (status "cancelled"); nothing was deleted now.' };
    }
    assertOwnEvent(existing);
    const guests = guestsOf(existing).length > 0;
    if (guests) await this.requireInvite(principal, account.id, 'Deleting an event with guests needs calendar_invite.');
    const sendUpdates: SendUpdates = guests ? (input.sendUpdates ?? 'all') : 'none';
    const etag = str(existing.etag);
    const out = await this.write(account, guests ? 'calendar_invite' : 'calendar_write', { method: 'DELETE', path, query: { sendUpdates } }, etag ? { 'if-match': etag } : {});
    const withSend = { ...base, sendUpdates };
    const series = Array.isArray(existing.recurrence) && existing.recurrence.length > 0;
    if (out.ok) {
      const who = !guests ? 'No guests were notified (there were none).' : sendUpdates === 'none' ? 'Guests were NOT notified (sendUpdates=none).' : `Google was asked to send cancellations (sendUpdates=${sendUpdates}).`;
      return { ...withSend, status: 'deleted', detail: `Permanently deleted${series ? ' (the whole series)' : ''}; this cannot be undone. ${who}` };
    }
    if (out.status === 404 || out.status === 410) return { ...withSend, status: 'not_found', detail: 'Google reports the event as already deleted or not found; nothing was deleted now.' };
    if (out.status === 412) return { ...withSend, status: 'precondition_failed', detail: 'The event changed just before the deletion (HTTP 412); nothing was deleted. Read it again and decide again.' };
    if (out.status === 'unknown') {
      return { ...withSend, status: 'indeterminate', detail: `${INDETERMINATE}Check with calendar_get_event: not found or status "cancelled" means it was deleted.` };
    }
    return { ...withSend, status: 'rejected', detail: `Not deleted: ${out.message}` };
  }

  /**
   * Answers an invitation for the account's own attendee entry (self:true, else the account email) with an
   * events.patch that carries only that entry and attendeesOmitted:true (Google: "can be used to only update
   * the participant's response"), If-Match on the fetched etag. Needs calendar_invite and calendar_read.
   */
  async respondEvent(principal: Principal, raw: Record<string, unknown>): Promise<RespondEventResult> {
    const input = parseRespondInput(raw);
    const account = await this.access.account(principal, input.accountId, 'calendar_invite');
    const path = eventPath(input.calendarId, input.eventId);
    const sendUpdates: SendUpdates = input.sendUpdates ?? 'all';
    const base = { ...provenance(account), calendarId: input.calendarId, eventId: input.eventId, response: input.response, sendUpdates };
    const existing = await this.existing(principal, account, input.calendarId, input.eventId);
    if (input.etag !== undefined && existing.etag !== input.etag) {
      return { ...base, status: 'precondition_failed', detail: 'The event changed since you read it (etag mismatch); nothing was sent. Read it again and decide again.' };
    }
    if (existing.status === 'cancelled') throw new PerchError('This event is cancelled; there is nothing to answer.', 'unsupported_event');
    if (existing.organizer?.self === true) {
      throw new PerchError('You organize this event, so there is no invitation to answer; change it with calendar_update_event instead. Nothing was sent.', 'unsupported_event');
    }
    if (existing.recurringEventId !== undefined) throw new PerchError(SINGLE_OCCURRENCE_REFUSED, 'unsupported_event');
    const list = Array.isArray(existing.attendees) ? existing.attendees : [];
    const email = account.email.toLowerCase();
    const own = list.find((a) => a?.self === true) ?? list.find((a) => typeof a?.email === 'string' && a.email.toLowerCase() === email);
    if (!own || typeof own.email !== 'string') throw new PerchError('You are not on the guest list of this event, so there is no invitation to answer. Nothing was sent.', 'unsupported_event');
    const entry: Record<string, unknown> = { email: own.email, responseStatus: input.response };
    if (own.optional === true) entry.optional = true;
    if (typeof own.comment === 'string') entry.comment = own.comment;
    if (Number.isInteger(own.additionalGuests)) entry.additionalGuests = own.additionalGuests;
    const etag = str(existing.etag);
    const out = await this.write(
      account,
      'calendar_invite',
      { method: 'PATCH', path, query: { sendUpdates }, json: { attendees: [entry], attendeesOmitted: true } },
      etag ? { 'if-match': etag } : {},
    );
    if (out.ok) {
      const event = parseEventBody(out.body);
      const who = sendUpdates === 'none' ? 'The organizer was NOT notified (sendUpdates=none).' : `Google was asked to notify the organizer (sendUpdates=${sendUpdates}).`;
      return { ...base, status: 'responded', ...(event ? { event: toEvent(event, input.calendarId) } : {}), detail: `Answered "${input.response}". ${who} ${ACCEPTED_NOTE}` };
    }
    if (out.status === 412) return { ...base, status: 'precondition_failed', detail: 'The event changed just before the answer (HTTP 412); nothing was sent. Read it again and decide again.' };
    if (out.status === 'unknown') return { ...base, status: 'indeterminate', detail: `${INDETERMINATE}Check your responseStatus with calendar_get_event.` };
    return { ...base, status: 'rejected', detail: `Not answered: ${out.message}` };
  }
}

function parseEventBody(body: Buffer): GoogleEvent | undefined {
  try {
    const v = JSON.parse(body.toString('utf8')) as unknown;
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as GoogleEvent) : undefined;
  } catch {
    return undefined;
  }
}
