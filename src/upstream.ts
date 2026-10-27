import { PerchError } from './errors.js';

/**
 * All outbound HTTP goes through here. Origins are fixed constants and every (method, path)
 * must match an allowlist before any network I/O. Routes are tagged with the capability they
 * exercise: read routes are the default, and draft/send routes are only reachable when the
 * caller explicitly passes the same capability tag (defence in depth behind the MCP-level grant
 * check). There is no way to point Perch at an arbitrary URL; tests swap the transport function,
 * never the origins.
 */

export type Service =
  | 'drive'
  | 'oauth'
  | 'notion'
  | 'gmail'
  | 'graph'
  | 'msauth'
  | 'calendar'
  | 'people'
  | 'openid'
  | 'slack'
  | 'slackfiles'
  | 'gowa'
  | 'cimd'
  | 'telegram'
  | 'luma'
  | 'lumaauth'
  | 'x';
/**
 * `admin` routes (GOWA device pairing/removal) are only ever passed by the local CLI, never by an MCP tool.
 */
export type RouteCapability = 'read' | 'draft' | 'send' | 'calendar_write' | 'calendar_invite' | 'slack_send' | 'whatsapp_send' | 'admin' | 'notify' | 'drive_write' | 'notion_write' | 'mail_modify' | 'x_post';
export type HttpMethod = 'GET' | 'POST' | 'PATCH' | 'DELETE';

export const ORIGINS: Readonly<Record<Service, string>> = Object.freeze({
  drive: 'https://www.googleapis.com',
  oauth: 'https://oauth2.googleapis.com',
  notion: 'https://api.notion.com',
  gmail: 'https://gmail.googleapis.com',
  graph: 'https://graph.microsoft.com',
  msauth: 'https://login.microsoftonline.com',
  calendar: 'https://www.googleapis.com',
  people: 'https://people.googleapis.com',
  /** userinfo_endpoint of Google's OpenID Connect discovery document (hard-coded, never fetched). */
  openid: 'https://openidconnect.googleapis.com',
  slack: 'https://slack.com',
  /** Slack file host: upload URLs from files.getUploadURLExternal and private file downloads (url_private_download). */
  slackfiles: 'https://files.slack.com',
  /**
   * GOWA (self-hosted WhatsApp bridge) has no fixed origin: each call passes the configured instance
   * origin, which must pass validateGowaOrigin (loopback or a Tailscale address only). This placeholder
   * is never used for a request.
   */
  gowa: 'http://127.0.0.1',
  /**
   * Client ID Metadata Documents of OAuth clients of the public access: the origin comes from an
   * allowlisted client_id URL and must pass validateCimdOrigin. Placeholder, never used for a request.
   */
  cimd: 'https://claude.ai',
  /** Optional operator notifications of the public access (Telegram Bot API). */
  telegram: 'https://api.telegram.org',
  /** Official Luma MCP server (docs/LUMA_SPEC.md): OAuth discovery only; MCP traffic uses src/luma/client.ts. */
  luma: 'https://mcp.luma.com',
  /** Luma's OAuth authorization server, taken from Luma's metadata; must pass validateLumaOrigin. Placeholder. */
  lumaauth: 'https://mcp.luma.com',
  /** X API v2 (docs/X_SPEC.md): OAuth 2.0 token/revoke, users/me and posting. Authorization runs in the browser (x.com). */
  x: 'https://api.x.com',
});

/** Services whose origin is configured per namespace instead of fixed (see validateGowaOrigin). */
const DYNAMIC_ORIGIN: ReadonlySet<Service> = new Set(['gowa', 'cimd', 'lumaauth']);

const SERVICE_NAMES: Record<Service, string> = {
  drive: 'Google Drive API',
  oauth: 'Google OAuth',
  notion: 'Notion API',
  gmail: 'Gmail API',
  graph: 'Microsoft Graph',
  msauth: 'Microsoft identity platform',
  calendar: 'Google Calendar API',
  people: 'Google People API',
  openid: 'Google OpenID Connect',
  slack: 'Slack Web API',
  slackfiles: 'Slack file host',
  gowa: 'WhatsApp bridge (GOWA)',
  cimd: 'OAuth client metadata document',
  telegram: 'Telegram Bot API',
  luma: 'Luma MCP server',
  lumaauth: 'Luma authorization server',
  x: 'X API',
};

const NOTION_ID = '[0-9a-fA-F-]{32,36}';
const DRIVE_ID = '[A-Za-z0-9_-]{1,200}';
const GMAIL_ID = '[A-Za-z0-9_-]{1,256}';
const GMAIL_ATTACHMENT_ID = '[A-Za-z0-9_-]{1,4096}';

/**
 * Calendar ids (primary, x@group.calendar.google.com, holiday ids with '#') after encodeURIComponent:
 * only '@', '+' and '#' may arrive encoded, so no encoded '/', '.' or '%' can reach the path.
 */
const CAL_ID = '(?:[A-Za-z0-9._-]|%40|%2B|%23){1,1024}';
/**
 * Event ids: base32hex (a-v, 0-9; the documented id alphabet), optionally with the recurring-instance
 * suffix `_YYYYMMDD` or `_YYYYMMDDTHHMMSSZ`. Reserved collection verbs are excluded explicitly.
 */
const EVENT_ID = '(?!import$|quickAdd$|watch$)[a-v0-9]{5,1024}(?:_[0-9]{8}(?:T[0-9]{6}Z)?)?';
/** A single event or a whole series: never the instance suffix (single occurrences are not written). */
const SERIES_EVENT_ID = '(?!import$|quickAdd$|watch$)[a-v0-9]{5,1024}';
/** People: only contact resource names (people/c<digits>), never people/me or Google account ids. */
const CONTACT_ID = 'c[0-9]{1,30}';

/** Slack Web API ids: channels/groups/DMs (C/G/D…), message timestamps. */
export const SLACK_CHANNEL_ID = /^[CGD][A-Z0-9]{2,30}$/;
export const SLACK_TS = /^[0-9]{9,11}\.[0-9]{6}$/;
/** Slack file ids (F…) and the opaque upload segment of files.getUploadURLExternal's upload_url. */
export const SLACK_FILE_ID = /^F[A-Z0-9]{2,30}$/;
export const SLACK_UPLOAD_PATH = /^\/upload\/v1\/[A-Za-z0-9_-]{1,2048}$/;
/**
 * url_private_download of a Slack file: /files-pri/<team>-<file>/download/<name> (or without "download/").
 * The name may be percent-encoded but never an encoded '/', backslash or '.', and never contain '..'.
 */
export const SLACK_DOWNLOAD_PATH = /^\/files-pri\/[TE][A-Z0-9]{2,30}-(F[A-Z0-9]{2,30})\/(?:download\/)?(?!.*\.\.)(?!.*%(?:2[fFeE]|5[cC]))[A-Za-z0-9._~%()+-]{1,255}$/;
/**
 * Value of Slack's browser cookie `d` for session workspaces (xoxd-…), URL-encoded as the browser sends it.
 * No ';', ',', spaces or control characters, so it can never smuggle another cookie or header.
 */
export const SLACK_SESSION_COOKIE = /^xoxd-[A-Za-z0-9%._~-]{20,2000}$/;
/** WhatsApp JIDs Perch reads and writes to: people (phone or LID) and groups. Never status/newsletter/broadcast. */
export const WHATSAPP_JID = /^(?:[0-9]{5,20}@s\.whatsapp\.net|[0-9]{5,20}@lid|[0-9]{5,20}(?:-[0-9]{5,20})?@g\.us)$/;
const JID_PATH = '[0-9]{5,20}(?:-[0-9]{5,20})?%40(?:s\\.whatsapp\\.net|lid|g\\.us)';
/** Device slots Perch creates in GOWA (`perch-` + 16 hex); other slots are never addressed. */
export const GOWA_DEVICE_ID = /^perch-[a-f0-9]{16}$/;
const DEVICE_PATH = 'perch-[a-f0-9]{16}';
/** WhatsApp message ids as Perch accepts them from whatsapp_get_messages. */
const WA_MESSAGE_PATH = '[A-Za-z0-9]{8,64}';

type Route = [method: string, path: RegExp, capability?: RouteCapability];

const ROUTES: Record<Service, Route[]> = {
  drive: [
    ['GET', /^\/drive\/v3\/about$/],
    ['GET', /^\/drive\/v3\/files$/],
    ['GET', new RegExp(`^/drive/v3/files/${DRIVE_ID}$`)],
    ['GET', new RegExp(`^/drive/v3/files/${DRIVE_ID}/export$`)],
    ['GET', new RegExp(`^/drive/v3/files/${DRIVE_ID}/permissions$`)],
    ['GET', new RegExp(`^/drive/v3/files/${DRIVE_ID}/comments$`)],
    // Writes (client grants with drive_write only). Deliberately NOT allowlisted: DELETE /drive/v3/files/{id}
    // (permanent delete), DELETE /drive/v3/files/trash (empty trash), PATCH .../permissions/{id} (role/owner
    // changes) and anything that transfers ownership (see assertDriveRequestSafe).
    ['POST', /^\/upload\/drive\/v3\/files$/, 'drive_write'],
    ['PATCH', new RegExp(`^/upload/drive/v3/files/${DRIVE_ID}$`), 'drive_write'],
    ['POST', /^\/drive\/v3\/files$/, 'drive_write'],
    ['PATCH', new RegExp(`^/drive/v3/files/(?!trash$)${DRIVE_ID}$`), 'drive_write'],
    ['POST', new RegExp(`^/drive/v3/files/${DRIVE_ID}/copy$`), 'drive_write'],
    ['POST', new RegExp(`^/drive/v3/files/${DRIVE_ID}/permissions$`), 'drive_write'],
    ['DELETE', new RegExp(`^/drive/v3/files/${DRIVE_ID}/permissions/${DRIVE_ID}$`), 'drive_write'],
    ['POST', new RegExp(`^/drive/v3/files/${DRIVE_ID}/comments$`), 'drive_write'],
  ],
  oauth: [
    ['POST', /^\/token$/],
    ['POST', /^\/revoke$/],
  ],
  notion: [
    ['GET', /^\/v1\/users\/me$/],
    // OAuth code exchange and refresh (public integrations); internal callers only, never reachable from a client grant.
    ['POST', /^\/v1\/oauth\/token$/, 'admin'],
    ['POST', /^\/v1\/search$/],
    ['GET', new RegExp(`^/v1/pages/${NOTION_ID}$`)],
    ['GET', new RegExp(`^/v1/blocks/${NOTION_ID}/children$`)],
    ['GET', new RegExp(`^/v1/databases/${NOTION_ID}$`)],
    ['GET', new RegExp(`^/v1/data_sources/${NOTION_ID}$`)],
    ['POST', new RegExp(`^/v1/data_sources/${NOTION_ID}/query$`)],
    ['GET', /^\/v1\/comments$/],
    // Writes (client grants with notion_write only). Trash is PATCH in_trash; DELETE /v1/blocks/{id} and
    // database/data source schema changes are deliberately never allowlisted.
    ['POST', /^\/v1\/pages$/, 'notion_write'],
    ['PATCH', new RegExp(`^/v1/pages/${NOTION_ID}$`), 'notion_write'],
    ['PATCH', new RegExp(`^/v1/blocks/${NOTION_ID}/children$`), 'notion_write'],
    ['PATCH', new RegExp(`^/v1/blocks/${NOTION_ID}$`), 'notion_write'],
    ['POST', /^\/v1\/comments$/, 'notion_write'],
  ],
  gmail: [
    ['GET', /^\/gmail\/v1\/users\/me\/profile$/],
    ['GET', /^\/gmail\/v1\/users\/me\/messages$/],
    ['GET', new RegExp(`^/gmail/v1/users/me/messages/${GMAIL_ID}$`)],
    ['GET', new RegExp(`^/gmail/v1/users/me/messages/${GMAIL_ID}/attachments/${GMAIL_ATTACHMENT_ID}$`)],
    ['POST', /^\/gmail\/v1\/users\/me\/drafts$/, 'draft'],
    ['POST', /^\/gmail\/v1\/users\/me\/messages\/send$/, 'send'],
    // Organizing (gmail.modify). Never: DELETE routes, messages/batchDelete, batchModify, threads/*/trash,
    // settings/filters or settings/forwardingAddresses (permanent deletion and mail rules are not offered).
    ['GET', /^\/gmail\/v1\/users\/me\/labels$/],
    ['GET', /^\/gmail\/v1\/users\/me\/drafts$/],
    ['GET', new RegExp(`^/gmail/v1/users/me/drafts/${GMAIL_ID}$`)],
    ['POST', new RegExp(`^/gmail/v1/users/me/messages/${GMAIL_ID}/(?:modify|trash|untrash)$`), 'mail_modify'],
    ['POST', /^\/gmail\/v1\/users\/me\/drafts\/send$/, 'send'],
  ],
  // Retired standalone OAuth services. Retain their names only to reject old callers before I/O.
  graph: [],
  msauth: [],
  calendar: [
    ['GET', /^\/calendar\/v3\/users\/me\/calendarList$/],
    ['GET', new RegExp(`^/calendar/v3/calendars/${CAL_ID}/events$`)],
    ['GET', new RegExp(`^/calendar/v3/calendars/${CAL_ID}/events/${EVENT_ID}$`)],
    // Writes: events.insert/patch/delete on one event or a whole series (never an instance id), tagged
    // calendar_write (events without guests: sendUpdates=none, no attendees in the body, see
    // assertCalendarRequestSafe) or calendar_invite (any write to an event with guests, invitations,
    // responses; CalendarService checks the existing event and picks the tag). Never: calendars.delete,
    // calendars.clear, calendarList/acl writes, events.move/import/quickAdd/instances.
    ['POST', new RegExp(`^/calendar/v3/calendars/${CAL_ID}/events$`), 'calendar_write'],
    ['POST', new RegExp(`^/calendar/v3/calendars/${CAL_ID}/events$`), 'calendar_invite'],
    ['PATCH', new RegExp(`^/calendar/v3/calendars/${CAL_ID}/events/${SERIES_EVENT_ID}$`), 'calendar_write'],
    ['PATCH', new RegExp(`^/calendar/v3/calendars/${CAL_ID}/events/${SERIES_EVENT_ID}$`), 'calendar_invite'],
    ['DELETE', new RegExp(`^/calendar/v3/calendars/${CAL_ID}/events/${SERIES_EVENT_ID}$`), 'calendar_write'],
    ['DELETE', new RegExp(`^/calendar/v3/calendars/${CAL_ID}/events/${SERIES_EVENT_ID}$`), 'calendar_invite'],
  ],
  people: [
    ['GET', /^\/v1\/people\/me\/connections$/],
    ['GET', new RegExp(`^/v1/people/${CONTACT_ID}$`)],
  ],
  openid: [['GET', /^\/v1\/userinfo$/]],
  slack: [
    ['GET', /^\/api\/auth\.test$/],
    ['GET', /^\/api\/conversations\.list$/],
    ['GET', /^\/api\/conversations\.info$/],
    ['GET', /^\/api\/conversations\.history$/],
    ['GET', /^\/api\/conversations\.replies$/],
    ['GET', /^\/api\/users\.info$/],
    ['GET', /^\/api\/search\.messages$/],
    ['GET', /^\/api\/files\.info$/],
    ['GET', /^\/api\/chat\.scheduledMessages\.list$/],
    ['POST', /^\/api\/chat\.postMessage$/, 'slack_send'],
    // DM / group DM with existing users (no channel creation, no invites) and not-yet-posted scheduled messages.
    ['POST', /^\/api\/conversations\.open$/, 'slack_send'],
    ['POST', /^\/api\/chat\.scheduleMessage$/, 'slack_send'],
    ['POST', /^\/api\/chat\.deleteScheduledMessage$/, 'slack_send'],
    // Own messages only (Slack refuses others with cant_update_message). chat.delete, files.delete and
    // files.sharedPublicURL are deliberately absent: Slack deletion is permanent, public links leak files.
    ['POST', /^\/api\/chat\.update$/, 'slack_send'],
    ['POST', /^\/api\/reactions\.add$/, 'slack_send'],
    ['POST', /^\/api\/reactions\.remove$/, 'slack_send'],
    ['POST', /^\/api\/files\.getUploadURLExternal$/, 'slack_send'],
    ['POST', /^\/api\/files\.completeUploadExternal$/, 'slack_send'],
  ],
  slackfiles: [
    ['GET', SLACK_DOWNLOAD_PATH],
    ['POST', SLACK_UPLOAD_PATH, 'slack_send'],
  ],
  gowa: [
    ['GET', /^\/chats$/],
    ['GET', new RegExp(`^/chat/${JID_PATH}/messages$`)],
    ['POST', /^\/send\/message$/, 'whatsapp_send'],
    // Media sends: multipart bodies built by Perch (file bytes only, never *_url fields).
    ['POST', /^\/send\/(?:image|video|audio|file)$/, 'whatsapp_send'],
    // Media download: the bridge saves the file and names its path; Perch then reads only that saved file.
    ['GET', new RegExp(`^/message/${WA_MESSAGE_PATH}/download$`)],
    ['GET', /^\/statics\/media\/[0-9]{5,20}(?:-[0-9]{5,20})?\/[0-9]{4}-[0-9]{2}-[0-9]{2}\/[A-Za-z0-9_-][A-Za-z0-9._-]{0,199}$/],
    // Local CLI only (pairing and unlinking); no MCP tool passes the admin capability.
    ['GET', /^\/devices$/, 'admin'],
    ['POST', /^\/devices$/, 'admin'],
    ['POST', new RegExp(`^/devices/${DEVICE_PATH}/login/code$`), 'admin'],
    ['GET', new RegExp(`^/devices/${DEVICE_PATH}$`), 'admin'],
    ['GET', new RegExp(`^/devices/${DEVICE_PATH}/status$`), 'admin'],
    ['DELETE', new RegExp(`^/devices/${DEVICE_PATH}$`), 'admin'],
  ],
  cimd: [['GET', /^\/(?!.*\.\.)[A-Za-z0-9._~\/-]{1,256}$/]],
  telegram: [['POST', /^\/bot[0-9]{5,15}:[A-Za-z0-9_-]{30,64}\/sendMessage$/, 'notify']],
  luma: [['GET', /^\/\.well-known\/oauth-protected-resource(?:\/mcp)?$/]],
  lumaauth: [
    ['GET', /^\/\.well-known\/(?:oauth-authorization-server|openid-configuration)(?:\/[A-Za-z0-9._~-]{1,100})?$/],
    // token, registration and revocation endpoints as announced in Luma's metadata (Luma hosts only)
    ['POST', /^\/(?!.*\.\.)[A-Za-z0-9._~\/-]{1,200}$/],
  ],
  x: [
    // OAuth 2.0 code exchange and refresh (public client: client_id in the body; confidential: Basic auth).
    ['POST', /^\/2\/oauth2\/token$/],
    // Local CLI only (perch x remove --revoke).
    ['POST', /^\/2\/oauth2\/revoke$/, 'admin'],
    ['GET', /^\/2\/users\/me$/],
    // Posting on the connected account only; no delete, no media, no DMs, no likes or follows.
    ['POST', /^\/2\/tweets$/, 'x_post'],
  ],
};

/** Hosts Perch accepts for Luma's authorization server (from metadata): luma.com, lu.ma and their subdomains. */
export function validateLumaOrigin(raw: string): string {
  const bad = () => new PerchError('Luma announced an authorization server outside luma.com / lu.ma; refusing', 'luma_metadata_invalid');
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw bad();
  }
  if (url.protocol !== 'https:' || url.port || url.username || url.password) throw bad();
  const h = url.hostname.toLowerCase();
  if (!(h === 'luma.com' || h.endsWith('.luma.com') || h === 'lu.ma' || h.endsWith('.lu.ma'))) throw bad();
  return url.origin;
}

/**
 * Origin of an allowlisted client_id URL (public access, CIMD): https on the default port, a DNS host name
 * (never an IP literal, localhost or a single-label name). Returns the normalised origin.
 */
export function validateCimdOrigin(raw: string): string {
  const bad = () => new PerchError('A client metadata URL must be https://<dns name>/<path> on the default port', 'bad_argument');
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw bad();
  }
  if (url.protocol !== 'https:' || url.port || url.username || url.password) throw bad();
  const host = url.hostname.toLowerCase();
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) throw bad();
  if (host === 'localhost' || host.endsWith('.localhost')) throw bad();
  return url.origin;
}

/**
 * A GOWA instance origin: http(s) on loopback (127.0.0.1, ::1, localhost) or a Tailscale address
 * (100.64.0.0/10, fd7a:115c:a1e0::/48), explicit port, no path, query, credentials or fragment.
 * Returns the normalised origin. GOWA can send messages and holds the whole chat history, so it must
 * never be reachable from anywhere else; Perch refuses to talk to it on any other address.
 */
export function validateGowaOrigin(raw: string): string {
  const bad = () =>
    new PerchError(
      'GOWA URL must be http(s)://127.0.0.1:PORT, http://localhost:PORT, http://[::1]:PORT or a Tailscale address (100.64.0.0/10) with explicit port and no path',
      'bad_argument',
    );
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw bad();
  }
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash) throw bad();
  if (url.pathname !== '/' && url.pathname !== '') throw bad();
  if (!url.port) throw bad();
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  const loopback = host === 'localhost' || host === '::1' || (ipv4 !== null && ipv4[1] === '127');
  // 100.100.100.100 is Tailscale's own service address (MagicDNS), never a node.
  const tailnet4 = ipv4 !== null && Number(ipv4[1]) === 100 && Number(ipv4[2]) >= 64 && Number(ipv4[2]) <= 127 && host !== '100.100.100.100';
  const tailnet6 = /^fd7a:115c:a1e0:/.test(host);
  if (ipv4 && ipv4.slice(1).some((o) => Number(o) > 255)) throw bad();
  if (!loopback && !tailnet4 && !tailnet6) throw bad();
  return url.origin;
}

/**
 * Drive writes never transfer ownership or grant the owner role, whatever the caller built: the query flags
 * transferOwnership/moveToNewOwnersRoot and an "owner" role in a JSON body are refused before any I/O.
 */
function assertDriveRequestSafe(opts: CallOptions): void {
  const q = opts.query ?? {};
  const bad =
    q.transferOwnership !== undefined ||
    q.moveToNewOwnersRoot !== undefined ||
    (opts.json !== null && typeof opts.json === 'object' && ['owner', 'organizer'].includes(String((opts.json as Record<string, unknown>).role)));
  if (bad) throw new PerchError('Blocked Google Drive ownership change', 'route_not_allowed');
}

const CALENDAR_SEND_UPDATES = new Set(['all', 'externalOnly', 'none']);

/**
 * Calendar writes carry only sendUpdates (all/externalOnly/none) and, on insert/patch, conferenceDataVersion
 * (0/1) as query parameters. A calendar_write call is only for events without guests: it must not notify
 * anyone (sendUpdates absent or none) and must not carry attendees or attendeesOmitted. Whether the existing
 * event has guests is not visible here; CalendarService reads it first and uses the calendar_invite tag for
 * any write to an event with guests (before or after the change).
 */
function assertCalendarRequestSafe(opts: CallOptions): void {
  if (opts.method === 'GET') return;
  const bad = (why: string) => new PerchError(`Blocked Google Calendar API write (${why})`, 'route_not_allowed');
  for (const [k, v] of Object.entries(opts.query ?? {})) {
    if (v === undefined) continue;
    if (k === 'sendUpdates') {
      if (!CALENDAR_SEND_UPDATES.has(String(v))) throw bad('sendUpdates');
      if (opts.capability === 'calendar_write' && v !== 'none') throw bad('notifications need calendar_invite');
    } else if (k === 'conferenceDataVersion' && opts.method !== 'DELETE') {
      if (String(v) !== '0' && String(v) !== '1') throw bad('conferenceDataVersion');
    } else throw bad(`query parameter ${k}`);
  }
  const body = opts.json;
  if (opts.capability === 'calendar_write' && body !== null && typeof body === 'object' && ('attendees' in body || 'attendeesOmitted' in body)) throw bad('attendees need calendar_invite');
}

/** True when (service, method, path) is allowlisted for exactly this capability. */
export function isAllowedRoute(service: Service, method: string, path: string, capability: RouteCapability = 'read'): boolean {
  return ROUTES[service].some(([m, re, cap]) => m === method && (cap ?? 'read') === capability && re.test(path));
}

export const DEFAULT_JSON_MAX_BYTES = 5 * 1024 * 1024;
export const DEFAULT_TIMEOUT_MS = 30_000;

export interface UpstreamRequest {
  method: HttpMethod;
  url: URL;
  headers: Record<string, string>;
  body?: string;
  /** Binary request body (uploads); when set, `body` is unset. */
  bodyBytes?: Buffer;
  maxBytes: number;
}

export interface UpstreamResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

export type UpstreamTransport = (req: UpstreamRequest) => Promise<UpstreamResponse>;

export class UpstreamError extends PerchError {
  constructor(
    message: string,
    readonly status: number,
    readonly upstreamCode: string | undefined,
    /** Sanitised Retry-After in seconds (delta-seconds form only), if the upstream sent one. */
    readonly retryAfterSeconds?: number,
  ) {
    super(message, 'upstream_error');
  }
}

function parseRetryAfter(value: string | undefined): number | undefined {
  return value !== undefined && /^\d{1,7}$/.test(value.trim()) ? Number(value.trim()) : undefined;
}

/** Production transport: global fetch, no redirects, hard timeout, streamed size cap. */
export function createFetchTransport(opts: { timeoutMs?: number } = {}): UpstreamTransport {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return async (req) => {
    const signal = AbortSignal.timeout(timeoutMs);
    const mapErr = (err: unknown): never => {
      if (err instanceof PerchError) throw err;
      if (signal.aborted) throw new PerchError('Upstream request timed out', 'upstream_timeout');
      throw new PerchError('Upstream service unreachable', 'upstream_unreachable');
    };
    let res: Response;
    try {
      res = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.bodyBytes ?? req.body,
        redirect: 'error',
        signal,
      });
    } catch (err) {
      return mapErr(err);
    }
    const tooLarge = () =>
      new PerchError(`Upstream response exceeds the ${req.maxBytes} byte limit`, 'response_too_large');
    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > req.maxBytes) {
      await res.body?.cancel().catch(() => {});
      throw tooLarge();
    }
    const chunks: Buffer[] = [];
    let total = 0;
    try {
      if (res.body) {
        const reader = res.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > req.maxBytes) {
            await reader.cancel().catch(() => {});
            throw tooLarge();
          }
          chunks.push(Buffer.from(value));
        }
      }
    } catch (err) {
      return mapErr(err);
    }
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    return { status: res.status, headers, body: Buffer.concat(chunks) };
  };
}

export interface CallOptions {
  method: HttpMethod;
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  headers?: Record<string, string>;
  json?: unknown;
  form?: Record<string, string>;
  /** Raw text body with explicit content type (when required by an allowed endpoint). */
  text?: { contentType: string; data: string };
  /** Binary body with explicit content type (uploads, multipart/form-data built by the caller). */
  bytes?: { contentType: string; data: Buffer };
  maxBytes?: number;
  /** Required for draft/send/calendar_write/calendar_invite routes; must equal the route's tag. */
  capability?: RouteCapability;
  /** Only for services without a fixed origin (GOWA): the configured instance origin, re-validated here. */
  origin?: string;
  /**
   * Slack session workspaces only: the stored `d` cookie, sent as `Cookie: d=<value>`. Accepted for the
   * slack and slackfiles services only; a raw Cookie header in `headers` is always refused.
   */
  slackCookie?: string;
}

const SAFE_CODE = /^[A-Za-z_]{1,64}$/;

function extractCode(service: Service, body: Buffer): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== 'object') return undefined;
  const o = parsed as Record<string, unknown>;
  let code: unknown;
  if (service === 'notion') code = o.code ?? o.error; // the OAuth token endpoint answers { error: "invalid_grant" }
  else if (typeof o.error === 'string') code = o.error;
  else if (o.error && typeof o.error === 'object') {
    const e = o.error as { errors?: Array<{ reason?: unknown }>; status?: unknown; code?: unknown };
    code = e.errors?.[0]?.reason ?? e.status ?? e.code;
  }
  return typeof code === 'string' && SAFE_CODE.test(code) ? code : undefined;
}

function statusHint(status: number): string {
  if (status === 401) return 'unauthorized: credential invalid, expired or revoked';
  if (status === 403) return 'forbidden or rate limited';
  if (status === 404) return 'not found or not accessible with this account';
  if (status === 429) return 'rate limited';
  if (status >= 500) return 'upstream service error';
  return 'request rejected';
}

export class Upstream {
  constructor(private readonly transport: UpstreamTransport) {}

  /** Performs an allowlisted call and returns the raw 2xx response; non-2xx become sanitised errors. */
  async raw(service: Service, opts: CallOptions): Promise<UpstreamResponse> {
    if (!isAllowedRoute(service, opts.method, opts.path, opts.capability)) {
      throw new PerchError(`Blocked non-allowlisted ${SERVICE_NAMES[service]} call`, 'route_not_allowed');
    }
    if (service === 'drive') assertDriveRequestSafe(opts);
    if (service === 'calendar') assertCalendarRequestSafe(opts);
    let origin = ORIGINS[service];
    if (DYNAMIC_ORIGIN.has(service)) {
      if (!opts.origin) throw new PerchError(`Blocked ${SERVICE_NAMES[service]} call without a configured origin`, 'route_not_allowed');
      origin = service === 'cimd' ? validateCimdOrigin(opts.origin) : service === 'lumaauth' ? validateLumaOrigin(opts.origin) : validateGowaOrigin(opts.origin);
    } else if (opts.origin !== undefined) {
      throw new PerchError(`Blocked ${SERVICE_NAMES[service]} call to a non-fixed origin`, 'route_not_allowed');
    }
    const url = new URL(opts.path, origin);
    if (url.origin !== origin || url.pathname !== opts.path) {
      throw new PerchError(`Blocked non-allowlisted ${SERVICE_NAMES[service]} call`, 'route_not_allowed');
    }
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
    if (Object.keys(opts.headers ?? {}).some((k) => k.toLowerCase() === 'cookie')) {
      throw new PerchError(`Blocked a raw Cookie header for ${SERVICE_NAMES[service]}`, 'route_not_allowed');
    }
    const headers: Record<string, string> = { accept: 'application/json', ...opts.headers };
    if (opts.slackCookie !== undefined) {
      if (service !== 'slack' && service !== 'slackfiles') throw new PerchError(`Blocked the Slack session cookie for ${SERVICE_NAMES[service]}`, 'route_not_allowed');
      if (!SLACK_SESSION_COOKIE.test(opts.slackCookie)) throw new PerchError('The stored Slack session cookie has an unexpected format', 'bad_argument');
      headers.cookie = `d=${opts.slackCookie}`;
    }
    let body: string | undefined;
    if (opts.json !== undefined) {
      headers['content-type'] = 'application/json';
      body = JSON.stringify(opts.json);
    } else if (opts.form) {
      headers['content-type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams(opts.form).toString();
    } else if (opts.text) {
      headers['content-type'] = opts.text.contentType;
      body = opts.text.data;
    }
    let bodyBytes: Buffer | undefined;
    if (opts.bytes) {
      headers['content-type'] = opts.bytes.contentType;
      bodyBytes = opts.bytes.data;
    }
    let res: UpstreamResponse;
    try {
      res = await this.transport({
        method: opts.method,
        url,
        headers,
        ...(bodyBytes ? { bodyBytes } : { body }),
        maxBytes: opts.maxBytes ?? DEFAULT_JSON_MAX_BYTES,
      });
    } catch (err) {
      if (err instanceof PerchError) throw err;
      throw new PerchError(`${SERVICE_NAMES[service]} unreachable`, 'upstream_unreachable');
    }
    if (res.status < 200 || res.status >= 300) {
      const code = extractCode(service, res.body);
      throw new UpstreamError(
        `${SERVICE_NAMES[service]} request failed (HTTP ${res.status}${code ? `, ${code}` : ''}): ${statusHint(res.status)}`,
        res.status,
        code,
        parseRetryAfter(res.headers['retry-after']),
      );
    }
    return res;
  }

  async json<T = unknown>(service: Service, opts: CallOptions): Promise<T> {
    const res = await this.raw(service, opts);
    try {
      return JSON.parse(res.body.toString('utf8')) as T;
    } catch {
      throw new PerchError(`${SERVICE_NAMES[service]} returned a malformed response`, 'upstream_bad_response');
    }
  }
}
