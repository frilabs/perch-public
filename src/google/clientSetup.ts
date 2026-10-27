import { PerchError } from '../errors.js';
import type { GoogleService } from './group.js';
import type { GoogleClientCredentials } from './oauth.js';

/**
 * Guided Google Cloud preparation (docs/GUIDED_PROVIDER_SETUP_SPEC.md §1): the pure parts — direct console links,
 * the scope list to enter under "Data Access" and the strict check of the pasted "Desktop app" client JSON.
 * The interactive walk-through lives in src/cli/googleClient.ts.
 */

/** Upper bound for the pasted client JSON (a real one is well below 1 KiB). */
export const MAX_CLIENT_JSON_BYTES = 16 * 1024;

const CONSOLE = 'https://console.cloud.google.com';
/** Google Cloud project ids: 6-30 characters, lower-case letters, digits and hyphens, starting with a letter. */
const PROJECT_ID_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;

export function validProjectId(id: string): boolean {
  return PROJECT_ID_RE.test(id);
}

/** A Cloud Console link, scoped to the project when its id is known. */
export function consoleLink(pathname: string, projectId?: string): string {
  const url = new URL(pathname, CONSOLE);
  if (projectId && validProjectId(projectId)) url.searchParams.set('project', projectId);
  return url.toString();
}

/** API library pages (the "Enable" button) of the selected services. */
const API_OF: Record<GoogleService, { title: string; api: string }> = {
  drive: { title: 'Google Drive API', api: 'drive.googleapis.com' },
  gmail: { title: 'Gmail API', api: 'gmail.googleapis.com' },
  calendar: { title: 'Google Calendar API', api: 'calendar-json.googleapis.com' },
  contacts: { title: 'People API (Contacts)', api: 'people.googleapis.com' },
};

export function apiLinks(services: readonly GoogleService[], projectId?: string): Array<{ title: string; url: string }> {
  return services.map((s) => ({ title: API_OF[s].title, url: consoleLink(`/apis/library/${API_OF[s].api}`, projectId) }));
}

/** Google Auth Platform pages in the order of the guide. */
export function authPlatformLinks(projectId?: string) {
  return {
    projectCreate: consoleLink('/projectcreate'),
    branding: consoleLink('/auth/branding', projectId),
    audience: consoleLink('/auth/audience', projectId),
    dataAccess: consoleLink('/auth/scopes', projectId),
    clients: consoleLink('/auth/clients/create', projectId),
  };
}

export interface ValidatedClient extends GoogleClientCredentials {
  /** The document to store (re-serialised; same content as the download). */
  json: string;
}

/**
 * Strict check of the downloaded client JSON. Messages never repeat the input (it holds the client secret).
 */
export function validateClientJson(text: string): ValidatedClient {
  const bad = (why: string) => new PerchError(`This is not a usable Google client file: ${why}`, 'bad_client_file');
  if (Buffer.byteLength(text, 'utf8') > MAX_CLIENT_JSON_BYTES) throw bad(`larger than ${MAX_CLIENT_JSON_BYTES} bytes`);
  if (!text.trim()) throw bad('nothing was pasted');
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw bad('not valid JSON (paste the whole content of the downloaded file)');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw bad('not a JSON object');
  const doc = parsed as Record<string, unknown>;
  if (!('installed' in doc)) {
    if ('web' in doc) throw bad('it is a "Web application" client; create one of type "Desktop app"');
    throw bad('the "installed" key of a "Desktop app" client is missing');
  }
  const c = doc.installed as Record<string, unknown> | null;
  if (!c || typeof c !== 'object') throw bad('the "installed" entry is not an object');
  if (typeof c.client_id !== 'string' || !/^[A-Za-z0-9-]{1,200}\.apps\.googleusercontent\.com$/.test(c.client_id)) {
    throw bad('client_id must end with .apps.googleusercontent.com');
  }
  if (typeof c.client_secret !== 'string' || !c.client_secret.trim()) throw bad('client_secret is missing');
  const uris = Array.isArray(c.redirect_uris) ? c.redirect_uris : [];
  if (!uris.some((u) => u === 'http://localhost' || u === 'http://localhost/')) throw bad('redirect_uris must contain http://localhost (a "Desktop app" client has it)');
  return { clientId: c.client_id, clientSecret: c.client_secret, json: `${JSON.stringify(doc, null, 2)}\n` };
}

/** "123456-abc….apps.googleusercontent.com" → "123456-abc…" with the middle cut (for `client show`). */
export function shortClientId(clientId: string): string {
  const base = clientId.replace(/\.apps\.googleusercontent\.com$/, '');
  return base.length > 16 ? `${base.slice(0, 8)}…${base.slice(-4)}.apps.googleusercontent.com` : clientId;
}

// ------------------------------------------------------------------ "Web application" client (public sign-in)

/** Google Auth Platform pages for the public sign-in client (docs/SIMPLE_CONNECT_SPEC.md §6, Nachtrag). */
export function webClientLinks() {
  return {
    clients: consoleLink('/auth/clients'),
    audience: consoleLink('/auth/audience'),
    dataAccess: consoleLink('/auth/scopes'),
  };
}

/** The redirect URI of Perch's public sign-in: <PERCH_PUBLIC_BASE_URL>/oauth/google/callback. */
export function loginRedirectUri(publicOrigin: string): string {
  return `${publicOrigin}/oauth/google/callback`;
}

/** The client id form the public listener accepts (src/access/google.ts). */
export const WEB_CLIENT_ID_RE = /^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$/;

/**
 * Strict check of a pasted "Web application" client JSON for the public sign-in: the "web" key, a client id
 * on .apps.googleusercontent.com, a client secret and the exact redirect URI in redirect_uris. A "Desktop app"
 * client is refused with a hint. Messages never repeat the input (it holds the client secret).
 */
export function validateWebClientJson(text: string, expectedRedirect: string): ValidatedClient {
  const bad = (why: string) => new PerchError(`This is not a usable Google sign-in client: ${why}`, 'bad_client_file');
  if (Buffer.byteLength(text, 'utf8') > MAX_CLIENT_JSON_BYTES) throw bad(`larger than ${MAX_CLIENT_JSON_BYTES} bytes`);
  if (!text.trim()) throw bad('nothing was pasted');
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw bad('not valid JSON (paste the whole content of the downloaded file)');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw bad('not a JSON object');
  const doc = parsed as Record<string, unknown>;
  if (!('web' in doc)) {
    if ('installed' in doc) throw bad('it is a "Desktop app" client (the one for your accounts); create a new client of type "Web application"');
    throw bad('the "web" key of a "Web application" client is missing');
  }
  const c = doc.web as Record<string, unknown> | null;
  if (!c || typeof c !== 'object' || Array.isArray(c)) throw bad('the "web" entry is not an object');
  if (typeof c.client_id !== 'string' || !WEB_CLIENT_ID_RE.test(c.client_id)) throw bad('client_id must end with .apps.googleusercontent.com');
  if (typeof c.client_secret !== 'string' || c.client_secret.trim().length < 10 || c.client_secret.length > 200) {
    throw bad('client_secret is missing (download the JSON right after creating the client; Google shows the secret only then)');
  }
  const uris = Array.isArray(c.redirect_uris) ? c.redirect_uris : [];
  if (!uris.includes(expectedRedirect)) {
    throw bad(`redirect_uris lacks ${expectedRedirect} (add it under "Authorized redirect URIs", save, then download the JSON again)`);
  }
  return { clientId: c.client_id, clientSecret: c.client_secret, json: `${JSON.stringify(doc, null, 2)}\n` };
}
