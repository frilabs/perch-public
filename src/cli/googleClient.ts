import path from 'node:path';
import type { PerchConfig } from '../config.js';
import { PerchError } from '../errors.js';
import {
  apiLinks,
  authPlatformLinks,
  MAX_CLIENT_JSON_BYTES,
  shortClientId,
  validateClientJson,
  validProjectId,
} from '../google/clientSetup.js';
import { googleGroupScopes, type GoogleGroupRequest, type GoogleService } from '../google/group.js';
import { parseClientFile, type GoogleClientCredentials } from '../google/oauth.js';
import { EMAIL_SCOPE, USERINFO_EMAIL_SCOPE } from '../google/productivity.js';
import { ensurePrivateDir, pathExists, readPrivateFile, writePrivateFileAtomic } from '../secureFs.js';
import { chooseAccess, chooseGoogleServices, yes, type Ask } from './onboarding.js';

/**
 * Guided Google Cloud preparation in the terminal (docs/GUIDED_PROVIDER_SETUP_SPEC.md §1): used by
 * `perch google client setup` and, when the client file is missing, empty or invalid, by every Google `add`.
 */

export interface GoogleClientIo {
  env: Record<string, string | undefined>;
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  readLine?: Ask;
  /** Hidden, multi-line tolerant paste of the client JSON (TTY only in production). */
  readSecretJson?: (prompt: string, maxBytes: number) => Promise<string>;
}

/** What the client is prepared for: the APIs to enable and the scopes to list under "Data Access". */
export interface GoogleClientNeeds {
  services: readonly GoogleService[];
  scopes: readonly string[];
}

/** The file Perch reads the client from: PERCH_GOOGLE_CLIENT_FILE, else ~/.config/perch/google-client.json. */
export function googleClientPath(config: PerchConfig): string {
  return config.googleClientFile ?? config.googleClientDefaultFile;
}

/** Google write opt-ins of the selected services, from the add flags (as chooseAccess set them). */
export function googleRequestFromFlags(services: GoogleService[], values: Record<string, unknown>): GoogleGroupRequest {
  const on = (s: GoogleService, flag: string) => services.includes(s) && values[flag] === true;
  return {
    services,
    driveWrite: on('drive', 'allow-write'),
    gmail: { drafts: on('gmail', 'allow-drafts'), send: on('gmail', 'allow-send'), modify: on('gmail', 'allow-modify') },
    calendarWrite: on('calendar', 'allow-calendar-write'),
  };
}

const UNUSABLE = new Set(['not_found', 'bad_client_file']);

async function readClient(file: string): Promise<GoogleClientCredentials> {
  const text = (await readPrivateFile(file)).toString('utf8');
  if (!text.trim()) throw new PerchError(`The Google client file ${file} is empty`, 'bad_client_file');
  return parseClientFile(text);
}

/**
 * The Google OAuth client for an `add`: read from the client file; when it is missing, empty or invalid, the guided
 * setup runs (with a terminal) or a clear error points to `perch google client setup`. Insecure permissions are
 * never "fixed" by the guide: they stay an error.
 */
export async function loadGoogleClient(config: PerchConfig, io: GoogleClientIo, needs: GoogleClientNeeds): Promise<GoogleClientCredentials> {
  const file = googleClientPath(config);
  try {
    return await readClient(file);
  } catch (err) {
    if (!(err instanceof PerchError && UNUSABLE.has(err.code))) throw err;
    const reason = err.code === 'not_found' ? 'it does not exist yet' : 'it is empty or not a "Desktop app" client';
    const noTerminal = () =>
      new PerchError(
        `No usable Google OAuth client at ${file} (${reason}). Run perch google client setup in a terminal ` +
          'or set PERCH_GOOGLE_CLIENT_FILE to your Google "Desktop app" client JSON.',
        'bad_config',
      );
    if (!io.readLine || !io.readSecretJson) throw noTerminal();
    io.stdout(`Perch needs a Google OAuth client first: no usable client file at ${file} (${reason}).\n`);
    let go: string;
    try {
      go = await io.readLine('Set it up now? [Y/n] ');
    } catch (e) {
      if (e instanceof PerchError && e.code === 'no_tty') throw noTerminal();
      throw e;
    }
    if (!yes(go, true)) throw new PerchError('Skipped: no Google OAuth client yet. Later: perch google client setup', 'bad_config');
    return runGoogleClientGuide(config, io, needs);
  }
}

/** Scopes as the "Data Access" page lists them (it shows `email` as the userinfo.email URL). */
function dataAccessScopes(scopes: readonly string[]): string[] {
  return [...new Set(scopes.map((s) => (s === EMAIL_SCOPE ? USERINFO_EMAIL_SCOPE : s)))];
}

/**
 * The walk-through: project, APIs, Google Auth Platform (branding, audience, data access), Desktop-app client,
 * then the pasted JSON is checked and stored (0600, atomic). Returns the stored client.
 */
export async function runGoogleClientGuide(config: PerchConfig, io: GoogleClientIo, needs: GoogleClientNeeds): Promise<GoogleClientCredentials> {
  const ask = io.readLine;
  const paste = io.readSecretJson;
  if (!ask || !paste) throw new PerchError('perch google client setup needs an interactive terminal', 'no_tty');
  const enter = (what: string) => ask(`  ${what} Press Enter when done. `);
  const out = io.stdout;

  out('\nSet up a Google OAuth client once for this Perch installation.\n\n');
  let links = authPlatformLinks();
  out(`Step 1/5 - Create a project (any name, e.g. "Perch"):\n  ${links.projectCreate}\n`);
  let projectId = (await ask('  Project ID (Enter to choose it in the browser): ')).trim();
  if (projectId && !validProjectId(projectId)) {
    out('  Invalid project ID. Choose the project in the browser.\n');
    projectId = '';
  }
  links = authPlatformLinks(projectId || undefined);

  out('\nStep 2/5 - Enable the APIs (open each link, click "Enable"):\n');
  for (const a of apiLinks(needs.services, projectId || undefined)) out(`  ${a.title}: ${a.url}\n`);
  await enter('');

  out(
    '\nStep 3/5 - Google Auth Platform (consent screen):\n' +
      `  a) Branding: app name "Perch", your e-mail as support and developer contact. Save.\n     ${links.branding}\n` +
      `  b) Audience: user type "External", publishing status "Testing"; under "Test users" add every Google account you\n` +
      `     will connect to Perch.\n     ${links.audience}\n` +
      `  c) Data Access: "Add or remove scopes", paste these under "Manually add scopes", then "Add to table" and Save:\n     ${links.dataAccess}\n`,
  );
  for (const s of dataAccessScopes(needs.scopes)) out(`       ${s}\n`);
  await enter('');

  out(
    `\nStep 4/5 - Create the OAuth client: application type "Desktop app", name "Perch", Create, then "Download JSON".\n  ${links.clients}\n`,
  );
  await enter('');

  out('\nStep 5/5 - Open the downloaded JSON file and paste its full contents here.\n');
  let client: ReturnType<typeof validateClientJson> | undefined;
  for (let attempt = 1; !client; attempt++) {
    const text = await paste('  Client JSON (input hidden; Enter after pasting): ', MAX_CLIENT_JSON_BYTES);
    try {
      client = validateClientJson(text);
    } catch (err) {
      if (!(err instanceof PerchError) || attempt >= 3) throw err;
      out(`  ${err.message}. Try again.\n`);
    }
  }
  const file = googleClientPath(config);
  await saveClientFile(file, client.json);
  out(`\nSaved Google OAuth client ${shortClientId(client.clientId)} to ${file}.\n`);
  out('In Google Testing mode, reconnect after 7 days using the same add command.\n\n');
  return { clientId: client.clientId, clientSecret: client.clientSecret };
}

async function saveClientFile(file: string, json: string): Promise<void> {
  const dir = path.dirname(file);
  // A directory Perch creates is 0700; an existing one (chosen via PERCH_GOOGLE_CLIENT_FILE) is used as it is.
  if (!(await pathExists(dir))) await ensurePrivateDir(dir);
  await writePrivateFileAtomic(file, Buffer.from(json, 'utf8'));
}

/** `perch google client setup|show`. */
export async function cmdGoogleClient(config: PerchConfig, io: GoogleClientIo, sub: string | undefined, values: Record<string, unknown>): Promise<void> {
  const file = googleClientPath(config);
  if (sub === 'show') {
    try {
      const c = await readClient(file);
      io.stdout(`Google OAuth client ${shortClientId(c.clientId)}\n  file: ${file}${config.googleClientFile ? ' (PERCH_GOOGLE_CLIENT_FILE)' : ' (default path)'}\n`);
    } catch (err) {
      if (!(err instanceof PerchError && UNUSABLE.has(err.code))) throw err;
      io.stdout(`No usable Google OAuth client at ${file}. Set one up: perch google client setup\n`);
    }
    return;
  }
  if (sub !== 'setup') throw new PerchError('Usage: perch google client setup | show', 'usage');
  if (!io.readLine) throw new PerchError('perch google client setup needs an interactive terminal', 'no_tty');
  let existing: GoogleClientCredentials | undefined;
  try {
    existing = await readClient(file);
  } catch (err) {
    if (!(err instanceof PerchError && UNUSABLE.has(err.code))) throw err;
  }
  if (existing && !yes(await io.readLine(`A Google OAuth client (${shortClientId(existing.clientId)}) is already stored at ${file}. Replace it? [y/N] `))) {
    io.stdout('Kept the existing client.\n');
    return;
  }
  const services = await chooseGoogleServices(values, io.readLine, io.stderr);
  await chooseAccess('google', values, io.readLine, io.stderr);
  await runGoogleClientGuide(config, io, { services, scopes: googleGroupScopes(googleRequestFromFlags(services, values)) });
  io.stdout('Next: perch google add --label NAME\n');
}
