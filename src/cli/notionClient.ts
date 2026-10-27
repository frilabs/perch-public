import type { PerchConfig } from '../config.js';
import { PerchError } from '../errors.js';
import {
  NOTION_OAUTH_REDIRECT_URI,
  parseNotionClient,
  readNotionClient,
  saveNotionClient,
  shortNotionClientId,
  type NotionClient,
} from '../notion/oauth.js';
import { NOTION_INTEGRATIONS_URL } from './notionGuide.js';
import { yes } from './onboarding.js';

/** The parts of CliIo the Notion OAuth client commands use. */
interface Io {
  stdout: (s: string) => void;
  readSecret: (prompt: string) => Promise<string>;
  readLine?: (prompt: string) => Promise<string>;
}

const UNUSABLE = new Set(['not_found', 'bad_client_file']);

async function tryRead(file: string): Promise<NotionClient | undefined> {
  try {
    return await readNotionClient(file);
  } catch (err) {
    if (err instanceof PerchError && UNUSABLE.has(err.code)) return undefined;
    throw err; // insecure permissions, symlink: stay an error, never "fixed" by the guide
  }
}

/**
 * Guided public-integration setup (once per installation): steps, then Client ID and Client Secret pasted hidden
 * (three attempts), stored 0600 in `file`.
 */
export async function runNotionClientGuide(io: Io, file: string): Promise<NotionClient> {
  const ask = io.readLine;
  if (!ask) throw new PerchError('perch notion client setup needs an interactive terminal', 'no_tty');
  io.stdout(
    '\nNotion OAuth client (once per Perch installation, works without owner rights):\n\n' +
      `1. Open ${NOTION_INTEGRATIONS_URL}\n` +
      '2. "New integration": name "Perch", type "Public" (OAuth).\n' +
      '   Installable in: "Any workspace".\n' +
      `3. Redirect URI: ${NOTION_OAUTH_REDIRECT_URI}\n` +
      '   Fill in the other required fields (company name, website,\n' +
      '   privacy policy, terms, e-mail) with your own details. Save.\n' +
      '4. Capabilities: Read content, Update content, Insert content,\n' +
      '   Read comments, Insert comments. Save changes.\n' +
      '5. Configuration tab: copy the "OAuth Client ID" and the\n' +
      '   "OAuth Client Secret".\n\n',
  );
  for (let attempt = 1; ; attempt++) {
    const clientId = await io.readSecret('OAuth Client ID (input hidden): ');
    const clientSecret = await io.readSecret('OAuth Client Secret (input hidden): ');
    try {
      const client = parseNotionClient({ clientId, clientSecret });
      await saveNotionClient(file, client);
      io.stdout(`Saved Notion OAuth client ${shortNotionClientId(client.clientId)} to\n  ${file}\n\n`);
      return client;
    } catch (err) {
      if (!(err instanceof PerchError) || err.code !== 'usage' || attempt >= 3) throw err;
      io.stdout(`${err.message}. Try again.\n`);
    }
  }
}

/** The OAuth client for `perch notion add --oauth`: the file, else the guide (terminal only), else a clear error. */
export async function ensureNotionClient(config: PerchConfig, io: Io): Promise<NotionClient> {
  const file = config.notionClientFile;
  const existing = await tryRead(file);
  if (existing) {
    // One client serves every workspace: reuse it (asked, so a wrong or rotated client can be replaced here).
    if (!io.readLine || yes(await io.readLine(`Use the stored Notion OAuth client (${shortNotionClientId(existing.clientId)})? [Y/n] `), true)) return existing;
    return runNotionClientGuide(io, file);
  }
  const noTerminal = new PerchError(
    `No usable Notion OAuth client at ${file}. Run perch notion client setup in a terminal (guided).`,
    'bad_config',
  );
  if (!io.readLine) throw noTerminal;
  io.stdout(`\nPerch needs a Notion OAuth client first; none is stored yet at\n  ${file}\n`);
  if (!yes(await io.readLine('Set it up now? [Y/n] '), true)) {
    throw new PerchError('Skipped: no Notion OAuth client yet. Later: perch notion client setup', 'bad_config');
  }
  return runNotionClientGuide(io, file);
}

/** `perch notion client setup | show`. */
export async function cmdNotionClient(config: PerchConfig, io: Io, action: string | undefined): Promise<void> {
  const file = config.notionClientFile;
  if (action === 'show') {
    const c = await tryRead(file);
    io.stdout(
      c
        ? `Notion OAuth client ${shortNotionClientId(c.clientId)}\n  file: ${file}\n  redirect URI: ${NOTION_OAUTH_REDIRECT_URI}\n`
        : `No usable Notion OAuth client at ${file}. Set one up: perch notion client setup\n`,
    );
    return;
  }
  if (action !== 'setup') throw new PerchError('Usage: perch notion client setup|show', 'usage');
  if (!io.readLine) throw new PerchError('perch notion client setup needs an interactive terminal', 'no_tty');
  const existing = await tryRead(file);
  if (existing && !yes(await io.readLine(`A Notion OAuth client (${shortNotionClientId(existing.clientId)}) is stored at ${file}. Replace it? [y/N] `))) {
    io.stdout('Kept the existing client.\n');
    return;
  }
  await runNotionClientGuide(io, file);
  io.stdout('Next: perch notion add --oauth --label NAME\n');
}
