import { randomBytes } from 'node:crypto';
import { userInfo } from 'node:os';
import path from 'node:path';
import { PRIVATE_OAUTH_DISABLED, PRIVATE_OAUTH_OFF } from '../access/baseUrl.js';
import { pairingBlocker } from '../access/runtime.js';
import { OAuthStore, type ListenerKind } from '../access/state.js';
import { createClientGrant } from '../auth/grants.js';
import type { PerchConfig } from '../config.js';
import { PerchError } from '../errors.js';
import { CredentialStore } from '../store/credentialStore.js';
import { pair, ACCESS_PROMPT, type PairAccessChoice } from './oauth.js';
import { yes } from './onboarding.js';
import { loginClientBlocker, publicSetup } from './publicSetup.js';
import type { CliIo } from './run.js';
import { wrap } from './text.js';

/**
 * perch connect (docs/SIMPLE_CONNECT_SPEC.md §3): a guide per AI. It prints the right address (private for
 * clients in the tailnet, public for clients that connect from a provider's cloud), the exact steps and
 * commands, and then offers to open a pairing window (like perch oauth pair). An agent on this server gets a
 * client grant with a token file instead; the token is never printed.
 */
export const CONNECT_TARGETS = ['claude-code', 'codex', 'claude-ai', 'chatgpt', 'desktop', 'server-agent', 'other'] as const;
export type ConnectTarget = (typeof CONNECT_TARGETS)[number];

const MENU: Array<[ConnectTarget, string]> = [
  ['claude-code', 'Claude Code'],
  ['codex', 'Codex'],
  ['claude-ai', 'claude.ai (web, desktop app, phone)'],
  ['chatgpt', 'ChatGPT'],
  ['desktop', 'Desktop chat app on a computer in your tailnet'],
  ['server-agent', 'Agent on this server'],
  ['other', 'Other MCP client'],
];


interface Addresses {
  /** Private MCP address (tailnet), if private OAuth is on. */
  privateUrl?: string;
  /** Public MCP address, if public access is configured. */
  publicUrl?: string;
  /** Why the public address cannot pair yet (null: it can). */
  publicBlocker: string | null;
}

async function addresses(config: PerchConfig): Promise<Addresses> {
  const privateUrl = config.privateBaseUrl ? `${config.privateBaseUrl}/mcp` : undefined;
  if (!config.publicBaseUrl) return { ...(privateUrl ? { privateUrl } : {}), publicBlocker: 'PERCH_PUBLIC_BASE_URL is not set.' };
  const publicUrl = `${new URL(config.publicBaseUrl).origin}/mcp`;
  let blocker: string | null;
  try {
    const store = await CredentialStore.open({ dataDir: config.dataDir, keyFile: config.keyFile });
    // In the order of perch public setup: the sign-in client first, then account and Perch code.
    blocker = (await loginClientBlocker(config)) ?? pairingBlocker(await new OAuthStore(store).read());
  } catch (err) {
    blocker = err instanceof PerchError ? err.message : 'The public access state could not be read.';
  }
  return { ...(privateUrl ? { privateUrl } : {}), publicUrl, publicBlocker: blocker };
}

const out = (io: CliIo, ...parts: string[]) => io.stdout(parts.join(''));
const step = (n: number, text: string) => wrap(text, '     ', 80, `  ${n}. `);
const cmd = (command: string) => `       ${command}\n`;

/** The public access is missing: offer perch public setup right away (SIMPLE_CONNECT_SPEC §6, Nachtrag). */
async function publicMissing(config: PerchConfig, io: CliIo, what: string, target: 'claude-ai' | 'chatgpt', a: Addresses): Promise<number> {
  out(io, wrap(`${what} needs Perch's public address.`), wrap(`Public access is not ready yet: ${a.publicBlocker ?? 'not configured.'}`));
  if (io.readLine) {
    const answer = await io.readLine('Set it up now? [Y/n] ').catch(() => 'n');
    if (yes(answer, true)) return publicSetup(config, io, { target, confirmed: true });
  }
  out(io, '\nSet it up first, then run perch connect again:\n', '  perch public setup\n', `  perch connect --target ${target}\n`);
  return 1;
}

function privateMissing(io: CliIo, what: string, config: PerchConfig): void {
  out(io, wrap(`${what} connects over your tailnet, but private OAuth is not available.`), wrap(config.privateOAuth ? PRIVATE_OAUTH_OFF : PRIVATE_OAUTH_DISABLED), '\n');
}

/** Steps for a client that connects over the tailnet (private) or, without one, the public address. */
function tailnetOrPublic(io: CliIo, what: string, a: Addresses, config: PerchConfig): string | null {
  if (a.privateUrl) return a.privateUrl;
  privateMissing(io, what, config);
  if (a.publicUrl && !a.publicBlocker) {
    out(io, wrap(`Using the public address instead: ${a.publicUrl}`), '\n');
    return a.publicUrl;
  }
  return null;
}

function awayHint(io: CliIo, a: Addresses, url: string): void {
  if (url === a.privateUrl && a.publicUrl) {
    out(io, '\n', wrap(`Outside your tailnet, use:${a.publicBlocker ? ' (set up first: perch public setup)' : ''}`), `  ${a.publicUrl}\n`);
  }
}

async function chooseTarget(io: CliIo): Promise<ConnectTarget> {
  if (!io.readLine) throw new PerchError('perch connect needs a terminal; or pass --target (claude-code, codex, claude-ai, chatgpt, desktop, server-agent, other)', 'no_tty');
  out(io, 'Which AI do you want to connect to Perch?\n');
  MENU.forEach(([, label], i) => out(io, `  ${i + 1}  ${label}\n`));
  for (let i = 0; i < 3; i++) {
    const a = (await io.readLine(`Choice [1-${MENU.length}]: `)).trim().toLowerCase();
    const byNumber = MENU[Number(a) - 1];
    if (byNumber) return byNumber[0];
    const byName = MENU.find(([t]) => t === a);
    if (byName) return byName[0];
  }
  throw new PerchError('No AI chosen; nothing was changed', 'aborted');
}

/** Agent on this server: a client grant with a 0600 token file; the token is never printed. */
async function serverAgent(config: PerchConfig, io: CliIo, values: Record<string, unknown>): Promise<number> {
  const user = userInfo().username;
  out(
    io,
    wrap("Perch saves this agent's token in a private file."),
    '\n',
  );
  let access: PairAccessChoice;
  if (values.full === true && values['read-only'] === true) throw new PerchError('Use either --full or --read-only', 'usage');
  if (values.full === true) access = 'full';
  else if (values['read-only'] === true) access = 'read';
  else {
    if (!io.readLine) throw new PerchError('Choose the rights with --full or --read-only (no terminal to ask)', 'usage');
    out(io, 'Read only: reads every account, writes nothing.\nFull: reads and writes on every account, also on accounts added later.\n');
    access = /^(f|full)$/i.test((await io.readLine(ACCESS_PROMPT).catch(() => '')).trim()) ? 'full' : 'read';
  }
  const label = typeof values.label === 'string' && values.label.trim() ? values.label.trim() : 'server agent';
  const tokenFile = path.resolve(typeof values['token-file'] === 'string' ? values['token-file'] : path.join(path.dirname(config.tokenFile), 'clients', `${randomBytes(4).toString('hex')}.token`));
  const store = await CredentialStore.open({ dataDir: config.dataDir, keyFile: config.keyFile });
  const { client } = await createClientGrant(store, { label, capabilities: [], accountIds: [], tokenFile, ...(access === 'full' ? { full: true } : { readAll: true }) });
  const local = `http://127.0.0.1:${config.httpPort}/mcp`;
  out(
    io,
    `\nCreated client ${client.id} "${client.label}", ${access === 'full' ? 'FULL access (read and write)' : 'read only'}.\n`,
    wrap(`Token file (readable only by ${user}):`),
    `  ${tokenFile}\n`,
    `MCP address on this server:\n  ${local}\n\n`,
    wrap(
      `Send "Authorization: Bearer <contents of the token file>" to the MCP address, or for stdio set PERCH_CLIENT_TOKEN_FILE to the file. An agent running as another user needs a copy it can read (as root: install -o <user> -m 600 <token file> <target>).`,
    ),
    `\nRevoke: perch client remove ${client.id}\n`,
  );
  return 0;
}

/** Opens a window for exactly the listener this target connects to (private or public). */
async function maybePair(config: PerchConfig, io: CliIo, values: Record<string, unknown>, nonInteractive: boolean, listener: ListenerKind): Promise<number> {
  const later = `When you are ready: perch oauth pair --${listener}\n`;
  if (values['no-pair'] === true) {
    out(io, `\n${later}`);
    return 0;
  }
  if (!nonInteractive) {
    out(io, `\nPairing address: ${listener}.\n`);
    const a = io.readLine ? (await io.readLine('Open a pairing window now? [Y/n] ').catch(() => 'n')).trim() : 'n';
    if (/^(n|no|nein)$/i.test(a)) {
      out(io, later);
      return 0;
    }
  }
  out(io, '\n');
  const access = values.full === true ? { access: 'full' as const } : values['read-only'] === true ? { access: 'read' as const } : {};
  return pair(config, io, { ...access, listener });
}

const listenerOf = (a: Addresses, url: string): ListenerKind => (url === a.privateUrl ? 'private' : 'public');

export async function cmdConnect(config: PerchConfig, io: CliIo, values: Record<string, unknown>): Promise<number> {
  const given = values.target;
  if (given !== undefined && (typeof given !== 'string' || !(CONNECT_TARGETS as readonly string[]).includes(given))) {
    throw new PerchError(`--target must be one of ${CONNECT_TARGETS.join(', ')}`, 'usage');
  }
  const nonInteractive = given !== undefined;
  const target = (given as ConnectTarget | undefined) ?? (await chooseTarget(io));
  if (target === 'server-agent') return serverAgent(config, io, values);
  const a = await addresses(config);

  if (target === 'claude-code') {
    const url = tailnetOrPublic(io, 'Claude Code', a, config);
    if (!url) return 1;
    out(
      io,
      '\nClaude Code:\n',
      step(1, 'On the computer with Claude Code, add Perch:'),
      cmd(`claude mcp add --scope user --transport http perch ${url}`),
      step(2, 'In Claude Code: /mcp → perch → Authenticate. Enter the pairing code in the browser.'),
      step(3, 'Return here to confirm the sign-in and choose access.'),
    );
    awayHint(io, a, url);
    return maybePair(config, io, values, nonInteractive, listenerOf(a, url));
  }
  if (target === 'codex') {
    const url = tailnetOrPublic(io, 'Codex', a, config);
    if (!url) return 1;
    out(
      io,
      '\nCodex:\n',
      step(1, 'On the computer with Codex, add Perch:'),
      cmd(`codex mcp add perch --url ${url}`),
      wrap('or add these lines to ~/.codex/config.toml:', '     '),
      cmd('[mcp_servers.perch]'),
      cmd(`url = "${url}"`),
      step(2, 'Sign in and enter the pairing code in the browser:'),
      cmd('codex mcp login perch'),
      step(3, 'Return here to confirm the sign-in and choose access.'),
    );
    awayHint(io, a, url);
    return maybePair(config, io, values, nonInteractive, listenerOf(a, url));
  }
  if (target === 'claude-ai') {
    if (!a.publicUrl || a.publicBlocker) return publicMissing(config, io, 'claude.ai', 'claude-ai', a);
    out(
      io,
      '\nclaude.ai:\n',
      step(1, 'In claude.ai open Settings, Connectors, Add custom connector. Name: Perch. URL:'),
      cmd(a.publicUrl),
      step(2, 'Click Connect. Enter the pairing code, sign in with Google, and enter your Perch code.'),
      step(3, 'Return here to confirm the sign-in and choose access. Pair again every 90 days.'),
    );
    return maybePair(config, io, values, nonInteractive, 'public');
  }
  if (target === 'chatgpt') {
    if (!a.publicUrl || a.publicBlocker) return publicMissing(config, io, 'ChatGPT', 'chatgpt', a);
    out(
      io,
      '\nChatGPT:\n',
      step(1, 'In ChatGPT open Settings, Apps & Connectors, Advanced settings and turn on Developer mode. Then create a connector with this MCP server URL and Authentication OAuth:'),
      cmd(a.publicUrl),
      step(2, 'Connect. Enter the pairing code, sign in with Google, and enter your Perch code.'),
      step(3, 'Return here to confirm the sign-in and choose access.'),
    );
    return maybePair(config, io, values, nonInteractive, 'public');
  }
  if (target === 'desktop') {
    const url = tailnetOrPublic(io, 'A desktop chat app', a, config);
    if (!url) return 1;
    out(
      io,
      '\nDesktop chat app on a computer in your tailnet:\n',
      step(1, 'App with remote MCP servers and OAuth: add this address as a remote (HTTP) MCP server. The app opens the sign-in in your browser.'),
      cmd(url),
      step(2, 'App with local (stdio) servers only: start the bridge mcp-remote from its MCP configuration:'),
      cmd(`"perch": { "command": "npx", "args": ["mcp-remote", "${url}"] }`),
      step(3, 'The browser asks for the pairing code. Return here to confirm the sign-in and choose access.'),
      '\n',
      wrap("Custom connectors in the Claude desktop app run in Anthropic's cloud: use the target claude-ai for those."),
    );
    return maybePair(config, io, values, nonInteractive, listenerOf(a, url));
  }
  // other
  if (!a.privateUrl && !(a.publicUrl && !a.publicBlocker)) {
    privateMissing(io, 'An MCP client', config);
    return 1;
  }
  out(io, '\nOther MCP client (Streamable HTTP with OAuth 2.1):\n');
  if (a.privateUrl) out(io, '  In your tailnet:   ', `${a.privateUrl}\n`);
  if (a.publicUrl && !a.publicBlocker) out(io, '  From the internet: ', `${a.publicUrl}\n`);
  out(
    io,
    '\n',
    wrap(
      'Add the address in your client. Enter the pairing code in the browser, then confirm the sign-in here.',
    ),
    wrap('For a client without OAuth, create a token file:'),
    '  perch client add --label NAME --read-all   (or --full)\n',
  );
  return maybePair(config, io, values, nonInteractive, a.privateUrl ? 'private' : 'public');
}
