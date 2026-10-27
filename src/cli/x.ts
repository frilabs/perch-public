import { homedir } from 'node:os';
import type { PerchConfig } from '../config.js';
import { PerchError } from '../errors.js';
import { DEFAULT_AUTH_TIMEOUT_MS, MAX_AUTH_TIMEOUT_MS } from '../oauth/loopback.js';
import { CredentialStore } from '../store/credentialStore.js';
import { createFetchTransport, Upstream } from '../upstream.js';
import {
  fetchXMe,
  parseXClient,
  readXClient,
  runXAuthorization,
  saveXClient,
  shortXClientId,
  upsertXAccount,
  X_DEVELOPER_URL,
  X_OAUTH_REDIRECT_URI,
  xClientFileFor,
  xClientKind,
  type XClient,
} from '../x/oauth.js';
import { removeXAccount } from '../x/x.js';
import { loginPrompts } from './loginPrompt.js';
import { yes } from './onboarding.js';
import type { CliIo } from './run.js';

/** perch x … (docs/X_SPEC.md). Local CLI only. */
const usage = (m: string) => new PerchError(m, 'usage');

/** The parts of CliIo the X client commands use. */
interface ClientIo {
  stdout: (s: string) => void;
  readSecret: (prompt: string) => Promise<string>;
  readLine?: (prompt: string) => Promise<string>;
}

const UNUSABLE = new Set(['not_found', 'bad_client_file']);

async function tryRead(file: string): Promise<XClient | undefined> {
  try {
    return await readXClient(file);
  } catch (err) {
    if (err instanceof PerchError && UNUSABLE.has(err.code)) return undefined;
    throw err; // insecure permissions, symlink: stay an error, never "fixed" by the guide
  }
}

/** The steps (every line at most 80 columns; checked in a real pseudo-terminal). */
export const X_CLIENT_GUIDE =
  '\nX developer app (once per Perch installation):\n\n' +
  `1. Open ${X_DEVELOPER_URL}\n` +
  '   and sign in. Buy API credits under "Billing" before posting.\n' +
  '2. Create an app (or open the existing one in your project).\n' +
  '3. "User authentication settings" -> "Set up":\n' +
  '   App permissions: "Read and write".\n' +
  '   Type of App: "Native App".\n' +
  `   Callback URI / Redirect URL: ${X_OAUTH_REDIRECT_URI}\n` +
  '   Website URL: any site of yours (X requires one). Save.\n' +
  '4. "Keys and tokens" -> "OAuth 2.0 Client ID and Client Secret":\n' +
  '   copy the Client ID (and the Client Secret, if X shows one).\n\n';

/** Guided app setup: steps, then Client ID and (optional) Client Secret pasted hidden (three attempts), stored 0600. */
export async function runXClientGuide(io: ClientIo, file: string): Promise<XClient> {
  if (!io.readLine) throw new PerchError('perch x client setup needs an interactive terminal', 'no_tty');
  io.stdout(X_CLIENT_GUIDE);
  for (let attempt = 1; ; attempt++) {
    const clientId = await io.readSecret('OAuth 2.0 Client ID (input hidden): ');
    const clientSecret = await io.readSecret('OAuth 2.0 Client Secret (input hidden; Enter if none): ');
    try {
      const client = parseXClient({ clientId, clientSecret });
      await saveXClient(file, client);
      io.stdout(`Saved the X client (${shortXClientId(client.clientId)}, ${xClientKind(client)}) to\n  ${file}\n\n`);
      return client;
    } catch (err) {
      if (!(err instanceof PerchError) || err.code !== 'usage' || attempt >= 3) throw err;
      io.stdout(`${err.message}. Try again.\n`);
    }
  }
}

export const xClientFile = (io: { env: Record<string, string | undefined> }) => xClientFileFor(io.env, homedir());

/** The app for `perch x add`: the file, else the guide (terminal only), else a clear error. */
export async function ensureXClient(io: ClientIo, file: string): Promise<XClient> {
  const existing = await tryRead(file);
  if (existing) {
    if (!io.readLine || yes(await io.readLine(`Use the stored X client (${shortXClientId(existing.clientId)})? [Y/n] `), true)) return existing;
    return runXClientGuide(io, file);
  }
  const noTerminal = new PerchError(`No usable X client at ${file}. Run perch x client setup in a terminal (guided).`, 'bad_config');
  if (!io.readLine) throw noTerminal;
  io.stdout(`\nPerch needs your X developer app first; none is stored yet at\n  ${file}\n`);
  if (!yes(await io.readLine('Set it up now? [Y/n] '), true)) {
    throw new PerchError('Skipped: no X client yet. Later: perch x client setup', 'bad_config');
  }
  return runXClientGuide(io, file);
}

async function cmdXClient(io: CliIo, action: string | undefined): Promise<void> {
  const file = xClientFile(io);
  if (action === 'show') {
    const c = await tryRead(file);
    io.stdout(
      c
        ? `X client ${shortXClientId(c.clientId)} (${xClientKind(c)})\n  file: ${file}\n  redirect URI: ${X_OAUTH_REDIRECT_URI}\n`
        : `No usable X client at ${file}. Set one up: perch x client setup\n`,
    );
    return;
  }
  if (action !== 'setup') throw usage('Usage: perch x client setup|show');
  if (!io.readLine) throw new PerchError('perch x client setup needs an interactive terminal', 'no_tty');
  const existing = await tryRead(file);
  if (existing && !yes(await io.readLine(`An X client (${shortXClientId(existing.clientId)}) is stored at ${file}. Replace it? [y/N] `))) {
    io.stdout('Kept the existing client.\n');
    return;
  }
  await runXClientGuide(io, file);
  io.stdout('Next: perch x add --label NAME\n');
}

export async function cmdX(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>): Promise<void> {
  if (sub === 'client') return cmdXClient(io, rest[0]);
  const store = await CredentialStore.open({ dataDir: config.dataDir, keyFile: config.keyFile });
  const upstream = new Upstream(io.transport ?? createFetchTransport());
  if (sub === 'list') {
    const d = await store.read();
    const lines = ['X accounts (labels are user-assigned):'];
    if (!d.x.length) lines.push('  (none)');
    for (const a of d.x) lines.push(`  ${a.id}  "${a.label}"  @${a.username}  ${a.scopes.includes('tweet.write') ? 'read+post' : 'read'}  connected ${a.createdAt}`);
    io.stdout(`${lines.join('\n')}\n`);
    return;
  }
  if (sub === 'remove') {
    const id = rest[0];
    if (!id) throw usage('Usage: perch x remove ID [--revoke]');
    const { revoked } = await removeXAccount(store, upstream, id, Boolean(values.revoke));
    io.stdout(
      `Removed ${id} locally.${revoked ? ' The login was revoked at X.' : values.revoke ? ' Revoking at X failed; remove the app under x.com → Settings → Connected apps.' : ''}\n`,
    );
    return;
  }
  if (sub !== 'add') throw usage('Usage: perch x add|list|remove|client');
  if (typeof values.label !== 'string') throw usage('--label is required');
  if (values.port !== undefined) throw usage(`perch x add uses the fixed port ${new URL(X_OAUTH_REDIRECT_URI).port} (the redirect URL registered in the X app)`);
  const timeoutS = values.timeout !== undefined ? Number(values.timeout) : DEFAULT_AUTH_TIMEOUT_MS / 1000;
  if (!Number.isInteger(timeoutS) || timeoutS < 1 || timeoutS > MAX_AUTH_TIMEOUT_MS / 1000) throw usage(`--timeout must be 1-${MAX_AUTH_TIMEOUT_MS / 1000} seconds`);
  const client = await ensureXClient(io, xClientFile(io));
  const grant = await runXAuthorization({
    client,
    upstream,
    timeoutMs: timeoutS * 1000,
    ...loginPrompts(io, 'sign in to the X account you want to add', timeoutS * 1000),
  });
  const me = await fetchXMe(upstream, grant.accessToken);
  const { account, updated } = await upsertXAccount(store, { label: values.label, grant, me });
  io.stdout(
    `${updated ? 'Updated' : 'Connected'} X account ${account.id} "${account.label}" (@${account.username}).\n` +
      'Posting needs a client grant, e.g.:\n' +
      `  perch client add --label NAME --allow x_read,x_post --account ${account.id}\n` +
      "Every post is billed to your X developer account (pay-per-use; see developer.x.com).\n",
  );
}
