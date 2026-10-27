import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { request } from 'node:http';
import path from 'node:path';
import { parseBaseUrl } from '../access/baseUrl.js';
import { loadGoogleLoginClient } from '../access/google.js';
import { pairingBlocker } from '../access/runtime.js';
import { expireDevices, isPublicLocked, OAuthStore } from '../access/state.js';
import type { PerchConfig } from '../config.js';
import { PerchError } from '../errors.js';
import { loginRedirectUri, MAX_CLIENT_JSON_BYTES, shortClientId, validateWebClientJson, webClientLinks } from '../google/clientSetup.js';
import { ensurePrivateDir, pathExists, readPrivateFile, writePrivateFileAtomic } from '../secureFs.js';
import { CredentialStore } from '../store/credentialStore.js';
import { yes } from './onboarding.js';
import { loginAllow, totpSetup } from './oauth.js';
import type { CliIo } from './run.js';
import { wrap } from './text.js';

/**
 * Guided setup and status of the public access (docs/SIMPLE_CONNECT_SPEC.md §6, Nachtrag 2026-10-27):
 * public address, Google "Web application" sign-in client, allowed Google account, Perch code, then a
 * checklist with the exact commands (systemd unit, Tailscale Funnel, a curl test, perch connect).
 * Perch never changes Tailscale or systemd itself; it changes the .env file only after an explicit [y/N].
 */

/** Ports Tailscale Funnel can serve. */
export const FUNNEL_PORTS = [443, 8443, 10000] as const;

/** The sign-in client file: PERCH_GOOGLE_LOGIN_CLIENT_FILE, else ~/.config/perch/google-web-client.json. */
export function loginClientFile(config: PerchConfig): string {
  return config.googleLoginClientFile ?? config.googleLoginClientDefaultFile;
}

/** The env file the process was started with: the last --env-file of Node (or --env-file-if-exists), else PERCH_ENV_FILE. */
export function detectEnvFile(execArgv: readonly string[], env: Record<string, string | undefined>): string | undefined {
  let found: string | undefined;
  for (let i = 0; i < execArgv.length; i++) {
    const a = execArgv[i]!;
    const m = /^--env-file(?:-if-exists)?=(.+)$/.exec(a);
    if (m) found = m[1];
    else if ((a === '--env-file' || a === '--env-file-if-exists') && execArgv[i + 1]) found = execArgv[++i];
  }
  if (!found && env.PERCH_ENV_FILE?.trim()) found = env.PERCH_ENV_FILE.trim();
  return found ? path.resolve(found) : undefined;
}

/** `tailscale funnel status` (local daemon only, no network); undefined when tailscale is missing or fails. */
export function tailscaleFunnelStatus(): Promise<string | undefined> {
  return new Promise((resolve) => {
    execFile('tailscale', ['funnel', 'status'], { timeout: 3000, maxBuffer: 256 * 1024 }, (err, stdout) => resolve(err ? undefined : String(stdout)));
  });
}

export type FunnelState = 'on' | 'off' | 'wrong_target' | 'unknown';

/** Reads `tailscale funnel status`: is `origin` funnelled to the public listener? */
export function parseFunnelStatus(text: string | undefined, origin: string, publicPort: number): FunnelState {
  if (text === undefined) return 'unknown';
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.trim().startsWith(`${origin} `) && /\(Funnel on\)/.test(l));
  if (start < 0) return 'off';
  for (let i = start + 1; i < lines.length && /^\s*\|/.test(lines[i]!); i++) {
    if (new RegExp(`proxy https?://(127\\.0\\.0\\.1|localhost):${publicPort}/?\\s*$`).test(lines[i]!)) return 'on';
  }
  return 'wrong_target';
}

/**
 * Suggests the public address from the tailnet name in PERCH_ALLOWED_HOSTS: port 10000 when 443 already serves
 * the private address (Tailscale Serve), else 443. Undefined without a tailnet name.
 */
export function suggestPublicBaseUrl(config: Pick<PerchConfig, 'allowedHosts' | 'privateBaseUrl'>): string | undefined {
  const host = config.allowedHosts.map((h) => h.trim().toLowerCase()).find((h) => /^[a-z0-9-]+(\.[a-z0-9-]+)*\.ts\.net$/.test(h));
  if (!host) return undefined;
  const privateOn443 = config.privateBaseUrl ? new URL(config.privateBaseUrl).host === host : false;
  return privateOn443 ? `https://${host}:10000` : `https://${host}`;
}

/** The https port of a public base URL (443 when none is given). */
export const httpsPort = (base: URL) => Number(base.port || 443);

interface UnitInfo {
  file: string;
  /** The path as shown in commands (~/… under HOME). */
  shown: string;
  text: string;
  hasPublic: boolean;
  /** The ExecStart line ends with `serve --http` (the documented unit), so a sed can add --public. */
  sedable: boolean;
}

/** The systemd user unit ~/.config/systemd/user/perch.service, if it exists. */
async function readUnit(env: Record<string, string | undefined>): Promise<UnitInfo | undefined> {
  const home = env.HOME;
  const configHome = env.XDG_CONFIG_HOME || (home ? path.join(home, '.config') : undefined);
  if (!configHome) return undefined;
  const file = path.join(configHome, 'systemd', 'user', 'perch.service');
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch {
    return undefined;
  }
  const shown = home && file === path.join(home, '.config', 'systemd', 'user', 'perch.service') ? '~/.config/systemd/user/perch.service' : file;
  const exec = text.split('\n').filter((l) => /^\s*ExecStart\s*=/.test(l));
  return { file, shown, text, hasPublic: exec.some((l) => /\s--public(\s|$)/.test(l)), sedable: exec.some((l) => /serve --http$/.test(l)) };
}

/** Is the public listener answering on 127.0.0.1:<port> for this origin (local only)? */
function probeListener(port: number, base: URL): Promise<boolean> {
  return new Promise((resolve) => {
    const req = request(
      { host: '127.0.0.1', port, path: '/.well-known/oauth-authorization-server', method: 'GET', headers: { host: base.host }, timeout: 1500 },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c: string) => {
          if (body.length < 64 * 1024) body += c;
        });
        res.on('end', () => {
          try {
            resolve(res.statusCode === 200 && (JSON.parse(body) as { issuer?: unknown }).issuer === base.origin);
          } catch {
            resolve(false);
          }
        });
      },
    );
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
    req.end();
  });
}

type ClientCheck = { ok: true; clientId: string } | { ok: false; reason: string; code: string };

async function checkLoginClient(file: string, origin: string): Promise<ClientCheck> {
  try {
    const c = await loadGoogleLoginClient(file, loginRedirectUri(origin));
    return { ok: true, clientId: c.clientId };
  } catch (err) {
    if (!(err instanceof PerchError)) throw err;
    return { ok: false, code: err.code, reason: err.code === 'not_found' ? 'it does not exist yet' : err.message };
  }
}

/** Why the public address cannot be used yet because of the sign-in client (null: it can). For perch connect. */
export async function loginClientBlocker(config: PerchConfig): Promise<string | null> {
  if (!config.publicBaseUrl) return 'PERCH_PUBLIC_BASE_URL is not set.';
  const c = await checkLoginClient(loginClientFile(config), parseBaseUrl(config.publicBaseUrl).origin);
  return c.ok ? null : `No usable Google sign-in client (${c.reason}).`;
}

// ------------------------------------------------------------------ texts

const out = (io: CliIo, ...parts: string[]) => io.stdout(parts.join(''));
const say = (text: string) => wrap(text, '  ');
const cmdLine = (command: string) => `      ${command}\n`;

/** The console walk-through for the "Web application" client (lines within 80 columns except URLs). */
export function webClientGuideText(origin: string): string {
  const links = webClientLinks();
  const redirect = loginRedirectUri(origin);
  return (
    say('Use the Google Cloud project of your Desktop client (or any other project).') +
    '\n' +
    wrap('Audience: your Google account must be listed under "Test users" while the app is in "Testing":', '     ', 80, '  a) ') +
    `     ${links.audience}\n` +
    wrap('Data Access: the sign-in uses only the scopes openid and email. Nothing else is needed; if they are not listed, add openid and .../auth/userinfo.email:', '     ', 80, '  b) ') +
    `     ${links.dataAccess}\n` +
    wrap('Clients: "Create client", application type "Web application", name "Perch sign-in":', '     ', 80, '  c) ') +
    `     ${links.clients}\n` +
    wrap('Under "Authorized redirect URIs" click "Add URI" and paste exactly:', '     ') +
    `       ${redirect}\n` +
    wrap('Leave "Authorized JavaScript origins" empty. Click "Create".', '     ') +
    wrap('In the dialog "OAuth client created" click "Download JSON" (Google shows the client secret only now).', '     ', 80, '  d) ')
  );
}

export interface ChecklistInput {
  origin: string;
  publicPort: number;
  unit?: Pick<UnitInfo, 'shown' | 'hasPublic' | 'sedable'>;
  /** The service has to be (re)started: something changed, or the listener does not run. */
  restartNeeded: boolean;
  listener: boolean;
  funnel: FunnelState;
  target?: 'claude-ai' | 'chatgpt';
}

/** The command that starts Perch with the public listener (or restarts it). */
export function serviceCommand(unit: ChecklistInput['unit']): { why: string; command: string } {
  if (!unit) return { why: 'Start Perch with the public listener (keep it running):', command: 'perch serve --http --public' };
  if (unit.hasPublic) return { why: 'Restart the Perch service so it loads the new settings:', command: 'systemctl --user restart perch' };
  if (unit.sedable) {
    return {
      why: 'Add --public to your systemd unit and restart Perch:',
      command: `sed -i 's#serve --http$#serve --http --public#' ${unit.shown} && systemctl --user daemon-reload && systemctl --user restart perch`,
    };
  }
  return {
    why: `In ${unit.shown}, add --public after "serve --http" in the ExecStart line, then reload and restart:`,
    command: 'systemctl --user daemon-reload && systemctl --user restart perch',
  };
}

export const funnelCommand = (origin: string, publicPort: number) => `sudo tailscale funnel --bg --https=${httpsPort(new URL(origin))} http://127.0.0.1:${publicPort}`;
export const curlCommand = (origin: string) => `curl -s ${origin}/.well-known/oauth-authorization-server`;

/** Indent under a checklist item ("  ☐ 1. "). */
const IND = '       ';

/** The closing checklist of perch public setup, with ☑ for what is already done. */
export function checklistText(c: ChecklistInput): string {
  const svc = serviceCommand(c.unit);
  const serviceDone = c.listener && !c.restartNeeded;
  const item = (done: boolean, n: number, text: string) => wrap(text, IND, 80, `  ${done ? '☑' : '☐'} ${n}. `);
  const command = (c: string) => `${IND}  ${c}\n`;
  let t = '\nAlmost done. Run these commands on this server:\n\n';
  t += item(serviceDone, 1, serviceDone ? 'Perch runs with the public listener.' : svc.why);
  if (!serviceDone) t += command(svc.command);
  const port = httpsPort(new URL(c.origin));
  const funnelText =
    c.funnel === 'on'
      ? `Tailscale Funnel serves port ${port}.`
      : c.funnel === 'wrong_target'
        ? `Tailscale Funnel serves port ${port}, but not to the public listener (127.0.0.1:${c.publicPort}). Point it there:`
        : `Open port ${port} to the internet with Tailscale Funnel (it forwards to the public listener):`;
  t += item(c.funnel === 'on', 2, funnelText);
  if (c.funnel !== 'on') {
    t += command(funnelCommand(c.origin, c.publicPort));
    t += wrap('If tailscale says Funnel is not enabled for your tailnet, open the link it prints, allow Funnel and run the command again.', IND);
  }
  t += item(false, 3, 'Test from any computer; the answer is JSON with "issuer":');
  t += command(curlCommand(c.origin));
  t += wrap('Google may take a few minutes before a new redirect URI works.', IND);
  t += item(false, 4, `Connect ${c.target === 'chatgpt' ? 'ChatGPT' : 'claude.ai'} (on this server):`);
  t += command(`perch connect --target ${c.target ?? 'claude-ai'}`);
  t += '\nCheck the progress at any time: perch public status\n';
  return t;
}

// ------------------------------------------------------------------ setup

async function openOAuth(config: PerchConfig): Promise<OAuthStore> {
  return new OAuthStore(await CredentialStore.open({ dataDir: config.dataDir, keyFile: config.keyFile }));
}

function needTerminal(io: CliIo): (prompt: string) => Promise<string> {
  if (!io.readLine) throw new PerchError('perch public setup needs an interactive terminal', 'no_tty');
  return io.readLine;
}

const ENV_LINE = /^\s*(export\s+)?PERCH_PUBLIC_BASE_URL\s*=.*$/m;

/** Sets PERCH_PUBLIC_BASE_URL in the env file (replacing an existing, e.g. empty, assignment). */
async function writeEnvLine(file: string, url: string): Promise<void> {
  const text = (await readPrivateFile(file)).toString('utf8');
  const line = `PERCH_PUBLIC_BASE_URL=${url}`;
  const next = ENV_LINE.test(text) ? text.replace(ENV_LINE, line) : `${text}${text && !text.endsWith('\n') ? '\n' : ''}${line}\n`;
  await writePrivateFileAtomic(file, Buffer.from(next, 'utf8'));
}

/** Step 1 when PERCH_PUBLIC_BASE_URL is missing: suggest, ask, and (only after [y/N]) write it to the env file. */
async function chooseAddress(config: PerchConfig, io: CliIo): Promise<{ url: string; envWritten?: string }> {
  const ask = needTerminal(io);
  const suggestion = suggestPublicBaseUrl(config);
  out(io, say('claude.ai and ChatGPT reach Perch at a public https address. With Tailscale Funnel this is the tailnet name of this server on port 443, 8443 or 10000.'));
  if (suggestion && new URL(suggestion).port === '10000') out(io, say('Port 443 already serves your private address (Tailscale Serve), so Perch suggests port 10000.'));
  let url: string | undefined;
  for (let attempt = 1; !url; attempt++) {
    const answer = (await ask(suggestion ? `  Public address [${suggestion}]: ` : '  Public address (https://…): ')).trim();
    const raw = answer || suggestion || '';
    try {
      const u = parseBaseUrl(raw);
      if (u.hostname.endsWith('.ts.net') && !(FUNNEL_PORTS as readonly number[]).includes(httpsPort(u))) {
        throw new PerchError(`Tailscale Funnel serves only the ports ${FUNNEL_PORTS.join(', ')}`, 'bad_config');
      }
      if (config.privateBaseUrl && u.origin === config.privateBaseUrl) {
        throw new PerchError('This is your private address; the public one needs another port (e.g. 10000)', 'bad_config');
      }
      url = u.origin;
    } catch (err) {
      if (!(err instanceof PerchError) || attempt >= 3) throw err;
      out(io, `  ${err.message}. Try again.\n`);
    }
  }
  const line = `PERCH_PUBLIC_BASE_URL=${url}`;
  const env = io.envFile;
  if (env) {
    out(io, `\n  Your env file:\n  ${env}\n  The line for it:\n`, cmdLine(line));
    if (yes(await ask('  Add it to this file now? [y/N] '))) {
      try {
        await writeEnvLine(env, url);
        out(io, '  Saved.\n\n');
        return { url, envWritten: env };
      } catch (err) {
        out(io, say(`Could not change ${env}: ${err instanceof PerchError ? err.message : 'write failed'}`));
      }
    }
    out(io, say('Add the line yourself; Perch reads it at the next start.'), '\n');
  } else {
    out(io, '\n', say('Perch was started without --env-file, so it does not know your .env file. Add this line to it (or as Environment= to the systemd unit):'), cmdLine(line), '\n');
  }
  return { url };
}

/** Step 2: the Google "Web application" client (pasted hidden, checked, stored 0600). Returns whether it changed. */
async function ensureLoginClient(config: PerchConfig, io: CliIo, origin: string, confirmed: boolean): Promise<boolean> {
  const file = loginClientFile(config);
  const check = await checkLoginClient(file, origin);
  if (check.ok) {
    out(io, `  OK: ${shortClientId(check.clientId)}\n      ${file}\n`);
    return false;
  }
  if (check.code === 'insecure_path') throw new PerchError(check.reason, 'insecure_path');
  out(io, say(`No usable Google sign-in client at ${file} (${check.reason}).`));
  out(io, say('Before every public pairing Perch asks for your Google account. That needs its own Google OAuth client of type "Web application"; the "Desktop app" client of your accounts does not work here.'));
  const ask = needTerminal(io);
  if (!confirmed && !yes(await ask('  Set it up now? [Y/n] '), true)) {
    throw new PerchError('Skipped: no Google sign-in client yet. Later: perch public setup', 'bad_config');
  }
  if (!io.readSecretJson) throw new PerchError('Pasting the client JSON needs an interactive terminal', 'no_tty');
  out(io, '\n', webClientGuideText(origin));
  await ask('  Press Enter when the JSON is downloaded. ');
  out(io, '\n', say('Open the downloaded JSON file and paste its full contents here.'));
  const redirect = loginRedirectUri(origin);
  let client: ReturnType<typeof validateWebClientJson> | undefined;
  for (let attempt = 1; !client; attempt++) {
    const text = await io.readSecretJson('  Client JSON (input hidden; Enter after pasting): ', MAX_CLIENT_JSON_BYTES);
    try {
      client = validateWebClientJson(text, redirect);
    } catch (err) {
      if (!(err instanceof PerchError) || attempt >= 3) throw err;
      out(io, wrap(`${err.message}. Try again.`, '  '));
    }
  }
  const dir = path.dirname(file);
  if (!(await pathExists(dir))) await ensurePrivateDir(dir);
  await writePrivateFileAtomic(file, Buffer.from(client.json, 'utf8'));
  out(io, `  Saved Google sign-in client ${shortClientId(client.clientId)}\n  (readable only by you) to\n  ${file}\n`);
  if (!config.googleLoginClientFile) out(io, say('Perch finds it there by itself; nothing to add to .env.'));
  return true;
}

export interface PublicSetupOptions {
  /** Shown in the last checklist step (perch connect --target …). */
  target?: 'claude-ai' | 'chatgpt';
  /** The operator already said yes (perch connect asked "Set it up now?"). */
  confirmed?: boolean;
}

/** perch public setup. */
export async function publicSetup(config: PerchConfig, io: CliIo, opts: PublicSetupOptions = {}): Promise<number> {
  needTerminal(io);
  out(io, '\nPublic access for claude.ai and ChatGPT\n\n', wrap('They connect from the internet, so Perch answers them on a separate public listener. This guide prepares it in four steps; Perch changes neither Tailscale nor systemd itself.'), '\n');

  out(io, 'Step 1/4 - Public address\n');
  let envWritten: string | undefined;
  let restartNeeded = false;
  if (!config.publicBaseUrl) {
    const chosen = await chooseAddress(config, io);
    config = { ...config, publicBaseUrl: chosen.url };
    envWritten = chosen.envWritten;
    restartNeeded = true;
  }
  const base = parseBaseUrl(config.publicBaseUrl!);
  out(io, `  ${base.origin}\n  MCP endpoint: ${base.origin}/mcp\n\n`);

  out(io, 'Step 2/4 - Google sign-in client\n');
  if (await ensureLoginClient(config, io, base.origin, opts.confirmed === true)) restartNeeded = true;

  const oauth = await openOAuth(config);
  out(io, '\nStep 3/4 - Your Google account\n');
  let s = await oauth.read();
  if (!s.loginAllow.length) {
    out(io, say('Only the Google accounts allowed here can pair over the public address. Use an account that is a test user of the Google project.'));
    const ask = needTerminal(io);
    for (let attempt = 1; ; attempt++) {
      try {
        await loginAllow(config, io, 'add', await ask('  Your Google account (email): '));
        break;
      } catch (err) {
        if (!(err instanceof PerchError) || err.code !== 'usage' || attempt >= 3) throw err;
        out(io, '  That is not an e-mail address. Try again.\n');
      }
    }
  } else out(io, `  Allowed: ${s.loginAllow.map((e) => e.email).join(', ')}\n`);

  out(io, '\nStep 4/4 - Perch code (authenticator app)\n');
  s = await oauth.read();
  if (!s.totp) {
    out(io, say('Every public pairing also asks for a 6-digit code from an authenticator app on your phone.'), '\n');
    await totpSetup(config, io);
  } else out(io, '  Already set up (perch oauth totp setup replaces it).\n');
  out(io, config.notifyTelegramFile ? '\nTelegram notifications: on\n' : '\nTelegram notifications: off (optional: PERCH_NOTIFY_TELEGRAM_FILE)\n');

  const unit = await readUnit(io.env);
  if (envWritten && unit && !unit.text.includes(envWritten)) {
    out(io, '\n', say(`Note: your systemd unit does not mention ${envWritten}. Make sure the service reads it (--env-file=${envWritten} before the CLI path in ExecStart).`));
  }
  const listener = await probeListener(config.publicPort, base);
  const funnel = parseFunnelStatus(io.funnelStatus ? await io.funnelStatus() : undefined, base.origin, config.publicPort);
  out(
    io,
    checklistText({
      origin: base.origin,
      publicPort: config.publicPort,
      ...(unit ? { unit } : {}),
      restartNeeded,
      listener,
      funnel,
      ...(opts.target ? { target: opts.target } : {}),
    }),
  );
  return 0;
}

// ------------------------------------------------------------------ status

/** perch public status: one ☑/☐ line per requirement, with the command that fixes it. */
export async function publicStatus(config: PerchConfig, io: CliIo): Promise<number> {
  const s = await (await openOAuth(config)).read();
  expireDevices(s);
  const rows: string[] = [];
  const row = (done: boolean, label: string, value: string, fix?: string) => {
    rows.push(wrap(value, ' '.repeat(28), 80, `  ${done ? '☑' : '☐'} ${label.padEnd(24)}`).trimEnd());
    if (!done && fix) rows.push(`      ${fix}`);
  };
  let base: URL | undefined;
  try {
    if (config.publicBaseUrl) base = parseBaseUrl(config.publicBaseUrl);
  } catch {
    base = undefined;
  }
  row(Boolean(base), 'Public address', base ? base.origin : config.publicBaseUrl ? 'PERCH_PUBLIC_BASE_URL is invalid' : 'not set (PERCH_PUBLIC_BASE_URL)', 'perch public setup');
  const file = loginClientFile(config);
  if (base) {
    const c = await checkLoginClient(file, base.origin);
    row(c.ok, 'Google sign-in client', c.ok ? shortClientId(c.clientId) : c.code === 'not_found' ? `not found: ${file}` : c.reason, 'perch public setup');
  } else row(false, 'Google sign-in client', 'needs the public address first', 'perch public setup');
  row(s.loginAllow.length > 0, 'Allowed Google account', s.loginAllow.length ? s.loginAllow.map((e) => e.email).join(', ') : 'none', 'perch oauth login-allow add you@example.com');
  row(Boolean(s.totp), 'Perch code (TOTP)', s.totp ? 'set up' : 'not set up', 'perch oauth totp setup');
  const unit = await readUnit(io.env);
  if (base) {
    const listener = await probeListener(config.publicPort, base);
    row(listener, 'Public listener', listener ? `runs on 127.0.0.1:${config.publicPort}` : `not running on 127.0.0.1:${config.publicPort}`, serviceCommand(unit).command);
    const funnel = parseFunnelStatus(io.funnelStatus ? await io.funnelStatus() : undefined, base.origin, config.publicPort);
    const port = httpsPort(base);
    const value = { on: `port ${port} is open`, off: `port ${port} is not open`, wrong_target: `port ${port} does not lead to 127.0.0.1:${config.publicPort}`, unknown: 'not checked (tailscale funnel status failed)' }[funnel];
    row(funnel === 'on', 'Tailscale Funnel', value, funnelCommand(base.origin, config.publicPort));
  } else {
    row(false, 'Public listener', 'needs the public address first');
    row(false, 'Tailscale Funnel', 'needs the public address first');
  }
  const blocker = pairingBlocker(s);
  out(
    io,
    'Public access (claude.ai, ChatGPT):\n',
    `${rows.join('\n')}\n\n`,
    `Kill switch: ${isPublicLocked(s) ? 'ON, public access is off (perch public on)' : 'off'} · active devices: ${s.devices.filter((d) => d.status === 'active').length}\n`,
    wrap(`Pairing: ${blocker ?? 'possible (perch oauth pair --public)'}`),
  );
  if (base) out(io, 'Test from any computer:\n', `  ${curlCommand(base.origin)}\n`);
  return 0;
}
