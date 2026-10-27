import { defaultNotionClientFile } from './notion/oauth.js';
import { homedir } from 'node:os';
import path from 'node:path';
import { PerchError } from './errors.js';
import { readPrivateFile } from './secureFs.js';
import { validateCimdOrigin } from './upstream.js';
import { derivePrivateBaseUrl } from './access/baseUrl.js';

function validateCimdUrl(raw: string): string {
  validateCimdOrigin(raw);
  const u = new URL(raw);
  if (u.search || u.hash || u.pathname === '/') throw new PerchError('PERCH_LUMA_CLIENT_ID must be an https URL with a path, without query or fragment', 'bad_config');
  return raw;
}

export interface PerchConfig {
  dataDir: string;
  keyFile: string;
  tokenFile: string;
  /** Token from PERCH_HTTP_TOKEN (takes precedence over the token file). */
  httpTokenEnv?: string;
  httpHost: string;
  httpPort: number;
  allowedHosts: string[];
  allowedOrigins: string[];
  /** PERCH_GOOGLE_CLIENT_FILE, if set. */
  googleClientFile?: string;
  /** Where `perch google client setup` stores the client without PERCH_GOOGLE_CLIENT_FILE (also read from there). */
  googleClientDefaultFile: string;
  /** Notion OAuth client (public integration): ~/.config/perch/notion-client.json, 0600. */
  notionClientFile: string;
  /** stdio only: client token file selecting a client grant (default stdio is read-only). */
  clientTokenFile?: string;
  /** Public access (docs/PUBLIC_ACCESS_SPEC.md §2): base URL of the public listener, e.g. https://host.tailnet.ts.net */
  publicBaseUrl?: string;
  /**
   * Private OAuth issuer on the local listener (docs/SIMPLE_CONNECT_SPEC.md §1): PERCH_PRIVATE_BASE_URL, else
   * https://<first non-loopback name in PERCH_ALLOWED_HOSTS>. Absent: private OAuth is off.
   */
  privateBaseUrl?: string;
  privateBaseUrlSource?: 'env' | 'allowed_hosts';
  /** PERCH_PRIVATE_OAUTH (default on): off switches private OAuth off even with a private base URL. */
  privateOAuth: boolean;
  /** Loopback port of the public listener. */
  publicPort: number;
  /** Google OAuth client of type "Web application" for the operator's sign-in (PERCH_GOOGLE_LOGIN_CLIENT_FILE, if set). */
  googleLoginClientFile?: string;
  /** Where `perch public setup` stores the sign-in client without PERCH_GOOGLE_LOGIN_CLIENT_FILE (also read from there). */
  googleLoginClientDefaultFile: string;
  /** Dynamic Client Registration (only while a pairing window is open). */
  oauthDcr: boolean;
  /** Optional Telegram notification file (bot token + chat id, 0600). */
  notifyTelegramFile?: string;
  /** Trust X-Forwarded-For from a loopback proxy for the shown IP and limits. */
  publicTrustForwarded: boolean;
  /** Overrides Perch's built-in Client ID Metadata Document URL for Luma. */
  lumaClientId?: string;
}

/**
 * PERCH_USER selected a provisioned user namespace until user isolation was removed (one operator per
 * installation). A leftover setting is an error, never silently the operator's own store.
 */
function rejectUserSelector(env: Record<string, string | undefined>): void {
  if (Object.prototype.hasOwnProperty.call(env, 'PERCH_USER') && env.PERCH_USER !== undefined) {
    throw new PerchError('PERCH_USER is no longer supported: Perch serves exactly one operator per installation. Unset it.', 'bad_config');
  }
}

const list = (v: string | undefined) =>
  (v ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

const safeOrigin = (raw: string) => {
  try {
    return new URL(raw.trim()).origin;
  } catch {
    return undefined;
  }
};

/** Configuration comes from environment variables only (no secrets on the command line). */
export function resolveConfig(env: Record<string, string | undefined>): PerchConfig {
  const home = homedir();
  const dataHome = env.XDG_DATA_HOME || path.join(home, '.local', 'share');
  const configHome = env.XDG_CONFIG_HOME || path.join(home, '.config');
  const port = Number(env.PERCH_HTTP_PORT || '8765');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new PerchError('PERCH_HTTP_PORT must be a valid port', 'bad_config');
  rejectUserSelector(env);
  const publicPort = Number(env.PERCH_PUBLIC_PORT || '8767');
  if (!Number.isInteger(publicPort) || publicPort < 0 || publicPort > 65535) throw new PerchError('PERCH_PUBLIC_PORT must be a valid port', 'bad_config');
  const flag = (name: string, dflt: boolean) => {
    const v = env[name]?.trim().toLowerCase();
    if (v === undefined || v === '') return dflt;
    if (['1', 'on', 'true', 'yes'].includes(v)) return true;
    if (['0', 'off', 'false', 'no'].includes(v)) return false;
    throw new PerchError(`${name} must be on or off`, 'bad_config');
  };
  const allowedHosts = list(env.PERCH_ALLOWED_HOSTS);
  const privateOAuth = flag('PERCH_PRIVATE_OAUTH', true);
  let privateBase = privateOAuth ? derivePrivateBaseUrl(env.PERCH_PRIVATE_BASE_URL?.trim() || undefined, allowedHosts) : null;
  // Two issuers, never the same origin: a derived clash switches private OAuth off, an explicit one is an error.
  if (privateBase && env.PERCH_PUBLIC_BASE_URL && privateBase.url === safeOrigin(env.PERCH_PUBLIC_BASE_URL)) {
    if (privateBase.source === 'env') throw new PerchError('PERCH_PRIVATE_BASE_URL must differ from PERCH_PUBLIC_BASE_URL (separate issuers)', 'bad_config');
    privateBase = null;
  }
  return {
    dataDir: path.resolve(env.PERCH_DATA_DIR || path.join(dataHome, 'perch')),
    keyFile: path.resolve(env.PERCH_KEY_FILE || path.join(configHome, 'perch', 'store.key')),
    tokenFile: path.resolve(env.PERCH_HTTP_TOKEN_FILE || path.join(configHome, 'perch', 'http-token')),
    ...(env.PERCH_HTTP_TOKEN ? { httpTokenEnv: env.PERCH_HTTP_TOKEN } : {}),
    httpHost: env.PERCH_HTTP_HOST || '127.0.0.1',
    httpPort: port,
    allowedHosts,
    allowedOrigins: list(env.PERCH_ALLOWED_ORIGINS),
    ...(env.PERCH_GOOGLE_CLIENT_FILE ? { googleClientFile: path.resolve(env.PERCH_GOOGLE_CLIENT_FILE) } : {}),
    // HOME from the given environment (not only the process's) so tests never touch the operator's real file.
    googleClientDefaultFile: path.resolve(env.XDG_CONFIG_HOME || path.join(env.HOME || home, '.config'), 'perch', 'google-client.json'),
    notionClientFile: defaultNotionClientFile(env.XDG_CONFIG_HOME || path.join(env.HOME || home, '.config')),
    ...(env.PERCH_CLIENT_TOKEN_FILE ? { clientTokenFile: path.resolve(env.PERCH_CLIENT_TOKEN_FILE) } : {}),
    ...(env.PERCH_PUBLIC_BASE_URL ? { publicBaseUrl: env.PERCH_PUBLIC_BASE_URL.trim() } : {}),
    ...(privateBase ? { privateBaseUrl: privateBase.url, privateBaseUrlSource: privateBase.source } : {}),
    privateOAuth,
    publicPort,
    ...(env.PERCH_GOOGLE_LOGIN_CLIENT_FILE ? { googleLoginClientFile: path.resolve(env.PERCH_GOOGLE_LOGIN_CLIENT_FILE) } : {}),
    googleLoginClientDefaultFile: path.resolve(env.XDG_CONFIG_HOME || path.join(env.HOME || home, '.config'), 'perch', 'google-web-client.json'),
    oauthDcr: flag('PERCH_OAUTH_DCR', true),
    ...(env.PERCH_NOTIFY_TELEGRAM_FILE ? { notifyTelegramFile: path.resolve(env.PERCH_NOTIFY_TELEGRAM_FILE) } : {}),
    publicTrustForwarded: flag('PERCH_PUBLIC_TRUST_FORWARDED', false),
    ...(env.PERCH_LUMA_CLIENT_ID ? { lumaClientId: validateCimdUrl(env.PERCH_LUMA_CLIENT_ID.trim()) } : {}),
  };
}

export async function loadHttpToken(config: PerchConfig): Promise<string> {
  if (config.httpTokenEnv) return config.httpTokenEnv;
  try {
    return (await readPrivateFile(config.tokenFile)).toString('utf8').trim();
  } catch (err) {
    if (err instanceof PerchError && err.code === 'not_found') {
      throw new PerchError(`No HTTP bearer token at ${config.tokenFile}. Run \`perch init\` or \`perch token rotate\`.`, 'no_token');
    }
    throw err;
  }
}
