import path from 'node:path';
import { PerchError } from '../errors.js';
import { newAccountId, validateLabel } from '../ids.js';
import { runPkceLoopback, type PasteRedirect } from '../oauth/loopback.js';
import { RefreshingTokenProvider, type TokenGrantResponse } from '../oauth/tokenProvider.js';
import { ensurePrivateDir, pathExists, readPrivateFile, writePrivateFileAtomic } from '../secureFs.js';
import type { CredentialStore, NotionWorkspace } from '../store/credentialStore.js';
import type { Upstream } from '../upstream.js';
import { NOTION_VERSION } from './notion.js';

/**
 * Notion public integration via OAuth (docs/SLACK_SESSION_NOTION_GUIDE_SPEC.md §4): for team workspaces where
 * members may not create internal integrations. One OAuth client per installation (notion-client.json, 0600);
 * the result is an ordinary Notion workspace record with authMode 'oauth'.
 */

export const NOTION_OAUTH_PORT = 8769;
export const NOTION_OAUTH_CALLBACK_PATH = '/notion/callback';
export const NOTION_OAUTH_REDIRECT_URI = `http://localhost:${NOTION_OAUTH_PORT}${NOTION_OAUTH_CALLBACK_PATH}`;
export const NOTION_AUTHORIZE_URL = 'https://api.notion.com/v1/oauth/authorize';
const TOKEN_PATH = '/v1/oauth/token';
/** Notion documents no lifetime for refreshed tokens without expires_in; re-check hourly then. */
const DEFAULT_REFRESHED_LIFETIME_S = 3600;
const MAX_CLIENT_FILE_BYTES = 4096;

export interface NotionClient {
  clientId: string;
  clientSecret: string;
}

/** Default location: $XDG_CONFIG_HOME/perch/notion-client.json (~/.config/perch/…). */
export function defaultNotionClientFile(configHome: string): string {
  return path.join(configHome, 'perch', 'notion-client.json');
}

const SAFE_VALUE = /^[\x21-\x7e]{8,512}$/;

/** Checks pasted client values (printable, no whitespace, sane length). Never echoes them. */
export function parseNotionClient(raw: { clientId: string; clientSecret: string }): NotionClient {
  const clientId = raw.clientId.trim();
  const clientSecret = raw.clientSecret.trim();
  if (!SAFE_VALUE.test(clientId)) throw new PerchError('The OAuth Client ID looks wrong (copy it from the integration\'s "Configuration" tab)', 'usage');
  if (!SAFE_VALUE.test(clientSecret)) throw new PerchError('The OAuth Client Secret looks wrong (copy it from the integration\'s "Configuration" tab)', 'usage');
  if (clientId === clientSecret) throw new PerchError('Client ID and Client Secret are the same value; copy each one separately', 'usage');
  return { clientId, clientSecret };
}

/** Reads the client file (owner-only, no symlink). Missing → PerchError 'not_found'; malformed → 'bad_client_file'. */
export async function readNotionClient(file: string): Promise<NotionClient> {
  const buf = await readPrivateFile(file);
  if (buf.length > MAX_CLIENT_FILE_BYTES) throw new PerchError(`The Notion client file ${file} is too large`, 'bad_client_file');
  try {
    const o = JSON.parse(buf.toString('utf8')) as { client_id?: unknown; client_secret?: unknown };
    if (typeof o.client_id !== 'string' || typeof o.client_secret !== 'string') throw new Error('shape');
    return parseNotionClient({ clientId: o.client_id, clientSecret: o.client_secret });
  } catch {
    throw new PerchError(`The Notion client file ${file} does not contain client_id and client_secret`, 'bad_client_file');
  }
}

export async function saveNotionClient(file: string, client: NotionClient): Promise<void> {
  const dir = path.dirname(file);
  if (!(await pathExists(dir))) await ensurePrivateDir(dir);
  const json = `${JSON.stringify({ client_id: client.clientId, client_secret: client.clientSecret }, null, 2)}\n`;
  await writePrivateFileAtomic(file, Buffer.from(json, 'utf8'));
}

export const shortNotionClientId = (id: string) => `${id.slice(0, 8)}…`;

const basic = (c: NotionClient) => `Basic ${Buffer.from(`${c.clientId}:${c.clientSecret}`, 'utf8').toString('base64')}`;
/** Same API version header as every other Notion call. */
const tokenHeaders = (c: NotionClient) => ({ authorization: basic(c), 'notion-version': NOTION_VERSION });

export interface NotionTokenResponse extends TokenGrantResponse {
  token_type?: string;
  bot_id?: string;
  workspace_id?: string;
  workspace_name?: string;
  owner?: { type?: string; user?: { id?: string; name?: string; type?: string } };
}

export interface NotionAuthorizationOptions {
  client: NotionClient;
  upstream: Upstream;
  timeoutMs?: number;
  onAuthUrl: (url: string) => void;
  paste?: PasteRedirect;
}

/** Login in the browser (owner=user, state), then the code exchange with Basic auth. */
export async function runNotionAuthorization(opts: NotionAuthorizationOptions): Promise<NotionTokenResponse> {
  return runPkceLoopback({
    provider: 'Notion',
    authEndpoint: NOTION_AUTHORIZE_URL,
    authParams: { client_id: opts.client.clientId, owner: 'user' },
    redirectHost: 'localhost',
    callbackPath: NOTION_OAUTH_CALLBACK_PATH,
    port: NOTION_OAUTH_PORT,
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    onAuthUrl: opts.onAuthUrl,
    ...(opts.paste ? { paste: opts.paste } : {}),
    exchange: async (code, _verifier, redirectUri) => {
      const tok = await opts.upstream.json<NotionTokenResponse>('notion', {
        method: 'POST',
        path: TOKEN_PATH,
        headers: tokenHeaders(opts.client),
        json: { grant_type: 'authorization_code', code, redirect_uri: redirectUri },
        capability: 'admin',
      });
      if (!tok.access_token) throw new PerchError('Notion did not return an access token', 'oauth_incomplete');
      if (!tok.workspace_id) throw new PerchError('Notion did not return a workspace id', 'oauth_incomplete');
      return tok;
    },
  });
}

/**
 * Stores the OAuth result: a new workspace record, or the existing one with the same Notion workspace_id updated in
 * place (same id, client grants stay valid). Refresh token and client are kept only when Notion issued one.
 */
export async function upsertNotionOAuthWorkspace(
  store: CredentialStore,
  input: { label: string; client: NotionClient; grant: NotionTokenResponse },
): Promise<{ workspace: NotionWorkspace; updated: boolean }> {
  const label = validateLabel(input.label);
  const { grant, client } = input;
  const owner = grant.owner?.user;
  return store.update((data) => {
    const now = new Date().toISOString();
    const fields = {
      label,
      token: grant.access_token!,
      authMode: 'oauth' as const,
      oauthWorkspaceId: grant.workspace_id!,
      ...(grant.workspace_name ? { workspaceName: grant.workspace_name.slice(0, 200) } : {}),
      ...(grant.bot_id ? { botId: grant.bot_id.slice(0, 100) } : {}),
      ...(owner?.id ? { tokenOwner: { id: owner.id, ...(owner.name ? { name: owner.name } : {}), ...(owner.type ? { type: owner.type } : {}) } } : {}),
      ...(grant.refresh_token ? { refreshToken: grant.refresh_token, clientId: client.clientId, clientSecret: client.clientSecret } : {}),
      updatedAt: now,
    };
    const existing = data.notion.find((w) => w.authMode === 'oauth' && w.oauthWorkspaceId === grant.workspace_id);
    if (existing) {
      delete existing.refreshToken;
      delete existing.clientId;
      delete existing.clientSecret;
      delete existing.workspaceName;
      delete existing.botId;
      Object.assign(existing, fields);
      return { workspace: existing, updated: true };
    }
    const ws: NotionWorkspace = { id: newAccountId('notion', data.notion.map((w) => w.id)), ...fields, createdAt: now };
    data.notion.push(ws);
    return { workspace: ws, updated: false };
  });
}

/** refresh_token grant at the same endpoint (Basic auth with the client stored on the workspace). */
export async function refreshNotionToken(upstream: Upstream, ws: NotionWorkspace, refreshToken: string): Promise<TokenGrantResponse> {
  if (!ws.clientId || !ws.clientSecret) {
    throw new PerchError(`Notion workspace ${ws.id} has no stored OAuth client. Reconnect: run perch notion add --oauth --label <label>.`, 'grant_invalid');
  }
  const tok = await upstream.json<TokenGrantResponse>('notion', {
    method: 'POST',
    path: TOKEN_PATH,
    headers: tokenHeaders({ clientId: ws.clientId, clientSecret: ws.clientSecret }),
    json: { grant_type: 'refresh_token', refresh_token: refreshToken },
    capability: 'admin',
  });
  return { ...tok, expires_in: tok.expires_in ?? DEFAULT_REFRESHED_LIFETIME_S };
}

/** Access tokens of OAuth workspaces with a refresh token (single-flight refresh, rotation persisted under the lock). */
export function createNotionTokenProvider(store: CredentialStore, upstream: Upstream): RefreshingTokenProvider<NotionWorkspace> {
  return new RefreshingTokenProvider<NotionWorkspace>(store, {
    name: 'Notion',
    list: (d) => d.notion,
    refresh: (ws, rt) => refreshNotionToken(upstream, ws, rt),
    reconnect: () => '`perch notion add --oauth --label <label>` (updates the same workspace)',
  });
}
