import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { AuditLog } from '../audit/audit.js';
import { createClientGrant, parseCapabilities, principalForClientToken, READONLY_PRINCIPAL, removeClientGrant } from '../auth/grants.js';
import { loadHttpToken, resolveConfig, type PerchConfig } from '../config.js';
import { createPerchContext } from '../context.js';
import { PerchError, safeMessage } from '../errors.js';
import { removeGoogleAccount } from '../google/accounts.js';
import {
  GOOGLE_SERVICE_TITLES,
  googleGroupScopes,
  parseGoogleServices,
  registerGoogleGroup,
  removeGoogleGroup,
  runGoogleGroupAuthorization,
  type GoogleGroupRequest,
  type GoogleService,
  type GroupRegistration,
} from '../google/group.js';
import { findGroup, grantStillValidHint, groupMembers, type SharedGrantHolder } from '../google/groupStore.js';
import {
  accessCommand,
  accessRequest,
  assertWritable,
  groupAccess,
  notConnected,
  resolveAccessGroup,
  restrictGmailToDrafts,
  revokeServiceWrite,
  WRITABLE_SERVICES,
} from '../google/access.js';
import { DEFAULT_AUTH_TIMEOUT_MS, DRIVE_SCOPE, MAX_AUTH_TIMEOUT_MS, runLoopbackAuthorization } from '../google/oauth.js';
import { CALENDAR_EVENTS_OWNED_SCOPE } from '../google/productivity.js';
import {
  parseServices,
  productivityScopesFor,
  registerProductivityAccount,
  removeProductivityAccount,
  runProductivityAuthorization,
} from '../google/productivity.js';
import { GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE, GMAIL_SEND_SCOPE, gmailScopesFor, registerGmailAccount, removeGmailAccount } from '../mail/gmailAccounts.js';
import { addImapAccount, removeImapAccount, verifyImapAccount } from '../mail/imapAccounts.js';
import { IMAP_PRESETS } from '../mail/imapPresets.js';
import { imapSentCopyEnabled } from '../mail/imap.js';
import { PRUNE_REFUSED, resolveSend } from '../mail/workflow.js';
import {
  ACCOUNT_ID_PATTERN,
  initMailWorkflowLedger,
  ledgerFilePath,
  MAX_AUDIT_EVENTS,
  MailWorkflowLedger,
  OPERATION_ID_PATTERN,
  SEND_STATES,
  type Actor,
} from '../mail/workflowLedger.js';
import { generateHttpToken, startHttpServer, validateHttpToken } from '../mcp/http.js';
import { createMcpServer } from '../mcp/server.js';
import { removeMicrosoftAccount } from '../microsoft/accounts.js';
import { cmdMicrosoftSession } from './microsoftSession.js';
import { SLACK_SESSION_WARNING, showSlackSessionGuide } from './slackGuide.js';
import { addNotionWorkspace, countVisibleNotionObjects, removeNotionWorkspace, type NotionVisibility } from '../notion/notion.js';
import { runNotionAuthorization, upsertNotionOAuthWorkspace } from '../notion/oauth.js';
import { cmdNotionClient, ensureNotionClient } from './notionClient.js';
import { maybeShowNotionGuide } from './notionGuide.js';
import { addSlackWorkspace, isSlackSession, normalizeSlackCookie, removeSlackWorkspace } from '../slack/slack.js';
import { ensurePrivateDir, pathExists, readPrivateFile, writePrivateFileAtomic, writePrivateFileExclusive } from '../secureFs.js';
import { renameRecord } from '../store/rename.js';
import { CredentialStore, initStore, type GoogleAccountGroup, type ImapAccount, type StoreData } from '../store/credentialStore.js';
import { createFetchTransport, Upstream, type UpstreamTransport } from '../upstream.js';
import { collectStatus, failedChecks, formatStatusText } from '../status/status.js';
import { accountCapabilities, formatStatusTerminal } from '../status/terminal.js';

import { startAccess, type Access } from '../access/runtime.js';
import { PRIVATE_OAUTH_DISABLED, PRIVATE_OAUTH_OFF } from '../access/baseUrl.js';
import { cmdOauth, cmdPublic } from './oauth.js';
import { cmdConnect } from './connect.js';
import { loginClientFile } from './publicSetup.js';
import { cmdLuma, lumaMcpFor } from './luma.js';
import { cmdX } from './x.js';
import { cmdGoogleClient, googleRequestFromFlags, loadGoogleClient } from './googleClient.js';
import { loginPrompts } from './loginPrompt.js';
import type { FetchLike } from '../luma/client.js';
import { PERCH_VERSION } from '../version.js';
import { chooseAccess, chooseGoogleServices, claudeAddCommand, runSetup, WRITE_FLAGS, yes } from './onboarding.js';
import { defaultInstallDeps, installGowa, rotateGowaPassword, type InstallDeps } from '../whatsapp/install.js';
import { DEFAULT_PAIR_TIMEOUT_MS, pairWhatsappAccount, probeWhatsappInstance, removeWhatsappAccount, setWhatsappInstance, whatsappDeviceStatus } from '../whatsapp/whatsapp.js';

export interface CliIo {
  env: Record<string, string | undefined>;
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  /** Masked secret input (TTY only in production). */
  readSecret: (prompt: string) => Promise<string>;
  /** Visible one-line input (confirmations, one-time codes); TTY only in production. */
  readLine?: (prompt: string) => Promise<string>;
  /** Hidden, multi-line tolerant paste of a secret JSON document (Google client file); TTY only in production. */
  readSecretJson?: (prompt: string, maxBytes: number) => Promise<string>;
  /** Hidden, cancellable paste of the OAuth redirect address (login without a tunnel); undefined without a TTY. */
  readPastedUrl?: (prompt: string, signal: AbortSignal) => Promise<string | undefined>;
  /** Tests inject a fetch serving a MOCK Luma MCP server; production uses fetch behind guardedLumaFetch. */
  lumaFetch?: FetchLike;
  /** Tests inject a MOCK upstream transport; production always uses fetch to fixed origins. */
  transport?: UpstreamTransport;
  /** Tests inject a MOCK IMAP/SMTP login check; production logs in to the real servers over TLS. */
  imapVerify?: (account: ImapAccount) => Promise<void>;
  /** Tests inject a no-op sleep (WhatsApp pairing polls the bridge). */
  sleep?: (ms: number) => Promise<void>;
  /** Tests inject MOCK platform, download, systemctl and pins for `perch whatsapp install`; production uses the real ones. */
  whatsappInstall?: Partial<InstallDeps>;
  /** stdout is a terminal (perch status: colour unless NO_COLOR); tests inject it, production passes process.stdout.isTTY. */
  stdoutIsTTY?: boolean;
  /** Terminal width for perch status; undefined when piped. */
  stdoutColumns?: number;
  /** The env file this process was started with (node --env-file=…, or PERCH_ENV_FILE); perch public setup may add a line to it after asking. */
  envFile?: string;
  /** Output of `tailscale funnel status` (local only), undefined when unavailable; tests inject it. */
  funnelStatus?: () => Promise<string | undefined>;
}

const USAGE = `perch ${PERCH_VERSION} - Your accounts, connected to your AI

Usage: perch COMMAND [options]

1. Set up your server
  perch setup                         Guided setup and account connection
  perch init                          Create private storage and keys
  perch serve --http                  Start the MCP server
  perch public setup                  Enable access for cloud AI clients
  perch status                        Check connections and access

2. Connect AI clients
  Run on your Perch server:
  perch connect                       Choose an AI and follow the steps
  perch connect --help                Show all AI clients and options
  perch connect --target codex        Codex app / terminal
  perch connect --target claude-code  Claude Code
  perch connect --target claude-ai    Claude web / app
  perch connect --target chatgpt      ChatGPT

3. Connect apps and accounts
  perch microsoft add --label NAME    Teams, mail, calendar, OneDrive / SharePoint
  perch google add --label NAME       Gmail, Drive, Calendar and Contacts
  perch slack add --label NAME        Slack browser session
  perch whatsapp add --label NAME --phone NUMBER
                                      WhatsApp (bridge: perch whatsapp install)
  perch notion add --label NAME       Notion workspace
  perch imap add --label NAME --email ADDRESS
                                      Other email providers
  perch luma add --label NAME         Luma account
  perch x add --label NAME            X account
  perch accounts                     List connected accounts

More help
  perch help --all                    Complete command and option reference
  perch oauth devices                List paired AI clients
  perch client list                  List clients using a token

Run setup and connection commands on the server; follow the printed steps on
your personal computer when prompted. Account permissions and AI access are
selected separately.`;

const CONNECT_HELP = `Connect AI clients to Perch

Run on your Perch server:
  perch connect                       Choose a client interactively
  perch connect --target codex        Codex app / terminal
  perch connect --target claude-code  Claude Code
  perch connect --target claude-ai    Claude web / desktop app / phone
  perch connect --target chatgpt      ChatGPT
  perch connect --target desktop      Other desktop app in your tailnet
  perch connect --target server-agent Agent running on this server
  perch connect --target other        Other MCP client

Follow the printed instructions on the computer running the AI, then confirm
its sign-in on the server. Claude and ChatGPT cloud connectors need public
access: perch public setup. Codex and Claude Code can use your private tailnet.

Options
  --no-pair                           Show steps without opening pairing
                                      (OAuth targets only)
  --read-only                         Allow reads only
  --full                              Allow reads and writes on all accounts
                                      including accounts added later

Example: perch connect --target codex --no-pair
More commands: perch help --all`;

const FULL_USAGE = `perch ${PERCH_VERSION} - Google Drive + Notion + mail + Calendar/Contacts + Slack + WhatsApp MCP server (read-only unless a client grant allows more)

Usage:
  perch setup                                  guided onboarding: connect services, then choose client access
  perch init                                   create key, encrypted store and HTTP token (if missing)
  perch serve --stdio                          MCP over stdio (read-only; PERCH_CLIENT_TOKEN_FILE selects a client grant)
  perch serve --http [--host IP] [--port N] [--public]   MCP over stateless Streamable HTTP (bearer auth);
                                               --public also starts the public OAuth listener (PERCH_PUBLIC_BASE_URL)
  perch public setup | status | on | off       public access: guided setup, checklist, kill switch (off signs out every device)
  perch connect [--target T] [--no-pair]       connect an AI step by step (T: claude-code, codex, claude-ai, chatgpt,
                                               desktop, server-agent, other); then pairs it like perch oauth pair
  perch oauth pair [--private|--public] [--full|--read-only]   open a pairing window for ONE address (default: private
                                               when available; 10 min, one device) and confirm the sign-in here
  perch oauth totp setup | status | recovery-codes      the Perch code (TOTP) for every pairing
  perch oauth login-allow add|remove EMAIL | list       Google accounts that may sign in
  perch oauth devices | revoke ID | revoke --all | revoke --private-all   paired devices (private or public)
  perch oauth grant ID --allow CAPS --account ID ... | ungrant ID --read-all   write capabilities of a device (like perch client add)
  perch oauth client add --name N --redirect URI | add --cimd URL | list | remove ID   extra OAuth clients
  perch luma add --label NAME [--port N] [--timeout SECONDS]   connect a Luma account (official Luma MCP, OAuth)
  perch luma list | remove ID [--revoke] | tools ID [--accept]   tools: approved vs live tool schemas
  perch oauth local-page enable | disable       local pairing page /local/pair with its own password
  Access: --read-only, --drafts-only (mail), or --write. Draft mode never enables Perch send or modify.
  perch accounts                               list all connected accounts
  perch rename ID "NEW LABEL"                  change the label of an account, a Google account group (ggroup-…, all its services) or a client
  perch status [--no-check] [--json] [--plain] overview with a live check per account, capabilities and the commands
                                               that enable missing ones (exit code 1 if a check failed); --plain: the
                                               previous one-line-per-account text; the same page: GET /status on serve --http
  perch google add --label NAME [--services drive,gmail,calendar,contacts] [--write | --read-only]
                   [--yes] [--port N] [--timeout SECONDS] [--login-hint EMAIL]
                                               ONE Google login for Drive, Gmail, Calendar and Contacts (asks once
                                               for the services, default all, and once for read only or read + write
                                               for all of them). Read/write per service: perch google access. Re-adding
                                               the same Google account updates its group (same ids; asks, without a
                                               terminal only with --yes). Fine-grained, rarely needed: --allow-write
                                               --allow-drafts --allow-send --allow-modify --allow-calendar-write
  perch google access ggroup-ID [--service drive|gmail|calendar|contacts --write | --read-only]
                     [--add SERVICE [--write | --read-only]] [--yes] [--port N] [--timeout SECONDS]
                                               show the read/write access per service of a Google account (group or
                                               member id) and change it; without flags on a terminal: asks what to
                                               change. Write and --add start a Google login for the same account (same
                                               ids); --read-only is local, no login. Write: Drive edit/share/trash,
                                               Gmail drafts + send + organize, Calendar own events + invitations;
                                               Contacts are read-only
  perch google client setup | show            guided Google Cloud preparation: project, APIs, consent screen and the
                                               "Desktop app" OAuth client (JSON pasted hidden, stored 0600); show: path
                                               and shortened client id. Every Google add starts it when the client is missing
  perch google list | remove ggroup-ID [--revoke [--force]] | remove ID --service drive|gmail|calendar|contacts
                                               remove a whole group (--revoke: once at Google, all its services) or
                                               one service of it (never revoked: the login is shared). --revoke ends
                                               Google's grant for that account and OAuth client; refused while another
                                               stored login of the same account uses it, unless --force
  perch notion add --label NAME [--internal|--oauth] [--skip-guide] [--timeout SECONDS]
                                               --internal: shows the integration steps, then reads the
                                               Internal Integration Secret (ntn_…) via a masked prompt;
                                               --oauth: public integration, login in the browser (port 8769),
                                               works without owner rights; same workspace again = update.
                                               Without a flag Perch asks
  perch notion client setup | show            guided Notion OAuth client (public integration); stored in
                                               ~/.config/perch/notion-client.json (0600)
  perch notion list | remove ID
  perch gmail add --label NAME [--allow-drafts] [--allow-send] [--allow-modify] [--port N] [--timeout SECONDS] [--login-hint EMAIL]
                                               Gmail only, separate login (the usual way: perch google add --services gmail)
  perch gmail list | remove ID [--revoke [--force]]
  perch microsoft add --label NAME [--write | --read-only] [--allow-invites]
                      [--ssh-host ALIAS] [--server-login] [--port N] [--timeout 30-900] [--yes]
                                               local Chrome login and SSH transfer; discovers Teams/mail/calendar/files
  perch microsoft sessions                    list registered service accounts and retained browser profiles
  perch microsoft reconnect mgroup-ID [--reuse-session] [--write | --read-only]
                                               rediscover services; --reuse-session uses the saved login
  perch microsoft access mgroup-ID [--service teams|mail|calendar|files] [--write | --read-only] [--allow-invites]
  perch microsoft doctor mgroup-ID              verify identity and enabled services without a login viewer
  perch microsoft list | remove ID
  perch imap add --label NAME --email ADDRESS [--username USER] [--preset gmx|gmx-com]
                 [--imap-host H --imap-port N --smtp-host H --smtp-port N --smtp-security tls|starttls]
                 [--allow-drafts] [--allow-send] [--allow-modify] [--drafts-mailbox NAME] [--no-sent-copy]
                 password via masked prompt; --no-sent-copy: never file sent mail in the Sent folder
  perch imap presets | list | remove ID
  perch google-productivity add --label NAME --services calendar,contacts [--allow-calendar-write]
                      [--port N] [--timeout SECONDS] [--login-hint EMAIL]
                                               Calendar/Contacts only, separate login (the usual way: perch google add)
  perch google-productivity list | remove ID [--revoke [--force]]
  perch slack add --label NAME [--skip-guide]   connect your browser session; cookie and token via masked prompts
  perch slack list | remove ID
  perch whatsapp install [--yes] [--dir PATH] [--port N]   download the pinned GOWA bridge (SHA-256 checked), run it as a
                                               systemd user service on 127.0.0.1 and store it in Perch (Linux; asks first);
                                               a re-run replaces a gowa.service written by an older Perch
  perch whatsapp rotate-password [--dir PATH]  new random GOWA password in .env, restart GOWA, store it in Perch;
                                               paired devices stay linked; the password is never shown
  perch whatsapp instance set --url http://127.0.0.1:3000   GOWA basic-auth user/password via masked prompts
  perch whatsapp instance show
  perch whatsapp add --label NAME --phone +43…  [--timeout SECONDS]   pair a new linked device by pairing code
  perch whatsapp list | status | remove ID [--keep-device]
  perch x add --label NAME [--timeout SECONDS]   post on your own X account: login in the browser (OAuth 2.0 with PKCE,
                                               fixed port 8771) with your X developer app; same X user = update
  perch x client setup | show                  guided X developer app (Client ID, optional secret, hidden);
                                               stored in ~/.config/perch/x-client.json (0600)
  perch x list | remove ID [--revoke]
  perch client add --label NAME --full [--token-file PATH]   read + write on every account (also later ones)
  perch client add --label NAME --read-all [--token-file PATH]   read only, every account (also later ones)
  perch client add --label NAME --allow CAPS --account ID [--account ID ...] [--token-file PATH]
                      CAPS: read,draft,send,modify (mail accounts); calendar_read,calendar_write,calendar_invite,contacts_read (gprod accounts);
                            slack_read,slack_send (slack accounts); whatsapp_read,whatsapp_send (whatsapp accounts);
                            luma_read,luma_events,luma_guests,luma_blast (luma accounts)
                            x_read,x_post (x accounts)
  perch client list | remove ID
  perch token rotate                           replace the HTTP bearer token file
  perch audit list [--limit N] [--client ID] [--account ID]   body-free audit trail
  perch mail-workflow list [--state pending|accepted|rejected|indeterminate]   idempotent send records
  perch mail-workflow resolve OPERATION_ID --outcome sent|not-sent   record a human-verified outcome (never sends)
  perch mail-workflow init                     create a missing ledger for a store created before it existed

Configuration is read from environment variables (see .env.example). Secrets are never
accepted as command-line arguments. Perch serves exactly one operator per installation.`;

const SECRET_FLAG = /^--?(token|pat|secret|client-secret|refresh-token|access-token|password|key|api-key|cookie|session-cookie)(=|$)/i;

class UsageError extends PerchError {
  constructor(message: string) {
    super(message, 'usage');
  }
}

function openRootStore(config: PerchConfig) {
  return CredentialStore.open({ dataDir: config.dataDir, keyFile: config.keyFile });
}

const openStore = openRootStore;

/**
 * User isolation was removed (one operator per installation). Stores that still list provisioned users
 * open as before; those users' tokens are no longer accepted, and their stores and keys stay untouched.
 */
async function warnAboutProvisionedUsers(store: CredentialStore, io: CliIo): Promise<void> {
  const active = (await store.read()).users.filter((u) => u.status === 'active');
  if (active.length) {
    io.stderr(
      `perch: warning: this store still lists ${active.length} provisioned user(s) (${active.map((u) => u.id).join(', ')}). ` +
        'User namespaces are no longer supported; their tokens are rejected. Their stores and keys were not touched (see docs/SETUP.md).\n',
    );
  }
}

type AccountSection = 'all' | 'google' | 'notion' | 'gmail' | 'imap' | 'productivity' | 'slack' | 'whatsapp';

function formatSlack(data: StoreData): string[] {
  const lines = ['Slack workspaces (labels are user-assigned):'];
  if (!data.slack.length) lines.push('  (none)');
  for (const w of data.slack) {
    const mode = isSlackSession(w) ? 'read+post  session' : w.scopes.includes('chat:write') ? 'read+post' : 'read';
    lines.push(`  ${w.id}  "${w.label}"  ${w.teamName ?? w.teamId}  user ${w.userName ?? w.userId}  ${mode}  connected ${w.createdAt}`);
  }
  return lines;
}

function formatWhatsapp(data: StoreData): string[] {
  const lines = [`WhatsApp accounts${data.whatsappInstance ? ` (bridge ${data.whatsappInstance.origin})` : ' (no bridge configured)'}:`];
  if (!data.whatsapp.length) lines.push('  (none)');
  for (const a of data.whatsapp) lines.push(`  ${a.id}  "${a.label}"  ${a.jid ?? 'unknown jid'}  device ${a.deviceId}  connected ${a.createdAt}`);
  return lines;
}

/** Permissions of a group member in plain words, from the scopes it records. */
function memberPermissions(data: StoreData, service: GoogleService, groupId: string): string {
  const m = groupMembers(data, groupId);
  if (service === 'drive') return m.drive?.scopes.includes(DRIVE_SCOPE) ? 'read, write' : 'read';
  if (service === 'gmail') {
    const s = m.gmail?.scopes ?? [];
    const compose = s.includes(GMAIL_COMPOSE_SCOPE);
    return ['read', ...(compose ? ['drafts'] : []), ...(!m.gmail?.draftsOnly && (compose || s.includes(GMAIL_SEND_SCOPE)) ? ['send'] : []), ...(!m.gmail?.draftsOnly && s.includes(GMAIL_MODIFY_SCOPE) ? ['organize'] : [])].join(', ');
  }
  if (service === 'calendar') return m.productivity?.allowCalendarWrite && m.productivity.scopes.includes(CALENDAR_EVENTS_OWNED_SCOPE) ? 'read, write' : 'read';
  return 'read';
}

function memberIdOf(data: StoreData, service: GoogleService, groupId: string): string | undefined {
  const m = groupMembers(data, groupId);
  return service === 'drive' ? m.drive?.id : service === 'gmail' ? m.gmail?.id : m.productivity?.services.includes(service) ? m.productivity.id : undefined;
}

function groupServiceLines(data: StoreData, groupId: string, indent = '    '): string[] {
  const lines: string[] = [];
  for (const s of ['drive', 'gmail', 'calendar', 'contacts'] as const) {
    const id = memberIdOf(data, s, groupId);
    if (id) lines.push(`${indent}${GOOGLE_SERVICE_TITLES[s].padEnd(9)} ${id}  ${memberPermissions(data, s, groupId)}`);
  }
  return lines;
}

function formatGoogleGroups(data: StoreData): string[] {
  const lines = ['Google accounts (one login per account for Drive, Gmail, Calendar and Contacts):'];
  if (!data.googleGroups.length) lines.push('  (none)');
  for (const g of data.googleGroups) {
    lines.push(`  ${g.id}  "${g.label}"  ${g.email}  connected ${g.createdAt}`, ...groupServiceLines(data, g.id));
  }
  const separate = data.google.filter((a) => !a.groupId);
  if (separate.length) {
    lines.push('Google Drive accounts connected separately:');
    for (const g of separate) lines.push(`  ${g.id}  "${g.label}"  ${g.email}  connected ${g.createdAt}`);
  }
  return lines;
}

const groupNote = (a: { groupId?: string }) => (a.groupId ? `  (Google account group ${a.groupId})` : '');

function formatProductivity(data: StoreData): string[] {
  const lines = ['Google Calendar/Contacts accounts:'];
  if (!data.googleProductivity.length) lines.push('  (none)');
  for (const a of data.googleProductivity) {
    lines.push(`  ${a.id}  "${a.label}"  ${a.email}  ${a.services.join(',')}${a.allowCalendarWrite ? ' (calendar write)' : ' (read-only)'}  connected ${a.createdAt}${groupNote(a)}`);
  }
  return lines;
}

function formatMail(data: StoreData, which: AccountSection): string[] {
  const rows = [
    ...(which === 'all' || which === 'gmail' ? data.gmail.map((a) => ({ a, kind: 'gmail', extra: a.scopes.map((x) => x.split('/').pop()).join(',') })) : []),
    ...(which === 'all' || which === 'imap'
      ? data.imap.map((a) => ({
          a,
          kind: 'imap',
          extra:
            `${a.imap.host}/${a.smtp.host}; drafts ${a.allowDrafts ? 'on' : 'off'}, send ${a.allowSend ? 'on' : 'off'}, ` +
            `organize ${a.allowModify ? 'on' : 'off'}, sent copy ${imapSentCopyEnabled(a) ? 'on' : 'off'}`,
        }))
      : []),
  ];
  const lines = ['Mail accounts:'];
  if (!rows.length) lines.push('  (none)');
  for (const { a, extra } of rows) lines.push(`  ${a.id}  "${a.label}"  ${a.email}  ${extra}  connected ${a.createdAt}${groupNote(a as { groupId?: string })}`);
  return lines;
}

function formatAccounts(data: StoreData, which: AccountSection): string {
  if (which === 'gmail' || which === 'imap') return `${formatMail(data, which).join('\n')}\n`;
  if (which === 'productivity') return `${formatProductivity(data).join('\n')}\n`;
  if (which === 'slack') return `${formatSlack(data).join('\n')}\n`;
  if (which === 'whatsapp') return `${formatWhatsapp(data).join('\n')}\n`;
  const lines: string[] = [];
  if (which !== 'notion') lines.push(...formatGoogleGroups(data));
  if (which !== 'google') {
    lines.push('Notion workspaces (labels are user-assigned, not verified by Notion):');
    if (!data.notion.length) lines.push('  (none)');
    for (const w of data.notion) {
      const owner = w.tokenOwner?.name ? `  token owner: ${w.tokenOwner.name}` : '';
      const via = w.authMode === 'oauth' ? `  via OAuth${w.workspaceName ? ` (${w.workspaceName})` : ''}` : '';
      lines.push(`  ${w.id}  "${w.label}"${owner}${via}  connected ${w.createdAt}`);
    }
  }
  if (which === 'all') lines.push(...formatMail(data, 'all'), ...formatProductivity(data), ...formatSlack(data), ...formatWhatsapp(data));
  return `${lines.join('\n')}\n`;
}

async function cmdInit(config: PerchConfig, io: CliIo) {
  const r = await initStore({ dataDir: config.dataDir, keyFile: config.keyFile });
  io.stdout(`${r.createdKey ? 'Created' : 'Kept existing'} key file: ${config.keyFile}\n`);
  io.stdout(`${r.createdStore ? 'Created' : 'Kept existing'} encrypted store: ${path.join(config.dataDir, 'store.enc')}\n`);
  const ledger = ledgerFilePath(config.dataDir);
  if (r.createdStore) io.stdout(`Created mail workflow ledger: ${ledger}\n`);
  else if (await pathExists(ledger)) io.stdout(`Kept existing mail workflow ledger: ${ledger}\n`);
  else {
    io.stdout(
      `Mail workflow ledger is missing (${ledger}); mail tools fail closed until it is restored from backup, or, only if this ` +
        'store predates it, created with: perch mail-workflow init\n',
    );
  }
  if (config.httpTokenEnv) {
    validateHttpToken(config.httpTokenEnv);
    io.stdout('HTTP token: provided via PERCH_HTTP_TOKEN (token file not touched)\n');
  } else {
    await ensurePrivateDir(path.dirname(config.tokenFile));
    const created = await writePrivateFileExclusive(config.tokenFile, Buffer.from(`${generateHttpToken()}\n`));
    if (!created) validateHttpToken(await loadHttpToken(config));
    io.stdout(`${created ? 'Created' : 'Kept existing'} HTTP token file: ${config.tokenFile}\n`);
  }
  if (r.createdKey) {
    io.stdout('Back up the key file separately from the data directory; without it the store cannot be decrypted.\n');
  }
}

async function cmdServe(config: PerchConfig, io: CliIo, values: Record<string, unknown>): Promise<number> {
  if (Boolean(values.stdio) === Boolean(values.http)) throw new UsageError('Choose exactly one of --stdio or --http');
  const store = await openRootStore(config);
  await warnAboutProvisionedUsers(store, io);
  const context = createPerchContext(store, io.transport ?? createFetchTransport(), undefined, lumaMcpFor(io));
  if (values.stdio) {
    // Plain stdio is the read-only operator; a client token file selects one of the client grants.
    const token = config.clientTokenFile ? (await readPrivateFile(config.clientTokenFile)).toString('utf8').trim() : undefined;
    const principal = token === undefined ? READONLY_PRINCIPAL : await principalForClientToken(store, token);
    if (!principal) throw new PerchError('PERCH_CLIENT_TOKEN_FILE does not hold a known client token (perch client list)', 'unknown_client');
    await context.luma.refresh();
    const server = createMcpServer(context, principal);
    const closed = new Promise<void>((resolve) => {
      server.server.onclose = () => resolve();
    });
    await server.connect(new StdioServerTransport());
    io.stderr(`perch: serving MCP over stdio (${principal.clientId ? `client ${principal.clientId}` : 'read-only'})\n`);
    await closed;
    return 0;
  }
  const port = values.port !== undefined ? Number(values.port) : config.httpPort;
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new UsageError('--port must be a valid port');
  if (values.public && !config.publicBaseUrl) throw new PerchError('--public needs PERCH_PUBLIC_BASE_URL (see perch public setup)', 'bad_config');
  // OAuth (docs/SIMPLE_CONNECT_SPEC.md §1): the private issuer on this listener whenever a private base URL
  // is known, the public listener with --public. Without either, only the static tokens work.
  let publicAccess: Access | undefined;
  if (values.public || config.privateBaseUrl) {
    const starting = startAccess({
      context,
      upstream: new Upstream(io.transport ?? createFetchTransport()),
      ...(config.privateBaseUrl ? { privateBaseUrl: config.privateBaseUrl } : {}),
      ...(values.public
        ? {
            public: {
              baseUrl: config.publicBaseUrl!,
              port: config.publicPort,
              googleLoginClientFile: loginClientFile(config),
            },
          }
        : {}),
      ...(config.notifyTelegramFile ? { telegramFile: config.notifyTelegramFile } : {}),
      dcrEnabled: config.oauthDcr,
      trustForwarded: config.publicTrustForwarded,
      log: (l) => io.stderr(`${l}\n`),
    });
    if (values.public) publicAccess = await starting;
    else {
      // Private OAuth only: a failure here must not stop the static tokens (as before OAuth existed).
      try {
        publicAccess = await starting;
      } catch (err) {
        io.stderr(`perch: private OAuth is off: ${safeMessage(err)}\n`);
      }
    }
    if (publicAccess?.publicServer) {
      io.stderr(`perch: public listener on http://127.0.0.1:${publicAccess.publicServer.port} for ${config.publicBaseUrl}/mcp (only /mcp, /.well-known/oauth-*, /oauth/*)\n`);
    }
  } else {
    io.stderr(`perch: ${config.privateOAuth ? PRIVATE_OAUTH_OFF : PRIVATE_OAUTH_DISABLED}\n`);
  }
  const running = await startHttpServer({
    host: (values.host as string | undefined) ?? config.httpHost,
    port,
    token: await loadHttpToken(config),
    context,
    ...(publicAccess ? { localPair: publicAccess.localPair } : {}),
    ...(publicAccess?.privateOAuth ? { oauth: publicAccess.privateOAuth } : {}),
    ...(publicAccess ? { statusOptions: { pairingOpen: () => publicAccess!.pairing.isOpen } } : {}),
    allowedHosts: config.allowedHosts,
    allowedOrigins: config.allowedOrigins,
    log: (l) => io.stderr(`${l}\n`),
  });
  io.stderr(`perch: listening on ${running.url} (allowed Host headers: ${running.allowedHosts.join(', ')})\n`);
  await new Promise<void>((resolve) => {
    const stop = () => resolve();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  await running.close();
  await publicAccess?.close();
  return 0;
}

function describeGoogleRequest(r: GoogleGroupRequest): string {
  return r.services
    .map((s) => {
      if (s === 'drive') return `Drive (${r.driveWrite ? 'read + write' : 'read-only'})`;
      if (s === 'gmail') {
        const extra = [r.gmail.drafts ? 'drafts' : '', r.gmail.send ? 'send' : '', r.gmail.modify ? 'organize' : ''].filter(Boolean);
        return `Gmail (${extra.length ? `read + ${extra.join(' + ')}` : 'read-only'})`;
      }
      if (s === 'calendar') return `Calendar (${r.calendarWrite ? 'read + write own events' : 'read-only'})`;
      return 'Contacts (read-only)';
    })
    .join(', ');
}

async function cmdGoogle(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>) {
  if (sub === 'client') return cmdGoogleClient(config, io, rest[0], values);
  const upstream = new Upstream(io.transport ?? createFetchTransport());
  const store = await openStore(config);
  if (sub === 'list') return io.stdout(formatAccounts(await store.read(), 'google'));
  if (sub === 'remove') {
    const id = rest[0];
    if (!id) throw new UsageError('Usage: perch google remove ggroup-ID [--revoke [--force]] | remove ID --service drive|gmail|calendar|contacts');
    const service = typeof values.service === 'string' ? parseGoogleServices([values.service])[0]! : undefined;
    if (service && values.service !== service) throw new UsageError('--service takes one of drive, gmail, calendar, contacts');
    const current = await store.read();
    const group = findGroup(current, id);
    if (!group) {
      // A Drive account connected separately (before account groups, or with an old Perch).
      if (service) throw new UsageError(`--service needs a Google account group or one of its accounts; ${id} is not part of one`);
      const r = await removeGoogleAccount(store, upstream, id, revokeOpts(values));
      io.stdout(`Removed ${id} locally.${r.revoked ? ' The grant was revoked at Google.' : ''}\n${alsoRevokedNote(r.alsoRevoked)}`);
      if (!values.revoke) io.stdout('The Google grant is still valid; revoke it at https://myaccount.google.com/permissions or rerun with --revoke.\n');
      return;
    }
    if (!service && id !== group.id) {
      // Never remove a whole group through one member's id: that would silently take the other services too.
      const m = groupMembers(current, group.id);
      const services = m.drive?.id === id ? ['drive'] : m.gmail?.id === id ? ['gmail'] : (m.productivity?.services ?? []);
      throw new UsageError(
        `${id} is one service of Google account group ${group.id}; a whole group is removed only by its id.\n` +
          `  Only this service: ${services.map((s) => `perch google remove ${group.id} --service ${s}`).join(' ; ')}\n` +
          `  The whole group:   perch google remove ${group.id} [--revoke]`,
      );
    }
    const r = await removeGoogleGroup(store, upstream, id, { ...revokeOpts(values), ...(service ? { service } : {}) });
    if (service) {
      io.stdout(
        `Removed ${GOOGLE_SERVICE_TITLES[service]} from Google account group ${r.group.id}${r.removed.length ? ` (deleted ${r.removed.join(', ')})` : ''}.` +
          `${r.groupRemoved ? ' It was its last service, so the group and its stored login were removed too.' : ''}\n` +
          'The Google login was not revoked: it is shared by the whole group, so revoking it would disconnect every service of the account. ' +
          (r.groupRemoved ? grantStillValidHint(r.group.id) : `Revoke everything with: perch google remove ${r.group.id} --revoke\n`),
      );
      return;
    }
    io.stdout(
      `Removed Google account group ${r.group.id} (${r.group.email}) and its accounts ${r.removed.join(', ') || '(none)'} locally.` +
        `${r.revoked ? ' The login was revoked at Google once (for all of its services).' : ''}\n${alsoRevokedNote(r.alsoRevoked)}`,
    );
    if (!values.revoke) io.stdout(grantStillValidHint(r.group.id));
    return;
  }
  if (sub === 'access') return cmdGoogleAccess(config, io, store, upstream, rest[0], values);
  if (sub !== 'add') throw new UsageError('Usage: perch google add|access|list|remove|client');
  if (typeof values.label !== 'string') throw new UsageError('--label is required');
  oauthTiming(values);
  const services = await chooseGoogleServices(values, io.readLine, io.stderr);
  if (values['drafts-only'] && !services.includes('gmail')) throw new UsageError('--drafts-only requires Gmail in --services');
  await chooseAccess('google', values, io.readLine, io.stderr);
  if (values['drafts-only'] && !services.includes('gmail')) throw new UsageError('--drafts-only requires Gmail in --services');
  const request: GoogleGroupRequest = googleRequestFromFlags(services, values);
  const reg = await googleGroupLogin(config, io, store, upstream, values, {
    label: values.label,
    request,
    confirmUpdate: async (g, current) => {
      if (values.yes === true) return true;
      const what = `${g.email} is already connected as Google account group ${g.id} "${g.label}" (${current.map((s) => GOOGLE_SERVICE_TITLES[s]).join(', ') || 'no services'})`;
      const noTerminal = () =>
        new PerchError(`${what}. No interactive terminal to confirm the update; nothing was changed. Rerun with --yes to update it (same account ids).`, 'confirmation_required');
      if (!io.readLine) throw noTerminal();
      let answer: string;
      try {
        answer = await io.readLine(`${what}. Update it with the new login and permissions (same account ids, client grants stay valid)? [Y/n] `);
      } catch (e) {
        if (e instanceof PerchError && e.code === 'no_tty') throw noTerminal();
        throw e;
      }
      // Default yes only here, with a terminal: the operator saw the question.
      return yes(answer, true);
    },
  });
  const data = await store.read();
  const g = reg.group;
  io.stdout(
    `${reg.updated ? 'Updated' : 'Connected'} Google account group ${g.id} (${g.email}) as "${g.label}", one login for:\n` +
      `${groupServiceLines(data, g.id, '  ').join('\n') || '  (no service)'}\n`,
  );
  reportGrantOutcome(io, reg);
  io.stdout(
    `All services of ${g.id} share this login: removing it with --revoke disconnects all of them; perch google remove ${g.id} --service SERVICE removes one.\n` +
      `Change the read/write access of single services: perch google access ${g.id}\n`,
  );
  if (request.driveWrite || request.calendarWrite || request.gmail.drafts || request.gmail.send || request.gmail.modify) {
    io.stdout('Writes still need a client grant: perch client add --label NAME --full (or --allow … --account ID for single accounts)\n');
  }
}

/**
 * The shared login path of `perch google add` and `perch google access`: Google OAuth client (guided setup when
 * missing), one loopback flow with paste-URL fallback, then the group is created or updated in place (matched on
 * `sub`; `expectGroupId` refuses any other Google account).
 */
async function googleGroupLogin(
  config: PerchConfig,
  io: CliIo,
  store: CredentialStore,
  upstream: Upstream,
  values: Record<string, unknown>,
  opts: {
    label: string;
    request: GoogleGroupRequest;
    loginHint?: string;
    expectGroupId?: string;
    confirmUpdate?: (group: GoogleAccountGroup, services: GoogleService[]) => Promise<boolean>;
  },
): Promise<GroupRegistration> {
  const { port, timeoutMs } = oauthTiming(values);
  // After the choice: a missing client starts the guide, which lists exactly these APIs and scopes.
  const client = await loadGoogleClient(config, io, { services: opts.request.services, scopes: googleGroupScopes(opts.request) });
  const what = describeGoogleRequest(opts.request);
  const loginHint = typeof values['login-hint'] === 'string' ? values['login-hint'] : opts.loginHint;
  const grant = await runGoogleGroupAuthorization({
    client,
    upstream,
    request: opts.request,
    port,
    timeoutMs,
    ...(loginHint ? { loginHint } : {}),
    ...loginPrompts(
      io,
      `approve Google access for ${what} (one login) ${opts.expectGroupId ? `with the Google account of ${opts.expectGroupId}${opts.loginHint ? ` (${opts.loginHint})` : ''}` : 'for the account you want to add'}`,
      timeoutMs,
    ),
  });
  return registerGoogleGroup(store, upstream, {
    label: opts.label,
    client,
    grant,
    request: opts.request,
    ...(opts.confirmUpdate ? { confirmUpdate: opts.confirmUpdate } : {}),
    ...(opts.expectGroupId ? { expectGroupId: opts.expectGroupId } : {}),
  });
}

/** What Google did not grant of a login (granular consent), with the `perch google access` command that fixes it. */
function reportGrantOutcome(io: CliIo, reg: GroupRegistration): void {
  const gid = reg.group.id;
  if (reg.outcome.denied.length) {
    const names = reg.outcome.denied.map((s) => GOOGLE_SERVICE_TITLES[s]).join(', ');
    io.stdout(
      `Not granted by Google (checkbox not ticked on the consent screen): ${names}. Not connected. ` +
        `To add later: ${reg.outcome.denied.map((s) => accessCommand(gid, s, 'add')).join(' ; ')}\n`,
    );
  }
  for (const m of reg.outcome.missingWrites) {
    io.stdout(`Not granted by Google: ${m.what}; ${GOOGLE_SERVICE_TITLES[m.service]} is connected read-only. To add it: ${accessCommand(gid, m.service, 'write')}\n`);
  }
  for (const x of reg.separate) {
    io.stdout(
      `${GOOGLE_SERVICE_TITLES[x.service]} of ${reg.group.email} is already connected separately as ${x.id} and was left unchanged. ` +
        `To move it into this group: remove ${x.id}, then ${accessCommand(gid, x.service, 'add')}\n`,
    );
  }
}

/** Per-service rights of a group, one line per service (☑/☐ per right). Never prints a secret. */
function formatGroupAccess(data: StoreData, group: GoogleAccountGroup): string {
  const lines = [`Google account group ${group.id} "${group.label}" (${group.email}), one login:`];
  const access = groupAccess(data, group.id);
  const idW = Math.max(13, ...access.map((a) => a.memberId?.length ?? 0));
  for (const a of access) {
    const title = GOOGLE_SERVICE_TITLES[a.service].padEnd(9);
    if (!a.memberId) {
      lines.push(`  ☐ ${title} ${'not connected'.padEnd(idW)}  add: ${accessCommand(group.id, a.service, 'add')}`);
      continue;
    }
    const rights = a.rights.map((r) => `${r.enabled ? '☑' : '☐'} ${r.name}`).join('   ');
    lines.push(`  ☑ ${title} ${a.memberId.padEnd(idW)}  ${rights}${a.write === 'n/a' ? '   (read-only service)' : ''}`);
  }
  lines.push(
    `Change: perch google access ${group.id} --service drive|gmail|calendar --write | --read-only`,
    `Add a service: perch google access ${group.id} --add SERVICE [--write | --read-only]`,
  );
  return `${lines.join('\n')}\n`;
}

/** One service flag (--service / --add): exactly one of drive, gmail, calendar, contacts. */
function oneService(values: Record<string, unknown>, flag: 'service' | 'add'): GoogleService | undefined {
  const v = values[flag];
  if (v === undefined) return undefined;
  if (typeof v !== 'string' || v.includes(',')) throw new UsageError(`--${flag} takes one of drive, gmail, calendar, contacts`);
  return parseGoogleServices([v])[0]!;
}

/**
 * `perch google access ID` (docs/GOOGLE_UNIFIED_SPEC.md, Nachtrag 2026-10-21): shows and changes the read/write
 * access of the services of a Google account group. Granting (write, a new service) needs a Google login for the
 * same group; revoking is local and needs none.
 */
async function cmdGoogleAccess(config: PerchConfig, io: CliIo, store: CredentialStore, upstream: Upstream, id: string | undefined, values: Record<string, unknown>) {
  if (!id) {
    throw new UsageError('Usage: perch google access ggroup-ID [--service drive|gmail|calendar|contacts --write|--read-only] [--service gmail --drafts-only] [--add SERVICE [--write|--read-only]] [--yes]');
  }
  const service = oneService(values, 'service');
  const add = oneService(values, 'add');
  if (service && add) throw new UsageError('Use either --service SERVICE (change its access) or --add SERVICE (connect it), not both');
  if (['write', 'read-only', 'drafts-only'].filter(k => values[k] === true).length > 1) throw new UsageError('Choose either --write, --read-only or --drafts-only');
  if (values['drafts-only'] && (service !== 'gmail' || add)) throw new UsageError('--drafts-only requires --service gmail');
  if (values['drafts-only'] && ['allow-send', 'allow-modify', 'allow-write', 'allow-calendar-write'].some(k => values[k] === true)) throw new UsageError('--drafts-only cannot be combined with other write flags');
  oauthTiming(values);
  const data = await store.read();
  const group = resolveAccessGroup(data, id);
  const gid = group.id;
  const mode = values.write === true ? 'write' : values['read-only'] === true ? 'read-only' : values['drafts-only'] === true ? 'drafts-only' : undefined;

  /** Grants write or adds a service: one login for the same group with every scope the group needs then. */
  const login = async (s: GoogleService, write: boolean, draftsOnly = false) => {
    const current = await store.read();
    const request = accessRequest(current, gid, s, write);
    if (draftsOnly) request.gmail = { drafts: true, send: false, modify: false };
    const g = current.googleGroups.find((x) => x.id === gid)!;
    const reg = await googleGroupLogin(config, io, store, upstream, values, { label: g.label, request, loginHint: g.email, expectGroupId: gid });
    io.stdout(`Updated Google account group ${gid} (${g.email}).\n${formatGroupAccess(await store.read(), reg.group)}`);
    reportGrantOutcome(io, reg);
    if (write || draftsOnly) io.stdout('Writes still need a client grant: perch client add --label NAME --full (or --allow … --account ID for single accounts)\n');
  };

  const change = async (s: GoogleService, to: 'write' | 'read-only' | 'drafts-only') => {
    const now = groupAccess(await store.read(), gid).find((a) => a.service === s)!;
    if (to === 'write') assertWritable(s);
    if (!now.memberId) throw notConnected(gid, s);
    if (to === 'drafts-only') {
      if (await restrictGmailToDrafts(store, gid)) {
        io.stdout(`Gmail of ${gid} now permits read and drafts only in Perch (no login needed). Sending and organizing are disabled.\n` + formatGroupAccess(await store.read(), group));
      } else await login(s, false, true);
      return;
    }
    if (to === 'read-only') {
      if (now.write === 'n/a' || !(await revokeServiceWrite(store, gid, s))) {
        io.stdout(`${GOOGLE_SERVICE_TITLES[s]} of ${gid} is already read-only; nothing changed.\n`);
        return;
      }
      io.stdout(
        `${GOOGLE_SERVICE_TITLES[s]} of ${gid} is now read-only in Perch (no login needed); its write tools are refused from now on. ` +
          'The permission itself stays granted at Google until the next login for this account.\n' +
          formatGroupAccess(await store.read(), group),
      );
      return;
    }
    if (now.write === 'full') {
      io.stdout(`${GOOGLE_SERVICE_TITLES[s]} of ${gid} already has write access; nothing changed.\n`);
      return;
    }
    await login(s, true);
  };

  const addService = async (s: GoogleService, write: boolean | undefined) => {
    const now = groupAccess(await store.read(), gid).find((a) => a.service === s)!;
    if (now.memberId) {
      io.stdout(
        `${GOOGLE_SERVICE_TITLES[s]} is already connected in ${gid} (${now.memberId}). ` +
          `${s === 'contacts' ? 'Contacts are read-only.' : `Change its access: ${accessCommand(gid, s, 'write')} (or --read-only)`}\n`,
      );
      return;
    }
    if (write) assertWritable(s);
    await login(s, write ?? false);
  };

  /** read/write for a service that is being added; asked on a terminal, read-only without one. */
  const askWrite = async (s: GoogleService): Promise<boolean> => {
    if (!WRITABLE_SERVICES.includes(s)) return false;
    try {
      if (!io.readLine) throw new PerchError('no terminal', 'no_tty');
      const a = (await io.readLine(`${GOOGLE_SERVICE_TITLES[s]}: [r]ead only, or read + [w]rite? [r/w] `)).trim().toLowerCase();
      if (a === 'w' || a === 'write') return true;
      if (a === '' || a === 'r' || a === 'read') return false;
      throw new UsageError('Answer r (read only) or w (read + write)');
    } catch (e) {
      if (e instanceof PerchError && e.code === 'no_tty') {
        io.stderr(`No interactive terminal: adding ${GOOGLE_SERVICE_TITLES[s]} read-only (repeat with --write for write access).\n`);
        return false;
      }
      throw e;
    }
  };

  if (add) return addService(add, mode === 'write' ? true : mode === 'read-only' ? false : await askWrite(add));
  if (service) {
    if (mode) return change(service, mode);
    io.stdout(formatGroupAccess(data, group));
    return;
  }
  if (mode) throw new UsageError('--write and --read-only need --service SERVICE (or --add SERVICE)');
  io.stdout(formatGroupAccess(data, group));

  // Interactive change, only with a terminal.
  if (!io.readLine) return;
  let pick: string;
  try {
    pick = (await io.readLine('Change a service? [drive/gmail/calendar/contacts, Enter = no change] ')).trim().toLowerCase();
  } catch (e) {
    if (e instanceof PerchError && e.code === 'no_tty') return;
    throw e;
  }
  if (!pick) return;
  const s = parseGoogleServices([pick])[0]!;
  const now = groupAccess(data, gid).find((a) => a.service === s)!;
  if (!now.memberId) {
    const write = await askWrite(s);
    if (values.yes !== true && !yes(await io.readLine(`Connect ${GOOGLE_SERVICE_TITLES[s]} ${write ? 'read + write' : 'read-only'} (needs a Google login for ${group.email})? [Y/n] `), true)) {
      io.stdout('Nothing changed.\n');
      return;
    }
    return addService(s, write);
  }
  if (now.write === 'n/a') {
    io.stdout(`${GOOGLE_SERVICE_TITLES[s]} are read-only in Perch; nothing to change.\n`);
    return;
  }
  const to = (await askWrite(s)) ? 'write' : 'read-only';
  const needsLogin = to === 'write' && now.write !== 'full';
  if (
    values.yes !== true &&
    !yes(await io.readLine(`Set ${GOOGLE_SERVICE_TITLES[s]} to ${to === 'write' ? 'read + write' : 'read only'}${needsLogin ? ` (needs a Google login for ${group.email})` : ''}? [Y/n] `), true)
  ) {
    io.stdout('Nothing changed.\n');
    return;
  }
  return change(s, to);
}

async function cmdNotion(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>) {
  const store = await openStore(config);
  if (sub === 'list') return io.stdout(formatAccounts(await store.read(), 'notion'));
  if (sub === 'remove') {
    const id = rest[0];
    if (!id) throw new UsageError('Usage: perch notion remove ID');
    await removeNotionWorkspace(store, id);
    io.stdout(
      `Disconnected ${id} locally. The token itself stays valid until you revoke it in Notion ` +
        '(Settings > Connections / personal access tokens).\n',
    );
    return;
  }
  if (sub === 'client') return cmdNotionClient(config, io, rest[0]);
  if (sub !== 'add') throw new UsageError('Usage: perch notion add|list|remove|client');
  if (typeof values.label !== 'string') throw new UsageError('--label is required');
  const upstream = new Upstream(io.transport ?? createFetchTransport());
  const hasWorkspace = (await store.read()).notion.length > 0;
  if ((await chooseNotionMode(io, values)) === 'oauth') {
    const timeoutS = values.timeout !== undefined ? Number(values.timeout) : DEFAULT_AUTH_TIMEOUT_MS / 1000;
    if (!Number.isInteger(timeoutS) || timeoutS < 1 || timeoutS > MAX_AUTH_TIMEOUT_MS / 1000) {
      throw new UsageError(`--timeout must be a whole number of seconds between 1 and ${MAX_AUTH_TIMEOUT_MS / 1000}`);
    }
    const client = await ensureNotionClient(config, io);
    const grant = await runNotionAuthorization({
      client,
      upstream,
      timeoutMs: timeoutS * 1000,
      ...loginPrompts(io, 'choose the workspace and the pages Perch may use', timeoutS * 1000),
    });
    const { workspace: ws, updated } = await upsertNotionOAuthWorkspace(store, { label: values.label, client, grant });
    io.stdout(
      `${updated ? 'Updated' : 'Connected'} Notion workspace ${ws.id} as "${ws.label}"` +
        `${ws.workspaceName ? ` (${ws.workspaceName})` : ''} via OAuth${ws.refreshToken ? ' (refreshing token)' : ''}.\n`,
    );
    io.stdout(notionVisibilityLine(await countVisibleNotionObjects(upstream, grant.access_token!), 'oauth'));
    return;
  }
  await maybeShowNotionGuide(io, { skip: values['skip-guide'] === true, hasWorkspace });
  const token = await io.readSecret(`Notion Internal Integration Secret (ntn_…) for "${values.label}" (input hidden): `);
  const ws = await addNotionWorkspace(store, upstream, {
    label: values.label,
    token,
  });
  io.stdout(
    `Connected Notion workspace ${ws.id} as "${ws.label}"` +
      `${ws.tokenOwner?.name ? ` (token owner: ${ws.tokenOwner.name})` : ''}.\n`,
  );
  io.stdout(notionVisibilityLine(await countVisibleNotionObjects(upstream, ws.token), 'token'));
}

/** --oauth / --internal, else asked in a terminal, else the internal token (the masked prompt then fails as before). */
async function chooseNotionMode(io: CliIo, values: Record<string, unknown>): Promise<'token' | 'oauth'> {
  if (values.oauth === true && values.internal === true) throw new UsageError('Use either --oauth or --internal');
  if (values.oauth === true) return 'oauth';
  if (values.internal === true || !io.readLine) return 'token';
  io.stdout(
    '\nNotion can be connected in two ways:\n' +
      '  [t]oken  internal integration (in team workspaces often owners only)\n' +
      '  [o]auth  public integration, login in the browser (no owner rights needed)\n',
  );
  for (;;) {
    const a = (await io.readLine('Connect via [t]oken or [o]auth? [T/o] ')).trim().toLowerCase();
    if (a === '' || a === 't' || a === 'token') return 'token';
    if (a === 'o' || a === 'oauth') return 'oauth';
  }
}

/** Post-connect hint from one small search call (no line when the call failed). */
function notionVisibilityLine(v: NotionVisibility | undefined, mode: 'token' | 'oauth'): string {
  if (!v) return '';
  if (v.count === 0) {
    return mode === 'oauth'
      ? 'No page shared yet: run the same command again and select pages in Notion, or open a page: ••• → Connections → Perch.\n'
      : 'No page shared yet: open a page in Notion, ••• → Connections → Perch (subpages inherit access).\n';
  }
  return `Perch can see ${v.more ? `at least ${v.count}` : v.count} page(s)/data source(s) in this workspace.\n`;
}

function oauthTiming(values: Record<string, unknown>) {
  const port = values.port !== undefined ? Number(values.port) : 0;
  const timeoutS = values.timeout !== undefined ? Number(values.timeout) : DEFAULT_AUTH_TIMEOUT_MS / 1000;
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new UsageError('--port must be a valid port');
  if (!Number.isInteger(timeoutS) || timeoutS < 1 || timeoutS > MAX_AUTH_TIMEOUT_MS / 1000) {
    throw new UsageError(`--timeout must be a whole number of seconds between 1 and ${MAX_AUTH_TIMEOUT_MS / 1000}`);
  }
  return { port, timeoutMs: timeoutS * 1000 };
}

const approve = (what: string) => `approve ${what} for the account you want to add`;

function groupMemberRemoved(id: string, groupId: string, groupRemoved: boolean): string {
  return (
    `Removed ${id} from Google account group ${groupId} locally.` +
    (groupRemoved
      ? ` It was its last service, so the group and its stored login were removed too.\n${grantStillValidHint(groupId)}`
      : ` The shared login stays for the group's other services (perch google list).\n`)
  );
}

/** --revoke and --force of the Google remove commands. */
function revokeOpts(values: Record<string, unknown>): { revoke: boolean; force: boolean } {
  if (values.force === true && values.revoke !== true) throw new UsageError('--force only applies to --revoke');
  return { revoke: values.revoke === true, force: values.force === true };
}

/** What a forced revoke ended as well (Google revokes the whole grant of the OAuth client for the account). */
function alsoRevokedNote(holders: readonly SharedGrantHolder[] | undefined): string {
  if (!holders?.length) return '';
  return (
    `--force: Google revoked the whole grant of this OAuth client for the account, so these lost access too: ${holders.map((h) => `${h.id} ("${h.label}")`).join(', ')}. ` +
    'Connect them again (perch google add) or remove them.\n'
  );
}

function describeOptIns(values: Record<string, unknown>): string {
  const extra = [values['allow-drafts'] ? 'drafts' : '', values['allow-send'] ? 'send' : '', values['allow-modify'] ? 'organize' : ''].filter(Boolean);
  return extra.length ? `read + ${extra.join(' + ')}` : 'read-only';
}

async function cmdGmail(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>) {
  const upstream = new Upstream(io.transport ?? createFetchTransport());
  const store = await openStore(config);
  if (sub === 'list') return io.stdout(formatAccounts(await store.read(), 'gmail'));
  if (sub === 'remove') {
    const id = rest[0];
    if (!id) throw new UsageError('Usage: perch gmail remove ID [--revoke]');
    const r = await removeGmailAccount(store, upstream, id, revokeOpts(values));
    if (r.groupId) return io.stdout(groupMemberRemoved(id, r.groupId, Boolean(r.groupRemoved)));
    io.stdout(`Removed ${id} locally.${r.revoked ? ' The grant was revoked at Google.' : ''}\n${alsoRevokedNote(r.alsoRevoked)}`);
    if (!values.revoke) io.stdout('The Gmail grant is still valid; revoke it at https://myaccount.google.com/permissions or rerun with --revoke.\n');
    return;
  }
  if (sub !== 'add') throw new UsageError('Usage: perch gmail add|list|remove');
  if (typeof values.label !== 'string') throw new UsageError('--label is required');
  const { port, timeoutMs } = oauthTiming(values);
  const scopes = gmailScopesFor({ send: Boolean(values['allow-send']), drafts: Boolean(values['allow-drafts']), modify: Boolean(values['allow-modify']) });
  const client = await loadGoogleClient(config, io, { services: ['gmail'], scopes });
  const grant = await runLoopbackAuthorization({
    client,
    upstream,
    port,
    timeoutMs,
    scopes,
    ...(typeof values['login-hint'] === 'string' ? { loginHint: values['login-hint'] } : {}),
    ...loginPrompts(io, approve(`Gmail access (${describeOptIns(values)})`), timeoutMs),
  });
  const account = await registerGmailAccount(store, upstream, { label: values.label, client, grant, draftsOnly: values['drafts-only'] === true });
  io.stdout(`Connected Gmail account ${account.id} (${account.email}) as "${account.label}" (${describeOptIns(values)}).\n`);
  io.stdout('This Gmail account has its own login. One login for Drive, Gmail, Calendar and Contacts: perch google add --label NAME\n');
}

async function cmdMicrosoft(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>) {
  if (sub === 'client' || values.oauth) {
    throw new UsageError('The standalone Microsoft Graph OAuth connector is retired. Reconnect with perch microsoft add --label NAME (browser session; no Entra app registration).');
  }
  if (sub === 'remove' && rest[0]?.startsWith('microsoft-')) {
    await removeMicrosoftAccount(await openStore(config), rest[0]);
    io.stdout(`Removed legacy Microsoft OAuth credential ${rest[0]} locally. Revoke the old app consent at https://account.live.com/consent/Manage (personal) or https://myapplications.microsoft.com (work/school).\n`);
    return;
  }
  return cmdMicrosoftSession(config, io, sub, values, rest);
}

async function cmdProductivity(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>) {
  const upstream = new Upstream(io.transport ?? createFetchTransport());
  const store = await openStore(config);
  if (sub === 'list') return io.stdout(formatAccounts(await store.read(), 'productivity'));
  if (sub === 'remove') {
    const id = rest[0];
    if (!id) throw new UsageError('Usage: perch google-productivity remove ID [--revoke]');
    const r = await removeProductivityAccount(store, upstream, id, revokeOpts(values));
    if (r.groupId) return io.stdout(groupMemberRemoved(id, r.groupId, Boolean(r.groupRemoved)));
    io.stdout(`Removed ${id} locally.${r.revoked ? ' The grant was revoked at Google.' : ''}\n${alsoRevokedNote(r.alsoRevoked)}`);
    if (!values.revoke) io.stdout('The Google grant is still valid; revoke it at https://myaccount.google.com/permissions or rerun with --revoke.\n');
    return;
  }
  if (sub !== 'add') throw new UsageError('Usage: perch google-productivity add|list|remove');
  if (typeof values.label !== 'string') throw new UsageError('--label is required');
  if (typeof values.services !== 'string') throw new UsageError('--services is required: calendar, contacts or calendar,contacts');
  const services = parseServices(values.services.split(','));
  const allowCalendarWrite = Boolean(values['allow-calendar-write']);
  const scopes = productivityScopesFor({ services, allowCalendarWrite });
  const { port, timeoutMs } = oauthTiming(values);
  const client = await loadGoogleClient(config, io, { services, scopes });
  const what = services.map((s) => (s === 'calendar' && allowCalendarWrite ? 'calendar (read + write own events)' : `${s} (read-only)`)).join(', ');
  const grant = await runProductivityAuthorization({
    client,
    upstream,
    services,
    allowCalendarWrite,
    port,
    timeoutMs,
    ...(typeof values['login-hint'] === 'string' ? { loginHint: values['login-hint'] } : {}),
    ...loginPrompts(io, approve(`Google ${what} access`), timeoutMs),
  });
  const account = await registerProductivityAccount(store, upstream, { label: values.label, client, grant, services, allowCalendarWrite });
  io.stdout(`Connected Google account ${account.id} (${account.email}) as "${account.label}" for ${what}.\n`);
  io.stdout('This account has its own login for Calendar/Contacts. One login for Drive, Gmail, Calendar and Contacts: perch google add --label NAME\n');
  if (allowCalendarWrite) io.stdout(`Calendar writes additionally need a client grant: perch client add --allow calendar_read,calendar_write[,calendar_invite] --account ${account.id} (calendar_invite: guests, invitations, responses)\n`);
}

function optPort(values: Record<string, unknown>, name: string): number | undefined {
  const v = values[name];
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new UsageError(`--${name} must be a valid port`);
  return n;
}

async function cmdImap(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>) {
  if (sub === 'presets') {
    const lines: string[] = [];
    for (const [name, p] of Object.entries(IMAP_PRESETS)) {
      lines.push(
        `${name}: ${p.name} (${p.domains.join(', ')})`,
        `  IMAP ${p.imap.host}:${p.imap.port} (TLS); SMTP ${p.smtp.host}:${p.smtp.port} (TLS) or :${p.smtpStarttlsPort} (STARTTLS)`,
        `  ${p.notes}`,
      );
    }
    return io.stdout(`${lines.join('\n')}\n`);
  }
  const store = await openStore(config);
  if (sub === 'list') return io.stdout(formatAccounts(await store.read(), 'imap'));
  if (sub === 'remove') {
    const id = rest[0];
    if (!id) throw new UsageError('Usage: perch imap remove ID');
    await removeImapAccount(store, id);
    io.stdout(`Removed ${id} locally (the stored password was deleted). Revoke an app password at your provider if you created one.\n`);
    return;
  }
  if (sub !== 'add') throw new UsageError('Usage: perch imap add|list|remove|presets');
  if (typeof values.label !== 'string') throw new UsageError('--label is required');
  if (typeof values.email !== 'string') throw new UsageError('--email is required');
  const security = values['smtp-security'];
  if (security !== undefined && security !== 'tls' && security !== 'starttls') throw new UsageError('--smtp-security must be tls or starttls');
  const password = await io.readSecret(`IMAP/SMTP password (app password) for ${values.email} (input hidden): `);
  const str = (k: string) => (typeof values[k] === 'string' ? (values[k] as string) : undefined);
  const imapPort = optPort(values, 'imap-port');
  const smtpPort = optPort(values, 'smtp-port');
  const account = await addImapAccount(
    store,
    {
      label: values.label,
      email: values.email,
      password,
      allowDrafts: Boolean(values['allow-drafts']),
      allowSend: Boolean(values['allow-send']),
      allowModify: Boolean(values['allow-modify']),
      ...(values['no-sent-copy'] ? { sentCopy: false } : {}),
      ...(str('username') ? { username: str('username')! } : {}),
      ...(str('preset') ? { preset: str('preset')! } : {}),
      ...(str('imap-host') ? { imapHost: str('imap-host')! } : {}),
      ...(imapPort ? { imapPort } : {}),
      ...(str('smtp-host') ? { smtpHost: str('smtp-host')! } : {}),
      ...(smtpPort ? { smtpPort } : {}),
      ...(security ? { smtpSecurity: security as 'tls' | 'starttls' } : {}),
      ...(str('drafts-mailbox') ? { draftsMailbox: str('drafts-mailbox')! } : {}),
    },
    io.imapVerify ?? ((a) => verifyImapAccount(a)),
  );
  io.stdout(
    `Connected IMAP account ${account.id} (${account.email}) as "${account.label}" via ${account.imap.host}/${account.smtp.host} ` +
      `(drafts ${account.allowDrafts ? 'on' : 'off'}, send ${account.allowSend ? 'on' : 'off'}, organize ${account.allowModify ? 'on' : 'off'}, ` +
      `sent copy ${imapSentCopyEnabled(account) ? 'on' : 'off'}).\n`,
  );
}

async function cmdSlack(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>) {
  if (sub === 'manifest') return io.stdout('Connect Slack with: perch slack add --label NAME\n');
  const store = await openStore(config);
  if (sub === 'list') return io.stdout(formatAccounts(await store.read(), 'slack'));
  if (sub === 'remove') {
    const id = rest[0];
    if (!id) throw new UsageError('Usage: perch slack remove ID');
    const session = (await store.read()).slack.some((w) => w.id === id && isSlackSession(w));
    await removeSlackWorkspace(store, id);
    io.stdout(
      session
        ? `Disconnected ${id} locally. The browser session stays valid until you sign out of Slack in that browser.\n`
        : `Disconnected ${id} locally. The token stays valid until you uninstall the app (or revoke the token) in that Slack workspace.\n`,
    );
    return;
  }
  if (sub !== 'add') throw new UsageError('Usage: perch slack add|list|remove');
  if (typeof values.label !== 'string') throw new UsageError('--label is required');
  const before = (await store.read()).slack;
  io.stdout(SLACK_SESSION_WARNING);
  showSlackSessionGuide(io, { skip: values['skip-guide'] === true });
  const sessionCookie = await io.readSecret(`Slack cookie "d" (xoxd-…) for "${values.label}" (input hidden): `);
  normalizeSlackCookie(sessionCookie); // Reject an invalid cookie before asking for the token.
  const token = await io.readSecret(`Slack session token (xoxc-…) for "${values.label}" (input hidden): `);
  const ws = await addSlackWorkspace(store, new Upstream(io.transport ?? createFetchTransport()), { label: values.label, token, sessionCookie });
  const updated = before.some((w) => w.id === ws.id);
  io.stdout(
    `${updated ? 'Updated' : 'Connected'} Slack workspace ${ws.id} "${ws.label}" (${ws.teamName ?? ws.teamId}, user ${ws.userName ?? ws.userId}) with your browser session.\n` +
      `Posting needs a client grant: perch client add --label NAME --allow slack_read,slack_send --account ${ws.id}\n`,
  );
}

async function cmdWhatsapp(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>) {
  const store = await openStore(config);
  const upstream = new Upstream(io.transport ?? createFetchTransport());
  const gowaDeps = (): InstallDeps => {
    const home = io.env.HOME;
    if (!home || !path.isAbsolute(home)) throw new PerchError('HOME is not set to an absolute path', 'usage');
    return {
      ...defaultInstallDeps({
        home,
        sleep: io.sleep,
        out: io.stdout,
        ask: io.readLine,
        configuredOrigin: async () => (await store.read()).whatsappInstance?.origin,
        probe: async (url, username, password) => void (await probeWhatsappInstance(upstream, { url, username, password })),
        store: async (url, username, password) => void (await setWhatsappInstance(store, upstream, { url, username, password })),
      }),
      ...io.whatsappInstall,
    };
  };
  if (sub === 'install') {
    if (rest.length) throw new UsageError('Usage: perch whatsapp install [--yes] [--dir PATH] [--port N]');
    const dir = typeof values.dir === 'string' ? values.dir : undefined;
    const r = await installGowa({ yes: values.yes === true, dir, port: optPort(values, 'port') }, gowaDeps());
    if (r.status === 'unit_updated') return;
    return io.stdout('Next: perch whatsapp add --label NAME --phone +43…  (pairs your phone by code)\n');
  }
  if (sub === 'rotate-password') {
    if (rest.length) throw new UsageError('Usage: perch whatsapp rotate-password [--dir PATH]');
    const dir = typeof values.dir === 'string' ? values.dir : undefined;
    await rotateGowaPassword({ dir }, gowaDeps());
    return;
  }
  if (sub === 'instance') {
    const action = rest[0];
    if (action === 'show') {
      const inst = (await store.read()).whatsappInstance;
      return io.stdout(inst ? `WhatsApp bridge: ${inst.origin} (basic auth user set; password stored encrypted), configured ${inst.createdAt}\n` : 'No WhatsApp bridge configured.\n');
    }
    if (action !== 'set') throw new UsageError('Usage: perch whatsapp instance set --url URL | show');
    if (typeof values.url !== 'string') throw new UsageError('--url is required, e.g. http://127.0.0.1:3000');
    const username = await io.readSecret('GOWA basic-auth username (input hidden): ');
    const password = await io.readSecret('GOWA basic-auth password (input hidden): ');
    const r = await setWhatsappInstance(store, upstream, { url: values.url, username, password });
    return io.stdout(`WhatsApp bridge ${r.origin} verified (${r.devices} device slot(s)) and stored.\n`);
  }
  if (sub === 'list') return io.stdout(formatAccounts(await store.read(), 'whatsapp'));
  if (sub === 'status') {
    const rows = await whatsappDeviceStatus(store, upstream);
    if (!rows.length) return io.stdout('No WhatsApp accounts.\n');
    return io.stdout(
      `${rows
        .map((r) => `  ${r.account.id}  "${r.account.label}"  ${r.error ? `error: ${r.error}` : `${r.loggedIn ? 'logged in' : 'NOT logged in (pair again)'}, ${r.connected ? 'connected' : 'disconnected'}`}`)
        .join('\n')}\n`,
    );
  }
  if (sub === 'remove') {
    const id = rest[0];
    if (!id) throw new UsageError('Usage: perch whatsapp remove ID [--keep-device]');
    const deleted = await removeWhatsappAccount(store, upstream, id, { keepDevice: values['keep-device'] === true });
    io.stdout(
      `Removed ${id} locally. ` +
        (values['keep-device'] === true
          ? 'Its device slot was kept in the bridge (still linked).\n'
          : deleted
            ? 'Its device slot was deleted in the bridge: unlinked from the phone, stored chats cleared.\n'
            : 'The bridge could not delete its device slot: unlink "Perch" under WhatsApp > Linked devices on the phone.\n'),
    );
    return;
  }
  if (sub !== 'add') throw new UsageError('Usage: perch whatsapp install|rotate-password|instance|add|list|status|remove');
  if (typeof values.label !== 'string') throw new UsageError('--label is required');
  if (typeof values.phone !== 'string') throw new UsageError('--phone is required (international format, e.g. +4366012345678)');
  const timeout = values.timeout === undefined ? DEFAULT_PAIR_TIMEOUT_MS / 1000 : Number(values.timeout);
  if (!Number.isInteger(timeout) || timeout < 30 || timeout > 900) throw new UsageError('--timeout must be 30-900 seconds');
  const account = await pairWhatsappAccount(store, upstream, {
    label: values.label,
    phone: values.phone,
    timeoutMs: timeout * 1000,
    sleep: io.sleep,
    onCode: (code) =>
      io.stdout(
        `Pairing code: ${code}\nOn the phone: WhatsApp > Settings > Linked devices > Link a device > "Link with phone number instead", ` +
          `then enter the code. Waiting up to ${timeout} s...\n`,
      ),
  });
  io.stdout(
    `Connected WhatsApp account ${account.id} "${account.label}"${account.jid ? ` (${account.jid})` : ''}.\n` +
      'Reading is available to the global token; sending needs a client grant: ' +
      `perch client add --label NAME --allow whatsapp_read,whatsapp_send --account ${account.id}\n`,
  );
}

async function cmdStatus(config: PerchConfig, io: CliIo, values: Record<string, unknown>): Promise<number> {
  const store = await openStore(config);
  const ctx = createPerchContext(store, io.transport ?? createFetchTransport(), undefined, lumaMcpFor(io));
  const report = await collectStatus(ctx, { live: values['no-check'] !== true, ...(io.imapVerify ? { imapVerify: io.imapVerify } : {}) });
  if (values.json === true) io.stdout(`${JSON.stringify(report, null, 2)}\n`);
  else if (values.plain === true) io.stdout(formatStatusText(report));
  else {
    const capabilities = accountCapabilities(await store.read());
    io.stdout(formatStatusTerminal(report, capabilities, { tty: io.stdoutIsTTY === true, ...(io.stdoutColumns ? { columns: io.stdoutColumns } : {}), env: io.env }));
  }
  return failedChecks(report) ? 1 : 0;
}

async function cmdClient(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>) {
  const store = await openStore(config);
  if (sub === 'list') {
    const { clients } = await store.read();
    const lines = ['Client grants:'];
    if (!clients.length) lines.push('  (none)');
    for (const c of clients) {
      lines.push(
        c.full
          ? `  ${c.id}  "${c.label}"  FULL access (all capabilities, all accounts incl. later ones)  created ${c.createdAt}`
          : c.readAll
            ? `  ${c.id}  "${c.label}"  read only (all accounts incl. later ones)  created ${c.createdAt}`
            : `  ${c.id}  "${c.label}"  ${c.capabilities.join(',')}  accounts ${c.accountIds.join(',')}  created ${c.createdAt}`,
      );
    }
    return io.stdout(`${lines.join('\n')}\n`);
  }
  if (sub === 'remove') {
    const id = rest[0];
    if (!id) throw new UsageError('Usage: perch client remove ID');
    await removeClientGrant(store, id);
    return io.stdout(`Removed client ${id}; its token stops working immediately. Delete its token file.\n`);
  }
  if (sub !== 'add') throw new UsageError('Usage: perch client add|list|remove');
  if (typeof values.label !== 'string') throw new UsageError('--label is required');
  const tokenFileFor = () =>
    path.resolve(
      typeof values['token-file'] === 'string'
        ? values['token-file']
        : path.join(path.dirname(config.tokenFile), 'clients', `${randomBytes(4).toString('hex')}.token`),
    );
  if (values['read-all'] === true) {
    if (values.full === true || values.allow !== undefined || values.account !== undefined) throw new UsageError('--read-all replaces --full, --allow and --account; use one of them');
    const tokenFile = tokenFileFor();
    const { client } = await createClientGrant(store, { label: values.label, capabilities: [], accountIds: [], tokenFile, readAll: true });
    io.stdout(
      `Created client ${client.id} "${client.label}" with read-only access to every connected account, including accounts connected later.\n` +
        `Its bearer token was written to ${tokenFile} (0600) and is not shown here. Revoke with: perch client remove ${client.id}\n`,
    );
    return;
  }
  if (values.full === true) {
    if (values.allow !== undefined || values.account !== undefined) throw new UsageError('--full replaces --allow and --account; use one or the other');
    const tokenFile = tokenFileFor();
    const { client } = await createClientGrant(store, { label: values.label, capabilities: [], accountIds: [], tokenFile, full: true });
    io.stdout(
      `Created client ${client.id} "${client.label}" with FULL access: read and write on every connected account, including accounts connected later.\n` +
        `Its bearer token was written to ${tokenFile} (0600) and is not shown here. Revoke with: perch client remove ${client.id}\n` +
        claudeAddCommand(config, tokenFile),
    );
    return;
  }
  if (typeof values.allow !== 'string') {
    throw new UsageError(
      '--allow is required (comma separated: read,draft,send for mail; calendar_read,calendar_write,calendar_invite,contacts_read for gprod accounts; ' +
        'slack_read,slack_send for slack accounts; whatsapp_read,whatsapp_send for whatsapp accounts)',
    );
  }
  const accounts = (values.account as string[] | undefined) ?? [];
  if (!accounts.length) throw new UsageError('--account is required (repeat for several accounts)');
  const capabilities = parseCapabilities(values.allow.split(','));
  const tokenFile = path.resolve(
    typeof values['token-file'] === 'string'
      ? values['token-file']
      : path.join(path.dirname(config.tokenFile), 'clients', `${randomBytes(4).toString('hex')}.token`),
  );
  const { client } = await createClientGrant(store, { label: values.label, capabilities, accountIds: accounts, tokenFile });
  io.stdout(
    `Created client ${client.id} "${client.label}" (${client.capabilities.join(',')}) for ${client.accountIds.join(', ')}.\n` +
      `Its bearer token was written to ${tokenFile} (0600) and is not shown here.\n` +
      'HTTP: send it as "Authorization: Bearer <token>". stdio: set PERCH_CLIENT_TOKEN_FILE to that file.\n',
  );
}

const describeActor = (a: Actor) =>
  a.kind === 'client' ? `client ${a.clientId}` : a.kind === 'local_admin' ? 'local admin' : a.kind === 'oauth' ? `public access${a.deviceId ? ` ${a.deviceId}` : ''}` : 'operator (read-only)';

function optOne(values: Record<string, unknown>, name: string, pattern: RegExp, what: string): string | undefined {
  const v = values[name];
  const list = Array.isArray(v) ? v : v === undefined ? [] : [v];
  if (list.length > 1 || (list.length === 1 && (typeof list[0] !== 'string' || !pattern.test(list[0])))) throw new UsageError(`--${name} must be one ${what}`);
  return list[0] as string | undefined;
}

async function cmdAudit(config: PerchConfig, io: CliIo, sub: string | undefined, values: Record<string, unknown>) {
  if (sub !== 'list') throw new UsageError('Usage: perch audit list [--limit N] [--client ID] [--account ID]');
  let limit: number | undefined;
  if (values.limit !== undefined) {
    limit = Number(values.limit);
    if (!/^\d+$/.test(String(values.limit)) || limit < 1 || limit > MAX_AUDIT_EVENTS) throw new UsageError(`--limit must be 1-${MAX_AUDIT_EVENTS}`);
  }
  const clientId = optOne(values, 'client', /^client-[a-f0-9]{8}$/, 'client id (client-…)');
  const accountId = optOne(values, 'account', ACCOUNT_ID_PATTERN, 'account id');
  const store = await openStore(config);
  const { events, dropped, total } = await new AuditLog(new MailWorkflowLedger(store)).list({
    ...(clientId ? { clientId } : {}),
    ...(accountId ? { accountId } : {}),
    ...(limit ? { limit } : {}),
  });
  const lines = [
    `Audit events (namespace ${store.namespace}; oldest first; ${events.length} of ${total} shown` +
      `${dropped ? `; ${dropped} older events were dropped (ring of ${MAX_AUDIT_EVENTS})` : ''}). No content, recipients or credentials are recorded:`,
  ];
  if (!events.length) lines.push('  (none)');
  for (const e of events) {
    const account = e.accountId ? `${e.accountId} (${e.provider})` : '-';
    lines.push(`  ${e.at}  ${e.operationId}  ${e.type}  ${e.outcome}  ${describeActor(e.actor)}  ${account}${e.code ? `  ${e.code}` : ''}`);
  }
  io.stdout(`${lines.join('\n')}\n`);
}

async function cmdMailWorkflow(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>) {
  if (sub === 'init') {
    const store = await openStore(config);
    if (!(await initMailWorkflowLedger(store))) {
      throw new PerchError(`Mail workflow ledger ${ledgerFilePath(store.storePaths.dataDir)} already exists; refusing to overwrite it`, 'ledger_exists');
    }
    return io.stdout(`Created mail workflow ledger: ${ledgerFilePath(store.storePaths.dataDir)} (namespace ${store.namespace})\n`);
  }
  if (sub === 'list') {
    const state = values.state;
    if (state !== undefined && !(SEND_STATES as readonly unknown[]).includes(state)) throw new UsageError(`--state must be one of ${SEND_STATES.join(', ')}`);
    const store = await openStore(config);
    const sends = (await new MailWorkflowLedger(store).read()).sends.filter((r) => state === undefined || r.state === state);
    const lines = [
      `Send records (namespace ${store.namespace}). "accepted" = accepted by the provider, not proof of delivery; ` +
        '"pending"/"indeterminate" = outcome unknown, never resent:',
    ];
    if (!sends.length) lines.push('  (none)');
    for (const r of sends) {
      lines.push(
        `  ${r.operationId}  ${r.state}  ${r.accountId} (${r.provider})  ${describeActor(r.actor)}  created ${r.createdAt}` +
          `${r.finalizedAt ? `  finalized ${r.finalizedAt}` : ''}${r.reason ? `  ${r.reason}` : ''}` +
          `${r.resolution ? `  resolved: ${r.resolution.outcome === 'sent' ? 'sent' : 'not sent'} ${r.resolution.at}` : ''}`,
      );
    }
    return io.stdout(`${lines.join('\n')}\n`);
  }
  if (sub === 'resolve') {
    const op = rest[0];
    if (!op || !OPERATION_ID_PATTERN.test(op)) throw new UsageError('Usage: perch mail-workflow resolve OPERATION_ID --outcome sent|not-sent');
    if (values.outcome !== 'sent' && values.outcome !== 'not-sent') throw new UsageError('--outcome must be sent or not-sent (after checking the Sent folder)');
    const outcome = values.outcome === 'sent' ? 'sent' : 'not_sent';
    const store = await openStore(config);
    await resolveSend(new MailWorkflowLedger(store), op, outcome);
    return io.stdout(
      `Recorded for ${op}: verified ${outcome === 'sent' ? 'sent' : 'not sent'}. Nothing was sent; the requestId stays used, so a client ` +
        'must use a new requestId to send again.\n',
    );
  }
  if (sub === 'prune') {
    // Refused before opening anything: forgetting a requestId would allow a duplicate send.
    throw new PerchError(PRUNE_REFUSED, 'prune_unsupported');
  }
  throw new UsageError('Usage: perch mail-workflow list|resolve|init');
}

async function cmdToken(config: PerchConfig, io: CliIo, sub: string | undefined) {
  if (sub !== 'rotate') throw new UsageError('Usage: perch token rotate');
  await ensurePrivateDir(path.dirname(config.tokenFile));
  await writePrivateFileAtomic(config.tokenFile, Buffer.from(`${generateHttpToken()}\n`));
  io.stdout(`Wrote a new HTTP token to ${config.tokenFile}. Restart \`perch serve --http\` and update the client header.\n`);
}

export async function runCli(argv: string[], io: CliIo): Promise<number> {
  if (argv.some((a) => SECRET_FLAG.test(a))) {
    io.stderr('Secrets are never accepted as command-line arguments. Use the masked prompt, a 0600 file or env vars.\n');
    return 2;
  }
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        stdio: { type: 'boolean' },
        http: { type: 'boolean' },
        host: { type: 'string' },
        port: { type: 'string' },
        label: { type: 'string' },
        timeout: { type: 'string' },
        'login-hint': { type: 'string' },
        revoke: { type: 'boolean' },
        force: { type: 'boolean' },
        'allow-send': { type: 'boolean' },
        'allow-drafts': { type: 'boolean' },
        'allow-calendar-write': { type: 'boolean' },
        'allow-invites': { type: 'boolean' },
        site: { type: 'string', multiple: true },
        services: { type: 'string' },
        service: { type: 'string' },
        add: { type: 'string' },
        'redirect-host': { type: 'string' },
        email: { type: 'string' },
        username: { type: 'string' },
        preset: { type: 'string' },
        'imap-host': { type: 'string' },
        'imap-port': { type: 'string' },
        'smtp-host': { type: 'string' },
        'smtp-port': { type: 'string' },
        'smtp-security': { type: 'string' },
        'drafts-mailbox': { type: 'string' },
        allow: { type: 'string' },
        account: { type: 'string', multiple: true },
        'token-file': { type: 'string' },
        limit: { type: 'string' },
        client: { type: 'string' },
        state: { type: 'string' },
        outcome: { type: 'string' },
        before: { type: 'string' },
        url: { type: 'string' },
        phone: { type: 'string' },
        'keep-device': { type: 'boolean' },
        'no-check': { type: 'boolean' },
        'skip-guide': { type: 'boolean' },
        oauth: { type: 'boolean' },
        internal: { type: 'boolean' },
        session: { type: 'boolean' },
        'ssh-host': { type: 'string' },
        'server-login': { type: 'boolean' },
        'reuse-session': { type: 'boolean' },
        'read-all': { type: 'boolean' },
        'allow-write': { type: 'boolean' },
        'allow-modify': { type: 'boolean' },
        'no-sent-copy': { type: 'boolean' },
        write: { type: 'boolean' },
        'drafts-only': { type: 'boolean' },
        'read-only': { type: 'boolean' },
        full: { type: 'boolean' },
        public: { type: 'boolean' },
        private: { type: 'boolean' },
        name: { type: 'string' },
        target: { type: 'string' },
        'no-pair': { type: 'boolean' },
        'private-all': { type: 'boolean' },
        redirect: { type: 'string', multiple: true },
        cimd: { type: 'string' },
        all: { type: 'boolean' },
        accept: { type: 'boolean' },
        json: { type: 'boolean' },
        plain: { type: 'boolean' },
        yes: { type: 'boolean' },
        dir: { type: 'string' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
      },
    });
  } catch {
    io.stderr(`Invalid arguments.\n\n${USAGE}\n`);
    return 2;
  }
  const { values, positionals } = parsed;
  const [cmd, sub, ...rest] = positionals;
  if (values.version) {
    io.stdout(`${PERCH_VERSION}\n`);
    return 0;
  }
  if (values.help || !cmd || cmd === 'help') {
    io.stdout(`${values.all ? FULL_USAGE : (cmd === 'connect' || (cmd === 'help' && sub === 'connect')) ? CONNECT_HELP : USAGE}\n`);
    return 0;
  }
  try {
    if (values['reuse-session'] && (cmd !== 'microsoft' || sub !== 'reconnect' || values['server-login'])) throw new UsageError('--reuse-session is only for microsoft reconnect and cannot be combined with --server-login.');
    const config = resolveConfig(io.env);
    let wantsWrite = false;
    // perch google add asks for its services first and then for the access (in cmdGoogle).
    if (sub === 'add' && WRITE_FLAGS[cmd] && cmd !== 'google' && cmd !== 'microsoft') wantsWrite = await chooseAccess(cmd, values as Record<string, unknown>, io.readLine, io.stderr);
    if (wantsWrite) {
      io.stdout('Requesting the selected permissions. Client grants separately limit read, draft, send and modify access.\n');
    }
    switch (cmd) {
      case 'init':
        await cmdInit(config, io);
        return 0;
      case 'serve':
        return await cmdServe(config, io, values);
      case 'oauth':
        return await cmdOauth(config, io, sub, rest, values);
      case 'luma':
        await cmdLuma(config, io, sub, rest, values);
        return 0;
      case 'x':
        await cmdX(config, io, sub, rest, values);
        return 0;
      case 'public':
        return await cmdPublic(config, io, sub);
      case 'connect':
        return await cmdConnect(config, io, values);
      case 'setup':
        return await runSetup(config, io, (argv) => runCli(argv, io), {
          whatsappConfigured: async () => Boolean((await (await openStore(config)).read()).whatsappInstance),
        });
      case 'status':
        return await cmdStatus(config, io, values);
      case 'accounts':
        io.stdout(formatAccounts(await (await openStore(config)).read(), 'all'));
        return 0;
      case 'rename': {
        if (!sub || rest.length !== 1) throw new UsageError('Usage: perch rename ID "NEW LABEL"   (ID from perch accounts, perch google list or perch client list)');
        const r = await renameRecord(await openStore(config), sub, rest[0]!);
        io.stdout(`Renamed ${r.renamed.join(', ')} to "${r.label}".\n`);
        return 0;
      }
      case 'google':
        await cmdGoogle(config, io, sub, rest, values);
        return 0;
      case 'notion':
        await cmdNotion(config, io, sub, rest, values);
        return 0;
      case 'gmail':
        await cmdGmail(config, io, sub, rest, values);
        return 0;
      case 'microsoft':
        await cmdMicrosoft(config, io, sub, rest, values);
        return 0;
      case 'imap':
        await cmdImap(config, io, sub, rest, values);
        return 0;
      case 'google-productivity':
        await cmdProductivity(config, io, sub, rest, values);
        return 0;
      case 'slack':
        await cmdSlack(config, io, sub, rest, values);
        return 0;
      case 'whatsapp':
        await cmdWhatsapp(config, io, sub, rest, values);
        return 0;
      case 'client':
        await cmdClient(config, io, sub, rest, values);
        return 0;
      case 'token':
        await cmdToken(config, io, sub);
        return 0;
      case 'audit':
        await cmdAudit(config, io, sub, values);
        return 0;
      case 'mail-workflow':
        await cmdMailWorkflow(config, io, sub, rest, values);
        return 0;
      default:
        throw new UsageError(`Unknown command: ${cmd}`);
    }
  } catch (err) {
    if (err instanceof UsageError) {
      io.stderr(`${err.message}\n\n${USAGE}\n`);
      return 2;
    }
    io.stderr(`perch: ${safeMessage(err)}\n`);
    return 1;
  }
}
