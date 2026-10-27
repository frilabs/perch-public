import { MICROSOFT_SESSION_CAPABILITIES, MicrosoftSessionGroupSchema } from '../microsoft/session/model.js';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import { PerchError } from '../errors.js';
import {
  ensurePrivateDir,
  pathExists,
  readPrivateFile,
  writePrivateFileAtomic,
  writePrivateFileExclusive,
} from '../secureFs.js';
import { createLedgerFile } from '../mail/workflowLedger.js';
import { decryptEnvelope, encryptEnvelope, generateKeyFileContents, parseKey } from './crypto.js';
import { withFileLock } from './lock.js';

export const GOOGLE_GROUP_ID_PATTERN = /^ggroup-[a-f0-9]{8}$/;

/**
 * Google account group (docs/GOOGLE_UNIFIED_SPEC.md): ONE Google login shared by the Drive (google-…), Gmail
 * (gmail-…) and Calendar/Contacts (gprod-…) records of the same Google account. The OAuth client and the refresh
 * token live only here (single source of truth); members carry `groupId` instead. `scopes` is everything Google
 * reported for the grant at the last authorization (include_granted_scopes); members record the part they use.
 */
const GoogleAccountGroupSchema = z.object({
  id: z.string().regex(GOOGLE_GROUP_ID_PATTERN),
  label: z.string().min(1).max(100),
  email: z.string().min(3).max(320),
  /** OpenID Connect subject: stable Google account id, used to find the group again on re-add. */
  sub: z.string().min(1).max(255),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  refreshToken: z.string().min(1),
  scopes: z.array(z.string()),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/**
 * Credentials of a Google member record: either its own (accounts connected separately, the only kind before
 * account groups existed) or none plus `groupId` (the group holds them). Optional fields keep older stores valid;
 * StoreDataSchema checks that exactly one of the two forms is used.
 */
const googleCredentialFields = {
  groupId: z.string().regex(GOOGLE_GROUP_ID_PATTERN).optional(),
  clientId: z.string().min(1).optional(),
  clientSecret: z.string().min(1).optional(),
  refreshToken: z.string().min(1).optional(),
};

const GoogleAccountSchema = z.object({
  id: z.string().regex(/^google-[a-f0-9]{8}$/),
  label: z.string().min(1).max(100),
  email: z.string().min(3),
  displayName: z.string().optional(),
  ...googleCredentialFields,
  scopes: z.array(z.string()),
  createdAt: z.string(),
  updatedAt: z.string(),
});

const NotionWorkspaceSchema = z.object({
  id: z.string().regex(/^notion-[a-f0-9]{8}$/),
  label: z.string().min(1).max(100),
  token: z.string().min(1),
  tokenOwner: z
    .object({ id: z.string(), name: z.string().optional(), type: z.string().optional() })
    .optional(),
  /** How the token was obtained: internal integration secret (absent = 'token') or a public integration via OAuth. */
  authMode: z.enum(['token', 'oauth']).optional(),
  /** OAuth only: Notion's workspace_id/workspace_name/bot_id from the token response (same workspace_id = update). */
  oauthWorkspaceId: z.string().min(1).max(100).optional(),
  workspaceName: z.string().max(200).optional(),
  botId: z.string().max(100).optional(),
  /** OAuth with expiring access tokens only: refresh token and the client it belongs to (like Google accounts). */
  clientId: z.string().min(1).max(512).optional(),
  clientSecret: z.string().min(1).max(512).optional(),
  refreshToken: z.string().min(1).optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/** Gmail grant (separate OAuth consent from Drive; default gmail.readonly, opt-in send/compose). */
const GmailAccountSchema = z.object({
  /** Local permission ceiling; gmail.compose itself also permits sending upstream. */
  draftsOnly: z.boolean().optional(),
  id: z.string().regex(/^gmail-[a-f0-9]{8}$/),
  label: z.string().min(1).max(100),
  email: z.string().min(3),
  ...googleCredentialFields,
  scopes: z.array(z.string()),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/** Retired Microsoft OAuth grant: readable for migration/explicit removal, never used by runtime. */
const MicrosoftAccountSchema = z.object({
  id: z.string().regex(/^microsoft-[a-f0-9]{8}$/),
  label: z.string().min(1).max(100),
  email: z.string().min(3),
  displayName: z.string().optional(),
  tenant: z.string().min(1).max(100),
  clientId: z.string().min(1),
  refreshToken: z.string().min(1),
  scopes: z.array(z.string()),
  createdAt: z.string(),
  updatedAt: z.string(),
});

const HostPortSchema = z.object({ host: z.string().min(1).max(253), port: z.number().int().min(1).max(65535) });

/** Generic IMAP (implicit TLS) + SMTP account, e.g. GMX. The password is stored encrypted like every other secret. */
const ImapAccountSchema = z.object({
  id: z.string().regex(/^imap-[a-f0-9]{8}$/),
  label: z.string().min(1).max(100),
  email: z.string().min(3),
  username: z.string().min(1),
  password: z.string().min(1),
  preset: z.string().optional(),
  imap: HostPortSchema,
  smtp: HostPortSchema.extend({ security: z.enum(['tls', 'starttls']) }),
  /** IMAP has no OAuth scopes: drafts/send are explicit opt-ins recorded at onboarding. */
  allowDrafts: z.boolean(),
  allowSend: z.boolean(),
  /**
   * Organizing (flags, move/archive, trash/restore) is a separate opt-in. Optional so that stores written before it
   * existed stay valid; absent means false (never inferred from allowDrafts/allowSend).
   */
  allowModify: z.boolean().optional(),
  draftsMailbox: z.string().optional(),
  /**
   * File a copy of every accepted SMTP send in the IMAP Sent folder. Optional so older stores stay valid; absent
   * means "on, unless the SMTP server files sent mail itself" (see imapSentCopyEnabled in src/mail/imap.ts).
   * `perch imap add --no-sent-copy` stores false.
   */
  sentCopy: z.boolean().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/**
 * Google Calendar/Contacts grant (separate OAuth consent from Drive and Gmail). `services` and
 * `allowCalendarWrite` record what was requested at onboarding; `scopes` what Google actually granted.
 * Both must agree before a tool runs (see src/google/productivity.ts).
 */
const GoogleProductivityAccountSchema = z.object({
  id: z.string().regex(/^gprod-[a-f0-9]{8}$/),
  label: z.string().min(1).max(100),
  email: z.string().min(3).max(320),
  /** OpenID Connect subject: stable Google account id, used to detect duplicate grants. */
  sub: z.string().min(1).max(255),
  ...googleCredentialFields,
  scopes: z.array(z.string()),
  services: z.array(z.enum(['calendar', 'contacts'])).min(1),
  allowCalendarWrite: z.boolean(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/**
 * Slack workspace connected with a user token (xoxp-…) of an internal app installed in that workspace
 * (docs/slack-app-manifest.json). `scopes` are what Slack reported for the token at onboarding.
 *
 * Session mode (docs/SLACK_SESSION_NOTION_GUIDE_SPEC.md §1, unofficial): `authMode: 'session'`, `token` is the
 * browser session token (xoxc-…) and `sessionCookie` the value of the browser cookie `d` (xoxd-…, URL-encoded
 * as the browser sends it). Session tokens report no scopes (`scopes` stays empty and is not checked).
 * Records without `authMode` are app workspaces.
 */
const SlackWorkspaceSchema = z
  .object({
    id: z.string().regex(/^slack-[a-f0-9]{8}$/),
    label: z.string().min(1).max(100),
    token: z.string().min(1),
    teamId: z.string().regex(/^[TE][A-Z0-9]{2,30}$/),
    teamName: z.string().max(200).optional(),
    teamUrl: z.string().max(500).optional(),
    userId: z.string().regex(/^[UW][A-Z0-9]{2,30}$/),
    userName: z.string().max(200).optional(),
    scopes: z.array(z.string().max(100)),
    authMode: z.enum(['app', 'session']).optional(),
    sessionCookie: z.string().min(1).max(4096).optional(),
    createdAt: z.string(),
    updatedAt: z.string(),
  })
  .refine((w) => (w.authMode === 'session') === (w.sessionCookie !== undefined), 'a Slack session workspace needs its cookie (and only it)');

/** The namespace's GOWA instance (self-hosted WhatsApp bridge). Basic-auth credentials are stored encrypted. */
const WhatsappInstanceSchema = z.object({
  origin: z.string().min(1).max(200),
  username: z.string().min(1).max(200),
  password: z.string().min(1).max(500),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/** One WhatsApp account = one GOWA device slot created and paired by Perch (`perch-` + 16 hex). */
const WhatsappAccountSchema = z.object({
  id: z.string().regex(/^whatsapp-[a-f0-9]{8}$/),
  label: z.string().min(1).max(100),
  deviceId: z.string().regex(/^perch-[a-f0-9]{16}$/),
  /** Own JID reported by GOWA after pairing, e.g. 4366012345678@s.whatsapp.net. */
  jid: z.string().max(200).optional(),
  displayName: z.string().max(200).optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/** Approved Luma tool (trust on first use): its JSON input schema as Perch exposes it and a structural hash. */
const LumaToolSnapshotSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/),
  hash: z.string().regex(/^[a-f0-9]{64}$/),
  schema: z.record(z.string(), z.unknown()),
  /** Luma's description of the tool (documentation only, not part of the hash). */
  description: z.string().max(4000).optional(),
});

/**
 * Luma account connected to the official Luma MCP server (https://mcp.luma.com) with OAuth (docs/LUMA_SPEC.md).
 * The authorization server endpoints come from Luma's metadata at onboarding (Luma hosts only). `tools` are the
 * approved tool schemas; a changed schema is blocked until the operator accepts it (perch luma tools --accept).
 */
const LumaAccountSchema = z.object({
  id: z.string().regex(/^luma-[a-f0-9]{8}$/),
  label: z.string().min(1).max(100),
  userId: z.string().max(200).optional(),
  name: z.string().max(200).optional(),
  email: z.string().max(254).optional(),
  clientId: z.string().min(1).max(512),
  registration: z.enum(['cimd', 'dcr']),
  issuer: z.string().max(500),
  tokenEndpoint: z.string().max(500),
  revocationEndpoint: z.string().max(500).optional(),
  /** RFC 8707 resource value announced by Luma's protected resource metadata. */
  resource: z.string().max(200).optional(),
  refreshToken: z.string().min(1),
  scopes: z.array(z.string().max(200)).max(50),
  tools: z.array(LumaToolSnapshotSchema).max(100),
  toolsApprovedAt: z.string(),
  createdAt: z.string(),
  updatedAt: z.string(),
});


/**
 * X account (docs/X_SPEC.md): OAuth 2.0 Authorization Code with PKCE through the operator's X developer app
 * (public client, or confidential with `clientSecret`). Refresh tokens rotate on every refresh (persisted by the
 * token provider). `userId`/`username` come from GET /2/users/me; re-adding the same X user updates this record.
 */
const XAccountSchema = z.object({
  id: z.string().regex(/^x-[a-f0-9]{8}$/),
  label: z.string().min(1).max(100),
  userId: z.string().regex(/^[0-9]{1,25}$/),
  username: z.string().regex(/^[A-Za-z0-9_]{1,50}$/),
  name: z.string().max(200).optional(),
  clientId: z.string().min(1).max(512),
  clientSecret: z.string().min(1).max(512).optional(),
  refreshToken: z.string().min(1).max(4096),
  scopes: z.array(z.string().max(100)).max(50),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/** Mail capabilities (email milestone) apply to mail accounts only. */
export const MAIL_CAPABILITIES = ['read', 'draft', 'send', 'modify'] as const;
/**
 * Calendar/Contacts capabilities apply to Google productivity accounts (gprod-…) only. calendar_invite:
 * writes that add/change guests or notify them (invitations, updates, cancellations, responses).
 */
export const PRODUCTIVITY_CAPABILITIES = ['calendar_read', 'calendar_write', 'calendar_invite', 'contacts_read'] as const;
/** Slack capabilities apply to Slack workspaces (slack-…) only. */
export const SLACK_CAPABILITIES = ['slack_read', 'slack_send'] as const;
/** WhatsApp capabilities apply to WhatsApp accounts (whatsapp-…) only. */
export const WHATSAPP_CAPABILITIES = ['whatsapp_read', 'whatsapp_send'] as const;
/** Luma capabilities apply to Luma accounts (luma-…) only (docs/LUMA_SPEC.md §5). */
export const LUMA_CAPABILITIES = ['luma_read', 'luma_events', 'luma_guests', 'luma_blast'] as const;
/** Google Drive capabilities apply to Drive accounts (google-…) only. */
export const DRIVE_CAPABILITIES = ['drive_read', 'drive_write'] as const;
/** Notion capabilities apply to Notion workspaces (notion-…) only. */
export const NOTION_CAPABILITIES = ['notion_read', 'notion_write'] as const;
/** X capabilities apply to X accounts (x-…) only (docs/X_SPEC.md). */
export const X_CAPABILITIES = ['x_read', 'x_post'] as const;
export const CAPABILITIES = [
  ...MAIL_CAPABILITIES,
  ...PRODUCTIVITY_CAPABILITIES,
  ...SLACK_CAPABILITIES,
  ...WHATSAPP_CAPABILITIES,
  ...LUMA_CAPABILITIES,
  ...DRIVE_CAPABILITIES,
  ...NOTION_CAPABILITIES,
  ...X_CAPABILITIES,
  ...MICROSOFT_SESSION_CAPABILITIES,
] as const;

/** Local per-client grant. Only the SHA-256 of the (high-entropy) client token is stored. */
const ClientGrantSchema = z.object({
  id: z.string().regex(/^client-[a-f0-9]{8}$/),
  label: z.string().min(1).max(100),
  tokenSha256: z.string().regex(/^[a-f0-9]{64}$/),
  capabilities: z.array(z.enum(CAPABILITIES)).min(1),
  accountIds: z.array(z.string()),
  /**
   * Full access: every capability on every account, including accounts and capabilities added later
   * (perch client add --full). `capabilities`/`accountIds` are then only a snapshot for display.
   */
  full: z.literal(true).optional(),
  /**
   * Read-only access on every account, including accounts added later (perch client add --read-all, perch
   * connect for an agent on the server): the read capabilities of the global token, but its own revocable
   * token. `accountIds` is only a snapshot (older Perch versions read it as a narrower read grant).
   */
  readAll: z.literal(true).optional(),
  createdAt: z.string(),
}).refine((g) => g.full === true || g.readAll === true || g.accountIds.length > 0, 'a client grant needs at least one account id');

/** Upper bound on registry entries (active and removed: ids are never reused, entries never deleted). */
export const MAX_USERS = 100;
export const USER_ID_PATTERN = /^user-[a-f0-9]{16}$/;
/** Namespace of the legacy store at the configured data dir: the local operator. */
export const ROOT_NAMESPACE = 'root';

/**
 * Admin-provisioned user, written by the removed user-isolation milestone. Still parsed so existing stores
 * open unchanged (schema v1), but ignored: Perch serves one operator per installation, and these users'
 * tokens are rejected. Their separate stores and keys are never opened or deleted.
 */
const UserSchema = z.object({
  id: z.string().regex(USER_ID_PATTERN),
  label: z.string().min(1).max(100),
  status: z.enum(['active', 'removed']),
  readTokenSha256: z.string().regex(/^[a-f0-9]{64}$/),
  createdAt: z.string(),
  removedAt: z.string().optional(),
});

const StoreDataSchema = z.object({
  version: z.literal(1),
  google: z.array(GoogleAccountSchema),
  notion: z.array(NotionWorkspaceSchema),
  // Added by the email milestone; stores written earlier have no such keys.
  gmail: z.array(GmailAccountSchema).default([]),
  microsoft: z.array(MicrosoftAccountSchema).default([]),
  microsoftSessions: z.array(MicrosoftSessionGroupSchema).optional(),
  imap: z.array(ImapAccountSchema).default([]),
  clients: z.preprocess((raw) => {
    if (!Array.isArray(raw)) return raw;
    return raw.flatMap((grant) => {
      if (!grant || typeof grant !== 'object') return [grant];
      const g = grant as Record<string, unknown>;
      if (!Array.isArray(g.capabilities) || !Array.isArray(g.accountIds)) return [grant];
      const capabilities = g.capabilities.filter(c => c !== 'linkedin_read' && c !== 'linkedin_post');
      const accountIds = g.accountIds.filter(id => typeof id !== 'string' || !id.startsWith('linkedin-'));
      // Removed-connector-only tokens are revoked, including malformed empty legacy grants.
      if (capabilities.length !== g.capabilities.length || accountIds.length !== g.accountIds.length) {
        if (!capabilities.length || (!accountIds.length && g.full !== true && g.readAll !== true)) return [];
        return [{ ...g, capabilities, accountIds }];
      }
      return [grant];
    });
  }, z.array(ClientGrantSchema).default([])),
  // Added by the Google productivity milestone.
  googleProductivity: z.array(GoogleProductivityAccountSchema).default([]),
  // Added by the removed user-isolation milestone; parsed for compatibility, otherwise ignored.
  users: z
    .array(UserSchema)
    .max(MAX_USERS)
    .default([])
    .refine((users) => new Set(users.map((u) => u.id)).size === users.length, 'duplicate user id'),
  // Added by the mail workflow milestone: set once this namespace's mail-workflow.enc exists. A missing
  // ledger with this marker was lost (restore from backup); it is never initialised again.
  mailWorkflowLedger: z.strictObject({ createdAt: z.string() }).optional(),
  // Added by the Slack/WhatsApp milestone.
  slack: z.array(SlackWorkspaceSchema).default([]),
  whatsappInstance: WhatsappInstanceSchema.optional(),
  whatsapp: z.array(WhatsappAccountSchema).default([]),
  // Added by the Luma milestone.
  luma: z.array(LumaAccountSchema).default([]),
  // Added by the unified Google onboarding (docs/GOOGLE_UNIFIED_SPEC.md).
  googleGroups: z.array(GoogleAccountGroupSchema).default([]),
  // Removed connector: retain encrypted records, never expose or use their credentials.
  linkedin: z.array(z.unknown()).optional(),
  // Added by the X connector (docs/X_SPEC.md).
  x: z.array(XAccountSchema).default([]),
}).superRefine((d, ctx) => {
  const msIds = (d.microsoftSessions ?? []).flatMap(g => [g.id, ...Object.values(g.members)]);
  if (new Set(msIds).size !== msIds.length) ctx.addIssue({code: 'custom', message: 'duplicate Microsoft session or member id'});
  const profiles = (d.microsoftSessions ?? []).map(g => g.profileId);
  if (new Set(profiles).size !== profiles.length) ctx.addIssue({code: 'custom', message: 'duplicate Microsoft browser profile'});
  const groups = new Set(d.googleGroups.map((g) => g.id));
  if (groups.size !== d.googleGroups.length) ctx.addIssue({ code: 'custom', message: 'duplicate Google account group id' });
  for (const [family, list] of [['google', d.google], ['gmail', d.gmail], ['googleProductivity', d.googleProductivity]] as const) {
    const seen = new Set<string>();
    for (const a of list as ReadonlyArray<{ id: string; groupId?: string; clientId?: string; clientSecret?: string; refreshToken?: string }>) {
      if (a.groupId) {
        // Single source of truth: a group member never carries its own credentials.
        if (!groups.has(a.groupId)) ctx.addIssue({ code: 'custom', message: `${a.id} belongs to an unknown Google account group` });
        if (a.clientId || a.clientSecret || a.refreshToken) ctx.addIssue({ code: 'custom', message: `${a.id} is a group member but stores its own credentials` });
        if (seen.has(a.groupId)) ctx.addIssue({ code: 'custom', message: `two ${family} records in one Google account group` });
        seen.add(a.groupId);
      } else if (!a.clientId || !a.clientSecret || !a.refreshToken) {
        ctx.addIssue({ code: 'custom', message: `${a.id} has no credentials` });
      }
    }
  }
});

export type GoogleAccount = z.infer<typeof GoogleAccountSchema>;
export type GoogleAccountGroup = z.infer<typeof GoogleAccountGroupSchema>;
export type NotionWorkspace = z.infer<typeof NotionWorkspaceSchema>;
export type GmailAccount = z.infer<typeof GmailAccountSchema>;
export type MicrosoftAccount = z.infer<typeof MicrosoftAccountSchema>;
export type ImapAccount = z.infer<typeof ImapAccountSchema>;
export type GoogleProductivityAccount = z.infer<typeof GoogleProductivityAccountSchema>;
export type ClientGrant = z.infer<typeof ClientGrantSchema>;
export type SlackWorkspace = z.infer<typeof SlackWorkspaceSchema>;
export type WhatsappInstance = z.infer<typeof WhatsappInstanceSchema>;
export type WhatsappAccount = z.infer<typeof WhatsappAccountSchema>;
export type SlackCapability = (typeof SLACK_CAPABILITIES)[number];
export type WhatsappCapability = (typeof WHATSAPP_CAPABILITIES)[number];
export type LumaCapability = (typeof LUMA_CAPABILITIES)[number];
export type DriveCapability = (typeof DRIVE_CAPABILITIES)[number];
export type NotionCapability = (typeof NOTION_CAPABILITIES)[number];
export type XCapability = (typeof X_CAPABILITIES)[number];
export type XAccount = z.infer<typeof XAccountSchema>;
export type LumaAccount = z.infer<typeof LumaAccountSchema>;
export type LumaToolSnapshot = z.infer<typeof LumaToolSnapshotSchema>;
export type UserRecord = z.infer<typeof UserSchema>;
export type Capability = (typeof CAPABILITIES)[number];
export type MailCapability = (typeof MAIL_CAPABILITIES)[number];
export type ProductivityCapability = (typeof PRODUCTIVITY_CAPABILITIES)[number];
export type StoreData = z.infer<typeof StoreDataSchema>;

export interface StorePaths {
  dataDir: string;
  keyFile: string;
}

export const storeFilePath = (dataDir: string) => path.join(dataDir, 'store.enc');
const lockFilePath = (dataDir: string) => path.join(dataDir, 'store.lock');

const emptyData = (): StoreData => ({
  version: 1,
  google: [],
  notion: [],
  gmail: [],
  microsoft: [],
  microsoftSessions: [],
  imap: [],
  clients: [],
  googleProductivity: [],
  users: [],
  slack: [],
  whatsapp: [],
  luma: [],
  googleGroups: [],
  x: [],
  // initStore creates the ledger before the store, so a new store is born with it.
  mailWorkflowLedger: { createdAt: new Date().toISOString() },
});

async function realpathOrResolve(p: string): Promise<string> {
  // Resolve the deepest existing ancestor so symlinked parents cannot hide containment.
  const abs = path.resolve(p);
  const rest: string[] = [];
  let cur = abs;
  for (;;) {
    try {
      return path.join(await realpath(cur), ...rest);
    } catch {
      const parent = path.dirname(cur);
      if (parent === cur) return abs;
      rest.unshift(path.basename(cur));
      cur = parent;
    }
  }
}

/** True if `inner` is `outer` or lies below it (after resolving symlinked ancestors). */
export async function isWithin(outer: string, inner: string): Promise<boolean> {
  const rel = path.relative(await realpathOrResolve(outer), await realpathOrResolve(inner));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

async function assertKeyOutsideDataDir(paths: StorePaths): Promise<void> {
  if (await isWithin(paths.dataDir, paths.keyFile)) {
    throw new PerchError('The key file must live outside the data directory (set PERCH_KEY_FILE)', 'insecure_path');
  }
}

function parseData(plain: Buffer): StoreData {
  const parsed = StoreDataSchema.safeParse(JSON.parse(plain.toString('utf8')));
  if (!parsed.success) throw new PerchError('Credential store content does not match the expected schema', 'store_schema');
  return parsed.data;
}

function serialise(key: Buffer, data: StoreData): Buffer {
  const parsed = StoreDataSchema.safeParse(data);
  if (!parsed.success) throw new PerchError('Refusing to write data that does not match the store schema', 'store_schema');
  return Buffer.from(encryptEnvelope(key, Buffer.from(JSON.stringify(parsed.data))));
}

/**
 * Explicit initialisation (`perch init`). Creates whatever is missing, but never generates
 * a new key when an encrypted store already exists (that would orphan the stored credentials).
 * A newly created store also gets its empty mail workflow ledger (`mail-workflow.enc`, bound to
 * `opts.namespace`, default root). An existing store never gets a ledger implicitly: a missing ledger
 * next to an existing store fails closed until restored or explicitly initialised.
 */
export async function initStore(paths: StorePaths, opts: { namespace?: string } = {}): Promise<{ createdKey: boolean; createdStore: boolean }> {
  await assertKeyOutsideDataDir(paths);
  await ensurePrivateDir(paths.dataDir);
  await ensurePrivateDir(path.dirname(paths.keyFile));
  const storeFile = storeFilePath(paths.dataDir);
  // The whole check-and-create runs under the store lock; key and store are additionally
  // created with no-overwrite semantics, so concurrent inits always agree on one key.
  return withFileLock(lockFilePath(paths.dataDir), async () => {
    const hasStore = await pathExists(storeFile);
    if (hasStore && !(await pathExists(paths.keyFile))) {
      throw new PerchError(
        `Key file is missing (${paths.keyFile}) but an encrypted store exists. Restore the key from backup; ` +
          'Perch will not generate a new key over existing data.',
        'key_missing',
      );
    }
    const createdKey = hasStore ? false : await writePrivateFileExclusive(paths.keyFile, generateKeyFileContents());
    const key = parseKey(await readPrivateFile(paths.keyFile));
    let createdStore = false;
    if (hasStore) {
      parseData(decryptEnvelope(key, (await readPrivateFile(storeFile)).toString('utf8')));
    } else {
      // Ledger first: a store without its ledger would make every audited call fail closed.
      await createLedgerFile(paths.dataDir, key, opts.namespace ?? ROOT_NAMESPACE);
      createdStore = await writePrivateFileExclusive(storeFile, serialise(key, emptyData()));
      if (!createdStore) parseData(decryptEnvelope(key, (await readPrivateFile(storeFile)).toString('utf8')));
    }
    return { createdKey, createdStore };
  });
}

/**
 * Opaque pagination cursors are sealed with a MAC keyed per store (namespace): a cursor issued by one
 * namespace, or for another query kind/account/parent, or edited by the caller, is rejected before any
 * provider request. Format: base64url(payload) "~" base64url(HMAC-SHA256 truncated to 128 bits).
 */
export interface CursorSeal {
  sealCursor(kind: string, payload: string): string;
  openCursor(kind: string, cursor: string): string;
}

const CURSOR_MAC_CHARS = 22;
const badCursor = () => new PerchError('Invalid cursor: it does not belong to this query, account or connection; repeat the same arguments', 'bad_cursor');

interface CacheStamp {
  ino: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
}

export class CredentialStore implements CursorSeal {
  private cache: { stamp: CacheStamp; data: StoreData } | null = null;
  private queue: Promise<unknown> = Promise.resolve();
  private readonly cursorKey: Buffer;

  private constructor(
    private readonly paths: StorePaths,
    private readonly key: Buffer,
    /** 'root' for the operator store, otherwise the owning user id. Never derived from caller input. */
    readonly namespace: string,
  ) {
    this.cursorKey = createHmac('sha256', key).update(`perch-cursor-v1\u0000${namespace}`).digest();
  }

  get storePaths(): StorePaths {
    return { ...this.paths };
  }

  /**
   * Opens an initialised store. Never creates keys or files. `namespace` is set by the caller that chose
   * the paths (root for the configured store, the user id for a provisioned user's store).
   */
  static async open(paths: StorePaths, opts: { namespace?: string } = {}): Promise<CredentialStore> {
    await assertKeyOutsideDataDir(paths);
    const storeFile = storeFilePath(paths.dataDir);
    const hasStore = await pathExists(storeFile);
    const hasKey = await pathExists(paths.keyFile);
    if (hasStore && !hasKey) {
      throw new PerchError(
        `Key file is missing (${paths.keyFile}) but an encrypted store exists. Restore the key from backup.`,
        'key_missing',
      );
    }
    if (!hasStore || !hasKey) throw new PerchError('Perch is not initialised. Run: perch init', 'not_initialised');
    const dirStat = await lstat(paths.dataDir);
    if (dirStat.isSymbolicLink()) throw new PerchError(`Refusing symlinked directory: ${paths.dataDir}`, 'insecure_path');
    const store = new CredentialStore(paths, parseKey(await readPrivateFile(paths.keyFile)), opts.namespace ?? ROOT_NAMESPACE);
    await store.read();
    return store;
  }

  /** Fails closed if the key file was removed, replaced or made insecure since the store was opened. */
  async assertKeyUnchanged(): Promise<void> {
    let current: Buffer;
    try {
      current = parseKey(await readPrivateFile(this.paths.keyFile));
    } catch (err) {
      if (err instanceof PerchError && err.code === 'not_found') {
        throw new PerchError(`Key file is missing (${this.paths.keyFile}). Restore the key from backup.`, 'key_missing');
      }
      throw err;
    }
    if (current.length !== this.key.length || !timingSafeEqual(current, this.key)) {
      throw new PerchError(`Key file ${this.paths.keyFile} changed since the store was opened; refusing to continue`, 'wrong_key');
    }
  }

  private cursorMac(kind: string, body: string): string {
    return createHmac('sha256', this.cursorKey).update(`${kind}\u0000${body}`).digest('base64url').slice(0, CURSOR_MAC_CHARS);
  }

  sealCursor(kind: string, payload: string): string {
    const body = Buffer.from(payload, 'utf8').toString('base64url');
    return `${body}~${this.cursorMac(kind, body)}`;
  }

  openCursor(kind: string, cursor: string): string {
    const m = /^([A-Za-z0-9_-]{1,32768})~([A-Za-z0-9_-]{22})$/.exec(cursor);
    if (!m) throw badCursor();
    const expected = Buffer.from(this.cursorMac(kind, m[1]!));
    if (!timingSafeEqual(expected, Buffer.from(m[2]!))) throw badCursor();
    return Buffer.from(m[1]!, 'base64url').toString('utf8');
  }

  /** Returns current data, re-decrypting only when the file on disk changed. */
  async read(): Promise<StoreData> {
    const file = storeFilePath(this.paths.dataDir);
    let st;
    try {
      st = await lstat(file);
    } catch {
      throw new PerchError('Credential store file disappeared. Run: perch init', 'not_initialised');
    }
    const stamp: CacheStamp = { ino: st.ino, size: st.size, mtimeMs: st.mtimeMs, ctimeMs: st.ctimeMs };
    const c = this.cache;
    if (
      c &&
      c.stamp.ino === stamp.ino &&
      c.stamp.size === stamp.size &&
      c.stamp.mtimeMs === stamp.mtimeMs &&
      c.stamp.ctimeMs === stamp.ctimeMs
    ) {
      return structuredClone(c.data);
    }
    const data = parseData(decryptEnvelope(this.key, (await readPrivateFile(file)).toString('utf8')));
    this.cache = { stamp, data };
    return structuredClone(data);
  }

  /** Read-modify-write under an in-process queue and a cross-process file lock. */
  update<T>(mutate: (data: StoreData) => T | Promise<T>): Promise<T> {
    const run = async () =>
      withFileLock(lockFilePath(this.paths.dataDir), async () => {
        this.cache = null;
        const data = await this.read();
        const result = await mutate(data);
        await writePrivateFileAtomic(storeFilePath(this.paths.dataDir), serialise(this.key, data));
        this.cache = null;
        return result;
      });
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => {});
    return p;
  }
}
