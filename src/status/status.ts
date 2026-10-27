import { PerchError, safeMessage } from '../errors.js';
import type { PerchContext } from '../context.js';
import { fetchDriveIdentity } from '../google/accounts.js';
import { groupServices } from '../google/groupStore.js';
import { fetchVerifiedIdentity } from '../google/productivity.js';
import { fetchGmailIdentity } from '../mail/gmailAccounts.js';
import { verifyImapAccount } from '../mail/imapAccounts.js';
import { MAX_SEND_RECORDS, MailWorkflowLedger } from '../mail/workflowLedger.js';
import { NOTION_VERSION } from '../notion/notion.js';
import { isSlackAuthFailure, isSlackSession, SLACK_USER_SCOPES, slackAuth, slackSessionAddCommand, slackSessionExpired } from '../slack/slack.js';
import { ROOT_NAMESPACE, type ImapAccount, type StoreData } from '../store/credentialStore.js';
import { expireDevices, isPublicLocked, OAuthStore } from '../access/state.js';
import { PERCH_VERSION } from '../version.js';
import { MICROSOFT_SERVICES, type MicrosoftService, type MicrosoftSessionGroup } from '../microsoft/session/model.js';

/**
 * Read-only overview of one namespace: connected accounts (labels, ids, identities, granted provider
 * permissions; never tokens, passwords or scopes' secrets), client grants, the WhatsApp bridge, the send
 * ledger fill level and, optionally, a live check per account. Live checks only call identity endpoints
 * that every grant already allows (Drive about, Gmail profile, Google userinfo, Notion
 * users/me, Slack auth.test, an IMAP/SMTP login, the GOWA device status) through the namespace's own
 * token providers, so refresh-token rotation never races with the running server.
 */

export type AccountFamily = 'drive' | 'notion' | 'mail' | 'calendar' | 'slack' | 'whatsapp' | 'luma' | 'x' | 'microsoft_session';

export const FAMILY_TITLES: Record<AccountFamily, string> = {
  drive: 'Google Drive',
  notion: 'Notion',
  mail: 'Mail',
  calendar: 'Google Calendar/Contacts',
  slack: 'Slack',
  whatsapp: 'WhatsApp',
  luma: 'Luma',
  x: 'X',
  microsoft_session: 'Microsoft browser session',
};

export interface CheckResult {
  state: 'ok' | 'error' | 'skipped';
  /** Sanitised message (PerchError text only). */
  message?: string;
  ms?: number;
}

export interface AccountStatus {
  family: AccountFamily;
  id: string;
  label: string;
  provider: string;
  /** Email, workspace/team or WhatsApp number as stored at onboarding. */
  identity?: string;
  /** Provider permissions in plain words, e.g. "read, send". */
  permissions: string;
  connectedAt: string;
  /** Non-fatal advice, e.g. scopes of the current manifest that the stored token lacks. */
  hint?: string;
  /** Google account group (one shared login) this account belongs to. */
  groupId?: string;
  /** Microsoft group membership is separate from the legacy Google grouping. */
  microsoftGroupId?: string;
  sessionService?: MicrosoftService;
  /** Logins with a fixed lifetime: connected until, and whether that is soon (7 days) or over. */
  expiresAt?: string;
  expiry?: 'ok' | 'soon' | 'expired';
  /** Command that renews such a login (soon or expired). */
  renew?: string;
  check?: CheckResult;
}

/** A Google account group: one login shared by its Drive, Gmail and Calendar/Contacts accounts. */
export interface GoogleGroupStatus {
  id: string;
  label: string;
  email: string;
  /** Connected services in canonical order (drive, gmail, calendar, contacts). */
  services: string[];
  /** Member account ids (google-…, gmail-…, gprod-…). */
  accountIds: string[];
  connectedAt: string;
}

export interface MicrosoftGroupStatus {
  id: string; label: string; email: string; connectedAt: string;
  /** Stored probe state only; collectStatus never launches the session browser. */
  services: Array<{
    service: MicrosoftService; accountId: string; enabled: boolean; write: boolean; invite: boolean;
    status: MicrosoftSessionGroup['services']['teams']['status']; checkedAt?: string;
  }>;
}

export interface StatusReport {
  generatedAt: string;
  version: string;
  namespace: string;
  checked: boolean;
  accounts: AccountStatus[];
  /** Google account groups; their members are in `accounts` with `groupId`. */
  googleGroups: GoogleGroupStatus[];
  /** Optional for compatibility with older callers constructing reports. */
  microsoftGroups?: MicrosoftGroupStatus[];
  clients: Array<{ id: string; label: string; capabilities: string[]; accountIds: string[]; full?: boolean; readAll?: boolean; createdAt: string }>;
  whatsappBridge?: { origin: string; configuredAt: string };
  ledger: { sends: number; maxSends: number; pending: number; auditEvents: number; auditDropped: number; lastActivityAt?: string } | { error: string };
  /** Public access (OAuth): never tokens or codes. */
  publicAccess:
    | { state: 'not_set_up' | 'on' | 'off'; totp: boolean; allowedAccounts: number; activeDevices: number; lastPairedAt?: string; pairingOpen?: boolean }
    | { error: string };
}

export const CHECK_TIMEOUT_MS = 20_000;
const CHECK_CONCURRENCY = 6;

const short = (scope: string) => scope.replace(/^https:\/\/www\.googleapis\.com\/auth\//, '');

function accountsOf(d: StoreData): AccountStatus[] {
  const rows: AccountStatus[] = [];
  const group = (a: { groupId?: string }) => (a.groupId ? { groupId: a.groupId } : {});
  for (const a of d.google) {
    rows.push({ family: 'drive', id: a.id, label: a.label, provider: 'google', identity: a.email, permissions: a.scopes.includes('https://www.googleapis.com/auth/drive') ? 'read, write' : 'read', connectedAt: a.createdAt, ...group(a) });
  }
  for (const w of d.notion) {
    rows.push({ family: 'notion', id: w.id, label: w.label, provider: 'notion', ...(w.tokenOwner?.name ? { identity: w.tokenOwner.name } : {}), permissions: 'read', connectedAt: w.createdAt });
  }
  for (const a of d.gmail) {
    const p = ['read', ...(a.scopes.some((s) => s.endsWith('gmail.compose')) ? ['draft'] : []), ...(!a.draftsOnly && a.scopes.some((s) => s.endsWith('gmail.send') || s.endsWith('gmail.compose')) ? ['send'] : [])];
    rows.push({ family: 'mail', id: a.id, label: a.label, provider: 'gmail', identity: a.email, permissions: p.join(', '), connectedAt: a.createdAt, ...group(a) });
  }
  for (const a of d.imap) {
    const p = ['read', ...(a.allowDrafts ? ['draft'] : []), ...(a.allowSend ? ['send'] : [])];
    rows.push({ family: 'mail', id: a.id, label: a.label, provider: a.preset ? `imap (${a.preset})` : 'imap', identity: a.email, permissions: p.join(', '), connectedAt: a.createdAt });
  }
  for (const a of d.googleProductivity) {
    const p = [...a.services.map((s) => `${s} read`), ...(a.allowCalendarWrite ? ['calendar write'] : [])];
    rows.push({ family: 'calendar', id: a.id, label: a.label, provider: 'google', identity: a.email, permissions: p.join(', '), connectedAt: a.createdAt, ...group(a) });
  }
  for (const w of d.slack) {
    // Session workspaces (unofficial) report no scopes: nothing to check, Slack decides per call.
    const session = isSlackSession(w);
    const has = (s: string) => session || w.scopes.includes(s);
    const p = ['read', ...(has('search:read') ? ['search'] : []), ...(has('chat:write') ? ['post'] : []), ...(has('im:write') || has('mpim:write') ? ['open dm'] : [])];
    // Scopes as Slack reported them at connect time (x-oauth-scopes); a missing one is a hint, not a failure.
    const missing = SLACK_USER_SCOPES.filter((s) => !has(s));
    rows.push({
      family: 'slack',
      id: w.id,
      label: w.label,
      provider: 'slack',
      identity: [w.teamName ?? w.teamId, w.userName].filter(Boolean).join(' / '),
      permissions: p.join(', '),
      connectedAt: w.createdAt,
      ...(session
        ? { hint: `session (unofficial); reconnect when expired: ${slackSessionAddCommand(w.label)}` }
        : missing.length
          ? { hint: `token lacks ${missing.join(', ')}; reconnect: ${slackSessionAddCommand(w.label)}` }
          : {}),
    });
  }
  for (const a of d.whatsapp) {
    const number = a.jid?.split('@')[0]?.split(':')[0];
    rows.push({ family: 'whatsapp', id: a.id, label: a.label, provider: 'gowa', ...(number ? { identity: `+${number}` } : {}), permissions: 'read, send', connectedAt: a.createdAt });
  }
  for (const a of d.luma) {
    const ident = a.email ?? a.name;
    rows.push({ family: 'luma', id: a.id, label: a.label, provider: 'luma-mcp', ...(ident ? { identity: ident } : {}), permissions: `${a.tools.length} tools approved`, connectedAt: a.createdAt });
  }
  for (const a of d.x) {
    rows.push({ family: 'x', id: a.id, label: a.label, provider: 'x', identity: `@${a.username}`, permissions: a.scopes.includes('tweet.write') ? 'read, post' : 'read', connectedAt: a.createdAt });
  }
  for (const group of d.microsoftSessions ?? []) {
    for (const service of MICROSOFT_SERVICES) {
      const access = group.services[service];
      if (!access.enabled) continue;
      const permissions = ['read', ...(access.write ? service === 'mail' ? access.draftsOnly ? ['draft'] : ['draft', 'send', 'modify'] : service === 'teams' ? ['send'] : ['write'] : []), ...(service === 'calendar' && access.write && access.invite ? ['invite'] : [])];
      rows.push({ family: 'microsoft_session', id: group.members[service], label: `${group.label} · ${service}`, provider: `microsoft-session-${service}`, identity: group.email,
        permissions: permissions.join(', '), connectedAt: group.createdAt, microsoftGroupId: group.id, sessionService: service,
        check: { state: 'skipped', message: `Stored last probe: ${access.status}${access.checkedAt ? ` at ${access.checkedAt}` : ' (never checked)'}. Run perch microsoft doctor ${group.id} for a fresh check.` } });
    }
  }
  return rows;
}

export interface StatusOptions {
  /** Run a live check per account (default true). */
  live?: boolean;
  /** Tests inject a MOCK IMAP/SMTP login check; production logs in to the real servers over TLS. */
  imapVerify?: (account: ImapAccount) => Promise<void>;
  timeoutMs?: number;
  /** Set by a server running the public access: whether a pairing window is open right now. */
  pairingOpen?: () => boolean;
}

async function publicAccessStatus(ctx: PerchContext, opts: StatusOptions): Promise<StatusReport['publicAccess']> {
  try {
    const s = await new OAuthStore(ctx.store).read();
    expireDevices(s);
    const active = s.devices.filter((d) => d.status === 'active');
    const last = s.devices.map((d) => d.pairedAt).sort().pop();
    return {
      state: isPublicLocked(s) ? 'off' : s.totp || s.loginAllow.length || s.devices.length ? 'on' : 'not_set_up',
      totp: s.totp !== undefined,
      allowedAccounts: s.loginAllow.length,
      activeDevices: active.length,
      ...(last ? { lastPairedAt: last } : {}),
      ...(opts.pairingOpen ? { pairingOpen: opts.pairingOpen() } : {}),
    };
  } catch (err) {
    return { error: safeMessage(err) };
  }
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      p,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new PerchError(`No answer within ${Math.round(ms / 1000)} s`, 'check_timeout')), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** One read-only identity call for the account. Throws a PerchError on failure. */
async function checkAccount(ctx: PerchContext, d: StoreData, a: AccountStatus, opts: StatusOptions): Promise<void> {
  const up = ctx.upstream;
  switch (a.family) {
    case 'drive':
      await fetchDriveIdentity(up, await ctx.tokens.drive.getAccessToken(a.id));
      return;
    case 'notion': {
      const ws = d.notion.find((w) => w.id === a.id)!;
      await up.json('notion', { method: 'GET', path: '/v1/users/me', headers: { authorization: `Bearer ${await ctx.notion.accessToken(ws)}`, 'notion-version': NOTION_VERSION } });
      return;
    }
    case 'mail':
      if (a.provider === 'gmail') await fetchGmailIdentity(up, await ctx.tokens.gmail.getAccessToken(a.id));
      else await (opts.imapVerify ?? verifyImapAccount)(d.imap.find((x) => x.id === a.id)!);
      return;
    case 'calendar':
      await fetchVerifiedIdentity(up, await ctx.tokens.productivity.getAccessToken(a.id));
      return;
    case 'slack': {
      const ws = d.slack.find((w) => w.id === a.id)!;
      const r = await up.json<{ ok?: boolean; error?: unknown }>('slack', { method: 'GET', path: '/api/auth.test', ...slackAuth(ws) });
      if (r.ok !== true) {
        const code = typeof r.error === 'string' && /^[a-z_]{1,64}$/.test(r.error) ? r.error : 'unknown_error';
        if (isSlackSession(ws) && isSlackAuthFailure(code)) throw slackSessionExpired(code, ws.label);
        throw new PerchError(`Slack refused the token (${code}); reconnect with perch slack add`, 'upstream_error');
      }
      return;
    }
    case 'whatsapp': {
      const acct = d.whatsapp.find((w) => w.id === a.id)!;
      const inst = d.whatsappInstance;
      if (!inst) throw new PerchError('No WhatsApp bridge configured', 'not_configured');
      const r = await up.json<{ code?: unknown; results?: { is_logged_in?: unknown; is_connected?: unknown } }>('gowa', {
        method: 'GET',
        path: `/devices/${acct.deviceId}/status`,
        origin: inst.origin,
        capability: 'admin',
        headers: { authorization: `Basic ${Buffer.from(`${inst.username}:${inst.password}`, 'utf8').toString('base64')}` },
      });
      if (r.code !== 'SUCCESS') throw new PerchError('The WhatsApp bridge reported a failure', 'upstream_error');
      if (r.results?.is_logged_in !== true) throw new PerchError('Not logged in to WhatsApp: pair again with perch whatsapp add', 'not_logged_in');
      if (r.results?.is_connected !== true) throw new PerchError('Logged in, but the bridge is not connected to WhatsApp right now', 'not_connected');
      return;
    }
    case 'luma':
      await ctx.luma.check(a.id);
      return;
    case 'x':
      await ctx.x.check(a.id);
      return;
  }
}

async function ledgerStatus(ctx: PerchContext): Promise<StatusReport['ledger']> {
  try {
    const l = await new MailWorkflowLedger(ctx.store).read();
    return {
      sends: l.sends.length,
      maxSends: MAX_SEND_RECORDS,
      pending: l.sends.filter((s) => s.state === 'pending').length,
      auditEvents: l.audit.length,
      auditDropped: l.auditDropped,
      ...(l.audit.length ? { lastActivityAt: l.audit[l.audit.length - 1]!.at } : {}),
    };
  } catch (err) {
    return { error: safeMessage(err) };
  }
}

export async function collectStatus(ctx: PerchContext, opts: StatusOptions = {}): Promise<StatusReport> {
  const d = await ctx.store.read();
  const accounts = accountsOf(d);
  const live = opts.live ?? true;
  if (live) {
    const queue = accounts.filter((a) => !a.check);
    const worker = async () => {
      for (let a = queue.shift(); a; a = queue.shift()) {
        const started = Date.now();
        try {
          await withTimeout(checkAccount(ctx, d, a, opts), opts.timeoutMs ?? CHECK_TIMEOUT_MS);
          a.check = { state: 'ok', ms: Date.now() - started };
        } catch (err) {
          a.check = { state: 'error', message: safeMessage(err), ms: Date.now() - started };
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(CHECK_CONCURRENCY, accounts.length) }, worker));
  }
  return {
    generatedAt: new Date().toISOString(),
    version: PERCH_VERSION,
    namespace: ctx.store.namespace,
    checked: live,
    accounts,
    googleGroups: d.googleGroups.map((g) => ({
      id: g.id,
      label: g.label,
      email: g.email,
      services: groupServices(d, g.id),
      accountIds: accounts.filter((a) => a.groupId === g.id).map((a) => a.id),
      connectedAt: g.createdAt,
    })),
    microsoftGroups: (d.microsoftSessions ?? []).map((group) => ({
      id: group.id, label: group.label, email: group.email, connectedAt: group.createdAt,
      services: MICROSOFT_SERVICES.map((service) => {
        const access = group.services[service];
        return { service, accountId: group.members[service], enabled: access.enabled, write: access.enabled && access.write,
          invite: service === 'calendar' && access.enabled && access.write && access.invite, status: access.status, ...(access.checkedAt ? { checkedAt: access.checkedAt } : {}) };
      }),
    })),
    clients: d.clients.map((c) => ({ id: c.id, label: c.label, capabilities: [...c.capabilities], accountIds: [...c.accountIds], ...(c.full ? { full: true } : {}), ...(c.readAll ? { readAll: true } : {}), createdAt: c.createdAt })),
    ...(d.whatsappInstance ? { whatsappBridge: { origin: d.whatsappInstance.origin, configuredAt: d.whatsappInstance.createdAt } } : {}),
    ledger: await ledgerStatus(ctx),
    publicAccess: await publicAccessStatus(ctx, opts),
  };
}

export const failedChecks = (r: StatusReport) => r.accounts.filter((a) => a.check?.state === 'error').length;

const day = (iso: string) => iso.slice(0, 10);

/** Plain-text rendering for `perch status`. */
export function formatStatusText(r: StatusReport): string {
  const lines = [`Perch ${r.version} · namespace ${r.namespace} · ${r.generatedAt.replace('T', ' ').slice(0, 16)} UTC${r.checked ? '' : ' · live checks skipped'}`, ''];
  const accountLine = (a: AccountStatus, indent: string) => {
    const mark = !a.check ? '·' : a.check.state === 'ok' ? '✓' : '✗';
    const result = !a.check ? '' : a.check.state === 'ok' ? `  ok (${a.check.ms} ms)` : `  ERROR: ${a.check.message}`;
    const until = a.expiresAt ? `  until ${day(a.expiresAt)}` : '';
    lines.push(`${indent}${mark} ${a.id}  "${a.label}"  ${a.identity ?? ''}  [${a.provider}: ${a.permissions}]  since ${day(a.connectedAt)}${until}${result}`);
    if (a.hint) lines.push(`${indent}    hint: ${a.hint}`);
  };
  // Google account groups first: one login, the services as accounts below it.
  if (r.googleGroups.length) {
    lines.push('Google accounts (one login each)');
    for (const g of r.googleGroups) {
      lines.push(`  ${g.id}  "${g.label}"  ${g.email}  services: ${g.services.join(', ') || 'none'}  since ${day(g.connectedAt)}`);
      for (const a of r.accounts.filter((x) => x.groupId === g.id)) accountLine(a, `    ${FAMILY_TITLES[a.family]}: `);
    }
  }
  for (const group of r.microsoftGroups ?? []) {
    lines.push('Microsoft account (one browser session; stored status only)', `  ${group.id}  "${group.label}"  ${group.email}  since ${day(group.connectedAt)}`);
    for (const service of group.services) {
      const rights = service.enabled ? `read${service.write ? ', write' : ''}${service.invite ? ', invite' : ''}` : 'disabled';
      lines.push(`    ${service.service}: ${service.accountId}  [${rights}]  ${service.status}  last probe: ${service.checkedAt ?? 'never'}`);
    }
    lines.push(`    fresh check: perch microsoft doctor ${group.id}`, `    local permissions: perch microsoft access ${group.id}`);
  }
  // Google is one service: without any Google account one line; Drive and Calendar/Contacts only list accounts
  // connected separately (own login, before account groups).
  const anyGoogle = r.googleGroups.length > 0 || r.accounts.some((a) => a.family === 'drive' || a.family === 'calendar' || a.provider === 'gmail');
  for (const family of Object.keys(FAMILY_TITLES) as AccountFamily[]) {
    if (family === 'microsoft_session') continue;
    const all = r.accounts.filter((a) => a.family === family);
    const rows = all.filter((a) => !a.groupId);
    if (family === 'drive' && !anyGoogle) lines.push('Google (Drive, Gmail, Calendar, Contacts): none');
    if ((family === 'drive' || family === 'calendar') && !rows.length) continue;
    lines.push(`${FAMILY_TITLES[family]}${rows.length ? '' : all.length ? ': only in Google account groups' : ': none'}`);
    for (const a of rows) accountLine(a, '  ');
  }
  lines.push('', `Client grants${r.clients.length ? '' : ': none'}`);
  for (const c of r.clients)
    lines.push(c.full ? `  ${c.id}  "${c.label}"  FULL access → every account (also later ones)` : c.readAll ? `  ${c.id}  "${c.label}"  read only → every account (also later ones)` : `  ${c.id}  "${c.label}"  ${c.capabilities.join(',')}  → ${c.accountIds.join(', ')}`);
  if (r.whatsappBridge) lines.push('', `WhatsApp bridge: ${r.whatsappBridge.origin}`);
  lines.push('');
  if ('error' in r.ledger) lines.push(`Send ledger: ERROR ${r.ledger.error}`);
  else {
    lines.push(
      `Send ledger: ${r.ledger.sends} / ${r.ledger.maxSends} records used${r.ledger.pending ? `, ${r.ledger.pending} pending (unknown outcome)` : ''}`,
      `Audit: ${r.ledger.auditEvents} events${r.ledger.auditDropped ? ` (+${r.ledger.auditDropped} rotated out)` : ''}${r.ledger.lastActivityAt ? `, last activity ${r.ledger.lastActivityAt.replace('T', ' ').slice(0, 16)} UTC` : ''}`,
    );
  }
  const p = r.publicAccess;
  if ('error' in p) lines.push(`Public access: ERROR ${p.error}`);
  else {
    lines.push(
      `Public access: ${p.state === 'off' ? 'OFF (kill switch)' : p.state === 'on' ? 'set up' : 'not set up'} · Perch code ${p.totp ? 'set up' : 'missing'} · ` +
        `${p.allowedAccounts} allowed Google account(s) · ${p.activeDevices} active device(s)${p.lastPairedAt ? `, last pairing ${p.lastPairedAt.replace('T', ' ').slice(0, 16)} UTC` : ''}` +
        `${p.pairingOpen ? ' · a pairing window is OPEN' : ''}`,
    );
  }
  const failed = failedChecks(r);
  if (r.checked) lines.push('', failed ? `${failed} check(s) failed.` : r.microsoftGroups?.length ? 'Microsoft session probes were not run; displayed state is from the last probe.' : 'All checks passed.');
  return `${lines.join('\n')}\n`;
}
