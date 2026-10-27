import { createDeviceGrant, parseCapabilities, removeClientGrant } from '../auth/grants.js';
import type { Capability } from '../store/credentialStore.js';
import { BUILTIN_CIMD, newPreClientId, validRedirectUri } from '../access/clients.js';
import { connectControl } from '../access/control.js';
import { silentNotifier, TelegramNotifier, type Notifier, type NoticeKind } from '../access/notify.js';
import { encodeQr, renderQrTerminal } from '../access/qr.js';
import { parseBaseUrl } from '../access/baseUrl.js';
import { field, wrap, WIDTH } from './text.js';
import { DEVICE_ID_PATTERN, deviceOrigin, endDevice, expireDevices, MAX_LOGIN_ALLOW, newRecoveryCodes, OAuthStore, PRECLIENT_ID_PATTERN, sha256Hex, type ListenerKind } from '../access/state.js';
import { randomBytes } from 'node:crypto';
import { base32Encode } from '../access/base32.js';
import { newTotpSecret, otpauthUri, verifyTotp } from '../access/totp.js';
import { AuditLog } from '../audit/audit.js';
import type { PerchConfig } from '../config.js';
import { PerchError } from '../errors.js';
import { MailWorkflowLedger } from '../mail/workflowLedger.js';
import { validateCimdOrigin, createFetchTransport, Upstream } from '../upstream.js';
import { CredentialStore } from '../store/credentialStore.js';
import type { CliIo } from './run.js';
import { httpsPort, publicSetup, publicStatus } from './publicSetup.js';

/**
 * Local CLI of the public access (docs/PUBLIC_ACCESS_SPEC.md §10). Everything here runs on the server only;
 * nothing of it is reachable over HTTP.
 */

const usage = (msg: string) => new PerchError(msg, 'usage');
const day = (iso: string | undefined) => (iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)}` : '-');

async function open(config: PerchConfig) {
  const store = await CredentialStore.open({ dataDir: config.dataDir, keyFile: config.keyFile });
  return { store, oauth: new OAuthStore(store), audit: new AuditLog(new MailWorkflowLedger(store)) };
}

async function notifierFor(config: PerchConfig, io: CliIo): Promise<Notifier> {
  if (!config.notifyTelegramFile) return silentNotifier;
  return TelegramNotifier.fromFile(config.notifyTelegramFile, new Upstream(io.transport ?? createFetchTransport()));
}

async function tryNotify(config: PerchConfig, io: CliIo, kind: NoticeKind): Promise<void> {
  try {
    await (await notifierFor(config, io)).notify(kind);
  } catch {
    io.stderr('perch: the notification could not be delivered.\n');
  }
}

const recordAudit = (audit: AuditLog, type: string, deviceId?: string, code?: string) =>
  audit.record({ type, actor: { kind: 'oauth', ...(deviceId ? { deviceId } : {}) }, outcome: 'ok', ...(code ? { code } : {}) });

function readLine(io: CliIo): (prompt: string) => Promise<string> {
  if (!io.readLine) throw new PerchError('This command needs an interactive terminal', 'no_tty');
  return io.readLine;
}

const yes = (answer: string) => /^(y|yes|j|ja)$/i.test(answer.trim());

/** Removes the client grants of devices that are no longer active. */
async function releaseGrants(store: CredentialStore, oauth: OAuthStore): Promise<void> {
  const grants: string[] = [];
  await oauth.transact((d) => {
    expireDevices(d);
    for (const dev of d.devices) {
      if (dev.status !== 'active' && dev.grantClientId) {
        grants.push(dev.grantClientId);
        dev.grantClientId = undefined;
      }
    }
  });
  for (const g of grants) await removeClientGrant(store, g).catch(() => {});
}

async function localPage(config: PerchConfig, io: CliIo, action: string | undefined): Promise<void> {
  const { oauth, audit } = await open(config);
  if (action === 'enable') {
    const password = randomBytes(24).toString('base64url');
    await oauth.transact((d) => {
      d.localPage = { passwordHash: sha256Hex(password), createdAt: new Date().toISOString() };
    });
    await recordAudit(audit, 'oauth_local_page', undefined, 'enabled');
    io.stdout(
      `Local pairing page enabled: http://127.0.0.1:${config.httpPort}/local/pair (local listener only).\n` +
        `Password (any user name; shown once, a new enable replaces it): ${password}\n` +
        wrap(
          'This password is a pairing credential: whoever has it can open a pairing window and approve a sign-in (read only; full access only in the terminal). Keep it like a password; perch oauth local-page disable turns the page off.',
        ),
    );
    return;
  }
  if (action === 'disable') {
    await oauth.transact((d) => {
      d.localPage = undefined;
    });
    await recordAudit(audit, 'oauth_local_page', undefined, 'disabled');
    io.stdout('Local pairing page disabled (/local/pair answers 404).\n');
    return;
  }
  throw usage('Usage: perch oauth local-page enable|disable');
}

// ------------------------------------------------------------------ TOTP

export async function totpSetup(config: PerchConfig, io: CliIo): Promise<void> {
  const { oauth, audit } = await open(config);
  const ask = readLine(io);
  const before = await oauth.read();
  if (before.totp) {
    const active = before.devices.filter((d) => d.status === 'active' && deviceOrigin(d) === 'public').length;
    const answer = await ask(`A Perch code already exists. Replacing it signs out all ${active} public device(s). Continue? [y/N] `);
    if (!yes(answer)) throw new PerchError('Aborted; nothing was changed', 'aborted');
  }
  const secret = newTotpSecret();
  const account = config.publicBaseUrl ? parseBaseUrl(config.publicBaseUrl).hostname : 'perch';
  const uri = otpauthUri(secret, account);
  io.stdout(`${wrap('Scan this QR code with your authenticator app (Google Authenticator, Aegis, 1Password, ...):')}\n`);
  io.stdout(renderQrTerminal(encodeQr(uri)));
  io.stdout(`\nOr enter this key by hand: ${base32Encode(secret, { pad: false }).replace(/(.{4})/g, '$1 ').trim()}\n(TOTP, SHA-1, 6 digits, 30 seconds)\n\n`);
  let step: number | null = null;
  for (let i = 0; i < 3 && step === null; i++) {
    step = verifyTotp(secret, (await ask('Enter the 6-digit code your app now shows: ')).replace(/\s/g, ''), Date.now(), undefined);
    if (step === null) io.stderr('That code does not match. Check the time on your phone and try again.\n');
  }
  if (step === null) throw new PerchError('The code could not be confirmed; nothing was changed', 'totp_not_confirmed');
  const { codes, records } = newRecoveryCodes();
  let signedOut = 0;
  await oauth.transact((d) => {
    if (d.totp) {
      // The Perch code protects the public pairing only; private (tailnet) devices never used it.
      for (const dev of d.devices) {
        if (dev.status === 'active' && deviceOrigin(dev) === 'public') {
          endDevice(dev, 'totp_changed');
          signedOut++;
        }
      }
    }
    d.totp = { secret: secret.toString('base64'), lastStep: step!, createdAt: new Date().toISOString(), recovery: records };
    d.totpFailures = [];
  });
  await releaseGrants((await open(config)).store, oauth);
  await recordAudit(audit, 'oauth_totp_set', undefined, before.totp ? 'replaced' : 'created');
  if (before.totp) await tryNotify(config, io, 'totp_changed');
  io.stdout(
    `\nPerch code set up.${signedOut ? ` ${signedOut} public device(s) were signed out.` : ''}\n\n` +
      wrap('Recovery codes (each works once instead of the 6-digit code; store them offline, they are not shown again):') +
      `${codes.map((c) => `  ${c.slice(0, 5)}-${c.slice(5)}`).join('\n')}\n`,
  );
}

async function totpRecoveryCodes(config: PerchConfig, io: CliIo): Promise<void> {
  const { oauth, audit } = await open(config);
  const { codes, records } = newRecoveryCodes();
  await oauth.transact((d) => {
    if (!d.totp) throw new PerchError('No Perch code is set up yet: run perch oauth totp setup', 'totp_missing');
    d.totp.recovery = records;
  });
  await recordAudit(audit, 'oauth_recovery_codes', undefined, 'regenerated');
  io.stdout(`New recovery codes (the old ones no longer work; not shown again):\n${codes.map((c) => `  ${c.slice(0, 5)}-${c.slice(5)}`).join('\n')}\n`);
}

// ------------------------------------------------------------------ pairing

export type PairAccessChoice = 'read' | 'full';

const LISTENER_NAME = { private: 'private (tailnet)', public: 'public (internet)' } as const;

/** Terminal text when a window opened (SIMPLE_CONNECT_SPEC §1, §5; lines within 80 columns). */
export function openedText(m: Record<string, unknown>): string {
  const listener: 'private' | 'public' = m.listener === 'private' ? 'private' : 'public';
  const notes = (Array.isArray(m.notes) ? m.notes : []).map(String);
  let t =
    `Pairing window for the ${listener === 'private' ? 'PRIVATE address (tailnet)' : 'PUBLIC address (internet)'}\n` +
    `open until ${String(m.expiresAt).slice(11, 19)} UTC (10 minutes, one device).\n\n` +
    `  Pairing code:  ${String(m.code)}\n\n` +
    'Only this address can pair in this window:\n' +
    `  ${`${LISTENER_NAME[listener]}:`.padEnd(20)}${typeof m.url === 'string' ? m.url : ''}\n`;
  for (const n of notes) t += wrap(n, '    ', WIDTH, '  - ');
  t += '\n';
  t += wrap(
    listener === 'private'
      ? 'Now start the sign-in in your AI (Claude Code: /mcp, then perch, then Authenticate). The browser asks for this pairing code. Then confirm here.'
      : 'Now start the sign-in in your AI (claude.ai or ChatGPT: Connect). The browser asks for this pairing code, your Google account and your Perch code. Then confirm here.',
  );
  t += 'Ctrl-C closes the window.\n\n';
  return t;
}

/** Terminal text of the confirmation (every detail the operator compares; lines within 80 columns). */
export function confirmText(d: Record<string, unknown>): string {
  const priv = d.origin === 'private';
  let t = `\nA device wants to pair over the ${priv ? 'PRIVATE address (tailnet)' : 'PUBLIC address (internet)'}:\n`;
  t += field('Client', `${String(d.clientName)} (${String(d.clientDisplay)})`);
  t += field('Registered as', String(d.registration));
  t += field('Returns to', String(d.redirectHost));
  if (!priv) t += field('Google account', String(d.googleEmail ?? '-'));
  t += field('Browser', String(d.userAgent));
  if (priv) {
    const ip = String(d.ip);
    t += field('Source', /^(127\.|::1$)/.test(ip) ? `${ip} (loopback: Tailscale Serve or this server)` : ip);
  } else t += field('IP', String(d.ip));
  t += field('Since opening', `${String(d.secondsSinceOpen)} s${d.usedRecoveryCode ? '  (a recovery code was used)' : ''}`);
  t += '\nOnly confirm if this is the device you are connecting right now.\n';
  return t;
}

export const ACCESS_PROMPT = '[r]ead only, or [f]ull (read and write on every account, also later ones)? ';
const accessOf = (answer: string): PairAccessChoice => (/^(f|full)$/i.test(answer.trim()) ? 'full' : 'read');

/**
 * perch oauth pair: opens a window over the control socket, shows the code, the confirmation details and asks
 * for the rights (unless `access` is given: --full / --read-only). The server creates the device with the
 * chosen rights before it issues the authorization code.
 */
export async function pair(config: PerchConfig, io: CliIo, opts: { access?: PairAccessChoice; listener?: ListenerKind } = {}): Promise<number> {
  const ask = readLine(io);
  const ctl = await connectControl(config.dataDir);
  return new Promise<number>((resolve) => {
    let paired: string | undefined;
    let done = false;
    let firstUseTimer: NodeJS.Timeout | undefined;
    const finish = (code: number) => {
      if (done) return;
      done = true;
      if (firstUseTimer) clearTimeout(firstUseTimer);
      ctl.socket.end();
      resolve(code);
    };
    ctl.socket.on('close', () => finish(paired ? 0 : 1));
    ctl.onMessage((m) => {
      switch (m.type) {
        case 'opened':
          io.stdout(openedText(m));
          break;
        case 'progress': {
          const via = m.origin === 'private' ? ' (private)' : m.origin === 'public' ? ' (public)' : '';
          const line = {
            started: `… a sign-in started${via}`,
            code_ok: `… pairing code accepted${via}`,
            google_ok: '… Google account accepted',
            totp_ok: '… Perch code accepted',
          }[String(m.step)];
          if (line) io.stdout(`${line}\n`);
          break;
        }
        case 'alarm':
          io.stderr(
            wrap(
              `ALARM: ${{ second_pairing_attempt: 'a second sign-in attempt in this window (possible phishing). Both were discarded.', pairing_code_wrong: 'a wrong pairing code was entered.', pairing_locked: 'too many wrong Perch codes; pairing is locked for a while.' }[String(m.kind)] ?? String(m.kind)}`,
              '       ',
            ),
          );
          break;
        case 'confirm': {
          io.stdout(confirmText(m.details as Record<string, unknown>));
          ask('Pair this device? [y/N] ')
            .then(async (a) => {
              if (!yes(a)) return ctl.send({ op: 'answer', approved: false });
              let access = opts.access;
              if (!access) {
                io.stdout('Read only: reads every account, writes nothing.\nFull: reads and writes on every account, also on accounts added later.\n');
                access = accessOf(await ask(ACCESS_PROMPT).catch(() => ''));
              }
              ctl.send({ op: 'answer', approved: true, access });
            })
            .catch(() => ctl.send({ op: 'answer', approved: false }));
          break;
        }
        case 'paired': {
          paired = String(m.deviceId);
          const where = m.origin === 'private' ? 'private' : 'public';
          if (m.access === 'full') {
            io.stdout(
              `\nPaired device ${paired} (${where}) with FULL access: read and write on\nevery account. Undo with one of:\n` +
                `  perch oauth ungrant ${paired} --read-all\n  perch oauth revoke ${paired}\n`,
            );
          } else io.stdout(`\nPaired device ${paired} (${where}), read only. To let it write:\n  perch oauth grant ${paired} --full\n`);
          io.stdout('Waiting up to 5 minutes for its first request (Ctrl-C to stop) ...\n');
          firstUseTimer = setTimeout(() => {
            io.stdout(`No request from ${paired} yet. If your client does not work, revoke it:\n  perch oauth revoke ${paired}\n`);
            finish(0);
          }, 5 * 60 * 1000);
          break;
        }
        case 'first_use':
          io.stdout(
            `First request from ${String(m.deviceId)} received. Done.\n` +
              `If your own client still does not work, something else used this pairing:\n  perch oauth revoke ${String(m.deviceId)}\n`,
          );
          finish(0);
          break;
        case 'closed':
          if (m.reason === 'consumed') break;
          if (!paired) {
            io.stderr(`Pairing window closed (${String(m.reason)}). Nothing was paired.\n`);
            finish(1);
          }
          break;
        case 'error':
          io.stderr(wrap(`perch: ${String(m.message)}`, '  '));
          finish(1);
          break;
      }
    });
    ctl.send({ op: 'open', ...(opts.listener ? { listener: opts.listener } : {}) });
  });
}

// ------------------------------------------------------------------ devices, grants, clients

async function devices(config: PerchConfig, io: CliIo): Promise<void> {
  const { store, oauth } = await open(config);
  await releaseGrants(store, oauth);
  const s = await oauth.read();
  const grants = new Map((await store.read()).clients.map((c) => [c.id, c]));
  const lines = ['Paired devices (OAuth; private = tailnet, public = internet):'];
  if (!s.devices.length) lines.push('  (none)');
  for (const d of s.devices) {
    const g = d.grantClientId ? grants.get(d.grantClientId) : undefined;
    const rights = !d.grantClientId ? 'read only' : g?.full ? `full access (grant ${d.grantClientId})` : `grant ${d.grantClientId}`;
    lines.push(
      `  ${d.id}  ${d.status === 'pending' ? 'pending (code not exchanged yet)' : d.status}${d.endedReason ? ` (${d.endedReason})` : ''}  ${deviceOrigin(d)}  ${rights}`,
      `      "${d.clientName}" via ${d.registration}, returns to ${d.redirectHost}${d.googleEmail ? `, ${d.googleEmail}` : ''}`,
      `      paired ${day(d.pairedAt)}  seen ${day(d.lastSeenAt)}  expires ${day(d.expiresAt)}`,
    );
  }
  io.stdout(`${lines.join('\n')}\n`);
}

async function revoke(config: PerchConfig, io: CliIo, id: string | undefined, all: boolean, privateAll = false): Promise<void> {
  const { store, oauth, audit } = await open(config);
  if (all && privateAll) throw usage('Use either --all or --private-all');
  const many = all || privateAll;
  if (!many && (!id || !DEVICE_ID_PATTERN.test(id))) throw usage('Usage: perch oauth revoke <oc-…> | --all | --private-all');
  const grants: string[] = [];
  const ended: string[] = [];
  await oauth.transact((d) => {
    for (const dev of d.devices) {
      if (dev.status !== 'active' && dev.status !== 'pending') continue;
      if (privateAll ? deviceOrigin(dev) !== 'private' : !all && dev.id !== id) continue;
      endDevice(dev, 'revoked');
      ended.push(dev.id);
      if (dev.grantClientId) grants.push(dev.grantClientId);
      dev.grantClientId = undefined;
    }
    if (!many && !ended.length) throw new PerchError(`No active device ${id}`, 'unknown_device');
  });
  for (const g of grants) await removeClientGrant(store, g).catch(() => {});
  for (const e of ended) await recordAudit(audit, 'oauth_device_revoked', e, 'local_admin');
  io.stdout(`Revoked ${ended.length}${privateAll ? ' private' : ''} device(s)${ended.length ? `: ${ended.join(', ')}` : ''}. Their tokens stop working with the next request.\n`);
}

async function grant(config: PerchConfig, io: CliIo, id: string | undefined, values: Record<string, unknown>): Promise<void> {
  if (!id || !DEVICE_ID_PATTERN.test(id)) throw usage('Usage: perch oauth grant <oc-…> --full | --allow CAPS --account ID [--account ID ...]');
  const full = values.full === true;
  if (full && (values.allow !== undefined || values.account !== undefined)) throw usage('--full replaces --allow and --account; use one or the other');
  if (!full && typeof values.allow !== 'string') throw usage('--allow is required (same capabilities as perch client add), or --full');
  const accounts = (values.account as string[] | undefined) ?? [];
  if (!full && !accounts.length) throw usage('--account is required (or --full)');
  const { store, oauth, audit } = await open(config);
  await grantDevice({ store, oauth, audit }, id, full ? { full: true } : { capabilities: parseCapabilities((values.allow as string).split(',')), accountIds: accounts });
  io.stdout(
    full
      ? `Device ${id} now has FULL access: read and write on every connected account, including accounts connected later.\n`
      : `Device ${id} now acts as a client grant for ${accounts.join(', ')}. Like perch client add, it then sees only what this grant covers; include read capabilities if it should keep reading.\n`,
  );
  io.stdout(`Undo: perch oauth ungrant ${id} --read-all (then it reads every account), or perch oauth revoke ${id}\n`);
}

/** Attaches a (full or narrow) grant to an active device, replacing an earlier one. */
async function grantDevice(
  ctx: Pick<Awaited<ReturnType<typeof open>>, 'store' | 'oauth' | 'audit'>,
  id: string,
  access: { full: true } | { capabilities: Capability[]; accountIds: string[] },
): Promise<void> {
  const { store, oauth, audit } = ctx;
  const dev = (await oauth.read()).devices.find((d) => d.id === id && d.status === 'active');
  if (!dev) throw new PerchError(`No active device ${id}`, 'unknown_device');
  const g = await createDeviceGrant(store, 'full' in access ? { label: `OAuth ${id}`, capabilities: [], accountIds: [], full: true } : { label: `OAuth ${id}`, ...access });
  let old: string | undefined;
  try {
    await oauth.transact((d) => {
      const x = d.devices.find((v) => v.id === id && v.status === 'active');
      if (!x) throw new PerchError(`No active device ${id}`, 'unknown_device');
      old = x.grantClientId;
      x.grantClientId = g.id;
    });
  } catch (err) {
    await removeClientGrant(store, g.id).catch(() => {});
    throw err;
  }
  if (old) await removeClientGrant(store, old).catch(() => {});
  await recordAudit(audit, 'oauth_device_grant', id, 'granted');
}

/**
 * Removing a device's grant makes it read-only over EVERY account again, which can be more than the grant
 * allowed (a grant names its accounts). That widening needs the explicit --read-all; to take access away,
 * use perch oauth revoke or a narrower perch oauth grant.
 */
async function ungrant(config: PerchConfig, io: CliIo, id: string | undefined, readAll: boolean): Promise<void> {
  if (!id || !DEVICE_ID_PATTERN.test(id)) throw usage('Usage: perch oauth ungrant <oc-…> --read-all');
  if (!readAll) {
    throw usage(
      `Without its grant, device ${id} could READ EVERY connected account, which may be more than its grant allows. ` +
        `To take access away use perch oauth revoke ${id} (or a narrower perch oauth grant); to really allow reading everything, repeat with --read-all.`,
    );
  }
  const { store, oauth, audit } = await open(config);
  let old: string | undefined;
  await oauth.transact((d) => {
    const x = d.devices.find((v) => v.id === id);
    if (!x) throw new PerchError(`Unknown device ${id}`, 'unknown_device');
    old = x.grantClientId;
    x.grantClientId = undefined;
  });
  if (old) await removeClientGrant(store, old).catch(() => {});
  await recordAudit(audit, 'oauth_device_grant', id, 'removed');
  io.stdout(`Device ${id} has no grant any more: it can read every connected account and write nothing.\n`);
}

export async function loginAllow(config: PerchConfig, io: CliIo, sub: string | undefined, arg: string | undefined): Promise<void> {
  const { oauth, audit } = await open(config);
  if (sub === 'list') {
    const s = await oauth.read();
    io.stdout(`Allowed Google accounts:\n${s.loginAllow.length ? s.loginAllow.map((e) => `  ${e.email}${e.sub ? '  (pinned)' : '  (pinned at first sign-in)'}`).join('\n') : '  (none)'}\n`);
    return;
  }
  const email = arg?.trim().toLowerCase();
  if ((sub !== 'add' && sub !== 'remove') || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw usage('Usage: perch oauth login-allow add|remove <email> | list');
  await oauth.transact((d) => {
    if (sub === 'add') {
      if (d.loginAllow.some((e) => e.email === email)) throw new PerchError(`${email} is already allowed`, 'exists');
      if (d.loginAllow.length >= MAX_LOGIN_ALLOW) throw new PerchError(`At most ${MAX_LOGIN_ALLOW} Google accounts`, 'too_many');
      d.loginAllow.push({ email, addedAt: new Date().toISOString() });
    } else {
      if (!d.loginAllow.some((e) => e.email === email)) throw new PerchError(`${email} is not on the list`, 'unknown');
      d.loginAllow = d.loginAllow.filter((e) => e.email !== email);
    }
  });
  await recordAudit(audit, 'oauth_login_allow', undefined, sub === 'add' ? 'added' : 'removed');
  io.stdout(wrap(sub === 'add' ? `Allowed ${email}. Its Google account id is pinned at the first sign-in.` : `Removed ${email}. Devices already paired with it keep working until revoked.`));
}

async function clients(config: PerchConfig, io: CliIo, sub: string | undefined, arg: string | undefined, values: Record<string, unknown>): Promise<void> {
  const { oauth } = await open(config);
  if (sub === 'list') {
    const s = await oauth.read();
    const lines = ['Built in: Claude client metadata documents under https://claude.ai/oauth/… and https://claude.com/oauth/…'];
    for (const u of s.cimdUrls) lines.push(`  metadata document  ${u}`);
    for (const c of s.preClients) lines.push(`  ${c.id}  "${c.name}"  ${c.redirectUris.join(' ')}`);
    io.stdout(`${lines.join('\n')}\n`);
    return;
  }
  if (sub === 'add' && typeof values.cimd === 'string') {
    const url = values.cimd.trim();
    validateCimdOrigin(url);
    const u = new URL(url);
    if (u.search || u.hash || u.pathname === '/' || BUILTIN_CIMD.test(url)) throw usage('--cimd must be an https URL with a path, without query or fragment (Claude and Codex documents are built in)');
    await oauth.transact((d) => {
      if (!d.cimdUrls.includes(url)) d.cimdUrls.push(url);
    });
    io.stdout(`Allowed the client metadata document ${url}.\n`);
    return;
  }
  if (sub === 'add') {
    const name = typeof values.name === 'string' ? values.name.trim() : '';
    const redirects = (values.redirect as string[] | undefined) ?? [];
    if (!name || !redirects.length || redirects.length > 5 || !redirects.every(validRedirectUri)) {
      throw usage('Usage: perch oauth client add --name NAME --redirect URI [--redirect URI ...]  (https, or http loopback)  |  add --cimd URL');
    }
    const id = newPreClientId();
    await oauth.transact((d) => {
      d.preClients.push({ id, name: name.slice(0, 100), redirectUris: redirects, createdAt: new Date().toISOString() });
    });
    io.stdout(`Pre-registered client ${id} ("${name}"). Use ${id} as its OAuth client id (public client with PKCE, no secret).\n`);
    return;
  }
  if (sub === 'remove' && arg) {
    await oauth.transact((d) => {
      if (PRECLIENT_ID_PATTERN.test(arg)) {
        if (!d.preClients.some((c) => c.id === arg)) throw new PerchError(`Unknown client ${arg}`, 'unknown');
        d.preClients = d.preClients.filter((c) => c.id !== arg);
      } else {
        if (!d.cimdUrls.includes(arg)) throw new PerchError(`Unknown client ${arg}`, 'unknown');
        d.cimdUrls = d.cimdUrls.filter((u) => u !== arg);
      }
    });
    io.stdout(`Removed ${arg}. Devices already paired with it keep working until revoked.\n`);
    return;
  }
  throw usage('Usage: perch oauth client add --name NAME --redirect URI | add --cimd URL | list | remove ID|URL');
}

export async function cmdOauth(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>): Promise<number> {
  switch (sub) {
    case 'pair': {
      if (values.full === true && values['read-only'] === true) throw usage('Use either --full or --read-only');
      if (values.private === true && values.public === true) throw usage('A pairing window serves one address: use either --private or --public');
      const listener: ListenerKind | undefined = values.private === true ? 'private' : values.public === true ? 'public' : undefined;
      return pair(config, io, { ...(values.full === true ? { access: 'full' as const } : values['read-only'] === true ? { access: 'read' as const } : {}), ...(listener ? { listener } : {}) });
    }
    case 'totp':
      if (rest[0] === 'setup') await totpSetup(config, io);
      else if (rest[0] === 'recovery-codes') await totpRecoveryCodes(config, io);
      else if (rest[0] === 'status') {
        const s = await (await open(config)).oauth.read();
        io.stdout(s.totp ? `Perch code set up ${day(s.totp.createdAt)}; ${s.totp.recovery.filter((r) => !r.usedAt).length} unused recovery code(s).\n` : 'No Perch code set up (perch oauth totp setup).\n');
      } else throw usage('Usage: perch oauth totp setup|status|recovery-codes');
      return 0;
    case 'login-allow':
      await loginAllow(config, io, rest[0], rest[1]);
      return 0;
    case 'client':
      await clients(config, io, rest[0], rest[1], values);
      return 0;
    case 'devices':
      await devices(config, io);
      return 0;
    case 'local-page':
      await localPage(config, io, rest[0]);
      return 0;
    case 'revoke':
      await revoke(config, io, rest[0], values.all === true, values['private-all'] === true);
      return 0;
    case 'grant':
      await grant(config, io, rest[0], values);
      return 0;
    case 'ungrant':
      await ungrant(config, io, rest[0], values['read-all'] === true);
      return 0;
    default:
      throw usage('Usage: perch oauth pair [--private|--public] [--full|--read-only] | totp … | login-allow … | client … | devices | revoke … | grant … | ungrant …');
  }
}

// ------------------------------------------------------------------ perch public

export async function cmdPublic(config: PerchConfig, io: CliIo, sub: string | undefined): Promise<number> {
  const { oauth, audit } = await open(config);
  if (sub === 'off') {
    let ended = 0;
    await oauth.transact((d) => {
      d.publicLocked = { since: new Date().toISOString() };
      // Only the public listener: private (tailnet) devices keep working (perch oauth revoke --private-all).
      for (const dev of d.devices) {
        if (dev.status === 'active' && deviceOrigin(dev) === 'public') {
          endDevice(dev, 'kill_switch');
          ended++;
        }
      }
    });
    await releaseGrants((await open(config)).store, oauth);
    await recordAudit(audit, 'oauth_kill_switch', undefined, 'off');
    await tryNotify(config, io, 'kill_switch');
    io.stdout(
      `Public access is OFF: the public listener answers 503 (also after restarts), an open pairing window closes for it, ${ended} public device(s) were signed out.\n` +
        'Private (tailnet) devices keep working; to sign them out too: perch oauth revoke --private-all\n' +
        `Also stop the public proxy, for Tailscale Funnel for example:\n  sudo tailscale funnel --https=${config.publicBaseUrl ? httpsPort(parseBaseUrl(config.publicBaseUrl)) : 443} off\n`,
    );
    return 0;
  }
  if (sub === 'on') {
    await oauth.transact((d) => {
      d.publicLocked = undefined;
    });
    await recordAudit(audit, 'oauth_kill_switch', undefined, 'on');
    io.stdout('Public access is ON again (if perch serve --http --public runs). Public devices have to be paired again: perch oauth pair --public\n');
    return 0;
  }
  if (sub === 'status' || sub === undefined) return publicStatus(config, io);
  if (sub === 'setup') return publicSetup(config, io);
  throw usage('Usage: perch public setup|status|on|off');
}
