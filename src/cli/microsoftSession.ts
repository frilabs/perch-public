import { readdir, rm, rmdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { isIP } from 'node:net';
import { PerchError } from '../errors.js';
import type { PerchConfig } from '../config.js';
import { assertPrivateDir, readPrivateFile } from '../secureFs.js';
import { findSessionBrowser, launchSessionBrowser, openSessionProfile, sessionProfileId } from '../microsoft/sessionBrowser.js';
import { startLocalSessionReceiver } from '../microsoft/localSessionReceiver.js';
import { importPortableState } from '../microsoft/session/portableState.js';
import { startSessionViewer } from '../microsoft/sessionViewer.js';
import { CredentialStore } from '../store/credentialStore.js';
import { newAccountId, validateLabel } from '../ids.js';
import { MICROSOFT_SERVICES, MicrosoftSessionGroupSchema, type MicrosoftIdentity, type MicrosoftService, type MicrosoftSessionGroup, type SelectedSite } from '../microsoft/session/model.js';
import { normalizeSelectedSiteUrl } from '../microsoft/session/policy.js';
import { SessionRuntime, type SessionProbeReport } from '../microsoft/session/runtime.js';
import { stageSessionProfile } from '../microsoft/session/profileStage.js';
export type { SessionProbeReport } from '../microsoft/session/runtime.js';

interface Io { env: NodeJS.ProcessEnv; stdout(s: string): void; stdoutIsTTY?: boolean; readLine?: (prompt: string) => Promise<string> }
const quote = (value: string) => `'${value.replace(/'/g, `'"'"'`)}'`;
export function sessionResumeCommand(label: string, port: number, sshHost?: string): string {
  return `perch microsoft add --label ${quote(label)} --port ${port}${sshHost ? ` --ssh-host ${quote(sshHost)}` : ''}`;
}
export function sessionInstructions(url: string, sshHost?: string): string {
  const port = new URL(url).port;
  const destination = sshHost ? quote(sshHost) : 'USER@SERVER';
  return `\nKeep this terminal open.\n\n` +
    `1. On your computer, run in a second terminal:\n` +
    `   ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:${port}:127.0.0.1:${port} ${destination}\n` +
    (!sshHost ? '   Replace USER@SERVER with your SSH destination.\n' : '') +
    `2. On your computer, open in a browser:\n   ${url}\n` +
    '3. Sign in to Microsoft and select “Finish sign-in”.\n' +
    '4. Confirm access here, then stop the tunnel with Ctrl+C.\n';
}

export interface MicrosoftSessionCliDependencies {
  openStore(config: PerchConfig): Promise<CredentialStore>;
  findBrowser: typeof findSessionBrowser;
  openProfile: typeof openSessionProfile;
  launchBrowser: typeof launchSessionBrowser;
  startViewer: typeof startSessionViewer;
  startLocalReceiver: typeof startLocalSessionReceiver;
  importState: typeof importPortableState;
  createRuntime(store: CredentialStore, env: NodeJS.ProcessEnv): Promise<Pick<SessionRuntime, 'probeProfile'>>;
  stageProfile: typeof stageSessionProfile;
  /** Called with the profile lock held; returns an empty root to remove nonrecursively after release. */
  removeProfileContents(profile: Awaited<ReturnType<typeof openSessionProfile>>, dataDir: string): Promise<string | undefined>;
}
const defaults: MicrosoftSessionCliDependencies = {
  openStore: (config) => CredentialStore.open({ dataDir: config.dataDir, keyFile: config.keyFile }),
  findBrowser: findSessionBrowser, openProfile: openSessionProfile, launchBrowser: launchSessionBrowser, startViewer: startSessionViewer,
  createRuntime: async (store, env) => new SessionRuntime(store, { env }),
  stageProfile: stageSessionProfile, startLocalReceiver: startLocalSessionReceiver, importState: importPortableState,
  removeProfileContents: async (profile, dataDir) => {
    if (!/^ms-session-[a-f0-9]{24}$/.test(profile.id)) throw new PerchError('Invalid Microsoft profile identity.', 'bad_config');
    const root = path.resolve(dataDir, 'microsoft-sessions', profile.id);
    if (path.resolve(profile.path) !== path.join(root, 'browser')) throw new PerchError('Microsoft profile is outside its private data directory.', 'bad_config');
    await assertPrivateDir(root);
    await rm(profile.path, { recursive: true, force: true });
    await rm(path.join(root, 'profile.json'), { force: true });
    return root;
  },
};
const usage = () => new PerchError('Usage: perch microsoft add --session --label NAME | sessions | reconnect GROUP_ID [--reuse-session] | access GROUP_ID [--service teams|mail|calendar|files --write|--read-only|--drafts-only] | doctor GROUP_ID | remove GROUP_ID', 'usage');
const revision = () => randomBytes(16).toString('hex');
function sameIdentity(a: MicrosoftIdentity, b: MicrosoftIdentity): boolean {
  return a.tenantId.toLowerCase() === b.tenantId.toLowerCase() && a.objectId.toLowerCase() === b.objectId.toLowerCase() && a.kind === b.kind && (a.mailboxId ?? '') === (b.mailboxId ?? '');
}
function requireIdentity(report: SessionProbeReport, expected?: MicrosoftIdentity) {
  if (expected && !sameIdentity(report.identity, expected)) throw new PerchError('The signed-in Microsoft identity or mailbox differs from this group. Reconnect with the original account; nothing was changed.', 'identity_mismatch');
}
function checkAccess(values: Record<string, unknown>) {
  if (['write', 'read-only', 'drafts-only'].filter(k => values[k] === true).length > 1) throw new PerchError('Choose --read-only, --drafts-only or --write.', 'usage');
  if (values['drafts-only'] && (values['allow-send'] || values['allow-modify'] || values['allow-write'] || values['allow-calendar-write'] || values['allow-invites'])) throw new PerchError('--drafts-only cannot be combined with other write flags.', 'usage');
  if (values['drafts-only'] && values.service && values.service !== 'mail') throw new PerchError('--drafts-only applies to mail only.', 'usage');
  if (values['read-only'] && (values['allow-invites'] || values['allow-send'] || values['allow-drafts'] || values['allow-modify'] || values['allow-write'] || values['allow-calendar-write'])) throw new PerchError('--read-only cannot be combined with write or invitation flags.', 'usage');
  if (values.service !== undefined && !MICROSOFT_SERVICES.includes(values.service as MicrosoftService)) throw usage();
}
async function applyAccess(services: MicrosoftSessionGroup['services'], values: Record<string, unknown>, io: Io, preserve = false): Promise<void> {
  const selected = typeof values.service === 'string' ? [values.service as MicrosoftService] : [...MICROSOFT_SERVICES];
  for (const service of selected) {
    const access = services[service];
    const legacy = service === 'mail' ? !!(values['allow-send'] || values['allow-drafts'] || values['allow-modify']) : service === 'calendar' ? !!values['allow-calendar-write'] : !!values['allow-write'];
    let write: boolean | undefined = values['drafts-only'] === true ? service === 'mail' : values['read-only'] === true ? false : values.write === true || legacy ? true : undefined;
    if (write === undefined && !preserve && access.enabled && io.stdoutIsTTY && io.readLine) {
      const answer = (await io.readLine(`${service}: [r]ead only / read + [w]rite [r]: `)).trim().toLowerCase();
      if (!['', 'r', 'read', 'w', 'write'].includes(answer)) throw new PerchError('Choose r or w.', 'usage');
      write = answer === 'w' || answer === 'write';
    }
    if (write !== undefined) {
      access.write = access.enabled && write;
      if (service === 'mail') access.draftsOnly = access.write && values['drafts-only'] === true;
    }
    if (!access.write) access.invite = false;
  }
  if (values['allow-invites'] === true) {
    if (!services.calendar.enabled || !services.calendar.write) throw new PerchError('--allow-invites requires an enabled calendar with write access.', 'usage');
    services.calendar.invite = true;
  }
}
function showGroup(io: Io, group: MicrosoftSessionGroup) {
  io.stdout(`\n${group.id}  ${JSON.stringify(group.label)}  ${group.email}\n`);
  for (const service of MICROSOFT_SERVICES) {
    const a = group.services[service];
    io.stdout(`  ${group.members[service]}  ${service}: ${a.status}${a.errorCode ? ` (${a.errorCode})` : ''}; ${a.enabled ? a.write ? a.draftsOnly ? 'read + draft' : 'read + write' : 'read-only' : 'not enabled'}${a.invite ? ' + invitations' : ''}\n`);
  }
  for (const site of group.sites) io.stdout(`  ${site.id}  ${JSON.stringify(site.url)}  ${site.driveIds.length} selected libraries\n`);
  if (MICROSOFT_SERVICES.some((s) => group.services[s].status !== 'ready')) io.stdout(`Check access: perch microsoft doctor ${group.id}\nSign in again: perch microsoft reconnect ${group.id}\n`);
}
function showBlockedHosts(io: Io, values: unknown[], groupId: string) {
  const hosts = [...new Set(values.slice(0, 100).filter((value): value is string => {
    if (typeof value !== 'string' || value.length > 253 || !value.includes('.')) return false;
    if (!value.split('.').every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(part))) return false;
    if (/(?:^|\.)(?:localhost|local|internal|invalid|onion)$|(?:^|\.)home\.arpa$/i.test(value)) return false;
    try { return !isIP(new URL(`https://${value}`).hostname); } catch { return false; }
  }).map((value) => value.toLowerCase()))].slice(0, 20);
  if (!hosts.length) return;
  io.stdout(`\nBlocked browser hosts: ${hosts.join(', ')}\n`);
  io.stdout(`For trusted hosts only: PERCH_MICROSOFT_ALLOWED_HOSTS='HOSTNAME[,HOSTNAME]' perch microsoft doctor ${groupId}\n`);
  io.stdout('Use the same host setting for reconnect and the Perch server.\n');
}
async function showUnregisteredProfiles(config: PerchConfig, io: Io, registered: ReadonlySet<string>) {
  const root = path.join(config.dataDir, 'microsoft-sessions');
  let names: string[];
  try { await assertPrivateDir(root); names = await readdir(root); }
  catch (err) { if (err instanceof PerchError && err.code === 'not_initialised') return; throw err; }
  for (const id of names.filter((v) => /^ms-session-[a-f0-9]{24}$/.test(v) && !registered.has(v))) {
    const dir = path.join(root, id); await assertPrivateDir(dir);
    const meta = JSON.parse((await readPrivateFile(path.join(dir, 'profile.json'))).toString('utf8'));
    if (!meta || typeof meta.label !== 'string' || sessionProfileId(meta.label) !== id) throw new PerchError('Invalid Microsoft session profile metadata.', 'bad_config');
    io.stdout(`${id}  ${JSON.stringify(meta.label)}  unverified (retained profile, no MCP account)\n`);
  }
}
async function sitesFor(values: Record<string, unknown>, io: Io, existing?: MicrosoftSessionGroup): Promise<SelectedSite[]> {
  let input: string[] | undefined;
  if (values.site !== undefined) {
    input = typeof values.site === 'string' ? [values.site] : Array.isArray(values.site) && values.site.every((x) => typeof x === 'string') ? values.site as string[] : undefined;
    if (!input) throw new PerchError('--site requires an HTTPS SharePoint or OneDrive for Business site URL.', 'usage');
  } else if (existing) return structuredClone(existing.sites);
  else input = [];
  if (input.length > 100) throw new PerchError('At most 100 sites can be selected.', 'usage');
  const sites: SelectedSite[] = structuredClone(existing?.sites ?? []);
  for (const raw of input) {
    const url = normalizeSelectedSiteUrl(raw);
    if (sites.some((s) => s.url === url)) continue;
    const known = existing?.sites.find((s) => s.url === url);
    sites.push(known ? structuredClone(known) : { id: newAccountId('ms-site', sites.map((s) => s.id)), url, kind: new URL(url).hostname.includes('-my.sharepoint.') ? 'onedrive' : 'sharepoint', driveIds: [], autoDiscoverLibraries: true });
  }
  return sites;
}
function collectLibraries(report: SessionProbeReport, previous?: MicrosoftSessionGroup): SelectedSite[] {
  return report.sites.map(site => {
    const before = previous?.sites.find(s => s.url === site.url);
    const found = report.libraries.find(entry => entry.siteId === site.id);
    // Existing explicit scopes stay narrow on reconnect. New sites are included in the confirmation.
    const driveIds = before && !before.autoDiscoverLibraries ? before.driveIds : found?.drives.map(d => d.id) ?? before?.driveIds ?? [];
    return { ...site, ...(before ? { autoDiscoverLibraries: before.autoDiscoverLibraries } : {}), driveIds: [...new Set(driveIds)] };
  });
}
function showDiscovery(io: Io, report: SessionProbeReport, sites: SelectedSite[]) {
  io.stdout('\nDetected Microsoft services:\n');
  for (const service of MICROSOFT_SERVICES) io.stdout(`  ${service}: ${report.services[service].status}${report.services[service].errorCode ? ` (${report.services[service].errorCode})` : ''}\n`);
  for (const site of sites) {
    io.stdout(`  ${site.kind}: ${JSON.stringify(site.url)} — ${site.driveIds.length} libraries\n`);
    for (const id of site.driveIds) {
      const drive = report.libraries.find(l => l.siteId === site.id)?.drives.find(d => d.id === id);
      io.stdout(`    ${JSON.stringify(drive?.name ?? id)}\n`);
    }
  }
  for (const source of report.discovery ?? []) io.stdout(`  File discovery ${source.source}: ${source.status}${source.code ? ` (${source.code})` : ''}\n`);
  const truncated = report.libraries.filter(l => l.hasMore).length;
  if (truncated) io.stdout(`${truncated} sites have more libraries; only verified results are included (up to 100 per site).\n`);
  if (report.fileErrors?.length) io.stdout(`${report.fileErrors.length} sites could not be fully checked.\n`);
  if (report.discovery?.some(s => s.status !== 'complete') || report.fileErrors?.length || truncated) {
    io.stdout('File discovery is incomplete. Retry with reconnect or add a missing site with --site URL.\n');
  }
}
async function confirmDiscoveredAccess(services: MicrosoftSessionGroup['services'], values: Record<string, unknown>, io: Io, preserve: boolean): Promise<boolean> {
  if (values.write === true || values['read-only'] === true || values['drafts-only'] === true) { await applyAccess(services, values, io, true); return true; }
  if (!io.stdoutIsTTY || !io.readLine) throw new PerchError('Confirm discovered access with --read-only, --drafts-only or --write, or use an interactive terminal.', 'no_tty');
  const prompt = preserve
    ? 'Connect all detected services: [k]eep access / [r]ead / read + [d]raft mail / read + [w]rite / [n] cancel [k]: '
    : 'Connect all detected services: [r]ead / read + [d]raft mail / read + [w]rite / [n] cancel [r]: ';
  const answer = (await io.readLine(prompt)).trim().toLowerCase();
  if (['n', 'no', 'nein'].includes(answer)) return false;
  if (!['', 'r', 'read', 'd', 'draft', 'w', 'write', ...(preserve ? ['k', 'keep'] : [])].includes(answer)) throw new PerchError('Choose r, d, w or n (k keeps existing rights on reconnect).', 'usage');
  const keep = preserve && ['', 'k', 'keep'].includes(answer);
  await applyAccess(services, keep ? values : { ...values, write: ['w', 'write'].includes(answer), 'drafts-only': ['d', 'draft'].includes(answer), 'read-only': !['w', 'write', 'd', 'draft'].includes(answer) }, io, true);
  return true;
}
function probeServices(report: SessionProbeReport, sites: SelectedSite[], previous?: MicrosoftSessionGroup, preserveAccess = false): MicrosoftSessionGroup['services'] {
  const services = structuredClone(report.services);
  for (const name of MICROSOFT_SERVICES) {
    const before = previous?.services[name];
    services[name] = { ...services[name], enabled: preserveAccess ? before?.enabled === true : services[name].status === 'ready' || before?.enabled === true, write: before?.write ?? false, ...(before?.draftsOnly ? { draftsOnly: true } : {}), invite: before?.invite ?? false };
  }
  if (!sites.some((s) => s.driveIds.length)) services.files = { ...services.files, enabled: false, write: false, invite: false, status: 'unavailable' };
  return services;
}
async function serverLogin(config: PerchConfig, io: Io, label: string, values: Record<string, unknown>, deps: MicrosoftSessionCliDependencies, suppliedProfile?: Awaited<ReturnType<typeof openSessionProfile>>) {
  const port = values.port === undefined ? 8783 : Number(values.port);
  const seconds = values.timeout === undefined ? 900 : Number(values.timeout);
  if (!Number.isInteger(port) || port < 0 || port > 65535 || !Number.isInteger(seconds) || seconds < 30 || seconds > 900) throw new PerchError('Session --port must be 0-65535 and --timeout 30-900 seconds.', 'usage');
  const sshHost = typeof values['ssh-host'] === 'string' ? values['ssh-host'] : undefined;
  if (sshHost && !/^[a-zA-Z0-9_][a-zA-Z0-9_.@:[\]-]{0,200}$/.test(sshHost)) throw new PerchError('--ssh-host must be an SSH alias or user@host without options or whitespace.', 'usage');
  let executable: string;
  try { executable = await deps.findBrowser(io.env); }
  catch (error) {
    if (error instanceof PerchError && error.message.startsWith('No executable Chrome/Chromium found.')) throw new PerchError(`${error.message}\nInstall Chrome or Chromium for your Perch user (Debian/Ubuntu: sudo apt install chromium).`, error.code);
    throw error;
  }

  const profile = suppliedProfile ?? await deps.openProfile(config.dataDir, label);
  let browser: Awaited<ReturnType<typeof launchSessionBrowser>> | undefined;
  let viewer: Awaited<ReturnType<typeof startSessionViewer>> | undefined;
  let wasInterrupted = false;
  const interrupted = () => { wasInterrupted = true; void viewer?.close(); };
  process.on('SIGINT', interrupted); process.on('SIGTERM', interrupted);
  try {
    browser = await deps.launchBrowser(executable, profile.path, undefined, { extraHosts: (io.env.PERCH_MICROSOFT_ALLOWED_HOSTS ?? '').split(',').map((host) => host.trim()).filter(Boolean) });
    if (wasInterrupted) throw new PerchError('Login cancelled; profile retained.', 'cancelled');
    viewer = await deps.startViewer(browser, { port, timeoutMs: seconds * 1000 });
    if (wasInterrupted) { await viewer.close(); throw new PerchError('Login cancelled; profile retained.', 'cancelled'); }
    io.stdout(sessionInstructions(viewer.url, sshHost));
    const result = await viewer.done;
    if (result !== 'finished' || wasInterrupted) throw new PerchError(`${result === 'expired' ? 'Login window expired' : 'Login cancelled'}; profile retained.\nRestart:\n${sessionResumeCommand(label, new URL(viewer.url).port ? Number(new URL(viewer.url).port) : port, sshHost)}`, result === 'expired' ? 'login_expired' : 'cancelled');
  } finally {
    process.removeListener('SIGINT', interrupted); process.removeListener('SIGTERM', interrupted);
    try { if (viewer) await viewer.close(); else if (browser) await browser.close(); }
    finally { await profile.release(); }
  }
}

/** Verify the exact helper from this Perch install before executing downloaded code. */
export function localLoginCommand(port: number, token: string, helperSha256: string, sshHost = 'USER@SERVER'): string {
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !/^[a-f0-9]{64}$/.test(token) || !/^[a-f0-9]{64}$/.test(helperSha256) || !/^(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(sshHost) || sshHost.length > 253) throw new PerchError('Invalid local login command.', 'usage');
  const verifier = `const a=[];let n=0;for await(const c of process.stdin){if((n+=c.length)>1048576)throw Error("Helper too large");a.push(c)}const b=Buffer.concat(a);if((await import("node:crypto")).createHash("sha256").update(b).digest("hex")!=="${helperSha256}")throw Error("Login expired or helper changed. Restart on server.");await(await import("data:text/javascript;base64,"+b.toString("base64"))).run(process.argv.slice(1))`;
  return `ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes ${quote(sshHost)} ${quote(`curl --fail --silent --show-error --max-time 15 http://127.0.0.1:${port}/helper.mjs`)} | node --input-type=module -e ${quote(verifier)} -- --ssh ${quote(sshHost)} --port ${port} --token ${quote(token)}`;
}
async function localLogin(config: PerchConfig, io: Io, label: string, values: Record<string, unknown>, deps: MicrosoftSessionCliDependencies, profile: Awaited<ReturnType<typeof openSessionProfile>>) {
  const port = values.port === undefined ? 8783 : Number(values.port);
  const seconds = values.timeout === undefined ? 900 : Number(values.timeout);
  let sshHost = typeof values['ssh-host'] === 'string' ? values['ssh-host'] : undefined;
  if (sshHost === undefined) {
    if (!io.readLine || !io.stdoutIsTTY) throw new PerchError('Provide --ssh-host with the SSH alias or USER@SERVER used on your computer.', 'usage');
    sshHost = (await io.readLine('SSH destination on your computer (alias or USER@SERVER): ')).trim();
  }
  if (!Number.isInteger(port) || port < 0 || port > 65535 || !Number.isInteger(seconds) || seconds < 30 || seconds > 900) throw new PerchError('Session --port must be 0-65535 and --timeout 30-900 seconds.', 'usage');
  if (sshHost !== undefined && (!/^(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(sshHost) || sshHost.length > 253)) throw new PerchError('--ssh-host must be an SSH alias or user@host without options or whitespace.', 'usage');
  const extraHosts = (io.env.PERCH_MICROSOFT_ALLOWED_HOSTS ?? '').split(',').map(host => host.trim()).filter(Boolean);
  let receiver: Awaited<ReturnType<typeof startLocalSessionReceiver>> | undefined;
  let browser: Awaited<ReturnType<typeof launchSessionBrowser>> | undefined;
  let stopped = false;
  const interrupt = () => { stopped = true; void receiver?.close(); void browser?.close(); };
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  try {
    const executable = await deps.findBrowser(io.env);
    receiver = await deps.startLocalReceiver({ port, timeoutMs: seconds * 1000, label, extraHosts });
    if (stopped) throw new PerchError('Login cancelled.', 'cancelled');
    io.stdout('\nKeep this terminal open. On your Mac (Node.js 22+ and Chrome):\n\n1. Run this command in a second terminal:\n   ' + localLoginCommand(receiver.port, receiver.token, receiver.helperSha256, sshHost) + '\n' +
      '2. Sign in to Microsoft in Chrome using Touch ID. Then press Enter in the Mac terminal.\n3. Confirm access here.\n');
    const state = await receiver.done;
    if (!state || stopped) throw new PerchError(`Login cancelled or expired. Restart:\n${sessionResumeCommand(label, receiver.port, sshHost)}`, 'cancelled');
    io.stdout('\nSign-in received. Checking server access …\n');
    browser = await deps.launchBrowser(executable, profile.path, 'about:blank', { extraHosts });
    if (stopped) throw new PerchError('Login cancelled.', 'cancelled');
    await deps.importState(browser, state);
    if (stopped) throw new PerchError('Login cancelled.', 'cancelled');
  } finally {
    process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt);
    try { await receiver?.close(); await browser?.close(); } finally { await profile.release(); }
  }
}

export async function cmdMicrosoftSession(config: PerchConfig, io: Io, sub: string | undefined, values: Record<string, unknown>, rest: string[] = [], injected: Partial<MicrosoftSessionCliDependencies> = {}): Promise<void> {
  const deps = { ...defaults, ...injected };
  checkAccess(values);
  if (!['add', 'sessions', 'list', 'reconnect', 'access', 'remove', 'doctor'].includes(sub ?? '')) throw usage();
  const reuseSession = values['reuse-session'] === true;
  if (reuseSession && (sub !== 'reconnect' || values['server-login'] === true)) throw new PerchError('--reuse-session is only for microsoft reconnect and cannot be combined with --server-login.', 'usage');
  if (sub === 'add') {
    if (typeof values.label !== 'string') throw usage();
    validateLabel(values.label); sessionProfileId(values.label);
    io.stdout('\nYour Microsoft sign-in will be stored on this server.\n');
    if (values.yes !== true) {
      if (!io.readLine) throw new PerchError('Use an interactive terminal or --yes. Microsoft login still requires browser interaction.', 'no_tty');
      if (!/^(y|yes|j|ja)$/i.test((await io.readLine('Start Microsoft sign-in? [y/N] ')).trim())) { io.stdout('Cancelled; no browser started.\n'); return; }
    }
  }
  const store = await deps.openStore(config);
  const groups = (await store.read()).microsoftSessions ?? [];
  if (sub === 'sessions' || sub === 'list') {
    for (const group of groups) showGroup(io, group);
    await showUnregisteredProfiles(config, io, new Set(groups.map((g) => g.profileId)));
    if (!groups.length) io.stdout('No registered Microsoft session groups. Connect: perch microsoft add --session --label NAME\n');
    return;
  }
  const existing = sub === 'add' ? groups.find((g) => g.profileId === sessionProfileId(values.label as string)) : groups.find((g) => g.id === rest[0]);
  if (sub !== 'add' && !existing) throw new PerchError('Unknown Microsoft session group. Run perch microsoft sessions.', 'unknown_account');
  if (existing && values.label !== undefined && values.label !== existing.label) throw new PerchError('Reconnect must use the original group label and profile.', 'identity_mismatch');
  if (existing && existing.profileId !== sessionProfileId(existing.label)) throw new PerchError('Stored label no longer matches the original session profile.', 'identity_mismatch');
  const assertCurrent = (current: MicrosoftSessionGroup | undefined) => {
    if (!existing || !current || current.revision !== existing.revision || !sameIdentity(current.identity, existing.identity)) throw new PerchError('The Microsoft session group changed during this operation. Retry.', 'account_changed');
  };
  if (sub === 'remove') {
    const profile = await deps.openProfile(config.dataDir, existing!.label);
    let emptyRoot: string | undefined;
    try {
      if (profile.id !== existing!.profileId) throw new PerchError('Microsoft profile identity changed.', 'identity_mismatch');
      await store.update((data) => { const current = data.microsoftSessions?.find((g) => g.id === existing!.id); assertCurrent(current); data.microsoftSessions = data.microsoftSessions!.filter((g) => g.id !== existing!.id); });
      try { emptyRoot = await deps.removeProfileContents(profile, config.dataDir); }
      catch { throw new PerchError('The group was removed, but local profile cleanup failed. Stop its browser and remove the private profile directory before reconnecting.', 'profile_cleanup_failed'); }
    } finally { await profile.release(); }
    // Never recursively remove after releasing the lock: another explicit add might have created a new profile.
    if (emptyRoot) try { await rmdir(emptyRoot); } catch (error) { if (!['ENOENT', 'ENOTEMPTY', 'EEXIST'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error; }
    io.stdout(`Removed ${existing!.id}, its service accounts, and its local browser credentials. Microsoft-side sessions were not revoked.\n`);
    return;
  }
  if (sub === 'access') {
    const services = structuredClone(existing!.services);
    await applyAccess(services, values, io);
    await store.update((data) => { const current = data.microsoftSessions?.find((g) => g.id === existing!.id); assertCurrent(current); Object.assign(current!, { services, updatedAt: new Date().toISOString(), revision: revision() }); });
    showGroup(io, { ...existing!, services });
    io.stdout('Clients still require matching grants to write. Changes take effect on the next operation.\n');
    return;
  }
  const runtime = await deps.createRuntime(store, io.env);
  const label = existing?.label ?? values.label as string;
  let sites = sub === 'doctor' ? structuredClone(existing!.sites) : await sitesFor(values, io, existing);
  const useLocal = values['server-login'] !== true;
  if (reuseSession) {
    // Refuse a missing saved browser rather than silently staging a new profile.
    const savedProfile = await deps.openProfile(config.dataDir, label, { existing: true });
    try { if (savedProfile.id !== existing!.profileId) throw new PerchError('Microsoft profile identity changed.', 'identity_mismatch'); }
    finally { await savedProfile.release(); }
  }
  const stage = (existing || useLocal) && sub !== 'doctor' ? await deps.stageProfile(config.dataDir, label, { empty: useLocal && !reuseSession }) : undefined;
  try {
    if (reuseSession) {
      await stage!.release();
    } else if (sub !== 'doctor') {
      if (useLocal) await localLogin(config, io, label, values, deps, stage!);
      else await serverLogin(config, io, label, values, deps, stage);
    }
    const probeLabel = stage?.probeLabel ?? label;
    io.stdout('\nChecking Microsoft identity and services …\n');
    const report = await runtime.probeProfile(probeLabel, sites, existing?.identity, (status) => io.stdout(`${status}\n`), sub !== 'doctor');
    const blockedHosts = [...(report.blockedHosts ?? [])];
    requireIdentity(report, existing?.identity);
    if (sub !== 'doctor') {
      sites = collectLibraries(report, existing);
      showDiscovery(io, report, sites);
    }
    const services = probeServices(report, sites, existing, sub === 'doctor');
    if (sub !== 'doctor' && !await confirmDiscoveredAccess(services, values, io, !!existing)) {
      io.stdout('Cancelled; no accounts or permissions saved.\n'); return;
    }
    const now = new Date().toISOString();
    let saved!: MicrosoftSessionGroup;
    await store.update(async (data) => {
      const all = data.microsoftSessions ??= [];
      const current = existing ? all.find((g) => g.id === existing.id) : undefined;
      if (existing) assertCurrent(current);
      else if (all.some((g) => g.profileId === sessionProfileId(label) || sameIdentity(g.identity, report.identity))) throw new PerchError('This Microsoft identity or profile is already registered. Use perch microsoft reconnect GROUP_ID.', 'duplicate_account');
      const taken = all.flatMap((g) => [g.id, ...Object.values(g.members)]);
      saved = MicrosoftSessionGroupSchema.parse({ id: existing?.id ?? newAccountId('mgroup', taken), label, profileId: existing?.profileId ?? sessionProfileId(label), identity: existing?.identity ?? report.identity, email: report.email, ...(report.displayName ? { displayName: report.displayName } : {}), members: existing?.members ?? { teams: newAccountId('msteams', taken), mail: newAccountId('msmail', taken), calendar: newAccountId('mscalendar', taken), files: newAccountId('msfiles', taken) }, services, sites, createdAt: existing?.createdAt ?? now, updatedAt: now, revision: sub === 'doctor' ? existing!.revision : revision() });
      await stage?.commit();
      if (current) Object.assign(current, saved); else all.push(saved);
    });
    showGroup(io, saved);
    showBlockedHosts(io, blockedHosts, saved.id);
    io.stdout(`\nSaved Microsoft connection for ${saved.email}. Enabled services are available through MCP.\n`);
    io.stdout(`Check connection: perch microsoft doctor ${saved.id}\n`);
    if (sub !== 'doctor') {
      io.stdout('Client access to all current and future services:\n  perch client add --label NAME --full\n');
      const caps: string[] = [], ids: string[] = [];
      for (const service of MICROSOFT_SERVICES) {
        const access = saved.services[service]; if (!access.enabled) continue;
        ids.push(saved.members[service]);
        if (service === 'mail') caps.push('read', ...(access.write ? access.draftsOnly ? ['draft'] : ['draft', 'send', 'modify'] : []));
        if (service === 'teams') caps.push('microsoft_teams_read', ...(access.write ? ['microsoft_teams_send'] : []));
        if (service === 'calendar') caps.push('microsoft_calendar_read', ...(access.write ? ['microsoft_calendar_write'] : []), ...(access.invite ? ['microsoft_calendar_invite'] : []));
        if (service === 'files') caps.push('microsoft_files_read', ...(access.write ? ['microsoft_files_write'] : []));
      }
      if (ids.length) io.stdout(`Client access to this group only:\n  perch client add --label NAME --allow ${caps.join(',')} ${ids.map((id) => `--account ${id}`).join(' ')}\n`);
      io.stdout('Sign-in saved on the server. You can close your Mac.\n');
    }
  } finally { await stage?.discard(); }
}
