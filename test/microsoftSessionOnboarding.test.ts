import { describe, expect, it, vi } from 'vitest';
import { cmdMicrosoftSession, type MicrosoftSessionCliDependencies, type SessionProbeReport } from '../src/cli/microsoftSession.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { resolveConfig } from '../src/config.js';
import { sessionProfileId } from '../src/microsoft/sessionBrowser.js';
import { MicrosoftSessionGroupSchema } from '../src/microsoft/session/model.js';
import { makeTempDirs } from './support/fixtures.js';
import { runCli } from '../src/cli/run.js';

const identity = { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', mailboxId: 'mailbox', kind: 'organization' as const };
const report = (): SessionProbeReport => ({ identity, email: 'self@example.test', displayName: 'Self', services: { teams: { enabled: true, write: false, invite: false, status: 'ready' }, mail: { enabled: true, write: false, invite: false, status: 'ready' }, calendar: { enabled: true, write: false, invite: false, status: 'ready' }, files: { enabled: false, write: false, invite: false, status: 'unavailable' } }, sites: [], libraries: [] });
async function fixture(action: (f: { store: CredentialStore; invoke: (sub: string, values?: Record<string, unknown>, rest?: string[]) => Promise<void>; events: string[]; output: () => string; answers: string[]; reports: SessionProbeReport[]; probes: unknown[]; outcomes: Array<'finished' | 'expired' | 'closed'>; deps: MicrosoftSessionCliDependencies; env: NodeJS.ProcessEnv }) => Promise<void>) {
  const dirs = await makeTempDirs();
  try {
    await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    const env = { HOME: dirs.root, PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile };
    const config = { ...resolveConfig(env), dataDir: dirs.dataDir, keyFile: dirs.keyFile };
    const events: string[] = [], answers: string[] = [], reports: SessionProbeReport[] = [], probes: unknown[] = [];
    const outcomes: Array<'finished' | 'expired' | 'closed'> = [];
    let output = '';
    const deps: MicrosoftSessionCliDependencies = {
      openStore: async () => store,
      findBrowser: async () => '/mock/chrome',
      openProfile: async (_dataDir, label) => { events.push('profile-open'); return { id: sessionProfileId(label), path: '/mock/profile', release: async () => { events.push('profile-release'); } }; },
      launchBrowser: async () => { events.push('browser-start'); return { close: async () => { events.push('browser-close'); } } as any; },
      startLocalReceiver: async () => { events.push('receiver-start'); return {port:8783,token:'a'.repeat(64),helperSha256:'b'.repeat(64),done:Promise.resolve((outcomes.shift() ?? 'finished') === 'finished' ? {version:1 as const,cookies:[],origins:[]} : undefined),close:async()=>{events.push('receiver-close');}}; },
      importState: async () => { events.push('state-import'); },
      startViewer: async () => ({ url: 'http://127.0.0.1:8783/#test-secret', done: Promise.resolve(outcomes.shift() ?? 'finished'), close: async () => { events.push('viewer-close'); } }),
      createRuntime: async () => ({ probeProfile: async (label, sites, expected, _onProgress, discover) => { events.push('probe'); probes.push({ label, sites: structuredClone(sites), expected, discover }); return reports.shift() ?? report(); } }),
      stageProfile: async (_dataDir, label) => { let committed = false; events.push('stage-open'); return { id: sessionProfileId(label), path: '/mock/staged-profile', probeLabel: 'staged-test', release: async () => { events.push('stage-release'); }, commit: async () => { events.push('stage-commit'); committed = true; }, discard: async () => { if (!committed) events.push('stage-discard'); } }; },
      removeProfileContents: async () => { events.push('profile-delete'); return undefined; },
    };
    const invoke = (sub: string, values: Record<string, unknown> = {}, rest: string[] = []) => cmdMicrosoftSession(config, { env, stdout: (s) => { output += s; }, stdoutIsTTY: true, readLine: async () => answers.shift() ?? '' }, sub, { 'ssh-host': 'example-server', ...values }, rest, deps);
    await action({ store, invoke, events, output: () => output, answers, reports, probes, outcomes, deps, env });
  } finally { await dirs.cleanup(); }
}

describe('verified Microsoft session onboarding', () => {
  it('signs in before discovery without asking for sites and confirms all services once', async () => fixture(async (f) => {
    const prompts: string[] = [];
    const found = report();
    found.sites = [{ id: 'ms-site-12345678', url: 'https://tenant.sharepoint.com/sites/Team', kind: 'sharepoint', driveIds: [] }];
    found.libraries = [{ siteId: 'ms-site-12345678', drives: [{ id: 'documents', name: 'Documents' }] }];
    found.services.files = { enabled: true, write: false, invite: false, status: 'ready' };
    f.reports.push(found);
    await cmdMicrosoftSession(resolveConfig(f.env), { env: f.env, stdout: () => {}, stdoutIsTTY: true,
      readLine: async prompt => { prompts.push(prompt); return 'w'; } }, 'add', { label: 'Auto', yes: true, 'ssh-host': 'example-server' }, [], f.deps);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toMatch(/all|alle/i);
    expect(prompts.join(' ')).not.toMatch(/site URLs|library numbers/);
    const group = (await f.store.read()).microsoftSessions![0]!;
    expect(group.sites[0]?.driveIds).toEqual(['documents']);
    expect(Object.values(group.services).every(s => s.enabled && s.write)).toBe(true);
    expect(group.services.calendar.invite).toBe(false);
  }));
  it('cancels after discovery without registering any account', async () => fixture(async (f) => {
    f.answers.push('n');
    await f.invoke('add', { label: 'Cancel', yes: true });
    expect((await f.store.read()).microsoftSessions ?? []).toEqual([]);
    expect(f.events).toContain('probe');
  }));

  it('releases the imported profile before probing and registers verified readonly members', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    const [group] = (await f.store.read()).microsoftSessions!;
    expect(group).toMatchObject({ label: 'Work', identity, email: 'self@example.test', profileId: sessionProfileId('Work') });
    expect(group!.members.mail).toMatch(/^msmail-/);
    expect(group!.services.mail).toMatchObject({ enabled: true, write: false, status: 'ready' });
    expect(group!.services.files.enabled).toBe(false);
    expect(f.events.indexOf('probe')).toBeGreaterThan(f.events.indexOf('stage-release'));
    expect(f.output()).toContain('MCP');
  }));
  it('passes the selected CLI environment host allowlist to the browser without adding blocked hosts', async () => fixture(async (f) => {
    f.env.PERCH_MICROSOFT_ALLOWED_HOSTS = ' trusted.example.org, cdn.example.org, ';
    let options: unknown;
    f.deps.launchBrowser = async (_executable, _profile, _url, value) => { options = value; return { close: async () => {} } as any; };
    f.reports.push({ ...report(), blockedHosts: ['untrusted.example.org'] });
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    expect(options).toEqual({ extraHosts: ['trusted.example.org', 'cdn.example.org'] });
    expect(f.env.PERCH_MICROSOFT_ALLOWED_HOSTS).toBe(' trusted.example.org, cdn.example.org, ');
  }));
  it('prints bounded hostname-only diagnostics and an explicit operator-controlled allowlist hint', async () => fixture(async (f) => {
    f.reports.push({ ...report(), blockedHosts: ['CDN.example.org', 'cdn.example.org', 'https://host.example.org/path?secret=hidden', 'bad.example.org\nInjected', '127.0.0.1', 'host.local', 'valid.example.org'] });
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    expect(f.output()).toContain('Blocked browser hosts: cdn.example.org, valid.example.org');
    expect(f.output()).toContain('PERCH_MICROSOFT_ALLOWED_HOSTS');
    expect(f.output()).toContain('For trusted hosts only');
    expect(f.output()).not.toContain('secret=hidden');
    expect(f.output()).not.toContain('Injected');
    expect(f.output()).not.toContain('host.local');
    expect((await f.store.read()).microsoftSessions![0]).not.toHaveProperty('blockedHosts');
  }));
  it('omits the allowlist hint when no valid blocked hosts were reported', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    expect(f.output()).not.toContain('PERCH_MICROSOFT_ALLOWED_HOSTS');
    expect(f.output()).not.toMatch(/Browser gefunden|Sandbox bleibt|Systempakete|Entra-App|Browserprofil/);
  }));
  it('preserves stable member IDs and write preferences on reconnect', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, write: true, 'allow-invites': true });
    const original = (await f.store.read()).microsoftSessions![0]!;
    await f.invoke('reconnect', { yes: true }, [original.id]);
    const current = (await f.store.read()).microsoftSessions![0]!;
    expect(current.members).toEqual(original.members);
    expect(current.profileId).toBe(original.profileId);
    expect(current.revision).not.toBe(original.revision);
    expect(current.services.calendar).toMatchObject({ write: true, invite: true });
    expect(f.probes[1]).toMatchObject({ label: 'staged-test', expected: identity });
    expect(f.events.lastIndexOf('stage-commit')).toBeGreaterThan(f.events.lastIndexOf('probe'));
  }));
  it.each(['write', 'read-only', 'keep'] as const)('reuses a staged copy without login and confirms %s access while preserving IDs and explicit scopes', async mode => fixture(async f => {
    const first = report(); first.services.teams = { enabled: false, write: false, invite: false, status: 'unavailable' };
    first.services.files = { enabled: true, write: false, invite: false, status: 'ready' };
    first.sites = [{ id: 'ms-site-12345678', url: 'https://tenant.sharepoint.com/sites/Team', kind: 'sharepoint', driveIds: [] }];
    first.libraries = [{ siteId: 'ms-site-12345678', drives: [{ id: 'chosen' }] }];
    f.reports.push(first);
    await f.invoke('add', { label: 'Work', yes: true, write: true });
    await f.store.update(data => { data.microsoftSessions![0]!.sites[0]!.autoDiscoverLibraries = false; });
    const original = (await f.store.read()).microsoftSessions![0]!;
    const next = report(); next.services.files = first.services.files;
    next.sites = structuredClone(original.sites);
    next.libraries = [{ siteId: 'ms-site-12345678', drives: [{ id: 'chosen' }, { id: 'unselected' }] }];
    f.reports.push(next); f.events.length = 0;
    const stage = vi.fn(f.deps.stageProfile), open = vi.fn(f.deps.openProfile);
    f.deps.stageProfile = stage; f.deps.openProfile = open;
    await f.invoke('reconnect', { 'reuse-session': true, 'ssh-host': undefined, ...(mode === 'keep' ? {} : { [mode]: true }) }, [original.id]);
    expect(stage).toHaveBeenCalledWith(expect.any(String), original.label, { empty: false });
    expect(open).toHaveBeenCalledWith(expect.any(String), original.label, { existing: true });
    for (const event of ['receiver-start', 'browser-start', 'state-import', 'viewer-close']) expect(f.events).not.toContain(event);
    expect(f.events.indexOf('stage-release')).toBeLessThan(f.events.indexOf('probe'));
    expect(f.events.indexOf('stage-commit')).toBeGreaterThan(f.events.indexOf('probe'));
    expect(f.probes[1]).toMatchObject({ label: 'staged-test', expected: original.identity, discover: true });
    const current = (await f.store.read()).microsoftSessions![0]!;
    expect(current.members).toEqual(original.members);
    expect(current.id).toBe(original.id); expect(current.profileId).toBe(original.profileId);
    expect(current.sites).toEqual(original.sites);
    expect(current.services.teams).toMatchObject({ enabled: true, write: mode === 'write' });
    expect(current.services.mail.write).toBe(mode !== 'read-only');
    expect(current.services.calendar.invite).toBe(false);
  }));
  it.each(['cancel', 'identity'] as const)('does not replace a reused profile or save grants on %s', async reason => fixture(async f => {
    await f.invoke('add', { label: 'Work', yes: true, write: true });
    const before = (await f.store.read()).microsoftSessions![0]!;
    f.events.length = 0;
    if (reason === 'cancel') {
      f.answers.push('n');
      await f.invoke('reconnect', { 'reuse-session': true }, [before.id]);
    } else {
      f.reports.push({ ...report(), identity: { ...identity, mailboxId: 'different' } });
      await expect(f.invoke('reconnect', { 'reuse-session': true, write: true }, [before.id])).rejects.toMatchObject({ code: 'identity_mismatch' });
    }
    expect((await f.store.read()).microsoftSessions![0]).toEqual(before);
    expect(f.events).toContain('stage-discard');
    expect(f.events).not.toContain('stage-commit');
    expect(f.events).not.toContain('receiver-start');
  }));
  it('refuses reuse when the saved browser profile is missing before staging anything', async () => fixture(async f => {
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    const before = (await f.store.read()).microsoftSessions![0]!;
    f.events.length = 0;
    f.deps.openProfile = async () => { throw new Error('Saved profile missing'); };
    await expect(f.invoke('reconnect', { 'reuse-session': true, write: true }, [before.id])).rejects.toThrow('Saved profile missing');
    expect(f.events).toEqual([]);
    expect((await f.store.read()).microsoftSessions![0]).toEqual(before);
  }));
  it.each(['add', 'doctor', 'access', 'remove', 'list', 'sessions'])('rejects reuse-session for %s before opening profiles', async sub => fixture(async f => {
    await expect(f.invoke(sub, { 'reuse-session': true, label: 'Work', yes: true, write: true }, ['mgroup-12345678'])).rejects.toMatchObject({ code: 'usage' });
    expect(f.events).toEqual([]);
  }));
  it('rejects reuse-session together with server-login', async () => fixture(async f => {
    await expect(f.invoke('reconnect', { 'reuse-session': true, 'server-login': true }, ['mgroup-12345678'])).rejects.toMatchObject({ code: 'usage' });
    expect(f.events).toEqual([]);
  }));
  it('parses reuse-session and restricts it to the Microsoft reconnect command', async () => fixture(async f => {
    let stderr = '';
    const io = { env: f.env, stdout: () => {}, stderr: (s: string) => { stderr += s; }, readSecret: async () => '' };
    expect(await runCli(['microsoft', 'reconnect', 'mgroup-12345678', '--reuse-session', '--write'], io)).not.toBe(0);
    expect(stderr).toContain('Unknown Microsoft session group');
    for (const args of [['accounts'], ['microsoft', 'doctor', 'mgroup-12345678'], ['microsoft', 'remove', 'microsoft-12345678']]) {
      stderr = '';
      expect(await runCli([...args, '--reuse-session'], io)).toBe(2);
      expect(stderr).toContain('--reuse-session');
      expect(stderr).not.toContain('Invalid arguments.');
    }
  }));
  it('rejects changed identity or changed mailbox on reconnect before saving', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    const before = (await f.store.read()).microsoftSessions![0]!;
    f.events.length = 0;
    f.reports.push({ ...report(), identity: { ...identity, mailboxId: 'different' } });
    await expect(f.invoke('reconnect', { yes: true }, [before.id])).rejects.toThrow(/identity|mailbox|different/i);
    expect((await f.store.read()).microsoftSessions![0]).toEqual(before);
    expect(f.events).toContain('stage-discard');
    expect(f.events).not.toContain('stage-commit');
    await expect(f.invoke('reconnect', { yes: true, label: 'Other' }, [before.id])).rejects.toThrow(/label|profile/i);
  }));
  it('adds an optional site without a library-number prompt and keeps existing scopes on reconnect', async () => fixture(async (f) => {
    const first = report(); first.services.files = { enabled: true, write: false, invite: false, status: 'ready' };
    Object.defineProperty(first, 'sites', { get: () => (f.probes[0] as any).sites });
    Object.defineProperty(first, 'libraries', { get: () => [{ siteId: (f.probes[0] as any).sites[0].id, drives: [{ id: 'drive-one' }, { id: 'drive-two' }] }] });
    f.reports.push(first);
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true, site: ['https://tenant.sharepoint.com/sites/Project'] });
    const group = (await f.store.read()).microsoftSessions![0]!;
    expect(group.sites[0]!.driveIds).toEqual(['drive-one', 'drive-two']);
    expect(group.services.files).toMatchObject({ enabled: true, status: 'ready' });
    expect(f.probes).toHaveLength(1);
    // A previously restricted scope must not widen just because a site has more libraries now.
    await f.store.update(data => { data.microsoftSessions![0]!.sites[0]!.driveIds = ['drive-one']; data.microsoftSessions![0]!.sites[0]!.autoDiscoverLibraries = false; });
    const next = report(); next.services.files = first.services.files;
    next.sites = structuredClone(group.sites); next.sites[0]!.driveIds = ['drive-one'];
    next.libraries = [{ siteId: group.sites[0]!.id, drives: [{ id: 'drive-one' }, { id: 'drive-two' }, { id: 'new-drive' }] }];
    f.reports.push(next);
    await f.invoke('reconnect', { 'read-only': true }, [group.id]);
    expect((await f.store.read()).microsoftSessions![0]!.sites[0]!.driveIds).toEqual(['drive-one']);
  }));
  it('reports partial discovery without hiding working services', async () => fixture(async (f) => {
    f.reports.push({ ...report(), discovery: [{ source: 'onedrive', status: 'unavailable', code: 'access_denied' }] });
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    expect(f.output()).toContain('File discovery is incomplete');
    expect((await f.store.read()).microsoftSessions![0]!.services.mail.enabled).toBe(true);
  }));
  it('cancels reconnect after new discovery without replacing profile, scope or permissions', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, write: true });
    const original = (await f.store.read()).microsoftSessions![0]!;
    const next = report(); next.sites = [{ id: 'ms-site-12345678', url: 'https://tenant.sharepoint.com/sites/New', kind: 'sharepoint', driveIds: [] }];
    next.libraries = [{ siteId: 'ms-site-12345678', drives: [{ id: 'new-drive' }] }];
    f.reports.push(next); f.answers.push('n'); f.events.length = 0;
    await f.invoke('reconnect', {}, [original.id]);
    expect((await f.store.read()).microsoftSessions![0]).toEqual(original);
    expect(f.events).toContain('stage-discard'); expect(f.events).not.toContain('stage-commit');
  }));
  it('changes one service access locally and removes invitation rights on downgrade', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, write: true, 'allow-invites': true });
    const before = (await f.store.read()).microsoftSessions![0]!;
    const probes = f.probes.length;
    await f.invoke('access', { service: 'calendar', 'read-only': true }, [before.id]);
    const after = (await f.store.read()).microsoftSessions![0]!;
    expect(after.services.calendar).toMatchObject({ write: false, invite: false });
    expect(after.services.mail.write).toBe(true);
    expect(after.revision).not.toBe(before.revision);
    expect(f.probes).toHaveLength(probes);
    await f.invoke('remove', {}, [before.id]);
    expect((await f.store.read()).microsoftSessions).toEqual([]);
    expect(f.events).toContain('profile-delete');
    expect(f.events.lastIndexOf('profile-release')).toBeGreaterThan(f.events.indexOf('profile-delete'));
  }));
  it('keeps the registered group and credentials when removal cannot acquire the profile lock', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    const original = (await f.store.read()).microsoftSessions![0]!;
    f.deps.openProfile = async () => { throw new Error('Microsoft browser profile is busy'); };
    await expect(f.invoke('remove', {}, [original.id])).rejects.toThrow(/busy/);
    expect((await f.store.read()).microsoftSessions![0]).toEqual(original);
    expect(f.events).not.toContain('profile-delete');
  }));
  it('reconnect retries automatic sites that had no accessible libraries at the first login', async () => fixture(async f => {
    const first = report(); first.sites = [{ id: 'ms-site-12345678', url: 'https://tenant.sharepoint.com/sites/Team', kind: 'sharepoint', driveIds: [], autoDiscoverLibraries: true }];
    f.reports.push(first);
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    const original = (await f.store.read()).microsoftSessions![0]!;
    const next = report(); next.sites = structuredClone(first.sites);
    next.libraries = [{ siteId: 'ms-site-12345678', drives: [{ id: 'new-drive' }] }];
    next.services.files.status = 'ready'; f.reports.push(next);
    await f.invoke('reconnect', {}, [original.id]);
    expect((await f.store.read()).microsoftSessions![0]!.sites[0]!.driveIds).toEqual(['new-drive']);
  }));
  it('doctor preserves disabled service permissions even when the probe becomes ready', async () => fixture(async f => {
    const first = report(); first.services.teams = { enabled: false, write: false, invite: false, status: 'unavailable' };
    f.reports.push(first);
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    const original = (await f.store.read()).microsoftSessions![0]!;
    await f.invoke('doctor', {}, [original.id]);
    expect((await f.store.read()).microsoftSessions![0]!.services.teams).toMatchObject({ enabled: false, write: false, invite: false, status: 'ready' });
  }));
  it('reconnect preserves an explicitly empty stored library scope', async () => fixture(async f => {
    const first = report(); first.sites = [{ id: 'ms-site-12345678', url: 'https://tenant.sharepoint.com/sites/Team', kind: 'sharepoint', driveIds: [] }];
    f.reports.push(first);
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    const original = (await f.store.read()).microsoftSessions![0]!;
    const next = report(); next.sites = structuredClone(first.sites);
    next.libraries = [{ siteId: 'ms-site-12345678', drives: [{ id: 'new-drive' }] }];
    next.services.files.status = 'ready'; f.reports.push(next);
    await f.invoke('reconnect', {}, [original.id]);
    expect((await f.store.read()).microsoftSessions![0]!.sites[0]!.driveIds).toEqual([]);
    expect((await f.store.read()).microsoftSessions![0]!.services.files.enabled).toBe(false);
  }));
  it('doctor checks the stored identity and reports degraded services without a login window', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    const group = (await f.store.read()).microsoftSessions![0]!;
    const diagnostic = report(); diagnostic.services.teams.status = 'reauth_required'; f.reports.push(diagnostic);
    const before = f.events.filter((e) => e === 'browser-start').length;
    await f.invoke('doctor', {}, [group.id]);
    expect(f.events.filter((e) => e === 'browser-start')).toHaveLength(before);
    expect((await f.store.read()).microsoftSessions![0]!.services.teams.status).toBe('reauth_required');
    expect(f.output()).toContain('reconnect');
  }));
  it('rejects unsafe sites and conflicting access flags before starting Chrome', async () => fixture(async (f) => {
    await expect(f.invoke('add', { label: 'Work', yes: true, site: ['https://evil.example/'] })).rejects.toThrow();
    await expect(f.invoke('add', { label: 'Work', yes: true, write: true, 'read-only': true })).rejects.toThrow();
    expect(f.events).not.toContain('browser-start');
  }));
  it.each(['expired', 'closed'] as const)('discards the candidate and never probes or registers after transfer %s', async (outcome) => fixture(async (f) => {
    f.outcomes.push(outcome);
    await expect(f.invoke('add', { label: 'Work', yes: true, 'read-only': true })).rejects.toThrow(/expired|cancelled/i);
    expect(f.events).toContain('stage-release');
    expect(f.events).not.toContain('probe');
    expect((await f.store.read()).microsoftSessions ?? []).toEqual([]);
  }));
  it('routes access/list/remove group commands and accepts session flags without touching Graph', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    const group = (await f.store.read()).microsoftSessions![0]!;
    let stdout = '', stderr = '';
    const io = { env: f.env, stdout: (s: string) => { stdout += s; }, stderr: (s: string) => { stderr += s; }, readSecret: async () => { throw new Error('No Graph secret prompt expected'); } };
    expect(await runCli(['microsoft', 'access', group.id, '--service', 'calendar', '--write', '--allow-invites'], io)).toBe(0);
    expect((await f.store.read()).microsoftSessions![0]!.services.calendar).toMatchObject({ write: true, invite: true });
    expect(await runCli(['microsoft', 'list'], io)).toBe(0);
    expect(stdout).toContain(group.members.calendar);
    expect(stderr).toBe('');
    expect(await runCli(['microsoft', 'remove', group.id], io)).toBe(0);
    expect((await f.store.read()).microsoftSessions).toEqual([]);
  }));
  it('prints immediately usable full and narrow client-grant commands plus doctor', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, write: true, 'allow-invites': true });
    const group = (await f.store.read()).microsoftSessions![0]!;
    expect(f.output()).toContain('perch client add --label NAME --full');
    expect(f.output()).toContain(`perch microsoft doctor ${group.id}`);
    expect(f.output()).toContain('microsoft_calendar_invite');
    expect(f.output()).toContain(`--account ${group.members.mail}`);
    expect(f.output()).not.toContain(`--account ${group.members.files}`);
  }));
  it('discards a cancelled reconnect candidate without modifying the registered group', async () => fixture(async (f) => {
    await f.invoke('add', { label: 'Work', yes: true, 'read-only': true });
    const original = (await f.store.read()).microsoftSessions![0]!;
    f.events.length = 0; f.outcomes.push('closed');
    await expect(f.invoke('reconnect', { yes: true }, [original.id])).rejects.toThrow(/cancelled/i);
    expect((await f.store.read()).microsoftSessions![0]).toEqual(original);
    expect(f.events).toContain('stage-discard');
    expect(f.events).not.toContain('stage-commit');
  }));
});

it('defaults to local transfer and closes the import browser before verifying and committing',async()=>fixture(async f=>{
 await f.invoke('add',{label:'Work',yes:true,'read-only':true,'ssh-host':'example-server'});
 expect(f.output()).toContain('Touch ID');expect(f.output()).toContain('example-server');
 expect(f.events.indexOf('state-import')).toBeGreaterThan(f.events.indexOf('receiver-start'));
 expect(f.events.indexOf('browser-close')).toBeGreaterThan(f.events.indexOf('state-import'));
 expect(f.events.indexOf('probe')).toBeGreaterThan(f.events.indexOf('browser-close'));
 expect(f.events.indexOf('stage-commit')).toBeGreaterThan(f.events.indexOf('probe'));
 expect(f.events).not.toContain('viewer-close');
}));
it('retains the server viewer only as an explicit fallback',async()=>fixture(async f=>{
 await f.invoke('add',{label:'Work',yes:true,'read-only':true,'server-login':true});
 expect(f.events).toContain('viewer-close');expect(f.events).not.toContain('receiver-start');
}));
it('discards a failed import without probing or registering accounts',async()=>fixture(async f=>{
 f.deps.importState=async()=>{throw new Error('mock import failure');};
 await expect(f.invoke('add',{label:'Work',yes:true})).rejects.toThrow();
 expect(f.events).toContain('browser-close');expect(f.events).toContain('stage-discard');
 expect(f.events).not.toContain('probe');expect(f.events).not.toContain('stage-commit');
 expect((await f.store.read()).microsoftSessions??[]).toEqual([]);
}));

it('asks for the actual client-side SSH destination when none is supplied',async()=>fixture(async f=>{
 f.answers.push('alice@my-own-box');
 await f.invoke('add',{label:'Work',yes:true,'read-only':true,'ssh-host':undefined});
 expect(f.output()).toContain("'alice@my-own-box'");
 expect(f.output()).not.toContain('example-server');expect(f.output()).not.toContain('USER@SERVER');
}));
it('rejects an empty SSH destination before opening the transfer receiver',async()=>fixture(async f=>{
 f.answers.push('');
 await expect(f.invoke('add',{label:'Work',yes:true,'ssh-host':undefined})).rejects.toThrow(/SSH|ssh/);
 expect(f.events).not.toContain('receiver-start');
}));
it('shows bounded service failure codes instead of only unavailable',async()=>fixture(async f=>{
 const next=report();next.services.calendar.status='unavailable';next.services.calendar.errorCode='browser_failed';f.reports.push(next);
 await f.invoke('add',{label:'Work',yes:true,'read-only':true});
 expect(f.output()).toContain('calendar: unavailable (browser_failed)');
}));

it('confirms draft-only mail while keeping other discovered services read-only', async () => fixture(async f => {
  f.answers.push('d');
  await f.invoke('add', { label: 'Drafts', yes: true });
  const group = (await f.store.read()).microsoftSessions![0]!;
  expect(group.services.mail).toMatchObject({ enabled: true, write: true, draftsOnly: true });
  for (const service of ['teams', 'calendar', 'files'] as const) expect(group.services[service].write).toBe(false);
  expect(f.output()).toContain('read + draft');
  await f.invoke('access', { service: 'mail', 'read-only': true }, [group.id]);
  expect((await f.store.read()).microsoftSessions![0]!.services.mail).toMatchObject({ write: false, draftsOnly: false });
}));


it.each(['keep', 'drafts-only', 'write', 'read-only'] as const)('preserves or explicitly changes draft-only access on reused reconnect: %s', async mode => fixture(async f => {
  await f.invoke('add', { label: 'Drafts', yes: true, 'drafts-only': true });
  const original = (await f.store.read()).microsoftSessions![0]!;
  f.events.length = 0;
  await f.invoke('reconnect', { 'reuse-session': true, ...(mode === 'keep' ? {} : { [mode]: true }) }, [original.id]);
  const current = (await f.store.read()).microsoftSessions![0]!;
  expect(current.members).toEqual(original.members);
  expect(current.services.mail).toMatchObject({ enabled: true, write: mode !== 'read-only', draftsOnly: mode === 'keep' || mode === 'drafts-only' });
  expect(current.services.calendar).toMatchObject({ write: mode === 'write', invite: false });
  expect(current.services.teams.write).toBe(mode === 'write');
  expect(f.events).not.toContain('receiver-start');
  expect(f.events).not.toContain('browser-start');
  expect(f.events).toContain('stage-commit');
  if (mode === 'keep' || mode === 'drafts-only') {
    const narrowGrant = f.output().trim().split('Client access to this group only:').at(-1)!;
    expect(narrowGrant).toContain('draft');
    expect(narrowGrant).not.toMatch(/(?:,|--allow )(?:send|modify)(?:,| )/);
  }
}));

it('doctor preserves the draft-only ceiling without changing its revision', async () => fixture(async f => {
  await f.invoke('add', { label: 'Drafts', yes: true, 'drafts-only': true });
  const original = (await f.store.read()).microsoftSessions![0]!;
  await f.invoke('doctor', {}, [original.id]);
  const current = (await f.store.read()).microsoftSessions![0]!;
  expect(current.services.mail).toEqual(original.services.mail);
  expect(current.revision).toBe(original.revision);
}));

it.each(['write', 'read-only', 'allow-send', 'allow-modify', 'allow-write', 'allow-calendar-write', 'allow-invites'])('rejects draft-only with %s before starting any profile or browser operation', async flag => fixture(async f => {
  await expect(f.invoke('add', { label: 'Drafts', yes: true, 'drafts-only': true, [flag]: true })).rejects.toMatchObject({ code: 'usage' });
  expect(f.events).toEqual([]);
}));

it.each(['teams', 'calendar', 'files'])('rejects draft-only access for %s', async service => fixture(async f => {
  await expect(f.invoke('access', { service, 'drafts-only': true }, ['mgroup-12345678'])).rejects.toMatchObject({ code: 'usage' });
  expect(f.events).toEqual([]);
}));

it('parses draft-only access and can explicitly upgrade mail to full write access', async () => fixture(async f => {
  await f.invoke('add', { label: 'Drafts', yes: true, 'read-only': true });
  const original = (await f.store.read()).microsoftSessions![0]!;
  let stderr = '';
  const io = { env: f.env, stdout: () => {}, stderr: (s: string) => { stderr += s; }, readSecret: async () => '' };
  expect(await runCli(['microsoft', 'access', original.id, '--service', 'mail', '--drafts-only'], io)).toBe(0);
  expect((await f.store.read()).microsoftSessions![0]!.services.mail).toMatchObject({ write: true, draftsOnly: true });
  expect(await runCli(['microsoft', 'access', original.id, '--service', 'mail', '--write'], io)).toBe(0);
  expect((await f.store.read()).microsoftSessions![0]!.services.mail).toMatchObject({ write: true, draftsOnly: false });
  expect(stderr).toBe('');
}));
