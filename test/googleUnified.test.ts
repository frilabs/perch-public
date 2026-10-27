// One Google login for Drive, Gmail, Calendar and Contacts (docs/GOOGLE_UNIFIED_SPEC.md): account groups with a
// single stored refresh token, granular consent, shared refresh, removal, re-add as update, legacy commands, grants,
// perch setup and perch status. MOCK Google upstream only; nothing reaches Google.
import { writeFile } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { principalForClientToken } from '../src/auth/grants.js';
import { runSetup } from '../src/cli/onboarding.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import type { PerchConfig } from '../src/config.js';
import { createPerchContext } from '../src/context.js';
import { GoogleTokenProvider } from '../src/google/accounts.js';
import { PerchError } from '../src/errors.js';
import { grantOutcome, googleGroupScopes } from '../src/google/group.js';
import { sharedGrantHolders } from '../src/google/groupStore.js';
import { createProductivityTokenProvider } from '../src/google/productivity.js';
import { createGmailTokenProvider } from '../src/mail/gmailAccounts.js';
import { CredentialStore, type StoreData } from '../src/store/credentialStore.js';
import { collectStatus, formatStatusText } from '../src/status/status.js';
import { accountCapabilities, formatStatusTerminal } from '../src/status/terminal.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGoogleUnified, type MockGooglePerson } from './support/mockGoogleUnified.js';
import { SCOPE } from './support/mockProductivity.js';

const DRIVE_RO = 'https://www.googleapis.com/auth/drive.readonly';
const DRIVE = 'https://www.googleapis.com/auth/drive';
const GMAIL_RO = 'https://www.googleapis.com/auth/gmail.readonly';
const GMAIL_SEND = 'https://www.googleapis.com/auth/gmail.send';
const GMAIL_COMPOSE = 'https://www.googleapis.com/auth/gmail.compose';
const GMAIL_MODIFY = 'https://www.googleapis.com/auth/gmail.modify';

let dirs: TempDirs;
let out: string;
let err: string;
let google: MockGoogleUnified;
let clientFile: string;

function io(extra: Partial<CliIo> = {}): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root, PERCH_GOOGLE_CLIENT_FILE: clientFile },
    stdout: (s) => void (out += s),
    stderr: (s) => void (err += s),
    readSecret: async () => {
      throw new Error('no TTY in tests');
    },
    transport: google.transport,
    ...extra,
  };
}

/** stderr hook that approves the printed auth URL for `person` by calling the loopback redirect (MOCK consent). */
function approving(person: MockGooglePerson) {
  let done = false;
  return (s: string) => {
    err += s;
    const m = /https:\/\/accounts\.google\.com\S+/.exec(s);
    if (m && !done) {
      done = true;
      const url = new URL(m[0]);
      const code = google.approve(url.toString(), person);
      void fetch(`${url.searchParams.get('redirect_uri')}?code=${code}&state=${url.searchParams.get('state')}`);
    }
  };
}

async function add(person: MockGooglePerson, args: string[], extra: Partial<CliIo> = {}): Promise<number> {
  return runCli(['google', 'add', '--timeout', '10', ...args], io({ stderr: approving(person), ...extra }));
}

const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
const read = async () => (await openStore()).read();

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = '';
  err = '';
  google = new MockGoogleUnified();
  clientFile = `${dirs.root}/client.json`;
  await writeFile(clientFile, JSON.stringify({ installed: { client_id: dummySecret('C'), client_secret: dummySecret('S') } }), { mode: 0o600 });
  expect(await runCli(['init'], io())).toBe(0);
  out = '';
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('perch google add (one login for every service)', () => {
  it('one flow creates the group and all members; the refresh token is stored once', async () => {
    const p = google.addPerson('dummy.all@example.test');
    expect(await add(p, ['--label', 'Private']), err).toBe(0);
    // Without a terminal: every service, read-only.
    expect(err).toMatch(/Connecting all Google services/);
    expect(err).toMatch(/read-only/);
    const params = google.lastAuthParams!;
    expect(params.get('include_granted_scopes')).toBe('true');
    expect(params.get('scope')!.split(' ')).toEqual(['openid', 'email', DRIVE_RO, GMAIL_RO, SCOPE.calendarRead, SCOPE.contactsRead]);
    expect(google.tokenRequests).toEqual(['authorization_code']);

    const d = await read();
    expect(d.googleGroups).toHaveLength(1);
    const g = d.googleGroups[0]!;
    expect(g).toMatchObject({ label: 'Private', email: p.email, sub: p.sub, refreshToken: p.refreshToken });
    expect(d.google).toEqual([expect.objectContaining({ groupId: g.id, email: p.email, scopes: [DRIVE_RO] })]);
    expect(d.gmail).toEqual([expect.objectContaining({ groupId: g.id, scopes: [GMAIL_RO] })]);
    expect(d.googleProductivity).toEqual([expect.objectContaining({ groupId: g.id, services: ['calendar', 'contacts'], allowCalendarWrite: false })]);
    // Single source of truth: no member carries credentials.
    for (const m of [...d.google, ...d.gmail, ...d.googleProductivity]) {
      expect(m.refreshToken).toBeUndefined();
      expect(m.clientSecret).toBeUndefined();
      expect(m.id).toMatch(/^(google|gmail|gprod)-[a-f0-9]{8}$/);
    }
    expect(JSON.stringify(d).split(p.refreshToken)).toHaveLength(2);
    expect(out).toMatch(new RegExp(`Connected Google account group ${g.id} \\(dummy\\.all@example\\.test\\) as "Private", one login for:`));
    expect(out).toMatch(/Drive\s+google-[a-f0-9]{8}\s+read\n/);
    expect(out).toMatch(/Gmail\s+gmail-[a-f0-9]{8}\s+read\n/);
    expect(out).toMatch(/Calendar\s+gprod-[a-f0-9]{8}\s+read\n/);
    expect(out).toMatch(/Contacts\s+gprod-[a-f0-9]{8}\s+read\n/);
    expect(out + err).not.toContain(p.refreshToken);

    out = '';
    expect(await runCli(['google', 'list'], io())).toBe(0);
    expect(out).toMatch(new RegExp(`${g.id}\\s+"Private"\\s+dummy\\.all@example\\.test[\\s\\S]*Drive\\s+google-[\\s\\S]*Contacts\\s+gprod-`));
  });

  it('--services and --write request only the selected services, with their write scopes', async () => {
    const p = google.addPerson('dummy.rw@example.test');
    expect(await add(p, ['--label', 'Work', '--services', 'gmail,calendar', '--write']), err).toBe(0);
    expect(google.lastAuthParams!.get('scope')!.split(' ')).toEqual(['openid', 'email', GMAIL_RO, GMAIL_COMPOSE, GMAIL_MODIFY, SCOPE.calendarRead, SCOPE.calendarOwned]);
    const d = await read();
    expect(d.google).toEqual([]);
    expect(d.gmail[0]!.scopes).toEqual([GMAIL_RO, GMAIL_COMPOSE, GMAIL_MODIFY]);
    expect(d.googleProductivity[0]).toMatchObject({ services: ['calendar'], allowCalendarWrite: true });
    expect(out).toMatch(/Writes still need a client grant/);
  });

  it('rejects unknown services before any OAuth request', async () => {
    expect(await runCli(['google', 'add', '--label', 'X', '--services', 'drive,photos'], io())).toBe(1);
    expect(err).toMatch(/Unknown service: photos/);
    expect(google.calls).toEqual([]);
  });

  it('granular consent: connects only what Google granted and says what is missing', async () => {
    const p = google.addPerson('dummy.partial@example.test');
    google.untick = [GMAIL_RO, DRIVE];
    expect(await add(p, ['--label', 'Partial', '--write']), err).toBe(0);
    const d = await read();
    expect(d.gmail).toEqual([]);
    expect(d.google[0]!.scopes).toEqual([DRIVE_RO]);
    expect(d.googleProductivity[0]).toMatchObject({ services: ['calendar', 'contacts'], allowCalendarWrite: true });
    const gid = d.googleGroups[0]!.id;
    expect(out).toContain(`Not granted by Google (checkbox not ticked on the consent screen): Gmail. Not connected. To add later: perch google access ${gid} --add gmail\n`);
    expect(out).toMatch(new RegExp(`Not granted by Google: Drive write .*Drive is connected read-only\\. To add it: perch google access ${gid} --service drive --write\\n`));
    expect(out).toContain(`Change the read/write access of single services: perch google access ${gid}\n`);
    // Granted Gmail write scopes without gmail.readonly do not connect Gmail.
    expect(JSON.stringify(d.googleGroups[0]!.scopes)).toContain(GMAIL_COMPOSE);
  });

  it('stores nothing when Google granted none of the selected services', async () => {
    const p = google.addPerson('dummy.none@example.test');
    google.untick = [DRIVE_RO];
    expect(await add(p, ['--label', 'None', '--services', 'drive'])).toBe(1);
    expect(err).toMatch(/granted none of the selected services \(Drive\); nothing was stored/);
    expect((await read()).googleGroups).toEqual([]);
  });

  it('grantOutcome and googleGroupScopes evaluate the request (unit)', () => {
    const req = { services: ['drive', 'gmail'] as const, driveWrite: true, gmail: { drafts: false, send: true, modify: false }, calendarWrite: false };
    expect(googleGroupScopes({ ...req, services: [...req.services] })).toEqual(['openid', 'email', DRIVE_RO, DRIVE, GMAIL_RO, GMAIL_SEND]);
    expect(grantOutcome({ ...req, services: [...req.services] }, ['openid', DRIVE, GMAIL_RO])).toEqual({
      connected: ['drive', 'gmail'],
      denied: [],
      missingWrites: [{ service: 'gmail', what: 'Gmail send', flag: '--allow-send' }],
    });
  });
});

describe('re-adding the same Google account updates its group', () => {
  it('keeps the ids, adds services and permissions, replaces the login; no duplicates', async () => {
    const p = google.addPerson('dummy.again@example.test');
    expect(await add(p, ['--label', 'Private', '--services', 'drive,calendar'])).toBe(0);
    const before = await read();
    const driveId = before.google[0]!.id;
    const prodId = before.googleProductivity[0]!.id;
    const groupId = before.googleGroups[0]!.id;
    const firstToken = before.googleGroups[0]!.refreshToken;

    out = '';
    expect(await add(p, ['--label', 'Private', '--services', 'gmail,contacts', '--allow-send', '--yes']), err).toBe(0);
    // include_granted_scopes: the earlier Drive and Calendar scopes are part of the new grant.
    expect(google.lastAuthParams!.get('scope')!.split(' ')).toEqual(['openid', 'email', GMAIL_RO, GMAIL_SEND, SCOPE.contactsRead]);
    const d = await read();
    expect(d.googleGroups).toHaveLength(1);
    expect(d.googleGroups[0]).toMatchObject({ id: groupId, refreshToken: p.refreshToken });
    expect(d.googleGroups[0]!.refreshToken).not.toBe(firstToken);
    expect(d.google.map((a) => a.id)).toEqual([driveId]);
    expect(d.google[0]!.scopes).toEqual([DRIVE_RO]);
    expect(d.gmail[0]).toMatchObject({ groupId, scopes: [GMAIL_RO, GMAIL_SEND] });
    expect(d.googleProductivity.map((a) => a.id)).toEqual([prodId]);
    expect(d.googleProductivity[0]!.services).toEqual(['calendar', 'contacts']);
    expect(out).toMatch(new RegExp(`Updated Google account group ${groupId}`));
  });

  it('asks before updating; "n" leaves the store unchanged', async () => {
    const p = google.addPerson('dummy.ask@example.test');
    expect(await add(p, ['--label', 'Private', '--services', 'drive'])).toBe(0);
    const before = await read();
    const questions: string[] = [];
    const answers = ['contacts', 'r', 'n'];
    const code = await add(p, ['--label', 'Private'], {
      readLine: async (q) => {
        questions.push(q);
        return answers.shift()!;
      },
    });
    expect(code).toBe(1);
    expect(questions[2]).toMatch(/already connected as Google account group ggroup-[a-f0-9]{8} "Private" \(Drive\)\. Update it/);
    expect(err).toMatch(/Nothing changed/);
    expect(await read()).toEqual(before);
  });

  it('a member connected separately stays unchanged and is reported, the rest joins the group', async () => {
    const p = google.addPerson('dummy.mixed@example.test');
    // Legacy Gmail account with its own login.
    expect(await runCli(['gmail', 'add', '--label', 'Old', '--read-only', '--timeout', '10'], io({ stderr: approving(p) })), err).toBe(0);
    const legacy = (await read()).gmail[0]!;
    expect(legacy.groupId).toBeUndefined();
    out = '';
    expect(await add(p, ['--label', 'New', '--services', 'drive,gmail'])).toBe(0);
    const d = await read();
    expect(d.gmail).toEqual([legacy]);
    expect(d.google[0]!.groupId).toBe(d.googleGroups[0]!.id);
    expect(out).toMatch(new RegExp(`Gmail of dummy\\.mixed@example\\.test is already connected separately as ${legacy.id} and was left unchanged`));
  });
});

describe('one login, one refresh', () => {
  it('concurrent calls across Drive, Gmail and Calendar members make exactly one token request', async () => {
    const p = google.addPerson('dummy.shared@example.test');
    expect(await add(p, ['--label', 'Shared'])).toBe(0);
    const d = await read();
    google.tokenRequests = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    google.beforeRefreshResponse = () => gate;
    const ctx = createPerchContext(await openStore(), google.transport);
    const pending = [
      ctx.tokens.drive.getAccessToken(d.google[0]!.id),
      ctx.tokens.gmail.getAccessToken(d.gmail[0]!.id),
      ctx.tokens.productivity.getAccessToken(d.googleProductivity[0]!.id),
      ctx.tokens.drive.getAccessToken(d.google[0]!.id),
    ];
    await new Promise((r) => setTimeout(r, 20));
    release();
    const tokens = await Promise.all(pending);
    expect(new Set(tokens).size).toBe(1);
    expect(google.tokenRequests).toEqual(['refresh_token']);
    // Cached for every member afterwards; the live scopes come from the shared login.
    await ctx.tokens.gmail.getAccessToken(d.gmail[0]!.id);
    expect(google.tokenRequests).toEqual(['refresh_token']);
    expect(ctx.tokens.productivity.lastGrantedScopes(d.googleProductivity[0]!.id)).toContain(SCOPE.calendarRead);
    // Invalidating through one member drops the shared token for all of them.
    ctx.tokens.drive.invalidate(d.google[0]!.id);
    google.beforeRefreshResponse = undefined;
    await ctx.tokens.productivity.getAccessToken(d.googleProductivity[0]!.id);
    expect(google.tokenRequests).toEqual(['refresh_token', 'refresh_token']);
  });

  it('providers built separately on the same store and upstream share the group login too', async () => {
    const p = google.addPerson('dummy.separate@example.test');
    expect(await add(p, ['--label', 'S', '--services', 'drive,gmail,calendar'])).toBe(0);
    const d = await read();
    google.tokenRequests = [];
    const store = await openStore();
    const upstream = new Upstream(google.transport);
    await Promise.all([
      new GoogleTokenProvider(store, upstream).getAccessToken(d.google[0]!.id),
      createGmailTokenProvider(store, upstream).getAccessToken(d.gmail[0]!.id),
      createProductivityTokenProvider(store, upstream).getAccessToken(d.googleProductivity[0]!.id),
    ]);
    expect(google.tokenRequests).toEqual(['refresh_token']);
  });

  it('a rotated refresh token is persisted once, on the group', async () => {
    const p = google.addPerson('dummy.rotate@example.test');
    expect(await add(p, ['--label', 'R', '--services', 'gmail'])).toBe(0);
    const d = await read();
    const rotated = dummySecret('ROTATED');
    const orig = google.transport;
    const transport: typeof orig = async (req) => {
      const res = await orig(req);
      if (new URLSearchParams(req.body ?? '').get('grant_type') !== 'refresh_token') return res;
      // Simulate Google rotating the refresh token for the whole grant.
      for (const x of google.people) if (x.email === p.email) Object.assign(x, { refreshToken: rotated }), Object.assign(x.prod, { refreshToken: rotated });
      const body = JSON.parse(res.body.toString('utf8')) as Record<string, unknown>;
      return { ...res, body: Buffer.from(JSON.stringify({ ...body, refresh_token: rotated })) };
    };
    const ctx = createPerchContext(await openStore(), transport);
    await ctx.tokens.gmail.getAccessToken(d.gmail[0]!.id);
    const after = await read();
    expect(after.googleGroups[0]!.refreshToken).toBe(rotated);
    expect(after.gmail[0]!.refreshToken).toBeUndefined();
  });

  it('invalid_grant on the shared login fails every member alike, with the group in the hint', async () => {
    const p = google.addPerson('dummy.revoked@example.test');
    expect(await add(p, ['--label', 'Evil "$(touch x)"'])).toBe(0);
    const d = await read();
    const groupId = d.googleGroups[0]!.id;
    google.revokeGrant(p);
    const ctx = createPerchContext(await openStore(), google.transport);
    for (const e of [
      await rejection(ctx.tokens.drive.getAccessToken(d.google[0]!.id)),
      await rejection(ctx.tokens.gmail.getAccessToken(d.gmail[0]!.id)),
      await rejection(ctx.tokens.productivity.getAccessToken(d.googleProductivity[0]!.id)),
    ]) {
      expect((e as { code?: string }).code).toBe('grant_invalid');
      expect(e.message).toContain(`Google grant for ${groupId} was revoked or expired`);
      expect(e.message).toContain('perch google add --label <label>');
      expect(e.message).not.toContain('$(touch x)');
    }
    const report = await collectStatus(ctx, { live: true });
    expect(report.accounts.filter((a) => a.groupId === groupId).map((a) => a.check?.state)).toEqual(['error', 'error', 'error']);
  });
});

describe('perch google remove', () => {
  it('removes the whole group and revokes the shared login once', async () => {
    const p = google.addPerson('dummy.rm@example.test');
    expect(await add(p, ['--label', 'Rm'])).toBe(0);
    const token = p.refreshToken;
    const d = await read();
    out = '';
    expect(await runCli(['google', 'remove', d.googleGroups[0]!.id, '--revoke'], io()), err).toBe(0);
    expect(google.revoked).toEqual([token]);
    const after = await read();
    expect([after.googleGroups, after.google, after.gmail, after.googleProductivity]).toEqual([[], [], [], []]);
    expect(out).toMatch(/revoked at Google once/);
  });

  it('--service removes one service without revoking; the last one removes the group', async () => {
    const p = google.addPerson('dummy.one@example.test');
    expect(await add(p, ['--label', 'One', '--services', 'gmail,calendar,contacts'])).toBe(0);
    const g = (await read()).googleGroups[0]!;
    expect(await runCli(['google', 'remove', g.id, '--service', 'gmail', '--revoke'], io())).toBe(1);
    expect(err).toMatch(/--revoke cannot be combined with --service/);
    out = '';
    expect(await runCli(['google', 'remove', g.id, '--service', 'gmail'], io()), err).toBe(0);
    expect(out).toMatch(/Removed Gmail from Google account group .* not revoked: it is shared/s);
    let d = await read();
    expect(d.gmail).toEqual([]);
    expect(d.googleGroups).toHaveLength(1);
    expect(await runCli(['google', 'remove', g.id, '--service', 'calendar'], io())).toBe(0);
    d = await read();
    expect(d.googleProductivity[0]).toMatchObject({ services: ['contacts'], allowCalendarWrite: false });
    expect(await runCli(['google', 'remove', g.id, '--service', 'drive'], io())).toBe(1);
    expect(err).toMatch(/does not connect Drive/);
    out = '';
    expect(await runCli(['google', 'remove', g.id, '--service', 'contacts'], io())).toBe(0);
    expect(out).toMatch(/last service, so the group and its stored login were removed too/);
    d = await read();
    expect([d.googleGroups, d.googleProductivity]).toEqual([[], []]);
    expect(google.revoked).toEqual([]);
  });
});

describe('legacy commands keep working', () => {
  it('perch gmail add and google-productivity add still create separate accounts and print the new way', async () => {
    const p = google.addPerson('dummy.legacy@example.test');
    expect(await runCli(['gmail', 'add', '--label', 'G', '--read-only', '--timeout', '10'], io({ stderr: approving(p) })), err).toBe(0);
    expect(google.lastAuthParams!.get('include_granted_scopes')).toBe('false');
    expect(out).toMatch(/One login for Drive, Gmail, Calendar and Contacts: perch google add/);
    const q = google.addPerson('dummy.legacy2@example.test');
    expect(await runCli(['google-productivity', 'add', '--label', 'C', '--services', 'calendar', '--read-only', '--timeout', '10'], io({ stderr: approving(q) })), err).toBe(0);
    const d = await read();
    expect(d.gmail[0]).toMatchObject({ refreshToken: expect.any(String) });
    expect(d.gmail[0]!.groupId).toBeUndefined();
    expect(d.googleProductivity[0]!.groupId).toBeUndefined();
    expect(d.googleGroups).toEqual([]);
    // Old Drive-only behaviour through --services drive.
    const r = google.addPerson('dummy.drive@example.test');
    expect(await add(r, ['--label', 'D', '--services', 'drive', '--allow-write'])).toBe(0);
    expect((await read()).google[0]!.scopes).toEqual([DRIVE_RO, DRIVE]);
    out = '';
    expect(await runCli(['accounts'], io())).toBe(0);
    expect(out).toMatch(/gmail-[a-f0-9]{8}\s+"G"/);
    expect(out).toMatch(/Google accounts \(one login per account/);
  });

  it('legacy add for a grouped account names the group; legacy remove only detaches, never revokes', async () => {
    const p = google.addPerson('dummy.grouped@example.test');
    expect(await add(p, ['--label', 'Grp', '--services', 'gmail,calendar'])).toBe(0);
    const d = await read();
    const gid = d.googleGroups[0]!.id;
    expect(await runCli(['gmail', 'add', '--label', 'Dup', '--read-only', '--timeout', '10'], io({ stderr: approving(p) }))).toBe(1);
    expect(err).toMatch(new RegExp(`already connected as gmail-[a-f0-9]{8} in group ${gid}`));
    expect(await runCli(['gmail', 'remove', d.gmail[0]!.id, '--revoke'], io())).toBe(1);
    expect(err).toMatch(new RegExp(`perch google remove ${gid} --revoke`));
    out = '';
    expect(await runCli(['gmail', 'remove', d.gmail[0]!.id], io())).toBe(0);
    expect(out).toMatch(new RegExp(`from Google account group ${gid}.*shared login stays`));
    expect(await runCli(['google-productivity', 'remove', d.googleProductivity[0]!.id], io())).toBe(0);
    const after = await read();
    expect([after.googleGroups, after.gmail, after.googleProductivity]).toEqual([[], [], []]);
    expect(google.revoked).toEqual([]);
  });
});

describe('client grants on group members', () => {
  it('grants and tools work per member id, families unchanged', async () => {
    const p = google.addPerson('dummy.grant@example.test');
    p.drive.files.push({ id: 'f1', name: 'Plan.txt', mimeType: 'text/plain', content: Buffer.from('hello') });
    expect(await add(p, ['--label', 'Grant'])).toBe(0);
    const d = await read();
    const ids = [d.google[0]!.id, d.gmail[0]!.id, d.googleProductivity[0]!.id];
    const tokenFile = `${dirs.root}/config/clients/g.token`;
    expect(await runCli(['client', 'add', '--label', 'C', '--allow', 'drive_read,read,calendar_read', '--account', ids[0]!, '--account', ids[1]!, '--account', ids[2]!, '--token-file', tokenFile], io()), err).toBe(0);
    // A group id is not an account id: grants stay per member.
    expect(await runCli(['client', 'add', '--label', 'X', '--allow', 'read', '--account', d.googleGroups[0]!.id, '--token-file', `${dirs.root}/config/clients/x.token`], io())).toBe(1);
    const store = await openStore();
    const { readFile } = await import('node:fs/promises');
    const principal = (await principalForClientToken(store, (await readFile(tokenFile, 'utf8')).trim()))!;
    const ctx = createPerchContext(store, google.transport);
    google.tokenRequests = [];
    const [files, cals, mail] = await Promise.all([
      ctx.drive.search({ accountId: ids[0]! }, principal),
      ctx.calendar.listCalendars(principal, { accountId: ids[2]! }),
      ctx.mail.search(principal, { accountId: ids[1]! }),
    ]);
    expect(files.results.map((f) => f.name)).toEqual(['Plan.txt']);
    expect(cals.results[0]).toMatchObject({ accountId: ids[2] });
    expect(mail.errors).toEqual([]);
    expect(google.tokenRequests).toEqual(['refresh_token']);
  });
});

describe('perch setup', () => {
  it('has a single Google step that runs perch google add', async () => {
    const answers = ['y', 'Private', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n'];
    const asked: string[] = [];
    const runs: string[][] = [];
    const code = await runSetup(
      { googleClientFile: clientFile, allowedHosts: [] } as unknown as PerchConfig,
      { stdout: (s) => void (out += s), stderr: (s) => void (err += s), readLine: async (q) => (asked.push(q), answers.shift() ?? 'n') },
      async (argv) => (runs.push(argv), 0),
    );
    expect(code).toBe(0);
    expect(asked[0]).toBe('Connect Google account (Drive, Gmail, Calendar, Contacts)? [y/N] ');
    expect(asked.filter((q) => /^Connect .*(Google|Gmail|Calendar)/.test(q))).toEqual([
      'Connect Google account (Drive, Gmail, Calendar, Contacts)? [y/N] ',
      'Connect another Google account? [y/N] ',
    ]);
    expect(runs).toContainEqual(['google', 'add', '--label', 'Private', '--port', '8766']);
    expect(runs.some((r) => r[0] === 'gmail' || r[0] === 'google-productivity')).toBe(false);
  });
});

describe('perch status with Google account groups', () => {
  async function connected(): Promise<{ d: StoreData; ctx: ReturnType<typeof createPerchContext> }> {
    const p = google.addPerson('dummy.status@example.test');
    expect(await add(p, ['--label', 'Private', '--services', 'drive,gmail,calendar'])).toBe(0);
    return { d: await read(), ctx: createPerchContext(await openStore(), google.transport) };
  }

  it('groups the members in json, plain text and the terminal view; hints suggest perch google access', async () => {
    const { d, ctx } = await connected();
    const g = d.googleGroups[0]!;
    const report = await collectStatus(ctx, { live: true });
    expect(report.googleGroups).toEqual([{ id: g.id, label: 'Private', email: g.email, services: ['drive', 'gmail', 'calendar'], accountIds: [d.google[0]!.id, d.gmail[0]!.id, d.googleProductivity[0]!.id], connectedAt: g.createdAt }]);
    expect(report.accounts.filter((a) => a.groupId === g.id).every((a) => a.check?.state === 'ok')).toBe(true);
    // One refresh for the three live checks.
    expect(google.tokenRequests.filter((t) => t === 'refresh_token')).toHaveLength(1);

    const plain = formatStatusText(report);
    expect(plain).toMatch(new RegExp(`Google accounts \\(one login each\\)\\n  ${g.id}  "Private"  dummy\\.status@example\\.test  services: drive, gmail, calendar`));
    expect(plain).toMatch(/\n    Google Drive: ✓ google-/);
    expect(plain).not.toMatch(/^Google Drive/m);

    const term = formatStatusTerminal(report, accountCapabilities(await read()), { tty: false, env: {} });
    expect(term).toMatch(/── Google · Private ─+\n☑ Private  dummy\.status@example\.test +one login · 3 services\n/);
    expect(term).toContain(`  ☐ Contacts   not connected (read contacts)\n      perch google access ${g.id} --add contacts\n`);
    expect(term).toMatch(new RegExp(`☑ Gmail {6}${d.gmail[0]!.id} +ok · \\d+ ms\\n {4}☑ read {3}☐ drafts {3}☐ send {3}☐ organize\\n {6}perch google access ${g.id} --service gmail --write\\n`));
    // Missing write permission of a member: changed through perch google access (same ids, no remove, no re-add).
    expect(term).toContain(`      perch google access ${g.id} --service drive --write\n`);
    expect(term).not.toMatch(/perch google (add|remove)/);
    expect(term).not.toMatch(/── Google Drive ─/);
    expect(term).not.toMatch(/☐ Google Drive /);

    const json = JSON.parse(JSON.stringify(report)) as typeof report;
    expect(json.accounts.find((a) => a.id === d.gmail[0]!.id)?.groupId).toBe(g.id);
    expect(JSON.stringify(report)).not.toContain(g.refreshToken);
  });

  it('CLI perch status --plain and --json render the group', async () => {
    await connected();
    out = '';
    expect(await runCli(['status', '--no-check', '--plain'], io())).toBe(0);
    expect(out).toMatch(/Google accounts \(one login each\)/);
    out = '';
    expect(await runCli(['status', '--no-check', '--json'], io())).toBe(0);
    expect((JSON.parse(out) as { googleGroups: unknown[] }).googleGroups).toHaveLength(1);
  });
});

describe('store schema', () => {
  it('rejects a group member with its own credentials, an unknown group or no credentials at all', async () => {
    const p = google.addPerson('dummy.schema@example.test');
    expect(await add(p, ['--label', 'S', '--services', 'gmail'])).toBe(0);
    const store = await openStore();
    await expect(store.update((d) => void (d.gmail[0]!.refreshToken = dummySecret('SECOND-COPY')))).rejects.toThrow(/schema/);
    await expect(store.update((d) => void (d.gmail[0]!.groupId = 'ggroup-00000000'))).rejects.toThrow(/schema/);
    await expect(store.update((d) => void delete d.gmail[0]!.groupId)).rejects.toThrow(/schema/);
    expect((await store.read()).gmail[0]!.groupId).toBe((await store.read()).googleGroups[0]!.id);
  });
});

describe('review fixes', () => {
  // M1: Google's revoke ends the whole grant of the OAuth client for the Google account.
  it('M1: --revoke of a group is refused while a separate login of the same account and client exists; --force revokes and says so', async () => {
    const p = google.addPerson('dummy.shared.revoke@example.test');
    expect(await runCli(['gmail', 'add', '--label', 'Old', '--read-only', '--timeout', '10'], io({ stderr: approving(p) })), err).toBe(0);
    expect(await add(p, ['--label', 'New', '--services', 'drive'])).toBe(0);
    const before = await read();
    const gid = before.googleGroups[0]!.id;
    const legacy = before.gmail[0]!.id;
    expect(await runCli(['google', 'remove', gid, '--revoke'], io())).toBe(1);
    expect(err).toContain(`Revoking the Google login of ${gid} would also end access for ${legacy} ("Old", dummy.shared.revoke@example.test)`);
    expect(err).toMatch(/add --force to revoke anyway/);
    expect(google.revoked).toEqual([]);
    expect(await read()).toEqual(before);
    // --force without --revoke is a usage error.
    expect(await runCli(['google', 'remove', gid, '--force'], io())).toBe(2);
    out = '';
    expect(await runCli(['google', 'remove', gid, '--revoke', '--force'], io()), err).toBe(0);
    expect(google.revoked).toHaveLength(1);
    expect(out).toContain(`--force: Google revoked the whole grant of this OAuth client for the account, so these lost access too: ${legacy} ("Old")`);
    const after = await read();
    expect(after.googleGroups).toEqual([]);
    expect(after.gmail.map((a) => a.id)).toEqual([legacy]);
  });

  it('M1: legacy remove --revoke of a separate account is refused while a group of the same account and client exists', async () => {
    const p = google.addPerson('dummy.legacy.revoke@example.test');
    expect(await runCli(['google-productivity', 'add', '--label', 'Cal', '--services', 'calendar', '--read-only', '--timeout', '10'], io({ stderr: approving(p) })), err).toBe(0);
    expect(await add(p, ['--label', 'Grp', '--services', 'gmail'])).toBe(0);
    const d = await read();
    const prod = d.googleProductivity[0]!;
    const gid = d.googleGroups[0]!.id;
    expect(await runCli(['google-productivity', 'remove', prod.id, '--revoke'], io())).toBe(1);
    expect(err).toContain(`Revoking the Google login of ${prod.id} would also end access for ${gid} ("Grp"`);
    expect(google.revoked).toEqual([]);
    out = '';
    expect(await runCli(['google-productivity', 'remove', prod.id, '--revoke', '--force'], io()), err).toBe(0);
    expect(google.revoked).toHaveLength(1);
    expect(out).toContain(`these lost access too: ${gid} ("Grp")`);
  });

  it('M1: other OAuth clients and other Google accounts do not block a revoke (unit)', () => {
    const base = { label: 'L', scopes: [], createdAt: 'x', updatedAt: 'x' };
    const data = {
      googleGroups: [
        { ...base, id: 'ggroup-00000001', email: 'a@example.test', sub: 'S1', clientId: 'C1', clientSecret: 's', refreshToken: 'r' },
        { ...base, id: 'ggroup-00000002', email: 'a@example.test', sub: 'S1', clientId: 'C2', clientSecret: 's', refreshToken: 'r' },
        { ...base, id: 'ggroup-00000003', email: 'b@example.test', sub: 'S2', clientId: 'C1', clientSecret: 's', refreshToken: 'r' },
      ],
      google: [{ ...base, id: 'google-00000001', email: 'A@example.test', clientId: 'C1', clientSecret: 's', refreshToken: 'r' }],
      gmail: [{ ...base, id: 'gmail-00000001', email: 'a@example.test', clientId: 'C2', clientSecret: 's', refreshToken: 'r' }],
      googleProductivity: [
        { ...base, id: 'gprod-00000001', email: 'a@example.test', sub: 'OTHER', clientId: 'C1', clientSecret: 's', refreshToken: 'r', services: ['calendar'], allowCalendarWrite: false },
      ],
    } as unknown as StoreData;
    // Same sub + client: none besides the e-mail-matched Drive record (no sub) of client C1.
    expect(sharedGrantHolders(data, data.googleGroups[0]!, 'C1', { id: 'ggroup-00000001' }).map((h) => h.id)).toEqual(['google-00000001']);
    expect(sharedGrantHolders(data, data.googleGroups[1]!, 'C2', { id: 'ggroup-00000002' }).map((h) => h.id)).toEqual(['gmail-00000001']);
  });

  // M2: groups are matched on sub only.
  it('M2: same e-mail but another Google account (sub) is refused; the old group and its sub stay', async () => {
    const p = google.addPerson('dummy.moved@example.test');
    expect(await add(p, ['--label', 'Old', '--services', 'drive'])).toBe(0);
    const before = await read();
    p.prod.sub = '999999999999999999999';
    expect(await add(p, ['--label', 'New', '--services', 'drive', '--yes'])).toBe(1);
    expect(err).toContain(`already connected as Google account group ${before.googleGroups[0]!.id} "Old", but for a different Google account`);
    expect(err).toContain(`perch google remove ${before.googleGroups[0]!.id}`);
    expect(await read()).toEqual(before);
  });

  it('M2: without a terminal, updating an existing group needs --yes; nothing changes otherwise', async () => {
    const p = google.addPerson('dummy.notty@example.test');
    expect(await add(p, ['--label', 'Private', '--services', 'drive'])).toBe(0);
    const before = await read();
    expect(await add(p, ['--label', 'Private', '--services', 'drive,gmail'])).toBe(1);
    expect(err).toMatch(/No interactive terminal to confirm the update; nothing was changed\. Rerun with --yes/);
    expect(await read()).toEqual(before);
    // A readLine that has no TTY behind it (production prompt) is treated alike.
    const noTty = async () => {
      throw new PerchError('no tty', 'no_tty');
    };
    err = '';
    expect(await add(p, ['--label', 'Private', '--services', 'drive,gmail', '--read-only'], { readLine: noTty })).toBe(1);
    expect(err).toMatch(/Rerun with --yes/);
    expect(await read()).toEqual(before);
  });

  // L3: a re-add with --read-only really narrows the requested services.
  it('L3: re-add narrows the requested services to the new request; other services keep their scopes', async () => {
    const p = google.addPerson('dummy.narrow@example.test');
    expect(await add(p, ['--label', 'N', '--services', 'drive,gmail,calendar', '--write'])).toBe(0);
    let d = await read();
    expect(d.gmail[0]!.scopes).toEqual([GMAIL_RO, GMAIL_COMPOSE, GMAIL_MODIFY]);
    expect(d.googleProductivity[0]!.allowCalendarWrite).toBe(true);
    expect(await add(p, ['--label', 'N', '--services', 'gmail,calendar', '--read-only', '--yes']), err).toBe(0);
    d = await read();
    expect(d.gmail[0]!.scopes).toEqual([GMAIL_RO]);
    expect(d.googleProductivity[0]).toMatchObject({ allowCalendarWrite: false, services: ['calendar'] });
    expect(d.googleProductivity[0]!.scopes).not.toContain(SCOPE.calendarOwned);
    expect(d.googleProductivity[0]!.scopes).toContain(SCOPE.calendarRead);
    // Drive was not part of this request: unchanged, write stays.
    expect(d.google[0]!.scopes).toEqual([DRIVE_RO, DRIVE]);
  });

  // L4: a member id never removes the whole group.
  it('L4: remove with a member id and no --service is a usage error naming the group and --service', async () => {
    const p = google.addPerson('dummy.member@example.test');
    expect(await add(p, ['--label', 'M', '--services', 'gmail,calendar,contacts'])).toBe(0);
    const before = await read();
    const gid = before.googleGroups[0]!.id;
    expect(await runCli(['google', 'remove', before.gmail[0]!.id], io())).toBe(2);
    expect(err).toContain(`${before.gmail[0]!.id} is one service of Google account group ${gid}`);
    expect(err).toContain(`perch google remove ${gid} --service gmail`);
    err = '';
    expect(await runCli(['google', 'remove', before.googleProductivity[0]!.id, '--revoke'], io())).toBe(2);
    expect(err).toContain(`perch google remove ${gid} --service calendar ; perch google remove ${gid} --service contacts`);
    expect(await read()).toEqual(before);
    expect(google.revoked).toEqual([]);
    // With --service a member id still works.
    expect(await runCli(['google', 'remove', before.googleProductivity[0]!.id, '--service', 'contacts'], io()), err).toBe(0);
    expect((await read()).googleProductivity[0]!.services).toEqual(['calendar']);
  });

  // L5: detaching the last member leaves the grant valid at Google; say so.
  it('L5: legacy remove of the last group member prints that the grant is still valid and how to revoke', async () => {
    const p = google.addPerson('dummy.last@example.test');
    expect(await add(p, ['--label', 'Last', '--services', 'gmail'])).toBe(0);
    const d = await read();
    const gid = d.googleGroups[0]!.id;
    out = '';
    expect(await runCli(['gmail', 'remove', d.gmail[0]!.id], io()), err).toBe(0);
    expect(out).toContain(`The Google grant of ${gid} is still valid at Google; revoke it at https://myaccount.google.com/permissions`);
    expect(out).toContain(`perch google remove ${gid} --revoke`);
    expect(google.revoked).toEqual([]);
    expect((await read()).googleGroups).toEqual([]);
  });

  // L8: a group id in client add names its member ids.
  it('L8: client add --account ggroup-… explains that grants take the member ids', async () => {
    const p = google.addPerson('dummy.l8@example.test');
    expect(await add(p, ['--label', 'L8', '--services', 'drive,gmail'])).toBe(0);
    const d = await read();
    const gid = d.googleGroups[0]!.id;
    expect(await runCli(['client', 'add', '--label', 'X', '--allow', 'read', '--account', gid, '--token-file', `${dirs.root}/config/clients/x.token`], io())).toBe(1);
    expect(err).toContain(`${gid} is a Google account group; grant its member ids: ${d.google[0]!.id}, ${d.gmail[0]!.id}`);
  });
});

// Nachtrag 2026-10-21: per-service read/write through `perch google access`.
describe('perch google access', () => {
  const access = (args: string[], extra: Partial<CliIo> = {}) => runCli(['google', 'access', ...args], io(extra));
  const grantAccess = (person: MockGooglePerson, args: string[], extra: Partial<CliIo> = {}) =>
    runCli(['google', 'access', '--timeout', '10', ...args], io({ stderr: approving(person), ...extra }));

  /** One group: Drive read, Gmail read, Calendar read (no Contacts). */
  async function group(email = 'dummy.access@example.test') {
    const p = google.addPerson(email);
    expect(await add(p, ['--label', 'Private', '--services', 'drive,gmail,calendar', '--read-only']), err).toBe(0);
    const d = await read();
    out = '';
    err = '';
    return { p, d, gid: d.googleGroups[0]!.id };
  }
  const noSecrets = (p: MockGooglePerson) => {
    for (const s of [p.refreshToken, dummySecret('S')]) expect(out + err).not.toContain(s);
  };

  it('shows the rights per service for a group id or a member id, without a login', async () => {
    const { p, d, gid } = await group();
    const calls = google.calls.length;
    expect(await access([gid]), err).toBe(0);
    expect(out).toContain(`Google account group ${gid} "Private" (dummy.access@example.test), one login:\n`);
    expect(out).toMatch(new RegExp(`  ☑ Drive +${d.google[0]!.id} +☑ read   ☐ write\\n`));
    expect(out).toMatch(new RegExp(`  ☑ Gmail +${d.gmail[0]!.id} +☑ read   ☐ drafts   ☐ send   ☐ organize\\n`));
    expect(out).toMatch(new RegExp(`  ☑ Calendar +${d.googleProductivity[0]!.id} +☑ read   ☐ write\\n`));
    expect(out).toContain(`  ☐ Contacts  not connected`);
    expect(out).toContain(`add: perch google access ${gid} --add contacts`);
    expect(out).toContain(`Change: perch google access ${gid} --service drive|gmail|calendar --write | --read-only`);
    out = '';
    expect(await access([d.gmail[0]!.id]), err).toBe(0);
    expect(out).toContain(`Google account group ${gid} "Private"`);
    expect(google.calls.length).toBe(calls);
    expect(await read()).toEqual(d);
    noSecrets(p);
  });

  it('--service gmail --write logs in once for the same group with the union of scopes; ids stay', async () => {
    const { p, d, gid } = await group();
    expect(await grantAccess(p, [gid, '--service', 'gmail', '--write']), err).toBe(0);
    const params = google.lastAuthParams!;
    expect(params.get('scope')!.split(' ')).toEqual(['openid', 'email', DRIVE_RO, GMAIL_RO, GMAIL_COMPOSE, GMAIL_MODIFY, SCOPE.calendarRead]);
    expect(params.get('login_hint')).toBe(p.email);
    expect(params.get('include_granted_scopes')).toBe('true');
    const after = await read();
    expect(after.googleGroups).toHaveLength(1);
    expect(after.googleGroups[0]).toMatchObject({ id: gid, refreshToken: p.refreshToken, sub: p.sub });
    expect(after.google).toEqual([expect.objectContaining({ id: d.google[0]!.id, scopes: [DRIVE_RO] })]);
    expect(after.gmail).toEqual([expect.objectContaining({ id: d.gmail[0]!.id, scopes: [GMAIL_RO, GMAIL_COMPOSE, GMAIL_MODIFY] })]);
    expect(after.googleProductivity).toEqual([expect.objectContaining({ id: d.googleProductivity[0]!.id, services: ['calendar'], allowCalendarWrite: false })]);
    expect(out).toContain(`Updated Google account group ${gid}`);
    expect(out).toMatch(/☑ Gmail +gmail-[a-f0-9]{8} +☑ read   ☑ drafts   ☑ send   ☑ organize/);
    expect(out).toContain('Writes still need a client grant');
    noSecrets(p);

    // Already write: nothing to do, no login.
    const tokens = google.tokenRequests.length;
    out = '';
    expect(await access([gid, '--service', 'gmail', '--write']), err).toBe(0);
    expect(out).toContain('Gmail of ' + gid + ' already has write access; nothing changed.');
    expect(google.tokenRequests.length).toBe(tokens);
  });

  it('--service calendar --write and drive --write; a member id selects the group too', async () => {
    const { p, d, gid } = await group();
    expect(await grantAccess(p, [d.googleProductivity[0]!.id, '--service', 'calendar', '--write']), err).toBe(0);
    let after = await read();
    expect(after.googleProductivity[0]).toMatchObject({ id: d.googleProductivity[0]!.id, allowCalendarWrite: true });
    expect(after.googleProductivity[0]!.scopes).toContain(SCOPE.calendarOwned);
    expect(after.gmail[0]!.scopes).toEqual([GMAIL_RO]);
    expect(await grantAccess(p, [gid, '--service', 'drive', '--write']), err).toBe(0);
    after = await read();
    expect(after.google[0]!.scopes).toEqual([DRIVE_RO, DRIVE]);
    // The earlier calendar write stays (part of the union request).
    expect(after.googleProductivity[0]!.allowCalendarWrite).toBe(true);
    expect(after.googleGroups).toHaveLength(1);
  });

  it('a login with another Google account is refused; nothing is stored', async () => {
    const { gid } = await group();
    const before = await read();
    const other = google.addPerson('dummy.other@example.test');
    expect(await grantAccess(other, [gid, '--service', 'gmail', '--write'])).toBe(1);
    expect(err).toContain(`You signed in to Google as dummy.other@example.test, but ${gid} belongs to dummy.access@example.test. Nothing was stored.`);
    expect(await read()).toEqual(before);
  });

  it('--read-only is local: scopes and opt-ins dropped on the member, no login, and it survives a later grant', async () => {
    const p = google.addPerson('dummy.revoke@example.test');
    expect(await add(p, ['--label', 'RW', '--services', 'drive,gmail,calendar', '--write'])).toBe(0);
    const d = await read();
    const gid = d.googleGroups[0]!.id;
    const tokens = google.tokenRequests.length;
    const auth = google.lastAuthParams;
    out = '';
    for (const s of ['gmail', 'calendar', 'drive']) expect(await access([gid, '--service', s, '--read-only']), err).toBe(0);
    expect(google.tokenRequests.length).toBe(tokens);
    expect(google.lastAuthParams).toBe(auth);
    expect(google.revoked).toEqual([]);
    let after = await read();
    expect(after.gmail[0]!.scopes).toEqual([GMAIL_RO]);
    expect(after.googleProductivity[0]).toMatchObject({ allowCalendarWrite: false });
    expect(after.googleProductivity[0]!.scopes).not.toContain(SCOPE.calendarOwned);
    expect(after.google[0]!.scopes).toEqual([DRIVE_RO]);
    // The login itself is untouched.
    expect(after.googleGroups[0]).toEqual(d.googleGroups[0]);
    expect(out).toContain(`Gmail of ${gid} is now read-only in Perch (no login needed)`);
    expect(out).toContain('stays granted at Google until the next login');
    noSecrets(p);
    out = '';
    expect(await access([gid, '--service', 'gmail', '--read-only']), err).toBe(0);
    expect(out).toContain(`Gmail of ${gid} is already read-only; nothing changed.`);
    // A later grant for Drive keeps Gmail and Calendar read-only.
    expect(await grantAccess(p, [gid, '--service', 'drive', '--write']), err).toBe(0);
    after = await read();
    expect(after.google[0]!.scopes).toEqual([DRIVE_RO, DRIVE]);
    expect(after.gmail[0]!.scopes).toEqual([GMAIL_RO]);
    expect(after.googleProductivity[0]!.allowCalendarWrite).toBe(false);
  });

  it('--add contacts and --add gmail --write connect a service through a login for the same group', async () => {
    const p = google.addPerson('dummy.addsvc@example.test');
    expect(await add(p, ['--label', 'Small', '--services', 'calendar', '--read-only'])).toBe(0);
    const d = await read();
    const gid = d.googleGroups[0]!.id;
    expect(await grantAccess(p, [gid, '--add', 'contacts']), err).toBe(0);
    expect(google.lastAuthParams!.get('scope')!.split(' ')).toEqual(['openid', 'email', SCOPE.calendarRead, SCOPE.contactsRead]);
    let after = await read();
    expect(after.googleProductivity).toEqual([expect.objectContaining({ id: d.googleProductivity[0]!.id, services: ['calendar', 'contacts'] })]);
    out = '';
    expect(await grantAccess(p, [gid, '--add', 'gmail', '--write']), err).toBe(0);
    after = await read();
    expect(after.gmail).toEqual([expect.objectContaining({ groupId: gid, scopes: [GMAIL_RO, GMAIL_COMPOSE, GMAIL_MODIFY] })]);
    expect(after.googleGroups).toHaveLength(1);
    // Without a terminal and without --write/--read-only, --add connects read-only.
    err = '';
    expect(await grantAccess(p, [gid, '--add', 'drive']), err).toBe(0);
    expect(err).toContain('No interactive terminal: adding Drive read-only');
    expect((await read()).google[0]!.scopes).toEqual([DRIVE_RO]);
    // Adding a connected service changes nothing.
    out = '';
    expect(await access([gid, '--add', 'gmail']), err).toBe(0);
    expect(out).toContain('Gmail is already connected in');
  });

  it('interactive on a terminal: pick a service, then r/w', async () => {
    const { p, gid } = await group();
    const answers = ['gmail', 'w', ''];
    const questions: string[] = [];
    const readLine = async (q: string) => {
      questions.push(q);
      return answers.shift()!;
    };
    expect(await grantAccess(p, [gid], { readLine }), err).toBe(0);
    expect(questions[0]).toMatch(/Change a service\?/);
    expect(questions[1]).toMatch(/Gmail: \[r\]ead only, or read \+ \[w\]rite\?/);
    expect(questions[2]).toMatch(/Set Gmail to read \+ write \(needs a Google login for dummy\.access@example\.test\)\? \[Y\/n\]/);
    expect((await read()).gmail[0]!.scopes).toEqual([GMAIL_RO, GMAIL_COMPOSE, GMAIL_MODIFY]);
    // Enter at the first question changes nothing.
    const before = await read();
    expect(await access([gid], { readLine: async () => '' }), err).toBe(0);
    expect(await read()).toEqual(before);
  });

  it('refusals: contacts write, unknown id, separate legacy account, bad flag combinations, unconnected service', async () => {
    const { p, gid } = await group();
    const before = await read();
    expect(await access([gid, '--service', 'contacts', '--write'])).toBe(1);
    expect(err).toContain('Contacts are read-only in Perch (contacts.readonly); there is no write access to grant.');
    err = '';
    expect(await access([gid, '--add', 'contacts', '--write'])).toBe(1);
    expect(err).toContain('Contacts are read-only in Perch');
    err = '';
    expect(await access(['ggroup-00000000'])).toBe(1);
    expect(err).toContain('Unknown Google account group or account: ggroup-00000000');
    err = '';
    expect(await access([gid, '--service', 'contacts', '--read-only']), err).toBe(1);
    expect(err).toContain(`${gid} does not connect Contacts. Add it: perch google access ${gid} --add contacts`);
    err = '';
    expect(await access([gid, '--write'])).toBe(2);
    expect(err).toContain('--write and --read-only need --service SERVICE');
    err = '';
    expect(await access([gid, '--service', 'gmail', '--add', 'contacts'])).toBe(2);
    err = '';
    expect(await access([gid, '--service', 'gmail', '--write', '--read-only'])).toBe(2);
    err = '';
    expect(await access([gid, '--service', 'gmail,drive', '--write'])).toBe(2);
    err = '';
    expect(await access([])).toBe(2);
    expect(await read()).toEqual(before);

    // A separately connected Gmail account (own login): pointed to its own commands or to a re-add as a group.
    const q = google.addPerson('dummy.legacy@example.test');
    expect(await runCli(['gmail', 'add', '--label', 'Old', '--read-only', '--timeout', '10'], io({ stderr: approving(q) })), err).toBe(0);
    const legacy = (await read()).gmail.find((a) => !a.groupId)!;
    err = '';
    expect(await access([legacy.id, '--service', 'gmail', '--write'])).toBe(1);
    expect(err).toContain(`${legacy.id} is connected separately (its own login, not a Google account group)`);
    expect(err).toContain(`perch gmail remove ${legacy.id}`);
    expect(err).toContain('perch google add --label NAME');
    noSecrets(p);
    expect(out + err).not.toContain(q.refreshToken);
  });

  it('full help: perch google add points to perch google access', async () => {
    expect(await runCli(['help', '--all'], io())).toBe(0);
    expect(out).toMatch(/perch google add[\s\S]*Read\/write per service: perch google access/);
    expect(out).toContain('perch google access ggroup-ID [--service drive|gmail|calendar|contacts --write | --read-only]');
  });
});

it('persists a draft-only ceiling despite the broader Gmail compose scope [mock Google]', async () => {
  const person = google.addPerson('drafts@example.test');
  expect(await add(person, ['--label', 'Drafts', '--drafts-only']), err).toBe(0);
  const data = await read();
  expect(data.gmail[0]?.draftsOnly).toBe(true);
  const { GmailProvider } = await import('../src/mail/gmail.js');
  const { createGmailTokenProvider } = await import('../src/mail/gmailAccounts.js');
  const { Upstream } = await import('../src/upstream.js');
  const store = await openStore();
  const upstream = new Upstream(google.transport);
  const provider = new GmailProvider(upstream, createGmailTokenProvider(store, upstream));
  expect(provider.providerCapabilities(data.gmail[0]!)).toEqual({ draft: true, send: false, modify: false });
  expect(provider.canSendDraft(data.gmail[0]!)).toBe(false);
  await expect(provider.send(data.gmail[0]!, { raw: Buffer.from('test'), envelope: { from: 'drafts@example.test', to: ['self@example.test'] } })).rejects.toMatchObject({ code: 'capability_denied' });
  await expect(provider.sendDraft(data.gmail[0]!, 'draft1')).rejects.toMatchObject({ code: 'provider_scope_missing' });
  expect(data.google[0]?.scopes.some(s => s.endsWith('/auth/drive'))).toBe(false);
});

it('preserves the Gmail draft ceiling when changing another service [mock Google]', async () => {
  const person = google.addPerson('keepdrafts@example.test');
  expect(await add(person, ['--label', 'Drafts', '--drafts-only']), err).toBe(0);
  const data = await read();
  const { groupAccess, accessRequest } = await import('../src/google/access.js');
  expect(groupAccess(data, data.googleGroups[0]!.id).find(s => s.service === 'gmail')?.rights.find(r => r.name === 'send')?.enabled).toBe(false);
  expect(accessRequest(data, data.googleGroups[0]!.id, 'drive', true).gmail).toEqual({ drafts: true, send: false, modify: false });
});

it('google access downgrades full Gmail to drafts locally and requires explicit write to restore sending', async () => {
  const p = google.addPerson('accessdrafts@example.test');
  expect(await add(p, ['--label', 'Access drafts', '--write']), err).toBe(0);
  const before = await read();
  const gid = before.googleGroups[0]!.id;
  const calls = google.calls.length;
  expect(await runCli(['google', 'access', gid, '--service', 'gmail', '--drafts-only'], io()), err).toBe(0);
  let after = await read();
  expect(after.gmail[0]!.draftsOnly).toBe(true);
  expect(after.gmail[0]!.scopes).toEqual(before.gmail[0]!.scopes);
  expect(after.googleGroups).toEqual(before.googleGroups);
  expect(after.google).toEqual(before.google);
  expect(after.googleProductivity).toEqual(before.googleProductivity);
  expect(google.calls.length).toBe(calls);
  const { GmailProvider } = await import('../src/mail/gmail.js');
  const provider = new GmailProvider(new Upstream(google.transport), createGmailTokenProvider(await openStore(), new Upstream(google.transport)));
  expect(provider.providerCapabilities(after.gmail[0]!)).toEqual({ draft: true, send: false, modify: false });
  expect(await runCli(['google', 'access', gid, '--service', 'gmail', '--write', '--timeout', '10'], io({ stderr: approving(p) })), err).toBe(0);
  after = await read();
  expect(provider.providerCapabilities(after.gmail[0]!)).toEqual({ draft: true, send: true, modify: true });
  expect(await runCli(['google', 'access', gid, '--service', 'gmail', '--drafts-only'], io()), err).toBe(0);
  expect(await runCli(['google', 'access', gid, '--service', 'gmail', '--read-only'], io()), err).toBe(0);
  expect(provider.providerCapabilities((await read()).gmail[0]!)).toEqual({ draft: false, send: false, modify: false });
});

it('google access rejects conflicting draft modes and draft mode on other services', async () => {
  const p = google.addPerson('accessdraftflags@example.test');
  expect(await add(p, ['--label', 'Flags', '--write']), err).toBe(0);
  const before = await read();
  const gid = before.googleGroups[0]!.id;
  for (const flags of [['--service', 'gmail', '--write'], ['--service', 'gmail', '--read-only'], ['--service', 'drive'], []]) {
    expect(await runCli(['google', 'access', gid, '--drafts-only', ...flags], io()), err).toBe(2);
    expect(await read()).toEqual(before);
  }
});

it('google access requests compose when enabling drafts on read-only Gmail', async () => {
  const p = google.addPerson('accessnewdrafts@example.test');
  expect(await add(p, ['--label', 'New drafts', '--read-only']), err).toBe(0);
  const gid = (await read()).googleGroups[0]!.id;
  expect(await runCli(['google', 'access', gid, '--service', 'gmail', '--drafts-only', '--timeout', '10'], io({ stderr: approving(p) })), err).toBe(0);
  const account = (await read()).gmail[0]!;
  expect(account.draftsOnly).toBe(true);
  expect(account.scopes).toContain(GMAIL_COMPOSE);
  expect(account.scopes).not.toContain(GMAIL_MODIFY);
});
