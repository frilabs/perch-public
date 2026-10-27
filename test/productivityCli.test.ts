// CLI onboarding for Google Calendar/Contacts (separate grant, explicit --services, opt-in
// --allow-calendar-write) and client grants with the new capabilities. MOCK Google upstream only.
import { readFile, stat, writeFile } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runCli, type CliIo } from '../src/cli/run.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockGoogleProductivity, SCOPE } from './support/mockProductivity.js';

let dirs: TempDirs;
let out: string[];
let err: string[];
let google: MockGoogleProductivity;
let clientFile: string;

function io(extra: Partial<CliIo> = {}): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root, PERCH_GOOGLE_CLIENT_FILE: clientFile },
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    readSecret: async () => {
      throw new Error('no TTY in tests');
    },
    transport: google.transport,
    ...extra,
  };
}

/** Approves the printed auth URL by calling the loopback redirect, as a browser would (MOCK consent). */
function approving(email: string, seen: { scope?: string }) {
  const acct = google.accounts.find((a) => a.email === email) ?? google.addAccount(email);
  let done = false;
  return (s: string) => {
    err.push(s);
    const m = /https:\/\/accounts\.google\.com\S+/.exec(s);
    if (m && !done) {
      done = true;
      const url = new URL(m[0]);
      seen.scope = url.searchParams.get('scope')!;
      const code = google.approve(url.toString(), acct);
      void fetch(`${url.searchParams.get('redirect_uri')}?code=${code}&state=${url.searchParams.get('state')}`);
    }
  };
}

const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = [];
  err = [];
  google = new MockGoogleProductivity();
  clientFile = `${dirs.root}/client.json`;
  await writeFile(clientFile, JSON.stringify({ installed: { client_id: dummySecret('C'), client_secret: dummySecret('S') } }), { mode: 0o600 });
  expect(await runCli(['init'], io())).toBe(0);
  out = [];
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('perch google-productivity', () => {
  it('requires an explicit --services selection and calendar for --allow-calendar-write', async () => {
    expect(await runCli(['google-productivity', 'add', '--label', 'X'], io())).toBe(2);
    expect(err.join('')).toMatch(/--services/);
    err = [];
    expect(await runCli(['google-productivity', 'add', '--label', 'X', '--services', 'contacts', '--allow-calendar-write'], io())).toBe(1);
    expect(err.join('')).toMatch(/calendar/i);
    err = [];
    expect(await runCli(['google-productivity', 'add', '--label', 'X', '--services', 'drive'], io())).toBe(1);
    expect(err.join('')).toMatch(/unknown service/i);
    expect(google.calls).toEqual([]);
  });

  it('adds a read-only Calendar account (no Drive/Gmail scopes), lists it and removes it with --revoke', async () => {
    const seen: { scope?: string } = {};
    const code = await runCli(['google-productivity', 'add', '--label', 'Private', '--services', 'calendar', '--timeout', '10'], io({ stderr: approving('dummy.a@example.test', seen) }));
    expect(err.join('')).not.toMatch(/perch: /);
    expect(code).toBe(0);
    expect(seen.scope).toBe(`openid email ${SCOPE.calendarRead}`);
    const [acct] = (await (await openStore()).read()).googleProductivity;
    expect(acct).toMatchObject({ label: 'Private', email: 'dummy.a@example.test', services: ['calendar'], allowCalendarWrite: false });
    expect(out.join('')).toMatch(/Connected .*gprod-[a-f0-9]{8}.*calendar \(read-only\)/);
    expect(out.join('') + err.join('')).not.toContain(google.accounts[0]!.refreshToken);

    out = [];
    expect(await runCli(['google-productivity', 'list'], io())).toBe(0);
    expect(out.join('')).toMatch(new RegExp(`${acct!.id}\\s+"Private"\\s+dummy\\.a@example\\.test\\s+calendar`));
    out = [];
    expect(await runCli(['accounts'], io())).toBe(0);
    expect(out.join('')).toMatch(/Google Calendar\/Contacts accounts:[\s\S]*gprod-/);

    expect(await runCli(['google-productivity', 'remove', acct!.id, '--revoke'], io())).toBe(0);
    expect(google.revoked).toEqual([google.accounts[0]!.refreshToken]);
    expect((await (await openStore()).read()).googleProductivity).toEqual([]);
  });

  it('requests calendar.events.owned only with --allow-calendar-write', async () => {
    const seen: { scope?: string } = {};
    const args = ['google-productivity', 'add', '--label', 'W', '--services', 'calendar,contacts', '--allow-calendar-write', '--timeout', '10'];
    expect(await runCli(args, io({ stderr: approving('dummy.w@example.test', seen) }))).toBe(0);
    expect(seen.scope!.split(' ')).toEqual(['openid', 'email', SCOPE.calendarRead, SCOPE.contactsRead, SCOPE.calendarOwned]);
    const [acct] = (await (await openStore()).read()).googleProductivity;
    expect(acct).toMatchObject({ services: ['calendar', 'contacts'], allowCalendarWrite: true });
    expect(acct!.scopes).toContain(SCOPE.calendarOwned);
  });
});

describe('perch client with calendar/contacts capabilities', () => {
  it('creates a calendar grant for a gprod account and rejects mismatched families', async () => {
    const seen: { scope?: string } = {};
    await runCli(['google-productivity', 'add', '--label', 'P', '--services', 'calendar', '--allow-calendar-write', '--timeout', '10'], io({ stderr: approving('dummy.p@example.test', seen) }));
    const id = (await (await openStore()).read()).googleProductivity[0]!.id;
    const tokenFile = `${dirs.root}/config/clients/cal.token`;
    out = [];
    expect(await runCli(['client', 'add', '--label', 'Cal', '--allow', 'calendar_read,calendar_write', '--account', id, '--token-file', tokenFile], io())).toBe(0);
    expect((await stat(tokenFile)).mode & 0o777).toBe(0o600);
    expect(out.join('')).not.toContain((await readFile(tokenFile, 'utf8')).trim());
    out = [];
    expect(await runCli(['client', 'list'], io())).toBe(0);
    expect(out.join('')).toMatch(new RegExp(`"Cal"\\s+calendar_read,calendar_write\\s+accounts ${id}`));
    err = [];
    expect(await runCli(['client', 'add', '--label', 'Bad', '--allow', 'read', '--account', id], io())).toBe(1);
    expect(err.join('')).toMatch(/mail capabilit/i);
    err = [];
    expect(await runCli(['client', 'add', '--label', 'Bad', '--allow', 'calendar_admin', '--account', id], io())).toBe(1);
    expect(err.join('')).toMatch(/unknown capability/i);
  });
});
