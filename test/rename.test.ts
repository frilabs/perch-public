// `perch rename`: label changes only; ids, credentials and grants stay. MOCK: no provider is contacted.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runCli, type CliIo } from '../src/cli/run.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
let out: string;
let err: string;

function io(): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root },
    stdout: (s) => void (out += s),
    stderr: (s) => void (err += s),
    readSecret: async () => dummySecret('IMAP-PW'),
    imapVerify: async () => {},
  };
}
const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
const now = '2026-10-21T00:00:00.000Z';

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = '';
  err = '';
  expect(await runCli(['init'], io())).toBe(0);
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('perch rename', () => {
  it('renames an account and a client without changing ids or secrets', async () => {
    expect(await runCli(['imap', 'add', '--label', 'GMX', '--email', 'dummy@gmx.at', '--preset', 'gmx', '--read-only'], io())).toBe(0);
    expect(await runCli(['client', 'add', '--label', 'Old', '--full', '--token-file', `${dirs.root}/c.token`], io())).toBe(0);
    const before = await (await openStore()).read();
    const imapId = before.imap[0]!.id;
    const clientId = before.clients[0]!.id;
    out = '';
    expect(await runCli(['rename', imapId, 'Privat GMX'], io())).toBe(0);
    expect(await runCli(['rename', clientId, 'Claude Code Mac'], io())).toBe(0);
    expect(out).toContain(`Renamed ${imapId} to "Privat GMX"`);
    const after = await (await openStore()).read();
    expect(after.imap[0]).toMatchObject({ id: imapId, label: 'Privat GMX', password: before.imap[0]!.password });
    expect(after.clients[0]).toMatchObject({ id: clientId, label: 'Claude Code Mac' });
  });

  it('renames a Google account group together with its services and refuses a single member', async () => {
    const store = await openStore();
    await store.update((d) => {
      d.googleGroups.push({ id: 'ggroup-1a2b3c4d', label: 'CDTM', email: 'a@example.org', sub: '1', clientId: 'c', clientSecret: dummySecret('CS'), refreshToken: dummySecret('RT'), scopes: [], createdAt: now, updatedAt: now });
      d.google.push({ id: 'google-11111111', label: 'CDTM', email: 'a@example.org', groupId: 'ggroup-1a2b3c4d', scopes: [], createdAt: now, updatedAt: now });
      d.gmail.push({ id: 'gmail-22222222', label: 'CDTM', email: 'a@example.org', groupId: 'ggroup-1a2b3c4d', scopes: [], createdAt: now, updatedAt: now });
    });
    expect(await runCli(['rename', 'gmail-22222222', 'Privat'], io())).not.toBe(0);
    expect(err).toMatch(/perch rename ggroup-1a2b3c4d/);
    expect(await runCli(['rename', 'ggroup-1a2b3c4d', 'Privat'], io())).toBe(0);
    const d = await (await openStore()).read();
    expect([d.googleGroups[0]!.label, d.google[0]!.label, d.gmail[0]!.label]).toEqual(['Privat', 'Privat', 'Privat']);
  });

  it('refuses unknown ids, bad labels and missing arguments', async () => {
    expect(await runCli(['rename', 'imap-00000000', 'X'], io())).not.toBe(0);
    expect(err).toMatch(/Unknown id/);
    expect(await runCli(['rename', 'imap-00000000'], io())).toBe(2);
    expect(await runCli(['rename', 'imap-00000000', ' '], io())).not.toBe(0);
  });
});
