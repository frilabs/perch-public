import { afterEach, describe, expect, it, vi } from 'vitest';
import { runCli } from '../src/cli/run.js';
import { cmdMicrosoftSession } from '../src/cli/microsoftSession.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { createPerchContext } from '../src/context.js';
import { createClientGrant, mailAccountIds, READONLY_PRINCIPAL } from '../src/auth/grants.js';
import { resolveConfig } from '../src/config.js';
import { collectStatus } from '../src/status/status.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';

// Routing tests isolate the browser: never start Chrome or a login listener.
vi.mock('../src/cli/microsoftSession.js', async (original) => ({
  ...await original<typeof import('../src/cli/microsoftSession.js')>(),
  cmdMicrosoftSession: vi.fn(),
}));
const dirs: TempDirs[] = [];
afterEach(async () => {
  vi.clearAllMocks();
  for (const d of dirs.splice(0)) await d.cleanup();
});

async function fixture() {
  const d = await makeTempDirs();
  dirs.push(d);
  await initStore(d);
  const store = await CredentialStore.open(d);
  const now = new Date().toISOString();
  const legacy = {
    id: 'microsoft-12345678', label: 'Legacy', email: 'legacy@example.test', tenant: 'common',
    clientId: '11111111-1111-4111-8111-111111111111', refreshToken: 'DUMMY-legacy-secret-preserved',
    scopes: ['Mail.Read', 'Mail.Send'], createdAt: now, updatedAt: now,
  };
  await store.update((data) => { data.microsoft.push(legacy); });
  let out = '', err = '';
  const transport = vi.fn(async () => { throw new Error('Unexpected upstream request'); });
  const io = {
    env: {
      HOME: d.root, PERCH_DATA_DIR: d.dataDir, PERCH_KEY_FILE: d.keyFile,
      PERCH_MICROSOFT_CLIENT_ID: 'stale-invalid', PERCH_MICROSOFT_TENANT: 'invalid/tenant',
    },
    stdout: (s: string) => { out += s; }, stderr: (s: string) => { err += s; },
    readSecret: vi.fn(async () => { throw new Error('Unexpected secret prompt'); }), transport,
  };
  return { d, store, legacy, io, transport, output: () => out, errors: () => err };
}

describe('retired standalone Microsoft Graph connector', () => {
  it.each([{ flags: [] }, { flags: ['--session'] }])('routes add directly to browser session: $flags', async ({ flags }) => {
    const f = await fixture();
    expect(await runCli(['microsoft', 'add', '--label', 'Work', ...flags], f.io)).toBe(0);
    expect(cmdMicrosoftSession).toHaveBeenCalledWith(expect.anything(), f.io, 'add', expect.objectContaining({ label: 'Work' }), []);
    expect(f.transport).not.toHaveBeenCalled();
  });

  it.each([
    { args: ['microsoft', 'add', '--oauth', '--label', 'Work'] },
    { args: ['microsoft', 'client', 'setup'] },
    { args: ['microsoft', 'client', 'show'] },
  ])('rejects retired command with session instructions: $args', async ({ args }) => {
    const f = await fixture();
    expect(await runCli(args, f.io)).not.toBe(0);
    expect(f.errors()).toMatch(/retired.*perch microsoft add/i);
    expect(cmdMicrosoftSession).not.toHaveBeenCalled();
    expect(f.transport).not.toHaveBeenCalled();
  });

  it('ignores old Entra config and hides legacy accounts from mail, grants and status while preserving credentials', async () => {
    const f = await fixture(), ctx = createPerchContext(f.store, f.transport), config = resolveConfig(f.io.env);
    expect(config).not.toHaveProperty('microsoftClientId');
    expect(config).not.toHaveProperty('microsoftTenant');
    expect(mailAccountIds(await f.store.read())).toEqual([]);
    expect(await ctx.mail.listAccounts(READONLY_PRINCIPAL)).toEqual([]);
    await expect(createClientGrant(f.store, {
      label: 'Old', capabilities: ['read'], accountIds: [f.legacy.id], tokenFile: f.d.root + '/client.token',
    })).rejects.toThrow();
    const report = await collectStatus(ctx, { live: true });
    expect(report.accounts).not.toEqual(expect.arrayContaining([expect.objectContaining({ id: f.legacy.id })]));
    expect((await (await CredentialStore.open(f.d)).read()).microsoft).toEqual([f.legacy]);
    expect(f.transport).not.toHaveBeenCalled();
  });

  it('explains how to reconnect when an old mail account is requested', async () => {
    const f = await fixture(), ctx = createPerchContext(f.store, f.transport);
    await expect(ctx.mail.read(READONLY_PRINCIPAL, {
      accountId: f.legacy.id, messageId: 'old-message',
    })).rejects.toThrow(/retired.*perch microsoft add/i);
    expect(f.transport).not.toHaveBeenCalled();
  });

  it('allows explicit removal of an inert legacy credential', async () => {
    const f = await fixture();
    expect(await runCli(['microsoft', 'remove', f.legacy.id], f.io)).toBe(0);
    expect((await f.store.read()).microsoft).toEqual([]);
    expect(f.output()).toMatch(/legacy/i);
    expect(f.transport).not.toHaveBeenCalled();
  });

  it('omits Entra app and OAuth connector setup from help', async () => {
    const f = await fixture();
    expect(await runCli(['--help'], f.io)).toBe(0);
    expect(f.output()).not.toMatch(/microsoft client|microsoft.*--oauth/);
  });
});
