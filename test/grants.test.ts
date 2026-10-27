// Per-client capability grants (read/draft/send bound to mail account ids) and store schema migration.
// Local only: no upstream is involved.
import { stat } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  assertMailCapability,
  createClientGrant,
  principalForClientToken,
  READONLY_PRINCIPAL,
  removeClientGrant,
} from '../src/auth/grants.js';
import { CredentialStore, initStore, storeFilePath } from '../src/store/credentialStore.js';
import { decryptEnvelope, encryptEnvelope, parseKey } from '../src/store/crypto.js';
import { readPrivateFile, writePrivateFileAtomic } from '../src/secureFs.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
let store: CredentialStore;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
});
afterEach(async () => {
  await dirs.cleanup();
});

/** Adds a dummy IMAP account directly (account onboarding is tested elsewhere). */
async function addImap(id: string) {
  const now = new Date().toISOString();
  await store.update((d) => {
    d.imap.push({
      id,
      label: `Label ${id}`,
      email: `${id}@example.test`,
      username: `${id}@example.test`,
      password: dummySecret('IMAP-PASSWORD'),
      imap: { host: 'imap.example.test', port: 993 },
      smtp: { host: 'smtp.example.test', port: 465, security: 'tls' },
      allowDrafts: true,
      allowSend: true,
      createdAt: now,
      updatedAt: now,
    });
  });
}

describe('store schema migration', () => {
  it('opens a store written by the Drive/Notion milestone (no mail or client sections)', async () => {
    const key = parseKey(await readPrivateFile(dirs.keyFile));
    const legacy = { version: 1, google: [], notion: [] };
    await writePrivateFileAtomic(storeFilePath(dirs.dataDir), Buffer.from(encryptEnvelope(key, Buffer.from(JSON.stringify(legacy)))));
    const reopened = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    const data = await reopened.read();
    expect(data).toMatchObject({ google: [], notion: [], gmail: [], microsoft: [], imap: [], clients: [] });
    await reopened.update(() => {});
    const raw = JSON.parse(decryptEnvelope(key, (await readPrivateFile(storeFilePath(dirs.dataDir))).toString()).toString());
    expect(raw.clients).toEqual([]);
  });
});

describe('client grants', () => {
  it('stores only a token hash, writes the token to a private file and resolves the principal', async () => {
    await addImap('imap-0000000a');
    const tokenFile = `${dirs.root}/config/clients/laptop.token`;
    const { client, token } = await createClientGrant(store, {
      label: 'Laptop',
      capabilities: ['read', 'draft'],
      accountIds: ['imap-0000000a'],
      tokenFile,
    });
    expect(client.id).toMatch(/^client-[a-f0-9]{8}$/);
    expect(token.length).toBeGreaterThanOrEqual(43);
    expect(((await stat(tokenFile)).mode & 0o777).toString(8)).toBe('600');
    expect((await readPrivateFile(tokenFile)).toString().trim()).toBe(token);
    const data = await store.read();
    expect(JSON.stringify(data)).not.toContain(token);
    expect(data.clients[0]!.tokenSha256).toMatch(/^[a-f0-9]{64}$/);

    const p = await principalForClientToken(store, token);
    expect(p).toMatchObject({ kind: 'client', clientId: client.id });
    expect([...p!.capabilities].sort()).toEqual(['draft', 'read']);
    expect(await principalForClientToken(store, dummySecret('WRONG'))).toBeNull();
  });

  it('refuses unknown accounts, empty capability sets and overwriting token files', async () => {
    const tokenFile = `${dirs.root}/config/clients/a.token`;
    expect((await rejection(createClientGrant(store, { label: 'X', capabilities: ['send'], accountIds: ['imap-0000000b'], tokenFile }))).message).toMatch(
      /unknown mail account/i,
    );
    await addImap('imap-0000000b');
    expect((await rejection(createClientGrant(store, { label: 'X', capabilities: [], accountIds: ['imap-0000000b'], tokenFile }))).message).toMatch(
      /capabilit/i,
    );
    await createClientGrant(store, { label: 'X', capabilities: ['read'], accountIds: ['imap-0000000b'], tokenFile });
    expect((await rejection(createClientGrant(store, { label: 'Y', capabilities: ['read'], accountIds: ['imap-0000000b'], tokenFile }))).message).toMatch(
      /exists/i,
    );
  });

  it('binds capabilities to the granted accounts and denies everything else', async () => {
    await addImap('imap-0000000c');
    await addImap('imap-0000000d');
    const { token } = await createClientGrant(store, {
      label: 'Sender',
      capabilities: ['read', 'send'],
      accountIds: ['imap-0000000c'],
      tokenFile: `${dirs.root}/config/clients/s.token`,
    });
    const p = (await principalForClientToken(store, token))!;
    expect(() => assertMailCapability(p, 'imap-0000000c', 'send')).not.toThrow();
    expect(() => assertMailCapability(p, 'imap-0000000c', 'read')).not.toThrow();
    expect(() => assertMailCapability(p, 'imap-0000000c', 'draft')).toThrow(/not granted/i);
    expect(() => assertMailCapability(p, 'imap-0000000d', 'read')).toThrow(/not granted/i);
    expect(() => assertMailCapability(p, 'imap-0000000d', 'send')).toThrow(/not granted/i);
  });

  it('keeps the global token principal read-only', () => {
    expect(() => assertMailCapability(READONLY_PRINCIPAL, 'imap-0000000e', 'read')).not.toThrow();
    expect(() => assertMailCapability(READONLY_PRINCIPAL, 'imap-0000000e', 'draft')).toThrow(/read-only/i);
    expect(() => assertMailCapability(READONLY_PRINCIPAL, 'imap-0000000e', 'send')).toThrow(/read-only/i);
  });

  it('revokes a client immediately on removal', async () => {
    await addImap('imap-0000000f');
    const { client, token } = await createClientGrant(store, {
      label: 'Gone',
      capabilities: ['send'],
      accountIds: ['imap-0000000f'],
      tokenFile: `${dirs.root}/config/clients/g.token`,
    });
    await removeClientGrant(store, client.id);
    expect(await principalForClientToken(store, token)).toBeNull();
  });
});
