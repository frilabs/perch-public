// Google productivity (Calendar/Contacts) store section and capability-specific client grants.
// Local only: no upstream is involved.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  assertMailCapability,
  assertProductivityCapability,
  createClientGrant,
  currentPrincipal,
  parseCapabilities,
  principalForClientToken,
  READONLY_PRINCIPAL,
} from '../src/auth/grants.js';
import { CredentialStore, initStore, storeFilePath } from '../src/store/credentialStore.js';
import { decryptEnvelope, encryptEnvelope, parseKey } from '../src/store/crypto.js';
import { readPrivateFile, writePrivateFileAtomic } from '../src/secureFs.js';
import { addDummyImap, addDummyProductivity } from './support/productivityFixtures.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';

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

const tokenFile = () => `${dirs.root}/config/clients/${Math.random().toString(16).slice(2)}.token`;

describe('store schema: googleProductivity section', () => {
  it('opens stores written by the Drive/Notion and email milestones (no googleProductivity key)', async () => {
    const key = parseKey(await readPrivateFile(dirs.keyFile));
    for (const legacy of [
      { version: 1, google: [], notion: [] },
      { version: 1, google: [], notion: [], gmail: [], microsoft: [], imap: [], clients: [] },
    ]) {
      await writePrivateFileAtomic(storeFilePath(dirs.dataDir), Buffer.from(encryptEnvelope(key, Buffer.from(JSON.stringify(legacy)))));
      const reopened = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
      expect((await reopened.read()).googleProductivity).toEqual([]);
      await reopened.update(() => {});
      const raw = JSON.parse(decryptEnvelope(key, (await readPrivateFile(storeFilePath(dirs.dataDir))).toString()).toString());
      expect(raw.googleProductivity).toEqual([]);
    }
  });

  it('keeps an email-milestone client grant (mail capabilities) valid after the upgrade', async () => {
    await addDummyImap(store, 'imap-0000000a');
    const { token } = await createClientGrant(store, { label: 'Old', capabilities: ['read', 'send'], accountIds: ['imap-0000000a'], tokenFile: tokenFile() });
    const p = (await principalForClientToken(store, token))!;
    expect(() => assertMailCapability(p, 'imap-0000000a', 'send')).not.toThrow();
    expect(() => assertProductivityCapability(p, 'imap-0000000a', 'calendar_read')).toThrow(/not granted/i);
  });
});

describe('capability-specific grants for Calendar/Contacts', () => {
  it('parses the new capability names and rejects unknown ones', () => {
    expect(parseCapabilities(['calendar_read', 'calendar_write', 'contacts_read'])).toEqual(['calendar_read', 'calendar_write', 'contacts_read']);
    expect(() => parseCapabilities(['calendar_admin'])).toThrow(/unknown capability/i);
  });

  it('a calendar-only grant gives no mail access and no contacts access', async () => {
    await addDummyImap(store, 'imap-0000000a');
    await addDummyProductivity(store, 'gprod-0000000a');
    const { token } = await createClientGrant(store, { label: 'Cal', capabilities: ['calendar_read'], accountIds: ['gprod-0000000a'], tokenFile: tokenFile() });
    const p = (await principalForClientToken(store, token))!;
    expect(() => assertProductivityCapability(p, 'gprod-0000000a', 'calendar_read')).not.toThrow();
    expect(() => assertProductivityCapability(p, 'gprod-0000000a', 'contacts_read')).toThrow(/not granted/i);
    expect(() => assertProductivityCapability(p, 'gprod-0000000a', 'calendar_write')).toThrow(/not granted/i);
    expect(() => assertMailCapability(p, 'imap-0000000a', 'read')).toThrow(/not granted/i);
    // A gprod id is never a mail account, even if a mail capability were present.
    expect(p.mailAccounts).not.toBe('all');
    expect([...(p.mailAccounts as Set<string>)]).toEqual([]);
  });

  it('binds productivity capabilities to the granted account ids only', async () => {
    await addDummyProductivity(store, 'gprod-0000000a');
    await addDummyProductivity(store, 'gprod-0000000b');
    const { token } = await createClientGrant(store, {
      label: 'Writer',
      capabilities: ['calendar_read', 'calendar_write'],
      accountIds: ['gprod-0000000a'],
      tokenFile: tokenFile(),
    });
    const p = (await principalForClientToken(store, token))!;
    expect(() => assertProductivityCapability(p, 'gprod-0000000a', 'calendar_write')).not.toThrow();
    expect(() => assertProductivityCapability(p, 'gprod-0000000b', 'calendar_read')).toThrow(/not granted/i);
    expect(() => assertProductivityCapability(p, 'gprod-0000000b', 'calendar_write')).toThrow(/not granted/i);
  });

  it('keeps the operator read-only for Calendar/Contacts', () => {
    expect(() => assertProductivityCapability(READONLY_PRINCIPAL, 'gprod-0000000a', 'calendar_read')).not.toThrow();
    expect(() => assertProductivityCapability(READONLY_PRINCIPAL, 'gprod-0000000a', 'contacts_read')).not.toThrow();
    expect(() => assertProductivityCapability(READONLY_PRINCIPAL, 'gprod-0000000a', 'calendar_write')).toThrow(/read-only/i);
  });

  it('refuses grants whose capabilities and account kinds do not match', async () => {
    await addDummyImap(store, 'imap-0000000a');
    await addDummyProductivity(store, 'gprod-0000000a');
    // Calendar capability with only a mail account.
    expect((await rejection(createClientGrant(store, { label: 'X', capabilities: ['calendar_read'], accountIds: ['imap-0000000a'], tokenFile: tokenFile() }))).message).toMatch(
      /calendar\/contacts capabilit.*gprod/i,
    );
    // Mail capability with only a productivity account.
    expect((await rejection(createClientGrant(store, { label: 'X', capabilities: ['read'], accountIds: ['gprod-0000000a'], tokenFile: tokenFile() }))).message).toMatch(
      /mail capabilit.*mail account/i,
    );
    // An account no granted capability applies to.
    expect(
      (await rejection(createClientGrant(store, { label: 'X', capabilities: ['calendar_read'], accountIds: ['gprod-0000000a', 'imap-0000000a'], tokenFile: tokenFile() })))
        .message,
    ).toMatch(/imap-0000000a.*no granted capability/i);
    expect((await rejection(createClientGrant(store, { label: 'X', capabilities: ['contacts_read'], accountIds: ['gprod-000000ff'], tokenFile: tokenFile() }))).message).toMatch(
      /unknown google productivity account/i,
    );
  });

  it('a mixed grant gets mail read on the mail account and contacts on the productivity account, nothing crossed', async () => {
    await addDummyImap(store, 'imap-0000000a');
    await addDummyProductivity(store, 'gprod-0000000a');
    const { token } = await createClientGrant(store, {
      label: 'Mixed',
      capabilities: ['read', 'contacts_read'],
      accountIds: ['imap-0000000a', 'gprod-0000000a'],
      tokenFile: tokenFile(),
    });
    const p = (await principalForClientToken(store, token))!;
    expect(() => assertMailCapability(p, 'imap-0000000a', 'read')).not.toThrow();
    expect(() => assertMailCapability(p, 'gprod-0000000a', 'read')).toThrow(/not granted/i);
    expect(() => assertProductivityCapability(p, 'gprod-0000000a', 'contacts_read')).not.toThrow();
    expect(() => assertProductivityCapability(p, 'imap-0000000a', 'contacts_read')).toThrow(/not granted/i);
  });

  it('re-resolution picks up narrowing of productivity capabilities', async () => {
    await addDummyProductivity(store, 'gprod-0000000a');
    const { client, token } = await createClientGrant(store, {
      label: 'Narrow',
      capabilities: ['calendar_read', 'calendar_write'],
      accountIds: ['gprod-0000000a'],
      tokenFile: tokenFile(),
    });
    const p = (await principalForClientToken(store, token))!;
    await store.update((d) => {
      d.clients.find((c) => c.id === client.id)!.capabilities = ['calendar_read'];
    });
    const now = await currentPrincipal(store, p);
    expect(() => assertProductivityCapability(now, 'gprod-0000000a', 'calendar_write')).toThrow(/not granted/i);
  });
});
