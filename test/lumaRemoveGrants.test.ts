// Removing a Luma account must keep full-access client grants (they have no account ids by design).
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { removeLumaAccount } from '../src/luma/service.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
const now = '2026-10-21T00:00:00.000Z';

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('removeLumaAccount', () => {
  it('keeps full grants, prunes grants that only covered the removed account', async () => {
    const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    await store.update((d) => {
      d.luma.push({
        id: 'luma-1a2b3c4d', label: 'Luma', clientId: 'c', registration: 'dcr', issuer: 'https://auth.example', tokenEndpoint: 'https://auth.example/token',
        refreshToken: dummySecret('RT'), scopes: [], tools: [], toolsApprovedAt: now, createdAt: now, updatedAt: now,
      });
      const base = { tokenSha256: 'a'.repeat(64), createdAt: now };
      d.clients.push({ ...base, id: 'client-00000001', label: 'Full', full: true, capabilities: ['read'], accountIds: [] } as never);
      d.clients.push({ ...base, id: 'client-00000002', label: 'Only Luma', capabilities: ['luma_read'], accountIds: ['luma-1a2b3c4d'] } as never);
    });
    const r = await removeLumaAccount(store, new Upstream(async () => { throw new Error('no network'); }), 'luma-1a2b3c4d', false);
    expect(r.removedGrants).toEqual(['client-00000002']);
    expect((await store.read()).clients.map((c) => c.id)).toEqual(['client-00000001']);
  });
});
