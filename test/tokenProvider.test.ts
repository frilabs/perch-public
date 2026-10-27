// Generic refresh-token provider (used by Gmail and Microsoft): single-flight, rotation persisted
// under the store lock, fail closed on removal/re-authorisation. MOCK token endpoint only.
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { RefreshingTokenProvider, type TokenGrantResponse } from '../src/oauth/tokenProvider.js';
import { CredentialStore, initStore, type MicrosoftAccount } from '../src/store/credentialStore.js';
import { UpstreamError } from '../src/upstream.js';
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

async function addAccount(): Promise<MicrosoftAccount> {
  const now = new Date().toISOString();
  const acct: MicrosoftAccount = {
    id: 'microsoft-0000000a',
    label: 'Work',
    email: 'dummy@example.test',
    tenant: 'common',
    clientId: dummySecret('CLIENT'),
    refreshToken: dummySecret('RT'),
    scopes: ['Mail.Read'],
    createdAt: now,
    updatedAt: now,
  };
  await store.update((d) => {
    d.microsoft.push(acct);
  });
  return acct;
}

function provider(refresh: (a: MicrosoftAccount) => Promise<TokenGrantResponse>) {
  return new RefreshingTokenProvider<MicrosoftAccount>(store, {
    name: 'Microsoft',
    list: (d) => d.microsoft,
    refresh,
    reconnect: (id) => `perch microsoft remove ${id}`,
  });
}

describe('RefreshingTokenProvider [MOCK token endpoint]', () => {
  it('coalesces concurrent refreshes and caches the access token', async () => {
    const a = await addAccount();
    let calls = 0;
    const p = provider(async () => {
      calls++;
      await new Promise((r) => setTimeout(r, 20));
      return { access_token: 'AT-1', expires_in: 3600 };
    });
    const tokens = await Promise.all([p.getAccessToken(a.id), p.getAccessToken(a.id), p.getAccessToken(a.id)]);
    expect(tokens).toEqual(['AT-1', 'AT-1', 'AT-1']);
    expect(await p.getAccessToken(a.id)).toBe('AT-1');
    expect(calls).toBe(1);
  });

  it('persists a rotated refresh token', async () => {
    const a = await addAccount();
    const rotated = dummySecret('RT-ROTATED');
    await provider(async () => ({ access_token: 'AT', expires_in: 3600, refresh_token: rotated })).getAccessToken(a.id);
    expect((await store.read()).microsoft[0]!.refreshToken).toBe(rotated);
  });

  it('fails closed when the account is removed or re-authorised during the refresh', async () => {
    const a = await addAccount();
    const removed = provider(async () => {
      await store.update((d) => {
        d.microsoft = [];
      });
      return { access_token: 'AT-LEAK', expires_in: 3600, refresh_token: dummySecret('RT2') };
    });
    const err = await rejection(removed.getAccessToken(a.id));
    expect(err.message).toMatch(/removed or re-authorised/i);
    expect(err.message).not.toContain('AT-LEAK');

    const b = await addAccount();
    const changed = provider(async () => {
      await store.update((d) => {
        d.microsoft[0]!.refreshToken = dummySecret('RT-OTHER');
      });
      return { access_token: 'AT-LEAK', expires_in: 3600 };
    });
    expect((await rejection(changed.getAccessToken(b.id))).message).toMatch(/removed or re-authorised/i);
  });

  it('refuses to hand out a token whose rotation could not be persisted', async () => {
    const a = await addAccount();
    // A stale lock makes every store write fail closed.
    const lockDir = path.join(dirs.dataDir, 'store.lock');
    await mkdir(lockDir);
    const { utimes } = await import('node:fs/promises');
    const old = new Date(Date.now() - 120_000);
    await utimes(lockDir, old, old);
    const err = await rejection(
      provider(async () => ({ access_token: 'AT-LEAK', expires_in: 3600, refresh_token: dummySecret('RT-NEW') })).getAccessToken(a.id),
    );
    expect(err.message).toMatch(/could not be saved/i);
    expect(err.message).not.toContain('AT-LEAK');
  });

  it('maps invalid_grant to a reconnect hint without the label', async () => {
    const a = await addAccount();
    const err = await rejection(
      provider(async () => {
        throw new UpstreamError('x', 400, 'invalid_grant');
      }).getAccessToken(a.id),
    );
    expect(err.message).toMatch(/revoked or expired/i);
    expect(err.message).toContain(`perch microsoft remove ${a.id}`);
    expect(err.message).not.toContain('Work');
  });

  it('treats interaction_required (MFA/consent revoked at Microsoft) like an invalid grant', async () => {
    const a = await addAccount();
    const err = await rejection(
      provider(async () => {
        throw new UpstreamError('x', 400, 'interaction_required');
      }).getAccessToken(a.id),
    );
    expect(err.message).toMatch(/revoked or expired/i);
  });
});
