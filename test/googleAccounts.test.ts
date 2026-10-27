// Google account registration and token refresh against the MOCK Google upstream. No live Google calls.
import { mkdir, rm, utimes } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  GoogleTokenProvider,
  registerGoogleAccount,
  removeGoogleAccount,
} from '../src/google/accounts.js';
import { DRIVE_READONLY_SCOPE } from '../src/google/oauth.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { Upstream } from '../src/upstream.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGoogle, type MockGoogleAccount } from './support/mockGoogle.js';

let dirs: TempDirs;
let store: CredentialStore;
let google: MockGoogle;

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  google = new MockGoogle();
});
afterEach(async () => {
  await dirs.cleanup();
});

const client = { clientId: dummySecret('CLIENT'), clientSecret: dummySecret('CLIENT-SECRET') };

async function register(acct: MockGoogleAccount, label: string) {
  return registerGoogleAccount(store, new Upstream(google.transport), {
    label,
    client,
    grant: {
      refreshToken: acct.refreshToken,
      accessToken: google.issueAccessToken(acct),
      expiresAt: Date.now() + 3600_000,
      scopes: [DRIVE_READONLY_SCOPE],
    },
  });
}

describe('registerGoogleAccount [mock Google]', () => {
  it('stores separate accounts with stable ids, labels and Drive-reported email', async () => {
    const a = await register(google.addAccount('dummy.a@example.test'), 'Private');
    const b = await register(google.addAccount('dummy.b@example.test'), 'Work');
    expect(a.id).toMatch(/^google-[a-f0-9]{8}$/);
    expect(a.id).not.toBe(b.id);
    const data = await store.read();
    expect(data.google.map((g) => [g.id, g.label, g.email])).toEqual([
      [a.id, 'Private', 'dummy.a@example.test'],
      [b.id, 'Work', 'dummy.b@example.test'],
    ]);
  });

  it('rejects a second grant for the same Google account', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    await register(acct, 'One');
    await expect(register(acct, 'Two')).rejects.toThrow(/already connected/i);
  });

  it('removes locally and optionally revokes at Google', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const a = await register(acct, 'One');
    await removeGoogleAccount(store, new Upstream(google.transport), a.id, { revoke: true });
    expect((await store.read()).google).toHaveLength(0);
    expect(google.revoked).toEqual([acct.refreshToken]);
    await expect(removeGoogleAccount(store, new Upstream(google.transport), a.id, {})).rejects.toThrow(/unknown/i);
  });
});

describe('GoogleTokenProvider [mock Google]', () => {
  it('refreshes once for concurrent callers and caches until near expiry', async () => {
    let now = 1_000_000;
    const acct = google.addAccount('dummy.a@example.test');
    const a = await register(acct, 'A');
    const provider = new GoogleTokenProvider(store, new Upstream(google.transport), () => now);
    const before = google.tokenCalls;
    const tokens = await Promise.all(Array.from({ length: 5 }, () => provider.getAccessToken(a.id)));
    expect(new Set(tokens).size).toBe(1);
    expect(google.tokenCalls - before).toBe(1);
    await provider.getAccessToken(a.id);
    expect(google.tokenCalls - before).toBe(1);
    now += 3599_000 - 30_000; // within the 60s safety margin
    await provider.getAccessToken(a.id);
    expect(google.tokenCalls - before).toBe(2);
  });

  it('keeps the stored refresh token when Google omits one on refresh', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const a = await register(acct, 'A');
    const original = acct.refreshToken;
    await new GoogleTokenProvider(store, new Upstream(google.transport)).getAccessToken(a.id);
    expect((await store.read()).google[0]!.refreshToken).toBe(original);
  });

  it('persists a rotated refresh token visible to other store instances', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const a = await register(acct, 'A');
    const rotated = dummySecret('GOOGLE-REFRESH-ROTATED');
    google.opts.rotateRefreshTokenTo = rotated;
    await new GoogleTokenProvider(store, new Upstream(google.transport)).getAccessToken(a.id);
    const other = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    expect((await other.read()).google[0]!.refreshToken).toBe(rotated);
  });

  it('turns invalid_grant into a re-authorisation hint without leaking tokens', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const a = await register(acct, 'A');
    const stored = acct.refreshToken;
    acct.refreshToken = dummySecret('REVOKED-ELSEWHERE');
    const err = await new GoogleTokenProvider(store, new Upstream(google.transport))
      .getAccessToken(a.id)
      .catch((e: Error) => e);
    expect((err as Error).message).toMatch(/revoked or expired/i);
    expect((err as Error).message).toContain(a.id);
    expect((err as Error).message).not.toContain(stored);
  });

  it('fails closed when the account is removed while a refresh is in flight', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const a = await register(acct, 'A');
    const cli = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    google.beforeRefreshResponse = () => removeGoogleAccount(cli, new Upstream(google.transport), a.id, {}).then(() => {});
    const provider = new GoogleTokenProvider(store, new Upstream(google.transport));
    await expect(provider.getAccessToken(a.id)).rejects.toThrow(/removed or re-authorised/i);
    google.beforeRefreshResponse = undefined;
    await expect(provider.getAccessToken(a.id)).rejects.toThrow(/unknown google account/i);
  });

  it('fails closed when the account is re-authorised (new refresh token) while a refresh is in flight', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const a = await register(acct, 'A');
    const fresh = dummySecret('GOOGLE-REFRESH-NEW-GRANT');
    google.beforeRefreshResponse = async () => {
      const cli = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
      await cli.update((d) => {
        d.google[0]!.refreshToken = fresh;
      });
    };
    const provider = new GoogleTokenProvider(store, new Upstream(google.transport));
    await expect(provider.getAccessToken(a.id)).rejects.toThrow(/removed or re-authorised/i);
    expect((await store.read()).google[0]!.refreshToken).toBe(fresh);
  });

  it('fails with a reconnect hint (no token in the message) when a rotated refresh token cannot be persisted', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const a = await register(acct, 'A');
    const rotated = dummySecret('GOOGLE-REFRESH-ROTATED');
    google.opts.rotateRefreshTokenTo = rotated;
    const lock = path.join(dirs.dataDir, 'store.lock');
    google.beforeRefreshResponse = async () => {
      // A leftover lock from a crashed process makes store writes fail closed.
      await mkdir(lock);
      const old = new Date(Date.now() - 10 * 60_000);
      await utimes(lock, old, old);
    };
    const provider = new GoogleTokenProvider(store, new Upstream(google.transport));
    const err = await rejection(provider.getAccessToken(a.id));
    expect(err.message).toMatch(/could not be saved/i);
    expect(err.message).toContain(`perch google remove ${a.id}`);
    expect(err.message).not.toContain(rotated);
    await rm(lock, { recursive: true });
    google.beforeRefreshResponse = undefined;
    // Nothing was cached: the next call refreshes again instead of returning an orphaned token.
    const before = google.tokenCalls;
    await provider.getAccessToken(a.id).catch(() => {});
    expect(google.tokenCalls).toBe(before + 1);
  });

  it('re-auth hint never embeds the user-supplied label in a shell command', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const a = await register(acct, 'Evil "$(touch x)" `id`');
    acct.refreshToken = dummySecret('REVOKED-ELSEWHERE');
    const err = await rejection(new GoogleTokenProvider(store, new Upstream(google.transport)).getAccessToken(a.id));
    expect(err.message).toContain(`perch google remove ${a.id}`);
    expect(err.message).not.toContain('$(touch x)');
    expect(err.message).not.toContain('`id`');
  });

  it('sees accounts removed by another process immediately', async () => {
    const acct = google.addAccount('dummy.a@example.test');
    const a = await register(acct, 'A');
    const provider = new GoogleTokenProvider(store, new Upstream(google.transport));
    await provider.getAccessToken(a.id);
    const cli = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    await removeGoogleAccount(cli, new Upstream(google.transport), a.id, {});
    await expect(provider.getAccessToken(a.id)).rejects.toThrow(/unknown google account/i);
  });
});
