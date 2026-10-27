// Cross-process store tests: real subprocesses share one data directory.
import { spawn, spawnSync } from 'node:child_process';
import { rm, stat, utimes, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';

const BUILD = path.resolve('node_modules/.cache/perch-test-build');
const WORKER = path.resolve('test/support/storeWorker.mjs');

let dirs: TempDirs;
const paths = () => ({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
const lockPath = () => path.join(dirs.dataDir, 'store.lock');

function worker(...args: string[]) {
  const child = spawn(process.execPath, [WORKER, BUILD, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  child.stdout.on('data', (c) => (out += c));
  child.stderr.on('data', (c) => (err += c));
  const done = new Promise<{ code: number | null; out: string; err: string }>((resolve) =>
    child.on('exit', (code) => resolve({ code, out, err })),
  );
  return { child, done, output: () => out };
}

beforeAll(() => {
  const r = spawnSync(process.execPath, [path.resolve('node_modules/typescript/bin/tsc'), '-p', 'tsconfig.build.json', '--outDir', BUILD], {
    encoding: 'utf8',
  });
  expect(r.status, r.stdout + r.stderr).toBe(0);
}, 120_000);

beforeEach(async () => {
  dirs = await makeTempDirs();
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('cross-process store serialisation', () => {
  it('concurrent subprocess writers lose no updates', async () => {
    await initStore(paths());
    const runs = Array.from({ length: 4 }, (_, i) => worker('update', dirs.dataDir, dirs.keyFile, '8', `w${i}`).done);
    const results = await Promise.all(runs);
    for (const r of results) expect(r.code, r.err).toBe(0);
    const data = await (await CredentialStore.open(paths())).read();
    expect(data.notion).toHaveLength(32);
    expect(new Set(data.notion.map((n) => n.label)).size).toBe(32);
  });

  it('fails closed on a stale lock left by a killed process and never takes it over', async () => {
    await initStore(paths());
    const holder = worker('hold', dirs.dataDir, dirs.keyFile);
    await new Promise<void>((resolve) => {
      const t = setInterval(() => {
        if (holder.output().includes('held')) {
          clearInterval(t);
          resolve();
        }
      }, 10);
    });
    holder.child.kill('SIGKILL');
    await holder.done;
    const old = new Date(Date.now() - 10 * 60_000);
    await utimes(lockPath(), old, old);

    const store = await CredentialStore.open(paths());
    const attempt = () =>
      store.update((d) => {
        d.notion = [];
      });
    await expect(attempt()).rejects.toThrow(/stale/i);
    await expect(attempt()).rejects.toThrow(lockPath());
    await stat(lockPath()); // still present: no automatic takeover

    // Documented manual recovery once no Perch process is running.
    await rm(lockPath(), { recursive: true, force: true });
    await expect(attempt()).resolves.toBeUndefined();
  });

  it('release never removes a lock it does not own', async () => {
    await initStore(paths());
    const store = await CredentialStore.open(paths());
    await store.update(async () => {
      // Simulate our lock having been replaced by another owner's lock.
      await rm(lockPath(), { recursive: true, force: true });
      await writeFile(lockPath(), 'foreign-owner', { mode: 0o600 });
    });
    await stat(lockPath());
  });
});

describe('concurrent init', () => {
  it('repeated concurrent inits agree on one key and leave a decryptable store', async () => {
    for (let round = 0; round < 4; round++) {
      const d = await makeTempDirs();
      try {
        const results = await Promise.all(
          Array.from({ length: 6 }, () => worker('init', d.dataDir, d.keyFile).done),
        );
        for (const r of results) expect(r.code, r.err).toBe(0);
        const created = results.map((r) => JSON.parse(r.out) as { createdKey: boolean; createdStore: boolean });
        expect(created.filter((c) => c.createdKey)).toHaveLength(1);
        expect(created.filter((c) => c.createdStore)).toHaveLength(1);
        const store = await CredentialStore.open({ dataDir: d.dataDir, keyFile: d.keyFile });
        expect((await store.read()).notion).toEqual([]);
      } finally {
        await d.cleanup();
      }
    }
  });
});
