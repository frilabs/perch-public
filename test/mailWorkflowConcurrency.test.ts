// Cross-process mail workflow tests: real subprocesses (compiled sources) share one namespace ledger.
// The provider in the workers is a MOCK that appends to a log file; nothing touches the network.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createClientGrant } from '../src/auth/grants.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';

// Separate build dir from storeConcurrency.test.ts: test files run in parallel.
const BUILD = path.resolve('node_modules/.cache/perch-test-build-workflow');
const WORKER = path.resolve('test/support/workflowWorker.mjs');

let dirs: TempDirs;
let tokenFile: string;
let sendLog: string;
let goFile: string;

function worker(mode: 'send' | 'hang', requestId: string) {
  const child = spawn(process.execPath, [WORKER, BUILD, mode, dirs.dataDir, dirs.keyFile, tokenFile, sendLog, goFile, requestId], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  let err = '';
  child.stdout.on('data', (c) => (out += c));
  child.stderr.on('data', (c) => (err += c));
  const done = new Promise<{ code: number | null; out: string; err: string }>((resolve) => child.on('exit', (code) => resolve({ code, out, err })));
  return { child, done, output: () => out };
}

const attempts = async () => (existsSync(sendLog) ? (await readFile(sendLog, 'utf8')).split('\n').filter(Boolean) : []);

beforeAll(() => {
  const r = spawnSync(process.execPath, [path.resolve('node_modules/typescript/bin/tsc'), '-p', 'tsconfig.build.json', '--outDir', BUILD], { encoding: 'utf8' });
  expect(r.status, r.stdout + r.stderr).toBe(0);
}, 120_000);

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  const now = new Date().toISOString();
  await store.update((d) => {
    d.imap.push({
      id: 'imap-0000000a',
      label: 'GMX',
      email: 'me@gmx.example.test',
      username: 'me@gmx.example.test',
      password: dummySecret('PW'),
      imap: { host: 'imap.invalid.example', port: 993 },
      smtp: { host: 'smtp.invalid.example', port: 465, security: 'tls' },
      allowDrafts: false,
      allowSend: true,
      createdAt: now,
      updatedAt: now,
    });
  });
  tokenFile = path.join(dirs.root, 'config', 'clients', 'worker.token');
  await createClientGrant(store, { label: 'Workers', capabilities: ['send'], accountIds: ['imap-0000000a'], tokenFile });
  sendLog = path.join(dirs.root, 'sends.log');
  goFile = path.join(dirs.root, 'go');
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('mail workflow across processes [MOCK provider]', () => {
  it('six concurrent processes with the same key submit exactly once', async () => {
    for (let round = 0; round < 3; round++) {
      const requestId = `xproc-round-${round}`;
      await rm(goFile, { force: true });
      const workers = Array.from({ length: 6 }, () => worker('send', requestId));
      await new Promise((r) => setTimeout(r, 300)); // all workers loaded and waiting at the barrier
      await writeFile(goFile, 'go');
      const results = await Promise.all(workers.map((w) => w.done));
      for (const r of results) expect(r.code, r.err).toBe(0);
      const outcomes = results.map((r) => JSON.parse(r.out.trim()) as { status: string; replayed: boolean; requestState: string });
      expect(outcomes.filter((o) => !o.replayed), `round ${round}`).toHaveLength(1);
      expect(outcomes.find((o) => !o.replayed)!.status).toBe('accepted');
      for (const o of outcomes.filter((x) => x.replayed)) expect(['indeterminate', 'accepted']).toContain(o.status);
      expect(await attempts(), `round ${round}`).toHaveLength(round + 1);
    }
  }, 60_000);

  it('a process killed after the claim leaves a durable pending record that later processes never resend', async () => {
    await writeFile(goFile, 'go');
    const victim = worker('hang', 'killed-key-0001');
    for (let i = 0; i < 500 && (await attempts()).length === 0; i++) await new Promise((r) => setTimeout(r, 10));
    expect(await attempts()).toHaveLength(1);
    victim.child.kill('SIGKILL');
    await victim.done;
    // Restarted processes (fresh store, fresh service) see "pending": unknown, never resubmitted.
    for (let i = 0; i < 2; i++) {
      const r = await worker('send', 'killed-key-0001').done;
      expect(r.code, r.err).toBe(0);
      expect(JSON.parse(r.out.trim())).toEqual({ status: 'indeterminate', replayed: true, requestState: 'pending' });
    }
    expect(await attempts()).toHaveLength(1);
    const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    expect((await new MailWorkflowLedger(store).read()).sends.map((s) => s.state)).toEqual(['pending']);
    // The ledger lock was released by the claim before the provider call, so nothing is left locked.
    expect(existsSync(path.join(dirs.dataDir, 'mail-workflow.lock'))).toBe(false);
  }, 60_000);
});
