// Encrypted mail workflow / audit ledger (mail-workflow.enc): creation, encryption, fail-closed opening,
// bounds and write failures. No provider is involved; every value is generated dummy data.
import { chmod, lstat, readFile, rename, rm, stat, symlink, truncate, utimes, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { generateKeyFileContents, parseKey } from '../src/store/crypto.js';
import {
  deriveLedgerKeys,
  initMailWorkflowLedger,
  LEDGER_FILE,
  LEDGER_LOCK,
  MAX_AUDIT_EVENTS,
  MAX_LEDGER_FILE_BYTES,
  MAX_SEND_RECORDS,
  MailWorkflowLedger,
  sealLedger,
  type AuditEvent,
  type SendRecord,
} from '../src/mail/workflowLedger.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
let store: CredentialStore;
const ledgerFile = () => path.join(dirs.dataDir, LEDGER_FILE);

const hex = (c: string, n = 64) => c.repeat(n).slice(0, n);
const record = (i: number, state: SendRecord['state'] = 'accepted'): SendRecord => ({
  key: i.toString(16).padStart(64, '0'),
  fp: hex('b'),
  binding: hex('c'),
  operationId: `op-${i.toString(16).padStart(24, '0')}`,
  accountId: 'imap-0000000a',
  provider: 'imap',
  actor: { kind: 'client', clientId: 'client-0000000a' },
  state,
  attempt: hex('d', 32),
  createdAt: new Date().toISOString(),
});
const event = (i: number): AuditEvent => ({
  at: new Date().toISOString(),
  ns: 'root',
  actor: { kind: 'operator_readonly' },
  operationId: `op-${i.toString(16).padStart(24, '0')}`,
  type: 'mail_search',
  outcome: 'ok',
});

beforeEach(async () => {
  dirs = await makeTempDirs();
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
});
afterEach(async () => {
  await chmod(dirs.dataDir, 0o700).catch(() => {});
  await dirs.cleanup();
});

describe('mail workflow ledger', () => {
  it('is created by initStore as an owner-only encrypted envelope bound to its namespace, with no plaintext', async () => {
    const st = await lstat(ledgerFile());
    expect(st.isFile()).toBe(true);
    expect(st.mode & 0o777).toBe(0o600);
    const raw = await readFile(ledgerFile(), 'utf8');
    const env = JSON.parse(raw);
    expect(Object.keys(env).sort()).toEqual(['alg', 'ct', 'iv', 'kid', 'tag', 'v']);
    expect(env.alg).toBe('AES-256-GCM');
    expect(raw).not.toMatch(/perch-mail-workflow|sends|audit|root/);
    const ledger = new MailWorkflowLedger(store);
    const data = await ledger.read();
    expect(data).toMatchObject({ format: 'perch-mail-workflow', version: 1, namespace: 'root', sends: [], audit: [], auditDropped: 0 });
    // The ledger key is a domain-separated subkey, not the store key: the store envelope kid differs.
    expect(env.kid).not.toBe(JSON.parse(await readFile(path.join(dirs.dataDir, 'store.enc'), 'utf8')).kid);
  });

  it('persists transactions across instances and records audit events in order', async () => {
    const a = new MailWorkflowLedger(store);
    await a.transact((d) => {
      d.sends.push(record(1, 'pending'));
      d.audit.push(event(1));
    });
    const b = new MailWorkflowLedger(await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile }));
    const data = await b.read();
    expect(data.sends.map((s) => s.state)).toEqual(['pending']);
    expect(data.audit.map((e) => e.operationId)).toEqual([event(1).operationId]);
  });

  it('serialises concurrent transactions of separate instances (no lost update)', async () => {
    const instances = await Promise.all(
      [0, 1, 2, 3].map(async () => new MailWorkflowLedger(await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile }))),
    );
    await Promise.all(instances.flatMap((l, n) => [0, 1, 2].map((i) => l.transact((d) => void d.sends.push(record(n * 10 + i))))));
    expect((await instances[0]!.read()).sends).toHaveLength(12);
  });

  it('fails closed when the ledger is missing and never recreates it implicitly', async () => {
    await rm(ledgerFile());
    const ledger = new MailWorkflowLedger(store);
    expect(await rejection(ledger.read())).toMatchObject({ code: 'ledger_missing' });
    expect(await rejection(ledger.transact(() => {}))).toMatchObject({ code: 'ledger_missing' });
    await expect(lstat(ledgerFile())).rejects.toThrow();
    // This namespace was initialised with a ledger (initStore): explicit init must never reset a lost one.
    expect(await rejection(initMailWorkflowLedger(store))).toMatchObject({ code: 'ledger_missing' });
    expect(await rejection(initMailWorkflowLedger(await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile })))).toMatchObject({
      code: 'ledger_missing',
    });
    await expect(lstat(ledgerFile())).rejects.toThrow();
  });

  it('initialises a ledger only for a namespace that never had one, then records that durably', async () => {
    // A store written before the ledger existed: no ledger file and no initialised marker.
    await rm(ledgerFile());
    await store.update((d) => void delete d.mailWorkflowLedger);
    const ledger = new MailWorkflowLedger(store);
    expect(await initMailWorkflowLedger(store)).toBe(true);
    expect((await store.read()).mailWorkflowLedger?.createdAt).toMatch(/^\d{4}-/);
    expect(await initMailWorkflowLedger(store)).toBe(false);
    expect((await ledger.read()).sends).toEqual([]);
    await rm(ledgerFile());
    expect(await rejection(initMailWorkflowLedger(store))).toMatchObject({ code: 'ledger_missing' });
    await expect(lstat(ledgerFile())).rejects.toThrow();
  });

  it('marks a ledger that exists without the initialised marker on first use, so it can never be re-initialised', async () => {
    await store.update((d) => void delete d.mailWorkflowLedger);
    await new MailWorkflowLedger(store).transact(() => {});
    expect((await store.read()).mailWorkflowLedger).toBeDefined();
    await rm(ledgerFile());
    expect(await rejection(initMailWorkflowLedger(store))).toMatchObject({ code: 'ledger_missing' });
  });

  it('marks an existing unmarked ledger via explicit init only after validating it (a corrupt one stays refused)', async () => {
    await store.update((d) => void delete d.mailWorkflowLedger);
    await writeFile(ledgerFile(), 'not json', { mode: 0o600 });
    expect(await rejection(initMailWorkflowLedger(store))).toMatchObject({ code: 'ledger_corrupt' });
    expect((await store.read()).mailWorkflowLedger).toBeUndefined();
    expect(await readFile(ledgerFile(), 'utf8')).toBe('not json');
  });

  it('fails closed on corrupt, tampered, foreign or future-version ledgers and never overwrites them', async () => {
    const ledger = new MailWorkflowLedger(store);
    const original = await readFile(ledgerFile(), 'utf8');
    const env = JSON.parse(original);
    const flip = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
    // A store envelope of ANOTHER namespace's key (wrong key) and plain garbage.
    const otherDirs = await makeTempDirs();
    await initStore({ dataDir: otherDirs.dataDir, keyFile: otherDirs.keyFile });
    const foreign = await readFile(path.join(otherDirs.dataDir, LEDGER_FILE), 'utf8');
    await otherDirs.cleanup();
    const cases: Array<[string, string]> = [
      ['garbage', 'not json'],
      ['tampered', JSON.stringify({ ...env, ct: flip(env.ct) })],
      ['future envelope', JSON.stringify({ ...env, v: 2 })],
      ['foreign key', foreign],
      ['store file swapped in', await readFile(path.join(dirs.dataDir, 'store.enc'), 'utf8')],
      ['empty', ''],
    ];
    for (const [name, content] of cases) {
      await writeFile(ledgerFile(), content, { mode: 0o600 });
      const before = await readFile(ledgerFile());
      const err = await rejection(ledger.transact((d) => void d.sends.push(record(1))));
      expect((err as { code?: string }).code, name).toMatch(/^ledger_(corrupt|wrong_key)$/);
      expect(await readFile(ledgerFile()), name).toEqual(before);
    }
    await writeFile(ledgerFile(), original, { mode: 0o600 });
    expect((await ledger.read()).sends).toEqual([]);
  });

  it('rejects a ledger whose decrypted content names another namespace or a future schema version', async () => {
    const ledger = new MailWorkflowLedger(store);
    // Validly encrypted (correct key and AAD) content that names a wrong namespace / future schema version.
    const original = await readFile(ledgerFile(), 'utf8');
    for (const mutate of [(d: Record<string, unknown>) => (d.namespace = 'user-0123456789abcdef'), (d: Record<string, unknown>) => (d.version = 2)]) {
      const data = (await ledger.read()) as unknown as Record<string, unknown>;
      mutate(data);
      const keys = deriveLedgerKeys(parseKey(await readFile(dirs.keyFile)), 'root');
      await writeFile(ledgerFile(), sealLedger(keys, 'root', Buffer.from(JSON.stringify(data))), { mode: 0o600 });
      expect(await rejection(ledger.read())).toMatchObject({ code: 'ledger_corrupt' });
      await writeFile(ledgerFile(), original, { mode: 0o600 });
    }
  });

  it('refuses symlinked, group-readable, oversized or non-regular ledgers', async () => {
    const ledger = new MailWorkflowLedger(store);
    const real = path.join(dirs.root, 'elsewhere.enc');
    await rename(ledgerFile(), real);
    await symlink(real, ledgerFile());
    expect(await rejection(ledger.read())).toMatchObject({ code: 'insecure_path' });
    expect(await rejection(ledger.transact(() => {}))).toMatchObject({ code: 'insecure_path' });
    expect((await lstat(ledgerFile())).isSymbolicLink()).toBe(true);
    await rm(ledgerFile());
    await rename(real, ledgerFile());

    await chmod(ledgerFile(), 0o640);
    expect(await rejection(ledger.read())).toMatchObject({ code: 'insecure_path' });
    await chmod(ledgerFile(), 0o600);

    const saved = await readFile(ledgerFile());
    await truncate(ledgerFile(), MAX_LEDGER_FILE_BYTES + 1);
    expect(await rejection(ledger.read())).toMatchObject({ code: 'ledger_corrupt' });
    await writeFile(ledgerFile(), saved, { mode: 0o600 });

    await rm(ledgerFile());
    await mkdir(ledgerFile(), { mode: 0o700 });
    expect(await rejection(ledger.read())).toMatchObject({ code: 'insecure_path' });
  });

  it('fails closed when the store key is missing or replaced', async () => {
    const ledger = new MailWorkflowLedger(store);
    await ledger.read();
    const key = await readFile(dirs.keyFile);
    await rm(dirs.keyFile);
    expect(await rejection(ledger.transact(() => {}))).toMatchObject({ code: 'key_missing' });
    await writeFile(dirs.keyFile, generateKeyFileContents(), { mode: 0o600 });
    expect(await rejection(ledger.read())).toMatchObject({ code: 'wrong_key' });
    await writeFile(dirs.keyFile, key, { mode: 0o600 });
    expect((await ledger.read()).sends).toEqual([]);
  });

  it('refuses a stale or concurrently held lock without taking it over', async () => {
    const ledger = new MailWorkflowLedger(store);
    const lock = path.join(dirs.dataDir, LEDGER_LOCK);
    await mkdir(lock, { mode: 0o700 });
    const old = new Date(Date.now() - 120_000);
    await utimes(lock, old, old);
    const before = await readFile(ledgerFile());
    expect(await rejection(ledger.transact((d) => void d.sends.push(record(1))))).toMatchObject({ code: 'lock_stale' });
    expect((await stat(lock)).isDirectory()).toBe(true);
    expect(await readFile(ledgerFile())).toEqual(before);
  });

  it('bounds send records (fail closed when full) and keeps audit as a counted ring', async () => {
    const ledger = new MailWorkflowLedger(store);
    await ledger.transact((d) => {
      for (let i = 0; i < MAX_SEND_RECORDS; i++) d.sends.push(record(i));
    });
    expect(await rejection(ledger.transact((d) => void d.sends.push(record(MAX_SEND_RECORDS))))).toMatchObject({ code: 'ledger_full' });
    expect((await ledger.read()).sends).toHaveLength(MAX_SEND_RECORDS);

    for (let i = 0; i < MAX_AUDIT_EVENTS + 5; i += 500) {
      await ledger.transact((d) => {
        for (let j = i; j < Math.min(i + 500, MAX_AUDIT_EVENTS + 5); j++) ledger.appendAudit(d, event(j));
      });
    }
    const data = await ledger.read();
    expect(data.audit).toHaveLength(MAX_AUDIT_EVENTS);
    expect(data.auditDropped).toBe(5);
    expect(data.audit[0]!.operationId).toBe(event(5).operationId);
  });

  it('rejects records with unsafe or unbounded fields before writing', async () => {
    const ledger = new MailWorkflowLedger(store);
    const before = await readFile(ledgerFile());
    for (const bad of [
      { ...event(1), type: 'mail_send\nInjected: yes' },
      { ...event(1), code: 'x'.repeat(200) },
      { ...event(1), accountId: 'friend@example.test' },
      { ...event(1), subject: 'Secret subject' },
    ]) {
      const err = await rejection(ledger.transact((d) => void d.audit.push(bad as AuditEvent)));
      expect((err as { code?: string }).code).toBe('ledger_schema');
    }
    const badRecord = { ...record(1), providerMessageId: '<abc@gmx.at>' };
    expect(await rejection(ledger.transact((d) => void d.sends.push(badRecord)))).toMatchObject({ code: 'ledger_schema' });
    expect(await readFile(ledgerFile())).toEqual(before);
  });

  it('fails closed on a write failure and leaves the previous ledger intact', async () => {
    const ledger = new MailWorkflowLedger(store);
    await ledger.transact((d) => void d.sends.push(record(1)));
    const before = await readFile(ledgerFile());
    await chmod(dirs.dataDir, 0o500);
    const err = await rejection(ledger.transact((d) => void d.sends.push(record(2))));
    expect(err).toBeInstanceOf(Error);
    await chmod(dirs.dataDir, 0o700);
    expect(await readFile(ledgerFile())).toEqual(before);
    expect((await ledger.read()).sends).toHaveLength(1);
  });

  it('derives domain-separated, namespace-bound MACs', async () => {
    const ledger = new MailWorkflowLedger(store);
    const a = await ledger.mac('send-key', ['x', 'y']);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
    expect(await ledger.mac('send-key', ['x', 'y'])).toBe(a);
    expect(await ledger.mac('send-payload', ['x', 'y'])).not.toBe(a);
    // Length-prefixed parts: no ambiguity between ['xy'] and ['x','y'].
    expect(await ledger.mac('send-key', ['xy'])).not.toBe(a);
    const other = await makeTempDirs();
    await initStore({ dataDir: other.dataDir, keyFile: other.keyFile });
    const otherLedger = new MailWorkflowLedger(await CredentialStore.open({ dataDir: other.dataDir, keyFile: other.keyFile }));
    expect(await otherLedger.mac('send-key', ['x', 'y'])).not.toBe(a);
    await other.cleanup();
  });
});
