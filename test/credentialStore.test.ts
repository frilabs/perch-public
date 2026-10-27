import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, stat, symlink, unlink, utimes, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { CredentialStore, initStore, storeFilePath } from '../src/store/credentialStore.js';
import { decryptEnvelope, encryptEnvelope } from '../src/store/crypto.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
const paths = () => ({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });

beforeEach(async () => {
  dirs = await makeTempDirs();
});
afterEach(async () => {
  await dirs.cleanup();
});

function notionEntry(id: string) {
  const now = new Date().toISOString();
  return { id, label: `Label ${id}`, token: dummySecret('PAT'), createdAt: now, updatedAt: now };
}

describe('crypto envelope', () => {
  it('round-trips and uses a fresh IV per encryption', () => {
    const key = randomBytes(32);
    const a = encryptEnvelope(key, Buffer.from('hello'));
    const b = encryptEnvelope(key, Buffer.from('hello'));
    expect(a).not.toEqual(b);
    expect(decryptEnvelope(key, a).toString()).toBe('hello');
  });

  it('detects tampering of ciphertext, tag and header', () => {
    const key = randomBytes(32);
    const env = JSON.parse(encryptEnvelope(key, Buffer.from('secret payload')));
    const flip = (b64: string) => {
      const buf = Buffer.from(b64, 'base64');
      buf[0] = buf[0]! ^ 0xff;
      return buf.toString('base64');
    };
    expect(() => decryptEnvelope(key, JSON.stringify({ ...env, ct: flip(env.ct) }))).toThrow(/integrity/i);
    expect(() => decryptEnvelope(key, JSON.stringify({ ...env, tag: flip(env.tag) }))).toThrow(/integrity/i);
    expect(() => decryptEnvelope(key, JSON.stringify({ ...env, iv: flip(env.iv) }))).toThrow(/integrity/i);
    expect(() => decryptEnvelope(key, JSON.stringify({ ...env, v: 2 }))).toThrow(/format/i);
    expect(() => decryptEnvelope(key, 'not json')).toThrow(/format/i);
  });

  it('rejects truncated tags, wrong IV lengths and non-canonical base64', () => {
    const key = randomBytes(32);
    const env = JSON.parse(encryptEnvelope(key, Buffer.from('secret payload')));
    const tag = Buffer.from(env.tag, 'base64');
    const iv = Buffer.from(env.iv, 'base64');
    // A GCM tag prefix verifies unless the length is pinned to 16 bytes.
    for (const len of [4, 8, 12, 15]) {
      expect(() => decryptEnvelope(key, JSON.stringify({ ...env, tag: tag.subarray(0, len).toString('base64') }))).toThrow(
        /format|integrity/i,
      );
    }
    expect(() => decryptEnvelope(key, JSON.stringify({ ...env, iv: Buffer.concat([iv, iv]).toString('base64') }))).toThrow(/format/i);
    expect(() => decryptEnvelope(key, JSON.stringify({ ...env, iv: iv.subarray(0, 8).toString('base64') }))).toThrow(/format/i);
    expect(() => decryptEnvelope(key, JSON.stringify({ ...env, ct: `${env.ct}!!` }))).toThrow(/format/i);
    expect(() => decryptEnvelope(key, JSON.stringify({ ...env, tag: env.tag.replace(/=+$/, '') }))).toThrow(/format/i);
  });

  it('reports a wrong key distinctly', () => {
    const env = encryptEnvelope(randomBytes(32), Buffer.from('x'));
    expect(() => decryptEnvelope(randomBytes(32), env)).toThrow(/wrong key/i);
  });
});

describe('CredentialStore', () => {
  it('init creates owner-only key, store and dirs; second init is a no-op', async () => {
    const first = await initStore(paths());
    expect(first).toEqual({ createdKey: true, createdStore: true });
    expect((await stat(dirs.keyFile)).mode & 0o777).toBe(0o600);
    expect((await stat(path.dirname(dirs.keyFile))).mode & 0o777).toBe(0o700);
    expect((await stat(storeFilePath(dirs.dataDir))).mode & 0o777).toBe(0o600);
    expect((await stat(dirs.dataDir)).mode & 0o777).toBe(0o700);
    const key = await readFile(dirs.keyFile, 'utf8');
    expect(await initStore(paths())).toEqual({ createdKey: false, createdStore: false });
    expect(await readFile(dirs.keyFile, 'utf8')).toBe(key);
  });

  it('persists encrypted data without plaintext secrets', async () => {
    await initStore(paths());
    const store = await CredentialStore.open(paths());
    const entry = notionEntry('notion-aaaa0001');
    await store.update((d) => {
      d.notion.push(entry);
    });
    const raw = await readFile(storeFilePath(dirs.dataDir), 'utf8');
    expect(raw).not.toContain(entry.token);
    expect(raw).not.toContain(entry.label);
    const reopened = await CredentialStore.open(paths());
    expect((await reopened.read()).notion).toEqual([entry]);
  });

  it('refuses to silently rekey when the key is lost but the DB exists', async () => {
    await initStore(paths());
    const before = await readFile(storeFilePath(dirs.dataDir));
    await unlink(dirs.keyFile);
    await expect(initStore(paths())).rejects.toThrow(/key file is missing/i);
    await expect(CredentialStore.open(paths())).rejects.toThrow(/key file is missing/i);
    await expect(stat(dirs.keyFile)).rejects.toThrow();
    expect(await readFile(storeFilePath(dirs.dataDir))).toEqual(before);
  });

  it('fails without init', async () => {
    await expect(CredentialStore.open(paths())).rejects.toThrow(/perch init/i);
  });

  it('rejects a wrong key and a tampered store', async () => {
    await initStore(paths());
    const store = await CredentialStore.open(paths());
    await store.update((d) => {
      d.notion.push(notionEntry('notion-aaaa0002'));
    });
    const file = storeFilePath(dirs.dataDir);
    const env = JSON.parse(await readFile(file, 'utf8'));
    const ct = Buffer.from(env.ct, 'base64');
    ct[3] = ct[3]! ^ 0x01;
    await writeFile(file, JSON.stringify({ ...env, ct: ct.toString('base64') }), { mode: 0o600 });
    await expect(CredentialStore.open(paths())).rejects.toThrow(/integrity/i);

    await writeFile(file, JSON.stringify(env), { mode: 0o600 });
    await writeFile(dirs.keyFile, randomBytes(32).toString('base64'), { mode: 0o600 });
    await expect(CredentialStore.open(paths())).rejects.toThrow(/wrong key/i);
  });

  it('rejects a key file inside the data directory', async () => {
    await expect(initStore({ dataDir: dirs.dataDir, keyFile: path.join(dirs.dataDir, 'k') })).rejects.toThrow(
      /outside the data directory/i,
    );
    await expect(initStore({ dataDir: dirs.dataDir, keyFile: path.join(dirs.dataDir, 'sub', 'k') })).rejects.toThrow(
      /outside the data directory/i,
    );
  });

  it('never loosens or tightens a pre-existing key parent directory (e.g. $HOME)', async () => {
    const home = path.join(dirs.root, 'home');
    await mkdir(home, { mode: 0o755 });
    await chmod(home, 0o755);
    await expect(initStore({ dataDir: dirs.dataDir, keyFile: path.join(home, 'store.key') })).rejects.toThrow(/chmod 700/);
    expect((await stat(home)).mode & 0o777).toBe(0o755);
  });

  it('rejects a malformed or loose-permission key file', async () => {
    await initStore(paths());
    await chmod(dirs.keyFile, 0o640);
    await expect(CredentialStore.open(paths())).rejects.toThrow(/permissions/i);
    await chmod(dirs.keyFile, 0o600);
    await writeFile(dirs.keyFile, 'c2hvcnQ=', { mode: 0o600 });
    await expect(CredentialStore.open(paths())).rejects.toThrow(/32 bytes/i);
  });

  it('refuses symlinked key and store files', async () => {
    await initStore(paths());
    const realKey = path.join(dirs.root, 'real.key');
    await rename(dirs.keyFile, realKey);
    await symlink(realKey, dirs.keyFile);
    await expect(CredentialStore.open(paths())).rejects.toThrow(/symlink/i);
    await unlink(dirs.keyFile);
    await rename(realKey, dirs.keyFile);

    const file = storeFilePath(dirs.dataDir);
    const realStore = path.join(dirs.root, 'real.enc');
    await rename(file, realStore);
    await symlink(realStore, file);
    await expect(CredentialStore.open(paths())).rejects.toThrow(/symlink/i);
  });

  it('makes changes from another instance (process) visible to a running reader', async () => {
    await initStore(paths());
    const server = await CredentialStore.open(paths());
    const cli = await CredentialStore.open(paths());
    expect((await server.read()).notion).toHaveLength(0);
    await cli.update((d) => {
      d.notion.push(notionEntry('notion-bbbb0001'));
    });
    expect((await server.read()).notion.map((w) => w.id)).toEqual(['notion-bbbb0001']);
    await cli.update((d) => {
      d.notion = [];
    });
    expect((await server.read()).notion).toHaveLength(0);
  });

  it('serialises concurrent writers without lost updates', async () => {
    await initStore(paths());
    const a = await CredentialStore.open(paths());
    const b = await CredentialStore.open(paths());
    await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        (i % 2 ? a : b).update((d) => {
          d.notion.push(notionEntry(`notion-cc${String(i).padStart(6, '0')}`));
        }),
      ),
    );
    const ids = (await a.read()).notion.map((w) => w.id);
    expect(ids).toHaveLength(20);
    expect(new Set(ids).size).toBe(20);
  });

  it('fails closed on a stale leftover lock instead of taking it over', async () => {
    await initStore(paths());
    const lock = path.join(dirs.dataDir, 'store.lock');
    await mkdir(lock, { mode: 0o700 });
    const old = new Date(Date.now() - 10 * 60_000);
    await utimes(lock, old, old);
    const store = await CredentialStore.open(paths());
    const add = () =>
      store.update((d) => {
        d.notion.push(notionEntry('notion-dddd0001'));
      });
    await expect(add()).rejects.toThrow(/stale.*rm -r/is);
    expect((await store.read()).notion).toHaveLength(0);
    await rm(lock, { recursive: true });
    await add();
    expect((await store.read()).notion).toHaveLength(1);
  });

  it('rejects data that does not match the schema', async () => {
    await initStore(paths());
    const store = await CredentialStore.open(paths());
    await expect(
      store.update((d) => {
        (d.notion as unknown[]).push({ id: 'bad' });
      }),
    ).rejects.toThrow(/schema/i);
  });

  it('refuses a data dir that is a symlink', async () => {
    const real = path.join(dirs.root, 'realdata');
    await mkdir(real, { mode: 0o700 });
    await symlink(real, dirs.dataDir);
    await expect(initStore(paths())).rejects.toThrow(/symlink/i);
  });
});

it('opens legacy LinkedIn state without exposing capabilities or retaining LinkedIn-only grants', async () => {
  await initStore(paths());
  const key = Buffer.from((await readFile(dirs.keyFile, 'utf8')).trim(), 'base64');
  const file = storeFilePath(dirs.dataDir);
  const data = JSON.parse(decryptEnvelope(key, await readFile(file, 'utf8')).toString());
  const legacy = { id: 'linkedin-12345678', token: dummySecret('OLD-LINKEDIN') };
  data.linkedin = [legacy];
  const grant = { label: 'Legacy', tokenSha256: 'a'.repeat(64), createdAt: new Date().toISOString() };
  data.clients = [
    { ...grant, id: 'client-11111111', capabilities: ['linkedin_read', 'linkedin_post'], accountIds: [legacy.id] },
    { ...grant, id: 'client-22222222', capabilities: ['linkedin_read', 'read'], accountIds: [legacy.id, 'imap-12345678'] },
  ];
  await writeFile(file, encryptEnvelope(key, Buffer.from(JSON.stringify(data))));
  const store = await CredentialStore.open(paths());
  const opened = await store.read();
  expect(opened.linkedin).toEqual([legacy]);
  expect(opened.clients).toHaveLength(1);
  expect(opened.clients[0]).toMatchObject({ id: 'client-22222222', capabilities: ['read'], accountIds: ['imap-12345678'] });
  await store.update(d => { d.clients[0]!.label = 'Still usable'; });
  expect((await store.read()).linkedin).toEqual([legacy]);
});
