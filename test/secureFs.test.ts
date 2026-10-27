import { execFileSync } from 'node:child_process';
import { chmod, mkdir, readdir, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ensurePrivateDir, readPrivateFile, writePrivateFileAtomic } from '../src/secureFs.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';

let dirs: TempDirs;
beforeEach(async () => {
  dirs = await makeTempDirs();
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('secureFs', () => {
  it('creates owner-only directories', async () => {
    const dir = path.join(dirs.root, 'a', 'b');
    await ensurePrivateDir(dir);
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
  });

  it('writes files atomically with 0600 and leaves no temp files', async () => {
    await ensurePrivateDir(dirs.dataDir);
    const file = path.join(dirs.dataDir, 'x.bin');
    await writePrivateFileAtomic(file, Buffer.from('one'));
    await writePrivateFileAtomic(file, Buffer.from('two'));
    expect((await stat(file)).mode & 0o777).toBe(0o600);
    expect((await readPrivateFile(file)).toString()).toBe('two');
    expect(await readdir(dirs.dataDir)).toEqual(['x.bin']);
  });

  it('refuses to read group/world-accessible files', async () => {
    await ensurePrivateDir(dirs.dataDir);
    const file = path.join(dirs.dataDir, 'loose');
    await writeFile(file, 'x', { mode: 0o644 });
    await chmod(file, 0o644);
    await expect(readPrivateFile(file)).rejects.toThrow(/permissions/i);
  });

  it('refuses symlinked files on read and write', async () => {
    await ensurePrivateDir(dirs.dataDir);
    const target = path.join(dirs.root, 'target');
    await writeFile(target, 'x', { mode: 0o600 });
    const link = path.join(dirs.dataDir, 'link');
    await symlink(target, link);
    await expect(readPrivateFile(link)).rejects.toThrow(/symlink/i);
    await expect(writePrivateFileAtomic(link, Buffer.from('y'))).rejects.toThrow(/symlink/i);
  });

  it('refuses a symlinked private directory', async () => {
    const real = path.join(dirs.root, 'real');
    await mkdir(real, { mode: 0o700 });
    const link = path.join(dirs.root, 'linkdir');
    await symlink(real, link);
    await expect(ensurePrivateDir(link)).rejects.toThrow(/symlink/i);
  });

  it('refuses (and never chmods) a pre-existing directory with loose permissions', async () => {
    const dir = path.join(dirs.root, 'loose');
    await mkdir(dir, { mode: 0o755 });
    await chmod(dir, 0o755);
    await expect(ensurePrivateDir(dir)).rejects.toThrow(/chmod 700/);
    expect((await stat(dir)).mode & 0o777).toBe(0o755);
  });

  it('accepts a pre-existing private directory and makes all newly created levels 0700', async () => {
    const dir = path.join(dirs.root, 'x', 'y', 'z');
    await ensurePrivateDir(dir);
    for (const p of ['x', 'x/y', 'x/y/z']) expect((await stat(path.join(dirs.root, p))).mode & 0o777).toBe(0o700);
    await ensurePrivateDir(dir);
  });

  it('rejects directories and FIFOs as private files (checked on the opened handle)', async () => {
    await ensurePrivateDir(dirs.dataDir);
    await expect(readPrivateFile(dirs.dataDir)).rejects.toThrow(/regular file/i);
    const fifo = path.join(dirs.dataDir, 'fifo');
    execFileSync('mkfifo', ['-m', '600', fifo]);
    await expect(readPrivateFile(fifo)).rejects.toThrow(/regular file/i);
  });
});
