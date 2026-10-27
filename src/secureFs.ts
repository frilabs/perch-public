import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, link, lstat, mkdir, open, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { PerchError } from './errors.js';

const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;

async function lstatOrNull(p: string) {
  try {
    return await lstat(p);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function pathExists(p: string): Promise<boolean> {
  return (await lstatOrNull(p)) !== null;
}

const ownedByMe = (uid: number) => typeof process.getuid !== 'function' || uid === process.getuid();

/**
 * Ensures an owner-only directory. Directories Perch creates get 0700 (every newly created
 * level). A pre-existing directory is never chmodded: if it is a symlink, foreign-owned or
 * accessible by group/others, this fails closed with instructions.
 */
export async function ensurePrivateDir(dir: string): Promise<void> {
  const st = await lstatOrNull(dir);
  if (!st) {
    const first = await mkdir(dir, { recursive: true, mode: 0o700 });
    if (first) {
      // mkdir's mode is subject to umask; fix only the levels this call created.
      for (let p = path.resolve(dir); ; p = path.dirname(p)) {
        await chmod(p, 0o700);
        if (p === path.resolve(first) || p === path.dirname(p)) break;
      }
      return;
    }
  }
  const cur = st ?? (await lstat(dir));
  if (cur.isSymbolicLink()) throw new PerchError(`Refusing symlinked directory: ${dir}`, 'insecure_path');
  if (!cur.isDirectory()) throw new PerchError(`Not a directory: ${dir}`, 'insecure_path');
  if (!ownedByMe(cur.uid)) throw new PerchError(`Directory ${dir} is not owned by the current user`, 'insecure_path');
  if ((cur.mode & 0o077) !== 0) {
    throw new PerchError(
      `Directory ${dir} is accessible by group/others (mode ${(cur.mode & 0o777).toString(8)}). Perch keeps secrets only ` +
        `in private directories: if this directory is meant for Perch, run chmod 700 '${dir}'; otherwise choose another path.`,
      'insecure_path',
    );
  }
}

/**
 * Checks an EXISTING owner-only directory without creating or changing anything: it must be a real
 * directory (not a symlink), owned by the current user and closed to group/others.
 */
export async function assertPrivateDir(dir: string): Promise<void> {
  const st = await lstatOrNull(dir);
  if (!st) throw new PerchError(`Directory not found: ${dir}`, 'not_initialised');
  if (st.isSymbolicLink()) throw new PerchError(`Refusing symlinked directory: ${dir}`, 'insecure_path');
  if (!st.isDirectory()) throw new PerchError(`Not a directory: ${dir}`, 'insecure_path');
  if (!ownedByMe(st.uid)) throw new PerchError(`Directory ${dir} is not owned by the current user`, 'insecure_path');
  if ((st.mode & 0o077) !== 0) throw new PerchError(`Directory ${dir} is accessible by group/others (run chmod 700 '${dir}')`, 'insecure_path');
}

/**
 * Reads a regular, owner-only, non-symlink file. The checks run on the opened handle (fstat),
 * so the file that is validated is the file that is read. O_NONBLOCK keeps FIFOs from hanging.
 */
export async function readPrivateFile(file: string): Promise<Buffer> {
  let fh;
  try {
    fh = await open(file, constants.O_RDONLY | O_NOFOLLOW | (constants.O_NONBLOCK ?? 0));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') throw new PerchError(`File not found: ${file}`, 'not_found');
    if (code === 'ELOOP') throw new PerchError(`Refusing symlinked file: ${file}`, 'insecure_path');
    throw err;
  }
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new PerchError(`Not a regular file: ${file}`, 'insecure_path');
    if ((st.mode & 0o077) !== 0) {
      throw new PerchError(`Insecure permissions on ${file} (expected 0600; run: chmod 600 '${file}')`, 'insecure_path');
    }
    if (!ownedByMe(st.uid)) throw new PerchError(`File ${file} is not owned by the current user`, 'insecure_path');
    return await fh.readFile();
  } finally {
    await fh.close();
  }
}

/**
 * Atomically replaces `file` with `data` (mode 0600): exclusive temp file in the same directory,
 * fsync, rename, fsync directory. Refuses to replace a symlink.
 */
export async function writePrivateFileAtomic(file: string, data: Uint8Array): Promise<void> {
  const st = await lstatOrNull(file);
  if (st?.isSymbolicLink()) throw new PerchError(`Refusing symlinked file: ${file}`, 'insecure_path');
  if (st && !st.isFile()) throw new PerchError(`Not a regular file: ${file}`, 'insecure_path');
  const tmp = await writeTempFile(file, data);
  try {
    await rename(tmp, file);
  } catch (err) {
    await unlink(tmp).catch(() => {});
    throw err;
  }
  await syncDir(path.dirname(file));
}

/**
 * Creates `file` (mode 0600) with complete contents only if it does not exist yet: the data is
 * written to a temp file and hard-linked into place, which fails with EEXIST instead of
 * overwriting. Returns false when the file already existed.
 */
export async function writePrivateFileExclusive(file: string, data: Uint8Array): Promise<boolean> {
  const tmp = await writeTempFile(file, data);
  try {
    await link(tmp, file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw err;
  } finally {
    await unlink(tmp).catch(() => {});
  }
  await syncDir(path.dirname(file));
  return true;
}

async function writeTempFile(file: string, data: Uint8Array): Promise<string> {
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${randomBytes(6).toString('hex')}.tmp`);
  const fh = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW, 0o600);
  try {
    await fh.writeFile(data);
    await fh.sync();
  } catch (err) {
    await fh.close();
    await unlink(tmp).catch(() => {});
    throw err;
  }
  await fh.close();
  return tmp;
}

async function syncDir(dir: string): Promise<void> {
  const dh = await open(dir, constants.O_RDONLY);
  try {
    await dh.sync();
  } catch {
    // Directory fsync is not supported on every platform; rename/link are still atomic.
  } finally {
    await dh.close();
  }
}
