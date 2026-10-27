import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, rmdir, unlink } from 'node:fs/promises';
import { hostname } from 'node:os';
import path from 'node:path';
import { PerchError } from '../errors.js';

/** A lock older than this is reported as stale (holders keep it for milliseconds). */
export const STALE_MS = 60_000;
const TIMEOUT_MS = 15_000;

/**
 * Cross-process exclusive lock: an atomically created directory (mkdir) holding an `owner`
 * file with a random token. There is deliberately NO automatic takeover of stale locks,
 * because a takeover cannot be made race-free with plain filesystem calls. A lock left by a
 * crashed process makes writes fail closed until the operator removes it (see docs/SETUP.md).
 * Release only removes a lock whose owner token is ours.
 */
export async function withFileLock<T>(lockDir: string, fn: () => Promise<T>): Promise<T> {
  const token = randomBytes(16).toString('hex');
  const deadline = Date.now() + TIMEOUT_MS;
  let delay = 5;
  for (;;) {
    try {
      await mkdir(lockDir, { mode: 0o700 });
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    }
    let age = 0;
    try {
      age = Date.now() - (await lstat(lockDir)).mtimeMs;
    } catch {
      continue; // released between mkdir and lstat; retry at once
    }
    if (age > STALE_MS) {
      throw new PerchError(
        `Credential store lock ${lockDir} is stale (held for ${Math.round(age / 1000)}s, probably by a crashed process). ` +
          `If no perch process is running, remove it manually: rm -r '${lockDir}'`,
        'lock_stale',
      );
    }
    if (Date.now() > deadline) {
      throw new PerchError(`Timed out waiting for the credential store lock ${lockDir}`, 'lock_timeout');
    }
    await new Promise((r) => setTimeout(r, delay + Math.random() * delay));
    delay = Math.min(delay * 2, 100);
  }

  const ownerFile = path.join(lockDir, 'owner');
  try {
    const fh = await open(ownerFile, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await fh.writeFile(JSON.stringify({ token, pid: process.pid, host: hostname(), since: new Date().toISOString() }));
    await fh.close();
  } catch (err) {
    await rmdir(lockDir).catch(() => {});
    throw err;
  }

  try {
    return await fn();
  } finally {
    await release(lockDir, ownerFile, token);
  }
}

async function release(lockDir: string, ownerFile: string, token: string): Promise<void> {
  let owner: { token?: unknown };
  try {
    owner = JSON.parse(await readFile(ownerFile, 'utf8')) as { token?: unknown };
  } catch {
    return; // not our lock any more (removed or replaced manually): leave it alone
  }
  if (owner.token !== token) return;
  await unlink(ownerFile).catch(() => {});
  await rmdir(lockDir).catch(() => {});
}
