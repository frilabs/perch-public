// Test fixtures. Every "secret" produced here is generated, unmistakably dummy data.
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

export function dummySecret(kind: string): string {
  return `DUMMY-TEST-${kind}-${randomBytes(12).toString('hex')}`;
}

/** Resolves with the error a promise rejects with; fails if it resolves. */
export async function rejection(p: Promise<unknown>): Promise<Error> {
  try {
    await p;
  } catch (err) {
    return err as Error;
  }
  throw new Error('expected the promise to reject');
}

export interface TempDirs {
  root: string;
  dataDir: string;
  keyFile: string;
  tokenFile: string;
  cleanup(): Promise<void>;
}

export async function makeTempDirs(): Promise<TempDirs> {
  const root = await mkdtemp(path.join(tmpdir(), 'perch-test-'));
  return {
    root,
    dataDir: path.join(root, 'data'),
    keyFile: path.join(root, 'config', 'store.key'),
    tokenFile: path.join(root, 'config', 'http-token'),
    // Retries: a background audit write of a just-closed server can still be creating files.
    cleanup: () => rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }),
  };
}
