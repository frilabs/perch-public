// Runs the adversarial-HTML suite (test/adversarial/) in a child process with a hard kill timeout.
// A super-linear HTML-to-text conversion blocks the event loop, which no in-process timer can
// interrupt; isolating it lets this test fail cleanly instead of hanging `npm test`.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { expect, it } from 'vitest';

const CHILD_TIMEOUT_MS = 45_000;

it('converts adversarial HTML bodies in linear time (isolated child process, hard timeout)', async () => {
  const child = spawn(
    process.execPath,
    [path.resolve('node_modules/vitest/vitest.mjs'), 'run', '--config', 'vitest.adversarial.config.ts', '--reporter', 'dot'],
    // Own process group, so the timeout also kills vitest's forked workers (a hung worker would
    // otherwise survive its parent and keep spinning).
    { stdio: ['ignore', 'pipe', 'pipe'], detached: true, env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' } },
  );
  let output = '';
  child.stdout.on('data', (c: Buffer) => (output += c.toString()));
  child.stderr.on('data', (c: Buffer) => (output += c.toString()));
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try {
      process.kill(-child.pid!, 'SIGKILL');
    } catch {
      child.kill('SIGKILL');
    }
  }, CHILD_TIMEOUT_MS);
  const code = await new Promise<number | null>((resolve) => child.once('exit', (c) => resolve(c)));
  clearTimeout(timer);
  expect(timedOut, `adversarial suite killed after ${CHILD_TIMEOUT_MS} ms (hung):\n${output.slice(-2000)}`).toBe(false);
  expect(code, output.slice(-4000)).toBe(0);
}, CHILD_TIMEOUT_MS + 10_000);
