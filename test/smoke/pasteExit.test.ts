// The paste-the-address prompt of the built artifact must not keep a process alive once the loopback callback won
// (docs/GUIDED_PROVIDER_SETUP_SPEC.md §2). A child reads from its real process.stdin (a pipe the parent keeps open,
// presented as a TTY); after the abort it has to exit on its own. No network is involved.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

const PROMPT = pathToFileURL(path.resolve('dist/cli/prompt.js')).href;

function child(abortAfterMs: number | null) {
  const script = `
    import { readPastedLineFromTty } from ${JSON.stringify(PROMPT)};
    process.stdin.isTTY = true;
    process.stdin.setRawMode = () => process.stdin;
    const ac = new AbortController();
    readPastedLineFromTty('Address: ', ac.signal).then((v) => process.stdout.write('done:' + String(v)));
    ${abortAfterMs === null ? '' : `setTimeout(() => ac.abort(), ${abortAfterMs});`}
  `;
  // stdin stays an open pipe for the child's whole life: only the reader itself can let the process end.
  const p = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  p.stdout.on('data', (d) => (stdout += d));
  const exited = new Promise<number | null>((resolve) => p.on('exit', (code) => resolve(code)));
  return { p, exited, stdout: () => stdout };
}

describe('paste prompt and process exit', () => {
  it('a cancelled paste prompt lets the process exit although stdin stays open', async () => {
    expect(existsSync(new URL(PROMPT)), 'run `npm run build` first').toBe(true);
    const c = child(100);
    const code = await Promise.race([c.exited, new Promise<'hung'>((r) => setTimeout(() => r('hung'), 10_000))]);
    if (code === 'hung') c.p.kill();
    expect(code).toBe(0);
    expect(c.stdout()).toBe('done:undefined');
  });

  it('control: without the abort the pending prompt keeps it alive', async () => {
    const c = child(null);
    const code = await Promise.race([c.exited, new Promise<'alive'>((r) => setTimeout(() => r('alive'), 1500))]);
    expect(code).toBe('alive');
    c.p.kill();
    await c.exited;
  });
});
