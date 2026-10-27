import { describe, expect, it } from 'vitest';
import { runCli } from '../src/cli/run.js';

async function help(args: string[]) {
  let output = '';
  const code = await runCli(args, {
    env: { PERCH_PRIVATE_BASE_URL: 'invalid' },
    stdout: value => { output += value; },
    stderr: () => { throw new Error('Help must not fail'); },
    readSecret: async () => { throw new Error('Help must not prompt'); },
    readLine: async () => { throw new Error('Help must not pair'); },
  });
  expect(code).toBe(0);
  return output;
}

describe('CLI help navigation', () => {
  it.each([[], ['--help'], ['help']])('shows the three task groups without initializing configuration: %j', async (...args) => {
    const output = await help(args as string[]);
    const headings = ['1. Set up your server', '2. Connect AI clients', '3. Connect apps and accounts'];
    expect(output.indexOf(headings[0]!)).toBeLessThan(output.indexOf(headings[1]!));
    expect(output.indexOf(headings[1]!)).toBeLessThan(output.indexOf(headings[2]!));
    for (const heading of headings) expect(output).toContain(heading);
    expect(output).toContain('perch help --all');
    expect(output.split('\n').length).toBeLessThan(65);
  });
  it('shows AI targets without starting pairing', async () => {
    const output = await help(['connect', '--help']);
    for (const target of ['codex', 'claude-code', 'claude-ai', 'chatgpt', 'desktop', 'server-agent', 'other']) expect(output).toContain(`--target ${target}`);
    expect(output).toContain('--no-pair');
    expect(output).not.toContain('perch microsoft add');
  });
  it('keeps the full reference available', async () => {
    expect(await help(['help', '--all'])).toContain('perch mail-workflow resolve');
    expect(await help(['--help', '--all'])).toContain('--smtp-security tls|starttls');
  });
});
