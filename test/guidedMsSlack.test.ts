import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runCli, type CliIo } from '../src/cli/run.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import { makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockSlack } from './support/mockSlack.js';

let dirs: TempDirs;
let out: string;
let err: string;
let prompts: string[];

interface IoOpts extends Partial<CliIo> {
  /** When the scripted answers run out: 'throw' (default) or 'hang' (a prompt racing another event). */
  exhausted?: 'throw' | 'hang';
}

function io(answers: string[] = [], { exhausted = 'throw', ...extra }: IoOpts = {}): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root },
    stdout: (s) => void (out += s),
    stderr: (s) => void (err += s),
    readSecret: async () => {
      throw new Error('MOCK: no secret expected');
    },
    readLine: async (p) => {
      prompts.push(p);
      const a = answers.shift();
      if (a !== undefined) return a;
      if (exhausted === 'hang') return new Promise<string>(() => {});
      throw new Error(`MOCK: no more answers (prompt: ${p})`);
    },
    ...extra,
  };
}

const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = '';
  err = '';
  prompts = [];
  expect(await runCli(['init'], io())).toBe(0);
  out = '';
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('perch slack add guide [MOCK Slack]', () => {
  function slackIo(answers: string[], secrets: string[]) {
    const slack = mock;
    return io(answers, {
      transport: slack.transport,
      readSecret: async (p) => {
        prompts.push(`SECRET:${p}`);
        const s = secrets.shift();
        if (s === undefined) throw new Error('MOCK: no secret');
        return s;
      },
    });
  }
  let mock: MockSlack;
  beforeEach(() => {
    mock = new MockSlack();
  });

  it('shows browser steps before the hidden session prompts without an app menu or confirmation', async () => {
    const team = mock.addTeam('A', { session: true });
    expect(await runCli(['slack', 'add', '--label', 'Company'], slackIo([], [team.cookie!, team.token]))).toBe(0);
    expect(out).toContain('https://app.slack.com/client');
    expect(out).toContain('Cookies');
    expect(out).not.toMatch(/manifest|Install to Workspace|User OAuth Token|new_app=1/);
    expect(prompts).toEqual([
      expect.stringMatching(/^SECRET:Slack cookie/),
      expect.stringMatching(/^SECRET:Slack session token/),
    ]);
    expect(out.indexOf('app.slack.com/client')).toBeLessThan(out.indexOf('Connected Slack workspace'));
    expect(out + err).not.toContain(team.token);
    expect(out + err).not.toContain(team.cookie);
  });

  it('--skip-guide goes straight to the hidden cookie and token prompts', async () => {
    const team = mock.addTeam('A', { session: true });
    expect(await runCli(['slack', 'add', '--label', 'Company', '--skip-guide'], slackIo([], [team.cookie!, team.token]))).toBe(0);
    expect(out).not.toContain('app.slack.com/client');
    expect(prompts).toEqual([expect.stringMatching(/^SECRET:/), expect.stringMatching(/^SECRET:/)]);
  });

  it('reconnecting needs only the cookie and token, with no repeat-guide question', async () => {
    const team = mock.addTeam('A', { session: true });
    expect(await runCli(['slack', 'add', '--label', 'A', '--skip-guide'], slackIo([], [team.cookie!, team.token]))).toBe(0);
    const id = (await (await openStore()).read()).slack[0]!.id;
    out = '';
    prompts = [];
    expect(await runCli(['slack', 'add', '--label', 'A'], slackIo([], [team.cookie!, team.token]))).toBe(0);
    expect(prompts).toHaveLength(2);
    expect(prompts.every((p) => p.startsWith('SECRET:'))).toBe(true);
    expect(out).toContain(`Updated Slack workspace ${id}`);
    expect((await (await openStore()).read()).slack).toHaveLength(1);
  });

  it('without credentials the masked prompt fails without falling back to an app', async () => {
    const noTty = slackIo([], []);
    delete noTty.readLine;
    expect(await runCli(['slack', 'add', '--label', 'X'], noTty)).toBe(1);
    expect(out).not.toContain('new_app=1');
  });
});

describe('perch setup hints', () => {
  it('Microsoft uses one browser login and Slack guides through preparation', async () => {
    // google n, microsoft y → the label prompt is next; the scripted answers end there (focus: the hint).
    await runCli(['setup'], io(['n', 'y']));
    expect(out).toMatch(/Sign in to Microsoft/);
    expect(out).not.toMatch(/Graph|Entra/);
    out = '';
    // google, microsoft, imap, notion n; slack y.
    await runCli(['setup'], io(['n', 'n', 'n', 'n', 'y']));
    expect(out).toMatch(/Open Slack in your browser/);
    expect(out).toMatch(/connect the session/);
    expect(out).not.toMatch(/manifest|create.*app|admin approval/i);
  });
});
