// CLI behaviour with MOCK Google/Notion transports. No live services, only generated dummy secrets.
import { readFile, stat } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readSecretFromTty } from '../src/cli/prompt.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import type { UpstreamTransport } from '../src/upstream.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockGoogleUnified } from './support/mockGoogleUnified.js';
import { MockNotion } from './support/mockNotion.js';

let dirs: TempDirs;
let out: string[];
let err: string[];

function io(extra: Partial<CliIo> = {}): CliIo {
  return {
    env: {
      PERCH_DATA_DIR: dirs.dataDir,
      HOME: dirs.root,
      PERCH_KEY_FILE: dirs.keyFile,
      PERCH_HTTP_TOKEN_FILE: dirs.tokenFile,
    },
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    readSecret: async () => {
      throw new Error('no TTY in tests');
    },
    ...extra,
  };
}

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = [];
  err = [];
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('perch CLI', () => {
  it('init creates key, store and an owner-only HTTP token without printing it', async () => {
    expect(await runCli(['init'], io())).toBe(0);
    const token = (await readFile(dirs.tokenFile, 'utf8')).trim();
    expect(token.length).toBeGreaterThanOrEqual(43);
    expect((await stat(dirs.tokenFile)).mode & 0o777).toBe(0o600);
    expect(out.join('') + err.join('')).not.toContain(token);
    expect(await runCli(['init'], io())).toBe(0);
    expect((await readFile(dirs.tokenFile, 'utf8')).trim()).toBe(token);
  });

  it('commands other than init fail cleanly before init', async () => {
    expect(await runCli(['accounts'], io())).toBe(1);
    expect(err.join('')).toMatch(/perch init/);
  });

  it('refuses secrets passed as arguments', async () => {
    await runCli(['init'], io());
    for (const flag of ['--token', '--pat', '--client-secret', '--refresh-token', '--secret']) {
      err = [];
      expect(await runCli(['notion', 'add', '--label', 'X', flag, dummySecret('ARG')], io())).toBe(2);
      expect(err.join('')).toMatch(/never accepted as command-line arguments/i);
    }
  });

  it('adds, lists and removes a Notion workspace with the PAT read via masked prompt [mock Notion]', async () => {
    await runCli(['init'], io());
    const notion = new MockNotion();
    const ws = notion.addWorkspace('A');
    const code = await runCli(
      ['notion', 'add', '--label', 'Personal'],
      io({ transport: notion.transport, readSecret: async () => ws.token }),
    );
    expect(code).toBe(0);
    expect(out.join('') + err.join('')).not.toContain(ws.token);
    out = [];
    expect(await runCli(['accounts'], io())).toBe(0);
    const listing = out.join('');
    expect(listing).toMatch(/notion-[a-f0-9]{8}/);
    expect(listing).toContain('Personal');
    expect(listing).not.toContain(ws.token);
    const id = /notion-[a-f0-9]{8}/.exec(listing)![0];
    expect(await runCli(['notion', 'remove', id], io())).toBe(0);
    expect(out.join('')).toMatch(/revoke/i);
    const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    expect((await store.read()).notion).toHaveLength(0);
  });

  it('notion add fails without a TTY (production prompt, test stdin is not a TTY)', async () => {
    await runCli(['init'], io());
    expect(process.stdin.isTTY).toBeFalsy();
    expect(await runCli(['notion', 'add', '--label', 'X'], io({ readSecret: readSecretFromTty }))).toBe(1);
    expect(err.join('')).toMatch(/TTY/);
  });

  it('google add --services drive runs the loopback flow and stores a one-service group [mock Google]', async () => {
    await runCli(['init'], io());
    const google = new MockGoogleUnified();
    const person = google.addPerson('dummy.cli@example.test');
    const clientFile = `${dirs.root}/client_secret_dummy.json`;
    const { writeFile } = await import('node:fs/promises');
    await writeFile(
      clientFile,
      JSON.stringify({ installed: { client_id: dummySecret('CLIENT'), client_secret: dummySecret('CLIENT-SECRET') } }),
      { mode: 0o600 },
    );
    const transport: UpstreamTransport = google.transport;
    const stderrLines: string[] = [];
    let approved = false;
    const cliIo = io({
      transport,
      env: { ...io().env, PERCH_GOOGLE_CLIENT_FILE: clientFile },
      stderr: (s) => {
        stderrLines.push(s);
        const m = /https:\/\/accounts\.google\.com\S+/.exec(s);
        if (m && !approved) {
          approved = true;
          const url = new URL(m[0]);
          const code = google.approve(url.toString(), person);
          void fetch(`${url.searchParams.get('redirect_uri')}?code=${code}&state=${url.searchParams.get('state')}`);
        }
      },
    });
    expect(await runCli(['google', 'add', '--label', 'Private', '--services', 'drive', '--timeout', '10'], cliIo)).toBe(0);
    expect(stderrLines.join('')).not.toContain(person.refreshToken);
    const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    const data = await store.read();
    expect(data.googleGroups[0]).toMatchObject({ label: 'Private', email: 'dummy.cli@example.test', refreshToken: person.refreshToken });
    const [g] = data.google;
    expect(g).toMatchObject({ label: 'Private', email: 'dummy.cli@example.test', groupId: data.googleGroups[0]!.id });
    const token = person.refreshToken;

    out = [];
    expect(await runCli(['google', 'remove', data.googleGroups[0]!.id, '--revoke'], io({ transport }))).toBe(0);
    expect(google.revoked).toEqual([token]);
  });

  it('google add --allow-write requests and stores the full drive scope [mock Google]', async () => {
    await runCli(['init'], io());
    const google = new MockGoogleUnified();
    const person = google.addPerson('dummy.write@example.test');
    const clientFile = `${dirs.root}/client_secret_dummy.json`;
    const { writeFile } = await import('node:fs/promises');
    await writeFile(clientFile, JSON.stringify({ installed: { client_id: dummySecret('CLIENT'), client_secret: dummySecret('CLIENT-SECRET') } }), { mode: 0o600 });
    let requested = '';
    const cliIo = io({
      transport: google.transport,
      env: { ...io().env, PERCH_GOOGLE_CLIENT_FILE: clientFile },
      stderr: (s) => {
        const m = /https:\/\/accounts\.google\.com\S+/.exec(s);
        if (m && !requested) {
          const url = new URL(m[0]);
          requested = url.searchParams.get('scope') ?? '';
          void fetch(`${url.searchParams.get('redirect_uri')}?code=${google.approve(url.toString(), person)}&state=${url.searchParams.get('state')}`);
        }
      },
    });
    expect(await runCli(['google', 'add', '--label', 'Write', '--services', 'drive', '--allow-write', '--timeout', '10'], cliIo)).toBe(0);
    expect(requested).toBe('openid email https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/drive');
    const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    expect((await store.read()).google[0]!.scopes).toEqual(['https://www.googleapis.com/auth/drive.readonly', 'https://www.googleapis.com/auth/drive']);
    expect(out.join('')).toMatch(/client grant/);
  });

  it('serve --http fails closed without a token', async () => {
    await runCli(['init'], io({ env: { ...io().env, PERCH_HTTP_TOKEN_FILE: `${dirs.root}/none/token` } }));
    const { rm } = await import('node:fs/promises');
    await rm(`${dirs.root}/none/token`, { force: true });
    err = [];
    expect(await runCli(['serve', '--http'], io({ env: { ...io().env, PERCH_HTTP_TOKEN_FILE: `${dirs.root}/none/token` } }))).toBe(1);
    expect(err.join('')).toMatch(/token/i);
  });

  it('rejects out-of-range --timeout values before starting the OAuth flow', async () => {
    await runCli(['init'], io());
    for (const t of ['99999999', '0', '-5', 'abc', '3601']) {
      err = [];
      expect(await runCli(['google', 'add', '--label', 'X', `--timeout=${t}`], io())).toBe(2);
      expect(err.join('')).toMatch(/--timeout/);
    }
  });

  it('init validates the strength of an existing token file and of PERCH_HTTP_TOKEN', async () => {
    const { mkdir, writeFile } = await import('node:fs/promises');
    await mkdir(`${dirs.root}/config`, { recursive: true, mode: 0o700 });
    await writeFile(dirs.tokenFile, 'weak\n', { mode: 0o600 });
    expect(await runCli(['init'], io())).toBe(1);
    expect(err.join('')).toMatch(/at least 43/);
    err = [];
    expect(await runCli(['init'], io({ env: { ...io().env, PERCH_HTTP_TOKEN: 'weak' } }))).toBe(1);
    expect(err.join('')).toMatch(/at least 43/);
  });

  it('serve --http refuses wildcard binds', async () => {
    await runCli(['init'], io());
    expect(await runCli(['serve', '--http', '--host', '0.0.0.0'], io())).toBe(1);
    expect(err.join('')).toMatch(/Refusing to bind/);
  });
});
