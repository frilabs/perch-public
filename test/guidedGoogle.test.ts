// Guided Google preparation (docs/GUIDED_PROVIDER_SETUP_SPEC.md §1) and the hidden JSON paste prompt.
// MOCK only: the Google login runs against MockGoogleUnified; every client id and secret is dummy data.
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { jsonBlockComplete, readSecretJsonFromTty, type TtyInput } from '../src/cli/prompt.js';
import { runCli, type CliIo } from '../src/cli/run.js';
import { MAX_CLIENT_JSON_BYTES, validateClientJson } from '../src/google/clientSetup.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockGoogleUnified } from './support/mockGoogleUnified.js';

let dirs: TempDirs;
let out: string;
let err: string;
let secret: string;
let clientId: string;

const clientJson = (over: Record<string, unknown> = {}, type = 'installed') =>
  JSON.stringify({
    [type]: {
      client_id: clientId,
      project_id: 'perch-test-123',
      auth_uri: 'https://accounts.google.com/o/oauth2/auth',
      token_uri: 'https://oauth2.googleapis.com/token',
      client_secret: secret,
      redirect_uris: ['http://localhost'],
      ...over,
    },
  });

function io(answers: string[], pastes: string[], extra: Partial<CliIo> = {}): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root },
    stdout: (s) => void (out += s),
    stderr: (s) => void (err += s),
    readSecret: async () => {
      throw new Error('MOCK: not asked');
    },
    readLine: async () => {
      const a = answers.shift();
      if (a === undefined) throw new Error('MOCK: no more answers');
      return a;
    },
    readSecretJson: async () => {
      const p = pastes.shift();
      if (p === undefined) throw new Error('MOCK: no more pastes');
      return p;
    },
    ...extra,
  };
}

const defaultFile = () => path.join(dirs.root, '.config', 'perch', 'google-client.json');

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = '';
  err = '';
  secret = dummySecret('GCLIENT-SECRET');
  clientId = `123456789012-${dummySecret('ID').toLowerCase().replace(/[^a-z0-9]/g, '')}.apps.googleusercontent.com`;
  expect(await runCli(['init'], io([], []))).toBe(0);
  out = '';
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('client JSON validation', () => {
  it('accepts a Desktop app client, single-line or pretty-printed', () => {
    expect(validateClientJson(clientJson())).toMatchObject({ clientId, clientSecret: secret });
    expect(validateClientJson(JSON.stringify(JSON.parse(clientJson()), null, 2)).clientId).toBe(clientId);
  });

  it.each([
    ['a Web application client', () => clientJson({}, 'web'), /"Web application".*"Desktop app"/],
    ['broken JSON', () => clientJson().slice(0, -3), /not valid JSON/],
    ['no installed key', () => JSON.stringify({ other: {} }), /"installed"/],
    ['a foreign client id', () => clientJson({ client_id: 'abc.example.com' }), /\.apps\.googleusercontent\.com/],
    ['no client secret', () => clientJson({ client_secret: '' }), /client_secret/],
    ['no http://localhost redirect', () => clientJson({ redirect_uris: ['urn:ietf:wg:oauth:2.0:oob'] }), /http:\/\/localhost/],
    ['too large', () => clientJson({ padding: 'x'.repeat(MAX_CLIENT_JSON_BYTES) }), /larger than/],
    ['empty', () => '  ', /nothing was pasted/],
  ])('refuses %s without repeating the input', (_name, make, msg) => {
    const e = (() => {
      try {
        validateClientJson(make());
      } catch (x) {
        return x as Error;
      }
      throw new Error('expected a rejection');
    })();
    expect(e.message).toMatch(msg);
    expect(e.message).not.toContain(secret);
  });
});

/** A fake terminal: chunks are typed into it; setRawMode is recorded. */
function fakeTty() {
  const s = new PassThrough() as PassThrough & TtyInput & { raw: boolean[] };
  s.isTTY = true;
  s.raw = [];
  s.setRawMode = (m: boolean) => (s.raw.push(m), s);
  return s;
}

describe('hidden JSON paste prompt', () => {
  it('knows when a JSON paste is complete (braces in strings do not count)', () => {
    expect(jsonBlockComplete('{"a":1}')).toBe(true);
    expect(jsonBlockComplete('{"installed":{\n"a":"}"')).toBe(false);
    expect(jsonBlockComplete('{"a":"{"}')).toBe(true);
    expect(jsonBlockComplete('{"a":"\\"}"')).toBe(false);
    expect(jsonBlockComplete('not json')).toBe(true);
  });

  it('reads a multi-line paste up to the closing brace without echo and restores the terminal', async () => {
    const tty = fakeTty();
    let shown = '';
    const p = readSecretJsonFromTty('JSON: ', 1000, tty, (s) => void (shown += s));
    const doc = JSON.stringify(JSON.parse(clientJson()), null, 2).replace(/\n/g, '\r');
    tty.write(doc.slice(0, 40));
    tty.write(`${doc.slice(40)}\r`);
    const value = await p;
    expect(JSON.parse(value).installed.client_secret).toBe(secret);
    expect(shown).toBe('JSON: \n');
    expect(tty.raw).toEqual([true, false]);
    expect(tty.listenerCount('data')).toBe(0);
    expect(tty.isPaused()).toBe(true);
  });

  it('refuses oversized input, Ctrl+C and a missing terminal', async () => {
    const big = fakeTty();
    const tooBig = readSecretJsonFromTty('JSON: ', 50, big, () => {});
    big.write(`{"a":"${'x'.repeat(100)}`);
    await expect(tooBig).rejects.toThrow(/larger than 50 bytes/);
    expect(big.listenerCount('data')).toBe(0);
    const ctrlC = fakeTty();
    const aborted = readSecretJsonFromTty('JSON: ', 50, ctrlC, () => {});
    ctrlC.write('{"a\u0003');
    await expect(aborted).rejects.toThrow(/Aborted/);
    const pipe = new PassThrough() as PassThrough & TtyInput;
    await expect(readSecretJsonFromTty('JSON: ', 50, pipe, () => {})).rejects.toThrow(/TTY/);
  });
});

describe('perch google client setup', () => {
  it('walks through the steps with project-scoped links and stores the client 0600 at the default path', async () => {
    // Answers: read/write -> w, project id, Enter x3 (APIs, consent screen, client).
    const answers = ['w', 'perch-test-123', '', '', ''];
    const code = await runCli(['google', 'client', 'setup', '--services', 'drive,calendar'], io(answers, ['garbage', clientJson()]));
    expect(err).toBe('');
    expect(code).toBe(0);
    expect(answers).toEqual([]);
    expect(out).toContain('https://console.cloud.google.com/projectcreate');
    expect(out).toContain('https://console.cloud.google.com/apis/library/drive.googleapis.com?project=perch-test-123');
    expect(out).toContain('https://console.cloud.google.com/apis/library/calendar-json.googleapis.com?project=perch-test-123');
    expect(out).not.toContain('gmail.googleapis.com');
    expect(out).not.toContain('people.googleapis.com');
    expect(out).toContain('https://console.cloud.google.com/auth/audience?project=perch-test-123');
    expect(out).toContain('https://console.cloud.google.com/auth/scopes?project=perch-test-123');
    expect(out).toContain('https://console.cloud.google.com/auth/clients/create?project=perch-test-123');
    expect(out).toContain('Desktop app');
    // Scope list for exactly the chosen services and access (write: full Drive and own calendar events).
    expect(out).toContain('       https://www.googleapis.com/auth/drive.readonly\n');
    expect(out).toContain('       https://www.googleapis.com/auth/drive\n');
    expect(out).toContain('       https://www.googleapis.com/auth/calendar.events.owned\n');
    expect(out).toContain('       https://www.googleapis.com/auth/userinfo.email\n');
    expect(out).not.toMatch(/gmail\.|contacts/);
    expect(out).toMatch(/not valid JSON.*Try again/);
    expect(out).toMatch(/7 days/);
    expect(out + err).not.toContain(secret);

    const file = defaultFile();
    expect((await stat(file)).mode & 0o777).toBe(0o600);
    expect((await stat(path.dirname(file))).mode & 0o777).toBe(0o700);
    expect(JSON.parse(await readFile(file, 'utf8')).installed).toMatchObject({ client_id: clientId, client_secret: secret });

    out = '';
    expect(await runCli(['google', 'client', 'show'], io([], []))).toBe(0);
    expect(out).toContain(`file: ${file} (default path)`);
    expect(out).toContain('12345678…');
    expect(out).not.toContain(secret);
    expect(out).not.toContain(clientId);
  });

  it('asks before replacing a stored client and keeps it on "no"', async () => {
    expect(await runCli(['google', 'client', 'setup', '--services', 'drive', '--read-only'], io(['', '', '', ''], [clientJson()]))).toBe(0);
    const before = await readFile(defaultFile(), 'utf8');
    out = '';
    const answers = ['n'];
    expect(await runCli(['google', 'client', 'setup'], io(answers, []))).toBe(0);
    expect(out).toContain('Kept the existing client');
    expect(await readFile(defaultFile(), 'utf8')).toBe(before);
  });

  it('writes to PERCH_GOOGLE_CLIENT_FILE when it is set, and gives up after three bad pastes', async () => {
    const custom = path.join(dirs.root, 'secrets', 'google.json');
    await mkdir(path.dirname(custom), { mode: 0o700 });
    const base = io(['not a project id!', '', '', ''], [clientJson({}, 'web'), clientJson()]);
    expect(await runCli(['google', 'client', 'setup', '--services', 'gmail', '--read-only'], { ...base, env: { ...base.env, PERCH_GOOGLE_CLIENT_FILE: custom } })).toBe(0);
    expect(out).toContain('Invalid project ID');
    expect(out).toContain('https://console.cloud.google.com/apis/library/gmail.googleapis.com\n');
    expect(out).toMatch(/"Web application" client/);
    expect(out).toContain(custom);
    expect((await stat(custom)).mode & 0o777).toBe(0o600);

    err = '';
    const bad = io(['y', '', '', '', ''], ['x', 'y', 'z']);
    expect(await runCli(['google', 'client', 'setup', '--services', 'drive', '--read-only'], { ...bad, env: { ...bad.env, PERCH_GOOGLE_CLIENT_FILE: custom } })).toBe(1);
    expect(err).toMatch(/not valid JSON/);
  });
});

describe('perch setup hint for Google', () => {
  it('announces the guided preparation when no client exists, and the browser-address login', async () => {
    const { runSetup } = await import('../src/cli/onboarding.js');
    const { resolveConfig } = await import('../src/config.js');
    const answers = ['y', 'Private', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n'];
    let shown = '';
    await runSetup(
      resolveConfig(io([], []).env),
      { stdout: (s) => void (shown += s), stderr: () => {}, readLine: async () => answers.shift() ?? 'n' },
      async () => 0,
    );
    expect(shown).toMatch(/Set up a Google OAuth client once/);
    expect(shown).toMatch(/copy its full address and paste it here/);
  });
});

describe('Google add commands without a client file', () => {
  it('without a terminal: a clear error pointing to perch google client setup', async () => {
    const noTty = io([], [], { readLine: undefined, readSecretJson: undefined });
    expect(await runCli(['gmail', 'add', '--label', 'Private', '--read-only'], noTty)).toBe(1);
    expect(err).toMatch(/No usable Google OAuth client at .*google-client\.json \(it does not exist yet\)\. Run perch google client setup/);
    err = '';
    const prodTty = io([], [], {
      readLine: async () => {
        const { PerchError } = await import('../src/errors.js');
        throw new PerchError('no tty', 'no_tty');
      },
    });
    expect(await runCli(['google-productivity', 'add', '--label', 'P', '--services', 'calendar', '--read-only'], prodTty)).toBe(1);
    expect(err).toMatch(/perch google client setup/);
  });

  it('an insecure client file stays an error (the guide never replaces it)', async () => {
    await mkdir(path.dirname(defaultFile()), { recursive: true, mode: 0o700 });
    await writeFile(defaultFile(), clientJson(), { mode: 0o644 });
    expect(await runCli(['google', 'add', '--label', 'P', '--services', 'drive', '--read-only'], io([], []))).toBe(1);
    expect(err).toMatch(/Insecure permissions/);
  });

  it('perch google add runs the guide for the chosen services, then logs in by pasted address [mock Google]', async () => {
    const google = new MockGoogleUnified();
    const person = google.addPerson('dummy.guided@example.test');
    let authUrl = '';
    // Services and access first, then: set up now? y, project id skipped, Enter x3.
    const answers = ['gmail,contacts', 'r', 'y', '', '', '', ''];
    const base = io(answers, [clientJson()], {
      transport: google.transport,
      stderr: (s) => {
        err += s;
        authUrl = /https:\/\/accounts\.google\.com\S+/.exec(s)?.[0] ?? authUrl;
      },
      // The browser could not reach the server: the operator pastes the address instead (no callback request).
      readPastedUrl: async () => {
        const u = new URL(authUrl);
        const code = google.approve(authUrl, person);
        return `${u.searchParams.get('redirect_uri')}?state=${u.searchParams.get('state')}&code=${code}&scope=x`;
      },
    });
    expect(await runCli(['google', 'add', '--label', 'Private', '--timeout', '10'], base)).toBe(0);
    expect(answers).toEqual([]);
    expect(out).toContain('gmail.googleapis.com');
    expect(out).toContain('people.googleapis.com');
    expect(out).not.toContain('drive.googleapis.com');
    expect(out).toContain('https://www.googleapis.com/auth/gmail.readonly');
    expect(out).not.toContain('https://www.googleapis.com/auth/gmail.send');
    expect(err).toMatch(/This site can't be reached/);
    expect(err).toMatch(/copy its full address and paste it here/);
    expect(out + err).not.toContain(secret);
    expect(out + err).not.toContain(person.refreshToken);
    expect((await stat(defaultFile())).mode & 0o777).toBe(0o600);
    const data = await (await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile })).read();
    expect(data.googleGroups[0]).toMatchObject({ email: 'dummy.guided@example.test', clientId, clientSecret: secret });
  });
});
