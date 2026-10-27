// Mail-related CLI commands. IMAP verification is injected (no mail server is contacted);
// the password comes from the (test) masked-prompt hook, never from argv.
import { stat } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runCli, type CliIo } from '../src/cli/run.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import type { UpstreamTransport } from '../src/upstream.js';
import { dummySecret, makeTempDirs, type TempDirs } from './support/fixtures.js';
import { MockGoogle } from './support/mockGoogle.js';

let dirs: TempDirs;
let out: string[];
let err: string[];
let verified: string[];
const password = dummySecret('GMX-APP-PASSWORD');

function io(extra: Partial<CliIo> = {}): CliIo {
  return {
    env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: dirs.root },
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    readSecret: async () => password,
    imapVerify: async (account) => {
      verified.push(account.imap.host);
    },
    ...extra,
  };
}

const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });

beforeEach(async () => {
  dirs = await makeTempDirs();
  out = [];
  err = [];
  verified = [];
  expect(await runCli(['init'], io())).toBe(0);
  out = [];
});
afterEach(async () => {
  await dirs.cleanup();
});

describe('perch imap', () => {
  it('adds a GMX account from the preset with the password from the masked prompt only', async () => {
    const code = await runCli(['imap', 'add', '--label', 'GMX', '--email', 'dummy@gmx.at', '--allow-send'], io());
    expect(err.join('')).toBe('');
    expect(code).toBe(0);
    expect(verified).toEqual(['imap.gmx.net']);
    const [acct] = (await (await openStore()).read()).imap;
    expect(acct).toMatchObject({
      label: 'GMX',
      email: 'dummy@gmx.at',
      imap: { host: 'imap.gmx.net', port: 993 },
      smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
      allowSend: true,
      allowDrafts: false,
      password,
    });
    expect(out.join('') + err.join('')).not.toContain(password);
  });

  it('refuses a password on the command line', async () => {
    expect(await runCli(['imap', 'add', '--label', 'X', '--email', 'dummy@gmx.at', `--password=${password}`], io())).toBe(2);
    expect(err.join('')).toMatch(/never accepted as command-line arguments/i);
    expect(verified).toEqual([]);
  });

  it('prints GMX presets with activation hints', async () => {
    expect(await runCli(['imap', 'presets'], io())).toBe(0);
    const text = out.join('');
    expect(text).toContain('imap.gmx.net');
    expect(text).toContain('imap.gmx.com');
    expect(text).toMatch(/IMAP/);
  });
});

describe('perch client', () => {
  it('creates a grant with a private token file, lists and removes it', async () => {
    await runCli(['imap', 'add', '--label', 'GMX', '--email', 'dummy@gmx.at', '--allow-send'], io());
    const id = (await (await openStore()).read()).imap[0]!.id;
    out = [];
    const tokenFile = `${dirs.root}/config/clients/laptop.token`;
    expect(await runCli(['client', 'add', '--label', 'Laptop', '--allow', 'read,send', '--account', id, '--token-file', tokenFile], io())).toBe(0);
    expect((await stat(tokenFile)).mode & 0o777).toBe(0o600);
    const token = (await (await import('node:fs/promises')).readFile(tokenFile, 'utf8')).trim();
    expect(out.join('')).not.toContain(token);
    expect(out.join('')).toContain(tokenFile);

    out = [];
    expect(await runCli(['client', 'list'], io())).toBe(0);
    expect(out.join('')).toMatch(/Laptop.*read,send/);
    const clientId = /client-[a-f0-9]{8}/.exec(out.join(''))![0];
    expect(await runCli(['client', 'remove', clientId], io())).toBe(0);
    expect((await (await openStore()).read()).clients).toEqual([]);
  });

  it('rejects unknown capabilities and unknown accounts', async () => {
    expect(await runCli(['client', 'add', '--label', 'X', '--allow', 'admin', '--account', 'imap-00000000'], io())).toBe(1);
    expect(err.join('')).toMatch(/unknown capability/i);
    err = [];
    expect(await runCli(['client', 'add', '--label', 'X', '--allow', 'send', '--account', 'imap-00000000'], io())).toBe(1);
    expect(err.join('')).toMatch(/unknown mail account/i);
  });
});

describe('perch gmail configuration errors', () => {
  it('requires PERCH_GOOGLE_CLIENT_FILE for gmail add', async () => {
    expect(await runCli(['gmail', 'add', '--label', 'Private'], io())).toBe(1);
    expect(err.join('')).toMatch(/PERCH_GOOGLE_CLIENT_FILE/);
  });

  it('lists mail accounts in perch accounts', async () => {
    await runCli(['imap', 'add', '--label', 'GMX', '--email', 'dummy@gmx.at'], io());
    out = [];
    expect(await runCli(['accounts'], io())).toBe(0);
    expect(out.join('')).toMatch(/Mail accounts:[\s\S]*imap-[a-f0-9]{8}\s+"GMX"\s+dummy@gmx\.at/);
  });
});

/** Approves the first printed auth URL by calling the loopback redirect, as a browser would (MOCK consent). */
function autoApprove(match: RegExp, approve: (url: string) => string) {
  let done = false;
  return (s: string) => {
    err.push(s);
    const m = match.exec(s);
    if (m && !done) {
      done = true;
      const url = new URL(m[0]);
      const code = approve(url.toString());
      const redirect = new URL(url.searchParams.get('redirect_uri')!);
      void fetch(`http://127.0.0.1:${redirect.port}${redirect.pathname}?code=${code}&state=${url.searchParams.get('state')}`);
    }
  };
}

describe('OAuth onboarding via CLI [MOCK Google/Gmail]', () => {
  it('gmail add requests read-only by default and send only with --allow-send', async () => {
    const send = 'https://www.googleapis.com/auth/gmail.send';
    const readonly = 'https://www.googleapis.com/auth/gmail.readonly';
    const google = new MockGoogle({ grantedScope: `${readonly} ${send}` });
    const acct = google.addAccount('dummy.gmail@example.test');
    // MOCK Gmail profile endpoint backed by the MOCK Google token issuer.
    const transport: UpstreamTransport = async (req) => {
      if (req.url.origin === 'https://gmail.googleapis.com' && req.url.pathname === '/gmail/v1/users/me/profile') {
        const a = google.accessTokens.get((req.headers.authorization ?? '').replace(/^Bearer /, ''));
        return a
          ? { status: 200, headers: {}, body: Buffer.from(JSON.stringify({ emailAddress: a.email })) }
          : { status: 401, headers: {}, body: Buffer.from('{}') };
      }
      return google.transport(req);
    };
    const clientFile = `${dirs.root}/client.json`;
    const { writeFile } = await import('node:fs/promises');
    await writeFile(clientFile, JSON.stringify({ installed: { client_id: dummySecret('C'), client_secret: dummySecret('S') } }), { mode: 0o600 });
    let requestedScope = '';
    const cliIo = io({
      transport,
      env: { ...io().env, PERCH_GOOGLE_CLIENT_FILE: clientFile },
      stderr: autoApprove(/https:\/\/accounts\.google\.com\S+/, (url) => {
        requestedScope = new URL(url).searchParams.get('scope')!;
        return google.approve(url, acct);
      }),
    });
    expect(await runCli(['gmail', 'add', '--label', 'Private', '--allow-send', '--timeout', '10'], cliIo), err.join('')).toBe(0);
    expect(requestedScope.split(' ').sort()).toEqual([readonly, send].sort());
    const [g] = (await (await openStore()).read()).gmail;
    expect(g).toMatchObject({ label: 'Private', email: 'dummy.gmail@example.test', refreshToken: acct.refreshToken });
    expect(err.join('') + out.join('')).not.toContain(acct.refreshToken);
  });


});

describe('--allow-modify opt-in (organizing) [MOCK]', () => {
  it('imap add stores allowModify only with --allow-modify (false by default)', async () => {
    expect(await runCli(['imap', 'add', '--label', 'GMX', '--email', 'dummy@gmx.at'], io())).toBe(0);
    expect(await runCli(['imap', 'add', '--label', 'GMX2', '--email', 'dummy2@gmx.at', '--allow-modify'], io())).toBe(0);
    const [plain, organize] = (await (await openStore()).read()).imap;
    expect(plain).toMatchObject({ allowModify: false, allowSend: false, allowDrafts: false });
    expect(organize).toMatchObject({ allowModify: true, allowSend: false, allowDrafts: false });
    expect(out.join('')).toContain('organize on');
  });

  it('imap add --no-sent-copy stores sentCopy: false; without it the field is absent (automatic, on for GMX)', async () => {
    expect(await runCli(['imap', 'add', '--label', 'GMX', '--email', 'dummy@gmx.at'], io())).toBe(0);
    expect(await runCli(['imap', 'add', '--label', 'GMX2', '--email', 'dummy2@gmx.at', '--no-sent-copy'], io())).toBe(0);
    const [auto, off] = (await (await openStore()).read()).imap;
    expect(auto!.sentCopy).toBeUndefined();
    expect(off!.sentCopy).toBe(false);
    expect(out.join('')).toContain('sent copy on');
    expect(out.join('')).toContain('sent copy off');
  });

  it('gmail add --allow-modify requests gmail.modify', async () => {
    const readonly = 'https://www.googleapis.com/auth/gmail.readonly';
    const modify = 'https://www.googleapis.com/auth/gmail.modify';
    const google = new MockGoogle({ grantedScope: `${readonly} ${modify}` });
    const gAcct = google.addAccount('dummy.gmail@example.test');
    const transport: UpstreamTransport = async (req) => {
      if (req.url.origin === 'https://gmail.googleapis.com' && req.url.pathname === '/gmail/v1/users/me/profile') {
        const a = google.accessTokens.get((req.headers.authorization ?? '').replace(/^Bearer /, ''));
        return a ? { status: 200, headers: {}, body: Buffer.from(JSON.stringify({ emailAddress: a.email })) } : { status: 401, headers: {}, body: Buffer.from('{}') };
      }
      return google.transport(req);
    };
    const clientFile = `${dirs.root}/client.json`;
    const { writeFile } = await import('node:fs/promises');
    await writeFile(clientFile, JSON.stringify({ installed: { client_id: dummySecret('C'), client_secret: dummySecret('S') } }), { mode: 0o600 });
    let gScope = '';
    const gIo = io({
      transport,
      env: { ...io().env, PERCH_GOOGLE_CLIENT_FILE: clientFile },
      stderr: autoApprove(/https:\/\/accounts\.google\.com\S+/, (url) => {
        gScope = new URL(url).searchParams.get('scope')!;
        return google.approve(url, gAcct);
      }),
    });
    expect(await runCli(['gmail', 'add', '--label', 'Private', '--allow-modify', '--timeout', '10'], gIo), err.join('')).toBe(0);
    expect(gScope.split(' ').sort()).toEqual([modify, readonly].sort());

  });
});
