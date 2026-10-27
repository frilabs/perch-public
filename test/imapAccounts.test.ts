// IMAP presets, server resolution and account onboarding. Onboarding uses a stubbed verifier;
// verifyImapAccount runs against local MOCK servers on 127.0.0.1 only. No real mail server is
// contacted and all credentials are generated dummies.
import type { AddressInfo } from 'node:net';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { SMTPServer } from 'smtp-server';
import { PerchError } from '../src/errors.js';
import { addImapAccount, removeImapAccount, verifyImapAccount } from '../src/mail/imapAccounts.js';
import { IMAP_PRESETS, presetForEmail, resolveServers } from '../src/mail/imapPresets.js';
import { CredentialStore, initStore, type ImapAccount } from '../src/store/credentialStore.js';
import { dummySecret, makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { makeSelfSignedCert, startMockImapServer, type TestCert } from './support/tlsCert.js';

describe('IMAP presets', () => {
  it('maps GMX Austria/Germany domains to the gmx.net servers (993 / 465 implicit TLS)', () => {
    for (const email of ['dummy@gmx.at', 'dummy@gmx.de', 'Dummy@GMX.NET']) expect(presetForEmail(email)).toBe('gmx');
    const s = resolveServers({ email: 'dummy@gmx.at' });
    expect(s).toEqual({
      preset: 'gmx',
      imap: { host: 'imap.gmx.net', port: 993 },
      smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
    });
    expect(IMAP_PRESETS.gmx.smtpStarttlsPort).toBe(587);
    expect(IMAP_PRESETS.gmx.notes).toMatch(/Allow POP3 and IMAP access/);
    expect(IMAP_PRESETS.gmx.notes).toMatch(/app password/);
  });

  it('maps gmx.com and other international GMX domains to the gmx.com servers', () => {
    for (const email of ['dummy@gmx.com', 'dummy@gmx.us', 'dummy@gmx.co.uk', 'dummy@gmx.fr']) {
      expect(presetForEmail(email)).toBe('gmx-com');
    }
    expect(resolveServers({ email: 'dummy@gmx.com' })).toEqual({
      preset: 'gmx-com',
      imap: { host: 'imap.gmx.com', port: 993 },
      smtp: { host: 'mail.gmx.com', port: 465, security: 'tls' },
    });
  });

  it('supports the STARTTLS alternative on 587 and explicit presets', () => {
    expect(resolveServers({ email: 'dummy@gmx.de', smtpSecurity: 'starttls' }).smtp).toEqual({
      host: 'mail.gmx.net',
      port: 587,
      security: 'starttls',
    });
    expect(resolveServers({ email: 'dummy@example.test', preset: 'gmx-com' }).imap.host).toBe('imap.gmx.com');
    expect(() => resolveServers({ email: 'dummy@gmx.at', preset: 'nope' })).toThrow(/Unknown preset/);
  });

  it('requires explicit hosts for unknown domains and validates them', () => {
    expect(presetForEmail('dummy@example.test')).toBeUndefined();
    expect(() => resolveServers({ email: 'dummy@example.test' })).toThrow(/imapHost and smtpHost/);
    const s = resolveServers({ email: 'dummy@example.test', imapHost: 'imap.example.test', smtpHost: 'smtp.example.test' });
    expect(s).toEqual({
      imap: { host: 'imap.example.test', port: 993 },
      smtp: { host: 'smtp.example.test', port: 465, security: 'tls' },
    });
    const base = { email: 'dummy@example.test', imapHost: 'imap.example.test', smtpHost: 'smtp.example.test' };
    for (const imapHost of ['127.0.0.1', '[::1]', '::1', 'user@imap.example.test', 'imap.example.test:993', 'imap..example', '-x.example', 'a b']) {
      expect(() => resolveServers({ ...base, imapHost }), imapHost).toThrow(/hostname/);
    }
    for (const smtpPort of [0, 65536, 1.5, Number.NaN]) {
      expect(() => resolveServers({ ...base, smtpPort }), String(smtpPort)).toThrow(/port/);
    }
    expect(() => resolveServers({ ...base, smtpSecurity: 'plain' as never })).toThrow(/smtpSecurity/);
  });

  it('rejects a malformed email', async () => {
    expect((await rejection(Promise.resolve().then(() => resolveServers({ email: 'not-an-address' })))).message).toMatch(/email/);
  });
});

describe('addImapAccount / removeImapAccount', () => {
  let dirs: TempDirs;
  let store: CredentialStore;
  beforeEach(async () => {
    dirs = await makeTempDirs();
    await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
    store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  });
  afterEach(async () => {
    await dirs.cleanup();
  });

  const password = dummySecret('GMX-APP-PASSWORD');
  const input = (over: Record<string, unknown> = {}) => ({
    label: ' GMX privat ',
    email: 'dummy.me@gmx.at',
    password,
    allowDrafts: true,
    allowSend: false,
    ...over,
  });

  it('verifies before saving and stores the resolved preset account', async () => {
    const seen: ImapAccount[] = [];
    const account = await addImapAccount(store, input(), async (a) => {
      expect((await store.read()).imap).toEqual([]); // nothing saved yet
      seen.push(a);
    });
    expect(seen).toHaveLength(1);
    expect(account).toMatchObject({
      label: 'GMX privat',
      email: 'dummy.me@gmx.at',
      username: 'dummy.me@gmx.at',
      password,
      preset: 'gmx',
      imap: { host: 'imap.gmx.net', port: 993 },
      smtp: { host: 'mail.gmx.net', port: 465, security: 'tls' },
      allowDrafts: true,
      allowSend: false,
    });
    expect(account.id).toMatch(/^imap-[a-f0-9]{8}$/);
    expect(seen[0]).toEqual(account);
    expect((await store.read()).imap).toEqual([account]);
  });

  it('supports explicit hosts, username, STARTTLS and a drafts mailbox', async () => {
    const a = await addImapAccount(
      store,
      input({ email: 'dummy@example.test', username: 'dummy-login', imapHost: 'imap.example.test', smtpHost: 'smtp.example.test', smtpSecurity: 'starttls', draftsMailbox: 'Entwürfe' }),
      async () => {},
    );
    expect(a).toMatchObject({ username: 'dummy-login', imap: { host: 'imap.example.test', port: 993 }, smtp: { host: 'smtp.example.test', port: 587, security: 'starttls' }, draftsMailbox: 'Entwürfe' });
    expect(a.preset).toBeUndefined();
  });

  it('stores nothing when verification fails, and never echoes the password', async () => {
    const err = await rejection(
      addImapAccount(store, input(), async (a) => {
        throw new Error(`login failed for ${a.username} with ${a.password}`);
      }),
    );
    expect(err).toBeInstanceOf(PerchError);
    expect(err.message).not.toContain(password);
    expect((await store.read()).imap).toEqual([]);

    const err2 = await rejection(
      addImapAccount(store, input(), async (a) => {
        throw new PerchError(`IMAP said: bad password ${a.password}`, 'imap_auth');
      }),
    );
    expect(err2).toMatchObject({ code: 'imap_auth' });
    expect(err2.message).not.toContain(password);
    expect((await store.read()).imap).toEqual([]);
  });

  it('rejects duplicates (same email + IMAP host) and invalid input without verifying', async () => {
    await addImapAccount(store, input(), async () => {});
    let verified = 0;
    const verify = async () => {
      verified++;
    };
    expect(await rejection(addImapAccount(store, input({ email: 'Dummy.Me@GMX.at', label: 'again' }), verify))).toMatchObject({ code: 'duplicate_account' });
    for (const bad of [
      input({ label: '' }),
      input({ password: '' }),
      input({ password: 'a\r\nb' }),
      input({ email: 'nope' }),
      input({ allowSend: 'yes' }),
      input({ draftsMailbox: 'a\nb' }),
      input({ imapHost: '10.0.0.1', smtpHost: 'smtp.example.test' }),
    ]) {
      const e = await rejection(addImapAccount(store, bad as never, verify));
      expect(e).toBeInstanceOf(PerchError);
      expect(e.message).not.toContain(password);
    }
    expect(verified).toBe(0);
    expect((await store.read()).imap).toHaveLength(1);
  });

  it('removes an account (and its stored password)', async () => {
    const a = await addImapAccount(store, input(), async () => {});
    await removeImapAccount(store, a.id);
    expect((await store.read()).imap).toEqual([]);
    expect(await rejection(removeImapAccount(store, a.id))).toMatchObject({ code: 'unknown_account' });
  });
});

describe('verifyImapAccount against local MOCK servers over real TLS', () => {
  let cert: TestCert;
  beforeAll(async () => {
    cert = await makeSelfSignedCert('localhost');
  });
  const pass = dummySecret('VERIFY-PASSWORD');
  const acct = (imapPort: number, smtpPort: number, allowSend: boolean): ImapAccount => ({
    id: 'imap-0a1b2c3d',
    label: 'Local',
    email: 'dummy.me@gmx.at',
    username: 'dummy.me@gmx.at',
    password: pass,
    imap: { host: 'localhost', port: imapPort },
    smtp: { host: 'localhost', port: smtpPort, security: 'tls' },
    allowDrafts: false,
    allowSend,
    createdAt: '2026-10-05T00:00:00.000Z',
    updatedAt: '2026-10-05T00:00:00.000Z',
  });

  it('logs in to IMAP, and to SMTP only when sending is allowed', async () => {
    const imap = await startMockImapServer(cert, { user: 'dummy.me@gmx.at', pass });
    const smtpAuths: string[] = [];
    const smtp = new SMTPServer({
      secure: true,
      key: cert.key,
      cert: cert.cert,
      authOptional: false,
      logger: false,
      disableReverseLookup: true,
      onAuth(auth, _s, cb) {
        smtpAuths.push(auth.username ?? '');
        cb(auth.password === pass ? null : new Error('bad'), { user: auth.username });
      },
    });
    smtp.on('error', () => {});
    await new Promise<void>((r) => smtp.listen(0, '127.0.0.1', r));
    const smtpPort = (smtp.server.address() as AddressInfo).port;
    try {
      const trust = { testOnlyTlsTrust: { ca: cert.cert } };
      await verifyImapAccount(acct(imap.port, smtpPort, false), trust);
      expect(imap.log.logins).toHaveLength(1);
      expect(smtpAuths).toEqual([]);
      await verifyImapAccount(acct(imap.port, smtpPort, true), trust);
      expect(imap.log.logins).toHaveLength(2);
      expect(smtpAuths).toEqual(['dummy.me@gmx.at']);
      // Without the test-only trust the self-signed certificate is refused.
      expect(await rejection(verifyImapAccount(acct(imap.port, smtpPort, false)))).toMatchObject({ code: 'imap_tls' });
      const bad = await rejection(verifyImapAccount({ ...acct(imap.port, smtpPort, true), password: dummySecret('WRONG') }, trust));
      expect(bad).toMatchObject({ code: 'imap_auth' });
    } finally {
      await imap.close();
      await new Promise<void>((r) => smtp.close(() => r()));
    }
  });
});
