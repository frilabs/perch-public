// SMTP sender against REAL local servers on 127.0.0.1 (smtp-server and bare TLS servers) with
// throwaway self-signed certificates. No real mail server is contacted; credentials are dummies.
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SMTPServer, type SMTPServerOptions } from 'smtp-server';
import { composeForProvider, validateOutgoing } from '../src/mail/compose.js';
import { SmtpSender } from '../src/mail/smtp.js';
import { ACCEPTED_NOTE, INDETERMINATE_NOTE } from '../src/mail/types.js';
import type { ImapAccount } from '../src/store/credentialStore.js';
import { dummySecret, rejection } from './support/fixtures.js';
import { makeSelfSignedCert, runtimeSupportsTls11, startTlsServer, type TestCert } from './support/tlsCert.js';

let cert: TestCert;
let otherCert: TestCert;
beforeAll(async () => {
  cert = await makeSelfSignedCert('localhost');
  otherCert = await makeSelfSignedCert('other.example.test');
});

const USER = 'dummy.me@gmx.at';
const PASS = dummySecret('SMTP-PASSWORD');

function account(port: number, over: Partial<ImapAccount['smtp']> = {}): ImapAccount {
  return {
    id: 'imap-0a1b2c3d',
    label: 'Local test',
    email: USER,
    username: USER,
    password: PASS,
    imap: { host: 'localhost', port: 993 },
    smtp: { host: 'localhost', port, security: 'tls', ...over },
    allowDrafts: true,
    allowSend: true,
    createdAt: '2026-10-05T00:00:00.000Z',
    updatedAt: '2026-10-05T00:00:00.000Z',
  };
}

interface Delivered {
  from?: string;
  to: string[];
  raw: Buffer;
}

async function startSmtp(over: Partial<SMTPServerOptions> = {}, behaviour: { destroyInData?: boolean } = {}) {
  const state = { connections: 0, auths: [] as string[], delivered: [] as Delivered[] };
  const server: SMTPServer = new SMTPServer({
    secure: true,
    key: cert.key,
    cert: cert.cert,
    authOptional: false,
    authMethods: ['PLAIN', 'LOGIN'],
    logger: false,
    disableReverseLookup: true,
    onConnect(_s, cb) {
      state.connections++;
      cb();
    },
    onAuth(auth, _s, cb) {
      if (auth.username === USER && auth.password === PASS) {
        state.auths.push(auth.username);
        return cb(null, { user: auth.username });
      }
      return cb(Object.assign(new Error('Invalid credentials'), { responseCode: 535 }));
    },
    onData(stream, session, cb) {
      if (behaviour.destroyInData) {
        for (const c of (server as unknown as { connections: Set<{ id: string; _socket: { destroy(): void } }> }).connections) {
          if (c.id === session.id) c._socket.destroy();
        }
        stream.resume();
        return;
      }
      const chunks: Buffer[] = [];
      stream.on('data', (c: Buffer) => chunks.push(c));
      stream.on('end', () => {
        state.delivered.push({
          ...(session.envelope.mailFrom ? { from: session.envelope.mailFrom.address } : {}),
          to: session.envelope.rcptTo.map((r) => r.address),
          raw: Buffer.concat(chunks),
        });
        cb();
      });
    },
    ...over,
  });
  server.on('error', () => {});
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.server.address() as AddressInfo).port;
  return { state, port, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

async function composed(extra: { cc?: string[]; to?: string[] } = {}) {
  const v = validateOutgoing(
    {
      to: extra.to ?? ['Dummy Recipient <dummy.to@example.test>'],
      ...(extra.cc ? { cc: extra.cc } : {}),
      bcc: ['dummy.bcc@example.test'],
      subject: 'Re: Dummy',
      text: 'Hallo – dummy body',
      inReplyTo: '<parent@example.test>',
      references: ['<root@example.test>', '<parent@example.test>'],
    },
    USER,
  );
  return composeForProvider(v, 'smtp');
}

const trusted = () => new SmtpSender({ testOnlyTlsTrust: { ca: cert.cert } });

describe('SmtpSender against a local smtp-server (implicit TLS, test-only CA trust)', () => {
  it('sends: accepted, Bcc only in the envelope, threading headers kept, AUTH used', async () => {
    const srv = await startSmtp();
    try {
      const mail = await composed();
      const res = await trusted().send(account(srv.port), mail.raw, mail.envelope);
      expect(res.status).toBe('accepted');
      expect(res.detail).toContain(ACCEPTED_NOTE);
      expect(res.providerMessageId).toMatch(/^<[^<>\s]+>$/);
      expect(srv.state.auths).toEqual([USER]);
      expect(srv.state.connections).toBe(1);
      const d = srv.state.delivered[0]!;
      expect(d.from).toBe(USER);
      expect(d.to).toEqual(['dummy.to@example.test', 'dummy.bcc@example.test']);
      const raw = d.raw.toString('utf8');
      expect(raw).not.toMatch(/^bcc:/im);
      expect(raw).not.toContain('dummy.bcc@example.test');
      expect(raw).toMatch(/^In-Reply-To: <parent@example.test>/m);
      expect(raw).toMatch(/^References: <root@example.test> <parent@example.test>/m);
      expect(raw).toContain(`Message-ID: ${res.providerMessageId}`);
    } finally {
      await srv.close();
    }
  });

  it('reports partially rejected recipients but still accepted', async () => {
    const srv = await startSmtp({
      onRcptTo(addr, _s, cb) {
        if (addr.address === 'dummy.cc@example.test') return cb(Object.assign(new Error('No such user'), { responseCode: 550 }));
        cb();
      },
    });
    try {
      const mail = await composed({ cc: ['dummy.cc@example.test'] });
      const res = await trusted().send(account(srv.port), mail.raw, mail.envelope);
      expect(res.status).toBe('accepted');
      expect(res.detail).toMatch(/1 recipient\(s\) were rejected/);
    } finally {
      await srv.close();
    }
  });

  it('all recipients rejected (550 on RCPT) → rejected, one connection, no retry', async () => {
    const srv = await startSmtp({
      onRcptTo(_a, _s, cb) {
        cb(Object.assign(new Error('Mailbox unavailable'), { responseCode: 550 }));
      },
    });
    try {
      const mail = await composed();
      const res = await trusted().send(account(srv.port), mail.raw, mail.envelope);
      expect(res.status).toBe('rejected');
      expect(res.detail).toMatch(/not sent/i);
      expect(srv.state.connections).toBe(1);
      expect(srv.state.delivered).toEqual([]);
    } finally {
      await srv.close();
    }
  });

  it('connection lost during DATA → indeterminate, one connection, no retry', async () => {
    const srv = await startSmtp({}, { destroyInData: true });
    try {
      const mail = await composed();
      const res = await trusted().send(account(srv.port), mail.raw, mail.envelope);
      expect(res.status).toBe('indeterminate');
      expect(res.detail).toBe(INDETERMINATE_NOTE);
      expect(srv.state.connections).toBe(1);
    } finally {
      await srv.close();
    }
  });

  it('authentication failure → rejected without echoing the password', async () => {
    const srv = await startSmtp();
    try {
      const mail = await composed();
      const acct = { ...account(srv.port), password: dummySecret('WRONG-PASSWORD') };
      const res = await trusted().send(acct, mail.raw, mail.envelope);
      expect(res.status).toBe('rejected');
      expect(res.detail).toMatch(/login failed/i);
      expect(JSON.stringify(res)).not.toContain(acct.password);
      expect(srv.state.connections).toBe(1);
    } finally {
      await srv.close();
    }
  });

  it('refuses an envelope sender other than the account address before connecting', async () => {
    const srv = await startSmtp();
    try {
      const mail = await composed();
      const err = await rejection(trusted().send(account(srv.port), mail.raw, { ...mail.envelope, from: 'dummy.other@example.test' }));
      expect(err).toMatchObject({ code: 'bad_argument' });
      expect(srv.state.connections).toBe(0);
    } finally {
      await srv.close();
    }
  });

  it('STARTTLS: upgrades before AUTH; a server without STARTTLS is refused (no plaintext AUTH)', async () => {
    const srv = await startSmtp({ secure: false });
    try {
      const mail = await composed();
      const res = await trusted().send(account(srv.port, { security: 'starttls' }), mail.raw, mail.envelope);
      expect(res.status).toBe('accepted');
      expect(srv.state.auths).toEqual([USER]);
    } finally {
      await srv.close();
    }
    const plain = await startSmtp({ secure: false, disabledCommands: ['STARTTLS'], allowInsecureAuth: true });
    try {
      const mail = await composed();
      const res = await trusted().send(account(plain.port, { security: 'starttls' }), mail.raw, mail.envelope);
      expect(res.status).toBe('rejected');
      expect(plain.state.auths).toEqual([]);
      expect(plain.state.delivered).toEqual([]);
    } finally {
      await plain.close();
    }
  });
});

describe('SmtpSender TLS verification (real TLS handshakes on 127.0.0.1)', () => {
  it('refuses an untrusted self-signed certificate: rejected, nothing sent', async () => {
    const srv = await startTlsServer({ ...cert });
    try {
      const mail = await composed();
      const res = await new SmtpSender().send(account(srv.port), mail.raw, mail.envelope);
      expect(res.status).toBe('rejected');
      expect(res.detail).toMatch(/TLS|certificate/);
      expect(srv.state.tcpConnections).toBe(1);
      expect(srv.state.secureConnections).toBe(0);
      expect(srv.state.received).toEqual([]);
    } finally {
      await srv.close();
    }
  });

  it('refuses a trusted certificate issued for another hostname', async () => {
    const srv = await startTlsServer({ ...otherCert });
    try {
      const mail = await composed();
      const res = await new SmtpSender({ testOnlyTlsTrust: { ca: otherCert.cert } }).send(account(srv.port), mail.raw, mail.envelope);
      expect(res.status).toBe('rejected');
      expect(srv.state.received).toEqual([]);
    } finally {
      await srv.close();
    }
  });

  it('refuses a server limited to TLS 1.1', async (ctx) => {
    if (!(await runtimeSupportsTls11(cert))) {
      ctx.skip('This Node/OpenSSL runtime cannot negotiate TLS 1.1 at all, so the refusal cannot be exercised');
    }
    const srv = await startTlsServer({ ...cert, minVersion: 'TLSv1.1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT@SECLEVEL=0' });
    try {
      const mail = await composed();
      const res = await trusted().send(account(srv.port), mail.raw, mail.envelope);
      expect(res.status).toBe('rejected');
      expect(srv.state.secureConnections).toBe(0);
    } finally {
      await srv.close();
    }
  });
});

afterAll(() => {});
