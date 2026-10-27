/**
 * Throwaway self-signed TLS certificates for local test servers on 127.0.0.1 (tests only).
 * Generated with openssl into a fresh temp dir and deleted again; never trusted by production code.
 */
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import type { AddressInfo } from 'node:net';
import { promisify } from 'node:util';

const run = promisify(execFile);

export interface TestCert {
  key: Buffer;
  cert: Buffer;
}

export async function makeSelfSignedCert(hostname = 'localhost'): Promise<TestCert> {
  const dir = await mkdtemp(path.join(tmpdir(), 'perch-test-cert-'));
  try {
    const key = path.join(dir, 'key.pem');
    const cert = path.join(dir, 'cert.pem');
    await run('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', key, '-out', cert, '-days', '1',
      '-subj', `/CN=${hostname}`, '-addext', `subjectAltName=DNS:${hostname}`,
    ]);
    return { key: await readFile(key), cert: await readFile(cert) };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * A bare TLS server on 127.0.0.1 that records handshakes and any bytes received after one.
 * Used to prove that clients refuse untrusted certificates / old TLS before sending anything.
 */
export async function startTlsServer(opts: tls.TlsOptions & TestCert, onSecure?: (socket: tls.TLSSocket) => void) {
  const state = { tcpConnections: 0, secureConnections: 0, received: [] as Buffer[] };
  const server = tls.createServer(opts, (socket) => {
    state.secureConnections++;
    socket.on('data', (d) => state.received.push(d));
    socket.on('error', () => {});
    onSecure?.(socket);
  });
  const sockets = new Set<import('node:net').Socket>();
  server.on('connection', (sock) => {
    state.tcpConnections++;
    sockets.add(sock);
    sock.on('close', () => sockets.delete(sock));
  });
  server.on('tlsClientError', () => {});
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    state,
    port: (server.address() as AddressInfo).port,
    close: () =>
      new Promise<void>((resolve) => {
        for (const sock of sockets) sock.destroy();
        server.close(() => resolve());
      }),
  };
}

/** Whether this Node/OpenSSL build can still negotiate TLS 1.1 at all (needs SECLEVEL=0). */
export async function runtimeSupportsTls11(c: TestCert): Promise<boolean> {
  const srv = await startTlsServer({ ...c, minVersion: 'TLSv1.1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT@SECLEVEL=0' });
  try {
    return await new Promise<boolean>((resolve) => {
      const s = tls.connect({
        host: '127.0.0.1',
        port: srv.port,
        servername: 'localhost',
        ca: c.cert,
        minVersion: 'TLSv1.1',
        maxVersion: 'TLSv1.1',
        ciphers: 'DEFAULT@SECLEVEL=0',
      });
      s.once('secureConnect', () => {
        s.destroy();
        resolve(true);
      });
      s.once('error', () => resolve(false));
    });
  } finally {
    await srv.close();
  }
}

/**
 * MOCK IMAP server (tests only): a scripted, minimal IMAP4rev1 responder over real TLS on
 * 127.0.0.1 that understands CAPABILITY, LOGIN and LOGOUT and answers everything else with BAD.
 * It exists to exercise the real imapflow connect/TLS/login path; it is NOT an IMAP implementation.
 */
export async function startMockImapServer(c: TestCert, creds: { user: string; pass: string }) {
  const log = { logins: [] as string[], commands: [] as string[] };
  const srv = await startTlsServer({ ...c }, (socket) => {
    let buf = '';
    socket.write('* OK [CAPABILITY IMAP4rev1] MOCK IMAP ready\r\n');
    socket.on('data', (d: Buffer) => {
      buf += d.toString('utf8');
      let i: number;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        const [tag, cmd = ''] = line.split(' ');
        log.commands.push(cmd.toUpperCase());
        if (cmd.toUpperCase() === 'CAPABILITY') socket.write(`* CAPABILITY IMAP4rev1\r\n${tag} OK done\r\n`);
        else if (cmd.toUpperCase() === 'LOGIN') {
          if (line.includes(creds.user) && line.includes(creds.pass)) {
            log.logins.push(creds.user);
            socket.write(`${tag} OK [CAPABILITY IMAP4rev1] logged in\r\n`);
          } else socket.write(`${tag} NO [AUTHENTICATIONFAILED] invalid credentials\r\n`);
        } else if (cmd.toUpperCase() === 'LOGOUT') {
          socket.end(`* BYE\r\n${tag} OK bye\r\n`);
        } else socket.write(`${tag} BAD unsupported\r\n`);
      }
    });
  });
  return { ...srv, log };
}
