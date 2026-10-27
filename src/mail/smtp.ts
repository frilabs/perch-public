import SMTPConnection from 'nodemailer/lib/smtp-connection';
import { PerchError } from '../errors.js';
import type { ImapAccount } from '../store/credentialStore.js';
import { isAddress } from './compose.js';
import { MAIL_TIMEOUTS, mailTlsOptions, validateHost, validatePort, type TestOnlyTlsTrust } from './imapPresets.js';
import { ACCEPTED_NOTE, INDETERMINATE_NOTE, type SendResult } from './types.js';

/**
 * SMTP submission with nodemailer's SMTPConnection (not createTransport): driving connect,
 * login and send as separate steps tells us exactly which phase failed. The transport reports
 * every socket loss as command "CONN", so "connection refused" and "connection lost during
 * DATA" would look identical there, and those two must be classified differently.
 *
 * Outcome classification (Perch NEVER retries a send):
 * - connect / TLS / EHLO / STARTTLS / AUTH failure: nothing was submitted → 'rejected' (not sent).
 * - MAIL FROM / RCPT TO refused (EENVELOPE), or the DATA command itself refused before any content
 *   was transmitted → 'rejected'.
 * - Anything else once the transaction started (socket loss, timeout, error reply after the
 *   content was transmitted) → 'indeterminate': the server may already have queued the message.
 * - info.accepted non-empty → 'accepted' (accepted for delivery, not proof of delivery).
 */

type Phase = 'connect' | 'auth' | 'transaction';

interface SmtpErr {
  code?: string;
  command?: string;
  responseCode?: number;
  message?: string;
}

const TLS_ERROR = /CERT|SELF_SIGNED|UNABLE_TO_(VERIFY|GET)|ALTNAME|HOSTNAME|ERR_SSL|ERR_TLS|EPROTO|ETLS/;

/** Runs one SMTPConnection step; errors may arrive via the callback OR the 'error'/'end' events. */
function step<T>(conn: SMTPConnection, start: (done: (err?: Error | null, value?: T) => void) => void): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const cleanup = () => {
      conn.off('error', onError);
      conn.off('end', onEnd);
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const onEnd = () => {
      cleanup();
      reject(Object.assign(new Error('Connection closed'), { code: 'ECONNECTION' }));
    };
    conn.on('error', onError);
    conn.on('end', onEnd);
    start((err, value) => {
      cleanup();
      if (err) reject(err);
      else resolve(value as T);
    });
  });
}

/** Message-ID header of the raw message (the provider-visible id). */
function messageIdOf(raw: Buffer): string | undefined {
  const end = raw.indexOf('\r\n\r\n');
  const head = raw.subarray(0, end < 0 ? Math.min(raw.length, 64 * 1024) : end).toString('utf8').replace(/\r?\n[ \t]+/g, ' ');
  return /^message-id:\s*(<[^<>\s]+>)/im.exec(head)?.[1];
}

function notSent(account: ImapAccount, phase: Phase, e: SmtpErr): string {
  const where = `${account.smtp.host}:${account.smtp.port}`;
  const code = e.responseCode ? ` (${e.responseCode})` : '';
  if (phase === 'auth' || e.code === 'EAUTH') return 'Not sent: SMTP login failed (check app password / SMTP access enabled)';
  if (TLS_ERROR.test(String(e.code ?? '')) || /certificate|ssl|tls/i.test(String(e.message ?? ''))) {
    return `Not sent: TLS verification failed for SMTP server ${where} (certificate, TLS version or STARTTLS not acceptable)`;
  }
  // nodemailer tries the host's other addresses after a failed handshake, so a certificate error
  // can surface as a plain connection error from the last address; say what was required.
  if (phase === 'connect') return `Not sent: could not connect to SMTP server ${where} with verified TLS (network, certificate or TLS version problem)`;
  if (e.command === 'DATA') return `Not sent: the server refused to accept message content${code}`;
  return `Not sent: the server refused the sender or all recipients${code}`;
}

/** Errors in the transaction phase that prove nothing was accepted for transmission. */
function refusedBeforeContent(e: SmtpErr): boolean {
  if (e.code === 'EENVELOPE') return e.command === 'MAIL FROM' || e.command === 'RCPT TO' || e.command === 'API' || e.command === 'DATA';
  return e.code === 'EMESSAGE' && e.command === 'MAIL FROM'; // size limit (SIZE extension) before DATA
}

export class SmtpSender {
  constructor(private readonly opts: { testOnlyTlsTrust?: TestOnlyTlsTrust } = {}) {}

  private connection(account: ImapAccount): SMTPConnection {
    const host = validateHost('smtp host', account.smtp.host);
    const port = validatePort('smtp port', account.smtp.port);
    const security = account.smtp.security;
    if (security !== 'tls' && security !== 'starttls') throw new PerchError('SMTP security must be tls or starttls', 'bad_argument');
    const conn = new SMTPConnection({
      // localhost is a loopback name; do not send it to Nodemailer's DNS resolver.
      // Keep the original name for certificate verification and SNI.
      host: host === 'localhost' ? '127.0.0.1' : host,
      servername: host,
      port,
      // 'tls' = implicit TLS from the first byte; 'starttls' = upgrade is mandatory before AUTH
      // (requireTLS fails the connection if the server does not offer STARTTLS). Never plaintext.
      secure: security === 'tls',
      ...(security === 'starttls' ? { requireTLS: true, ignoreTLS: false, opportunisticTLS: false } : {}),
      tls: mailTlsOptions(host, this.opts.testOnlyTlsTrust),
      connectionTimeout: MAIL_TIMEOUTS.connectionMs,
      greetingTimeout: MAIL_TIMEOUTS.greetingMs,
      socketTimeout: MAIL_TIMEOUTS.socketMs,
      logger: false,
      debug: false,
      transactionLog: false,
    });
    conn.on('error', () => {}); // handled per step; an unhandled 'error' event would crash the process
    return conn;
  }

  private async open(account: ImapAccount, conn: SMTPConnection, phase: { current: Phase }) {
    await step<void>(conn, (done) => conn.connect((err) => done(err)));
    // Defence in depth: never send credentials unless the channel is TLS (implicit or STARTTLS).
    if (!conn.secure) throw Object.assign(new Error('Connection is not TLS protected'), { code: 'ETLS' });
    phase.current = 'auth';
    await step<void>(conn, (done) => conn.login({ user: account.username, pass: account.password }, (err) => done(err)));
  }

  /** Connects and logs in only (onboarding check). Throws a sanitised PerchError on failure. */
  async verify(account: ImapAccount): Promise<void> {
    const conn = this.connection(account);
    const phase = { current: 'connect' as Phase };
    try {
      await this.open(account, conn, phase);
    } catch (err) {
      throw new PerchError(notSent(account, phase.current, err as SmtpErr).replace(/^Not sent: /, ''), 'smtp_verify_failed');
    } finally {
      conn.close();
    }
  }

  async send(account: ImapAccount, raw: Buffer, envelope: { from: string; to: string[] }): Promise<SendResult> {
    // The envelope sender is always the account address: no sending as someone else.
    if (typeof envelope?.from !== 'string' || envelope.from.toLowerCase() !== account.email.toLowerCase()) {
      throw new PerchError('SMTP envelope sender must be the account address', 'bad_argument');
    }
    if (!Array.isArray(envelope.to) || !envelope.to.length || !envelope.to.every((a) => typeof a === 'string' && isAddress(a))) {
      throw new PerchError('SMTP envelope needs at least one valid recipient', 'bad_argument');
    }
    const conn = this.connection(account);
    const phase = { current: 'connect' as Phase };
    try {
      await this.open(account, conn, phase);
      phase.current = 'transaction';
      const info = await step<SMTPConnection.SentMessageInfo>(conn, (done) =>
        conn.send({ from: account.email, to: envelope.to }, raw, (err, i) => done(err, i)),
      );
      const providerMessageId = messageIdOf(raw);
      if (info.accepted.length > 0) {
        const rejected = info.rejected.length;
        return {
          status: 'accepted',
          ...(providerMessageId ? { providerMessageId } : {}),
          detail: rejected ? `${ACCEPTED_NOTE} ${rejected} recipient(s) were rejected by the server.` : ACCEPTED_NOTE,
        };
      }
      return { status: 'rejected', detail: 'Not sent: the server rejected all recipients' };
    } catch (err) {
      const e = err as SmtpErr;
      if (phase.current !== 'transaction' || refusedBeforeContent(e)) {
        return { status: 'rejected', detail: notSent(account, phase.current, e) };
      }
      return { status: 'indeterminate', detail: INDETERMINATE_NOTE };
    } finally {
      conn.close();
    }
  }
}
