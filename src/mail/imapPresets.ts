import { PerchError } from '../errors.js';
import { isAddress } from './compose.js';

/**
 * Server presets for generic IMAP + SMTP accounts. Sources (checked 2026-10-05):
 * https://hilfe.gmx.net/pop-imap/imap/imap-serverdaten.html and
 * https://support.gmx.com/pop-imap/imap/server.html
 * IMAP is always implicit TLS; SMTP defaults to implicit TLS (465) with STARTTLS (587) as the
 * documented alternative. Plaintext is never offered.
 */

export type SmtpSecurity = 'tls' | 'starttls';

export interface ImapPreset {
  name: string;
  domains: string[];
  imap: { host: string; port: number };
  smtp: { host: string; port: number };
  smtpStarttlsPort: number;
  /** What the user must enable at the provider before IMAP login works. */
  notes: string;
}

const GMX_NOTES =
  'In GMX web mail: Settings → POP3/IMAP → Allow POP3 and IMAP access. ' +
  'With two-factor authentication, use an app password.';

export const IMAP_PRESETS = {
  gmx: {
    name: 'GMX (Austria/Germany)',
    domains: ['gmx.at', 'gmx.de', 'gmx.net'],
    imap: { host: 'imap.gmx.net', port: 993 },
    smtp: { host: 'mail.gmx.net', port: 465 },
    smtpStarttlsPort: 587,
    notes: GMX_NOTES,
  },
  'gmx-com': {
    name: 'GMX (international)',
    // Only domains the GMX international help names; other GMX domains need an explicit preset.
    domains: ['gmx.com', 'gmx.us', 'gmx.co.uk', 'gmx.fr'],
    imap: { host: 'imap.gmx.com', port: 993 },
    smtp: { host: 'mail.gmx.com', port: 465 },
    smtpStarttlsPort: 587,
    notes: GMX_NOTES,
  },
} as const satisfies Record<string, ImapPreset>;

export type ImapPresetName = keyof typeof IMAP_PRESETS;

const isPresetName = (s: string): s is ImapPresetName => Object.hasOwn(IMAP_PRESETS, s);

export function presetForEmail(email: string): ImapPresetName | undefined {
  const domain = email.slice(email.lastIndexOf('@') + 1).toLowerCase();
  for (const [name, p] of Object.entries(IMAP_PRESETS)) {
    if ((p.domains as readonly string[]).includes(domain)) return name as ImapPresetName;
  }
  return undefined;
}

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * DNS hostnames only: no IP literals (TLS certificates are issued for names, and an IP would
 * make SNI/hostname verification meaningless), no userinfo, no port suffix.
 */
export function validateHost(field: string, host: string): string {
  const h = typeof host === 'string' ? host.trim().toLowerCase().replace(/\.$/, '') : '';
  const labels = h.split('.');
  if (!h || h.length > 253 || !labels.every((l) => LABEL.test(l)) || /^[0-9]+$/.test(labels[labels.length - 1]!)) {
    throw new PerchError(`${field} must be a DNS hostname like imap.example.com (no IP address, user or port)`, 'bad_argument');
  }
  return h;
}

export function validatePort(field: string, port: number): number {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new PerchError(`${field} must be a port number between 1 and 65535`, 'bad_argument');
  }
  return port;
}

/**
 * TEST-ONLY: an extra trust anchor for throwaway local test servers. Production code never
 * sets it. It can only ADD a CA; certificate and hostname verification stay on regardless.
 */
export interface TestOnlyTlsTrust {
  ca: Buffer;
}

/** Bounded timeouts so a stalled server can never hang a tool call indefinitely. */
export const MAIL_TIMEOUTS = { connectionMs: 30_000, greetingMs: 30_000, socketMs: 60_000 } as const;

/** TLS options for every IMAP/SMTP connection: verified certificate, TLS 1.2+, SNI = host. */
export function mailTlsOptions(host: string, testOnlyTrust?: TestOnlyTlsTrust) {
  return {
    rejectUnauthorized: true as const,
    minVersion: 'TLSv1.2' as const,
    servername: host,
    ...(testOnlyTrust ? { ca: testOnlyTrust.ca } : {}),
  };
}

export interface ServerInput {
  email: string;
  preset?: string;
  imapHost?: string;
  imapPort?: number;
  smtpHost?: string;
  smtpPort?: number;
  smtpSecurity?: SmtpSecurity;
}

export interface ResolvedServers {
  preset?: ImapPresetName;
  imap: { host: string; port: number };
  smtp: { host: string; port: number; security: SmtpSecurity };
}

/**
 * Explicit hosts win; otherwise the explicit preset, otherwise the preset matching the email
 * domain. Unknown domains require both hosts. Ports default to 993 (IMAP) and 465/587 (SMTP).
 */
export function resolveServers(input: ServerInput): ResolvedServers {
  if (typeof input.email !== 'string' || !isAddress(input.email)) throw new PerchError('email must be a plain address', 'bad_argument');
  const security = input.smtpSecurity ?? 'tls';
  if (security !== 'tls' && security !== 'starttls') {
    throw new PerchError("smtpSecurity must be 'tls' (implicit TLS) or 'starttls'", 'bad_argument');
  }
  let presetName: ImapPresetName | undefined;
  if (input.preset !== undefined) {
    if (!isPresetName(input.preset)) {
      throw new PerchError(`Unknown preset "${input.preset}". Known: ${Object.keys(IMAP_PRESETS).join(', ')}`, 'bad_argument');
    }
    presetName = input.preset;
  } else if (input.imapHost === undefined && input.smtpHost === undefined) {
    presetName = presetForEmail(input.email);
  }
  const preset = presetName ? IMAP_PRESETS[presetName] : undefined;
  const imapHost = input.imapHost ?? preset?.imap.host;
  const smtpHost = input.smtpHost ?? preset?.smtp.host;
  if (!imapHost || !smtpHost) {
    throw new PerchError('No preset for this email domain: imapHost and smtpHost are required', 'bad_argument');
  }
  const defaultSmtpPort = security === 'tls' ? (preset?.smtp.port ?? 465) : (preset?.smtpStarttlsPort ?? 587);
  return {
    ...(presetName ? { preset: presetName } : {}),
    imap: { host: validateHost('imapHost', imapHost), port: validatePort('imapPort', input.imapPort ?? preset?.imap.port ?? 993) },
    smtp: {
      host: validateHost('smtpHost', smtpHost),
      port: validatePort('smtpPort', input.smtpPort ?? defaultSmtpPort),
      security,
    },
  };
}
