import { PerchError } from '../errors.js';

/**
 * Base URLs of the two OAuth issuers (docs/SIMPLE_CONNECT_SPEC.md §1): https, host and optional port only.
 * The private issuer lives on the local listener (tailnet, behind Tailscale Serve), the public one on the
 * public listener (Funnel or another TLS proxy).
 */
export function parseBaseUrl(raw: string, name = 'PERCH_PUBLIC_BASE_URL'): URL {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new PerchError(`${name} must be an https URL such as https://homeserver.tailnet-xyz.ts.net`, 'bad_config');
  }
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || (u.pathname !== '/' && u.pathname !== '')) {
    throw new PerchError(`${name} must be https://host[:port] without path, query or fragment`, 'bad_config');
  }
  return u;
}

const LOOPBACK_HOST = /^(127\.|localhost(:|$)|\[::1\])/i;
const IP_HOST = /^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-f:]+\])(:\d+)?$/i;

/**
 * The private base URL: PERCH_PRIVATE_BASE_URL, otherwise https://<first DNS name in PERCH_ALLOWED_HOSTS that
 * is not loopback> (the Tailscale Serve name). Null: private OAuth is off.
 */
export function derivePrivateBaseUrl(explicit: string | undefined, allowedHosts: string[]): { url: string; source: 'env' | 'allowed_hosts' } | null {
  if (explicit) return { url: parseBaseUrl(explicit, 'PERCH_PRIVATE_BASE_URL').origin, source: 'env' };
  for (const h of allowedHosts) {
    const host = h.trim().toLowerCase();
    if (!host || LOOPBACK_HOST.test(host) || IP_HOST.test(host)) continue;
    try {
      return { url: parseBaseUrl(`https://${host}`, 'PERCH_ALLOWED_HOSTS').origin, source: 'allowed_hosts' };
    } catch {
      continue;
    }
  }
  return null;
}

export const PRIVATE_OAUTH_OFF =
  'Private OAuth is off: add the tailnet name of this server to PERCH_ALLOWED_HOSTS (e.g. homeserver.tailnet-xyz.ts.net) or set PERCH_PRIVATE_BASE_URL.';
export const PRIVATE_OAUTH_DISABLED = 'Private OAuth is switched off (PERCH_PRIVATE_OAUTH=off); only the static tokens work on the local listener.';
