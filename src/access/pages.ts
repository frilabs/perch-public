import { createHash } from 'node:crypto';
import { esc, SYMBOL } from '../status/page.js';
import type { ConfirmDetails } from './pairing.js';

/**
 * Sign-in pages of the public access (Spec §9) and the local pairing page: server-rendered, no script,
 * one <style> block allowed by hash, forms POST to the same origin only. Every page names the real Perch
 * address and says that Perch never asks for a sign-in by message (Spec §0a item 7).
 */
const STYLE = `
:root{--bg:#fff;--surface:#fafafa;--text:#0a0a0a;--text2:#525252;--muted:#737373;--border:#e5e5e5;--bad:#dc2626;--bad-soft:#fdecec;--ok:#15803d;--ok-soft:#e8f5ec;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#000;--surface:#0a0a0a;--text:#fafafa;--text2:#a3a3a3;--muted:#7a7a7a;--border:#262626;--bad:#f87171;--bad-soft:#2c1111;--ok:#4ade80;--ok-soft:#0d2416}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 "Source Sans 3",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:560px;margin:0 auto;padding:40px 16px 64px}
header{display:flex;align-items:center;gap:12px;margin-bottom:24px}
header svg{width:36px;height:36px;fill:currentColor;flex:none}
h1{margin:0;font-size:24px;letter-spacing:-.02em}
p{margin:0 0 16px}
.box{border:1px solid var(--border);border-radius:12px;background:var(--surface);padding:16px;margin:0 0 16px}
dl{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;margin:0}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
.mono{font-family:"Source Code Pro",ui-monospace,Menlo,monospace}
.code{font-size:28px;letter-spacing:.2em}
label{display:block;font-weight:600;margin:0 0 6px}
input[type=text]{width:100%;font:inherit;font-size:20px;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text);letter-spacing:.1em}
button{font:inherit;font-weight:600;padding:10px 18px;border-radius:8px;border:1px solid var(--text);background:var(--text);color:var(--bg);cursor:pointer;margin:12px 8px 0 0}
button.secondary{background:transparent;color:var(--text)}
.err{background:var(--bad-soft);color:var(--bad);border-radius:8px;padding:10px 12px;margin:0 0 16px}
.ok{background:var(--ok-soft);color:var(--ok);border-radius:8px;padding:10px 12px;margin:0 0 16px}
.warn{border-left:3px solid var(--bad);padding-left:12px}
form.inline{display:inline}
footer{margin-top:32px;color:var(--muted);font-size:14px}
`.trim();

export const ACCESS_STYLE_HASH = `sha256-${createHash('sha256').update(STYLE).digest('base64')}`;

export function pageHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy': `default-src 'none'; style-src '${ACCESS_STYLE_HASH}'; base-uri 'none'; form-action 'self' https://accounts.google.com; frame-ancestors 'none'`,
    'cache-control': 'no-store',
    pragma: 'no-cache',
    // Not no-referrer: with no-referrer, browsers send `Origin: null` on form posts (Fetch spec, "serializing
    // a request origin"), and the same-origin form check then refuses every sign-in step. same-origin keeps
    // the real Origin on our own forms and still sends no referrer to any other site.
    'referrer-policy': 'same-origin',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'strict-transport-security': 'max-age=31536000',
    ...extra,
  };
}

function layout(base: string, title: string, body: string, refreshSeconds?: number): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
${refreshSeconds ? `<meta http-equiv="refresh" content="${refreshSeconds}">` : ''}
<title>${esc(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
<header>${SYMBOL}<h1>${esc(title)}</h1></header>
${body}
<footer>This is Perch at <span class="mono">${esc(base)}</span>. Perch never asks you to sign in by message: every sign-in starts with <span class="mono">perch oauth pair</span> on your own server.</footer>
</main>
</body>
</html>
`;
}

const clientBox = (c: { clientDisplay: string; clientName: string; registration: string; redirectHost: string }) => `<div class="box"><dl>
<dt>Client</dt><dd>${esc(c.clientName)} <span class="mono">(${esc(c.clientDisplay)})</span></dd>
<dt>Registered as</dt><dd>${esc(c.registration)}</dd>
<dt>Returns to</dt><dd class="mono">${esc(c.redirectHost)}</dd>
</dl></div>`;

export interface ClientView {
  clientDisplay: string;
  clientName: string;
  registration: string;
  redirectHost: string;
  loopbackOnly: boolean;
}

const loopbackWarning = (c: ClientView) =>
  c.loopbackOnly ? '<p class="warn">This client returns to a local program on the computer you are using. Only continue if you started that program yourself.</p>' : '';

export const noWindowPage = (base: string) =>
  layout(
    base,
    'No pairing open',
    '<p>No pairing window is open. To connect a device, run <span class="mono">perch oauth pair</span> on your server (or open the local pairing page there) and try again within 10 minutes.</p>',
  );

export const errorPage = (base: string, title: string, message: string) => layout(base, title, `<div class="err">${esc(message)}</div>`);

/** `next`: what follows the code: Google sign-in (public listener) or the terminal confirmation (private). */
export const pairCodePage = (base: string, csrf: string, c: ClientView, error?: string, next: 'google' | 'confirm' = 'google') =>
  layout(
    base,
    'Connect a device',
    `${error ? `<div class="err">${esc(error)}</div>` : ''}${clientBox(c)}${loopbackWarning(c)}${
      next === 'confirm' ? '<p>Private address (your tailnet): after the pairing code you confirm this sign-in in your terminal on the server. No Google sign-in.</p>' : ''
    }
<form method="post" action="/oauth/pair">
<input type="hidden" name="csrf" value="${esc(csrf)}">
<label for="code">Pairing code from your terminal</label>
<input type="text" id="code" name="code" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="16" required autofocus>
<button type="submit">${next === 'confirm' ? 'Continue' : 'Continue with Google'}</button>
</form>`,
  );

export const totpPage = (base: string, csrf: string, email: string, error?: string) =>
  layout(
    base,
    'Perch code',
    `${error ? `<div class="err">${esc(error)}</div>` : ''}<p>Signed in with Google as <b>${esc(email)}</b>. Enter the 6-digit code from your authenticator app (or one of your recovery codes).</p>
<form method="post" action="/oauth/totp">
<input type="hidden" name="csrf" value="${esc(csrf)}">
<label for="code">Perch code</label>
<input type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" spellcheck="false" maxlength="16" required autofocus>
<button type="submit">Continue</button>
</form>`,
  );

export const waitPage = (base: string, c: ClientView) =>
  layout(
    base,
    'Confirm in your terminal',
    `<p><b>Confirm this sign-in in your terminal on the server.</b> This page continues by itself once you answer there.</p>${clientBox(c)}`,
    2,
  );

export const notConfirmedPage = (base: string) =>
  layout(base, 'Not connected', '<div class="err">This sign-in was not confirmed, or the pairing window closed. Nothing was connected.</div>');

/**
 * Local pairing page (local listener only, its own password). Its password is a PAIRING credential: whoever
 * holds it can open a window and approve a sign-in READ ONLY. Full access is never approved here; the page
 * shows the terminal command for it instead (SIMPLE_CONNECT_SPEC §5).
 */
export function localPairPage(opts: {
  base: string;
  csrf: string;
  state: 'idle' | 'open' | 'confirm' | 'paired' | 'locked';
  code?: string;
  expiresAt?: string;
  /** Listener the open window serves, and its MCP address. */
  listener?: 'private' | 'public';
  url?: string;
  /** Listeners a new window can be opened for (idle state); private first. */
  canOpen?: Array<'private' | 'public'>;
  details?: ConfirmDetails;
  /** Device paired through this page (read only). */
  paired?: string;
  /** Why no window can be opened (state 'locked'). */
  blocked?: string;
  lastEvents: string[];
}): string {
  const form = (action: string, label: string, secondary = false) =>
    `<form method="post" action="/local/pair" class="inline"><input type="hidden" name="csrf" value="${esc(opts.csrf)}"><input type="hidden" name="action" value="${esc(action)}"><button type="submit"${secondary ? ' class="secondary"' : ''}>${esc(label)}</button></form>`;
  const name = (l: 'private' | 'public') => (l === 'private' ? 'private address (tailnet)' : 'public address (internet)');
  let body = '';
  if (opts.paired) {
    body += `<div class="ok">Paired ${esc(opts.paired)} (read only).</div><p>To give it full access (read and write on every account), run on the server:</p><div class="box mono">perch oauth grant ${esc(opts.paired)} --full</div>`;
  }
  if (opts.state === 'idle' || (opts.state === 'paired' && opts.canOpen?.length)) {
    const can = opts.canOpen ?? ['private'];
    body += `<p>No pairing window is open. A window serves one address for 10 minutes and pairs one device.</p>${can
      .map((l, i) => form(`open_${l}`, `Open a window for the ${name(l)}`, i > 0))
      .join('')}`;
  }
  if (opts.state === 'locked') body += `<div class="err">${esc(opts.blocked ?? 'Pairing is not possible right now (another pairing window is open, or pairing is locked). See perch status.')}</div>`;
  if (opts.state === 'open') {
    body += `<p>Enter this pairing code on the sign-in page of the device you are connecting:</p><div class="box"><span class="mono code">${esc(opts.code ?? '')}</span><br><span>open until ${esc(opts.expiresAt ?? '')}</span></div>${
      opts.listener ? `<div class="box"><dl><dt>Only for the ${esc(name(opts.listener))}</dt><dd class="mono">${esc(opts.url ?? '')}</dd></dl></div>` : ''
    }${form('close', 'Close the window', true)}`;
  }
  if (opts.state === 'confirm' && opts.details) {
    const d = opts.details;
    const priv = d.origin === 'private';
    body += `<p><b>Pair this device?</b> Only confirm if this is the device you are connecting right now.</p><div class="box"><dl>
<dt>Address</dt><dd>${priv ? 'private (tailnet)' : 'public (internet)'}</dd>
<dt>Client</dt><dd>${esc(d.clientName)} <span class="mono">(${esc(d.clientDisplay)})</span></dd>
<dt>Registered as</dt><dd>${esc(d.registration)}</dd>
<dt>Returns to</dt><dd class="mono">${esc(d.redirectHost)}</dd>
${priv ? '' : `<dt>Google account</dt><dd>${esc(d.googleEmail ?? '-')}</dd>
`}<dt>Browser</dt><dd>${esc(d.userAgent)}</dd>
<dt>${priv ? 'Source' : 'IP'}</dt><dd>${esc(d.ip)}</dd>
<dt>Since opening</dt><dd>${esc(d.secondsSinceOpen)} s${d.usedRecoveryCode ? ' · recovery code used' : ''}</dd>
</dl></div><p>This page pairs <b>read only</b> (reads every account, writes nothing). Full access is granted in the terminal on the server afterwards: <span class="mono">perch oauth grant &lt;id&gt; --full</span>.</p>${form('approve', 'Pair: read only')}${form('reject', 'Reject', true)}`;
  }
  if (opts.lastEvents.length) body += `<div class="box mono">${opts.lastEvents.map((e) => esc(e)).join('<br>')}</div>`;
  return layout(opts.base, 'Pair a device', body, opts.state === 'open' ? 3 : undefined);
}
