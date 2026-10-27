import { createHash } from 'node:crypto';
import { FAMILY_TITLES, failedChecks, type AccountFamily, type AccountStatus, type StatusReport } from './status.js';

/**
 * The read-only status page: server-rendered HTML, no script, no forms, no external resources. Every
 * value is HTML-escaped; the single <style> block is allowed by its hash in the CSP (statusPageHeaders).
 */

export const esc = (v: unknown) =>
  String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const when = (iso: string | undefined) => (iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : '');

const STYLE = `
:root{--bg:#fff;--surface:#fafafa;--text:#0a0a0a;--text2:#525252;--muted:#737373;--border:#e5e5e5;--ok:#15803d;--ok-soft:#e8f5ec;--bad:#dc2626;--bad-soft:#fdecec;--warn:#b45309;--warn-soft:#fdf3e3;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#000;--surface:#0a0a0a;--text:#fafafa;--text2:#a3a3a3;--muted:#7a7a7a;--border:#262626;--ok:#4ade80;--ok-soft:#0d2416;--bad:#f87171;--bad-soft:#2c1111;--warn:#fbbf24;--warn-soft:#2a1f08}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 "Source Sans 3",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:40px 16px 64px}
header{display:flex;flex-wrap:wrap;align-items:center;gap:12px 16px;margin-bottom:8px}
header svg{width:40px;height:40px;fill:currentColor;flex:none}
h1{margin:0;font-size:28px;letter-spacing:-.02em}
.sub{color:var(--text2);margin:0 0 32px}
h2{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:32px 0 8px;font-weight:600}
.box{border:1px solid var(--border);border-radius:12px;background:var(--surface);overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:15px}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:0}
th{font-size:12px;color:var(--muted);font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.mono{font-family:"Source Code Pro",ui-monospace,Menlo,monospace;font-size:13px;color:var(--text2)}
.muted{color:var(--muted)}
.empty{padding:12px 14px;color:var(--muted)}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:13px;font-weight:600;white-space:nowrap}
.ok{background:var(--ok-soft);color:var(--ok)}
.bad{background:var(--bad-soft);color:var(--bad)}
.warn{background:var(--warn-soft);color:var(--warn)}
.skip{background:var(--border);color:var(--text2)}
.err{display:block;margin-top:4px;color:var(--bad);font-size:14px}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.fact{border:1px solid var(--border);border-radius:12px;background:var(--surface);padding:14px 16px}
.fact b{display:block;font-size:22px}
.fact b.mono{font-size:15px;color:var(--text);overflow-wrap:anywhere;margin-top:6px}
table.acct{table-layout:fixed;min-width:720px}
table.acct th:nth-child(1){width:24%}table.acct th:nth-child(2){width:26%}table.acct th:nth-child(3){width:18%}table.acct th:nth-child(4){width:12%}table.acct th:nth-child(5){width:20%}
td{overflow-wrap:anywhere}
@media (max-width:640px){table.acct{min-width:0;table-layout:auto}table.acct thead{display:none}table.acct tr{display:grid;grid-template-columns:1fr 1fr;gap:6px 12px;padding:12px 14px;border-bottom:1px solid var(--border)}table.acct tr:last-child{border-bottom:0}table.acct td{padding:0;border:0}table.acct td:nth-child(5){grid-column:1/-1}}
progress{width:100%;height:8px;accent-color:var(--text)}
footer{margin-top:40px;color:var(--muted);font-size:14px}
`.trim();

export const STATUS_STYLE_HASH = `sha256-${createHash('sha256').update(STYLE).digest('base64')}`;

/** Security headers of the status page: no script, nothing external, never framed, cached or referred. */
export function statusPageHeaders(): Record<string, string> {
  return {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-security-policy': `default-src 'none'; style-src '${STATUS_STYLE_HASH}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
  };
}

/** Perch symbol (brand/logo/perch-symbol-black.svg), colored by the text color. */
export const SYMBOL =
  '<svg viewBox="0 0 100 100" aria-hidden="true"><path d="M 2 81.23 C 33.23 62.72 64.46 37.28 98 9.52 C 66.77 39.59 36.7 69.66 7.78 90.48 Z M 27.45 67.35 C 25.13 54.63 27.45 40.75 32.07 28.02 C 33.23 40.75 35.54 52.31 36.7 62.72 Z M 57.52 43.06 C 70.24 39.59 84.12 41.9 96.84 48.84 C 84.12 47.69 71.4 46.53 62.14 45.37 Z"/></svg>';

function checkCell(a: AccountStatus): string {
  if (!a.check) return '<span class="pill skip">not checked</span>';
  if (a.check.state === 'skipped') return `<span class="pill skip">${a.microsoftGroupId ? 'Stored probe' : 'not checked'}</span><br><span class="muted">${esc(a.check.message)}</span>`;
  if (a.check.state === 'ok') return `<span class="pill ok">OK</span> <span class="muted">${esc(a.check.ms)} ms</span>`;
  return `<span class="pill bad">Error</span><span class="err">${esc(a.check.message)}</span>`;
}

function familyTable(rows: AccountStatus[]): string {
  if (!rows.length) return '<div class="box"><div class="empty">Nothing connected.</div></div>';
  const body = rows
    .map(
      (a) =>
        `<tr><td><b>${esc(a.label)}</b><br><span class="mono">${esc(a.id)}</span></td><td>${esc(a.identity)}<br><span class="muted">${esc(a.provider)}</span></td>` +
        `<td>${esc(a.permissions)}</td><td>${esc(a.connectedAt.slice(0, 10))}</td><td>${checkCell(a)}</td></tr>`,
    )
    .join('');
  return `<div class="box"><table class="acct"><thead><tr><th>Account</th><th>Identity</th><th>Permissions</th><th>Since</th><th>Live check</th></tr></thead><tbody>${body}</tbody></table></div>`;
}

export function renderStatusPage(r: StatusReport, opts: { cachedSeconds?: number } = {}): string {
  const failed = failedChecks(r);
  const overall = !r.checked
    ? '<span class="pill skip">Live checks skipped</span>'
    : failed
      ? `<span class="pill bad">${failed} check${failed === 1 ? '' : 's'} failed</span>`
      : r.microsoftGroups?.length
        ? '<span class="pill skip">Microsoft session status is stored</span>'
        : '<span class="pill ok">All checks passed</span>';
  const sections = (Object.keys(FAMILY_TITLES) as AccountFamily[])
    .map((f) => `<h2>${esc(FAMILY_TITLES[f])}</h2>${familyTable(r.accounts.filter((a) => a.family === f))}`)
    .join('');
  const clients = r.clients.length
    ? `<div class="box"><table><thead><tr><th>Client</th><th>Capabilities</th><th>Accounts</th><th>Since</th></tr></thead><tbody>${r.clients
        .map(
          (c) =>
            `<tr><td><b>${esc(c.label)}</b><br><span class="mono">${esc(c.id)}</span></td><td>${c.full ? '<b>Full access</b> (read + write)' : c.readAll ? '<b>Read only</b>' : esc(c.capabilities.join(', '))}</td>` +
            `<td class="mono">${c.full || c.readAll ? 'all accounts, also later ones' : c.accountIds.map(esc).join('<br>')}</td><td>${esc(c.createdAt.slice(0, 10))}</td></tr>`,
        )
        .join('')}</tbody></table></div>`
    : '<div class="box"><div class="empty">No client grants: every connection is read-only.</div></div>';
  let ledger: string;
  if ('error' in r.ledger) ledger = `<div class="fact"><span class="pill bad">Error</span><span class="err">${esc(r.ledger.error)}</span></div>`;
  else {
    const l = r.ledger;
    const tone = l.sends >= l.maxSends * 0.9 ? 'bad' : l.sends >= l.maxSends * 0.7 ? 'warn' : 'ok';
    ledger =
      `<div class="fact"><span class="muted">Send records (mail, Slack, WhatsApp)</span><b>${esc(l.sends)} / ${esc(l.maxSends)}</b>` +
      `<progress value="${esc(l.sends)}" max="${esc(l.maxSends)}">${esc(l.sends)}</progress>` +
      `${l.pending ? ` <span class="pill warn">${esc(l.pending)} pending</span>` : ''}${tone !== 'ok' ? ` <span class="pill ${tone}">nearly full</span>` : ''}</div>` +
      `<div class="fact"><span class="muted">Audit events</span><b>${esc(l.auditEvents)}</b>${l.auditDropped ? `<span class="muted">+${esc(l.auditDropped)} rotated out</span>` : ''}</div>` +
      `<div class="fact"><span class="muted">Last activity</span><b>${l.lastActivityAt ? esc(when(l.lastActivityAt)) : '—'}</b></div>`;
  }
  const bridge = r.whatsappBridge
    ? `<div class="fact"><span class="muted">WhatsApp bridge</span><b class="mono">${esc(r.whatsappBridge.origin)}</b></div>`
    : '';
  const p = r.publicAccess;
  const publicAccess =
    'error' in p
      ? `<div class="fact"><span class="muted">Public access</span><span class="pill bad">Error</span><span class="err">${esc(p.error)}</span></div>`
      : `<div class="fact"><span class="muted">Public access</span><b>${p.state === 'off' ? 'Off (kill switch)' : p.state === 'on' ? 'Set up' : 'Not set up'}</b>` +
        `<span class="muted">Perch code ${p.totp ? 'set up' : 'missing'} · ${esc(p.activeDevices)} active device(s)${p.lastPairedAt ? ` · last pairing ${esc(when(p.lastPairedAt))}` : ''}</span>` +
        `${p.pairingOpen ? ' <span class="pill warn">pairing window open</span>' : ''}</div>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Perch status</title>
<style>${STYLE}</style>
</head>
<body>
<main>
<header>${SYMBOL}<h1>Perch status</h1>${overall}</header>
<p class="sub">Namespace <span class="mono">${esc(r.namespace)}</span> · version ${esc(r.version)} · ${esc(when(r.generatedAt))}${
    opts.cachedSeconds ? ` · cached for up to ${esc(opts.cachedSeconds)} s` : ''
  }</p>
${sections}
<h2>Client grants</h2>${clients}
<h2>Operations</h2><div class="facts">${ledger}${bridge}${publicAccess}</div>
<footer>Read-only overview. Connect, change or remove accounts and grants with the perch CLI on the server.</footer>
</main>
</body>
</html>
`;
}
