import type { PerchConfig } from '../config.js';
import { PerchError } from '../errors.js';
import { guardedLumaFetch, LumaMcp } from '../luma/client.js';
import { runLumaAuthorization } from '../luma/oauth.js';
import { LUMA_TOOLS } from '../luma/policy.js';
import { createLumaTokenProvider, LumaService, registerLumaAccount, removeLumaAccount } from '../luma/service.js';
import { DEFAULT_AUTH_TIMEOUT_MS, MAX_AUTH_TIMEOUT_MS } from '../oauth/loopback.js';
import { AuditLog } from '../audit/audit.js';
import { SendWorkflow } from '../mail/workflow.js';
import { MailWorkflowLedger } from '../mail/workflowLedger.js';
import { CredentialStore } from '../store/credentialStore.js';
import { createFetchTransport, Upstream } from '../upstream.js';
import { loginPrompts } from './loginPrompt.js';
import type { CliIo } from './run.js';

/** perch luma … (docs/LUMA_SPEC.md §7). Local CLI only. */
const usage = (m: string) => new PerchError(m, 'usage');

export function lumaMcpFor(io: CliIo): LumaMcp {
  return new LumaMcp(guardedLumaFetch(io.lumaFetch));
}

async function service(config: PerchConfig, io: CliIo) {
  const store = await CredentialStore.open({ dataDir: config.dataDir, keyFile: config.keyFile });
  const upstream = new Upstream(io.transport ?? createFetchTransport());
  const ledger = new MailWorkflowLedger(store);
  const svc = new LumaService(store, new SendWorkflow(ledger), new AuditLog(ledger), createLumaTokenProvider(store, upstream), lumaMcpFor(io));
  return { store, upstream, svc };
}

export async function cmdLuma(config: PerchConfig, io: CliIo, sub: string | undefined, rest: string[], values: Record<string, unknown>): Promise<void> {
  const { store, upstream, svc } = await service(config, io);
  if (sub === 'list') {
    const d = await store.read();
    const lines = ['Luma accounts (official Luma MCP; labels are user-assigned):'];
    if (!d.luma.length) lines.push('  (none)');
    for (const a of d.luma) lines.push(`  ${a.id}  "${a.label}"  ${a.email ?? a.name ?? ''}  ${a.tools.length} tool(s) approved  via ${a.registration}  connected ${a.createdAt}`);
    io.stdout(`${lines.join('\n')}\n`);
    return;
  }
  if (sub === 'remove') {
    const id = rest[0];
    if (!id) throw usage('Usage: perch luma remove ID [--revoke]');
    const { revoked, removedGrants } = await removeLumaAccount(store, upstream, id, Boolean(values.revoke));
    io.stdout(`Removed ${id} locally.${revoked ? ' The token was revoked at Luma.' : values.revoke ? ' Luma offers no revocation endpoint; remove the app in your Luma settings.' : ''}\n`);
    if (removedGrants.length) io.stdout(`Client grants that covered only this account were removed: ${removedGrants.join(', ')}\n`);
    return;
  }
  if (sub === 'tools') {
    const id = rest[0];
    if (!id) throw usage('Usage: perch luma tools ID [--accept]');
    if (values.accept) {
      const r = await svc.acceptTools(id);
      io.stdout(`Approved ${r.approved.length} tool schema(s) as Luma serves them now.\n`);
      for (const b of r.blocked) io.stdout(`  still blocked: ${b.name} (unknown fields: ${b.fields.join(', ')}; needs a Perch update)\n`);
      return;
    }
    const states = await svc.toolStates(id);
    const lines = [`Luma tools for ${id} (only these can ever be passed through):`];
    for (const s of states) lines.push(`  ${s.state === 'ok' ? '✓' : '✗'} ${s.name.padEnd(32)} ${s.group.padEnd(7)} ${s.state}`);
    if (states.some((s) => s.state === 'changed' || s.state === 'not_approved')) lines.push('', `Review the changes, then approve them: perch luma tools ${id} --accept`);
    if (states.some((s) => s.state === 'new_fields')) lines.push('', 'Tools with new_fields stay blocked until Perch knows those fields (Perch update).');
    io.stdout(`${lines.join('\n')}\n`);
    return;
  }
  if (sub !== 'add') throw usage('Usage: perch luma add|list|remove|tools');
  if (typeof values.label !== 'string') throw usage('--label is required');
  const port = values.port !== undefined ? Number(values.port) : 0;
  const timeoutS = values.timeout !== undefined ? Number(values.timeout) : DEFAULT_AUTH_TIMEOUT_MS / 1000;
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw usage('--port must be a valid port');
  if (!Number.isInteger(timeoutS) || timeoutS < 1 || timeoutS > MAX_AUTH_TIMEOUT_MS / 1000) throw usage(`--timeout must be 1-${MAX_AUTH_TIMEOUT_MS / 1000} seconds`);
  const grant = await runLumaAuthorization({
    upstream,
    ...(config.lumaClientId ? { clientIdUrl: config.lumaClientId } : {}),
    port,
    timeoutMs: timeoutS * 1000,
    ...loginPrompts(io, 'sign in to the Luma account you want to add', timeoutS * 1000),
  });
  const { account, blocked, missing } = await registerLumaAccount(store, svc.mcp, { label: values.label, grant });
  const known = Object.keys(LUMA_TOOLS).length;
  io.stdout(
    `Connected Luma account ${account.id} "${account.label}"${account.email ? ` (${account.email})` : ''} via ${account.registration}.\n` +
      `${account.tools.length} of ${known} allowlisted tools approved (their schemas are pinned).\n` +
      (blocked.length ? `Blocked (unknown fields): ${blocked.map((b) => b.name).join(', ')}\n` : '') +
      (missing.length ? `Not offered by Luma: ${missing.join(', ')}\n` : '') +
      'Reading works for the global token. Writes need a grant, e.g.: perch client add --label X --allow luma_read,luma_events --account ' +
      `${account.id}\n`,
  );
}
