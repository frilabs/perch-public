import { afterEach, describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { AuditLog } from '../src/audit/audit.js';
import { createDeviceGrant, principalFromGrant, READONLY_PRINCIPAL } from '../src/auth/grants.js';
import { PerchError } from '../src/errors.js';
import { SendWorkflow } from '../src/mail/workflow.js';
import { MailWorkflowLedger } from '../src/mail/workflowLedger.js';
import { CredentialStore, initStore, type Capability } from '../src/store/credentialStore.js';
import { MicrosoftSessionGroupSchema } from '../src/microsoft/session/model.js';
import { MicrosoftSessionService } from '../src/microsoft/session/service.js';
import { microsoftSessionTools } from '../src/mcp/tools/microsoftSession.js';
import type { PerchContext } from '../src/context.js';
import { makeTempDirs } from './support/fixtures.js';

const cleanups: Array<() => Promise<unknown>> = [];
afterEach(async () => { vi.restoreAllMocks(); for (const cleanup of cleanups.splice(0)) await cleanup(); });
const accountId = 'msteams-12345678';
const request = { accountId, conversationId: '19:conversation@thread.v2', text: 'DUMMY-PRIVATE-MESSAGE-CONTENT', requestId: 'request-12345678' };
async function fixture(capabilities: string[] = ['microsoft_teams_read', 'microsoft_teams_send'], accountIds = [accountId]) {
  const dirs = await makeTempDirs(); cleanups.push(dirs.cleanup);
  await initStore({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  const store = await CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });
  const group = MicrosoftSessionGroupSchema.parse({
    id: 'mgroup-12345678', label: 'Test group', email: 'dummy@example.test', profileId: 'ms-session-0123456789abcdef01234567',
    identity: { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', kind: 'organization' },
    members: { teams: accountId, mail: 'msmail-12345678', calendar: 'mscalendar-12345678', files: 'msfiles-12345678' },
    services: Object.fromEntries(['teams', 'mail', 'calendar', 'files'].map((name) => [name, { enabled: true, write: true, invite: true, status: 'ready' }])),
    sites: [], createdAt: '2026-10-26T00:00:00.000Z', updatedAt: '2026-10-26T00:00:00.000Z', revision: '12345678',
  });
  await store.update((data) => { data.microsoftSessions = [group]; });
  const grant = await createDeviceGrant(store, { label: 'Test client', capabilities: capabilities as Capability[], accountIds });
  const p = principalFromGrant(grant);
  const ledger = new MailWorkflowLedger(store), workflow = new SendWorkflow(ledger), audit = new AuditLog(ledger);
  const runtime = { execute: vi.fn(async (_account: string, _op: string, _args: unknown, _options?: { allowInvites?: boolean }): Promise<unknown> => ({ messageId: '1234567890123', clientMessageId: '1234567890123123456', extra: 'first-response-only' })) };
  const service = new MicrosoftSessionService({ store, workflow, audit, runtime });
  return { dirs, store, group, grant, p, ledger, workflow, audit, runtime, service };
}

describe('Microsoft session service authorization and shared write ledger', () => {
  it('resolves current grants for reads and never dispatches a revoked grant', async () => {
    const f = await fixture();
    expect(await f.service.execute(f.p, 'teams.listChats', { accountId })).toMatchObject({ accountId, result: { messageId: '1234567890123' } });
    await f.store.update((data) => { data.clients = []; });
    await expect(f.service.execute(f.p, 'teams.listChats', { accountId })).rejects.toMatchObject({ code: 'grant_revoked' });
    expect(f.runtime.execute).toHaveBeenCalledTimes(1);
  });
  it('passes the approved revision and caller binding to the worker boundary for reads and writes', async () => {
    const f = await fixture();
    const options = { allowInvites: false, expectedRevision: f.group.revision, caller: { kind: 'client', clientId: f.grant.id, tokenSha256: f.grant.tokenSha256 } };
    await f.service.execute(f.p, 'teams.listChats', { accountId });
    expect(f.runtime.execute.mock.calls[0]![3]).toEqual(options);
    await f.service.execute(f.p, 'teams.send', request);
    expect(f.runtime.execute.mock.calls[1]![3]).toEqual(options);
  });
  it('rejects wrong-family accounts, unknown operations, mail, internal setup operations, and transport arguments', async () => {
    const f = await fixture();
    for (const [operation, input] of [['teams.listChats', { accountId: 'msfiles-12345678' }], ['mail.search', { accountId: 'msmail-12345678' }], ['files.probeSite', { accountId: 'msfiles-12345678', siteId: 'ms-site-12345678' }], ['browser.eval', { accountId }], ['teams.listChats', { accountId, url: 'https://evil.test' }]] as const) {
      await expect(f.service.execute(f.p, operation, input)).rejects.toThrow();
    }
    expect(f.runtime.execute).not.toHaveBeenCalled();
  });
  it('enforces account enabled/write opt-ins and read-only operator restrictions', async () => {
    const f = await fixture();
    await expect(f.service.execute(READONLY_PRINCIPAL, 'teams.send', request)).rejects.toMatchObject({ code: 'capability_denied' });
    await f.store.update((data) => { data.microsoftSessions![0]!.services.teams.write = false; });
    await expect(f.service.execute(f.p, 'teams.send', request)).rejects.toMatchObject({ code: 'provider_scope_missing' });
    await f.store.update((data) => { data.microsoftSessions![0]!.services.teams.enabled = false; });
    await expect(f.service.execute(f.p, 'teams.listChats', { accountId })).rejects.toMatchObject({ code: 'provider_scope_missing' });
    expect(f.runtime.execute).not.toHaveBeenCalled();
  });
  it('persists one accepted attempt and replays without storing response content', async () => {
    const f = await fixture();
    const first = await f.service.execute(f.p, 'teams.send', request);
    expect(first).toMatchObject({ status: 'accepted', replayed: false, result: { extra: 'first-response-only' } });
    const replay = await f.service.execute(f.p, 'teams.send', request);
    expect(replay).toMatchObject({ status: 'accepted', replayed: true, providerMessageId: '1234567890123', resultRetained: false });
    expect(replay.result).toBeUndefined();
    expect(f.runtime.execute).toHaveBeenCalledTimes(1);
    const serialized = JSON.stringify(await f.ledger.read());
    expect(serialized).not.toContain('first-response-only');
    expect(serialized).not.toContain(request.text);
    await expect(f.service.execute(f.p, 'teams.send', { ...request, text: 'Different' })).rejects.toMatchObject({ code: 'idempotency_conflict' });
  });
  it('binds replay and status to revision and identity, not just the member ID', async () => {
    const f = await fixture();
    await f.service.execute(f.p, 'teams.send', request);
    await f.store.update((data) => { data.microsoftSessions![0]!.revision = '87654321'; });
    await expect(f.service.execute(f.p, 'teams.send', request)).rejects.toMatchObject({ code: 'account_changed' });
    await expect(f.service.writeStatus(f.p, { accountId, operation: 'teams.send', requestId: request.requestId })).rejects.toMatchObject({ code: 'account_changed' });
    expect(f.runtime.execute).toHaveBeenCalledTimes(1);
  });
  it('rechecks authorization after claim and does not send if revoked before dispatch', async () => {
    const f = await fixture();
    const claim = f.workflow.claim.bind(f.workflow);
    vi.spyOn(f.workflow, 'claim').mockImplementation(async (input) => { const result = await claim(input); await f.store.update((data) => { data.clients = []; }); return result; });
    expect(await f.service.execute(f.p, 'teams.send', request)).toMatchObject({ status: 'rejected' });
    expect(f.runtime.execute).not.toHaveBeenCalled();
  });
  it('rejects a changed identity after the durable claim without browser dispatch', async () => {
    const f = await fixture();
    const claim = f.workflow.claim.bind(f.workflow);
    vi.spyOn(f.workflow, 'claim').mockImplementation(async (input) => {
      const result = await claim(input);
      await f.store.update((data) => { data.microsoftSessions![0]!.identity.objectId = '33333333-3333-4333-8333-333333333333'; });
      return result;
    });
    expect(await f.service.execute(f.p, 'teams.send', request)).toMatchObject({ status: 'rejected' });
    expect(f.runtime.execute).not.toHaveBeenCalled();
  });
  it('binds the conversation to the canonical write so a reused key cannot send elsewhere', async () => {
    const f = await fixture();
    await f.service.execute(f.p, 'teams.send', request);
    await expect(f.service.execute(f.p, 'teams.send', { ...request, conversationId: '19:different@thread.v2' })).rejects.toMatchObject({ code: 'idempotency_conflict' });
    expect(f.runtime.execute).toHaveBeenCalledTimes(1);
  });
  it('bounds first-write result size and explicitly says when a completed result was omitted', async () => {
    const f = await fixture();
    f.runtime.execute.mockResolvedValue({ messageId: '123', content: 'x'.repeat(300 * 1024) });
    const view = await f.service.execute(f.p, 'teams.send', request);
    expect(view).toMatchObject({ status: 'accepted', resultOmitted: true, providerMessageId: '123' });
    expect(view.result).toBeUndefined();
    expect(view.detail).toMatch(/exceeded|omitted/);
  });
  it('does not report acceptance if finalizing the durable outcome fails', async () => {
    const f = await fixture();
    vi.spyOn(f.workflow, 'finalize').mockResolvedValue(false);
    const first = await f.service.execute(f.p, 'teams.send', request);
    expect(first).toMatchObject({ status: 'indeterminate', requestState: 'pending' });
    expect(first.result).toBeUndefined();
    expect(await f.service.execute(f.p, 'teams.send', request)).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(f.runtime.execute).toHaveBeenCalledTimes(1);
  });
  it.each(['partial_write', 'provider_error', 'access_denied'])('records post-dispatch %s as indeterminate and never retries it', async (code) => {
    const f = await fixture();
    f.runtime.execute.mockRejectedValue(new PerchError('provider-private-error', code));
    const first = await f.service.execute(f.p, 'teams.send', request);
    expect(first).toMatchObject({ status: 'indeterminate' });
    expect(JSON.stringify(first)).not.toContain('provider-private-error');
    expect(await f.service.execute(f.p, 'teams.send', request)).toMatchObject({ status: 'indeterminate', replayed: true });
    expect(f.runtime.execute).toHaveBeenCalledTimes(1);
  });
  it('does not report acceptance before the runtime operation finishes; concurrent repeats do not send twice', async () => {
    const f = await fixture();
    let complete!: (value: unknown) => void;
    let started!: () => void;
    const dispatch = new Promise<void>((resolve) => { started = resolve; });
    f.runtime.execute.mockImplementation(async () => { started(); return new Promise((resolve) => { complete = resolve; }); });
    const first = f.service.execute(f.p, 'teams.send', request);
    await dispatch;
    expect(await f.service.execute(f.p, 'teams.send', request)).toMatchObject({ status: 'indeterminate', requestState: 'pending', replayed: true });
    complete({ messageId: '123' });
    expect(await first).toMatchObject({ status: 'accepted', result: { messageId: '123' } });
    expect(f.runtime.execute).toHaveBeenCalledTimes(1);
  });
  it('returns write status only to the actor who made the request', async () => {
    const f = await fixture();
    await f.service.execute(f.p, 'teams.send', request);
    expect(await f.service.writeStatus(f.p, { accountId, operation: 'teams.send', requestId: request.requestId })).toMatchObject({ status: 'accepted', providerMessageId: '1234567890123', resultRetained: false });
    const other = principalFromGrant(await createDeviceGrant(f.store, { label: 'Other', capabilities: ['microsoft_teams_send'], accountIds: [accountId] }));
    await expect(f.service.writeStatus(other, { accountId, operation: 'teams.send', requestId: request.requestId })).rejects.toMatchObject({ code: 'unknown_request' });
  });
  it('passes invitation authority only when both the current grant and group opt-in allow it', async () => {
    const calendarId = 'mscalendar-12345678';
    const f = await fixture(['microsoft_calendar_write'], [calendarId]);
    await f.service.execute(f.p, 'calendar.updateEvent', { accountId: calendarId, eventId: 'event-1', subject: 'Update', requestId: 'calendar-1' });
    expect(f.runtime.execute.mock.calls[0]![3]).toMatchObject({ allowInvites: false });
    await f.store.update((data) => { data.clients[0]!.capabilities.push('microsoft_calendar_invite'); });
    await f.service.execute(f.p, 'calendar.updateEvent', { accountId: calendarId, eventId: 'event-1', subject: 'Update', requestId: 'calendar-2' });
    expect(f.runtime.execute.mock.calls[1]![3]).toMatchObject({ allowInvites: true });
    await f.store.update((data) => { data.microsoftSessions![0]!.services.calendar.invite = false; });
    await f.service.execute(f.p, 'calendar.updateEvent', { accountId: calendarId, eventId: 'event-1', subject: 'Update', requestId: 'calendar-3' });
    expect(f.runtime.execute.mock.calls[2]![3]).toMatchObject({ allowInvites: false });
  });
  it('lists only enabled service members visible to the current principal', async () => {
    const f = await fixture();
    const result = await f.service.listAccounts(f.p);
    expect(result.map((account) => account.accountId)).toEqual([accountId]);
    expect(JSON.stringify(result)).not.toContain(f.group.profileId);
    await f.store.update((data) => { data.clients = []; });
    await expect(f.service.listAccounts(f.p)).rejects.toMatchObject({ code: 'grant_revoked' });
  });
  it('registers capability-filtered MCP tools without mail or internal setup and dispatches through the service', async () => {
    const f = await fixture(['microsoft_teams_read']);
    const server = new McpServer({ name: 'test-session', version: '1' });
    microsoftSessionTools.register(server, { microsoftSession: f.service } as unknown as PerchContext, f.p, false, async (_name, _args, fn) => ({ content: [{ type: 'text', text: JSON.stringify(await fn(f.p)) }] }));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test', version: '1' });
    await server.connect(serverTransport); await client.connect(clientTransport);
    cleanups.unshift(async () => { await client.close(); await server.close(); });
    const names = (await client.listTools()).tools.map((tool) => tool.name);
    expect(names).toContain('microsoft_teams_list_chats');
    expect(names).not.toContain('microsoft_teams_send');
    expect(names.some((name) => name.includes('mail') || name.includes('probe_site'))).toBe(false);
    await client.callTool({ name: 'microsoft_teams_list_chats', arguments: { accountId } });
    expect(f.runtime.execute).toHaveBeenCalledWith(accountId, 'teams.listChats', { limit: 50 }, expect.objectContaining({ allowInvites: false }));
  });
});
