import { z } from 'zod';
import { actorOf, type AuditLog } from '../../audit/audit.js';
import { assertMicrosoftSessionCapability, currentPrincipal, type Principal } from '../../auth/grants.js';
import { PerchError } from '../../errors.js';
import { type SendWorkflow } from '../../mail/workflow.js';
import { PROVIDER_MESSAGE_ID_PATTERN } from '../../mail/workflowLedger.js';
import { messageSendStatus, sendMessageIdempotently, type MessageSendResult } from '../../messaging/send.js';
import type { CredentialStore } from '../../store/credentialStore.js';
import type { SessionOperation, SessionOperations } from './contracts.js';
import { filesOperations } from './files.js';
import type { MicrosoftSessionCapability, MicrosoftSessionGroup, SessionCaller } from './model.js';
import { outlookOperations } from './outlook.js';
import { teamsOperations } from './teams.js';

type PublicService = 'teams' | 'calendar' | 'files';
export type PublicSessionOperation = SessionOperation & { service: PublicService };
/** Mail stays with MailService; setup probes never become caller-controlled tools. */
export const microsoftSessionOperations: Readonly<Record<string, PublicSessionOperation>> = Object.fromEntries(
  Object.entries({ ...teamsOperations, ...outlookOperations, ...filesOperations } satisfies SessionOperations)
    .filter((entry): entry is [string, PublicSessionOperation] => entry[1].service !== 'mail' && !entry[1].internalOnly),
);
export function sessionCapability(operation: PublicSessionOperation): MicrosoftSessionCapability {
  if (operation.mode === 'read') return `microsoft_${operation.service}_read`;
  if (operation.service === 'teams') return 'microsoft_teams_send';
  if (operation.service === 'calendar' && operation.mode === 'invite') return 'microsoft_calendar_invite';
  return `microsoft_${operation.service}_write`;
}
const serviceCapabilities: Record<PublicService, readonly MicrosoftSessionCapability[]> = {
  teams: ['microsoft_teams_read', 'microsoft_teams_send'],
  calendar: ['microsoft_calendar_read', 'microsoft_calendar_write', 'microsoft_calendar_invite'],
  files: ['microsoft_files_read', 'microsoft_files_write'],
};
const accountSchema = z.string().regex(/^(msteams|mscalendar|msfiles)-[a-f0-9]{8}$/);
const statusSchema = z.object({ accountId: accountSchema, operation: z.string().min(1).max(100), requestId: z.string().min(8).max(128) }).strict();
const MAX_WRITE_RESULT_BYTES = 256 * 1024;

export interface MicrosoftSessionRuntime {
  execute(accountId: string, operation: string, args: unknown, options?: { allowInvites?: boolean; caller?: SessionCaller; expectedRevision?: string }): Promise<unknown>;
}
export interface MicrosoftSessionServiceDependencies { store: CredentialStore; workflow: SendWorkflow; audit: AuditLog; runtime: MicrosoftSessionRuntime }
export interface MicrosoftSessionAccountView {
  accountId: string; groupId: string; service: PublicService; label: string; email: string;
  status: string; canWrite: boolean; canInvite: boolean;
}
export interface SessionExecutionView {
  accountId: string; groupId: string; service: PublicService; operation: string; result?: unknown;
  status?: 'accepted' | 'rejected' | 'indeterminate'; requestState?: string; operationId?: string;
  detail?: string; replayed?: boolean; providerMessageId?: string; resultRetained?: false; resultOmitted?: boolean;
}
function findOperation(name: string): PublicSessionOperation {
  if (!Object.hasOwn(microsoftSessionOperations, name)) throw new PerchError('Unknown or unavailable Microsoft session operation.', 'bad_argument');
  return microsoftSessionOperations[name]!;
}
function parse<S extends z.ZodType>(schema: S, value: unknown): z.infer<S> {
  const result = schema.safeParse(value);
  if (!result.success) throw new PerchError('Invalid Microsoft session operation arguments.', 'bad_argument');
  return result.data;
}
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => [key, canonical(value)]));
  return value;
}
function bindingParts(group: MicrosoftSessionGroup, accountId: string, operation: string): string[] {
  return ['microsoft-session-write-v1', group.id, accountId, operation, group.revision, group.profileId, group.identity.tenantId, group.identity.objectId, group.identity.mailboxId ?? '', group.identity.kind];
}
function providerId(result: unknown): string | undefined {
  if (!result || typeof result !== 'object' || Array.isArray(result)) return undefined;
  const object = result as Record<string, unknown>;
  for (const key of ['messageId', 'eventId', 'itemId', 'id']) {
    const value = object[key];
    if (typeof value === 'string' && PROVIDER_MESSAGE_ID_PATTERN.test(value)) return value;
  }
  return undefined;
}
function boundedResult(value: unknown): unknown {
  try { const json = JSON.stringify(value); return json && Buffer.byteLength(json) <= MAX_WRITE_RESULT_BYTES ? JSON.parse(json) : undefined; }
  catch { return undefined; }
}
function granted(p: Principal, service: PublicService, accountId: string, capability: MicrosoftSessionCapability): boolean {
  try { assertMicrosoftSessionCapability(p, service, accountId, capability); return true; } catch { return false; }
}
function callerBinding(principal: Principal): SessionCaller {
  return principal.kind === 'client' ? { kind: 'client', clientId: principal.clientId, tokenSha256: principal.tokenSha256 } : { kind: 'operator_readonly' };
}

/** Fresh grants and account binding around every operation; writes claim the
 * shared durable ledger before the single browser dispatch. No body is stored. */
export class MicrosoftSessionService {
  constructor(private readonly dependencies: MicrosoftSessionServiceDependencies) {}

  private async authorize(p: Principal, operation: PublicSessionOperation, accountId: string) {
    const current = await currentPrincipal(this.dependencies.store, p);
    assertMicrosoftSessionCapability(current, operation.service, accountId, sessionCapability(operation));
    if (operation.mode === 'invite') assertMicrosoftSessionCapability(current, 'calendar', accountId, 'microsoft_calendar_write');
    const group = ((await this.dependencies.store.read()).microsoftSessions ?? []).find((group) => group.members[operation.service] === accountId);
    if (!group) throw new PerchError('Unknown Microsoft session account for this service.', 'unknown_account');
    const access = group.services[operation.service];
    if (!access.enabled || (operation.mode !== 'read' && !access.write) || (operation.mode === 'invite' && !access.invite)) {
      throw new PerchError('This Microsoft service or write permission is disabled. Change the local connection permissions first.', 'provider_scope_missing');
    }
    const allowInvites = operation.service === 'calendar' && access.invite && granted(current, 'calendar', accountId, 'microsoft_calendar_invite');
    return { group, allowInvites, principal: current };
  }

  async listAccounts(p: Principal): Promise<MicrosoftSessionAccountView[]> {
    const current = await currentPrincipal(this.dependencies.store, p);
    return ((await this.dependencies.store.read()).microsoftSessions ?? []).flatMap((group) => (['teams', 'calendar', 'files'] as const).flatMap((service) => {
      const accountId = group.members[service], access = group.services[service];
      if (!access.enabled || !serviceCapabilities[service].some((capability) => granted(current, service, accountId, capability))) return [];
      const write = service === 'teams' ? 'microsoft_teams_send' : `microsoft_${service}_write` as const;
      return [{ accountId, groupId: group.id, service, label: group.label, email: group.email, status: access.status,
        canWrite: access.write && granted(current, service, accountId, write),
        canInvite: service === 'calendar' && access.write && access.invite && granted(current, service, accountId, 'microsoft_calendar_write') && granted(current, service, accountId, 'microsoft_calendar_invite') }];
    }));
  }

  async execute(p: Principal, name: string, input: unknown): Promise<SessionExecutionView> {
    const operation = findOperation(name);
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PerchError('Microsoft operation arguments are required.', 'bad_argument');
    const { accountId: rawId, ...rest } = input as Record<string, unknown>;
    const accountId = parse(accountSchema, rawId);
    const { requestId, ...writeArgs } = rest;
    const args = parse(operation.schema, operation.mode === 'read' ? rest : writeArgs);
    if (operation.mode === 'read') {
      const { group, allowInvites, principal } = await this.authorize(p, operation, accountId);
      const result = await this.dependencies.runtime.execute(accountId, name, args, { allowInvites, caller: callerBinding(principal), expectedRevision: group.revision });
      return { accountId, groupId: group.id, service: operation.service, operation: name, result };
    }

    let group: MicrosoftSessionGroup | undefined;
    let result: unknown;
    let resultOmitted = false;
    const view = await sendMessageIdempotently({
      workflow: this.dependencies.workflow, audit: this.dependencies.audit, actor: actorOf(p),
      provider: 'microsoftSessionWrite', accountId,
      prepare: async () => {
        ({ group } = await this.authorize(p, operation, accountId));
        return { accountId, requestId, canonical: JSON.stringify(['microsoft-session-operation-v1', accountId, name, canonical(args)]), binding: bindingParts(group, accountId, name) };
      },
      attempt: async (binding): Promise<MessageSendResult> => {
        let current: Awaited<ReturnType<MicrosoftSessionService['authorize']>>;
        try { current = await this.authorize(p, operation, accountId); }
        catch { return { status: 'rejected', detail: 'Not submitted: the Microsoft account or permission is no longer available.', reason: 'not_submitted_authorization' }; }
        if (await this.dependencies.workflow.binding(bindingParts(current.group, accountId, name)) !== binding) {
          return { status: 'rejected', detail: 'Not submitted: the Microsoft account connection changed.', reason: 'not_submitted_account_changed' };
        }
        try {
          const response = await this.dependencies.runtime.execute(accountId, name, args, { allowInvites: current.allowInvites, caller: callerBinding(current.principal), expectedRevision: current.group.revision });
          result = boundedResult(response);
          resultOmitted = response !== undefined && result === undefined;
          return { status: 'accepted', detail: 'Microsoft completed the operation.', reason: 'provider_accepted', providerMessageId: providerId(response) };
        } catch {
          // A multi-step operation can fail after an earlier mutation. Even a
          // later 4xx must not turn a partial/unknown write into a safe retry.
          return { status: 'indeterminate', detail: 'The Microsoft operation may have changed data. Its outcome is unknown; inspect the resource before using a new requestId. Perch will not retry this request.', reason: 'provider_unknown' };
        }
      },
    });
    return { accountId, groupId: group!.id, service: operation.service, operation: name, ...view,
      detail: view.replayed ? `${view.detail} The complete operation result was not retained; re-read the resource using its ID.` : view.status === 'accepted' ? resultOmitted ? 'Microsoft completed the operation. Its result was omitted because it exceeded the output limit or could not be serialized; re-read the resource using its ID.' : 'Microsoft completed the operation. The complete result is returned once and is not retained in the ledger.' : view.detail,
      resultRetained: false, ...(result !== undefined && view.status === 'accepted' ? { result } : {}), ...(resultOmitted ? { resultOmitted: true } : {}) };
  }

  async writeStatus(p: Principal, input: unknown) {
    const args = parse(statusSchema, input), operation = findOperation(args.operation);
    if (operation.mode === 'read') throw new PerchError('Write status requires a Microsoft write operation.', 'bad_argument');
    const { group } = await this.authorize(p, operation, args.accountId);
    const view = await messageSendStatus(this.dependencies.workflow, actorOf(p), args.accountId, args.requestId, bindingParts(group, args.accountId, args.operation));
    return { accountId: args.accountId, groupId: group.id, service: operation.service, operation: args.operation, ...view, resultRetained: false,
      detail: `${view.detail} The complete operation result was not retained; re-read the resource using its ID.` };
  }
}
