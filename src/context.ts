import { SessionRuntime } from './microsoft/session/runtime.js';
import { MicrosoftSessionService, type MicrosoftSessionRuntime } from './microsoft/session/service.js';
import { AuditLog } from './audit/audit.js';
import { GoogleTokenProvider } from './google/accounts.js';
import { googleGroupTokens } from './google/groupStore.js';
import { CalendarService } from './google/calendar.js';
import { ContactsService } from './google/contacts.js';
import { DriveService } from './google/drive.js';
import { DriveWriteService } from './google/driveWrite.js';
import { createProductivityTokenProvider } from './google/productivity.js';
import { createGmailTokenProvider } from './mail/gmailAccounts.js';
import { createMailProviders } from './mail/providers.js';
import type { RefreshingTokenProvider } from './oauth/tokenProvider.js';
import { MailService, type MailProviders } from './mail/service.js';
import { SendWorkflow } from './mail/workflow.js';
import { MailWorkflowLedger } from './mail/workflowLedger.js';
import { NotionService } from './notion/notion.js';
import { SlackService } from './slack/slack.js';
import type { CredentialStore, GmailAccount, GoogleAccountGroup, GoogleProductivityAccount, LumaAccount, XAccount } from './store/credentialStore.js';
import { createFetchTransport, Upstream, type UpstreamTransport } from './upstream.js';
import { WhatsappService } from './whatsapp/whatsapp.js';
import { LumaMcp } from './luma/client.js';
import { createLumaTokenProvider, LumaService } from './luma/service.js';
import { createXTokenProvider } from './x/oauth.js';
import { XService } from './x/x.js';

/** Long-lived services shared by all MCP requests (keeps the access-token caches warm). */
export interface PerchContext {
  store: CredentialStore;
  upstream: Upstream;
  drive: DriveService;
  /** Drive writes (client grants with drive_write; idempotent creates on the shared ledger). */
  driveWrite: DriveWriteService;
  notion: NotionService;
  mail: MailService;
  calendar: CalendarService;
  contacts: ContactsService;
  slack: SlackService;
  whatsapp: WhatsappService;
  luma: LumaService;
  /** X posting (docs/X_SPEC.md). */
  x: XService;
  microsoftSession: MicrosoftSessionService;
  /** The namespace's OAuth access-token providers (shared by services and status checks). */
  tokens: {
    drive: GoogleTokenProvider;
    gmail: RefreshingTokenProvider<GmailAccount>;
    productivity: RefreshingTokenProvider<GoogleProductivityAccount>;
    luma: RefreshingTokenProvider<LumaAccount>;
    x: RefreshingTokenProvider<XAccount>;
    /** Shared logins of Google account groups; the drive, gmail and productivity providers delegate group members here. */
    googleGroups: RefreshingTokenProvider<GoogleAccountGroup>;
  };
  /** Body-free audit trail of this namespace (in its mail workflow ledger), written by the MCP tool runner. */
  audit: AuditLog;
}

/**
 * `transport` and `mailProviders` are only overridden by tests (MOCK upstreams/providers);
 * production uses fetch to fixed origins and the real mail adapters.
 */
export function createPerchContext(
  store: CredentialStore,
  transport: UpstreamTransport = createFetchTransport(),
  mailProviders?: MailProviders,
  /** Tests only: MOCK Luma MCP client. */
  lumaMcp?: LumaMcp,
  /** Per-installation runtime options. */
  opts: { microsoftSessionRuntime?: MicrosoftSessionRuntime } = {},
): PerchContext {
  const upstream = new Upstream(transport);
  // One login per Google account group: Drive, Gmail and Calendar/Contacts members share its cache and refresh.
  const groupTokens = googleGroupTokens(store, upstream);
  const tokens = new GoogleTokenProvider(store, upstream, Date.now, groupTokens);
  // One token provider for Calendar and Contacts: they share the account's single grant.
  const productivityTokens = createProductivityTokenProvider(store, upstream, Date.now, groupTokens);
  // One ledger per namespace: idempotent sends and the audit trail share mail-workflow.enc.
  const ledger = new MailWorkflowLedger(store);
  const gmailTokens = createGmailTokenProvider(store, upstream, Date.now, groupTokens);
  const audit = new AuditLog(ledger);
  // Slack and WhatsApp sends use the same idempotent workflow (and send-record ledger) as mail.
  const workflow = new SendWorkflow(ledger);
  const lumaTokens = createLumaTokenProvider(store, upstream);
  const xTokens = createXTokenProvider(store, upstream);
  const sessionRuntime = opts.microsoftSessionRuntime ?? new SessionRuntime(store);
  return {
    microsoftSession: new MicrosoftSessionService({store, workflow, audit, runtime: sessionRuntime}),
    store,
    upstream,
    drive: new DriveService(store, upstream, tokens),
    driveWrite: new DriveWriteService(store, upstream, tokens, workflow, audit),
    notion: new NotionService(store, upstream, { workflow, audit }),
    mail: new MailService(store, mailProviders ?? createMailProviders(store, upstream, { gmail: gmailTokens }, (accountId, operation, args, options) => sessionRuntime.execute(accountId, operation, args, options)), ledger),
    calendar: new CalendarService(store, upstream, productivityTokens),
    contacts: new ContactsService(store, upstream, productivityTokens),
    slack: new SlackService(store, upstream, workflow, audit),
    whatsapp: new WhatsappService(store, upstream, workflow, audit),
    luma: new LumaService(store, workflow, audit, lumaTokens, lumaMcp ?? new LumaMcp()),
    x: new XService(store, upstream, workflow, audit, xTokens),
    tokens: { drive: tokens, gmail: gmailTokens, productivity: productivityTokens, luma: lumaTokens, x: xTokens, googleGroups: groupTokens },
    audit,
  };
}
