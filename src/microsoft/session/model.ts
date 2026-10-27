import { z } from 'zod';

export const MICROSOFT_SERVICES = ['teams', 'mail', 'calendar', 'files'] as const;
export type MicrosoftService = (typeof MICROSOFT_SERVICES)[number];
export const MICROSOFT_SESSION_CAPABILITIES = ['microsoft_teams_read', 'microsoft_teams_send', 'microsoft_calendar_read', 'microsoft_calendar_write', 'microsoft_calendar_invite', 'microsoft_files_read', 'microsoft_files_write'] as const;
export type MicrosoftSessionCapability = (typeof MICROSOFT_SESSION_CAPABILITIES)[number];
export const MicrosoftIdentitySchema = z.object({
  tenantId: z.string().uuid(), objectId: z.string().uuid(),
  mailboxId: z.string().min(1).max(512).optional(), kind: z.enum(['organization', 'personal']),
});
export type MicrosoftIdentity = z.infer<typeof MicrosoftIdentitySchema>;
export const SelectedSiteSchema = z.object({
  id: z.string().regex(/^ms-site-[a-f0-9]{8}$/),
  url: z.string().url(), kind: z.enum(['onedrive', 'sharepoint']),
  /** Concrete confirmed library IDs; automatic discovery never grants wildcard access. */
  driveIds: z.array(z.string().min(1).max(512)).max(100),
  /** Missing on legacy manually selected sites: preserve even an empty scope. */
  autoDiscoverLibraries: z.boolean().optional(),
  displayName: z.string().max(300).optional(),
});
export type SelectedSite = z.infer<typeof SelectedSiteSchema>;
const ServiceAccessSchema = z.object({
  enabled: z.boolean(), write: z.boolean(), invite: z.boolean(),
  /** Mail only: permit creating drafts, never sending or organizing. */
  draftsOnly: z.boolean().optional(),
  status: z.enum(['ready', 'unverified', 'unavailable', 'reauth_required', 'blocked_by_policy', 'degraded']),
  checkedAt: z.string().datetime().optional(), errorCode: z.string().regex(/^[a-z_]{1,64}$/).optional(),
});
export const MicrosoftSessionGroupSchema = z.object({
  id: z.string().regex(/^mgroup-[a-f0-9]{8}$/), label: z.string().min(1).max(100),
  email: z.string().email().max(320), displayName: z.string().max(300).optional(),
  profileId: z.string().regex(/^ms-session-[a-f0-9]{24}$/), identity: MicrosoftIdentitySchema,
  members: z.object({ teams: z.string().regex(/^msteams-[a-f0-9]{8}$/), mail: z.string().regex(/^msmail-[a-f0-9]{8}$/), calendar: z.string().regex(/^mscalendar-[a-f0-9]{8}$/), files: z.string().regex(/^msfiles-[a-f0-9]{8}$/) }),
  services: z.object({ teams: ServiceAccessSchema, mail: ServiceAccessSchema, calendar: ServiceAccessSchema, files: ServiceAccessSchema }),
  sites: z.array(SelectedSiteSchema).max(100),
  createdAt: z.string().datetime(), updatedAt: z.string().datetime(), revision: z.string().regex(/^[a-f0-9]{8,64}$/),
});
export type MicrosoftSessionGroup = z.infer<typeof MicrosoftSessionGroupSchema>;
export interface SessionCaller { kind: 'operator_readonly' | 'client'; clientId?: string; tokenSha256?: string }
export interface SessionMailAccount {
  /** Trusted request caller, attached in memory only; never persisted with an account. */
  caller?: SessionCaller;
  id: string; groupId: string; label: string; email: string; createdAt: string; updatedAt: string;
  identity: MicrosoftIdentity; revision: string; allowDrafts: boolean; allowSend: boolean; allowModify: boolean;
}
export function sessionMailAccounts(groups: readonly MicrosoftSessionGroup[]): SessionMailAccount[] {
  return groups.filter((g) => g.services.mail.enabled).map((g) => ({
    id: g.members.mail, groupId: g.id, label: g.label, email: g.email, identity: g.identity, revision: g.revision,
    createdAt: g.createdAt, updatedAt: g.updatedAt,
    allowDrafts: g.services.mail.write, allowSend: g.services.mail.write && !g.services.mail.draftsOnly, allowModify: g.services.mail.write && !g.services.mail.draftsOnly,
  }));
}
