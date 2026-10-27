import type { z } from 'zod';
import type { CursorSeal } from '../../store/credentialStore.js';
import { PerchError } from '../../errors.js';
import type { MicrosoftIdentity, MicrosoftService, SelectedSite } from './model.js';

export type SessionResource = 'outlook' | 'chat' | 'csa' | 'substrate' | 'graph' | 'sharepoint' | 'download';
/** Internal adapter request only. Never accepted as an MCP/worker operation from a caller. */
export interface SessionHttpRequest {
  resource: SessionResource; path: string; method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  query?: Record<string, string>; headers?: Record<string, string>; body?: unknown;
  bodyBase64?: string; siteId?: string; maxBytes?: number; responseType?: 'json' | 'bytes';
}
export interface SessionHttpResponse { status: number; headers: Record<string, string>; body: Buffer }
export type SessionHttp = (request: SessionHttpRequest) => Promise<SessionHttpResponse>;
export interface OperationContext { cursors?: CursorSeal; request: SessionHttp; identity: MicrosoftIdentity; sites: readonly SelectedSite[]; displayName?: string; allowInvites?: boolean }
export interface SessionOperation {
  service: MicrosoftService; mode: 'read' | 'write' | 'invite'; description: string;
  schema: z.ZodObject<any>; internalOnly?: boolean;
  run(ctx: OperationContext, args: any): Promise<unknown>;
}
export type SessionOperations = Readonly<Record<string, SessionOperation>>;
export function checkedJson(response: SessionHttpResponse): any {
  if (response.status === 401) throw new PerchError('Microsoft session expired. Run perch microsoft reconnect GROUP_ID.', 'reauth_required');
  if (response.status === 403) throw new PerchError('Microsoft denied this resource or operation.', 'access_denied');
  if (response.status === 429) throw new PerchError('Microsoft rate limit reached. Retry later.', 'rate_limited');
  if (response.status < 200 || response.status >= 300) throw new PerchError(`Microsoft request failed (HTTP ${response.status}).`, 'provider_error');
  if (!response.body.length) return {};
  try { return JSON.parse(response.body.toString('utf8')); }
  catch { throw new PerchError('Microsoft returned an unexpected response format.', 'invalid_response'); }
}
export const opaqueId = (id: string): string => encodeURIComponent(id);
