import { createHash, randomInt, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { PerchError } from '../../errors.js';
import { htmlToText, truncateUtf8 } from '../../mail/html.js';
import { checkedJson, opaqueId, type OperationContext, type SessionHttpRequest, type SessionOperation, type SessionOperations } from './contracts.js';

// Independently implemented protocol adapter. Service origins and authentication
// belong to the browser transport, never to an operation's arguments or cursor.
const conversation = z.string().max(1024).regex(/^(?:19|48):[A-Za-z0-9_@.+:=\-]+$/);
const groupId = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i).transform(value => value.toLowerCase());
const CHANNEL_SELECT = 'id,displayName,description,membershipType';
const messageId = z.string().regex(/^\d{1,30}$/);
const page = { limit: z.number().int().min(1).max(200).default(50), cursor: z.string().min(1).max(16000).optional() };
const cursorSchema = z.object({ scope: z.string().length(64), value: z.union([
  z.object({ offset: z.number().int().min(0).max(10000) }).strict(),
  z.object({ token: z.string().min(1).max(8000) }).strict(),
  z.object({ params: z.object({ startTime: z.string().max(100).optional(), endTime: z.string().max(100).optional(), syncState: z.string().max(8000).optional() }).strict() }).strict(),
]) }).strict();
type CursorValue = z.infer<typeof cursorSchema>['value'];
type RecordValue = Record<string, unknown>;

export interface TeamsChat { conversationId: string; title?: string; type: 'channel' | 'meeting' | 'group' | 'oneOnOne' | 'chat'; preview: string; lastMessageAt?: string; lastSender?: string }
export interface TeamsChannel { channelId: string; name: string; teamId: string; teamName: string; groupId?: string; type: 'standard' | 'private' | 'shared'; description?: string }
export interface TeamsMessage { id: string; conversationId: string; text: string; truncated: boolean; contentType: string; sender: { id?: string; name?: string }; timestamp?: string; rootMessageId?: string; clientMessageId?: string; isFromMe: boolean }
export interface TeamsSearchMessage { resultId?: string; conversationId?: string; messageId?: string; rootMessageId?: string; text: string; truncated: boolean; sender?: string; timestamp?: string; channelName?: string; teamName?: string }
export interface TeamsAttachment { name?: string; webUrl?: string; size?: number; extension?: string; sharedBy?: string; sharedAt?: string }
export interface TeamsSendResult { conversationId: string; clientMessageId: string; messageId?: string; arrivalTime?: number }

function invalidResponse(): never { throw new PerchError('Microsoft Teams returned an unexpected response format.', 'invalid_response'); }
function record(value: unknown): RecordValue { return value && typeof value === 'object' && !Array.isArray(value) ? value as RecordValue : {}; }
function list(value: unknown): unknown[] { if (!Array.isArray(value)) return invalidResponse(); return value; }
function string(value: unknown, max = 2048): string | undefined { return typeof value === 'string' ? value.slice(0, max) : undefined; }
function numericId(value: unknown): string | undefined { return typeof value === 'string' && /^\d{1,30}$/.test(value) ? value : undefined; }
function text(value: unknown, html = true, maxBytes = 64 * 1024) { return html ? htmlToText(string(value, 1024 * 1024) ?? '', maxBytes) : truncateUtf8(string(value, 1024 * 1024) ?? '', maxBytes); }
function safeWebUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 8000) return undefined;
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : undefined; } catch { return undefined; }
}
function scope(ctx: OperationContext, route: string): string {
  return createHash('sha256').update(JSON.stringify([ctx.identity.tenantId, ctx.identity.objectId, route])).digest('hex');
}
function encodeCursor(ctx: OperationContext, route: string, value: CursorValue): string {
  return Buffer.from(JSON.stringify({ scope: scope(ctx, route), value })).toString('base64url');
}
function decodeCursor(ctx: OperationContext, route: string, cursor?: string): CursorValue | undefined {
  if (!cursor) return undefined;
  try {
    if (!/^[A-Za-z0-9_-]+$/.test(cursor)) throw new Error();
    const parsed = cursorSchema.parse(JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')));
    if (parsed.scope !== scope(ctx, route)) throw new Error();
    return parsed.value;
  } catch { throw new PerchError('Invalid cursor for this Teams account, conversation or query.', 'invalid_cursor'); }
}
function cursorOffset(ctx: OperationContext, route: string, cursor?: string): number {
  const value = decodeCursor(ctx, route, cursor);
  if (value && !('offset' in value)) throw new PerchError('Invalid Teams page cursor.', 'invalid_cursor');
  return value?.offset ?? 0;
}
function queryCursor(ctx: OperationContext, route: string, cursor?: string): Record<string, string> {
  const value = decodeCursor(ctx, route, cursor);
  if (value && !('params' in value)) throw new PerchError('Invalid Teams history cursor.', 'invalid_cursor');
  return Object.fromEntries(Object.entries(value?.params ?? {}).filter((pair): pair is [string, string] => typeof pair[1] === 'string'));
}
function historyCursor(ctx: OperationContext, route: string, link: unknown): string | undefined {
  if (typeof link !== 'string' || !link || link.length > 12000) return undefined;
  try {
    // The link's host/path are deliberately discarded. Only documented paging
    // fields can affect a second request to the exact original route.
    const source = new URL(link).searchParams;
    const params: Record<string, string> = {};
    for (const key of ['startTime', 'endTime', 'syncState']) {
      const value = source.get(key);
      if (value) params[key] = value;
    }
    if (!Object.keys(params).length) return undefined;
    const value = cursorSchema.shape.value.parse({ params });
    return encodeCursor(ctx, route, value);
  } catch { return invalidResponse(); }
}
async function request(ctx: OperationContext, args: SessionHttpRequest): Promise<RecordValue> {
  const value: unknown = checkedJson(await ctx.request({ maxBytes: 4 * 1024 * 1024, ...args }));
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalidResponse();
  return value as RecordValue;
}
function operation<S extends z.ZodRawShape>(description: string, mode: 'read' | 'write', shape: S, run: (ctx: OperationContext, args: z.infer<z.ZodObject<S>>) => Promise<unknown>): SessionOperation {
  const schema = z.object(shape).strict();
  return { service: 'teams', mode, description, schema, run: (ctx, args) => run(ctx, schema.parse(args)) };
}
function messagesPath(id: string, root?: string): string {
  return `/v1/users/ME/conversations/${opaqueId(root ? `${id};messageid=${root}` : id)}/messages`;
}
function normalizeMessage(value: unknown, conversationId: string, ctx: OperationContext): TeamsMessage | undefined {
  const raw = record(value);
  const id = numericId(raw.id);
  const contentType = string(raw.messagetype);
  if (!id || !contentType || contentType.startsWith('Control/') || contentType === 'ThreadActivity/AddMember' || record(raw.properties).deletetime) return undefined;
  const body = text(raw.content, contentType !== 'Text');
  return { id, conversationId, ...body, contentType, sender: { id: string(raw.from), name: string(raw.imdisplayname ?? raw.displayName) },
    timestamp: string(raw.originalarrivaltime ?? raw.composetime), rootMessageId: numericId(raw.rootMessageId),
    clientMessageId: numericId(raw.clientmessageid), isFromMe: raw.from === `8:orgid:${ctx.identity.objectId}` };
}

function enumerationLimit(): never {
  throw new PerchError('Teams channel enumeration exceeds the limit of 100 teams, 1000 channels or 200 pages.', 'enumeration_limit');
}
function requiredString(value: unknown): string {
  if (typeof value !== 'string' || !value || value.length > 2048) return invalidResponse();
  return value;
}
function graphGroupId(value: unknown): string {
  const parsed = groupId.safeParse(value);
  return parsed.success ? parsed.data : invalidResponse();
}
function channelId(value: unknown): string {
  const parsed = conversation.safeParse(value);
  return parsed.success && parsed.data.startsWith('19:') ? parsed.data : invalidResponse();
}
function graphNextQuery(value: unknown, path: string, initial: Record<string, string>): Record<string, string> | undefined {
  if (value === undefined || value === null) return undefined;
  // Require the literal origin and route before URL parsing can normalize them.
  if (typeof value !== 'string' || value.length > 12000 || !value.startsWith(`https://graph.microsoft.com${path}?`) || /[\\#\u0000-\u0020\u007f]/.test(value)) return invalidResponse();
  let url: URL;
  try { url = new URL(value); } catch { return invalidResponse(); }
  const query = { ...initial };
  const seen = new Set<string>();
  let token = false;
  for (const [key, item] of url.searchParams) {
    if (seen.has(key)) return invalidResponse();
    seen.add(key);
    if (key === '$select' && initial[key] === item) continue;
    if (!['$skiptoken', '$skipToken'].includes(key) || token || !item || item.length > 8000 || /[\u0000-\u001f\u007f]/.test(item)) return invalidResponse();
    query[key] = item;
    token = true;
  }
  if (!token) return invalidResponse();
  return query;
}
async function graphChannels(ctx: OperationContext, selectedTeam?: string): Promise<TeamsChannel[]> {
  // The transport has checked the token tenant; confirm its immutable user ID
  // against Graph itself before trusting any team or channel response.
  const me = await request(ctx, { resource: 'graph', path: '/v1.0/me', query: { '$select': 'id' } });
  if (graphGroupId(me.id) !== ctx.identity.objectId.toLowerCase()) throw new PerchError('The Graph session belongs to a different Microsoft identity.', 'identity_mismatch');
  let pages = 0;
  async function collect(path: string, initial: Record<string, string>, maximum: number): Promise<unknown[]> {
    const values: unknown[] = [];
    let query = initial;
    const seen = new Set<string>();
    while (true) {
      const key = JSON.stringify(query);
      if (seen.has(key)) return invalidResponse();
      seen.add(key);
      if (++pages > 200) return enumerationLimit();
      const data = await request(ctx, { resource: 'graph', path, ...(Object.keys(query).length ? { query } : {}) });
      const batch = list(data.value);
      if (values.length + batch.length > maximum) return enumerationLimit();
      values.push(...batch);
      const next = graphNextQuery(data['@odata.nextLink'], path, initial);
      if (!next) return values;
      query = next;
    }
  }
  const teams = await collect('/v1.0/me/joinedTeams', {}, 100);
  const channels: TeamsChannel[] = [];
  const seenTeams = new Set<string>();
  for (const entry of teams) {
    const team = record(entry), teamId = graphGroupId(team.id), teamName = requiredString(team.displayName);
    if (seenTeams.has(teamId)) return invalidResponse();
    seenTeams.add(teamId);
    if (selectedTeam && selectedTeam !== teamId) continue;
    const entries = await collect(`/v1.0/teams/${teamId}/channels`, { '$select': CHANNEL_SELECT }, 1000 - channels.length);
    const seenChannels = new Set<string>();
    for (const entry of entries) {
      const raw = record(entry), id = channelId(raw.id), name = requiredString(raw.displayName);
      if (seenChannels.has(id) || typeof raw.membershipType !== 'string' || !['standard', 'private', 'shared'].includes(raw.membershipType)) return invalidResponse();
      seenChannels.add(id);
      if (raw.description !== undefined && raw.description !== null && (typeof raw.description !== 'string' || raw.description.length > 2048)) return invalidResponse();
      channels.push({ channelId: id, name, teamId, teamName, groupId: teamId, type: raw.membershipType as TeamsChannel['type'], description: typeof raw.description === 'string' ? raw.description : undefined });
    }
  }
  return channels;
}
async function csaChannels(ctx: OperationContext, selectedTeam?: string): Promise<TeamsChannel[]> {
  const data = await request(ctx, { resource: 'csa', path: '/api/v3/teams/users/me', query: { isPrefetch: 'false', enableMembershipSummary: 'true' } });
  const teams = list(data.teams);
  if (teams.length > 100) return enumerationLimit();
  const channels: TeamsChannel[] = [];
  let count = 0;
  for (const entry of teams) {
    const team = record(entry), teamId = string(team.id), teamName = string(team.displayName);
    if (!teamId || !teamName) continue;
    const entries = list(team.channels ?? []);
    count += entries.length;
    if (count > 1000) return enumerationLimit();
    for (const entry of entries) {
      const raw = record(entry), id = channelId(raw.id), name = string(raw.displayName);
      if (selectedTeam && selectedTeam !== teamId && selectedTeam !== string(raw.groupId)?.toLowerCase() && selectedTeam !== string(team.groupId)?.toLowerCase()) continue;
      if (name) channels.push({ channelId: id, name, teamId, teamName, groupId: string(raw.groupId ?? team.groupId), type: raw.channelType === 1 ? 'private' : raw.channelType === 2 ? 'shared' : 'standard', description: string(raw.description) });
    }
  }
  return channels;
}

export const teamsOperations: SessionOperations = {
  'teams.listChats': operation('List recent Teams conversations with last-message previews.', 'read', page, async (ctx, args) => {
    const path = '/v1/users/ME/conversations';
    const data = await request(ctx, { resource: 'chat', path, query: { ...queryCursor(ctx, path, args.cursor), view: 'msnp24Equivalent', pageSize: String(args.limit) } });
    const chats: TeamsChat[] = list(data.conversations).slice(0, args.limit).flatMap((value) => {
      const raw = record(value), last = record(raw.lastMessage), id = string(raw.id);
      if (!id) return [];
      return [{ conversationId: id, title: string(record(raw.threadProperties).topic), type: id.includes('meeting_') ? 'meeting' : id.endsWith('@thread.tacv2') ? 'channel' : id.endsWith('@unq.gbl.spaces') ? 'oneOnOne' : id.endsWith('@thread.v2') ? 'group' : 'chat', preview: text(last.content, true, 512).text, lastMessageAt: string(last.originalarrivaltime ?? last.composetime), lastSender: string(last.imdisplayname) }];
    });
    return { chats, cursor: historyCursor(ctx, path, record(data._metadata).backwardLink) };
  }),
  'teams.listChannels': operation('List channels in joined Teams. Graph team IDs are group UUIDs; legacy CSA IDs are team threads.', 'read', { ...page, teamId: z.union([groupId, conversation]).optional() }, async (ctx, args) => {
    const route = `channels:${args.teamId ?? '*'}`;
    const offset = cursorOffset(ctx, route, args.cursor);
    let channels: TeamsChannel[];
    if (args.teamId && !groupId.safeParse(args.teamId).success) channels = await csaChannels(ctx, args.teamId);
    else {
      try { channels = await graphChannels(ctx, args.teamId); }
      catch (error) {
        if (!(error instanceof PerchError) || !['reauth_required', 'access_denied'].includes(error.code)) throw error;
        channels = await csaChannels(ctx, args.teamId);
      }
    }
    const end = offset + args.limit;
    return { channels: channels.slice(offset, end), cursor: end < channels.length ? encodeCursor(ctx, route, { offset: end }) : undefined };
  }),
  'teams.getThread': operation('Read a page of chat messages or replies to a channel root message.', 'read', { ...page, conversationId: conversation, replyToMessageId: messageId.optional() }, async (ctx, args) => {
    const path = messagesPath(args.conversationId, args.replyToMessageId);
    const data = await request(ctx, { resource: 'chat', path, query: { ...queryCursor(ctx, path, args.cursor), view: 'msnp24Equivalent|supportsMessageProperties', pageSize: String(args.limit) } });
    const messages = list(data.messages).slice(0, args.limit).map((raw) => normalizeMessage(raw, args.conversationId, ctx)).filter((message): message is TeamsMessage => !!message);
    return { conversationId: args.conversationId, messages, cursor: historyCursor(ctx, path, record(data._metadata).backwardLink) };
  }),
  'teams.getMessage': operation('Read one Teams message by its server message ID.', 'read', { conversationId: conversation, messageId }, async (ctx, args) => {
    const data = await request(ctx, { resource: 'chat', path: `${messagesPath(args.conversationId)}/${opaqueId(args.messageId)}` });
    const message = normalizeMessage(data, args.conversationId, ctx);
    if (!message || message.id !== args.messageId) return invalidResponse();
    return message;
  }),
  'teams.search': operation('Search Teams messages. Search IDs are separate from message and thread IDs.', 'read', { ...page, query: z.string().trim().min(1).max(2000) }, async (ctx, args) => {
    const route = `search:${args.query}`, offset = cursorOffset(ctx, route, args.cursor);
    const data = await request(ctx, { resource: 'substrate', path: '/searchservice/api/v2/query', method: 'POST', body: {
      entityRequests: [{ entityType: 'Message', contentSources: ['Teams'], propertySet: 'Optimized', fields: ['Extension_SkypeSpaces_ConversationPost_Extension_FromSkypeInternalId_String', 'Extension_SkypeSpaces_ConversationPost_Extension_ThreadType_String', 'Extension_SkypeSpaces_ConversationPost_Extension_SkypeGroupId_String'], query: { queryString: `(${args.query}) AND NOT (isClientSoftDeleted:TRUE)`, displayQueryString: args.query }, from: offset, size: args.limit, topResultsCount: 5 }],
      cvid: randomUUID(), logicalId: randomUUID(), timezone: 'UTC',
      QueryAlterationOptions: { EnableAlteration: true, EnableSuggestion: true, SupportedRecourseDisplayTypes: ['Suggestion'] },
      scenario: { Name: 'powerbar', Dimensions: [{ DimensionName: 'QueryType', DimensionValue: 'Messages' }, { DimensionName: 'FormFactor', DimensionValue: 'general.web.reactSearch' }] },
    } });
    const messages: TeamsSearchMessage[] = [];
    let total: number | undefined;
    for (const entity of list(data.EntitySets)) for (const resultSet of list(record(entity).ResultSets)) {
      const set = record(resultSet), count = set.Total ?? set.TotalCount ?? set.TotalEstimate;
      if (typeof count === 'number' && Number.isFinite(count) && count >= 0) total = Math.max(total ?? 0, count);
      for (const entry of list(set.Results)) {
        const item = record(entry), source = record(item.Source), ext = record(source.Extensions);
        const combinedId = string(source.ClientConversationId), conv = string(source.ClientThreadId ?? ext.SkypeSpaces_ConversationPost_Extension_SkypeGroupId ?? combinedId)?.split(';')[0];
        const timestamp = string(source.DateTimeReceived ?? source.DateTimeSent ?? source.DateTimeCreated);
        const from = source.From ?? source.Sender;
        const explicitId = numericId(source.MessageId ?? source.OriginalMessageId ?? source.ReferenceObjectId);
        const timestampId = timestamp && Number.isFinite(Date.parse(timestamp)) ? String(Date.parse(timestamp)) : undefined;
        messages.push({ resultId: string(item.Id ?? item.ReferenceId), conversationId: conv, messageId: explicitId ?? timestampId, rootMessageId: combinedId?.match(/;messageid=(\d+)/)?.[1], ...text(item.HitHighlightedSummary ?? item.Summary), sender: typeof from === 'string' ? string(from) : string(record(from).Name ?? record(from).DisplayName), timestamp, channelName: string(source.ChannelName ?? source.Topic), teamName: string(source.TeamName ?? source.GroupName) });
      }
    }
    const end = offset + args.limit;
    const hasMore = total === undefined ? messages.length >= args.limit : end < total;
    return { messages: messages.slice(0, args.limit), total, cursor: hasMore && end <= 10000 ? encodeCursor(ctx, route, { offset: end }) : undefined };
  }),
  'teams.listAttachments': operation('List file metadata shared in a Teams conversation; use the files adapter for authorized downloads.', 'read', { ...page, conversationId: conversation }, async (ctx, args) => {
    const route = `attachments:${args.conversationId}`, cursor = decodeCursor(ctx, route, args.cursor);
    if (cursor && !('token' in cursor)) throw new PerchError('Invalid Teams attachment cursor.', 'invalid_cursor');
    const principal = opaqueId(`OID:${ctx.identity.objectId}@${ctx.identity.tenantId}`);
    const data = await request(ctx, { resource: 'substrate', path: `/AllFiles/api/users('${principal}')/AllShared`, query: { ThreadId: args.conversationId, ItemTypes: 'File', PageSize: String(Math.min(args.limit, 100)), ...(cursor ? { '$skiptoken': cursor.token } : {}) } });
    const attachments: TeamsAttachment[] = list(data.Items).slice(0, Math.min(args.limit, 100)).flatMap((entry) => {
      const item = record(entry), file = record(item.FileData);
      return item.ItemType === 'File' ? [{ name: string(file.FileName), webUrl: safeWebUrl(file.FileUrl ?? file.WebUrl), size: typeof file.SizeInBytes === 'number' && file.SizeInBytes >= 0 ? file.SizeInBytes : undefined, extension: string(file.FileExtension, 100), sharedBy: string(item.SharedByDisplayName), sharedAt: string(item.SharedDateTime ?? item.SharedTime) }] : [];
    });
    if (data.SkipToken != null && (typeof data.SkipToken !== 'string' || data.SkipToken.length > 8000)) return invalidResponse();
    const token = string(data.SkipToken, 8000);
    return { conversationId: args.conversationId, attachments, cursor: token ? encodeCursor(ctx, route, { token }) : undefined };
  }),
  'teams.send': operation('Send a plain-text chat message, channel post, or channel thread reply. Writes are not retried.', 'write', { conversationId: conversation, text: z.string().min(1).max(28000).refine((value) => value.trim().length > 0, 'Message must contain text'), replyToMessageId: messageId.optional(), subject: z.string().trim().min(1).max(250).optional() }, async (ctx, args): Promise<TeamsSendResult> => {
    if ((args.replyToMessageId || args.subject) && !args.conversationId.endsWith('@thread.tacv2')) throw new PerchError('Thread replies and subjects require a Teams channel conversation.', 'invalid_input');
    if (args.replyToMessageId && args.subject) throw new PerchError('A thread reply cannot start a new titled post.', 'invalid_input');
    const clientMessageId = `${Date.now()}${randomInt(0, 1000000).toString().padStart(6, '0')}`;
    const data = await request(ctx, { resource: 'chat', path: messagesPath(args.conversationId, args.replyToMessageId), method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Ms-Client-Version': '1415/1.0.0.2025010401' }, body: {
      content: args.text, messagetype: 'Text', contenttype: 'text', imdisplayname: ctx.displayName ?? 'User', clientmessageid: clientMessageId,
      ...(args.subject ? { properties: { subject: args.subject } } : {}),
    } });
    return { conversationId: args.conversationId, clientMessageId, messageId: numericId(data.id ?? data.MessageId), arrivalTime: typeof data.OriginalArrivalTime === 'number' ? data.OriginalArrivalTime : undefined };
  }),
};
