import { createHash } from 'node:crypto';
import { z } from 'zod';
import { PerchError } from '../../errors.js';
import { htmlToText, truncateUtf8 } from '../../mail/html.js';
import { ACCEPTED_NOTE, DEFAULT_MAIL_MAX_BYTES, HARD_MAIL_MAX_BYTES, INDETERMINATE_NOTE, type MailAttachmentMeta, type MailMessage, type MailSummary, type SendResult } from '../../mail/types.js';
import { checkedJson, opaqueId, type OperationContext, type SessionHttpRequest, type SessionOperation, type SessionOperations } from './contracts.js';

// Independently implemented Outlook REST contracts. All requests stay in the authenticated user's mailbox.
const ROOT = '/api/v2.0/me';
const ORIGIN = 'https://outlook.office.com';
const id = z.string().min(1).max(512).regex(/^[A-Za-z0-9+/_=-]+$/);
const pageSize = z.number().int().min(1).max(50).default(20);
const cursor = z.string().max(24000).regex(/^[A-Za-z0-9_-]+$/).optional();
const maxBytes = z.number().int().min(1).max(HARD_MAIL_MAX_BYTES).default(DEFAULT_MAIL_MAX_BYTES);
const listShape = { pageSize, cursor };
const email = z.string().email().max(320);
const text = z.string().max(1024 * 1024);
const headerValue = z.string().min(1).max(998).regex(/^[^\r\n\u0000]+$/);
const LIST_SELECT = 'Id,ConversationId,Subject,From,ToRecipients,ReceivedDateTime,LastModifiedDateTime,BodyPreview,HasAttachments,ParentFolderId,IsDraft';
const ATTACHMENT_SELECT = 'Id,Name,ContentType,Size,IsInline';
const READ_SELECT = `${LIST_SELECT},CcRecipients,ReplyTo,InternetMessageId,InternetMessageHeaders,Body`;
const EVENT_SELECT = 'Id,Subject,Start,End,Location,Organizer,Attendees,IsAllDay,IsCancelled,IsOrganizer,ResponseStatus,Type,SeriesMasterId,Recurrence,WebLink,OnlineMeeting,BodyPreview';
const large = () => new PerchError('Attachment is too large for the requested or browser transport byte limit.', 'attachment_too_large');
const badResponse = () => new PerchError('Microsoft returned an unexpected Outlook response.', 'invalid_response');
const badCursor = () => new PerchError('Invalid cursor for this mailbox, operation or query.', 'bad_cursor');
type Row = Record<string, any>;
function record(value: unknown): Row {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw badResponse();
  return value as Row;
}
function requiredId(value: unknown): string {
  if (!id.safeParse(value).success) throw badResponse();
  return value as string;
}
const optionalString = (value: unknown): string | undefined => typeof value === 'string' ? value : undefined;
function operation(service: 'mail' | 'calendar', mode: 'read' | 'write', description: string, schema: z.ZodObject<any>, run: SessionOperation['run']): SessionOperation {
  return { service, mode, description, schema, run: (ctx, args) => run(ctx, schema.parse(args)) };
}
async function json(ctx: OperationContext, request: Omit<SessionHttpRequest, 'resource'>): Promise<Row> {
  return record(checkedJson(await ctx.request({ resource: 'outlook', maxBytes: 4 * 1024 * 1024, ...request })));
}
function queryBinding(ctx: OperationContext, path: string, query: Record<string, string>, headers?: Record<string, string>): string {
  return createHash('sha256').update(JSON.stringify([ctx.identity.tenantId, ctx.identity.objectId, ctx.identity.mailboxId ?? '', path, Object.entries(query).sort(), Object.entries(headers ?? {}).sort()])).digest('hex');
}
function continuation(link: unknown, path: string, fixed: Record<string, string>): Record<string, string> {
  if (typeof link !== 'string' || link.length > 16000) throw badCursor();
  let url: URL;
  try { url = new URL(link); } catch { throw badCursor(); }
  if (url.origin !== ORIGIN || url.username || url.password || url.hash || url.pathname !== path) throw badCursor();
  const result: Record<string, string> = {};
  for (const [key, value] of url.searchParams) {
    if (Object.hasOwn(result, key) || (!Object.hasOwn(fixed, key) && key !== '$skip' && key !== '$skiptoken')) throw badCursor();
    if (key === '$skip' && !/^\d{1,12}$/.test(value)) throw badCursor();
    if (key === '$skiptoken' && (!value || value.length > 12000)) throw badCursor();
    result[key] = value;
  }
  for (const [key, value] of Object.entries(fixed)) if (result[key] !== value) throw badCursor();
  return result;
}
async function page(ctx: OperationContext, path: string, query: Record<string, string>, token: string | undefined, map: (row: Row) => unknown, headers?: Record<string, string>): Promise<{ items: any[]; next?: string }> {
  const binding = queryBinding(ctx, path, query, headers);
  let requestQuery = query;
  if (token) {
    let data: Row;
    try { data = record(JSON.parse(Buffer.from(token, 'base64url').toString('utf8'))); } catch { throw badCursor(); }
    if (data.v !== 1 || data.binding !== binding) throw badCursor();
    requestQuery = continuation(data.link, path, query);
  }
  const result = await json(ctx, { path, query: requestQuery, headers });
  if (!Array.isArray(result.value) || result.value.length > 1000) throw badResponse();
  const items = result.value.map((row: unknown) => map(record(row)));
  const link = result['@odata.nextLink'];
  if (link === undefined || link === null) return { items };
  continuation(link, path, query);
  return { items, next: Buffer.from(JSON.stringify({ v: 1, binding, link })).toString('base64url') };
}
function address(value: any): string | undefined {
  const a = value?.EmailAddress;
  if (typeof a?.Address !== 'string') return undefined;
  return typeof a.Name === 'string' && a.Name && a.Name !== a.Address ? `${a.Name} <${a.Address}>` : a.Address;
}
function addresses(value: unknown): string[] | undefined {
  return Array.isArray(value) ? value.map(address).filter((v): v is string => v !== undefined) : undefined;
}
function summary(row: Row): MailSummary {
  return { messageId: requiredId(row.Id), threadId: optionalString(row.ConversationId), folder: optionalString(row.ParentFolderId), from: address(row.From), to: addresses(row.ToRecipients), subject: optionalString(row.Subject), date: optionalString(row.ReceivedDateTime ?? row.LastModifiedDateTime), snippet: optionalString(row.BodyPreview), hasAttachments: typeof row.HasAttachments === 'boolean' ? row.HasAttachments : undefined };
}
function attachmentMeta(row: Row): MailAttachmentMeta {
  return { attachmentId: requiredId(row.Id), ...(typeof row.Name === 'string' ? { filename: row.Name } : {}), contentType: typeof row.ContentType === 'string' ? row.ContentType : 'application/octet-stream', ...(Number.isSafeInteger(row.Size) && row.Size >= 0 ? { size: row.Size } : {}), ...(typeof row.IsInline === 'boolean' ? { inline: row.IsInline } : {}) };
}
async function attachmentPage(ctx: OperationContext, args: { messageId: string; pageSize: number; cursor?: string }) {
  return page(ctx, `${ROOT}/messages/${opaqueId(args.messageId)}/attachments`, { $top: String(args.pageSize), $select: ATTACHMENT_SELECT }, args.cursor, attachmentMeta);
}
function bodyHeaders(row: Row, name: string): string | undefined {
  if (!Array.isArray(row.InternetMessageHeaders)) return undefined;
  const found = row.InternetMessageHeaders.find((h: any) => typeof h?.Name === 'string' && h.Name.toLowerCase() === name.toLowerCase());
  return optionalString(found?.Value);
}
const attachmentInput = z.object({ filename: z.string().min(1).max(255).regex(/^[^\r\n\u0000]+$/), contentType: z.string().min(1).max(200).regex(/^[\w!#$&^.+-]+\/[\w!#$&^.+-]+$/), contentBase64: z.string().max(4_000_000).regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/) }).strict();
const composition = z.object({ subject: z.string().max(998).regex(/^[^\r\n\u0000]*$/), text: text.optional(), html: text.optional(), to: z.array(email).max(100), cc: z.array(email).max(100).optional(), bcc: z.array(email).max(100).optional(), attachments: z.array(attachmentInput).max(20).optional(), sourceMessageId: id.optional(), inReplyTo: headerValue.optional(), references: z.array(headerValue).max(100).optional() }).strict().superRefine((args, ctx) => {
  if (args.text === undefined && args.html === undefined) ctx.addIssue({ code: 'custom', message: 'A text or HTML body is required.' });
  if (args.to.length + (args.cc?.length ?? 0) + (args.bcc?.length ?? 0) === 0) ctx.addIssue({ code: 'custom', message: 'At least one recipient is required.' });
  if (args.to.length + (args.cc?.length ?? 0) + (args.bcc?.length ?? 0) > 100) ctx.addIssue({ code: 'custom', message: 'At most 100 recipients are allowed.' });
  if (!args.sourceMessageId && (args.inReplyTo || args.references?.length)) ctx.addIssue({ code: 'custom', message: 'Threaded mail requires sourceMessageId for a native Outlook reply.' });
  if (Buffer.byteLength(JSON.stringify(args), 'utf8') > 4_000_000) ctx.addIssue({ code: 'custom', message: 'The composed message exceeds the 4 MB request limit.' });
});
type Composition = z.infer<typeof composition>;
function outgoing(args: Composition): Row {
  const recipients = (list: string[]) => list.map((Address) => ({ EmailAddress: { Address } }));
  return { Subject: args.subject, Body: { ContentType: args.html !== undefined ? 'HTML' : 'Text', Content: args.html ?? args.text ?? '' }, ToRecipients: recipients(args.to), CcRecipients: recipients(args.cc ?? []), BccRecipients: recipients(args.bcc ?? []) };
}
const outgoingAttachment = (a: z.infer<typeof attachmentInput>) => ({ '@odata.type': '#Microsoft.OutlookServices.FileAttachment', Name: a.filename, ContentType: a.contentType, ContentBytes: a.contentBase64 });
async function draft(ctx: OperationContext, args: Composition): Promise<{ draftId: string; messageId: string; threadId?: string }> {
  let created: Row;
  if (args.sourceMessageId) {
    created = await json(ctx, { method: 'POST', path: `${ROOT}/messages/${opaqueId(args.sourceMessageId)}/createreply`, body: {} });
    const createdId = requiredId(created.Id);
    // The caller already composed quoted text and recipients. Native createReply retains Outlook threading.
    try {
      await json(ctx, { method: 'PATCH', path: `${ROOT}/messages/${opaqueId(createdId)}`, body: outgoing(args) });
      for (const a of args.attachments ?? []) await json(ctx, { method: 'POST', path: `${ROOT}/messages/${opaqueId(createdId)}/attachments`, body: outgoingAttachment(a) });
    } catch {
      throw new PerchError(`Reply draft ${createdId} was created, but a later update was not confirmed. Inspect that draft before retrying; it has not been sent by this operation.`, 'partial_write');
    }
  } else {
    created = await json(ctx, { method: 'POST', path: `${ROOT}/messages`, body: { ...outgoing(args), ...(args.attachments?.length ? { Attachments: args.attachments.map(outgoingAttachment) } : {}) } });
  }
  const draftId = requiredId(created.Id);
  return { draftId, messageId: draftId, ...(typeof created.ConversationId === 'string' ? { threadId: created.ConversationId } : {}) };
}
async function sendAttempt(ctx: OperationContext, path: string, body?: unknown): Promise<SendResult> {
  let response;
  try { response = await ctx.request({ resource: 'outlook', method: 'POST', path, ...(body !== undefined ? { body } : {}), maxBytes: 64 * 1024 }); }
  catch { return { status: 'indeterminate', detail: INDETERMINATE_NOTE }; }
  if (response.status >= 200 && response.status < 300) return { status: 'accepted', detail: ACCEPTED_NOTE };
  if (response.status >= 500 || response.status === 408) return { status: 'indeterminate', detail: INDETERMINATE_NOTE };
  if (response.status === 401 || response.status === 403) checkedJson(response);
  return { status: 'rejected', detail: `Microsoft refused the send (HTTP ${response.status}).` };
}
async function move(ctx: OperationContext, messageId: string, destination: string) {
  const result = await json(ctx, { method: 'POST', path: `${ROOT}/messages/${opaqueId(messageId)}/move`, body: { DestinationId: destination } });
  return { messageId: requiredId(result.Id), ...(typeof result.ParentFolderId === 'string' ? { folderId: result.ParentFolderId } : {}) };
}
const zone = z.string().min(1).max(100).regex(/^[A-Za-z0-9 ()+_.:-]+$/);
const wallTime = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/).refine((value) => {
  const parsed = new Date(`${value}Z`); return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 19) === value;
}, 'Use a valid local date and time, without an offset, and an explicit Windows time zone.');
const dateTime = z.object({ dateTime: wallTime, timeZone: zone }).strict();
const attendee = z.object({ email, name: z.string().max(200).optional(), type: z.enum(['required', 'optional']).default('required') }).strict();
const eventFields = { subject: z.string().min(1).max(500), start: dateTime, end: dateTime, text: text.optional(), html: text.optional(), location: z.string().max(1000).optional(), attendees: z.array(attendee).max(100).optional(), isAllDay: z.boolean().optional(), teamsMeeting: z.boolean().optional() };
function validateEvent(args: any, ctx: z.RefinementCtx) {
  if ((args.start === undefined) !== (args.end === undefined)) ctx.addIssue({ code: 'custom', message: 'Supply both start and end when changing event times.' });
  if (args.start && args.end && (args.start.timeZone !== args.end.timeZone || args.end.dateTime <= args.start.dateTime)) ctx.addIssue({ code: 'custom', message: 'End must be after start and use the same time zone.' });
  if (args.isAllDay && args.start && (!args.start.dateTime.endsWith('T00:00:00') || !args.end.dateTime.endsWith('T00:00:00'))) ctx.addIssue({ code: 'custom', message: 'All-day events must start and end at local midnight.' });
  if (args.text !== undefined && args.html !== undefined) ctx.addIssue({ code: 'custom', message: 'Supply either text or HTML for the event body.' });
}
const createEvent = z.object({ calendarId: id.optional(), ...eventFields }).strict().superRefine(validateEvent);
const updateEvent = z.object({ eventId: id, ...Object.fromEntries(Object.entries(eventFields).map(([key, value]) => [key, value.optional()])) }).strict().superRefine((args, ctx) => {
  validateEvent(args, ctx);
  if (Object.keys(args).filter((k) => k !== 'eventId').length === 0) ctx.addIssue({ code: 'custom', message: 'Specify at least one event change.' });
});
function eventBody(args: any): Row {
  const body: Row = {};
  if (args.subject !== undefined) body.Subject = args.subject;
  for (const [key, target] of [['start', 'Start'], ['end', 'End']] as const) if (args[key]) body[target] = { DateTime: args[key].dateTime, TimeZone: args[key].timeZone };
  if (args.text !== undefined || args.html !== undefined) body.Body = { ContentType: args.html !== undefined ? 'HTML' : 'Text', Content: args.html ?? args.text };
  if (args.location !== undefined) body.Location = { DisplayName: args.location };
  if (args.isAllDay !== undefined) body.IsAllDay = args.isAllDay;
  if (args.attendees !== undefined) body.Attendees = args.attendees.map((a: z.infer<typeof attendee>) => ({ Type: a.type === 'optional' ? 'Optional' : 'Required', EmailAddress: { Address: a.email, ...(a.name ? { Name: a.name } : {}) } }));
  if (args.teamsMeeting === true) Object.assign(body, { IsOnlineMeeting: true, OnlineMeetingProvider: 'TeamsForBusiness' });
  return body;
}
function event(row: Row): Row {
  const date = (value: any) => value && typeof value.DateTime === 'string' ? { dateTime: value.DateTime, timeZone: optionalString(value.TimeZone) } : undefined;
  const result: Row = { eventId: requiredId(row.Id), subject: optionalString(row.Subject), start: date(row.Start), end: date(row.End), location: optionalString(row.Location?.DisplayName), organizer: address(row.Organizer), attendees: Array.isArray(row.Attendees) ? row.Attendees.map((a: any) => ({ email: optionalString(a.EmailAddress?.Address), name: optionalString(a.EmailAddress?.Name), type: optionalString(a.Type), response: optionalString(a.Status?.Response) })) : [], isAllDay: row.IsAllDay, isCancelled: row.IsCancelled, isOrganizer: row.IsOrganizer, type: optionalString(row.Type), seriesMasterId: optionalString(row.SeriesMasterId), webLink: optionalString(row.WebLink), joinUrl: optionalString(row.OnlineMeeting?.JoinUrl), snippet: optionalString(row.BodyPreview) };
  if (row.Body?.Content) result.text = String(row.Body.ContentType).toLowerCase() === 'html' ? htmlToText(row.Body.Content, DEFAULT_MAIL_MAX_BYTES).text : truncateUtf8(row.Body.Content, DEFAULT_MAIL_MAX_BYTES).text;
  return result;
}
function requireInvites(ctx: OperationContext, required: boolean) {
  if (required && !ctx.allowInvites) throw new PerchError('Calendar invitation permission is required for events with attendees.', 'access_denied');
}
const timeHeaders = (timeZone?: string) => timeZone ? { Prefer: `outlook.timezone="${timeZone}"` } : undefined;

export const outlookOperations: SessionOperations = {
  'mail.profile': operation('mail', 'read', 'Read the signed-in mailbox profile.', z.object({}).strict(), async (ctx) => {
    const me = await json(ctx, { path: ROOT });
    if (typeof me.Id !== 'string' || !me.Id || me.Id.length > 1024 || /[\u0000-\u001f]/.test(me.Id)) throw badResponse();
    return { id: me.Id, email: optionalString(me.EmailAddress), displayName: optionalString(me.DisplayName), mailboxId: optionalString(me.MailboxGuid), alias: optionalString(me.Alias) };
  }),
  'mail.listFolders': operation('mail', 'read', 'List folders in this mailbox.', z.object({ ...listShape, parentId: id.optional() }).strict(), async (ctx, args) => page(ctx, args.parentId ? `${ROOT}/mailfolders/${opaqueId(args.parentId)}/childfolders` : `${ROOT}/mailfolders`, { $top: String(args.pageSize), $select: 'Id,DisplayName,ParentFolderId,ChildFolderCount,UnreadItemCount,TotalItemCount' }, args.cursor, (row) => ({ folderId: requiredId(row.Id), name: optionalString(row.DisplayName) ?? row.Id, role: 'other', total: row.TotalItemCount, unread: row.UnreadItemCount, childFolderCount: row.ChildFolderCount }))),
  'mail.search': operation('mail', 'read', 'Search or list messages in this mailbox.', z.object({ ...listShape, query: z.string().min(1).max(1000).regex(/^[^"\r\n\u0000]+$/).optional(), folder: id.optional() }).strict().refine((args) => !(args.query && args.folder), 'Search covers the whole mailbox; omit folder when searching.'), async (ctx, args) => {
    const query: Record<string, string> = { $top: String(args.pageSize), $select: LIST_SELECT };
    if (args.query) query.$search = `"${args.query}"`; else query.$orderby = 'ReceivedDateTime desc';
    return page(ctx, args.query ? `${ROOT}/messages` : `${ROOT}/mailfolders/${opaqueId(args.folder ?? 'inbox')}/messages`, query, args.cursor, summary);
  }),
  'mail.read': operation('mail', 'read', 'Read a message with bounded text and attachment metadata.', z.object({ messageId: id, maxBytes }).strict(), async (ctx, args) => {
    const row = await json(ctx, { path: `${ROOT}/messages/${opaqueId(args.messageId)}`, query: { $select: READ_SELECT }, headers: { Prefer: 'outlook.body-content-type="text"' }, maxBytes: HARD_MAIL_MAX_BYTES });
    const raw = typeof row.Body?.Content === 'string' ? row.Body.Content : '';
    const isHtml = String(row.Body?.ContentType).toLowerCase() === 'html';
    const content = isHtml ? htmlToText(raw, args.maxBytes) : truncateUtf8(raw, args.maxBytes);
    const attachments: MailAttachmentMeta[] = [];
    if (row.HasAttachments) {
      let token: string | undefined;
      let pages = 0;
      do {
        const listed = await attachmentPage(ctx, { messageId: args.messageId, pageSize: 50, cursor: token });
        attachments.push(...listed.items); token = listed.next;
        pages++;
        if (token && (attachments.length >= 200 || pages >= 4)) throw new PerchError('Too many attachment pages for a single message read; use paginated attachment listing.', 'response_too_large');
      } while (token);
    }
    const result: MailMessage = { ...summary(row), cc: addresses(row.CcRecipients), replyTo: addresses(row.ReplyTo), internetMessageId: optionalString(row.InternetMessageId), inReplyTo: bodyHeaders(row, 'In-Reply-To'), references: bodyHeaders(row, 'References')?.split(/\s+/).filter(Boolean), text: content.text, textSource: isHtml ? 'text/html' : 'text/plain', truncated: content.truncated, attachments };
    return result;
  }),
  'mail.attachments': operation('mail', 'read', 'List attachment metadata without downloading bytes.', z.object({ messageId: id, ...listShape }).strict(), attachmentPage),
  'mail.attachment': operation('mail', 'read', 'Download one bounded file attachment.', z.object({ messageId: id, attachmentId: id, maxBytes }).strict(), async (ctx, args) => {
    const path = `${ROOT}/messages/${opaqueId(args.messageId)}/attachments/${opaqueId(args.attachmentId)}`;
    const meta = await json(ctx, { path, query: { $select: ATTACHMENT_SELECT } });
    if (meta['@odata.type'] && !String(meta['@odata.type']).endsWith('FileAttachment')) throw new PerchError('This attachment is not a downloadable file.', 'unsupported_attachment');
    if (!Number.isSafeInteger(meta.Size) || meta.Size < 0) throw badResponse();
    const byteLimit = Math.min(args.maxBytes, Math.floor((HARD_MAIL_MAX_BYTES - 64 * 1024) / 4) * 3);
    if (meta.Size > byteLimit) throw large();
    const full = await json(ctx, { path, maxBytes: Math.min(HARD_MAIL_MAX_BYTES, Math.ceil(byteLimit / 3) * 4 + 64 * 1024) });
    const bytes = full.ContentBytes;
    if (typeof bytes !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(bytes)) throw badResponse();
    if (bytes.length > Math.ceil(byteLimit / 3) * 4) throw large();
    const decoded = Buffer.from(bytes, 'base64');
    if (decoded.length > byteLimit) throw large();
    if (decoded.toString('base64') !== bytes) throw badResponse();
    return { ...attachmentMeta(meta), size: decoded.length, contentBase64: bytes };
  }),
  'mail.createDraft': operation('mail', 'write', 'Create a draft; never sends it.', composition, draft),
  'mail.send': operation('mail', 'write', 'Send the composed message once.', composition, async (ctx, args: Composition) => {
    if (args.sourceMessageId) { const created = await draft(ctx, args); return sendAttempt(ctx, `${ROOT}/messages/${opaqueId(created.draftId)}/send`); }
    return sendAttempt(ctx, `${ROOT}/sendmail`, { Message: { ...outgoing(args), ...(args.attachments?.length ? { Attachments: args.attachments.map(outgoingAttachment) } : {}) }, SaveToSentItems: true });
  }),
  'mail.sendDraft': operation('mail', 'write', 'Send an existing draft once.', z.object({ draftId: id }).strict(), async (ctx, args) => {
    const path = `${ROOT}/messages/${opaqueId(args.draftId)}`;
    const current = await json(ctx, { path, query: { $select: 'Id,IsDraft' } });
    if (current.IsDraft !== true) throw new PerchError('This message is not a draft.', 'not_a_draft');
    return sendAttempt(ctx, `${path}/send`);
  }),
  'mail.mark': operation('mail', 'write', 'Change read or follow-up flags.', z.object({ messageId: id, read: z.boolean().optional(), starred: z.boolean().optional() }).strict().refine((args) => args.read !== undefined || args.starred !== undefined, 'Specify a flag change.'), async (ctx, args) => {
    const path = `${ROOT}/messages/${opaqueId(args.messageId)}`;
    await json(ctx, { method: 'PATCH', path, body: { ...(args.read !== undefined ? { IsRead: args.read } : {}), ...(args.starred !== undefined ? { Flag: { FlagStatus: args.starred ? 'Flagged' : 'NotFlagged' } } : {}) } });
    const after = await json(ctx, { path, query: { $select: 'IsRead,Flag' } });
    const mismatch = (args.read !== undefined && after.IsRead !== args.read) || (args.starred !== undefined && after.Flag?.FlagStatus !== (args.starred ? 'Flagged' : 'NotFlagged'));
    return { messageId: args.messageId, ...(mismatch ? { note: 'Microsoft accepted the change but the re-read did not confirm all requested flags.' } : {}) };
  }),
  'mail.move': operation('mail', 'write', 'Move a message within this mailbox.', z.object({ messageId: id, folderId: id.optional(), archive: z.boolean().optional() }).strict().refine((args) => args.archive === true ? args.folderId === undefined : args.folderId !== undefined, 'Specify either archive or folderId.').refine((args) => args.folderId?.toLowerCase() !== 'drafts', 'Cannot move messages into drafts.'), async (ctx, args) => {
    const destination = args.archive ? 'archive' : args.folderId;
    if (!['inbox', 'archive', 'deleteditems', 'junkemail', 'sentitems'].includes(destination.toLowerCase())) {
      const drafts = await json(ctx, { path: `${ROOT}/mailfolders/drafts`, query: { $select: 'Id' } });
      if (requiredId(drafts.Id) === destination) throw new PerchError('Cannot move messages into drafts.', 'bad_argument');
    }
    return move(ctx, args.messageId, destination);
  }),
  'mail.trash': operation('mail', 'write', 'Move a message to recoverable deleted items.', z.object({ messageId: id }).strict(), (ctx, args) => move(ctx, args.messageId, 'deleteditems')),
  'mail.restore': operation('mail', 'write', 'Move a message back to the inbox.', z.object({ messageId: id }).strict(), (ctx, args) => move(ctx, args.messageId, 'inbox')),
  'calendar.listCalendars': operation('calendar', 'read', 'List calendars in this mailbox.', z.object(listShape).strict(), async (ctx, args) => page(ctx, `${ROOT}/calendars`, { $top: String(args.pageSize), $select: 'Id,Name,Color,CanEdit,Owner' }, args.cursor, (row) => ({ calendarId: requiredId(row.Id), name: optionalString(row.Name), color: row.Color, canEdit: row.CanEdit, owner: address({ EmailAddress: row.Owner }) }))),
  'calendar.listEvents': operation('calendar', 'read', 'List occurrences in an explicit time window.', z.object({ ...listShape, calendarId: id.optional(), start: z.string().max(40).datetime({ offset: true }), end: z.string().max(40).datetime({ offset: true }), timeZone: zone.optional() }).strict().refine((args) => { const span = Date.parse(args.end) - Date.parse(args.start); return span > 0 && span <= 366 * 86400000; }, 'The window must be positive and at most 366 days.'), async (ctx, args) => page(ctx, args.calendarId ? `${ROOT}/calendars/${opaqueId(args.calendarId)}/calendarview` : `${ROOT}/calendarview`, { startDateTime: args.start, endDateTime: args.end, $top: String(args.pageSize), $select: EVENT_SELECT, $orderby: 'Start/DateTime' }, args.cursor, event, timeHeaders(args.timeZone))),
  'calendar.getEvent': operation('calendar', 'read', 'Read a calendar event.', z.object({ eventId: id, timeZone: zone.optional() }).strict(), async (ctx, args) => event(await json(ctx, { path: `${ROOT}/events/${opaqueId(args.eventId)}`, headers: timeHeaders(args.timeZone) }))),
  'calendar.createEvent': operation('calendar', 'write', 'Create an appointment; attendees require invitation permission.', createEvent, async (ctx, args) => {
    requireInvites(ctx, !!args.attendees?.length);
    return event(await json(ctx, { method: 'POST', path: args.calendarId ? `${ROOT}/calendars/${opaqueId(args.calendarId)}/events` : `${ROOT}/events`, body: eventBody(args) }));
  }),
  'calendar.updateEvent': operation('calendar', 'write', 'Update one event or occurrence while preserving recurrence.', updateEvent, async (ctx, args) => {
    const path = `${ROOT}/events/${opaqueId(args.eventId)}`;
    const current = await json(ctx, { path, query: { $select: 'Id,IsOrganizer,Attendees,Type,Start,End,IsAllDay,IsOnlineMeeting' } });
    if (current.IsOrganizer !== true) throw new PerchError('Only the organizer can update this event.', 'access_denied');
    if (current.Type === 'SeriesMaster') throw new PerchError('Updating a whole recurring series is not supported; choose an occurrence.', 'unsupported_operation');
    if (!Array.isArray(current.Attendees)) throw badResponse();
    requireInvites(ctx, current.Attendees.length > 0 || !!args.attendees?.length);
    if ((args.isAllDay === true && current.IsAllDay !== true) || ((args.isAllDay ?? current.IsAllDay) === true && args.start)) {
      const start = args.start?.dateTime;
      const end = args.end?.dateTime;
      if (typeof start !== 'string' || typeof end !== 'string' || !/T00:00:00(?:\.0+)?$/.test(start) || !/T00:00:00(?:\.0+)?$/.test(end)) throw new PerchError('All-day events must start and end at local midnight; supply explicit start and end times.', 'bad_argument');
    }
    if (args.teamsMeeting === false && current.IsOnlineMeeting) throw new PerchError('Removing an existing online meeting is not supported.', 'unsupported_operation');
    const body = eventBody(args);
    if (Object.keys(body).length === 0) throw new PerchError('No event change was specified.', 'bad_argument');
    const updated = await json(ctx, { method: 'PATCH', path, body });
    return event(updated.Id ? updated : await json(ctx, { path, headers: timeHeaders(args.start?.timeZone) }));
  }),
};
