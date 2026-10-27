import { describe, expect, it } from 'vitest';
import { outlookOperations } from '../src/microsoft/session/outlook.js';
import type { OperationContext, SessionHttpRequest } from '../src/microsoft/session/contracts.js';

const identity = { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', mailboxId: 'mailbox', kind: 'organization' as const };
const ORIGIN = 'https://outlook.office.com';
function fixture(responses: unknown[] = [], allowInvites = false) {
  const calls: SessionHttpRequest[] = [];
  const ctx: OperationContext & { allowInvites: boolean } = { identity, sites: [], allowInvites, request: async (request) => {
    calls.push(request);
    const result = responses.shift();
    if (result instanceof Error) throw result;
    return { status: 200, headers: {}, body: Buffer.from(JSON.stringify(result ?? {})) };
  } };
  return { ctx, calls };
}
async function run(name: string, input: unknown, ctx: OperationContext): Promise<any> {
  const operation = outlookOperations[name]!;
  return operation.run(ctx, operation.schema.parse(input));
}
const mail = { Id: 'm/a=', Subject: 'Subject', From: { EmailAddress: { Address: 'from@example.com', Name: 'Sender' } },
  ToRecipients: [{ EmailAddress: { Address: 'to@example.com' } }], BccRecipients: [{ EmailAddress: { Address: 'secret@example.com' } }],
  ConversationId: 'thread', InternetMessageId: '<original@example.com>', Body: { ContentType: 'Text', Content: 'A😀BC' },
  HasAttachments: false, InternetMessageHeaders: [{ Name: 'Bcc', Value: 'secret@example.com' }] };
const dates = { start: { dateTime: '2026-10-27T09:00:00', timeZone: 'W. Europe Standard Time' }, end: { dateTime: '2026-10-27T10:00:00', timeZone: 'W. Europe Standard Time' } };

describe('Microsoft browser-session Outlook operations', () => {
  it('exposes all requested operations with strict schemas and no generic HTTP escape', () => {
    expect(Object.keys(outlookOperations)).toEqual(expect.arrayContaining(['mail.profile', 'mail.listFolders', 'mail.search', 'mail.read', 'mail.attachments', 'mail.attachment', 'mail.createDraft', 'mail.send', 'mail.sendDraft', 'mail.mark', 'mail.move', 'mail.trash', 'mail.restore', 'calendar.listCalendars', 'calendar.listEvents', 'calendar.getEvent', 'calendar.createEvent', 'calendar.updateEvent']));
    for (const operation of Object.values(outlookOperations)) expect(operation.schema.safeParse({ arbitraryUrl: 'https://evil.example' }).success).toBe(false);
  });
  it('normalizes message reads, bounds UTF-8 and never returns Bcc', async () => {
    const f = fixture([mail]);
    const result = await run('mail.read', { messageId: 'm/a=', maxBytes: 5 }, f.ctx);
    expect(result).toMatchObject({ messageId: 'm/a=', threadId: 'thread', from: 'Sender <from@example.com>', text: 'A😀', truncated: true, attachments: [] });
    expect(JSON.stringify(result)).not.toContain('secret@example.com');
    expect(f.calls[0]).toMatchObject({ resource: 'outlook', path: '/api/v2.0/me/messages/m%2Fa%3D', headers: { Prefer: 'outlook.body-content-type="text"' } });
  });
  it('uses mailbox-wide search without incompatible order or filter', async () => {
    const f = fixture([{ value: [mail] }]);
    const result = await run('mail.search', { query: 'hello', pageSize: 5 }, f.ctx);
    expect(result.items[0].messageId).toBe('m/a=');
    expect(f.calls[0]).toMatchObject({ path: '/api/v2.0/me/messages', query: { $search: '"hello"', $top: '5' } });
    expect(f.calls[0]!.query).not.toHaveProperty('$orderby');
    expect(JSON.stringify(result)).not.toContain('secret@example.com');
  });
  it('binds cursors to identity, route and query and refuses hostile provider links', async () => {
    const first = fixture();
    first.ctx.request = async (request) => {
      first.calls.push(request);
      const u = new URL('https://outlook.office.com' + request.path);
      Object.entries(request.query ?? {}).forEach(([k, v]) => u.searchParams.set(k, v));
      u.searchParams.set('$skip', '5');
      return { status: 200, headers: {}, body: Buffer.from(JSON.stringify({ value: [], '@odata.nextLink': u.href })) };
    };
    const page = await run('mail.search', { query: 'hello', pageSize: 5 }, first.ctx);
    const next = fixture([{ value: [] }]);
    await run('mail.search', { query: 'hello', pageSize: 5, cursor: page.next }, next.ctx);
    expect(next.calls[0]!.query!.$skip).toBe('5');
    await expect(run('mail.search', { query: 'other', pageSize: 5, cursor: page.next }, fixture().ctx)).rejects.toThrow(/cursor/i);
    const other = fixture(); other.ctx.identity = { ...identity, objectId: '33333333-3333-4333-8333-333333333333' };
    await expect(run('mail.search', { query: 'hello', pageSize: 5, cursor: page.next }, other.ctx)).rejects.toThrow(/cursor/i);
    for (const link of ['https://evil.example/api/v2.0/me/messages', 'https://outlook.office.com/api/v2.0/users/other/messages', 'https://outlook.office.com/api/v2.0/me/events']) {
      await expect(run('mail.search', {}, fixture([{ value: [], '@odata.nextLink': link }]).ctx)).rejects.toThrow(/cursor/i);
    }
  });
  it('attachment listing excludes bytes and content checks size before downloading', async () => {
    const f = fixture([{ value: [{ Id: 'a', Name: 'x', ContentType: 'text/plain', Size: 10, ContentBytes: 'c2VjcmV0' }] }]);
    const listed = await run('mail.attachments', { messageId: 'm' }, f.ctx);
    expect(listed.items[0]).toEqual({ attachmentId: 'a', filename: 'x', contentType: 'text/plain', size: 10 });
    expect(f.calls[0]!.query!.$select).not.toContain('ContentBytes');
    const big = fixture([{ Id: 'a', Size: 100, '@odata.type': '#Microsoft.OutlookServices.FileAttachment' }]);
    await expect(run('mail.attachment', { messageId: 'm', attachmentId: 'a', maxBytes: 10 }, big.ctx)).rejects.toThrow(/large/i);
    expect(big.calls).toHaveLength(1);
  });
  it('returns complete canonical attachment bytes and rejects oversized or malformed data', async () => {
    const meta = { Id: 'a', Name: 'a.txt', ContentType: 'text/plain', Size: 3 };
    const f = fixture([meta, { ...meta, ContentBytes: 'YWJj' }]);
    expect(await run('mail.attachment', { messageId: 'm', attachmentId: 'a', maxBytes: 3 }, f.ctx)).toMatchObject({ contentBase64: 'YWJj', size: 3 });
    await expect(run('mail.attachment', { messageId: 'm', attachmentId: 'a', maxBytes: 3 }, fixture([meta, { ...meta, ContentBytes: 'YWJjZA==' }]).ctx)).rejects.toThrow(/large/i);
    await expect(run('mail.attachment', { messageId: 'm', attachmentId: 'a' }, fixture([meta, { ...meta, ContentBytes: 'not base64!' }]).ctx)).rejects.toThrow();
    await expect(run('mail.attachment', { messageId: 'm', attachmentId: 'a' }, fixture([{ ...meta, '@odata.type': '#Microsoft.OutlookServices.ItemAttachment' }]).ctx)).rejects.toThrow(/file/i);
  });
  it('composes native reply drafts and attaches files without inventing RFC header writes', async () => {
    const f = fixture([{ Id: 'draft' }, {}, {}]);
    expect(await run('mail.createDraft', { subject: 'Reply', text: 'Hi', to: ['to@example.com'], bcc: ['secret@example.com'], attachments: [{ filename: 'a.txt', contentType: 'text/plain', contentBase64: 'YWJj' }], sourceMessageId: 'original', inReplyTo: '<a@example.com>', references: ['<b@example.com>'] }, f.ctx)).toMatchObject({ draftId: 'draft', messageId: 'draft' });
    expect(f.calls[0]).toMatchObject({ method: 'POST', path: '/api/v2.0/me/messages/original/createreply' });
    expect(f.calls[1]).toMatchObject({ method: 'PATCH', path: '/api/v2.0/me/messages/draft', body: { Subject: 'Reply', Body: { ContentType: 'Text', Content: 'Hi' }, BccRecipients: [{ EmailAddress: { Address: 'secret@example.com' } }] } });
    expect(f.calls[2]).toMatchObject({ method: 'POST', path: '/api/v2.0/me/messages/draft/attachments', body: { '@odata.type': '#Microsoft.OutlookServices.FileAttachment', Name: 'a.txt', ContentBytes: 'YWJj' } });
    const noSource = fixture();
    await expect(run('mail.createDraft', { subject: 'Reply', text: 'Hi', to: ['to@example.com'], inReplyTo: '<a@example.com>' }, noSource.ctx)).rejects.toThrow(/thread|source/i);
    expect(noSource.calls).toHaveLength(0);
  });
  it('sends once, classifies ambiguous outcomes, and refuses sending a non-draft', async () => {
    const sent = fixture([{}]);
    expect(await run('mail.send', { subject: 'Hello', text: 'Hi', to: ['to@example.com'] }, sent.ctx)).toMatchObject({ status: 'accepted' });
    expect(sent.calls).toHaveLength(1);
    const lost = fixture([new Error('network lost')]);
    expect(await run('mail.send', { subject: 'Hello', text: 'Hi', to: ['to@example.com'] }, lost.ctx)).toMatchObject({ status: 'indeterminate' });
    expect(lost.calls).toHaveLength(1);
    const notDraft = fixture([{ IsDraft: false }]);
    await expect(run('mail.sendDraft', { draftId: 'm' }, notDraft.ctx)).rejects.toThrow(/draft/i);
    expect(notDraft.calls).toHaveLength(1);
  });
  it('marks flags and moves to trash/restore without deleting, returning the new id', async () => {
    const f = fixture([{}, { IsRead: false, Flag: { FlagStatus: 'Flagged' } }, { Id: 'new', ParentFolderId: 'trash' }, { Id: 'restored', ParentFolderId: 'inbox' }]);
    await run('mail.mark', { messageId: 'm', read: false, starred: true }, f.ctx);
    expect(f.calls[0]!.body).toEqual({ IsRead: false, Flag: { FlagStatus: 'Flagged' } });
    expect(await run('mail.trash', { messageId: 'm' }, f.ctx)).toEqual({ messageId: 'new', folderId: 'trash' });
    expect(await run('mail.restore', { messageId: 'new' }, f.ctx)).toEqual({ messageId: 'restored', folderId: 'inbox' });
    expect(f.calls.filter((x) => x.method === 'POST').map((x) => x.body)).toEqual([{ DestinationId: 'deleteditems' }, { DestinationId: 'inbox' }]);
    expect(f.calls.some((x) => x.method === 'DELETE')).toBe(false);
  });
  it('lists recurrence-expanded events and keeps recurrence identifiers', async () => {
    const f = fixture([{ value: [{ Id: 'e', Subject: 'Weekly', Type: 'Occurrence', SeriesMasterId: 'series', Start: { DateTime: dates.start.dateTime, TimeZone: dates.start.timeZone }, End: { DateTime: dates.end.dateTime, TimeZone: dates.end.timeZone } }] }]);
    const page = await run('calendar.listEvents', { calendarId: 'c/a', start: '2026-10-27T00:00:00Z', end: '2026-10-28T00:00:00Z' }, f.ctx);
    expect(f.calls[0]!.path).toBe('/api/v2.0/me/calendars/c%2Fa/calendarview');
    expect(page.items[0]).toMatchObject({ eventId: 'e', type: 'Occurrence', seriesMasterId: 'series' });
  });
  it('requires invitation permission for new attendees and for removing all existing attendees', async () => {
    const f = fixture();
    await expect(run('calendar.createEvent', { subject: 'Meeting', ...dates, attendees: [{ email: 'to@example.com' }] }, f.ctx)).rejects.toThrow(/invitation/i);
    expect(f.calls).toHaveLength(0);
    const existing = fixture([{ Id: 'e', IsOrganizer: true, Attendees: [{ EmailAddress: { Address: 'to@example.com' } }], Start: { DateTime: dates.start.dateTime, TimeZone: dates.start.timeZone }, End: { DateTime: dates.end.dateTime, TimeZone: dates.end.timeZone } }]);
    await expect(run('calendar.updateEvent', { eventId: 'e', attendees: [] }, existing.ctx)).rejects.toThrow(/invitation/i);
    expect(existing.calls).toHaveLength(1);
  });
  it('updates only explicit event fields and refuses attendee-copy and series-master updates', async () => {
    const f = fixture([{ Id: 'e', IsOrganizer: true, Type: 'Occurrence', SeriesMasterId: 'series', Attendees: [] }, { Id: 'e', Subject: 'Changed', Type: 'Occurrence', SeriesMasterId: 'series' }]);
    expect(await run('calendar.updateEvent', { eventId: 'e', subject: 'Changed' }, f.ctx)).toMatchObject({ eventId: 'e', seriesMasterId: 'series' });
    expect(f.calls[1]!.body).toEqual({ Subject: 'Changed' });
    await expect(run('calendar.updateEvent', { eventId: 'e', subject: 'Changed' }, fixture([{ Id: 'e', IsOrganizer: false }], true).ctx)).rejects.toThrow(/organizer/i);
    await expect(run('calendar.updateEvent', { eventId: 'e', subject: 'Changed' }, fixture([{ Id: 'e', IsOrganizer: true, Type: 'SeriesMaster' }], true).ctx)).rejects.toThrow(/series/i);
  });
  it('rejects invalid dates, unbounded content, forbidden fields and empty changes before HTTP', async () => {
    for (const [name, args] of [
      ['calendar.createEvent', { subject: 'Bad', ...dates, end: dates.start }],
      ['calendar.createEvent', { subject: 'Bad', ...dates, start: { dateTime: '2026-02-31T09:00:00', timeZone: 'UTC' } }],
      ['calendar.updateEvent', { eventId: 'e' }],
      ['mail.mark', { messageId: 'm' }],
      ['mail.read', { messageId: '../users/other' }],
      ['mail.send', { subject: 'X', text: 'x', to: ['bad\r\nBcc:x@example.com'] }],
      ['mail.move', { messageId: 'm', folderId: 'drafts' }],
      ['mail.attachment', { messageId: 'm', attachmentId: 'a', maxBytes: 11 * 1024 * 1024 }],
    ] as const) {
      const f = fixture(); await expect(run(name, args, f.ctx)).rejects.toThrow(); expect(f.calls).toHaveLength(0);
    }
  });
  it('normalizes profiles whose provider identity includes a tenant suffix', async () => {
    const f = fixture([{ Id: `${identity.objectId}@${identity.tenantId}`, EmailAddress: 'self@example.com', DisplayName: 'Self', MailboxGuid: 'mailbox', Unexpected: 'hidden' }]);
    const me = await run('mail.profile', {}, f.ctx);
    expect(me).toMatchObject({ id: `${identity.objectId}@${identity.tenantId}`, email: 'self@example.com', mailboxId: 'mailbox' });
    expect(me).not.toHaveProperty('Unexpected');
  });
  it('retains the created reply draft id when a later write fails', async () => {
    const f = fixture([{ Id: 'created-draft' }, new Error('transport lost')]);
    await expect(run('mail.createDraft', { sourceMessageId: 'original', subject: 'Reply', text: 'Hello', to: ['to@example.com'] }, f.ctx)).rejects.toMatchObject({ code: 'partial_write', message: expect.stringContaining('created-draft') });
    expect(f.calls).toHaveLength(2);
  });
  it('bounds attachment page requests even when Outlook returns empty pages with next links', async () => {
    const f = fixture();
    f.ctx.request = async (request) => {
      f.calls.push(request);
      let value: unknown = { ...mail, HasAttachments: true };
      if (request.path.endsWith('/attachments')) {
        const u = new URL(ORIGIN + request.path);
        Object.entries(request.query ?? {}).forEach(([k, v]) => u.searchParams.set(k, v)); u.searchParams.set('$skip', String(f.calls.length));
        value = { value: [], '@odata.nextLink': u.href };
        if (f.calls.length > 6) throw new Error('unbounded pagination');
      }
      return { status: 200, headers: {}, body: Buffer.from(JSON.stringify(value)) };
    };
    await expect(run('mail.read', { messageId: 'm' }, f.ctx)).rejects.toMatchObject({ code: 'response_too_large' });
    expect(f.calls.length).toBeLessThanOrEqual(5);
  });
  it('checks existing all-day times before an update can create a malformed all-day event', async () => {
    const f = fixture([{ Id: 'e', Type: 'SingleInstance', IsOrganizer: true, Attendees: [], IsAllDay: false, Start: { DateTime: dates.start.dateTime, TimeZone: dates.start.timeZone }, End: { DateTime: dates.end.dateTime, TimeZone: dates.end.timeZone } }]);
    await expect(run('calendar.updateEvent', { eventId: 'e', isAllDay: true }, f.ctx)).rejects.toThrow(/midnight/i);
    expect(f.calls).toHaveLength(1);
  });
  it('creates events only after explicit invitation permission and sends the exact timezone', async () => {
    const f = fixture([{ Id: 'created', Type: 'SingleInstance', Subject: 'Meet' }], true);
    await run('calendar.createEvent', { subject: 'Meet', ...dates, attendees: [{ email: 'to@example.com', type: 'optional' }], teamsMeeting: true }, f.ctx);
    expect(f.calls[0]).toMatchObject({ method: 'POST', path: '/api/v2.0/me/events', body: { Start: { DateTime: dates.start.dateTime, TimeZone: dates.start.timeZone }, Attendees: [{ Type: 'Optional', EmailAddress: { Address: 'to@example.com' } }], IsOnlineMeeting: true, OnlineMeetingProvider: 'TeamsForBusiness' } });
  });
  it('validates megabyte attachments without recursive-regex stack exhaustion', async () => {
    const bytes = Buffer.alloc(1024 * 1024, 97).toString('base64');
    const f = fixture([{ Id: 'draft' }]);
    await expect(run('mail.createDraft', { subject: 'File', text: '', to: ['to@example.com'], attachments: [{ filename: 'a.bin', contentType: 'application/octet-stream', contentBase64: bytes }] }, f.ctx)).resolves.toMatchObject({ draftId: 'draft' });
  });
  it('preserves cc-only and bcc-only sends while rejecting messages with no recipients', async () => {
    const f = fixture([{}]);
    await expect(run('mail.send', { subject: 'Private', text: 'Hello', to: [], bcc: ['private@example.com'] }, f.ctx)).resolves.toMatchObject({ status: 'accepted' });
    expect(f.calls[0]!.body).toMatchObject({ Message: { ToRecipients: [], BccRecipients: [{ EmailAddress: { Address: 'private@example.com' } }] } });
    await expect(run('mail.send', { subject: 'Nobody', text: '', to: [] }, fixture().ctx)).rejects.toThrow(/recipient/i);
  });
  it('rejects attachments exceeding the browser response budget before requesting bytes', async () => {
    const f = fixture([{ Id: 'a', Size: 8 * 1024 * 1024 }]);
    await expect(run('mail.attachment', { messageId: 'm', attachmentId: 'a', maxBytes: 10 * 1024 * 1024 }, f.ctx)).rejects.toThrow(/large/i);
    expect(f.calls).toHaveLength(1);
  });
});
