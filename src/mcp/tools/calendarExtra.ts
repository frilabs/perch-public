import { z } from 'zod';
import { RESPONSES, SEND_UPDATES } from '../../google/calendarWrite.js';
import { DESTRUCTIVE, type ToolModule } from './kit.js';

/**
 * Calendar: permanent delete and answering invitations (docs/MAIL_CALENDAR_SLACK_SPEC.md §2). Only for client
 * grants (never the global token). Delete needs calendar_write and calendar_read (plus calendar_invite for
 * events with guests, checked by the service); respond needs calendar_invite and calendar_read. Single
 * occurrences of a series are refused; a series is deleted or answered as a whole via its series id.
 */

const WRITES = ['calendar_delete_event', 'calendar_respond_event'] as const;

const accountId = z.string().max(64).describe('Google Calendar/Contacts account id from perch_list_accounts, e.g. gprod-1a2b3c4d');
const calendarId = z.string().max(255).describe('Calendar id from calendar_list_calendars, or "primary"');
const eventId = z
  .string()
  .max(1100)
  .describe('Event id or series id. Occurrence ids (with "_<date>" suffix) are refused: use the recurringEventId of the occurrence for the whole series');
const etag = z.string().max(210).describe('Optional etag from calendar_get_event/calendar_list_events: refuse if the event changed since');
const sendUpdates = z.enum(SEND_UPDATES).optional();
const CONFIRM = 'Only act after the user explicitly confirmed this exact action.';

export const calendarExtraTools: ToolModule = {
  readTools: [],
  writeTools: [...WRITES],
  selfAudited: [],
  auditedWrites: [...WRITES],
  register(server, ctx, principal, _operator, tool) {
    if (principal.kind !== 'client' || !principal.capabilities.has('calendar_read')) return;
    if (principal.capabilities.has('calendar_write')) {
      server.registerTool(
        'calendar_delete_event',
        {
          description:
            'PERMANENTLY delete an event you organise, or a whole recurring series when given the series id. This is not a trash: it ' +
            'cannot be undone. Single occurrences are not supported. Events with guests need calendar_invite (also with sendUpdates none); Google then emails ' +
            `cancellations according to sendUpdates (default all; none = silently). ${CONFIRM} ` +
            'Outcomes: "deleted", "not_found" (already gone or cancelled), "precondition_failed" (etag stale), "rejected", "indeterminate" (unknown; never retried).',
          inputSchema: {
            accountId,
            calendarId,
            eventId,
            etag: etag.optional(),
            sendUpdates: sendUpdates.describe('Cancellation emails for events with guests: all (default), externalOnly or none'),
          },
          annotations: DESTRUCTIVE,
        },
        (a) => tool('calendar_delete_event', a, (p) => ctx.calendar.deleteEvent(p, a)),
      );
    }
    if (principal.capabilities.has('calendar_invite')) {
      server.registerTool(
        'calendar_respond_event',
        {
          description:
            'Answer an invitation (accepted, declined or tentative) for your own guest entry on an event someone else organizes (events you ' +
            'organize are refused: change them with calendar_update_event); for a recurring series, the series id answers ' +
            'every occurrence (single occurrences are not supported). Google notifies the organizer according to sendUpdates (default all). ' +
            `${CONFIRM} Outcomes: "responded", "precondition_failed", "rejected", "indeterminate" (unknown; never retried).`,
          inputSchema: {
            accountId,
            calendarId,
            eventId,
            response: z.enum(RESPONSES),
            etag: etag.optional(),
            sendUpdates: sendUpdates.describe('Notify the organizer: all (default), externalOnly or none'),
          },
          annotations: DESTRUCTIVE,
        },
        (a) => tool('calendar_respond_event', a, (p) => ctx.calendar.respondEvent(p, a)),
      );
    }
  },
};
