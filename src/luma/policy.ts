import { createHash } from 'node:crypto';
import type { LumaCapability } from '../store/credentialStore.js';

/**
 * Which tools of the official Luma MCP server Perch passes through, and to whom (docs/LUMA_SPEC.md §5).
 * Every other Luma tool (delete/remove, admins, hosts, memberships, contact import, calendars, coupons,
 * people search, profile, feedback, ...) stays hidden. `props` are the input fields Perch knows for the tool:
 * a live schema with any other top-level field is a changed tool and is blocked until reviewed.
 */
export type LumaGroup = 'read' | 'events' | 'guests' | 'blast';

export const GROUP_CAPABILITY: Record<LumaGroup, LumaCapability> = {
  read: 'luma_read',
  events: 'luma_events',
  guests: 'luma_guests',
  blast: 'luma_blast',
};

export interface LumaToolPolicy {
  group: LumaGroup;
  props: readonly string[];
}

const EVENT_FIELDS = [
  'can_register_for_multiple_tickets',
  'cover_url',
  'create_meeting',
  'description_md',
  'end_at',
  // Added by Luma (live 2026-10-27): post-event feedback e-mail to guests; enabled: true needs luma_guests.
  'feedback_email',
  'font',
  'geo_address_json',
  'location_visibility',
  'max_capacity',
  'meeting_url',
  'name',
  'name_requirement',
  'phone_number_requirement',
  'registration_open',
  'show_guest_list',
  'slug',
  'start_at',
  'theme',
  'timezone',
  'tint_color',
  'visibility',
  'waitlist_status',
] as const;
const PAGE = ['cursor', 'limit'] as const;

export const LUMA_TOOLS: Readonly<Record<string, LumaToolPolicy>> = Object.freeze({
  // --- read
  get_self: { group: 'read', props: [] },
  list_calendars: { group: 'read', props: [] },
  get_calendar: { group: 'read', props: ['calendar_id'] },
  list_events: { group: 'read', props: ['after', 'before', ...PAGE, 'period', 'status'] },
  list_calendar_events: { group: 'read', props: ['after', 'before', 'calendar_id', ...PAGE, 'period', 'status'] },
  get_event: { group: 'read', props: ['event_id'] },
  search_events: { group: 'read', props: ['after', 'before', 'latitude', 'location', 'longitude', 'query'] },
  list_guests: { group: 'read', props: ['approval_status', ...PAGE, 'event_id', 'query'] },
  get_guest: { group: 'read', props: ['event_id', 'id'] },
  list_blasts: { group: 'read', props: ['event_id'] },
  list_coupons: { group: 'read', props: ['calendar_id', ...PAGE, 'event_id'] },
  list_membership_tiers: { group: 'read', props: ['calendar_id', ...PAGE] },
  list_calendar_contacts: {
    group: 'read',
    props: ['calendar_id', 'calendar_membership_tier_id', ...PAGE, 'membership_status', 'query', 'sort_column', 'tags'],
  },
  list_calendar_contact_tags: { group: 'read', props: ['calendar_id'] },
  list_calendar_event_tags: { group: 'read', props: ['calendar_id'] },
  list_pending_calendar_events: { group: 'read', props: [...PAGE, 'organization_id'] },
  list_organizations: { group: 'read', props: [] },
  list_organization_calendars: { group: 'read', props: [...PAGE, 'organization_id'] },
  lookup_entity: { group: 'read', props: ['slug'] },
  // --- events
  create_event: { group: 'events', props: ['calendar_id', ...EVENT_FIELDS, 'registration_questions', 'ticket_types'] },
  update_event: { group: 'events', props: ['event_id', ...EVENT_FIELDS, 'email_guests', 'tax_config'] },
  create_ticket_type: {
    group: 'events',
    props: ['cents', 'currency', 'description', 'event_id', 'is_flexible', 'is_hidden', 'max_capacity', 'min_cents', 'name', 'require_approval', 'type', 'valid_end_at', 'valid_start_at'],
  },
  add_registration_question: { group: 'events', props: ['event_id', 'question'] },
  update_registration_question: {
    group: 'events',
    props: ['collect_job_title', 'event_id', 'job_title_label', 'label', 'multiline', 'multiple', 'options', 'question_id', 'required', 'terms'],
  },
  reorder_registration_questions: { group: 'events', props: ['event_id', 'question_ids'] },
  add_calendar_event: { group: 'events', props: ['calendar_id', 'event'] },
  approve_calendar_events: { group: 'events', props: ['calendar_event_ids', 'calendar_id'] },
  reject_calendar_events: { group: 'events', props: ['calendar_event_ids', 'calendar_id', 'message', 'notify_submitter'] },
  apply_calendar_event_tag: { group: 'events', props: ['calendar_id', 'event_ids', 'tag'] },
  unapply_calendar_event_tag: { group: 'events', props: ['calendar_id', 'event_ids', 'tag'] },
  // --- guests (e-mails third parties)
  invite_guests: { group: 'guests', props: ['event_id', 'guests', 'message'] },
  update_guest_status: { group: 'guests', props: ['event_id', 'guest_id', 'message', 'send_email', 'should_refund', 'status'] },
  update_guest_tickets: { group: 'guests', props: ['event_id', 'guest_id', 'send_email', 'ticket_ids_to_remove', 'tickets_to_add'] },
  // --- blast (mass e-mail, cannot be recalled)
  create_blast: { group: 'blast', props: ['content_md', 'event_id', 'recipient_groups', 'scheduled_for', 'subject'] },
});

/** Perch's own limit for invitations per call (Luma allows 100; Perch limit: 50). */
export const MAX_INVITES_PER_CALL = 50;

/** The MCP tool name Perch exposes for a Luma tool. */
export const perchToolName = (lumaName: string) => `luma_${lumaName}`;

/**
 * Additional capability a concrete call needs, or a refusal (checked before any request to Luma):
 * - create_event/update_event with feedback_email.enabled: true and update_event with email_guests: true, approve_calendar_events and reject_calendar_events with a
 *   notification e-mail third parties: they also need luma_guests;
 * - create_blast only immediately (scheduled blasts would be counted now but sent later);
 * - update_guest_status never refunds payments through Perch;
 * - invite_guests at most MAX_INVITES_PER_CALL addresses per call.
 */
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export function callRules(name: string, args: Record<string, unknown>): { alsoNeeds?: LumaCapability; refuse?: string } {
  if (name === 'update_event' && args.email_guests === true) return { alsoNeeds: 'luma_guests' };
  // feedback_email.enabled: true makes Luma e-mail every guest after the event: e-mail to third parties.
  if ((name === 'create_event' || name === 'update_event') && isRecord(args.feedback_email) && args.feedback_email.enabled === true) {
    return { alsoNeeds: 'luma_guests' };
  }
  // Approving always notifies the submitter; rejecting does when asked to: e-mail to third parties.
  if (name === 'approve_calendar_events') return { alsoNeeds: 'luma_guests' };
  if (name === 'reject_calendar_events' && (args.notify_submitter === true || args.message !== undefined)) return { alsoNeeds: 'luma_guests' };
  if (name === 'create_blast' && args.scheduled_for !== undefined) return { refuse: 'Perch sends blasts only immediately (the recipient count is checked now); schedule blasts in Luma itself' };
  if (name === 'update_guest_status' && args.should_refund === true) return { refuse: 'Perch never refunds payments; do that in Luma itself (should_refund must be false or omitted)' };
  if (name === 'invite_guests' && Array.isArray(args.guests) && args.guests.length > MAX_INVITES_PER_CALL) {
    return { refuse: `At most ${MAX_INVITES_PER_CALL} guests per invite_guests call` };
  }
  return {};
}

/** Keys that never change what a call does (documentation only): ignored by the structural hash. */
const DOC_KEYS = new Set(['description', 'title', '$schema', 'examples', '$comment']);

/** Schema keywords whose values are maps of NAME -> schema (names are data, never documentation keys). */
const MAP_KEYWORDS = new Set(['properties', 'patternProperties', 'definitions', '$defs', 'dependentSchemas']);

/** Canonical JSON of a schema without documentation keywords, keys sorted (structural pin). */
export function canonicalSchema(v: unknown, isMap = false): unknown {
  if (Array.isArray(v)) return v.map((x) => canonicalSchema(x));
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) {
      if (isMap) out[k] = canonicalSchema(o[k]); // a property named "description" is a field, not documentation
      else if (!DOC_KEYS.has(k)) out[k] = canonicalSchema(o[k], MAP_KEYWORDS.has(k));
    }
    return out;
  }
  return v;
}

export const schemaHash = (schema: unknown) => createHash('sha256').update(JSON.stringify(canonicalSchema(schema))).digest('hex');

/** Top-level input fields of a live schema that Perch does not know for this tool (empty = acceptable). */
export function unknownProps(name: string, schema: unknown): string[] {
  const policy = LUMA_TOOLS[name];
  if (!policy) return ['(tool not allowed)'];
  const props = schema && typeof schema === 'object' ? (schema as { properties?: Record<string, unknown> }).properties : undefined;
  if (props !== undefined && (typeof props !== 'object' || props === null)) return ['(malformed schema)'];
  return Object.keys(props ?? {}).filter((k) => !policy.props.includes(k));
}
