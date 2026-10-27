/**
 * MOCK Slack Web API (in-memory fake of the methods Perch uses) for tests only.
 * Nothing here talks to Slack; passing tests are NOT evidence of a live integration.
 */
import type { UpstreamRequest, UpstreamResponse, UpstreamTransport } from '../../src/upstream.js';
import { dummySecret } from './fixtures.js';

export interface MockSlackMessage {
  ts: string;
  user?: string;
  text: string;
  thread_ts?: string;
  reply_count?: number;
  files?: Array<{ name: string; mimetype: string; size: number }>;
}

export interface MockSlackChannel {
  id: string;
  name?: string;
  user?: string;
  kind: 'public_channel' | 'private_channel' | 'mpim' | 'im';
  messages: MockSlackMessage[];
  replies?: Record<string, MockSlackMessage[]>;
  /** DMs / group DMs opened by conversations.open: the other members. */
  members?: string[];
}

export interface MockSlackTeam {
  token: string;
  /** Session mode (browser session): the `d` cookie value (URL-encoded) every request must carry. */
  cookie?: string;
  /** Session mode: the session was signed out / expired (every call answers invalid_auth). */
  expired?: boolean;
  teamId: string;
  team: string;
  userId: string;
  user: string;
  scopes: string[];
  users: Record<string, string>;
  channels: MockSlackChannel[];
  posted: Array<{ channel: string; text: string; thread_ts?: string; reply_broadcast?: boolean }>;
  reactions: Array<{ channel: string; ts: string; name: string }>;
  edits: Array<{ channel: string; ts: string; text: string }>;
  files: MockSlackFile[];
  /** Scheduled, not yet posted messages (chat.scheduleMessage / chat.deleteScheduledMessage). */
  scheduled: MockSlackScheduled[];
}

export interface MockSlackScheduled {
  id: string;
  channel: string;
  text: string;
  post_at: number;
  thread_ts?: string;
  date_created: number;
}

export interface MockSlackFile {
  id: string;
  name: string;
  title?: string;
  mimetype: string;
  content?: Buffer;
  /** Set by files.completeUploadExternal. */
  shared?: { channel_id: string; thread_ts?: string; initial_comment?: string };
  /** Overrides the url_private_download announced by files.info (hostile-URL tests). */
  downloadUrl?: string;
  is_external?: boolean;
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}): UpstreamResponse => ({
  status,
  headers: { 'content-type': 'application/json', ...headers },
  body: Buffer.from(JSON.stringify(body)),
});

let tsCounter = 0;
export const mockTs = () => `${1_760_000_000 + ++tsCounter}.000${String(100 + (tsCounter % 900)).padStart(3, '0')}`;

export class MockSlack {
  readonly calls: UpstreamRequest[] = [];
  readonly teams: MockSlackTeam[] = [];
  /** Next requests answer HTTP 429 with this Retry-After. */
  rateLimitQueue: string[] = [];
  /** chat.postMessage behaviour: ok, a Slack error code, an HTTP status, or a thrown transport error. */
  postMode: { kind: 'ok' } | { kind: 'error'; code: string } | { kind: 'http'; status: number } | { kind: 'throw' } = { kind: 'ok' };
  /** files.completeUploadExternal behaviour (same shapes as postMode). */
  completeMode: { kind: 'ok' } | { kind: 'error'; code: string } | { kind: 'http'; status: number } | { kind: 'throw' } = { kind: 'ok' };
  /** chat.scheduleMessage behaviour (same shapes as postMode). */
  scheduleMode: { kind: 'ok' } | { kind: 'error'; code: string } | { kind: 'http'; status: number } | { kind: 'throw' } = { kind: 'ok' };
  /** Clock of the mock (seconds); tests may move it. */
  nowSeconds: () => number = () => Math.floor(Date.now() / 1000);
  /** Overrides the upload_url returned by files.getUploadURLExternal (hostile-URL tests). */
  uploadUrlOverride?: string;
  /** Upload URLs handed out and not yet used: path -> (team, file id, announced length). */
  private readonly uploads = new Map<string, { team: MockSlackTeam; fileId: string; length: number; filename: string }>();
  private teamCounter = 0;
  private fileCounter = 0;
  private convCounter = 0;
  private scheduleCounter = 0;

  addTeam(name: string, opts: { scopes?: string[]; session?: boolean } = {}): MockSlackTeam {
    this.teamCounter++;
    const n = this.teamCounter;
    const secret = () => dummySecret('SLACK').replace(/[^A-Za-z0-9-]/g, '');
    const team: MockSlackTeam = {
      token: `${opts.session ? 'xoxc' : 'xoxp'}-${secret()}`,
      // Like the browser shows it: base64 with '/', '+' and '=' URL-encoded.
      ...(opts.session ? { cookie: `xoxd-${secret()}%2F${secret()}%2B${secret()}%3D%3D` } : {}),
      teamId: `T0MOCK${n}`,
      team: `Mock team ${name}`,
      userId: `U0ME${n}`,
      user: `me${n}`,
      scopes: opts.scopes ?? ['channels:read', 'channels:history', 'groups:read', 'groups:history', 'im:read', 'im:history', 'mpim:read', 'mpim:history', 'users:read', 'search:read', 'chat:write', 'reactions:read', 'reactions:write', 'files:read', 'files:write', 'im:write', 'mpim:write'],
      users: {},
      channels: [],
      posted: [],
      reactions: [],
      edits: [],
      files: [],
      scheduled: [],
    };
    this.teams.push(team);
    return team;
  }

  /** The team a request authenticates as: bearer token, and for session teams the exact `d` cookie. */
  private authed(req: UpstreamRequest): MockSlackTeam | undefined {
    const token = (req.headers.authorization ?? '').replace(/^Bearer /, '');
    const team = this.teams.find((t) => t.token === token);
    if (!team) return undefined;
    if (team.cookie !== undefined && (team.expired || req.headers.cookie !== `d=${team.cookie}`)) return undefined;
    if (team.cookie === undefined && req.headers.cookie !== undefined) return undefined;
    return team;
  }

  private filesHost(req: UpstreamRequest): UpstreamResponse {
    const path = req.url.pathname;
    if (req.method === 'POST' && path.startsWith('/upload/v1/')) {
      const up = this.uploads.get(path);
      if (!up) return { status: 404, headers: {}, body: Buffer.from('not found') };
      this.uploads.delete(path);
      const data = req.bodyBytes ?? Buffer.alloc(0);
      if (data.length !== up.length) return { status: 400, headers: {}, body: Buffer.from('length mismatch') };
      up.team.files.push({ id: up.fileId, name: up.filename, mimetype: 'application/octet-stream', content: data });
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from(`OK - ${data.length}`) };
    }
    const m = /^\/files-pri\/([A-Z0-9]+)-(F[A-Z0-9]+)\//.exec(path);
    if (req.method === 'GET' && m) {
      const t = this.authed(req);
      const team = t && t.teamId === m[1] ? t : undefined;
      const file = team?.files.find((f) => f.id === m[2]);
      // Slack answers an unauthenticated download with its HTML login page (HTTP 200).
      if (!file?.content) return { status: 200, headers: { 'content-type': 'text/html' }, body: Buffer.from('<html>login</html>') };
      return { status: 200, headers: { 'content-type': file.mimetype }, body: file.content };
    }
    return { status: 404, headers: {}, body: Buffer.from('not found') };
  }

  readonly transport: UpstreamTransport = async (req) => {
    this.calls.push(req);
    if (req.url.origin === 'https://files.slack.com') return this.filesHost(req);
    if (req.url.origin !== 'https://slack.com') throw new Error(`MOCK Slack: unexpected origin ${req.url.origin}`);
    if (this.rateLimitQueue.length) return json(429, { ok: false, error: 'ratelimited' }, { 'retry-after': this.rateLimitQueue.shift()! });
    const team = this.authed(req);
    if (!team) return json(200, { ok: false, error: 'invalid_auth' });
    const q = req.url.searchParams;
    const method = req.url.pathname.replace('/api/', '');
    switch (method) {
      case 'auth.test':
        return json(
          200,
          { ok: true, url: `https://mock-${team.teamId.toLowerCase()}.slack.example/`, team: team.team, user: team.user, team_id: team.teamId, user_id: team.userId },
          // Session tokens report no scopes.
          team.cookie === undefined ? { 'x-oauth-scopes': team.scopes.join(',') } : {},
        );
      case 'conversations.list': {
        const types = (q.get('types') ?? '').split(',');
        const all = team.channels.filter((c) => types.includes(c.kind));
        const start = Number(q.get('cursor') ?? 0);
        const limit = Number(q.get('limit') ?? 100);
        const page = all.slice(start, start + limit);
        const next = start + limit < all.length ? String(start + limit) : '';
        return json(200, {
          ok: true,
          channels: page.map((c) => ({
            id: c.id,
            ...(c.name ? { name: c.name } : {}),
            ...(c.user ? { user: c.user } : {}),
            is_im: c.kind === 'im',
            is_mpim: c.kind === 'mpim',
            is_private: c.kind === 'private_channel',
            is_member: true,
          })),
          response_metadata: { next_cursor: next },
        });
      }
      case 'conversations.history': {
        const ch = team.channels.find((c) => c.id === q.get('channel'));
        if (!ch) return json(200, { ok: false, error: 'channel_not_found' });
        const oldest = Number(q.get('oldest') ?? 0);
        const latest = Number(q.get('latest') ?? Infinity);
        const msgs = ch.messages.filter((m) => Number(m.ts) > oldest && Number(m.ts) < latest).sort((a, b) => Number(b.ts) - Number(a.ts));
        const start = Number(q.get('cursor') ?? 0);
        const limit = Number(q.get('limit') ?? 100);
        const next = start + limit < msgs.length ? String(start + limit) : '';
        return json(200, { ok: true, messages: msgs.slice(start, start + limit), has_more: Boolean(next), response_metadata: { next_cursor: next } });
      }
      case 'conversations.replies': {
        const ch = team.channels.find((c) => c.id === q.get('channel'));
        const replies = ch?.replies?.[q.get('ts') ?? ''];
        if (!replies) return json(200, { ok: false, error: 'thread_not_found' });
        return json(200, { ok: true, messages: replies, response_metadata: { next_cursor: '' } });
      }
      case 'users.info': {
        const name = team.users[q.get('user') ?? ''];
        if (!name) return json(200, { ok: false, error: 'user_not_found' });
        return json(200, { ok: true, user: { id: q.get('user'), name: name.toLowerCase(), profile: { real_name: name, display_name: '' } } });
      }
      case 'search.messages': {
        if (!team.scopes.includes('search:read')) return json(200, { ok: false, error: 'missing_scope' });
        const needle = (q.get('query') ?? '').toLowerCase();
        const matches = team.channels.flatMap((c) =>
          c.messages
            .filter((m) => m.text.toLowerCase().includes(needle))
            .map((m) => ({ ...m, channel: { id: c.id, name: c.name ?? c.id }, username: m.user ? team.users[m.user]?.toLowerCase() : undefined, permalink: `https://mock.slack.example/${c.id}/${m.ts}` })),
        );
        const count = Number(q.get('count') ?? 20);
        const page = Number(q.get('page') ?? 1);
        return json(200, {
          ok: true,
          messages: { matches: matches.slice((page - 1) * count, page * count), paging: { page, pages: Math.max(1, Math.ceil(matches.length / count)) } },
        });
      }
      case 'chat.postMessage': {
        if (req.method !== 'POST') return json(405, { ok: false, error: 'method_not_allowed' });
        if (this.postMode.kind === 'throw') throw new Error('MOCK: connection reset after send');
        if (this.postMode.kind === 'http') return json(this.postMode.status, { ok: false });
        if (this.postMode.kind === 'error') return json(200, { ok: false, error: this.postMode.code });
        const body = JSON.parse(req.body ?? '{}') as { channel: string; text: string; thread_ts?: string; reply_broadcast?: boolean };
        if (!team.channels.some((c) => c.id === body.channel)) return json(200, { ok: false, error: 'channel_not_found' });
        team.posted.push(body);
        return json(200, { ok: true, channel: body.channel, ts: mockTs() });
      }
      case 'reactions.add':
      case 'reactions.remove': {
        if (req.method !== 'POST') return json(405, { ok: false, error: 'method_not_allowed' });
        if (!team.scopes.includes('reactions:write')) return json(200, { ok: false, error: 'missing_scope' });
        const f = new URLSearchParams(req.body ?? '');
        const r = { channel: f.get('channel') ?? '', ts: f.get('timestamp') ?? '', name: f.get('name') ?? '' };
        const ch = team.channels.find((c) => c.id === r.channel);
        if (!ch) return json(200, { ok: false, error: 'channel_not_found' });
        if (!ch.messages.some((m) => m.ts === r.ts)) return json(200, { ok: false, error: 'message_not_found' });
        const i = team.reactions.findIndex((x) => x.channel === r.channel && x.ts === r.ts && x.name === r.name);
        if (method === 'reactions.add') {
          if (i >= 0) return json(200, { ok: false, error: 'already_reacted' });
          team.reactions.push(r);
        } else {
          if (i < 0) return json(200, { ok: false, error: 'no_reaction' });
          team.reactions.splice(i, 1);
        }
        return json(200, { ok: true });
      }
      case 'chat.update': {
        if (req.method !== 'POST') return json(405, { ok: false, error: 'method_not_allowed' });
        const body = JSON.parse(req.body ?? '{}') as { channel: string; ts: string; text: string };
        const ch = team.channels.find((c) => c.id === body.channel);
        const msg = ch?.messages.find((m) => m.ts === body.ts);
        if (!msg) return json(200, { ok: false, error: 'message_not_found' });
        if (msg.user !== team.userId) return json(200, { ok: false, error: 'cant_update_message' });
        msg.text = body.text;
        team.edits.push(body);
        return json(200, { ok: true, channel: body.channel, ts: body.ts, text: body.text });
      }
      case 'files.getUploadURLExternal': {
        if (req.method !== 'POST') return json(405, { ok: false, error: 'method_not_allowed' });
        if (!team.scopes.includes('files:write')) return json(200, { ok: false, error: 'missing_scope' });
        const f = new URLSearchParams(req.body ?? '');
        const n = ++this.fileCounter;
        const fileId = `F0MOCK${n}`;
        const path = `/upload/v1/MOCKUPLOAD${n}_x-Y`;
        this.uploads.set(path, { team, fileId, length: Number(f.get('length')), filename: f.get('filename') ?? '' });
        return json(200, { ok: true, upload_url: this.uploadUrlOverride ?? `https://files.slack.com${path}`, file_id: fileId });
      }
      case 'files.completeUploadExternal': {
        if (req.method !== 'POST') return json(405, { ok: false, error: 'method_not_allowed' });
        if (this.completeMode.kind === 'throw') throw new Error('MOCK: connection reset after complete');
        if (this.completeMode.kind === 'http') return json(this.completeMode.status, { ok: false });
        if (this.completeMode.kind === 'error') return json(200, { ok: false, error: this.completeMode.code });
        const f = new URLSearchParams(req.body ?? '');
        const files = JSON.parse(f.get('files') ?? '[]') as Array<{ id: string; title?: string }>;
        const channel = f.get('channel_id') ?? '';
        if (!team.channels.some((c) => c.id === channel)) return json(200, { ok: false, error: 'channel_not_found' });
        for (const { id, title } of files) {
          const file = team.files.find((x) => x.id === id);
          if (!file) return json(200, { ok: false, error: 'file_not_found' });
          file.title = title;
          file.shared = { channel_id: channel, ...(f.get('thread_ts') ? { thread_ts: f.get('thread_ts')! } : {}), ...(f.get('initial_comment') ? { initial_comment: f.get('initial_comment')! } : {}) };
        }
        return json(200, { ok: true, files: files.map((x) => ({ id: x.id })) });
      }
      case 'files.info': {
        if (!team.scopes.includes('files:read')) return json(200, { ok: false, error: 'missing_scope' });
        const file = team.files.find((x) => x.id === q.get('file'));
        if (!file) return json(200, { ok: false, error: 'file_not_found' });
        return json(200, {
          ok: true,
          file: {
            id: file.id,
            name: file.name,
            title: file.title ?? file.name,
            mimetype: file.mimetype,
            filetype: 'binary',
            size: file.content?.length ?? 0,
            created: 1_760_000_000,
            user: team.userId,
            is_external: file.is_external ?? false,
            url_private: `https://files.slack.com/files-pri/${team.teamId}-${file.id}/${encodeURIComponent(file.name)}`,
            url_private_download: file.downloadUrl ?? `https://files.slack.com/files-pri/${team.teamId}-${file.id}/download/${encodeURIComponent(file.name)}`,
            permalink: `https://mock.slack.example/files/${file.id}`,
          },
        });
      }
      case 'conversations.open': {
        if (req.method !== 'POST') return json(405, { ok: false, error: 'method_not_allowed' });
        const users = (new URLSearchParams(req.body ?? '').get('users') ?? '').split(',').filter(Boolean);
        if (!users.length) return json(200, { ok: false, error: 'users_list_not_supplied' });
        if (users.length > 8) return json(200, { ok: false, error: 'too_many_users' });
        if (!team.scopes.includes(users.length > 1 ? 'mpim:write' : 'im:write')) return json(200, { ok: false, error: 'missing_scope' });
        if (users.some((u) => u !== team.userId && !team.users[u])) return json(200, { ok: false, error: 'user_not_found' });
        const key = [...users].sort().join(',');
        const kind = users.length > 1 ? 'mpim' : 'im';
        const existing = team.channels.find((c) => c.kind === kind && c.members && [...c.members].sort().join(',') === key);
        if (existing) return json(200, { ok: true, no_op: true, already_open: true, channel: { id: existing.id } });
        const id = `${kind === 'im' ? 'D' : 'G'}0OPEN${++this.convCounter}`;
        team.channels.push({ id, kind, members: users, ...(kind === 'im' ? { user: users[0] } : { name: `mpdm-${key}` }), messages: [] });
        return json(200, { ok: true, channel: { id } });
      }
      case 'chat.scheduleMessage': {
        if (req.method !== 'POST') return json(405, { ok: false, error: 'method_not_allowed' });
        if (this.scheduleMode.kind === 'throw') throw new Error('MOCK: connection reset after schedule');
        if (this.scheduleMode.kind === 'http') return json(this.scheduleMode.status, { ok: false });
        if (this.scheduleMode.kind === 'error') return json(200, { ok: false, error: this.scheduleMode.code });
        const f = new URLSearchParams(req.body ?? '');
        const channel = f.get('channel') ?? '';
        const postAt = Number(f.get('post_at'));
        if (!team.channels.some((c) => c.id === channel)) return json(200, { ok: false, error: 'channel_not_found' });
        const now = this.nowSeconds();
        if (!(postAt > now)) return json(200, { ok: false, error: 'time_in_past' });
        if (postAt > now + 120 * 86_400) return json(200, { ok: false, error: 'time_too_far' });
        const id = `Q0MOCK${++this.scheduleCounter}`;
        team.scheduled.push({ id, channel, text: f.get('text') ?? '', post_at: postAt, date_created: now, ...(f.get('thread_ts') ? { thread_ts: f.get('thread_ts')! } : {}) });
        return json(200, { ok: true, channel, scheduled_message_id: id, post_at: postAt });
      }
      case 'chat.scheduledMessages.list': {
        const channel = q.get('channel');
        const all = team.scheduled.filter((m) => !channel || m.channel === channel).sort((a, b) => a.post_at - b.post_at);
        const start = Number(q.get('cursor') ?? 0);
        const limit = Number(q.get('limit') ?? 100);
        const next = start + limit < all.length ? String(start + limit) : '';
        return json(200, {
          ok: true,
          scheduled_messages: all.slice(start, start + limit).map((m) => ({ id: m.id, channel_id: m.channel, post_at: m.post_at, date_created: m.date_created, text: m.text })),
          response_metadata: { next_cursor: next },
        });
      }
      case 'chat.deleteScheduledMessage': {
        if (req.method !== 'POST') return json(405, { ok: false, error: 'method_not_allowed' });
        const f = new URLSearchParams(req.body ?? '');
        const i = team.scheduled.findIndex((m) => m.id === f.get('scheduled_message_id') && m.channel === f.get('channel'));
        if (i < 0) return json(200, { ok: false, error: 'invalid_scheduled_message_id' });
        team.scheduled.splice(i, 1);
        return json(200, { ok: true });
      }
      default:
        return json(404, { ok: false, error: 'unknown_method' });
    }
  };
}
