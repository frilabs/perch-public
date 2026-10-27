import { describe, expect, it } from 'vitest';
import { teamsOperations } from '../src/microsoft/session/teams.js';
import type { OperationContext, SessionHttpRequest } from '../src/microsoft/session/contracts.js';

const conversationId = '19:example@thread.tacv2';
const identity = { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', kind: 'organization' as const };
function fixture(body: unknown, status = 200) {
  const requests: SessionHttpRequest[] = [];
  const ctx: OperationContext = { identity, sites: [], displayName: 'Sample User', request: async (request) => {
    requests.push(request);
    return { status, headers: {}, body: Buffer.from(JSON.stringify(body)) };
  } };
  return { ctx, requests };
}
async function run(name: string, ctx: OperationContext, args: unknown = {}): Promise<any> {
  const operation = teamsOperations[name]!;
  return operation.run(ctx, operation.schema.parse(args));
}

describe('Microsoft session Teams operations', () => {
  it('exposes only the seven bounded operations and rejects transport/credential input', () => {
    expect(Object.keys(teamsOperations).sort()).toEqual(['teams.getMessage', 'teams.getThread', 'teams.listAttachments', 'teams.listChannels', 'teams.listChats', 'teams.search', 'teams.send']);
    for (const [name, operation] of Object.entries(teamsOperations)) {
      expect(operation.service).toBe('teams');
      expect(operation.mode).toBe(name === 'teams.send' ? 'write' : 'read');
    }
    expect(() => teamsOperations['teams.listChats']!.schema.parse({ url: 'https://evil.test', token: 'secret' })).toThrow();
    expect(() => teamsOperations['teams.listChats']!.schema.parse({ limit: 201 })).toThrow();
    expect(() => teamsOperations['teams.getThread']!.schema.parse({ conversationId: '../escape' })).toThrow();
    expect(() => teamsOperations['teams.getThread']!.schema.parse({ conversationId: `${conversationId};messageid=123` })).toThrow();
  });

  it('lists chats with safe text previews and bounded output', async () => {
    const { ctx, requests } = fixture({ conversations: [{ id: '19:a_b@unq.gbl.spaces', threadProperties: { topic: 'Topic' }, lastMessage: { originalarrivaltime: '2026-10-26T10:00:00Z', imdisplayname: 'Name', content: '<b>Hello &amp; welcome</b>' } }, { id: '19:g@thread.v2' }] });
    const result = await run('teams.listChats', ctx, { limit: 1 });
    expect(result.chats).toEqual([expect.objectContaining({ conversationId: '19:a_b@unq.gbl.spaces', type: 'oneOnOne', title: 'Topic', preview: 'Hello & welcome' })]);
    expect(requests[0]).toMatchObject({ resource: 'chat', path: '/v1/users/ME/conversations', query: { view: 'msnp24Equivalent', pageSize: '1' } });
  });

  it('retains team thread and group IDs separately while paging channels', async () => {
    const { ctx, requests } = fixture({ teams: [{ id: '19:team@thread.tacv2', displayName: 'Team', channels: [{ id: conversationId, displayName: 'General', groupId: 'group-guid', channelType: 0 }, { id: '19:private@thread.tacv2', displayName: 'Private', groupId: 'group-guid', channelType: 1 }] }] });
    const first = await run('teams.listChannels', ctx, { limit: 1, teamId: '19:team@thread.tacv2' });
    expect(first.channels[0]).toMatchObject({ channelId: conversationId, teamId: '19:team@thread.tacv2', groupId: 'group-guid', type: 'standard' });
    expect(first.cursor).toEqual(expect.any(String));
    const next = await run('teams.listChannels', ctx, { limit: 1, teamId: '19:team@thread.tacv2', cursor: first.cursor });
    expect(next.channels[0].type).toBe('private');
    expect(next.cursor).toBeUndefined();
    expect(requests[0]).toMatchObject({ resource: 'csa', path: '/api/v3/teams/users/me' });
    await expect(run('teams.listChannels', ctx, { teamId: '19:other@thread.tacv2', cursor: first.cursor })).rejects.toMatchObject({ code: 'invalid_cursor' });
  });

  it('reads a thread and keeps pagination on the same conversation route', async () => {
    const { ctx, requests } = fixture({ messages: [{ id: '1760000000000', content: '<p>Reply</p>', messagetype: 'RichText/Html', from: `8:orgid:${identity.objectId}`, rootMessageId: '1750000000000' }, { id: '2', messagetype: 'Control/Test', content: 'hidden' }, { id: '3', messagetype: 'Text', properties: { deletetime: '1' } }], _metadata: { backwardLink: 'https://regional.msg.teams.microsoft.com/ignored?syncState=abc%3D&startTime=1&pageSize=200&view=other' } });
    const first = await run('teams.getThread', ctx, { conversationId, replyToMessageId: '1750000000000', limit: 20 });
    expect(first.messages).toHaveLength(1);
    expect(first.messages[0]).toMatchObject({ id: '1760000000000', text: 'Reply', rootMessageId: '1750000000000', isFromMe: true });
    await run('teams.getThread', ctx, { conversationId, replyToMessageId: '1750000000000', limit: 20, cursor: first.cursor });
    expect(requests[1]).toMatchObject({ resource: 'chat', path: `/v1/users/ME/conversations/${encodeURIComponent(`${conversationId};messageid=1750000000000`)}/messages`, query: { syncState: 'abc=', startTime: '1', pageSize: '20', view: 'msnp24Equivalent|supportsMessageProperties' } });
    await expect(run('teams.getThread', ctx, { conversationId: '19:other@thread.tacv2', cursor: first.cursor })).rejects.toMatchObject({ code: 'invalid_cursor' });
    await expect(run('teams.getThread', { ...ctx, identity: { ...identity, objectId: '33333333-3333-4333-8333-333333333333' } }, { conversationId, replyToMessageId: '1750000000000', cursor: first.cursor })).rejects.toMatchObject({ code: 'invalid_cursor' });
  });

  it('rejects cursor-supplied query keys and never accepts a URL as cursor', async () => {
    const { ctx, requests } = fixture({ messages: [] });
    await expect(run('teams.getThread', ctx, { conversationId, cursor: 'https://evil.test/?token=secret' })).rejects.toThrow();
    expect(requests).toHaveLength(0);
  });

  it('discards unknown paging fields and refuses tampered cursor keys', async () => {
    const { ctx, requests } = fixture({ messages: [], _metadata: { backwardLink: 'https://evil.test/private?syncState=continue&url=https%3A%2F%2Fevil.test&Authorization=secret' } });
    const first = await run('teams.getThread', ctx, { conversationId });
    await run('teams.getThread', ctx, { conversationId, cursor: first.cursor });
    expect(requests[1]!.query).toEqual({ syncState: 'continue', view: 'msnp24Equivalent|supportsMessageProperties', pageSize: '50' });
    const cursor = JSON.parse(Buffer.from(first.cursor, 'base64url').toString());
    cursor.value.params.url = 'https://evil.test';
    await expect(run('teams.getThread', ctx, { conversationId, cursor: Buffer.from(JSON.stringify(cursor)).toString('base64url') })).rejects.toMatchObject({ code: 'invalid_cursor' });
    expect(requests).toHaveLength(2);
  });

  it('reads a single message without exposing raw upstream fields', async () => {
    const { ctx, requests } = fixture({ id: '1234567890123', messagetype: 'Text', content: 'A < B', from: '8:orgid:other', secret: 'do not return' });
    const result = await run('teams.getMessage', ctx, { conversationId, messageId: '1234567890123' });
    expect(result).toMatchObject({ id: '1234567890123', text: 'A < B', conversationId });
    expect(JSON.stringify(result)).not.toContain('do not return');
    expect(requests[0]!.path).toBe(`/v1/users/ME/conversations/${encodeURIComponent(conversationId)}/messages/1234567890123`);
  });

  it('refuses a single-message response for a different requested message', async () => {
    const { ctx } = fixture({ id: '222', messagetype: 'Text', content: 'Wrong message' });
    await expect(run('teams.getMessage', ctx, { conversationId, messageId: '111' })).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('searches Teams messages and keeps a search result ID distinct from a server message ID', async () => {
    const { ctx, requests } = fixture({ EntitySets: [{ ResultSets: [{ Total: 2, Results: [{ Id: 'search-item', HitHighlightedSummary: '<b>Found</b>', Source: { ClientConversationId: `${conversationId};messageid=123`, MessageId: '456', From: { Name: 'Person' }, DateTimeReceived: '2026-10-26T00:00:00Z' } }] }] }] });
    const result = await run('teams.search', ctx, { query: 'budget', limit: 1 });
    expect(result.messages[0]).toMatchObject({ resultId: 'search-item', messageId: '456', conversationId, rootMessageId: '123', text: 'Found' });
    expect(result.cursor).toEqual(expect.any(String));
    expect(requests[0]).toMatchObject({ resource: 'substrate', path: '/searchservice/api/v2/query', method: 'POST', body: { entityRequests: [{ entityType: 'Message', contentSources: ['Teams'], from: 0, size: 1, query: { queryString: '(budget) AND NOT (isClientSoftDeleted:TRUE)' } }] } });
    await run('teams.search', ctx, { query: 'budget', limit: 1, cursor: result.cursor });
    expect((requests[1]!.body as any).entityRequests[0].from).toBe(1);
    await expect(run('teams.search', ctx, { query: 'other', cursor: result.cursor })).rejects.toMatchObject({ code: 'invalid_cursor' });
  });

  it('lists shared attachment metadata with identity-bound AllFiles and an opaque token', async () => {
    const { ctx, requests } = fixture({ Items: [{ ItemType: 'File', FileData: { FileName: 'report.pdf', FileUrl: 'https://example.sharepoint.com/a/report.pdf', WebUrl: null, SizeInBytes: 5 }, SharedByDisplayName: 'Person', SharedDateTime: '2026-10-26T00:00:00Z' }, { ItemType: 'Link', WeblinkData: { WebUrl: 'https://example.test', Title: 'Link' } }], SkipToken: 'next-token' });
    const result = await run('teams.listAttachments', ctx, { conversationId });
    expect(result.attachments[0]).toMatchObject({ name: 'report.pdf', webUrl: 'https://example.sharepoint.com/a/report.pdf', size: 5 });
    expect(result.attachments).toHaveLength(1);
    expect(requests[0]!.path).toContain(encodeURIComponent(`OID:${identity.objectId}@${identity.tenantId}`));
    expect(requests[0]).toMatchObject({ resource: 'substrate', query: { ThreadId: conversationId, ItemTypes: 'File' } });
    await run('teams.listAttachments', ctx, { conversationId, cursor: result.cursor });
    expect(requests[1]!.query!['$skiptoken']).toBe('next-token');
  });

  it('refuses an oversized attachment token instead of silently corrupting pagination', async () => {
    const { ctx } = fixture({ Items: [], SkipToken: 'x'.repeat(8001) });
    await expect(run('teams.listAttachments', ctx, { conversationId })).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('keeps shared-channel type and missing-group metadata distinct', async () => {
    const { ctx } = fixture({ teams: [{ id: '19:team@thread.tacv2', displayName: 'Team', channels: [{ id: conversationId, displayName: 'General', channelType: 2 }] }] });
    const result = await run('teams.listChannels', ctx, { teamId: '19:team@thread.tacv2' });
    expect(result.channels[0].type).toBe('shared');
    expect(result.channels[0].groupId).toBeUndefined();
  });

  it('sends a reply once using a decimal client ID and reports IDs accurately', async () => {
    const { ctx, requests } = fixture({ OriginalArrivalTime: 1760000000000 });
    const result = await run('teams.send', ctx, { conversationId, text: 'A < B', replyToMessageId: '123' });
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({ resource: 'chat', method: 'POST', path: `/v1/users/ME/conversations/${encodeURIComponent(`${conversationId};messageid=123`)}/messages`, body: { content: 'A < B', messagetype: 'Text', contenttype: 'text', imdisplayname: 'Sample User' } });
    expect((requests[0]!.body as any).clientmessageid).toMatch(/^\d{19}$/);
    expect(result.clientMessageId).toBe((requests[0]!.body as any).clientmessageid);
    expect(result.messageId).toBeUndefined();
    expect(result.arrivalTime).toBe(1760000000000);
    expect(Object.keys(requests[0]!.headers ?? {})).not.toContain('Origin');
  });

  it('rejects channel-only send options for chats before network access', async () => {
    const { ctx, requests } = fixture({});
    await expect(run('teams.send', ctx, { conversationId: '19:a_b@unq.gbl.spaces', text: 'Message', replyToMessageId: '123' })).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(run('teams.send', ctx, { conversationId, text: 'Message', replyToMessageId: '123', subject: 'New post' })).rejects.toMatchObject({ code: 'invalid_input' });
    expect(requests).toHaveLength(0);
  });

  it('returns a server message ID only when the response actually identifies one', async () => {
    const { ctx, requests } = fixture({ id: '1234567890123', OriginalArrivalTime: 1234567890123 });
    const result = await run('teams.send', ctx, { conversationId, text: 'Hello', subject: 'Title' });
    expect(result.messageId).toBe('1234567890123');
    expect(result.clientMessageId).not.toBe(result.messageId);
    expect(requests[0]).toMatchObject({ body: { properties: { subject: 'Title' } } });
  });

  it.each([[401, 'reauth_required'], [403, 'access_denied'], [429, 'rate_limited'], [500, 'provider_error']] as const)('returns sanitized HTTP %d errors and never retries send', async (status, code) => {
    const { ctx, requests } = fixture({ secret: 'never leak' }, status);
    await expect(run('teams.send', ctx, { conversationId, text: 'Message' })).rejects.toMatchObject({ code });
    expect(requests).toHaveLength(1);
  });

  it('rejects malformed successful responses rather than reporting empty access', async () => {
    for (const name of ['teams.listChats', 'teams.listChannels', 'teams.getThread', 'teams.search', 'teams.listAttachments']) {
      const { ctx } = fixture({ error: 'wrong shape' });
      await expect(run(name, ctx, name === 'teams.search' ? { query: 'test' } : name === 'teams.getThread' || name === 'teams.listAttachments' ? { conversationId } : {})).rejects.toMatchObject({ code: 'invalid_response' });
    }
  });
});

const graphTeamId = '33333333-3333-4333-8333-333333333333';
const graphChannelPath = `/v1.0/teams/${graphTeamId}/channels`;
const channelSelect = 'id,displayName,description,membershipType';
const graphChannel = { id: conversationId, displayName: 'General', membershipType: 'standard', description: 'Description' };
function graphFixture(respond: (request: SessionHttpRequest) => unknown = () => undefined) {
  const requests: SessionHttpRequest[] = [];
  const ctx: OperationContext = { identity, sites: [], request: async (request) => {
    requests.push(request);
    const override = respond(request);
    const body = override ?? (request.path === '/v1.0/me' ? { id: identity.objectId } : request.path === '/v1.0/me/joinedTeams' ? { value: [{ id: graphTeamId, displayName: 'Team' }] } : { value: [graphChannel] });
    if (typeof body === 'number') return { status: body, headers: {}, body: Buffer.from('{}') };
    return { status: 200, headers: {}, body: Buffer.from(JSON.stringify(body)) };
  } };
  return { ctx, requests };
}

describe('Graph session channel enumeration', () => {
  it('verifies Graph identity first and returns group UUIDs without inventing team thread IDs', async () => {
    const { ctx, requests } = graphFixture();
    const result = await run('teams.listChannels', ctx);
    expect(result.channels).toEqual([{ channelId: conversationId, name: 'General', teamId: graphTeamId, groupId: graphTeamId, teamName: 'Team', type: 'standard', description: 'Description' }]);
    expect(requests.map(r => [r.resource, r.path])).toEqual([['graph', '/v1.0/me'], ['graph', '/v1.0/me/joinedTeams'], ['graph', graphChannelPath]]);
    expect(requests[2]!.query).toEqual({ '$select': channelSelect });
  });
  it('accepts a UUID filter only for a joined team and binds result cursors to that filter and identity', async () => {
    const { ctx, requests } = graphFixture(r => r.path === graphChannelPath ? { value: [graphChannel, { ...graphChannel, id: '19:private@thread.tacv2', membershipType: 'private' }] } : undefined);
    const first = await run('teams.listChannels', ctx, { teamId: graphTeamId.toUpperCase(), limit: 1 });
    const next = await run('teams.listChannels', ctx, { teamId: graphTeamId, limit: 1, cursor: first.cursor });
    expect(next.channels[0].type).toBe('private');
    expect(next.cursor).toBeUndefined();
    await expect(run('teams.listChannels', ctx, { cursor: first.cursor })).rejects.toMatchObject({ code: 'invalid_cursor' });
    const other = await run('teams.listChannels', ctx, { teamId: identity.tenantId });
    expect(other.channels).toEqual([]);
    expect(requests.at(-1)!.path).toBe('/v1.0/me/joinedTeams');
  });
  it('reconstructs pagination as bounded query data for the exact original route', async () => {
    const { ctx, requests } = graphFixture(r => {
      if (r.path === '/v1.0/me/joinedTeams' && !r.query?.['$skiptoken']) return { value: [], '@odata.nextLink': 'https://graph.microsoft.com/v1.0/me/joinedTeams?$skiptoken=team%3D' };
      if (r.path === graphChannelPath && !r.query?.['$skipToken']) return { value: [], '@odata.nextLink': `https://graph.microsoft.com${graphChannelPath}?$select=${channelSelect}&$skipToken=channel%3D` };
      return undefined;
    });
    expect((await run('teams.listChannels', ctx)).channels).toHaveLength(1);
    expect(requests[2]).toMatchObject({ path: '/v1.0/me/joinedTeams', query: { '$skiptoken': 'team=' } });
    expect(requests[4]).toMatchObject({ path: graphChannelPath, query: { '$select': channelSelect, '$skipToken': 'channel=' } });
  });
  it.each([
    'https://evil.test/v1.0/me/joinedTeams?$skiptoken=x',
    'https://graph.microsoft.com/v1.0/me/drives?$skiptoken=x',
    'https://user@graph.microsoft.com/v1.0/me/joinedTeams?$skiptoken=x',
    'https://graph.microsoft.com:443/v1.0/me/joinedTeams?$skiptoken=x',
    'https://graph.microsoft.com/v1.0/me/x/../joinedTeams?$skiptoken=x',
    'https://graph.microsoft.com/v1.0/me/joinedTeams?$skiptoken=x#fragment',
    'https://graph.microsoft.com/v1.0/me/joinedTeams?$skiptoken=x&$skiptoken=y',
    'https://graph.microsoft.com/v1.0/me/joinedTeams?$skiptoken=x&$skipToken=y',
    'https://graph.microsoft.com/v1.0/me/joinedTeams?$skiptoken=x&$select=id',
    'https://graph.microsoft.com/v1.0/me/joinedTeams?$skiptoken=x&$top=100',
  ])('rejects unsafe continuation %s without CSA fallback', async link => {
    const { ctx, requests } = graphFixture(r => r.path === '/v1.0/me/joinedTeams' ? { value: [], '@odata.nextLink': link } : undefined);
    await expect(run('teams.listChannels', ctx)).rejects.toMatchObject({ code: 'invalid_response' });
    expect(requests).toHaveLength(2);
  });
  it('rejects a changed channel selection or repeated continuation', async () => {
    for (const selection of ['id', channelSelect]) {
      const { ctx, requests } = graphFixture(r => r.path === graphChannelPath ? { value: [], '@odata.nextLink': `https://graph.microsoft.com${graphChannelPath}?$select=${selection}&$skiptoken=same` } : undefined);
      await expect(run('teams.listChannels', ctx)).rejects.toMatchObject({ code: 'invalid_response' });
      expect(requests.every(r => r.resource === 'graph')).toBe(true);
      expect(requests.length).toBeLessThanOrEqual(4);
    }
  });
  it.each([401, 403])('falls back to legacy CSA only for Graph HTTP %d', async status => {
    const { ctx, requests } = graphFixture(r => r.resource === 'graph' ? status : { teams: [{ id: '19:team@thread.tacv2', displayName: 'Team', channels: [{ id: conversationId, displayName: 'General', groupId: graphTeamId, channelType: 0 }] }] });
    const result = await run('teams.listChannels', ctx, { teamId: graphTeamId });
    expect(result.channels[0]).toMatchObject({ teamId: '19:team@thread.tacv2', groupId: graphTeamId });
    expect(requests.map(r => r.resource)).toEqual(['graph', 'csa']);
  });
  it.each([[429, 'rate_limited'], [500, 'provider_error'], [{}, 'invalid_response'], [{ id: graphTeamId }, 'identity_mismatch']])('never falls back on an unsafe or unavailable Graph result', async (body, code) => {
    const { ctx, requests } = graphFixture(() => body);
    await expect(run('teams.listChannels', ctx)).rejects.toMatchObject({ code });
    expect(requests).toHaveLength(1);
  });
  it.each([{ id: '../escape', displayName: 'Team' }, { id: graphTeamId }, { id: graphTeamId, displayName: '' }])('rejects malformed team records', async team => {
    const { ctx } = graphFixture(r => r.path === '/v1.0/me/joinedTeams' ? { value: [team] } : undefined);
    await expect(run('teams.listChannels', ctx)).rejects.toMatchObject({ code: 'invalid_response' });
  });
  it.each([{ ...graphChannel, id: '48:other' }, { ...graphChannel, id: '19:../escape' }, { ...graphChannel, membershipType: 'unknown' }, { ...graphChannel, membershipType: ['standard'] }])('rejects malformed channel records', async channel => {
    const { ctx } = graphFixture(r => r.path === graphChannelPath ? { value: [channel] } : undefined);
    await expect(run('teams.listChannels', ctx)).rejects.toMatchObject({ code: 'invalid_response' });
  });
  it('accepts the exact team/channel limits without silently truncating or dropping the cursor', async () => {
    const { ctx, requests } = graphFixture(r => r.path === '/v1.0/me/joinedTeams'
      ? { value: Array.from({ length: 100 }, (_, i) => ({ id: `33333333-3333-4333-8333-${String(i).padStart(12, '0')}`, displayName: 'Team' })) }
      : r.path.endsWith('/channels') ? { value: Array.from({ length: 10 }, (_, i) => ({ ...graphChannel, id: `19:channel${i}@thread.tacv2` })) } : undefined);
    let cursor: string | undefined;
    let count = 0;
    do {
      const result = await run('teams.listChannels', ctx, { limit: 200, ...(cursor ? { cursor } : {}) });
      count += result.channels.length;
      cursor = result.cursor;
    } while (cursor);
    expect(count).toBe(1000);
    expect(requests).toHaveLength(510);
  });
  it('discards partial Graph enumeration before an authorized CSA fallback', async () => {
    const { ctx, requests } = graphFixture(r => r.path === graphChannelPath ? 403 : r.resource === 'csa' ? { teams: [] } : undefined);
    expect((await run('teams.listChannels', ctx)).channels).toEqual([]);
    expect(requests.map(r => r.resource)).toEqual(['graph', 'graph', 'graph', 'csa']);
  });
  it('enforces the channel bound across provider pages', async () => {
    const { ctx } = graphFixture(r => r.path === graphChannelPath ? {
      value: Array.from({ length: r.query?.['$skiptoken'] ? 1 : 1000 }, (_, i) => ({ ...graphChannel, id: `19:channel${i}@thread.tacv2` })),
      ...(r.query?.['$skiptoken'] ? {} : { '@odata.nextLink': `https://graph.microsoft.com${graphChannelPath}?$skiptoken=next` }),
    } : undefined);
    await expect(run('teams.listChannels', ctx)).rejects.toMatchObject({ code: 'enumeration_limit' });
  });
  it('fails explicitly on more than 100 teams, 1000 channels, or 200 list pages', async () => {
    for (const [path, body] of [
      ['/v1.0/me/joinedTeams', { value: Array.from({ length: 101 }, (_, i) => ({ id: `33333333-3333-4333-8333-${String(i).padStart(12, '0')}`, displayName: 'Team' })) }],
      [graphChannelPath, { value: Array.from({ length: 1001 }, (_, i) => ({ ...graphChannel, id: `19:channel${i}@thread.tacv2` })) }],
    ] as const) {
      const { ctx } = graphFixture(r => r.path === path ? body : undefined);
      await expect(run('teams.listChannels', ctx)).rejects.toMatchObject({ code: 'enumeration_limit' });
    }
    let n = 0;
    const { ctx, requests } = graphFixture(r => r.path === '/v1.0/me/joinedTeams' ? { value: [], '@odata.nextLink': `https://graph.microsoft.com/v1.0/me/joinedTeams?$skiptoken=${++n}` } : undefined);
    await expect(run('teams.listChannels', ctx)).rejects.toMatchObject({ code: 'enumeration_limit' });
    expect(requests).toHaveLength(201);
  });
});
