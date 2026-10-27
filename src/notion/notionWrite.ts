import { actorOf, type AuditLog } from '../audit/audit.js';
import { assertDocsCapability, currentPrincipal, type Principal } from '../auth/grants.js';
import { PerchError } from '../errors.js';
import type { SendWorkflow } from '../mail/workflow.js';
import { sendMessageIdempotently, type MessageSendResult, type MessageSendView } from '../messaging/send.js';
import type { CredentialStore, NotionWorkspace } from '../store/credentialStore.js';
import { UpstreamError, type Upstream } from '../upstream.js';
import { fingerprint, headers, normaliseNotionId } from './notion.js';

/**
 * Notion create, edit, trash and comments (docs/FULL_ACCESS_SPEC.md §3.2). Every write needs a client grant
 * holding notion_write for the workspace; the read-only operator never writes. Deleting is trash only
 * (`in_trash: true`, restorable in Notion); DELETE /v1/blocks/{id} is not allowlisted (src/upstream.ts).
 *
 * Creating operations (page, appended blocks, comment) take a requestId and run through the shared idempotent
 * send workflow (src/messaging/send.ts, provider "notion", audit type notion_write): the ledger stores only
 * HMACs of the payload and the created object's id, never titles or content. Plain edits (properties, block
 * content, trash/restore) are audited by the MCP runner before the provider call. Writes are never retried.
 *
 * Payloads (properties, blocks, rich text) are Notion JSON objects passed through, but bounded before any I/O.
 */

export const MAX_REQUEST_JSON_BYTES = 512 * 1024;
/** Blocks per request, nested children included. */
export const MAX_WRITE_BLOCKS = 100;
/** Notion's own limit for text.content of one rich text item. */
export const MAX_RICH_TEXT_CONTENT = 2000;
/** Notion's own limit for the items of one rich text array. */
export const MAX_RICH_TEXT_ITEMS = 100;
const MAX_NESTING = 40;

type Json = Record<string, unknown>;

export const RESTRICTED_RESOURCE =
  'Notion refused the write (restricted_resource): the integration token lacks the needed capability. In the integration settings ' +
  '(notion.so/profile/integrations) enable "Update content", "Insert content" and, for comments, "Insert comments", and share the page ' +
  'with the integration.';

const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Bounds a caller-supplied Notion payload: serialised size, nesting depth, rich text item length and count,
 * and the total number of blocks (every element of a `children` array, at any depth). No I/O.
 */
export function assertPayloadBounds(payload: unknown): void {
  let size: number;
  try {
    size = Buffer.byteLength(JSON.stringify(payload) ?? '', 'utf8');
  } catch {
    throw new PerchError('The Notion payload is not valid JSON', 'bad_argument');
  }
  if (size > MAX_REQUEST_JSON_BYTES) throw new PerchError(`The Notion request exceeds ${MAX_REQUEST_JSON_BYTES} bytes of JSON`, 'bad_argument');
  let blocks = 0;
  const walk = (v: unknown, depth: number, key: string | undefined): void => {
    if (depth > MAX_NESTING) throw new PerchError(`The Notion payload is nested deeper than ${MAX_NESTING} levels`, 'bad_argument');
    if (Array.isArray(v)) {
      if (key === 'children') {
        blocks += v.length;
        if (blocks > MAX_WRITE_BLOCKS) throw new PerchError(`At most ${MAX_WRITE_BLOCKS} blocks per request (nested children included)`, 'bad_argument');
      }
      if ((key === 'rich_text' || key === 'title' || key === 'caption') && v.length > MAX_RICH_TEXT_ITEMS) {
        throw new PerchError(`A rich text array may hold at most ${MAX_RICH_TEXT_ITEMS} items`, 'bad_argument');
      }
      for (const x of v) walk(x, depth + 1, undefined);
      return;
    }
    if (!isObject(v)) return;
    const text = v.text;
    if (isObject(text) && typeof text.content === 'string' && text.content.length > MAX_RICH_TEXT_CONTENT) {
      throw new PerchError(`A rich text item may hold at most ${MAX_RICH_TEXT_CONTENT} characters (split it into several items)`, 'bad_argument');
    }
    for (const [k, x] of Object.entries(v)) walk(x, depth + 1, k);
  };
  walk(payload, 0, undefined);
}

function objectArg(v: unknown, name: string): Json {
  if (!isObject(v)) throw new PerchError(`${name} must be a JSON object`, 'bad_argument');
  return v;
}

function optionalObject(v: unknown, name: string): Json | null | undefined {
  if (v === undefined || v === null) return v;
  return objectArg(v, name);
}

function blocksArg(v: unknown, name: string, required: boolean): Json[] | undefined {
  if (v === undefined && !required) return undefined;
  if (!Array.isArray(v) || (required && v.length === 0)) throw new PerchError(`${name} must be a${required ? ' non-empty' : 'n'} array of Notion block objects`, 'bad_argument');
  if (v.length > MAX_WRITE_BLOCKS) throw new PerchError(`At most ${MAX_WRITE_BLOCKS} blocks per request`, 'bad_argument');
  return v.map((b, i) => objectArg(b, `${name}[${i}]`));
}

function richTextArg(v: unknown): Json[] {
  if (!Array.isArray(v) || v.length === 0) throw new PerchError('richText must be a non-empty array of Notion rich text objects', 'bad_argument');
  return v.map((x, i) => objectArg(x, `richText[${i}]`));
}

/** Block type names that may be updated (never meta fields such as in_trash/archived). */
const BLOCK_TYPE = /^[a-z][a-z0-9_]{0,39}$/;
const NOT_A_BLOCK_TYPE = new Set(['in_trash', 'archived', 'is_archived', 'object', 'id', 'parent', 'children', 'type', 'has_children']);

const bindingParts = (ws: NotionWorkspace) => ['notion', ws.id, ws.tokenOwner?.id ?? '', fingerprint(ws.token)];

export interface WorkspaceProvenance {
  workspaceId: string;
  workspaceLabel: string;
}

export interface CreatePageInput {
  workspaceId: string;
  parentPageId?: string;
  parentDataSourceId?: string;
  title?: string;
  properties?: Json;
  children?: Json[];
  icon?: Json;
  cover?: Json;
  requestId: string;
}

export interface UpdatePageInput {
  workspaceId: string;
  pageId: string;
  properties?: Json;
  icon?: Json | null;
  cover?: Json | null;
}

export interface AppendBlocksInput {
  workspaceId: string;
  blockId: string;
  children: Json[];
  after?: string;
  requestId: string;
}

export interface UpdateBlockInput {
  workspaceId: string;
  blockId: string;
  type: string;
  content: Json;
}

export interface AddCommentInput {
  workspaceId: string;
  pageId?: string;
  discussionId?: string;
  richText: Json[];
  requestId: string;
}

interface CreatePlan {
  path: string;
  method: 'POST' | 'PATCH';
  body: Json;
  canonical: unknown[];
  /** Id of the created object from the provider response (kept in the ledger as providerMessageId). */
  createdId: (res: Json) => string | undefined;
}

const idOf = (v: unknown): string | undefined => {
  if (typeof v !== 'string') return undefined;
  try {
    return normaliseNotionId(v);
  } catch {
    return undefined;
  }
};

function rejection(err: UpstreamError): string {
  if (err.status === 403 && err.upstreamCode === 'restricted_resource') return RESTRICTED_RESOURCE;
  if (err.status === 404 || err.upstreamCode === 'object_not_found') {
    return 'Notion could not find the target, or it is not shared with the integration (HTTP 404).';
  }
  if (err.status === 429) return 'Notion rate-limited the request before processing it (HTTP 429); try again later.';
  if (err.status === 409) return 'Notion reported a conflicting concurrent edit (HTTP 409); read the current state and try again.';
  return `Notion rejected the request (HTTP ${err.status}${err.upstreamCode ? `, ${err.upstreamCode}` : ''}).`;
}

export class NotionWriter {
  constructor(
    private readonly store: CredentialStore,
    private readonly upstream: Upstream,
    private readonly workflow: SendWorkflow,
    private readonly audit: AuditLog,
    /** OAuth workspaces with expiring tokens resolve their access token here; default: the stored token. */
    private readonly accessToken: (ws: NotionWorkspace) => Promise<string> = async (ws) => ws.token,
  ) {}

  private prov(ws: NotionWorkspace): WorkspaceProvenance {
    return { workspaceId: ws.id, workspaceLabel: ws.label };
  }

  /** Asserts notion_write for the workspace before any lookup or I/O, then loads it. */
  private async writable(p: Principal, id: unknown): Promise<NotionWorkspace> {
    if (typeof id !== 'string') throw new PerchError('workspaceId is required', 'bad_argument');
    assertDocsCapability(p, 'notion', id, 'notion_write');
    const ws = (await this.store.read()).notion.find((w) => w.id === id);
    if (!ws) throw new PerchError(`Unknown Notion workspace: ${id}`, 'unknown_account');
    return ws;
  }

  /** Re-resolves the stored grant right before the provider call (revocation applies immediately). */
  private async stillAllowed(stale: Principal, workspaceId: string): Promise<void> {
    assertDocsCapability(await currentPrincipal(this.store, stale), 'notion', workspaceId, 'notion_write');
  }

  private async call(ws: NotionWorkspace, method: 'POST' | 'PATCH', path: string, body: Json): Promise<Json> {
    // Writes go straight to the upstream: no 429 retry (the read path's retry never applies here).
    return this.upstream.json<Json>('notion', { method, path, json: body, headers: headers(await this.accessToken(ws)), capability: 'notion_write' });
  }

  /** One idempotent creating write (see src/messaging/send.ts). */
  private async create(
    p: Principal,
    workspaceId: unknown,
    requestId: unknown,
    plan: (ws: NotionWorkspace) => CreatePlan,
  ): Promise<MessageSendView & WorkspaceProvenance> {
    let ws: NotionWorkspace | undefined;
    let built: CreatePlan | undefined;
    const view = await sendMessageIdempotently({
      workflow: this.workflow,
      audit: this.audit,
      actor: actorOf(p),
      provider: 'notion',
      accountId: workspaceId,
      prepare: async () => {
        ws = await this.writable(p, workspaceId);
        built = plan(ws);
        assertPayloadBounds(built.body);
        return { accountId: ws.id, requestId, canonical: JSON.stringify([...built.canonical, ws.id, built.body]), binding: bindingParts(ws) };
      },
      attempt: (binding) => this.attempt(p, ws!.id, built!, binding),
    });
    return { ...this.prov(ws!), ...view };
  }

  private async attempt(p: Principal, workspaceId: string, plan: CreatePlan, binding: string): Promise<MessageSendResult> {
    const notDone = (detail: string, reason: MessageSendResult['reason']): MessageSendResult => ({ status: 'rejected', detail: `Not written: ${detail}`, reason });
    try {
      await this.stillAllowed(p, workspaceId);
    } catch (err) {
      return notDone(err instanceof PerchError ? err.message : 'the request is no longer authorised', 'not_submitted_authorization');
    }
    const current = (await this.store.read()).notion.find((w) => w.id === workspaceId);
    if (!current || (await this.workflow.binding(bindingParts(current))) !== binding) {
      return notDone('the workspace was removed or reconnected since this requestId was first used', 'not_submitted_account_changed');
    }
    let res: Json;
    try {
      res = await this.call(current, plan.method, plan.path, plan.body);
    } catch (err) {
      // Notion answered with an error status: not applied (429 = rate limited before processing).
      if (err instanceof UpstreamError && err.status < 500) return notDone(rejection(err), 'provider_rejected');
      if (err instanceof PerchError && err.code === 'route_not_allowed') return notDone(err.message, 'not_submitted_provider_precheck');
      return { status: 'indeterminate', detail: 'The request to Notion failed after it may have been processed; the outcome is unknown.', reason: 'provider_unknown' };
    }
    const id = plan.createdId(res);
    return { status: 'accepted', detail: 'Written to Notion.', ...(id ? { providerMessageId: id } : {}), reason: 'provider_accepted' };
  }

  /** One plain edit (audited by the MCP runner): validation first, then the grant again, then exactly one call. */
  private async edit(p: Principal, workspaceId: unknown, path: string, body: Json): Promise<WorkspaceProvenance & { status: 'accepted'; object: Json }> {
    const ws = await this.writable(p, workspaceId);
    assertPayloadBounds(body);
    await this.stillAllowed(p, ws.id);
    let res: Json;
    try {
      res = await this.call(ws, 'PATCH', path, body);
    } catch (err) {
      if (err instanceof UpstreamError && err.status < 500) throw new PerchError(`Rejected, nothing was changed: ${rejection(err)}`, 'provider_rejected');
      if (err instanceof PerchError && err.code === 'route_not_allowed') throw err;
      throw new PerchError(
        'The request to Notion failed after it may have been processed; the outcome is unknown. Perch does not retry: check the page in Notion.',
        'outcome_unknown',
      );
    }
    const object: Json = {
      object: res.object,
      id: res.id,
      ...(res.type ? { type: res.type } : {}),
      ...(typeof res.in_trash === 'boolean' ? { in_trash: res.in_trash } : {}),
      ...(res.url ? { url: res.url } : {}),
      ...(res.last_edited_time ? { last_edited_time: res.last_edited_time } : {}),
    };
    return { ...this.prov(ws), status: 'accepted', object };
  }

  async createPage(p: Principal, input: CreatePageInput) {
    const result = await this.create(p, input?.workspaceId, input?.requestId, () => {
      const hasPage = input.parentPageId !== undefined;
      const hasDs = input.parentDataSourceId !== undefined;
      if (hasPage === hasDs) throw new PerchError('Give exactly one of parentPageId or parentDataSourceId', 'bad_argument');
      const parent = hasPage
        ? { type: 'page_id', page_id: normaliseNotionId(String(input.parentPageId)) }
        : { type: 'data_source_id', data_source_id: normaliseNotionId(String(input.parentDataSourceId)) };
      const properties: Json = { ...(optionalObject(input.properties, 'properties') ?? {}) };
      if (input.title !== undefined) {
        if (typeof input.title !== 'string' || !input.title.trim()) throw new PerchError('title must be a non-empty string', 'bad_argument');
        if (input.title.length > MAX_RICH_TEXT_CONTENT) throw new PerchError(`title may hold at most ${MAX_RICH_TEXT_CONTENT} characters`, 'bad_argument');
        if (!hasPage) throw new PerchError('title is only for a page parent; for a data source row set its title property in properties', 'bad_argument');
        if ('title' in properties) throw new PerchError('Give the title either as title or as properties.title, not both', 'bad_argument');
        properties.title = { title: [{ type: 'text', text: { content: input.title } }] };
      }
      if (!Object.keys(properties).length && hasDs) throw new PerchError('A data source row needs properties (at least its title property)', 'bad_argument');
      const children = blocksArg(input.children, 'children', false);
      const icon = optionalObject(input.icon, 'icon');
      const cover = optionalObject(input.cover, 'cover');
      const body: Json = {
        parent,
        properties,
        ...(children ? { children } : {}),
        ...(icon ? { icon } : {}),
        ...(cover ? { cover } : {}),
      };
      return { method: 'POST', path: '/v1/pages', body, canonical: ['perch-notion-create-page-v1'], createdId: (r) => idOf(r.id) };
    });
    const { providerMessageId, ...rest } = result;
    return { ...rest, ...(providerMessageId ? { pageId: providerMessageId } : {}) };
  }

  async appendBlocks(p: Principal, input: AppendBlocksInput) {
    let created: string[] = [];
    const result = await this.create(p, input?.workspaceId, input?.requestId, () => {
      const blockId = normaliseNotionId(String(input.blockId));
      const children = blocksArg(input.children, 'children', true)!;
      const after = input.after === undefined ? undefined : normaliseNotionId(String(input.after));
      const body: Json = { children, ...(after ? { after } : {}) };
      return {
        method: 'PATCH',
        path: `/v1/blocks/${blockId}/children`,
        body,
        canonical: ['perch-notion-append-blocks-v1', blockId],
        createdId: (r) => {
          const results = Array.isArray(r.results) ? (r.results as Json[]) : [];
          created = results.map((b) => idOf(b.id)).filter((x): x is string => x !== undefined);
          return created[0];
        },
      };
    });
    const { providerMessageId, ...rest } = result;
    return {
      ...rest,
      ...(providerMessageId ? { firstBlockId: providerMessageId } : {}),
      ...(created.length ? { blockIds: created } : {}),
    };
  }

  async addComment(p: Principal, input: AddCommentInput) {
    const result = await this.create(p, input?.workspaceId, input?.requestId, () => {
      const hasPage = input.pageId !== undefined;
      const hasDiscussion = input.discussionId !== undefined;
      if (hasPage === hasDiscussion) throw new PerchError('Give exactly one of pageId or discussionId', 'bad_argument');
      const rich_text = richTextArg(input.richText);
      const body: Json = hasPage
        ? { parent: { page_id: normaliseNotionId(String(input.pageId)) }, rich_text }
        : { discussion_id: normaliseNotionId(String(input.discussionId)), rich_text };
      return { method: 'POST', path: '/v1/comments', body, canonical: ['perch-notion-add-comment-v1'], createdId: (r) => idOf(r.id) };
    });
    const { providerMessageId, ...rest } = result;
    return { ...rest, ...(providerMessageId ? { commentId: providerMessageId } : {}) };
  }

  async updatePage(p: Principal, input: UpdatePageInput) {
    const pageId = normaliseNotionId(String(input?.pageId));
    const properties = optionalObject(input.properties, 'properties');
    const icon = optionalObject(input.icon, 'icon');
    const cover = optionalObject(input.cover, 'cover');
    const body: Json = {
      ...(properties ? { properties } : {}),
      ...(icon !== undefined ? { icon } : {}),
      ...(cover !== undefined ? { cover } : {}),
    };
    if (!Object.keys(body).length) throw new PerchError('Nothing to change: give properties, icon or cover', 'bad_argument');
    return this.edit(p, input.workspaceId, `/v1/pages/${pageId}`, body);
  }

  async updateBlock(p: Principal, input: UpdateBlockInput) {
    const blockId = normaliseNotionId(String(input?.blockId));
    if (typeof input.type !== 'string' || !BLOCK_TYPE.test(input.type) || NOT_A_BLOCK_TYPE.has(input.type)) {
      throw new PerchError('type must be the block type name (e.g. paragraph, heading_1, to_do)', 'bad_argument');
    }
    const content = objectArg(input.content, 'content');
    return this.edit(p, input.workspaceId, `/v1/blocks/${blockId}`, { [input.type]: content });
  }

  /** Moves a page to Notion's trash (restorable with restorePage). */
  async setPageTrashed(p: Principal, input: { workspaceId: string; pageId: string }, inTrash: boolean) {
    const pageId = normaliseNotionId(String(input?.pageId));
    return this.edit(p, input.workspaceId, `/v1/pages/${pageId}`, { in_trash: inTrash });
  }

  /** Moves a block to Notion's trash (restorable in Notion). Never DELETE. */
  async trashBlock(p: Principal, input: { workspaceId: string; blockId: string }) {
    const blockId = normaliseNotionId(String(input?.blockId));
    return this.edit(p, input.workspaceId, `/v1/blocks/${blockId}`, { in_trash: true });
  }
}
