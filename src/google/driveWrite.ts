import { createHash, randomBytes } from 'node:crypto';
import { actorOf, type AuditLog } from '../audit/audit.js';
import { assertDocsCapability, currentPrincipal, type Principal } from '../auth/grants.js';
import { PerchError } from '../errors.js';
import type { SendWorkflow } from '../mail/workflow.js';
import { PROVIDER_MESSAGE_ID_PATTERN } from '../mail/workflowLedger.js';
import { sendMessageIdempotently, type MessageSendResult, type MessageSendView } from '../messaging/send.js';
import type { CredentialStore, GoogleAccount } from '../store/credentialStore.js';
import { UpstreamError, type CallOptions, type Upstream } from '../upstream.js';
import type { GoogleTokenProvider } from './accounts.js';
import { assertFileId, MIME } from './drive.js';
import { DRIVE_SCOPE } from './oauth.js';

/**
 * Drive writes (docs/FULL_ACCESS_SPEC.md §3.1), only for client grants holding drive_write for the account,
 * and only on accounts connected with the full `drive` scope (perch google add --allow-write).
 *
 * - Creating, copying, sharing and commenting carry a requestId and run through the idempotent send workflow
 *   (src/messaging/send.ts): one provider attempt per requestId, outcome accepted/rejected/indeterminate,
 *   never retried. The ledger keeps only HMACs and the opaque id of the created object (file, permission or
 *   comment id), never names, content or e-mail addresses.
 * - Plain edits (replace content, rename/move, trash/restore, unshare) are audited by the MCP runner before the
 *   provider call and re-resolve the grant immediately before it.
 * - Deleting means trash only: there is no permanent delete, no empty trash and no ownership transfer
 *   (the upstream allowlist does not contain those routes).
 */

export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
/** Longest base64 text for MAX_UPLOAD_BYTES. */
export const MAX_UPLOAD_BASE64 = Math.ceil(MAX_UPLOAD_BYTES / 3) * 4;
export const MAX_NAME_LENGTH = 1024;
export const MAX_DESCRIPTION_LENGTH = 4096;
export const MAX_COMMENT_LENGTH = 4096;
export const MAX_PARENTS = 10;
export const SHARE_TYPES = ['user', 'group', 'domain', 'anyone'] as const;
/** Never "owner" (and no organizer roles): sharing cannot hand over a file. */
export const SHARE_ROLES = ['reader', 'commenter', 'writer'] as const;
export const DOCUMENT_KINDS = ['doc', 'sheet', 'slides'] as const;

const FOLDER = 'application/vnd.google-apps.folder';
const NATIVE: Record<(typeof DOCUMENT_KINDS)[number], string> = {
  doc: 'application/vnd.google-apps.document',
  sheet: 'application/vnd.google-apps.spreadsheet',
  slides: 'application/vnd.google-apps.presentation',
};
const FILE_FIELDS = 'id,name,mimeType,size,modifiedTime,webViewLink,parents,trashed';
const EMAIL = /^[^\s@<>()",;:\\]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$/;
const DOMAIN = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

type ShareType = (typeof SHARE_TYPES)[number];
type ShareRole = (typeof SHARE_ROLES)[number];

export interface DriveWriteView extends Omit<MessageSendView, 'providerMessageId'> {
  accountId: string;
  accountLabel: string;
}

const sha256 = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

function name(v: unknown, field = 'name'): string {
  if (typeof v !== 'string' || !v.trim()) throw new PerchError(`${field} must not be empty`, 'bad_argument');
  if (v.length > MAX_NAME_LENGTH) throw new PerchError(`${field} exceeds ${MAX_NAME_LENGTH} characters`, 'bad_argument');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) throw new PerchError(`${field} must not contain control characters`, 'bad_argument');
  return v;
}

function optId(v: unknown, field: string): string | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'string') throw new PerchError(`${field} must be a string`, 'bad_argument');
  try {
    assertFileId(v);
  } catch {
    throw new PerchError(`Invalid ${field}`, 'bad_argument');
  }
  return v;
}

function fileIdOf(v: unknown): string {
  const id = optId(v, 'fileId');
  if (!id) throw new PerchError('fileId is required', 'bad_argument');
  return id;
}

function mimeOf(v: unknown, fallback: string): string {
  if (v === undefined) return fallback;
  if (typeof v !== 'string' || v.length > 255 || !MIME.test(v)) throw new PerchError('Invalid mimeType', 'bad_argument');
  if (v.startsWith('application/vnd.google-apps.')) {
    throw new PerchError('Google-native types cannot be uploaded as content; use drive_create_document or drive_create_folder', 'bad_argument');
  }
  return v;
}

/** Strict base64 (standard alphabet, optional whitespace), at most MAX_UPLOAD_BYTES decoded. */
export function decodeContent(v: unknown): Buffer {
  if (typeof v !== 'string') throw new PerchError('contentBase64 must be a string', 'bad_argument');
  const s = v.replace(/\s+/g, '');
  if (s.length > MAX_UPLOAD_BASE64 + 4) throw new PerchError(`Content exceeds ${MAX_UPLOAD_BYTES} bytes`, 'file_too_large');
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new PerchError('contentBase64 is not valid base64', 'bad_argument');
  const buf = Buffer.from(s, 'base64');
  if (buf.length > MAX_UPLOAD_BYTES) throw new PerchError(`Content exceeds ${MAX_UPLOAD_BYTES} bytes`, 'file_too_large');
  return buf;
}

function optBool(v: unknown, field: string): boolean | undefined {
  if (v !== undefined && typeof v !== 'boolean') throw new PerchError(`${field} must be a boolean`, 'bad_argument');
  return v;
}

function parentList(v: unknown, field: string): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > MAX_PARENTS) throw new PerchError(`${field} must be a list of up to ${MAX_PARENTS} folder ids`, 'bad_argument');
  return v.map((x) => optId(x, field)!);
}

/** multipart/related body for Drive's multipart upload: JSON metadata, then the media. */
function multipart(metadata: Record<string, unknown>, mime: string, data: Buffer): { contentType: string; data: Buffer } {
  let boundary = `perch-${randomBytes(16).toString('hex')}`;
  while (data.includes(boundary)) boundary = `perch-${randomBytes(16).toString('hex')}`;
  const head = Buffer.from(
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n` +
      `--${boundary}\r\nContent-Type: ${mime}\r\n\r\n`,
    'utf8',
  );
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
  return { contentType: `multipart/related; boundary=${boundary}`, data: Buffer.concat([head, data, tail]) };
}

const bindingParts = (a: GoogleAccount) => ['drive', a.id, a.email.toLowerCase(), a.createdAt];

interface Prepared {
  canonical: unknown[];
  /** Builds the single provider call; the access token is fetched only after every pre-check passed. */
  call: (auth: Record<string, string>) => CallOptions;
}

export class DriveWriteService {
  constructor(
    private readonly store: CredentialStore,
    private readonly upstream: Upstream,
    private readonly tokens: GoogleTokenProvider,
    private readonly workflow: SendWorkflow,
    private readonly audit: AuditLog,
  ) {}

  private async account(accountId: unknown): Promise<GoogleAccount> {
    if (typeof accountId !== 'string') throw new PerchError('accountId is required', 'bad_argument');
    const a = (await this.store.read()).google.find((g) => g.id === accountId);
    if (!a) throw new PerchError(`Unknown Google account: ${accountId}`, 'unknown_account');
    return a;
  }

  /** The provider grant must include the full drive scope (read-only connections cannot write). */
  private assertWriteScope(a: GoogleAccount): void {
    if (!a.scopes.includes(DRIVE_SCOPE)) {
      throw new PerchError(
        `Google account ${a.id} was connected read-only at Google. To allow writes, reconnect it: ` +
          (a.groupId
            ? `perch google add --label "${a.label}" --services drive --allow-write (updates group ${a.groupId}, same account ids)`
            : `perch google remove ${a.id}, then perch google add --label "${a.label}" --services drive --allow-write`),
        'provider_scope_missing',
      );
    }
  }

  private async authorize(p: Principal, accountId: unknown): Promise<GoogleAccount> {
    if (typeof accountId !== 'string') throw new PerchError('accountId is required', 'bad_argument');
    assertDocsCapability(p, 'drive', accountId, 'drive_write');
    const a = await this.account(accountId);
    this.assertWriteScope(a);
    return a;
  }

  private async auth(a: GoogleAccount) {
    return { authorization: `Bearer ${await this.tokens.getAccessToken(a.id)}` };
  }

  private prov(a: GoogleAccount) {
    return { accountId: a.id, accountLabel: a.label };
  }

  // ---- idempotent creates (requestId) ------------------------------------------------------------------

  /**
   * One idempotent Drive write: authorisation, validation and the canonical payload before any I/O, then a
   * single attempt that re-checks grant, account identity and scope right before the provider call.
   */
  private async once(
    p: Principal,
    input: { accountId?: unknown; requestId?: unknown },
    op: string,
    prepare: () => Prepared,
  ): Promise<DriveWriteView & { id?: string; result?: unknown }> {
    let a: GoogleAccount | undefined;
    let prepared: Prepared | undefined;
    let response: Record<string, unknown> | undefined;
    const view = await sendMessageIdempotently({
      workflow: this.workflow,
      audit: this.audit,
      actor: actorOf(p),
      provider: 'drive',
      accountId: input?.accountId,
      prepare: async () => {
        a = await this.authorize(p, input?.accountId);
        prepared = prepare();
        return {
          accountId: a.id,
          requestId: input.requestId,
          canonical: JSON.stringify([`perch-drive-${op}-v1`, a.id, ...prepared.canonical]),
          binding: bindingParts(a),
        };
      },
      attempt: async (binding) => {
        const r = await this.attempt(p, a!.id, binding, prepared!);
        response = r.body;
        // A permission id identifies the grantee's Google account: never stored in the ledger (no recipients there).
        if (op === 'share') {
          const { providerMessageId: _grantee, ...withoutId } = r.result;
          return withoutId;
        }
        return r.result;
      },
    });
    const { providerMessageId, ...rest } = view;
    const fixed = rest.status === 'accepted' && !rest.replayed ? { ...rest, detail: 'Done (accepted by Google Drive).' } : rest;
    return {
      ...this.prov(a!),
      ...fixed,
      ...(providerMessageId ? { id: providerMessageId } : typeof response?.id === 'string' ? { id: response.id } : {}),
      ...(response ? { result: response } : {}),
    };
  }

  private async attempt(p: Principal, accountId: string, binding: string, prepared: Prepared): Promise<{ result: MessageSendResult; body?: Record<string, unknown> }> {
    const notDone = (detail: string, reason: MessageSendResult['reason']) => ({ result: { status: 'rejected' as const, detail: `Not done: ${detail}`, reason } });
    try {
      assertDocsCapability(await currentPrincipal(this.store, p), 'drive', accountId, 'drive_write');
    } catch (err) {
      return notDone(err instanceof PerchError ? err.message : 'the request is no longer authorised', 'not_submitted_authorization');
    }
    const current = (await this.store.read()).google.find((g) => g.id === accountId);
    if (!current || (await this.workflow.binding(bindingParts(current))) !== binding) {
      return notDone('the account was removed or reconnected since this requestId was first used', 'not_submitted_account_changed');
    }
    let call: CallOptions;
    try {
      this.assertWriteScope(current);
      call = prepared.call(await this.auth(current));
    } catch (err) {
      return notDone(err instanceof PerchError ? err.message : 'the Google access token could not be obtained', 'not_submitted_provider_precheck');
    }
    let body: Record<string, unknown>;
    try {
      body = await this.upstream.json<Record<string, unknown>>('drive', call);
    } catch (err) {
      if (err instanceof UpstreamError && err.status < 500) return notDone(`Google Drive refused the request (HTTP ${err.status}${err.upstreamCode ? `, ${err.upstreamCode}` : ''})`, 'provider_rejected');
      if (err instanceof PerchError && err.code === 'route_not_allowed') return notDone(err.message, 'not_submitted_provider_precheck');
      return { result: { status: 'indeterminate', detail: 'The request to Google Drive failed after it may have been processed; the outcome is unknown.', reason: 'provider_unknown' } };
    }
    const id = typeof body.id === 'string' && PROVIDER_MESSAGE_ID_PATTERN.test(body.id) ? body.id : undefined;
    return { result: { status: 'accepted', detail: 'Done.', ...(id ? { providerMessageId: id } : {}), reason: 'provider_accepted' }, body };
  }

  /** Uploads a file (multipart, at most 10 MiB). */
  upload(p: Principal, input: { accountId: string; name: string; parentId?: string; mimeType?: string; contentBase64: string; requestId: string }) {
    return this.once(p, input, 'upload', () => {
      const n = name(input.name);
      const parent = optId(input.parentId, 'parentId');
      const mime = mimeOf(input.mimeType, 'application/octet-stream');
      const data = decodeContent(input.contentBase64);
      return {
        canonical: [n, parent ?? null, mime, sha256(data), data.length],
        call: (auth) => ({
          method: 'POST',
          path: '/upload/drive/v3/files',
          capability: 'drive_write',
          headers: auth,
          query: { uploadType: 'multipart', supportsAllDrives: true, fields: FILE_FIELDS },
          bytes: multipart({ name: n, mimeType: mime, ...(parent ? { parents: [parent] } : {}) }, mime, data),
        }),
      };
    });
  }

  createFolder(p: Principal, input: { accountId: string; name: string; parentId?: string; requestId: string }) {
    return this.once(p, input, 'folder', () => {
      const n = name(input.name);
      const parent = optId(input.parentId, 'parentId');
      return {
        canonical: [n, parent ?? null],
        call: (auth) => ({
          method: 'POST',
          path: '/drive/v3/files',
          capability: 'drive_write',
          headers: auth,
          query: { supportsAllDrives: true, fields: FILE_FIELDS },
          json: { name: n, mimeType: FOLDER, ...(parent ? { parents: [parent] } : {}) },
        }),
      };
    });
  }

  /** Google Doc/Sheet/Slides, empty or converted by Drive from plain text (doc) or CSV (sheet). */
  createDocument(p: Principal, input: { accountId: string; kind: string; name: string; parentId?: string; content?: string; requestId: string }) {
    return this.once(p, input, 'document', () => {
      if (!(DOCUMENT_KINDS as readonly string[]).includes(input.kind)) throw new PerchError(`kind must be one of ${DOCUMENT_KINDS.join(', ')}`, 'bad_argument');
      const kind = input.kind as (typeof DOCUMENT_KINDS)[number];
      const n = name(input.name);
      const parent = optId(input.parentId, 'parentId');
      if (input.content !== undefined && typeof input.content !== 'string') throw new PerchError('content must be a string', 'bad_argument');
      if (input.content !== undefined && kind === 'slides') throw new PerchError('Initial content is supported for doc (text) and sheet (CSV) only', 'bad_argument');
      const content = input.content === undefined ? undefined : Buffer.from(input.content, 'utf8');
      if (content && content.length > MAX_UPLOAD_BYTES) throw new PerchError(`content exceeds ${MAX_UPLOAD_BYTES} bytes`, 'file_too_large');
      const metadata = { name: n, mimeType: NATIVE[kind], ...(parent ? { parents: [parent] } : {}) };
      return {
        canonical: [kind, n, parent ?? null, content ? sha256(content) : null],
        call: (auth): CallOptions =>
          content
            ? {
                method: 'POST',
                path: '/upload/drive/v3/files',
                capability: 'drive_write',
                headers: auth,
                query: { uploadType: 'multipart', supportsAllDrives: true, fields: FILE_FIELDS },
                bytes: multipart(metadata, kind === 'sheet' ? 'text/csv' : 'text/plain', content),
              }
            : {
                method: 'POST',
                path: '/drive/v3/files',
                capability: 'drive_write',
                headers: auth,
                query: { supportsAllDrives: true, fields: FILE_FIELDS },
                json: metadata,
              },
      };
    });
  }

  copy(p: Principal, input: { accountId: string; fileId: string; name?: string; parentId?: string; requestId: string }) {
    return this.once(p, input, 'copy', () => {
      const fileId = fileIdOf(input.fileId);
      const n = input.name === undefined ? undefined : name(input.name);
      const parent = optId(input.parentId, 'parentId');
      return {
        canonical: [fileId, n ?? null, parent ?? null],
        call: (auth) => ({
          method: 'POST',
          path: `/drive/v3/files/${fileId}/copy`,
          capability: 'drive_write',
          headers: auth,
          query: { supportsAllDrives: true, fields: FILE_FIELDS },
          json: { ...(n ? { name: n } : {}), ...(parent ? { parents: [parent] } : {}) },
        }),
      };
    });
  }

  /** Adds a permission (never owner; no ownership transfer). */
  share(
    p: Principal,
    input: {
      accountId: string;
      fileId: string;
      type: string;
      role: string;
      emailAddress?: string;
      domain?: string;
      sendNotificationEmail?: boolean;
      allowFileDiscovery?: boolean;
      requestId: string;
    },
  ) {
    return this.once(p, input, 'share', () => {
      const fileId = fileIdOf(input.fileId);
      if (!(SHARE_TYPES as readonly string[]).includes(input.type)) throw new PerchError(`type must be one of ${SHARE_TYPES.join(', ')}`, 'bad_argument');
      if (!(SHARE_ROLES as readonly string[]).includes(input.role)) {
        throw new PerchError(`role must be one of ${SHARE_ROLES.join(', ')} (Perch never grants or transfers ownership)`, 'bad_argument');
      }
      const type = input.type as ShareType;
      const role = input.role as ShareRole;
      const person = type === 'user' || type === 'group';
      if (person !== (input.emailAddress !== undefined)) throw new PerchError('emailAddress is required for type user/group and not allowed otherwise', 'bad_argument');
      if ((type === 'domain') !== (input.domain !== undefined)) throw new PerchError('domain is required for type domain and not allowed otherwise', 'bad_argument');
      if (person && (typeof input.emailAddress !== 'string' || input.emailAddress.length > 320 || !EMAIL.test(input.emailAddress))) {
        throw new PerchError('Invalid emailAddress', 'bad_argument');
      }
      if (type === 'domain' && (typeof input.domain !== 'string' || !DOMAIN.test(input.domain))) throw new PerchError('Invalid domain', 'bad_argument');
      const notify = optBool(input.sendNotificationEmail, 'sendNotificationEmail');
      const discovery = optBool(input.allowFileDiscovery, 'allowFileDiscovery');
      if (notify !== undefined && !person) throw new PerchError('sendNotificationEmail applies to type user/group only', 'bad_argument');
      if (discovery !== undefined && person) throw new PerchError('allowFileDiscovery applies to type domain/anyone only', 'bad_argument');
      const body = {
        type,
        role,
        ...(person ? { emailAddress: input.emailAddress } : {}),
        ...(type === 'domain' ? { domain: input.domain!.toLowerCase() } : {}),
        ...(discovery !== undefined ? { allowFileDiscovery: discovery } : {}),
      };
      return {
        canonical: [fileId, body, notify ?? null],
        call: (auth) => ({
          method: 'POST',
          path: `/drive/v3/files/${fileId}/permissions`,
          capability: 'drive_write',
          headers: auth,
          query: {
            supportsAllDrives: true,
            fields: 'id,type,role,emailAddress,domain,allowFileDiscovery',
            ...(notify !== undefined ? { sendNotificationEmail: notify } : {}),
          },
          json: body,
        }),
      };
    });
  }

  addComment(p: Principal, input: { accountId: string; fileId: string; content: string; requestId: string }) {
    return this.once(p, input, 'comment', () => {
      const fileId = fileIdOf(input.fileId);
      if (typeof input.content !== 'string' || !input.content.trim()) throw new PerchError('content must not be empty', 'bad_argument');
      if (input.content.length > MAX_COMMENT_LENGTH) throw new PerchError(`content exceeds ${MAX_COMMENT_LENGTH} characters`, 'bad_argument');
      return {
        canonical: [fileId, input.content],
        call: (auth) => ({
          method: 'POST',
          path: `/drive/v3/files/${fileId}/comments`,
          capability: 'drive_write',
          headers: auth,
          query: { fields: 'id,content,createdTime' },
          json: { content: input.content },
        }),
      };
    });
  }

  // ---- plain edits (audited by the runner) ------------------------------------------------------------

  /**
   * Validates, then re-resolves the grant immediately before the single provider call. Every pre-check
   * failure means nothing was sent to Google.
   */
  private async edit(
    p: Principal,
    accountId: unknown,
    build: () => (auth: Record<string, string>) => CallOptions,
    precheck?: (auth: Record<string, string>) => Promise<void>,
  ) {
    const a = await this.authorize(p, accountId);
    const call = build();
    const auth = await this.auth(a);
    if (precheck) await precheck(auth);
    assertDocsCapability(await currentPrincipal(this.store, p), 'drive', a.id, 'drive_write');
    const opts = call(auth);
    // DELETE answers 204 without a body.
    const body = opts.method === 'DELETE' ? (await this.upstream.raw('drive', opts), {}) : await this.upstream.json<Record<string, unknown>>('drive', opts);
    return { ...this.prov(a), ...body };
  }

  updateContent(p: Principal, input: { accountId: string; fileId: string; contentBase64: string; mimeType?: string }) {
    return this.edit(p, input?.accountId, () => {
      const fileId = fileIdOf(input.fileId);
      const mime = mimeOf(input.mimeType, 'application/octet-stream');
      const data = decodeContent(input.contentBase64);
      return (auth) => ({
        method: 'PATCH',
        path: `/upload/drive/v3/files/${fileId}`,
        capability: 'drive_write',
        headers: auth,
        query: { uploadType: 'media', supportsAllDrives: true, fields: FILE_FIELDS },
        bytes: { contentType: mime, data },
      });
    });
  }

  /**
   * driveId of a file or folder ('' for My Drive). Moving an existing file into another drive (a shared drive
   * the user does not own, possibly in another organisation) hands ownership to that drive, whose organisers
   * could then delete it for good: Perch refuses such moves.
   */
  private async driveIdOf(auth: Record<string, string>, id: string): Promise<string> {
    const meta = await this.upstream.json<{ driveId?: unknown }>('drive', {
      method: 'GET',
      path: `/drive/v3/files/${id}`,
      headers: auth,
      query: { supportsAllDrives: true, fields: 'id,driveId' },
    });
    return typeof meta.driveId === 'string' ? meta.driveId : '';
  }

  /** Rename, change the description, or move (addParents/removeParents) within the file's own drive. */
  updateFile(p: Principal, input: { accountId: string; fileId: string; name?: string; description?: string; addParents?: string[]; removeParents?: string[] }) {
    const moveCheck = async (auth: Record<string, string>) => {
      const add = parentList(input.addParents, 'addParents');
      if (!add.length) return;
      const own = await this.driveIdOf(auth, fileIdOf(input.fileId));
      for (const parent of add) {
        if ((await this.driveIdOf(auth, parent)) !== own) {
          throw new PerchError(
            'Moving a file into another drive (e.g. a shared drive) transfers it to that drive; Perch only moves files within their own drive. Copy it instead.',
            'not_permitted',
          );
        }
      }
    };
    return this.edit(p, input?.accountId, () => {
      const fileId = fileIdOf(input.fileId);
      const n = input.name === undefined ? undefined : name(input.name);
      if (input.description !== undefined && (typeof input.description !== 'string' || input.description.length > MAX_DESCRIPTION_LENGTH)) {
        throw new PerchError(`description must be a string of at most ${MAX_DESCRIPTION_LENGTH} characters`, 'bad_argument');
      }
      const add = parentList(input.addParents, 'addParents');
      const remove = parentList(input.removeParents, 'removeParents');
      if (n === undefined && input.description === undefined && !add.length && !remove.length) {
        throw new PerchError('Nothing to change: give name, description, addParents or removeParents', 'bad_argument');
      }
      return (auth) => ({
        method: 'PATCH',
        path: `/drive/v3/files/${fileId}`,
        capability: 'drive_write',
        headers: auth,
        query: {
          supportsAllDrives: true,
          fields: FILE_FIELDS,
          ...(add.length ? { addParents: add.join(',') } : {}),
          ...(remove.length ? { removeParents: remove.join(',') } : {}),
        },
        json: { ...(n !== undefined ? { name: n } : {}), ...(input.description !== undefined ? { description: input.description } : {}) },
      });
    }, moveCheck);
  }

  /** Moves to trash (trashed=true) or restores (trashed=false). Never deletes permanently. */
  setTrashed(p: Principal, input: { accountId: string; fileId: string }, trashed: boolean) {
    return this.edit(p, input?.accountId, () => {
      const fileId = fileIdOf(input.fileId);
      return (auth) => ({
        method: 'PATCH',
        path: `/drive/v3/files/${fileId}`,
        capability: 'drive_write',
        headers: auth,
        query: { supportsAllDrives: true, fields: FILE_FIELDS },
        json: { trashed },
      });
    });
  }

  /** Removes one permission (unshare). */
  async unshare(p: Principal, input: { accountId: string; fileId: string; permissionId: string }) {
    const r = await this.edit(p, input?.accountId, () => {
      const fileId = fileIdOf(input.fileId);
      const permissionId = optId(input.permissionId, 'permissionId');
      if (!permissionId) throw new PerchError('permissionId is required', 'bad_argument');
      return (auth) => ({
        method: 'DELETE',
        path: `/drive/v3/files/${fileId}/permissions/${permissionId}`,
        capability: 'drive_write',
        headers: auth,
        query: { supportsAllDrives: true },
      });
    });
    return { ...r, fileId: input.fileId, permissionId: input.permissionId, removed: true };
  }
}
