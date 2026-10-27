import { PerchError } from '../../errors.js';
import type { SourcePage } from '../../fanout.js';
import { DEFAULT_MAIL_MAX_BYTES, type DraftResult, type MailAttachmentContent, type MailDraftSummary, type MailFolder, type MailMessage, type MailProvider, type MailSummary, type MarkChange, type MoveTarget, type OrganizeResult, type OutgoingMime, type ReadOptions, type ReplyContext, type SearchOptions, type SendResult } from '../../mail/types.js';
import type { SessionCaller, SessionMailAccount } from './model.js';

/** The runtime owns browser/session identity; MailService checks principal grants before dispatch. */
export type MicrosoftSessionDispatch = (accountId: string, operation: string, args: unknown, options: { caller?: SessionCaller; expectedRevision: string }) => Promise<unknown>;

export class MicrosoftSessionMailProvider implements MailProvider<SessionMailAccount> {
  readonly kind = 'microsoftSession' as const;
  constructor(private readonly dispatch: MicrosoftSessionDispatch) {}

  providerCapabilities(account: SessionMailAccount) {
    return { draft: account.allowDrafts, send: account.allowSend, modify: account.allowModify };
  }
  canSendDraft(account: SessionMailAccount): boolean { return account.allowSend; }
  private allowed(account: SessionMailAccount, capability: 'draft' | 'send' | 'modify') {
    if (!this.providerCapabilities(account)[capability]) throw new PerchError(`Microsoft session ${capability} permission is not enabled for this account.`, 'provider_capability');
    if (account.caller?.kind !== 'client' || !account.caller.clientId || !account.caller.tokenSha256) throw new PerchError('Microsoft session writes require trusted client caller context.', 'capability_denied');
  }
  private call<T>(account: SessionMailAccount, operation: string, args: unknown): Promise<T> {
    return this.dispatch(account.id, operation, args, { caller: account.caller, expectedRevision: account.revision }) as Promise<T>;
  }
  search(account: SessionMailAccount, opts: SearchOptions, cursor: string | undefined): Promise<SourcePage<MailSummary>> {
    return this.call(account, 'mail.search', { ...opts, ...(cursor ? { cursor } : {}) });
  }
  read(account: SessionMailAccount, messageId: string, opts: ReadOptions): Promise<MailMessage> {
    return this.call(account, 'mail.read', { messageId, maxBytes: opts.maxBytes });
  }
  getAttachment(account: SessionMailAccount, messageId: string, attachmentId: string, opts: ReadOptions): Promise<MailAttachmentContent> {
    return this.call(account, 'mail.attachment', { messageId, attachmentId, maxBytes: opts.maxBytes });
  }
  async replyContext(account: SessionMailAccount, messageId: string): Promise<ReplyContext> {
    const message = await this.read(account, messageId, { maxBytes: DEFAULT_MAIL_MAX_BYTES });
    return { internetMessageId: message.internetMessageId, references: message.references ?? [], subject: message.subject, threadId: message.threadId };
  }
  private composition(mail: OutgoingMime) {
    if (!mail.structured) throw new PerchError('Microsoft session mail requires validated structured composition.', 'bad_argument');
    return { ...mail.structured, ...(mail.sourceMessageId ? { sourceMessageId: mail.sourceMessageId } : {}) };
  }
  async createDraft(account: SessionMailAccount, mail: OutgoingMime): Promise<DraftResult> {
    this.allowed(account, 'draft');
    return this.call(account, 'mail.createDraft', this.composition(mail));
  }
  async send(account: SessionMailAccount, mail: OutgoingMime): Promise<SendResult> {
    this.allowed(account, 'send');
    return this.call(account, 'mail.send', this.composition(mail));
  }
  async listFolders(account: SessionMailAccount): Promise<MailFolder[]> {
    const folders: MailFolder[] = [];
    const seen = new Set<string>();
    const queue: Array<{ parentId?: string; depth: number }> = [{ depth: 0 }];
    let requests = 0;
    while (queue.length) {
      const parent = queue.shift()!;
      let cursor: string | undefined;
      do {
        if (++requests > 25) throw new PerchError('Folder listing exceeds the bounded request limit.', 'response_too_large');
        const page: SourcePage<MailFolder & { childFolderCount?: number }> = await this.call(account, 'mail.listFolders', { pageSize: 50, ...(parent.parentId ? { parentId: parent.parentId } : {}), ...(cursor ? { cursor } : {}) });
        for (const folder of page.items) {
          if (seen.has(folder.folderId)) continue;
          seen.add(folder.folderId); folders.push(folder);
          if (folders.length > 500) throw new PerchError('Folder listing exceeds the 500-folder limit.', 'response_too_large');
          if ((folder.childFolderCount ?? 0) > 0) {
            if (parent.depth >= 3) throw new PerchError('Folder hierarchy exceeds the supported depth.', 'response_too_large');
            queue.push({ parentId: folder.folderId, depth: parent.depth + 1 });
          }
        }
        cursor = page.next ?? undefined;
      } while (cursor);
    }
    return folders;
  }
  async listDrafts(account: SessionMailAccount, opts: { pageSize: number }, cursor: string | undefined): Promise<SourcePage<MailDraftSummary>> {
    const page = await this.search(account, { folder: 'drafts', pageSize: opts.pageSize }, cursor);
    return { ...page, items: page.items.map((item) => ({ draftId: item.messageId, messageId: item.messageId, subject: item.subject, to: item.to, date: item.date })) };
  }
  async markMessage(account: SessionMailAccount, messageId: string, change: MarkChange): Promise<OrganizeResult> {
    this.allowed(account, 'modify'); return this.call(account, 'mail.mark', { messageId, ...change });
  }
  async moveMessage(account: SessionMailAccount, messageId: string, target: MoveTarget): Promise<OrganizeResult> {
    this.allowed(account, 'modify'); return this.call(account, 'mail.move', { messageId, ...(target.archive ? { archive: true } : { folderId: target.folderId }) });
  }
  async trashMessage(account: SessionMailAccount, messageId: string): Promise<OrganizeResult> {
    this.allowed(account, 'modify'); return this.call(account, 'mail.trash', { messageId });
  }
  async restoreMessage(account: SessionMailAccount, messageId: string): Promise<OrganizeResult> {
    this.allowed(account, 'modify'); return this.call(account, 'mail.restore', { messageId });
  }
  async sendDraft(account: SessionMailAccount, draftId: string): Promise<SendResult> {
    this.allowed(account, 'send'); return this.call(account, 'mail.sendDraft', { draftId });
  }
}
