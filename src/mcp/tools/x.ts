import { z } from 'zod';
import { REQUEST_ID_PATTERN } from '../../mail/workflow.js';
import { X_MAX_RAW_TEXT, X_MAX_WEIGHTED_LENGTH, X_URL_LENGTH } from '../../x/text.js';
import { DESTRUCTIVE, READ_ONLY, type ToolModule } from './kit.js';

/**
 * X (docs/X_SPEC.md): x_status for x_read (and the read-only operator); x_post and x_post_status only
 * for client grants holding x_post (never listed for the global read-only token).
 */
const POST_NOTE =
  'requestId is required: generate a new random id (8-128 chars of A-Z a-z 0-9 . _ : -) for every new post and reuse it only to ' +
  'retry or check THAT post (x_post_status). A repeat with the same requestId and identical text is never posted twice: it returns ' +
  'the stored outcome (replayed: true); the same requestId with different text fails (idempotency_conflict). "accepted" = posted, ' +
  '"rejected" = not posted (X refused it, HTTP 4xx), "indeterminate" = unknown (timeout, network or X server error): Perch never ' +
  'retries, so check the profile before posting again with a new requestId.';

export const xTools: ToolModule = {
  readTools: ['x_status'],
  writeTools: ['x_post', 'x_post_status'],
  // Audited by the shared message send workflow (src/messaging/send.ts), atomically with the send record.
  selfAudited: ['x_post'],
  auditedWrites: [],
  register(server, ctx, principal, operator, tool) {
    const accountId = z.string().max(64).describe('X account id from perch_list_accounts, e.g. x-1a2b3c4d');
    if (operator || principal.capabilities.has('x_read')) {
      server.registerTool(
        'x_status',
        {
          description:
            'Connected X account: @username, name, user id, profile URL and whether it can post. Reads only what Perch stored at ' +
            'connect time (no X API call, nothing billed).',
          inputSchema: { accountId },
          annotations: READ_ONLY,
        },
        (a) => tool('x_status', a, (p) => ctx.x.status(p, a)),
      );
    }
    if (!principal.capabilities.has('x_post')) return;
    const requestId = z.string().min(8).max(128).regex(REQUEST_ID_PATTERN).describe('Required idempotency key (see the tool description)');
    server.registerTool(
      'x_post',
      {
        description:
          'Publish a public text post on the explicitly chosen X account (no images, no replies, no threads). Only use after the user ' +
          `confirmed account and exact text. At most ${X_MAX_WEIGHTED_LENGTH} weighted characters: every URL counts ${X_URL_LENGTH}, emoji ` +
          'and CJK characters count 2 (checked before sending; borderline cases are decided by X). Returns postId and url. Each post ' +
          `is billed to the operator's X developer account. Requires a client grant with x_post. ${POST_NOTE}`,
        inputSchema: {
          accountId: accountId.describe('X account to post as (explicit)'),
          text: z.string().min(1).max(X_MAX_RAW_TEXT).describe('Post text (plain text; URLs are shortened by X)'),
          requestId,
        },
        annotations: DESTRUCTIVE,
      },
      (a) => tool('x_post', a, (p) => ctx.x.post(p, a)),
    );
    server.registerTool(
      'x_post_status',
      {
        description: 'Current outcome of one of YOUR earlier x_post calls (same client, account and requestId), without posting anything.',
        inputSchema: { accountId, requestId },
        annotations: READ_ONLY,
      },
      (a) => tool('x_post_status', a, (p) => ctx.x.postStatus(p, a)),
    );
  },
};
