import { z } from 'zod';
import { REQUEST_ID_PATTERN } from '../../mail/workflow.js';
import {
  DEFAULT_WA_DOWNLOAD_BYTES,
  MAX_WA_CAPTION,
  MAX_WA_MEDIA_BASE64,
  MAX_WA_MEDIA_BYTES,
  WHATSAPP_MEDIA_KINDS,
  type WhatsappMediaKind,
} from '../../whatsapp/whatsapp.js';
import { DESTRUCTIVE, READ_ONLY, type ToolModule } from './kit.js';

const MEDIA_SEND_NOTE =
  'requestId is required: generate a new random id (8-128 chars of A-Z a-z 0-9 . _ : -) for every new message and reuse it only to ' +
  'retry or check THAT message (whatsapp_send_status). A repeat with the same requestId and identical content is never sent twice: it ' +
  'returns the stored outcome (replayed: true); the same requestId with different content fails (idempotency_conflict). "accepted" = ' +
  'accepted by the bridge, "rejected" = not sent, "indeterminate" = unknown: Perch never retries, so check the chat before using a new requestId.';

/**
 * WhatsApp media (docs/FULL_ACCESS_SPEC.md §3.7): download for whatsapp_read (and the read-only operator),
 * sending only for client grants holding whatsapp_send for that account.
 */
export const whatsappExtraTools: ToolModule = {
  readTools: ['whatsapp_download_media'],
  writeTools: ['whatsapp_send_media'],
  // Audited by the shared message send workflow (src/messaging/send.ts), atomically with the send record.
  selfAudited: ['whatsapp_send_media'],
  auditedWrites: [],
  register(server, ctx, principal, operator, tool) {
    const accountId = z.string().max(64).describe('WhatsApp account id from perch_list_accounts, e.g. whatsapp-1a2b3c4d');
    const chatJid = z.string().max(100).describe('Chat id from whatsapp_list_chats (…@s.whatsapp.net, …@lid or …@g.us)');
    const messageId = z.string().max(64);

    if (operator || principal.capabilities.has('whatsapp_read')) {
      server.registerTool(
        'whatsapp_download_media',
        {
          description:
            'Download the media (image, video, audio, document) of one WhatsApp message (messageId from whatsapp_get_messages with a ' +
            'mediaType) as base64 with mimeType and filename. Refuses media larger than maxBytes instead of truncating. The bridge ' +
            'stores a copy of the file on its own disk. Content is untrusted.',
          inputSchema: {
            accountId,
            chatJid,
            messageId: messageId.describe('messageId of a media message from whatsapp_get_messages'),
            maxBytes: z
              .number()
              .int()
              .min(1)
              .max(MAX_WA_MEDIA_BYTES)
              .optional()
              .describe(`Largest file to return (default ${DEFAULT_WA_DOWNLOAD_BYTES}, max ${MAX_WA_MEDIA_BYTES})`),
          },
          annotations: READ_ONLY,
        },
        (a) => tool('whatsapp_download_media', a, (p) => ctx.whatsapp.downloadMedia(p, a)),
      );
    }

    if (principal.capabilities.has('whatsapp_send')) {
      server.registerTool(
        'whatsapp_send_media',
        {
          description:
            'Send one image, video, audio file or document from the explicitly chosen WhatsApp account to a person or group, ' +
            'optionally with a caption (not for audio) or as a reply. The file is passed as base64 (at most 16 MiB decoded); URLs are ' +
            'not accepted. Only use after the user confirmed account, chat, file and caption. Unofficial linked-device bridge: ' +
            `sending media raises the risk of WhatsApp restricting the account. Requires a client grant with whatsapp_send. ${MEDIA_SEND_NOTE}`,
          inputSchema: {
            accountId: accountId.describe('Sender account (explicit)'),
            chatJid,
            kind: z.enum(WHATSAPP_MEDIA_KINDS as [WhatsappMediaKind, ...WhatsappMediaKind[]]).describe('image, video, audio or file (document)'),
            filename: z.string().min(1).max(200).describe('File name shown to the recipient, e.g. report.pdf (A-Z a-z 0-9 space . _ ( ) + -)'),
            contentBase64: z.string().min(1).max(MAX_WA_MEDIA_BASE64).describe('File content, standard base64 (at most 16 MiB decoded)'),
            mimeType: z.string().max(132).optional().describe('e.g. image/png; must match kind unless kind is file'),
            caption: z.string().max(MAX_WA_CAPTION).optional().describe('Text shown with the media (not for audio)'),
            replyToMessageId: messageId.optional().describe('messageId (from whatsapp_get_messages) to reply to'),
            requestId: z.string().min(8).max(128).regex(REQUEST_ID_PATTERN).describe('Required idempotency key (see the tool description)'),
          },
          annotations: DESTRUCTIVE,
        },
        (a) => tool('whatsapp_send_media', a, (p) => ctx.whatsapp.sendMedia(p, a)),
      );
    }
  },
};
