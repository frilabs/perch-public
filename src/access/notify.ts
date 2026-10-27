import { z } from 'zod';
import { PerchError } from '../errors.js';
import { readPrivateFile } from '../secureFs.js';
import type { Upstream } from '../upstream.js';

/**
 * Optional operator notifications of the public access (Spec §8). Hints and alarms only: never a link,
 * never a token, code or content, never a request to sign in, and no way to answer (no buttons, no
 * commands back). A failing channel never blocks a pairing; the caller logs the failure.
 */
export type NoticeKind =
  | 'window_opened'
  | 'device_paired'
  | 'recovery_code_used'
  | 'totp_changed'
  | 'kill_switch'
  | 'second_pairing_attempt'
  | 'pairing_code_wrong'
  | 'pairing_locked'
  | 'refresh_reuse';

const TEXT: Record<NoticeKind, string> = {
  window_opened: 'Perch: a pairing window was opened on the server (10 minutes).',
  device_paired: 'Perch: a new device was paired.',
  recovery_code_used: 'Perch: a recovery code was used for a pairing.',
  totp_changed: 'Perch: the Perch code (TOTP) was changed; all devices were signed out.',
  kill_switch: 'Perch: public access was switched off; all devices were signed out.',
  second_pairing_attempt: 'Perch ALARM: a second sign-in attempt in the same pairing window. Both were discarded (possible phishing).',
  pairing_code_wrong: 'Perch ALARM: a wrong pairing code was entered.',
  pairing_locked: 'Perch ALARM: too many wrong Perch codes; pairing is locked for a while.',
  refresh_reuse: 'Perch ALARM: an old refresh token was reused (possibly copied). The device was signed out.',
};
const FOOTER = '\nPerch never asks you to sign in by message. Every pairing starts with perch oauth pair on your server.';

export interface Notifier {
  notify(kind: NoticeKind, detail?: string): Promise<void>;
}

export const silentNotifier: Notifier = { notify: async () => {} };

const TelegramFileSchema = z.strictObject({
  botToken: z.string().regex(/^[0-9]{5,15}:[A-Za-z0-9_-]{30,64}$/),
  chatId: z.union([z.number().int(), z.string().regex(/^-?[0-9]{1,20}$/)]),
});

/** `detail` is restricted to safe fixed-shape text (device ids, short labels); everything else is dropped. */
const SAFE_DETAIL = /^[A-Za-z0-9 ._:,()@+-]{1,120}$/;

export class TelegramNotifier implements Notifier {
  constructor(
    private readonly upstream: Upstream,
    private readonly cfg: z.infer<typeof TelegramFileSchema>,
  ) {}

  static async fromFile(file: string, upstream: Upstream): Promise<TelegramNotifier> {
    let parsed;
    try {
      parsed = TelegramFileSchema.safeParse(JSON.parse((await readPrivateFile(file)).toString('utf8')));
    } catch (err) {
      if (err instanceof PerchError) throw err;
      throw new PerchError(`${file} is not valid JSON ({"botToken": "...", "chatId": ...})`, 'bad_config');
    }
    if (!parsed.success) throw new PerchError(`${file} must contain {"botToken": "<id>:<secret>", "chatId": <number>}`, 'bad_config');
    return new TelegramNotifier(upstream, parsed.data);
  }

  async notify(kind: NoticeKind, detail?: string): Promise<void> {
    const extra = detail !== undefined && SAFE_DETAIL.test(detail) ? ` (${detail})` : '';
    await this.upstream.json('telegram', {
      method: 'POST',
      path: `/bot${this.cfg.botToken}/sendMessage`,
      json: { chat_id: this.cfg.chatId, text: `${TEXT[kind]}${extra}${FOOTER}`, disable_web_page_preview: true },
      capability: 'notify',
      maxBytes: 64 * 1024,
    });
  }
}

export const noticeText = (kind: NoticeKind) => TEXT[kind];
