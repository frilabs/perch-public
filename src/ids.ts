import { randomBytes } from 'node:crypto';
import { PerchError } from './errors.js';

/** Random, stable account id like `google-1a2b3c4d`, unique among `existing`. */
export type IdPrefix = 'google' | 'ggroup' | 'notion' | 'gmail' | 'microsoft' | 'imap' | 'client' | 'gprod' | 'slack' | 'whatsapp' | 'luma' | 'x' | 'mgroup' | 'msteams' | 'msmail' | 'mscalendar' | 'msfiles' | 'ms-site';

export function newAccountId(prefix: IdPrefix, existing: Iterable<string>): string {
  const taken = new Set(existing);
  for (;;) {
    const id = `${prefix}-${randomBytes(4).toString('hex')}`;
    if (!taken.has(id)) return id;
  }
}

export function validateLabel(label: string): string {
  const trimmed = label.trim();
  if (!trimmed || trimmed.length > 100 || /[\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new PerchError('Label must be 1-100 printable characters', 'bad_label');
  }
  return trimmed;
}
