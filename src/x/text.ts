import { PerchError } from '../errors.js';

/**
 * Simplified X ("twitter-text" v3) weighted length (docs/X_SPEC.md): checked BEFORE posting so an
 * over-long post is refused locally (nothing is sent, nothing is billed). The rules, after Unicode NFC:
 * - every URL counts 23 (X shortens it to a t.co link): http(s)://… and www.…, plus bare domains on common TLDs;
 * - an emoji (one grapheme cluster with a pictographic or regional-indicator code point) counts 2;
 * - every other code point counts 1 inside the Latin/Greek/Cyrillic/… ranges of twitter-text
 *   (U+0000–U+10FF, U+2000–U+200D, U+2010–U+201F, U+2032–U+2037) and 2 elsewhere (CJK, Hangul, …).
 * Edge cases (rare URL forms, unusual emoji sequences) may count differently on X; X's own check decides
 * and such a post is then rejected by X (HTTP 4xx, not posted).
 */
export const X_MAX_WEIGHTED_LENGTH = 280;
export const X_URL_LENGTH = 23;
/** Hard upper bound on the raw input (far above anything that could fit into 280 weighted characters). */
export const X_MAX_RAW_TEXT = 4000;

const LIGHT_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x10ff],
  [0x2000, 0x200d],
  [0x2010, 0x201f],
  [0x2032, 0x2037],
];

const TLDS =
  'com|org|net|edu|gov|io|dev|app|ai|co|me|ly|gg|tv|fm|eu|uk|us|de|at|ch|fr|it|es|nl|be|se|no|dk|fi|pl|cz|info|biz|xyz|tech|site|online|blog|news|link|page';
/** Scheme or www. URLs, or bare domains on a common TLD; trailing punctuation is not part of the URL. */
const URL_RE = new RegExp(
  `(?:https?:\\/\\/[^\\s<>"]+|\\bwww\\.[^\\s<>"]+|(?<![@\\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${TLDS})\\b(?:[/?#][^\\s<>"]*)?)`,
  'giu',
);
const TRAILING = /[.,:;!?'")\]}>]+$/u;
const EMOJI = /\p{Extended_Pictographic}|\p{Regional_Indicator}/u;

const segmenter = new Intl.Segmenter('en', { granularity: 'grapheme' });

function codePointWeight(cp: number): number {
  return LIGHT_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi) ? 1 : 2;
}

function plainWeight(s: string): number {
  let n = 0;
  for (const { segment } of segmenter.segment(s)) {
    if (EMOJI.test(segment)) {
      n += 2;
      continue;
    }
    for (const ch of segment) n += codePointWeight(ch.codePointAt(0)!);
  }
  return n;
}

/** Weighted length of a post text as X counts it (simplified; see above). */
export function xWeightedLength(raw: string): number {
  const text = raw.normalize('NFC');
  let n = 0;
  let last = 0;
  for (const m of text.matchAll(URL_RE)) {
    const url = m[0].replace(TRAILING, '');
    if (!url) continue;
    n += plainWeight(text.slice(last, m.index)) + X_URL_LENGTH;
    last = m.index + url.length;
  }
  return n + plainWeight(text.slice(last));
}

/** Refuses an empty or over-long post before any request. Messages never repeat the text. */
export function assertPostableXText(text: unknown): string {
  if (typeof text !== 'string' || !text.trim()) throw new PerchError('text must not be empty', 'bad_argument');
  if (text.length > X_MAX_RAW_TEXT) throw new PerchError(`text is too long for a post (at most ${X_MAX_WEIGHTED_LENGTH} weighted characters)`, 'bad_argument');
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) throw new PerchError('text contains control characters', 'bad_argument');
  const weighted = xWeightedLength(text);
  if (weighted > X_MAX_WEIGHTED_LENGTH) {
    throw new PerchError(
      `text is ${weighted} weighted characters; X allows at most ${X_MAX_WEIGHTED_LENGTH} (URLs count ${X_URL_LENGTH}, emoji and CJK characters 2). Nothing was posted.`,
      'bad_argument',
    );
  }
  return text;
}
