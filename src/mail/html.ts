/**
 * Plain-text rendering of untrusted HTML mail bodies, shared by the Gmail and IMAP adapters.
 *
 * A single forward scan with `indexOf` jumps and no backtracking regex, so the cost is linear in the
 * input even for hostile bodies such as '<'.repeat(2e6) or unclosed '<style' runs (the earlier
 * regex chains were quadratic on those and blocked the event loop). Scanning also stops once enough
 * text for `maxBytes` has been produced, so the work is bounded by the output limit as well.
 *
 * Display only: this is not an HTML sanitiser and the result is still untrusted content.
 */

/** Elements whose content is never shown as text. */
const HIDDEN = new Set(['head', 'script', 'style', 'template']);
/** Closing tags that end a line. `<br>` always does. */
const BLOCK = new Set(['p', 'div', 'li', 'tr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre', 'table', 'ul', 'ol']);
const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

/** Cuts `text` to at most maxBytes of UTF-8 without splitting a character. */
export function truncateUtf8(text: string, maxBytes: number): { text: string; truncated: boolean } {
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= maxBytes) return { text, truncated: false };
  let end = Math.max(0, maxBytes);
  while (end > 0 && (buf[end]! & 0xc0) === 0x80) end--;
  return { text: buf.subarray(0, end).toString('utf8'), truncated: true };
}

const isNameChar = (c: number) => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);

/** Case-insensitive ASCII match of `name` (lowercase) at `at`. */
function nameAt(html: string, at: number, name: string): boolean {
  if (at + name.length > html.length) return false;
  for (let k = 0; k < name.length; k++) if ((html.charCodeAt(at + k) | 0x20) !== name.charCodeAt(k)) return false;
  return true;
}

/** Index just past `</name ...>` from `from`, or the end of input when it is never closed. */
function skipHidden(html: string, from: number, name: string): number {
  let k = from;
  for (;;) {
    const c = html.indexOf('</', k);
    if (c === -1) return html.length;
    const after = c + 2 + name.length;
    if (nameAt(html, c + 2, name) && !isNameChar(html.charCodeAt(after))) {
      const gt = html.indexOf('>', after);
      return gt === -1 ? html.length : gt + 1;
    }
    k = c + 2;
  }
}

/** Markup-free text, at most about `limit` characters; `cut` is true when input was left unread. */
function scan(html: string, limit: number): { raw: string; cut: boolean } {
  const out: string[] = [];
  let len = 0;
  const n = html.length;
  let i = 0;
  const emit = (s: string) => {
    out.push(s);
    len += s.length;
  };
  while (i < n) {
    if (len > limit) return { raw: out.join(''), cut: true };
    const lt = html.indexOf('<', i);
    const textEnd = lt === -1 ? n : lt;
    if (textEnd > i) emit(html.slice(i, Math.min(textEnd, i + (limit - len) + 1)));
    if (len > limit) return { raw: out.join(''), cut: true };
    if (lt === -1) break;
    i = lt;
    if (html.startsWith('<!--', i)) {
      const end = html.indexOf('-->', i + 4);
      i = end === -1 ? n : end + 3;
      continue;
    }
    let j = i + 1;
    const closing = html.charCodeAt(j) === 0x2f; // '/'
    if (closing) j++;
    const nameStart = j;
    // A tag name starts with an ASCII letter ("3<4" is text).
    if (j < n && isNameChar(html.charCodeAt(j)) && (html.charCodeAt(j) | 0x20) >= 0x61) {
      while (j < n && isNameChar(html.charCodeAt(j))) j++;
    }
    if (j === nameStart) {
      const next = html[i + 1];
      if (closing || next === '!' || next === '?') {
        // </ >, <!DOCTYPE …>, <?xml …?>: markup, skipped to the next '>'.
        const gt = html.indexOf('>', i + 1);
        i = gt === -1 ? n : gt + 1;
      } else {
        emit('<'); // a literal '<' such as "a < b"
        i++;
      }
      continue;
    }
    const name = html.slice(nameStart, j).toLowerCase();
    const gt = html.indexOf('>', j);
    if (gt === -1) break; // unterminated tag: the rest is inside it
    i = gt + 1;
    if (!closing && HIDDEN.has(name)) i = skipHidden(html, i, name);
    else if (name === 'br' || (closing && BLOCK.has(name))) emit('\n');
  }
  return { raw: out.join(''), cut: false };
}

function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]{1,6}|#[0-9]{1,7}|[a-z]{2,8});/gi, (whole, e: string) => {
    if (e[0] === '#') {
      const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return cp > 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) ? String.fromCodePoint(cp) : whole;
    }
    return ENTITIES[e.toLowerCase()] ?? whole;
  });
}

/**
 * Text of an HTML body, bounded by `maxBytes` of UTF-8. `truncated` is true when the text was cut
 * at maxBytes or when scanning stopped early because enough text had been produced.
 */
export function htmlToText(html: string, maxBytes: number): { text: string; truncated: boolean } {
  // Whitespace collapsing shrinks the text afterwards, so scan some headroom past maxBytes.
  const { raw, cut } = scan(html, maxBytes * 4 + 4096);
  const text = decodeEntities(raw)
    .split('\n')
    .map((l) => l.replace(/[ \t\r\f\v ]+/g, ' ').trim())
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  const bounded = truncateUtf8(text, maxBytes);
  return { text: bounded.text, truncated: bounded.truncated || cut };
}
