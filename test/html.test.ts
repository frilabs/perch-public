// Shared bounded HTML-to-text scanner (src/mail/html.ts) used by the Gmail, Graph and IMAP adapters.
import { describe, expect, it } from 'vitest';
import { htmlToText } from '../src/mail/html.js';

describe('htmlToText (bounded linear scanner)', () => {
  it('drops head/script/style/template and comments, keeps block breaks, decodes entities', () => {
    const html =
      '<!DOCTYPE html><html><head><title>T</title><style>p{color:red}</style></head><body>' +
      '<!-- hidden --><SCRIPT type="x">alert("x")</Script ><template><p>tpl</p></template>' +
      '<p>Hello&nbsp;&amp; welcome</p><p>Line&lt;2&gt; &quot;q&quot; &#39;s&#39; &#x263A;</p>bye<br>now<BR/>end</body></html>';
    expect(htmlToText(html, 4096)).toEqual({ text: 'Hello & welcome\nLine<2> "q" \'s\' ☺\nbye\nnow\nend', truncated: false });
  });

  it('keeps a literal "<" that does not start a tag, and an entity-encoded tag stays text', () => {
    expect(htmlToText('a < b and 3<4 &lt;b&gt;', 4096).text).toBe('a < b and 3<4 <b>');
  });

  it('drops an unterminated tag, comment or raw-text element to the end (as a browser would)', () => {
    expect(htmlToText('keep<a href="x', 100).text).toBe('keep');
    expect(htmlToText('keep<!-- never closed <p>x</p>', 100).text).toBe('keep');
    expect(htmlToText('keep<style>p{} <p>x</p>', 100).text).toBe('keep');
    expect(htmlToText('a<style>x</styles></style >b', 100).text).toBe('ab');
  });

  it('does not decode invalid or surrogate code points', () => {
    expect(htmlToText('&#xD800;&#0;&#x110000;&bogus;', 100).text).toBe('&#xD800;&#0;&#x110000;&bogus;');
  });

  it('bounds the output at maxBytes on a UTF-8 boundary and flags truncation', () => {
    const r = htmlToText(`<p>${'ä'.repeat(100)}</p>`, 11);
    expect(r).toEqual({ text: 'ä'.repeat(5), truncated: true });
    expect(htmlToText('<p>short</p>', 11)).toEqual({ text: 'short', truncated: false });
  });

  it('stops scanning early on huge bodies and still reports truncation', () => {
    const r = htmlToText(`<div>${'word '.repeat(2_000_000)}</div>`, 1000);
    expect(r.truncated).toBe(true);
    expect(Buffer.byteLength(r.text)).toBeLessThanOrEqual(1000);
    expect(r.text.startsWith('word word')).toBe(true);
  });

  it('runs in linear time on adversarial input (in-process; the scanner has no backtracking)', () => {
    for (const input of ['<'.repeat(2_000_000), '<style'.repeat(300_000), '<!--'.repeat(500_000), '</'.repeat(1_000_000), '<a '.repeat(650_000), '<script>'.repeat(250_000)]) {
      const t0 = performance.now();
      const r = htmlToText(input, 4096);
      expect(performance.now() - t0).toBeLessThan(1000);
      expect(Buffer.byteLength(r.text)).toBeLessThanOrEqual(4096);
    }
  });
});
