/**
 * Terminal text helpers for the guided commands (perch connect, perch oauth pair): lines stay within 80
 * columns. Words longer than the width (URLs, commands) are never broken; they stand on their own line.
 */
export const WIDTH = 80;

/** Word-wraps `text` to `width`, prefixing every line with `indent` (the first with `first` if given). */
export function wrap(text: string, indent = '', width = WIDTH, first = indent): string {
  const out: string[] = [];
  let line = first;
  let empty = true;
  for (const word of text.split(/\s+/).filter(Boolean)) {
    if (!empty && line.length + 1 + word.length > width) {
      out.push(line);
      line = indent;
      empty = true;
    }
    line += (empty ? '' : ' ') + word;
    empty = false;
  }
  out.push(line);
  return `${out.join('\n')}\n`;
}

/** `  Label:          value`, the value wrapped under itself. */
export function field(label: string, value: string, labelWidth = 17): string {
  const head = `  ${`${label}:`.padEnd(labelWidth)}`;
  return wrap(value, ' '.repeat(head.length), WIDTH, head);
}
