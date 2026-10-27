import { PerchError } from '../errors.js';

/** At most this many `*` are echoed: long pasted secrets (Slack session cookie) stay on one terminal line. */
export const MAX_SECRET_ECHO = 32;

/**
 * Reads a secret from the controlling terminal without echoing it (one `*` per character, at most
 * MAX_SECRET_ECHO). Refuses to run without a TTY so secrets never come from arguments, pipes or shell history.
 */
export function readSecretFromTty(prompt: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
    return Promise.reject(new PerchError('A secret prompt needs an interactive TTY; run this command in a terminal', 'no_tty'));
  }
  return new Promise((resolve, reject) => {
    let value = '';
    process.stderr.write(prompt);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const finish = (err?: Error) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.off('data', onData);
      process.stderr.write('\n');
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return finish();
        if (ch === '\u0003' || ch === '\u0004') return finish(new PerchError('Aborted', 'aborted'));
        if (ch === '\u007f' || ch === '\b') {
          if (value.length) {
            if (value.length <= MAX_SECRET_ECHO) process.stderr.write('\b \b');
            value = value.slice(0, -1);
          }
        } else if (ch >= ' ') {
          value += ch;
          if (value.length <= MAX_SECRET_ECHO) process.stderr.write('*');
        }
      }
    };
    stdin.on('data', onData);
  });
}

/** Reads one visible line from the controlling terminal (confirmations, one-time codes). TTY only. */
export function readLineFromTty(prompt: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) return Promise.reject(new PerchError('This prompt needs an interactive TTY; run this command in a terminal', 'no_tty'));
  return new Promise((resolve, reject) => {
    let value = '';
    process.stderr.write(prompt);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (chunk: string) => {
      const i = chunk.search(/[\r\n]/);
      if (i < 0) {
        value += chunk;
        return;
      }
      value += chunk.slice(0, i);
      stdin.off('data', onData);
      stdin.off('end', onEnd);
      stdin.pause();
      resolve(value.trim());
    };
    const onEnd = () => {
      stdin.off('data', onData);
      reject(new PerchError('Aborted', 'aborted'));
    };
    stdin.on('data', onData);
    stdin.once('end', onEnd);
  });
}

/** The parts of process.stdin the cancellable prompts use (tests inject a stream). */
export interface TtyInput {
  isTTY?: boolean;
  setRawMode?: (mode: boolean) => unknown;
  resume(): unknown;
  pause(): unknown;
  setEncoding(enc: BufferEncoding): unknown;
  on(ev: 'data', fn: (chunk: string) => void): unknown;
  off(ev: 'data', fn: (chunk: string) => void): unknown;
}

interface RawReadOptions {
  signal?: AbortSignal;
  input?: TtyInput;
  write?: (s: string) => void;
  maxLength: number;
  /** Decides whether Enter ends the input (false: the newline is kept and reading goes on). */
  complete: (value: string) => boolean;
  tooLong: () => Error;
}

/**
 * Raw-mode, no-echo reader that ends on Enter (when `complete` agrees), Ctrl+C (rejects "Aborted"), Ctrl+D or
 * `signal` (both resolve undefined). It always restores the terminal and stops reading (listener removed, stream
 * paused), so a cancelled prompt never keeps the process alive.
 */
function readRaw(prompt: string, opts: RawReadOptions): Promise<string | undefined> {
  const input = opts.input ?? (process.stdin as unknown as TtyInput);
  const write = opts.write ?? ((s: string) => void process.stderr.write(s));
  if (!input.isTTY || typeof input.setRawMode !== 'function') return Promise.resolve(undefined);
  if (opts.signal?.aborted) return Promise.resolve(undefined);
  const setRaw = input.setRawMode.bind(input);
  return new Promise((resolve, reject) => {
    let value = '';
    let finished = false;
    write(prompt);
    setRaw(true);
    input.setEncoding('utf8');
    const finish = (result: { value?: string; err?: Error }) => {
      if (finished) return;
      finished = true;
      setRaw(false);
      input.off('data', onData);
      input.pause();
      opts.signal?.removeEventListener('abort', onAbort);
      write('\n');
      if (result.err) reject(result.err);
      else resolve(result.value);
    };
    const onAbort = () => finish({});
    const onData = (chunk: string) => {
      for (const ch of String(chunk)) {
        if (ch === '\u0003') return finish({ err: new PerchError('Aborted', 'aborted') });
        if (ch === '\u0004') return finish({});
        if (ch === '\r' || ch === '\n') {
          if (opts.complete(value)) return finish({ value });
          value += '\n';
        } else if (ch === '\u007f' || ch === '\b') {
          value = value.slice(0, -1);
        } else if (ch >= ' ' || ch === '\t') {
          value += ch;
        }
        if (value.length > opts.maxLength) return finish({ err: opts.tooLong() });
      }
    };
    input.on('data', onData);
    input.resume();
    opts.signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Reads one pasted line without echo (the redirect address carries an authorization code). Resolves undefined
 * without a terminal, on Ctrl+D or when `signal` aborts (the loopback callback won); Ctrl+C rejects.
 */
export function readPastedLineFromTty(prompt: string, signal?: AbortSignal, input?: TtyInput, write?: (s: string) => void): Promise<string | undefined> {
  return readRaw(prompt, {
    ...(signal ? { signal } : {}),
    ...(input ? { input } : {}),
    ...(write ? { write } : {}),
    maxLength: 16 * 1024,
    complete: () => true,
    tooLong: () => new PerchError('The pasted address is too long', 'paste_too_long'),
  });
}

/**
 * True when Enter should end a JSON paste: nothing JSON-like started yet, or every brace/bracket opened outside a
 * string is closed again. Keeps reading a JSON document that arrives over several lines.
 */
export function jsonBlockComplete(text: string): boolean {
  let depth = 0;
  let started = false;
  let inString = false;
  let escaped = false;
  for (const ch of text) {
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
    } else if (ch === '"') inString = true;
    else if (ch === '{' || ch === '[') {
      depth++;
      started = true;
    } else if (ch === '}' || ch === ']') depth--;
  }
  return !started || (depth <= 0 && !inString);
}

/**
 * Reads a pasted secret JSON document without echo (e.g. the Google client file, whose client_secret is a secret).
 * A single-line paste ends on Enter; a multi-line paste is read until its closing brace. Rejects without a
 * terminal (no_tty), on Ctrl+C/Ctrl+D (aborted) and above `maxBytes` characters (too_large).
 */
export async function readSecretJsonFromTty(prompt: string, maxBytes: number, input?: TtyInput, write?: (s: string) => void): Promise<string> {
  const stdin = input ?? (process.stdin as unknown as TtyInput);
  if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
    throw new PerchError('A secret prompt needs an interactive TTY; run this command in a terminal', 'no_tty');
  }
  const value = await readRaw(prompt, {
    input: stdin,
    ...(write ? { write } : {}),
    maxLength: maxBytes,
    complete: jsonBlockComplete,
    tooLong: () => new PerchError(`The pasted text is larger than ${maxBytes} bytes; paste only the downloaded client JSON`, 'too_large'),
  });
  if (value === undefined) throw new PerchError('Aborted', 'aborted');
  return value;
}
