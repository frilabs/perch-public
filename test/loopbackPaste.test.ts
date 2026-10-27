// Login without a tunnel (docs/GUIDED_PROVIDER_SETUP_SPEC.md §2): the pasted redirect address races the loopback
// callback. Local only; the code exchange is a MOCK callback and every code is dummy data.
import { request } from 'node:http';
import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { readPastedLineFromTty, type TtyInput } from '../src/cli/prompt.js';
import { parsePastedRedirect, runPkceLoopback, type PasteRedirect } from '../src/oauth/loopback.js';
import { dummySecret } from './support/fixtures.js';

function get(url: string) {
  return new Promise<number>((resolve, reject) => {
    const u = new URL(url);
    const req = request({ host: '127.0.0.1', port: u.port, path: u.pathname + u.search, method: 'GET' }, (res) => {
      res.resume();
      resolve(res.statusCode!);
    });
    req.on('error', reject);
    req.end();
  });
}

const STATE = 'state-abc_DEF-123';
const expected = { port: 8766, callbackPath: '/oauth2/callback', state: STATE, provider: 'Google' };

describe('parsePastedRedirect', () => {
  it('takes the code from a correct address on any loopback host (scheme optional)', () => {
    expect(parsePastedRedirect(`http://127.0.0.1:8766/oauth2/callback?state=${STATE}&code=C1&scope=x`, expected)).toBe('C1');
    expect(parsePastedRedirect(`  http://localhost:8766/oauth2/callback?code=C2&state=${STATE}\n`, expected)).toBe('C2');
    expect(parsePastedRedirect(`http://[::1]:8766/oauth2/callback?code=C3&state=${STATE}`, expected)).toBe('C3');
    expect(parsePastedRedirect(`127.0.0.1:8766/oauth2/callback?code=C4&state=${STATE}`, expected)).toBe('C4');
  });

  it.each([
    ['a wrong state', `http://127.0.0.1:8766/oauth2/callback?state=other&code=SECRETCODE`, /state does not match/],
    ['no state', `http://127.0.0.1:8766/oauth2/callback?code=SECRETCODE`, /state does not match/],
    ['a foreign host', `http://evil.example:8766/oauth2/callback?state=${STATE}&code=SECRETCODE`, /127\.0\.0\.1 or localhost/],
    ['a lookalike host', `http://127.0.0.1.evil.example:8766/oauth2/callback?state=${STATE}&code=SECRETCODE`, /127\.0\.0\.1 or localhost/],
    ['a wrong port', `http://127.0.0.1:8767/oauth2/callback?state=${STATE}&code=SECRETCODE`, /port 8766/],
    ['no port', `http://127.0.0.1/oauth2/callback?state=${STATE}&code=SECRETCODE`, /port 8766/],
    ['a wrong path', `http://127.0.0.1:8766/other?state=${STATE}&code=SECRETCODE`, /path must be \/oauth2\/callback/],
    ['https', `https://127.0.0.1:8766/oauth2/callback?state=${STATE}&code=SECRETCODE`, /http:\/\//],
    ['credentials', `http://u:p@127.0.0.1:8766/oauth2/callback?state=${STATE}&code=SECRETCODE`, /user name/],
    ['no code', `http://127.0.0.1:8766/oauth2/callback?state=${STATE}`, /no authorization code/],
    ['garbage', 'not an address at all ::', /not a web address|127\.0\.0\.1/],
    ['nothing', '   ', /empty/],
  ])('refuses %s without repeating the address', (_n, raw, msg) => {
    let e: Error | undefined;
    try {
      parsePastedRedirect(raw, expected);
    } catch (x) {
      e = x as Error;
    }
    expect(e?.message).toMatch(msg);
    expect(e?.message).not.toContain('SECRETCODE');
    expect((e as { code?: string }).code).toBe('paste_rejected');
  });

  it('reports error= (with the right state) as a denial', () => {
    expect(() => parsePastedRedirect(`http://127.0.0.1:8766/oauth2/callback?state=${STATE}&error=access_denied`, expected)).toThrow(
      /Google authorization failed: access_denied/,
    );
    expect(() => parsePastedRedirect(`http://127.0.0.1:8766/oauth2/callback?state=${STATE}&error=<b>`, expected)).toThrow(/unknown_error/);
  });
});

/** Starts a flow; `paste` gets the auth URL so the test can build the address the browser would show. */
function startFlow(paste: (authUrl: URL) => PasteRedirect | undefined) {
  let resolveUrl!: (u: URL) => void;
  const authUrl = new Promise<URL>((r) => (resolveUrl = r));
  const exchanged: string[] = [];
  let pasteImpl: PasteRedirect | undefined;
  const flow = runPkceLoopback({
    provider: 'Google',
    authEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    authParams: { client_id: 'dummy', scope: 's' },
    redirectHost: '127.0.0.1',
    callbackPath: '/oauth2/callback',
    timeoutMs: 5000,
    onAuthUrl: (u) => {
      const url = new URL(u);
      pasteImpl = paste(url);
      resolveUrl(url);
    },
    paste: {
      read: (signal) => pasteImpl!.read(signal),
      onRejected: (r) => pasteImpl!.onRejected?.(r),
    },
    exchange: async (code) => (exchanged.push(code), 'ok'),
  });
  flow.catch(() => {});
  return { flow, authUrl, exchanged };
}

const redirectOf = (u: URL) => new URL(u.searchParams.get('redirect_uri')!);

describe('runPkceLoopback with a pasted address', () => {
  it('the paste wins: the code is exchanged and the callback port is closed', async () => {
    const code = dummySecret('CODE');
    const { flow, authUrl, exchanged } = startFlow((u) => ({
      read: async () => `${redirectOf(u)}?state=${u.searchParams.get('state')}&code=${code}`,
    }));
    expect(await flow).toBe('ok');
    expect(exchanged).toEqual([code]);
    await expect(get(`${redirectOf(await authUrl).toString()}?state=x&code=y`)).rejects.toThrow(/ECONNREFUSED/);
  });

  it('a refused paste is reported and the next paste still works; state is checked like the callback', async () => {
    const rejected: string[] = [];
    let n = 0;
    const { flow, exchanged } = startFlow((u) => ({
      read: async () => {
        n++;
        const r = redirectOf(u);
        if (n === 1) return `${r}?state=forged&code=EVIL`;
        if (n === 2) return `http://127.0.0.1:${Number(r.port) + 1}${r.pathname}?state=${u.searchParams.get('state')}&code=EVIL`;
        return `${r}?state=${u.searchParams.get('state')}&code=GOOD`;
      },
      onRejected: (reason) => rejected.push(reason),
    }));
    expect(await flow).toBe('ok');
    expect(exchanged).toEqual(['GOOD']);
    expect(rejected).toHaveLength(2);
    expect(rejected[0]).toMatch(/state does not match/);
    expect(rejected[1]).toMatch(/port/);
  });

  it('a pasted error= ends the flow as a denial', async () => {
    const { flow, exchanged } = startFlow((u) => ({
      read: async () => `${redirectOf(u)}?state=${u.searchParams.get('state')}&error=access_denied`,
    }));
    await expect(flow).rejects.toThrow(/Google authorization failed: access_denied/);
    expect(exchanged).toEqual([]);
  });

  it('the callback wins: the pending paste is cancelled through its signal', async () => {
    let signal: AbortSignal | undefined;
    let pasteSettled = false;
    const { flow, authUrl, exchanged } = startFlow(() => ({
      read: (s) =>
        new Promise<string | undefined>((resolve) => {
          signal = s;
          s.addEventListener('abort', () => ((pasteSettled = true), resolve(undefined)));
        }),
    }));
    const u = await authUrl;
    expect(await get(`${redirectOf(u)}?state=${u.searchParams.get('state')}&code=CB`)).toBe(200);
    expect(await flow).toBe('ok');
    expect(exchanged).toEqual(['CB']);
    expect(signal?.aborted).toBe(true);
    expect(pasteSettled).toBe(true);
  });

  it('no terminal (read resolves undefined): only the callback counts', async () => {
    const { flow, authUrl } = startFlow(() => ({ read: async () => undefined }));
    const u = await authUrl;
    expect(await get(`${redirectOf(u)}?state=${u.searchParams.get('state')}&code=CB2`)).toBe(200);
    expect(await flow).toBe('ok');
  });

  it('Ctrl+C in the paste prompt aborts the flow', async () => {
    const { flow } = startFlow(() => ({
      read: async () => {
        const { PerchError } = await import('../src/errors.js');
        throw new PerchError('Aborted', 'aborted');
      },
    }));
    await expect(flow).rejects.toThrow(/Aborted/);
  });
});

function fakeTty() {
  const s = new PassThrough() as PassThrough & TtyInput & { raw: boolean[] };
  s.isTTY = true;
  s.raw = [];
  s.setRawMode = (m: boolean) => (s.raw.push(m), s);
  return s;
}

describe('readPastedLineFromTty', () => {
  it('reads one line without echo', async () => {
    const tty = fakeTty();
    let shown = '';
    const p = readPastedLineFromTty('Address: ', undefined, tty, (s) => void (shown += s));
    tty.write('http://127.0.0.1:1/cb?code=SECRET');
    tty.write('CODE\r');
    expect(await p).toBe('http://127.0.0.1:1/cb?code=SECRETCODE');
    expect(shown).toBe('Address: \n');
    expect(tty.raw).toEqual([true, false]);
  });

  it('stops reading when aborted: terminal restored, listener removed, stream paused', async () => {
    const tty = fakeTty();
    const ac = new AbortController();
    const p = readPastedLineFromTty('Address: ', ac.signal, tty, () => {});
    tty.write('http://partial');
    ac.abort();
    expect(await p).toBeUndefined();
    expect(tty.raw).toEqual([true, false]);
    expect(tty.listenerCount('data')).toBe(0);
    expect(tty.isPaused()).toBe(true);
  });

  it('resolves undefined without a terminal or when already aborted', async () => {
    expect(await readPastedLineFromTty('x', undefined, new PassThrough() as PassThrough & TtyInput, () => {})).toBeUndefined();
    const ac = new AbortController();
    ac.abort();
    expect(await readPastedLineFromTty('x', ac.signal, fakeTty(), () => {})).toBeUndefined();
  });
});
