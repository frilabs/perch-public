import type { PasteRedirect } from '../oauth/loopback.js';

/**
 * Terminal side of every loopback OAuth login (Google, Microsoft, Luma; docs/GUIDED_PROVIDER_SETUP_SPEC.md §2):
 * prints the login link and, with a terminal, also accepts the pasted address the browser could not open, so no
 * SSH tunnel is needed. The tunnel stays as the alternative.
 */
export interface LoginPromptIo {
  stderr: (s: string) => void;
  /** Hidden, cancellable one-line paste; resolves undefined without a terminal. */
  readPastedUrl?: (prompt: string, signal: AbortSignal) => Promise<string | undefined>;
}

export function loginPrompts(io: LoginPromptIo, what: string, timeoutMs: number): { onAuthUrl: (url: string) => void; paste?: PasteRedirect } {
  const canPaste = Boolean(io.readPastedUrl);
  const onAuthUrl = (url: string) => {
    const redirect = new URL(new URL(url).searchParams.get('redirect_uri')!);
    const p = redirect.port;
    io.stderr(
      `Open this URL and ${what}:\n\n${url}\n\n` +
        (canPaste
          ? `If the final page says "This site can't be reached", copy its full address and paste it here.\n`
          : `Forward the login port, then open the link:\nssh -N -L ${p}:127.0.0.1:${p} <this-server>\n`) +
        `Login expires in ${Math.round(timeoutMs / 1000)}s.\n`,
    );
  };
  const read = io.readPastedUrl;
  if (!read) return { onAuthUrl };
  return {
    onAuthUrl,
    paste: {
      read: (signal) => read('Browser address (hidden; paste, then Enter): ', signal),
      onRejected: (reason) => io.stderr(`${reason}. Paste the full browser address again.\n`),
    },
  };
}
