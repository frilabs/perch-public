import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { PerchContext } from '../context.js';
import { PerchError } from '../errors.js';
import type { Upstream } from '../upstream.js';
import { parseBaseUrl } from './baseUrl.js';
import { ClientResolver } from './clients.js';
import { startControlServer, type ControlServer, type OpenPlan } from './control.js';
import { loadGoogleLoginClient, type GoogleLoginClient } from './google.js';
import { silentNotifier, TelegramNotifier, type Notifier } from './notify.js';
import { localPairPage, pageHeaders } from './pages.js';
import { PairingManager, type ConfirmDetails, type PairEvent } from './pairing.js';
import { createOAuthApp, startPublicServer, type OAuthApp, type RunningPublicServer } from './server.js';
import { removeClientGrant } from '../auth/grants.js';
import { PRIVATE_OAUTH_OFF } from './baseUrl.js';
import { hexEqual, isPublicLocked, OAuthStore, removePendingDevices, sha256Hex, type ListenerKind, type OAuthState } from './state.js';

/**
 * Wires OAuth for `perch serve --http` (SIMPLE_CONNECT_SPEC §1, PUBLIC_ACCESS_SPEC §1): state, pairing
 * manager, control socket, the private issuer on the local listener (if a private base URL is known), the
 * public listener (with --public) and the local pairing page (served by the local listener only).
 */
export interface AccessOptions {
  context: PerchContext;
  upstream: Upstream;
  /** Private OAuth on the local listener (PERCH_PRIVATE_BASE_URL or the tailnet name). */
  privateBaseUrl?: string;
  /** The public listener (perch serve --http --public). */
  public?: {
    baseUrl: string;
    port: number;
    googleLoginClientFile?: string;
    /** Tests inject the client directly. */
    googleClient?: GoogleLoginClient;
  };
  telegramFile?: string;
  notifier?: Notifier;
  dcrEnabled: boolean;
  trustForwarded: boolean;
  log: (line: string) => void;
}

/** Kept for the public access wiring and its tests: the public listener, optionally plus private OAuth. */
export interface PublicAccessOptions {
  baseUrl: string;
  port: number;
  context: PerchContext;
  upstream: Upstream;
  googleLoginClientFile?: string;
  googleClient?: GoogleLoginClient;
  telegramFile?: string;
  notifier?: Notifier;
  dcrEnabled: boolean;
  trustForwarded: boolean;
  privateBaseUrl?: string;
  log: (line: string) => void;
}

export interface Access {
  oauth: OAuthStore;
  pairing: PairingManager;
  publicServer?: RunningPublicServer;
  /** OAuth of the local listener (passed to startHttpServer). */
  privateOAuth?: OAuthApp;
  /** Handles /local/pair on the local listener (its own password). */
  localPair: (req: IncomingMessage, res: ServerResponse, url: URL) => Promise<void>;
  close(): Promise<void>;
}

export type PublicAccess = Access & { publicServer: RunningPublicServer };

/** Why a pairing window cannot serve the PUBLIC listener right now (null = it can). */
export function pairingBlocker(s: OAuthState, now = Date.now()): string | null {
  if (isPublicLocked(s)) return 'Public access is switched off (perch public on to enable it again).';
  if (!s.totp) return 'The Perch code (TOTP) is not set up: run perch oauth totp setup.';
  if (!s.loginAllow.length) return 'No Google account is allowed: run perch oauth login-allow add <email>.';
  if (s.pairLock && Date.parse(s.pairLock.until) > now) return `Pairing is locked after wrong Perch codes until ${s.pairLock.until}.`;
  return null;
}

export async function startPublicAccess(opts: PublicAccessOptions): Promise<PublicAccess> {
  const a = await startAccess({
    context: opts.context,
    upstream: opts.upstream,
    ...(opts.privateBaseUrl ? { privateBaseUrl: opts.privateBaseUrl } : {}),
    public: {
      baseUrl: opts.baseUrl,
      port: opts.port,
      ...(opts.googleLoginClientFile ? { googleLoginClientFile: opts.googleLoginClientFile } : {}),
      ...(opts.googleClient ? { googleClient: opts.googleClient } : {}),
    },
    ...(opts.telegramFile ? { telegramFile: opts.telegramFile } : {}),
    ...(opts.notifier ? { notifier: opts.notifier } : {}),
    dcrEnabled: opts.dcrEnabled,
    trustForwarded: opts.trustForwarded,
    log: opts.log,
  });
  return a as PublicAccess;
}

export async function startAccess(opts: AccessOptions): Promise<Access> {
  const oauth = new OAuthStore(opts.context.store);
  const publicBase = opts.public ? parseBaseUrl(opts.public.baseUrl) : undefined;
  const privateBase = opts.privateBaseUrl ? parseBaseUrl(opts.privateBaseUrl, 'PERCH_PRIVATE_BASE_URL') : undefined;
  if (publicBase && privateBase && publicBase.origin === privateBase.origin) throw new PerchError('The private and the public base URL must differ', 'bad_config');
  if (publicBase) {
    await oauth.read(); // the public listener fails closed early on a damaged state
  } else {
    // Private only: the static tokens of the local listener keep working; OAuth answers 503 until repaired.
    await oauth.read().catch(() => opts.log('perch: OAuth state is unreadable; private OAuth answers 503 until oauth.enc is restored'));
  }
  let google: GoogleLoginClient | null = null;
  if (opts.public) {
    try {
      google = opts.public.googleClient ?? (opts.public.googleLoginClientFile ? await loadGoogleLoginClient(opts.public.googleLoginClientFile, `${publicBase!.origin}/oauth/google/callback`) : null);
    } catch (err) {
      if (err instanceof PerchError && err.code === 'not_found') google = null;
      else throw err;
    }
    if (!google) throw new PerchError('Public access needs a Google sign-in client of type "Web application": run perch public setup', 'bad_config');
  }
  const notifier = opts.notifier ?? (opts.telegramFile ? await TelegramNotifier.fromFile(opts.telegramFile, opts.upstream) : silentNotifier);
  const pairing = new PairingManager();
  const clients = new ClientResolver(opts.upstream);
  const notify = (kind: Parameters<Notifier['notify']>[0], detail?: string) =>
    notifier.notify(kind, detail).catch(() => opts.log(`perch: notification ${kind} could not be delivered`));
  const audit = (type: string, outcome: 'ok' | 'denied', code?: string) =>
    opts.context.audit.record({ type, actor: { kind: 'oauth' }, outcome, ...(code ? { code } : {}) }).catch(() => opts.log('perch: could not write an OAuth audit event'));

  const privateOAuth = privateBase
    ? createOAuthApp({
        listener: 'private',
        baseUrl: privateBase.origin,
        context: opts.context,
        oauth,
        pairing,
        clients,
        upstream: opts.upstream,
        google: null,
        notifier,
        dcrEnabled: opts.dcrEnabled,
        trustForwarded: false,
        log: opts.log,
      })
    : undefined;
  if (privateOAuth) {
    try {
      privateOAuth.warm((await oauth.read()).devices);
    } catch {
      // fail closed later
    }
    opts.log(`perch: private OAuth issuer ${privateOAuth.origin} (MCP ${privateOAuth.resource}; pair with perch oauth pair)`);
  }
  // Pending devices of an earlier run can never be activated (their codes lived in memory): remove them.
  try {
    const grants = await oauth.transact((d) => removePendingDevices(d));
    for (const g of grants) await removeClientGrant(opts.context.store, g).catch(() => {});
  } catch {
    // unreadable state: fails closed later
  }
  const urls: Partial<Record<ListenerKind, string>> = {
    ...(privateOAuth ? { private: privateOAuth.resource } : {}),
    ...(publicBase ? { public: `${publicBase.origin}/mcp` } : {}),
  };

  /** Why each listener cannot pair right now (null: it can). */
  const availability = async (): Promise<Record<ListenerKind, string | null>> => {
    const s = await oauth.read();
    return {
      private: privateOAuth ? null : PRIVATE_OAUTH_OFF,
      public: publicBase ? pairingBlocker(s) : 'Public access is not running (perch serve --http --public).',
    };
  };
  const NAME: Record<ListenerKind, string> = { private: 'Private address (tailnet)', public: 'Public address (internet)' };
  /**
   * The ONE listener a new window serves: the requested one, else private when it can pair, else public.
   * Throws with the reason(s) when that is not possible.
   */
  const canOpen = async (requested?: ListenerKind): Promise<OpenPlan> => {
    const why = await availability();
    let listener: ListenerKind;
    if (requested) {
      if (why[requested]) throw new PerchError(`${NAME[requested]}: ${why[requested]}`, 'pairing_blocked');
      listener = requested;
    } else if (!why.private) listener = 'private';
    else if (!why.public) listener = 'public';
    else throw new PerchError(`${NAME.private}: ${why.private} ${NAME.public}: ${why.public}`, 'pairing_blocked');
    const other: ListenerKind = listener === 'private' ? 'public' : 'private';
    const notes = why[other] ? [] : [`This window is for the ${listener} address only. For the ${other} address open a separate window: perch oauth pair --${other}`];
    return { listener, ...(urls[listener] ? { url: urls[listener] } : {}), notes };
  };
  const onEvent = (ev: PairEvent) => {
    if (ev.type === 'opened') {
      void notify('window_opened');
      void audit('oauth_pair_window', 'ok', `opened_${ev.listener}`);
    } else if (ev.type === 'closed') {
      void audit('oauth_pair_window', ev.reason === 'consumed' ? 'ok' : 'denied', `closed_${ev.reason}`);
    }
  };

  const control: ControlServer = await startControlServer(opts.context.store.storePaths.dataDir, pairing, { canOpen, onEvent });
  let publicServer: RunningPublicServer | undefined;
  if (opts.public) {
    try {
      publicServer = await startPublicServer({
        listener: 'public',
        baseUrl: publicBase!.origin,
        port: opts.public.port,
        context: opts.context,
        oauth,
        pairing,
        clients,
        upstream: opts.upstream,
        google,
        notifier,
        dcrEnabled: opts.dcrEnabled,
        trustForwarded: opts.trustForwarded,
        log: opts.log,
      });
    } catch (err) {
      await control.close();
      throw err;
    }
  }

  // Expired authorization codes remove their pending devices; perch public off runs in another process:
  // while a public window is open, notice the marker within seconds.
  const killWatch = setInterval(() => {
    pairing.sweepCodes();
    if (pairing.openListener !== 'public' || !publicBase) return;
    oauth.read().then(
      (st) => {
        if (isPublicLocked(st)) pairing.lockout('kill_switch');
      },
      () => pairing.close('aborted'),
    );
  }, 2000);
  killWatch.unref();

  // ------------------------------------------------------------ local pairing page
  const page = {
    windowId: undefined as string | undefined,
    code: undefined as string | undefined,
    expiresAt: undefined as string | undefined,
    listener: undefined as ListenerKind | undefined,
    url: undefined as string | undefined,
    details: undefined as ConfirmDetails | undefined,
    confirmId: undefined as string | undefined,
    paired: undefined as string | undefined,
    events: [] as string[],
  };
  const csrfTokens = new Map<string, number>();
  const newCsrf = () => {
    const t = randomBytes(24).toString('base64url');
    const now = Date.now();
    for (const [k, at] of csrfTokens) if (now - at > 10 * 60 * 1000) csrfTokens.delete(k);
    while (csrfTokens.size >= 20) csrfTokens.delete(csrfTokens.keys().next().value!);
    csrfTokens.set(t, now);
    return t;
  };
  const csrfOk = (t: string) => {
    for (const k of csrfTokens.keys()) {
      const a = Buffer.from(k);
      const b = Buffer.from(t);
      if (a.length === b.length && timingSafeEqual(a, b)) {
        csrfTokens.delete(k);
        return true;
      }
    }
    return false;
  };
  const pageListener = (ev: PairEvent) => {
    onEvent(ev);
    const line = (s: string) => {
      page.events = [...page.events, `${new Date().toISOString().slice(11, 19)} ${s}`].slice(-8);
    };
    if (ev.type === 'opened') {
      page.code = ev.code;
      page.expiresAt = ev.expiresAt;
      page.listener = ev.listener;
      page.url = ev.url;
      page.details = undefined;
      page.paired = undefined;
      line(`window opened (${ev.listener})`);
    } else if (ev.type === 'progress') line(`progress (${ev.origin}): ${ev.step}`);
    else if (ev.type === 'confirm') {
      page.details = ev.details;
      page.confirmId = ev.confirmId;
      line('waiting for your confirmation');
    } else if (ev.type === 'paired') {
      page.paired = ev.deviceId;
      page.details = undefined;
      line(`paired ${ev.deviceId} (${ev.origin}, ${ev.access === 'full' ? 'full access' : 'read only'})`);
    } else if (ev.type === 'first_use') line(`first request from ${ev.deviceId}`);
    else if (ev.type === 'alarm') line(`ALARM: ${ev.kind}`);
    else if (ev.type === 'closed') {
      page.windowId = undefined;
      page.code = undefined;
      page.details = undefined;
      line(`window closed (${ev.reason})`);
    }
  };

  /**
   * The local page has its own password (perch oauth local-page enable), never the global token: an MCP
   * client holding the global token must not be able to open or confirm pairings. Disabled: 404.
   */
  const localAuth = async (req: IncomingMessage, res: ServerResponse): Promise<boolean> => {
    let s: OAuthState;
    try {
      s = await oauth.read();
    } catch {
      res.writeHead(503, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end('{"error":"temporarily_unavailable"}');
      return false;
    }
    if (!s.localPage) {
      res.writeHead(404, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end('{"error":"not_found"}');
      return false;
    }
    const m = /^Basic\s+([A-Za-z0-9+/=]{1,1024})\s*$/i.exec(String(req.headers.authorization ?? ''));
    const decoded = m ? Buffer.from(m[1]!, 'base64').toString('utf8') : '';
    const password = decoded.slice(decoded.indexOf(':') + 1);
    if (!m || decoded.indexOf(':') < 0 || !hexEqual(sha256Hex(password), s.localPage.passwordHash)) {
      res.writeHead(401, { 'www-authenticate': 'Basic realm="Perch pairing", charset="UTF-8"', 'cache-control': 'no-store' }).end();
      return false;
    }
    return true;
  };

  const localPair = async (req: IncomingMessage, res: ServerResponse) => {
    if (!(await localAuth(req, res))) return;
    let message: string | undefined;
    if (req.method === 'POST') {
      const chunks: Buffer[] = [];
      let total = 0;
      for await (const c of req) {
        total += (c as Buffer).length;
        if (total > 4096) {
          res.writeHead(413).end();
          return;
        }
        chunks.push(c as Buffer);
      }
      const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
      if (!csrfOk(form.get('csrf') ?? '')) {
        res.writeHead(403, pageHeaders()).end('Forbidden');
        return;
      }
      try {
        const action = form.get('action');
        if (action === 'open' || action === 'open_private' || action === 'open_public') {
          const plan = await canOpen(action === 'open_private' ? 'private' : action === 'open_public' ? 'public' : undefined);
          page.windowId = pairing.open(pageListener, plan.listener, { ...(plan.url ? { url: plan.url } : {}), ...(plan.notes ? { notes: plan.notes } : {}) }).windowId;
          for (const n of plan.notes ?? []) page.events = [...page.events, `note: ${n}`].slice(-8);
        } else if (action === 'approve_full') {
          // The page password is a pairing credential, not the operator's terminal: full access is granted in the
          // terminal only (perch oauth pair, or perch oauth grant <id> --full afterwards).
          throw new PerchError('Full access cannot be approved on this page; pair read only, then run perch oauth grant <id> --full on the server', 'usage');
        } else if (action === 'close' || action === 'approve' || action === 'reject') {
          // Only the window this page opened, and only the confirmation it showed. Approval here is read only.
          if (!page.windowId) throw new PerchError('This page has no open pairing window', 'nothing_to_confirm');
          if (action === 'close') pairing.close('aborted', page.windowId);
          else {
            if (!page.confirmId) throw new PerchError('Nothing is waiting for confirmation', 'nothing_to_confirm');
            pairing.answer(action === 'approve', page.windowId, page.confirmId, 'read');
            page.confirmId = undefined;
          }
        }
      } catch (err) {
        message = err instanceof PerchError ? err.message : 'Action failed';
      }
      res.writeHead(303, { location: '/local/pair', 'cache-control': 'no-store' }).end();
      if (message) page.events = [...page.events, `error: ${message}`].slice(-8);
      return;
    }
    let blocked: string | null = null;
    let can: ListenerKind[] = [];
    try {
      const why = await availability();
      can = (['private', 'public'] as const).filter((l) => !why[l]);
      if (!can.length) blocked = `${NAME.private}: ${why.private} ${NAME.public}: ${why.public}`;
    } catch (err) {
      blocked = err instanceof PerchError ? err.message : 'Pairing is not possible right now.';
    }
    const state = page.details ? 'confirm' : page.windowId ? 'open' : page.paired ? 'paired' : blocked && !pairing.isOpen ? 'locked' : 'idle';
    const shown = pairing.isOpen && !page.windowId ? 'locked' : state;
    res.writeHead(200, pageHeaders());
    res.end(
      localPairPage({
        base: privateOAuth?.origin ?? publicBase?.origin ?? 'this server',
        csrf: newCsrf(),
        state: shown,
        ...(page.code ? { code: page.code } : {}),
        ...(page.expiresAt ? { expiresAt: page.expiresAt } : {}),
        ...(page.listener ? { listener: page.listener } : {}),
        ...(page.url ? { url: page.url } : {}),
        canOpen: can,
        ...(page.details ? { details: page.details } : {}),
        ...(page.paired ? { paired: page.paired } : {}),
        ...(shown === 'locked' ? { blocked: pairing.isOpen && !page.windowId ? 'A pairing window is open in a terminal (perch oauth pair).' : (blocked ?? undefined) } : {}),
        lastEvents: page.events,
      }),
    );
  };

  return {
    oauth,
    pairing,
    ...(publicServer ? { publicServer } : {}),
    ...(privateOAuth ? { privateOAuth } : {}),
    localPair,
    close: async () => {
      clearInterval(killWatch);
      pairing.close('aborted');
      await publicServer?.close();
      await control.close();
    },
  };
}
