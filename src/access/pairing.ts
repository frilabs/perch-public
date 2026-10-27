import { randomBytes, timingSafeEqual } from 'node:crypto';
import { PerchError } from '../errors.js';
import { base32Encode } from './base32.js';
import type { DcrRegistration, ResolvedClient } from './clients.js';
import type { GoogleIdentity } from './google.js';
import type { ListenerKind } from './state.js';

/**
 * Pairing windows (PUBLIC_ACCESS_SPEC §0a, §6; SIMPLE_CONNECT_SPEC §1). Held in memory by the running server
 * only: a window exists only while the operator's `perch oauth pair` (or the local /local/pair page) holds it
 * open, for at most 10 minutes, and it pairs at most one device. Every session belongs to exactly one window.
 *
 * A window serves exactly ONE listener (private: the local listener in the tailnet, public: the internet
 * listener), chosen when it is opened; for the other listener no window exists. Code failures, sessions and
 * DCR registrations therefore count per listener. Private sessions skip Google and the Perch code, but the
 * pairing code, the locks and the operator's confirmation stay.
 *
 * An issued authorization code belongs to a `pending` device. When the code expires unused, is burnt by
 * repeated mismatching exchanges, or the window closes before the browser picked the code up, `onAbandoned`
 * removes that pending device (and its grant).
 */
export const PAIR_WINDOW_MS = 10 * 60 * 1000;
export const PAIR_CODE_MAX_FAILURES = 3;
export const MAX_DCR_PER_WINDOW = 3;
export const AUTH_CODE_TTL_MS = 60 * 1000;
/** Mismatching exchanges (client, redirect, PKCE, resource) a code survives before it is burnt. */
export const CODE_MAX_MISMATCHES = 5;
export const FIRST_USE_WAIT_MS = 5 * 60 * 1000;
const MAX_SESSIONS_PER_WINDOW = 10;

/** 'ready': a private session passed the pairing code and waits to ask for confirmation. */
export type PairStep = 'code' | 'google' | 'totp' | 'ready' | 'confirm' | 'approved' | 'done';
export type PairAccess = 'read' | 'full';

export interface AuthRequest {
  clientId: string;
  redirectUri: string;
  state?: string;
  codeChallenge: string;
  resource: string;
}

export interface PairSession {
  id: string;
  csrf: string;
  createdAt: number;
  /** Listener this session runs on. */
  origin: ListenerKind;
  auth: AuthRequest;
  client: ResolvedClient;
  step: PairStep;
  google?: { state: string; nonce: string; verifier: string };
  identity?: GoogleIdentity;
  usedRecoveryCode?: boolean;
  userAgent?: string;
  ip?: string;
  deviceId?: string;
  authCode?: string;
  /** Rights the operator chose when confirming. */
  access?: PairAccess;
}

export interface ConfirmDetails {
  origin: ListenerKind;
  clientName: string;
  clientDisplay: string;
  registration: string;
  redirectHost: string;
  /** Public pairing only. */
  googleEmail?: string;
  userAgent: string;
  ip: string;
  secondsSinceOpen: number;
  usedRecoveryCode: boolean;
}

export interface OpenInfo {
  /** MCP address of the window's listener, for the operator's terminal. */
  url?: string;
  /** Hints for the operator (e.g. how to pair over the other listener). */
  notes?: string[];
}

export type PairEvent =
  | { type: 'opened'; windowId: string; code: string; expiresAt: string; listener: ListenerKind; url?: string; notes: string[] }
  | { type: 'progress'; step: 'started' | 'code_ok' | 'google_ok' | 'totp_ok'; origin: ListenerKind }
  | { type: 'confirm'; confirmId: string; details: ConfirmDetails }
  | { type: 'paired'; deviceId: string; origin: ListenerKind; access: PairAccess }
  | { type: 'first_use'; deviceId: string }
  | { type: 'alarm'; kind: 'second_pairing_attempt' | 'pairing_code_wrong' | 'pairing_locked' }
  | { type: 'closed'; reason: CloseReason };

export type CloseReason = 'expired' | 'aborted' | 'rejected' | 'consumed' | 'second_attempt' | 'code_failures' | 'totp_lockout' | 'kill_switch' | 'replaced';

export type PairListener = (ev: PairEvent) => void;

interface PairWindow {
  id: string;
  code: string;
  openedAt: number;
  expiresAt: number;
  codeFailures: number;
  /** The one listener this window serves. */
  kind: ListenerKind;
  sessions: Map<string, PairSession>;
  /** Session that passed the pairing code (at most one per window). */
  codeSession?: string;
  dcr: Map<string, DcrRegistration>;
  /** Abandon hook of the device issued in this window (until its code is picked up by the browser). */
  abandon?: () => void;
  confirming?: { sessionId: string; confirmId: string; onAnswer: (approved: boolean, access: PairAccess) => void };
  /** A device was already issued in this window (one device per window). */
  issued: boolean;
  listener: PairListener;
  timer: NodeJS.Timeout;
}

export interface IssuedCode {
  deviceId: string;
  origin: ListenerKind;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  resource: string;
  expiresAt: number;
}

interface CodeEntry extends IssuedCode {
  mismatches: number;
  /** Removes the pending device of this code (expired, burnt or window closed before pick-up). */
  abandon: () => void;
}

const random = (bytes: number) => randomBytes(bytes).toString('base64url');

/** 8 base32 characters = 40 bits (Spec §0a item 2). */
export const newPairingCode = () => base32Encode(randomBytes(5), { pad: false });

const secondAttempt = () => new PerchError('A second sign-in attempt in this pairing window; the window was closed', 'second_pairing_attempt');

export class PairingManager {
  private window: PairWindow | null = null;
  private readonly codes = new Map<string, CodeEntry>();
  /** Exchanged codes (10 min): a second use ends the device (RFC 6749 §4.1.2). */
  private readonly usedCodes = new Map<string, { deviceId: string; until: number }>();
  /** After a pairing: who waits for the first /mcp call of which device (Gegenprobe). */
  private readonly firstUseWatch = new Map<string, { listener: PairListener; until: number }>();

  constructor(private readonly now: () => number = Date.now) {}

  /** A window is open (for any listener). */
  get isOpen(): boolean {
    this.expireIfDue();
    return this.window !== null;
  }

  /** A window is open for this listener. */
  isOpenFor(kind: ListenerKind): boolean {
    this.expireIfDue();
    return this.window !== null && this.window.kind === kind;
  }

  /** Listener of the open window, if any. */
  get openListener(): ListenerKind | undefined {
    this.expireIfDue();
    return this.window?.kind;
  }

  /** Opens the (single) window for exactly one listener. A second open while one is open is refused. */
  open(listener: PairListener, kind: ListenerKind = 'public', info: OpenInfo = {}): { windowId: string; code: string; expiresAt: number } {
    this.expireIfDue();
    if (this.window) throw new PerchError('A pairing window is already open (only one at a time)', 'pairing_busy');
    if (kind !== 'private' && kind !== 'public') throw new PerchError('A pairing window serves the private or the public listener', 'pairing_blocked');
    const openedAt = this.now();
    const w: PairWindow = {
      id: random(9),
      code: newPairingCode(),
      openedAt,
      expiresAt: openedAt + PAIR_WINDOW_MS,
      codeFailures: 0,
      kind,
      sessions: new Map(),
      dcr: new Map(),
      issued: false,
      listener,
      timer: setTimeout(() => this.close('expired'), PAIR_WINDOW_MS),
    };
    w.timer.unref?.();
    this.window = w;
    listener({
      type: 'opened',
      windowId: w.id,
      code: w.code,
      expiresAt: new Date(w.expiresAt).toISOString(),
      listener: kind,
      ...(info.url ? { url: info.url } : {}),
      notes: info.notes ?? [],
    });
    return { windowId: w.id, code: w.code, expiresAt: w.expiresAt };
  }

  /** Closes the window (if any, optionally only if it is `windowId`) and discards its sessions. */
  close(reason: CloseReason, windowId?: string): void {
    const w = this.window;
    if (!w || (windowId !== undefined && w.id !== windowId)) return;
    clearTimeout(w.timer);
    this.window = null;
    w.confirming?.onAnswer(false, 'read');
    // Closed before the browser picked its code up: the pending device must not survive the window.
    if (reason !== 'consumed') w.abandon?.();
    w.listener({ type: 'closed', reason });
  }

  private expireIfDue(): void {
    if (this.window && this.now() >= this.window.expiresAt) this.close('expired');
  }

  private emit(ev: PairEvent): void {
    this.window?.listener(ev);
  }

  /** DCR registrations of the open window, if it serves this listener (empty map otherwise). */
  dcrRegistrations(kind: ListenerKind = 'public'): ReadonlyMap<string, DcrRegistration> {
    this.expireIfDue();
    return this.isOpenFor(kind) ? new Map(this.window!.dcr) : new Map();
  }

  addDcr(reg: DcrRegistration, kind: ListenerKind = 'public'): void {
    this.expireIfDue();
    const w = this.window;
    if (!w || !this.isOpenFor(kind)) throw new PerchError('No pairing window is open', 'no_pairing_window');
    if (w.dcr.size >= MAX_DCR_PER_WINDOW) throw new PerchError('Too many registrations in this pairing window', 'too_many_registrations');
    w.dcr.set(reg.clientId, reg);
  }

  /**
   * Starts (or restarts, for the same browser) a session for an authorization request. A different
   * browser session while another one already passed the pairing code closes the window (Spec §6 step 3).
   */
  startSession(
    existingId: string | undefined,
    input: { auth: AuthRequest; client: ResolvedClient; userAgent?: string; ip?: string; origin?: ListenerKind },
  ): PairSession {
    this.expireIfDue();
    const origin = input.origin ?? 'public';
    const w = this.window;
    if (!w || !this.isOpenFor(origin)) throw new PerchError('No pairing window is open', 'no_pairing_window');
    const same = existingId !== undefined ? w.sessions.get(existingId) : undefined;
    if (!same && w.codeSession !== undefined) {
      this.alarmSecondAttempt();
      throw secondAttempt();
    }
    if (same && w.codeSession === same.id) {
      // The browser that passed the pairing code started over: never reset its progress (that would let
      // another browser join without an alarm). The window is closed; the operator opens a new one.
      this.close('replaced');
      throw new PerchError('This sign-in was started again after the pairing code; the window was closed. Open a new one.', 'pairing_restarted');
    }
    if (!same && w.sessions.size >= MAX_SESSIONS_PER_WINDOW) throw new PerchError('Too many sign-in attempts in this pairing window', 'too_many_sessions');
    const session: PairSession = {
      id: same?.id ?? random(24),
      csrf: random(24),
      createdAt: this.now(),
      origin,
      auth: input.auth,
      client: input.client,
      step: 'code',
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
      ...(input.ip ? { ip: input.ip } : {}),
    };
    w.sessions.set(session.id, session);
    this.emit({ type: 'progress', step: 'started', origin });
    return session;
  }

  /** Session of the open window on this listener, or null (unknown, other window/listener, or no window). */
  session(id: string | undefined, kind: ListenerKind = 'public'): PairSession | null {
    this.expireIfDue();
    if (!id || !this.window || !this.isOpenFor(kind)) return null;
    const s = this.window.sessions.get(id);
    return s && s.origin === kind ? s : null;
  }

  private alarmSecondAttempt(): void {
    this.emit({ type: 'alarm', kind: 'second_pairing_attempt' });
    this.close('second_attempt');
  }

  /**
   * Step 4: pairing code. Wrong codes count per window (= per listener); the third closes it.
   */
  submitPairingCode(s: PairSession, code: string): boolean {
    const w = this.window;
    if (!w || !w.sessions.has(s.id) || s.step !== 'code' || !this.isOpenFor(s.origin)) throw new PerchError('This sign-in is no longer valid', 'pairing_session_invalid');
    const given = Buffer.from(code.replace(/[\s-]/g, '').toUpperCase());
    const expected = Buffer.from(w.code);
    const ok = given.length === expected.length && timingSafeEqual(given, expected);
    if (!ok) {
      w.codeFailures++;
      this.emit({ type: 'alarm', kind: 'pairing_code_wrong' });
      if (w.codeFailures >= PAIR_CODE_MAX_FAILURES) this.close('code_failures');
      return false;
    }
    if (w.codeSession !== undefined && w.codeSession !== s.id) {
      this.alarmSecondAttempt();
      throw secondAttempt();
    }
    w.codeSession = s.id;
    s.step = s.origin === 'private' ? 'ready' : 'google';
    this.emit({ type: 'progress', step: 'code_ok', origin: s.origin });
    return true;
  }

  googleStarted(s: PairSession, google: NonNullable<PairSession['google']>): void {
    this.assertCurrent(s, 'google', 'public');
    s.google = google;
  }

  googleDone(s: PairSession, identity: GoogleIdentity): void {
    this.assertCurrent(s, 'google', 'public');
    s.identity = identity;
    s.google = undefined;
    s.step = 'totp';
    this.emit({ type: 'progress', step: 'google_ok', origin: s.origin });
  }

  /**
   * Public step 6 passed: asks the operator for the final confirmation (Spec §6 step 7). `onApproved` creates
   * the device (and returns its id); the authorization code is issued only after it resolves.
   */
  totpDone(s: PairSession, usedRecoveryCode: boolean, onApproved: (s: PairSession) => Promise<string>, onAbandoned: (deviceId: string) => void = () => {}): void {
    this.assertCurrent(s, 'totp', 'public');
    this.emit({ type: 'progress', step: 'totp_ok', origin: s.origin });
    this.requestConfirmation(s, usedRecoveryCode, onApproved, onAbandoned);
  }

  /** Private listener: right after the pairing code, the operator confirms (no Google, no Perch code). */
  privateCodeDone(s: PairSession, onApproved: (s: PairSession) => Promise<string>, onAbandoned: (deviceId: string) => void = () => {}): void {
    this.assertCurrent(s, 'ready', 'private');
    this.requestConfirmation(s, false, onApproved, onAbandoned);
  }

  private requestConfirmation(s: PairSession, usedRecoveryCode: boolean, onApproved: (s: PairSession) => Promise<string>, onAbandoned: (deviceId: string) => void): void {
    const w = this.window!;
    if (w.confirming || w.issued) {
      this.alarmSecondAttempt();
      throw secondAttempt();
    }
    s.usedRecoveryCode = usedRecoveryCode;
    s.step = 'confirm';
    const details: ConfirmDetails = {
      origin: s.origin,
      clientName: s.client.clientName,
      clientDisplay: s.client.displayName,
      registration: s.client.registration === 'cimd' ? `metadata document ${s.client.clientId}` : s.client.registration === 'dcr' ? 'self-registered (DCR)' : 'pre-registered',
      redirectHost: redirectHostOf(s.auth.redirectUri),
      ...(s.identity ? { googleEmail: s.identity.email } : {}),
      userAgent: s.userAgent ?? 'unknown',
      ip: s.ip ?? 'unknown',
      secondsSinceOpen: Math.round((this.now() - w.openedAt) / 1000),
      usedRecoveryCode,
    };
    const confirmId = random(12);
    w.confirming = {
      sessionId: s.id,
      confirmId,
      onAnswer: (approved, access) => {
        w.confirming = undefined;
        if (!approved) {
          if (this.window === w) this.close('rejected');
          return;
        }
        w.issued = true;
        s.access = access;
        void onApproved(s).then(
          (deviceId) => {
            if (this.window !== w) {
              onAbandoned(deviceId); // the window closed meanwhile: the device must not stay active
              return;
            }
            s.deviceId = deviceId;
            const authCode = random(32);
            s.authCode = authCode;
            let abandoned = false;
            const abandon = () => {
              if (abandoned) return;
              abandoned = true;
              this.codes.delete(authCode);
              onAbandoned(deviceId);
            };
            w.abandon = abandon;
            this.codes.set(authCode, {
              deviceId,
              origin: s.origin,
              clientId: s.auth.clientId,
              redirectUri: s.auth.redirectUri,
              codeChallenge: s.auth.codeChallenge,
              resource: s.auth.resource,
              expiresAt: this.now() + AUTH_CODE_TTL_MS,
              mismatches: 0,
              abandon,
            });
            s.step = 'approved';
            for (const [id, fw] of this.firstUseWatch) if (fw.until <= this.now()) this.firstUseWatch.delete(id);
            this.firstUseWatch.set(deviceId, { listener: w.listener, until: this.now() + FIRST_USE_WAIT_MS });
            this.emit({ type: 'paired', deviceId, origin: s.origin, access });
          },
          () => {
            if (this.window === w) this.close('aborted');
          },
        );
      },
    };
    this.emit({ type: 'confirm', confirmId, details });
  }

  /**
   * The operator's answer (control channel or local page) for exactly the confirmation they were shown
   * (window id and confirmation id from the 'confirm' event), with the rights they chose. A stale or foreign
   * answer is refused.
   */
  answer(approved: boolean, windowId: string, confirmId: string, access: PairAccess = 'read'): void {
    const w = this.window;
    if (!w || w.id !== windowId || !w.confirming || w.confirming.confirmId !== confirmId) throw new PerchError('Nothing is waiting for this confirmation', 'nothing_to_confirm');
    w.confirming.onAnswer(approved, access === 'full' ? 'full' : 'read');
  }

  /** The browser picked up its redirect: the window is consumed (the code now lives on until exchanged or expired). */
  finish(s: PairSession): void {
    if (s.step !== 'approved') return;
    s.step = 'done';
    if (this.window?.sessions.has(s.id)) {
      this.window.abandon = undefined;
      this.close('consumed');
    }
  }

  /** Drops expired authorization codes and abandons their pending devices (called often; cheap). */
  sweepCodes(): void {
    const t = this.now();
    for (const [k, v] of this.usedCodes) if (v.until <= t) this.usedCodes.delete(k);
    for (const c of [...this.codes.values()]) if (c.expiresAt <= t) c.abandon();
  }

  /**
   * Looks an authorization code up WITHOUT consuming it, so a mismatching request (other listener, client,
   * redirect, PKCE) cannot burn the legitimate client's code. `reused`: the code was exchanged already.
   */
  peekCode(code: string): IssuedCode | { reused: string } | null {
    this.sweepCodes();
    const used = this.usedCodes.get(code);
    if (used) return { reused: used.deviceId };
    const c = this.codes.get(code);
    return c ? { deviceId: c.deviceId, origin: c.origin, clientId: c.clientId, redirectUri: c.redirectUri, codeChallenge: c.codeChallenge, resource: c.resource, expiresAt: c.expiresAt } : null;
  }

  /** A mismatching exchange of a live code: after CODE_MAX_MISMATCHES the code is burnt (pending device removed). */
  codeMismatch(code: string): void {
    const c = this.codes.get(code);
    if (c && ++c.mismatches >= CODE_MAX_MISMATCHES) c.abandon();
  }

  /** Consumes a validated, single-use authorization code (Spec §6 step 8). */
  takeCode(code: string): IssuedCode | { reused: string } | null {
    const t = this.now();
    this.sweepCodes();
    const used = this.usedCodes.get(code);
    if (used) return { reused: used.deviceId };
    const c = this.codes.get(code);
    if (!c) return null;
    this.codes.delete(code);
    this.usedCodes.set(code, { deviceId: c.deviceId, until: t + 10 * 60 * 1000 });
    return c.expiresAt > t ? c : null;
  }

  /** TOTP lockout and the kill switch close a PUBLIC window; a private window is not affected (spec §5). */
  lockout(reason: 'totp_lockout' | 'kill_switch'): void {
    if (this.window?.kind !== 'public') return;
    if (reason === 'totp_lockout') this.emit({ type: 'alarm', kind: 'pairing_locked' });
    this.close(reason);
  }

  /** First /mcp call of a freshly paired device (Gegenprobe, Spec §0a item 6). */
  firstUse(deviceId: string): void {
    const w = this.firstUseWatch.get(deviceId);
    if (!w) return;
    this.firstUseWatch.delete(deviceId);
    if (w.until > this.now()) w.listener({ type: 'first_use', deviceId });
  }

  stopWatching(listener: PairListener): void {
    for (const [id, w] of this.firstUseWatch) if (w.listener === listener) this.firstUseWatch.delete(id);
  }

  private assertCurrent(s: PairSession, step: PairStep, origin: ListenerKind): void {
    this.expireIfDue();
    if (!this.window || !this.window.sessions.has(s.id) || s.step !== step || s.origin !== origin || this.window.codeSession !== s.id || this.window.kind !== origin) {
      throw new PerchError('This sign-in is no longer valid', 'pairing_session_invalid');
    }
  }

  /** Id of the open window, if any. */
  get windowId(): string | undefined {
    this.expireIfDue();
    return this.window?.id;
  }

  /** For status output. */
  openSince(): number | null {
    this.expireIfDue();
    return this.window?.openedAt ?? null;
  }
}

function redirectHostOf(uri: string): string {
  try {
    return new URL(uri).host;
  } catch {
    return '?';
  }
}
