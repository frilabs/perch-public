import { setTimeout as delay } from 'node:timers/promises';
import { PerchError } from '../../errors.js';
import type { SessionProtocol } from '../sessionBrowser.js';
import { createSessionRequestGuard, type SessionRequestGuard } from './requestGuard.js';

export interface SessionTargetGuards {
  createPage(): Promise<{ sessionId: string; targetId: string }>;
  guard(sessionId: string): SessionRequestGuard;
  assertHealthy(): void;
  close(): void;
}
const managers = new WeakMap<SessionProtocol, Promise<SessionTargetGuards>>();
const autoAttach = { autoAttach: true, waitForDebuggerOnStart: true, flatten: true, filter: [
  { type: 'browser', exclude: true }, { type: 'tab', exclude: true }, { type: 'browser_ui', exclude: true }, {},
] };
const failed = () => new PerchError('Microsoft browser target protection failed.', 'browser_failed');
interface TargetState { sessionId: string; targetId: string; worker: boolean; waitingForDebugger: boolean; guard?: SessionRequestGuard; ready: boolean }

/** One owner per browser connection, initialized before its network gate opens. */
export function getSessionTargetGuards(protocol: SessionProtocol, options: { startupTargetId?: string } = {}): Promise<SessionTargetGuards> {
  const existing = managers.get(protocol);
  if (existing) return existing;
  const result = initialize(protocol, options.startupTargetId);
  managers.set(protocol, result);
  return result;
}
async function initialize(protocol: SessionProtocol, startupTargetId?: string): Promise<SessionTargetGuards> {
  const sessions = new Map<string, TargetState>();
  const targets = new Map<string, TargetState>();
  const pending = new Set<Promise<void>>();
  const changed = new Set<() => void>();
  const extra = (process.env.PERCH_MICROSOFT_ALLOWED_HOSTS ?? '').split(',').map(s => s.trim()).filter(Boolean);
  let closed = false, unhealthy = false;
  let quarantining = startupTargetId !== undefined;
  const startupTargets = new Set<string>();
  const quarantineFailures = new Set<string>();
  const track = (task: Promise<void>) => { pending.add(task); void task.finally(() => pending.delete(task)); };
  async function quarantine(state: TargetState): Promise<void> {
    // Already-running restored documents may navigate at any moment. Do not
    // evaluate lockdown scripts or resume them: pause their new descendants and
    // let the closed proxy contain existing requests until their owners vanish.
    try { await protocol.call('Target.setAutoAttach', autoAttach, state.sessionId); }
    catch { quarantineFailures.add(state.targetId); }
  }
  async function cancelStartupTargets(): Promise<void> {
    const deadline = Date.now() + 10_000;
    const closing = new Set<string>();
    while (Date.now() < deadline) {
      assertHealthy();
      const { targetInfos } = await protocol.call('Target.getTargets');
      if (!Array.isArray(targetInfos) || targetInfos.some(t => typeof t?.targetId !== 'string' || !t.targetId || typeof t.type !== 'string')) throw failed();
      // browser_ui are Chrome control surfaces, never account renderers.
      const old = targetInfos.filter(t => t.targetId !== startupTargetId && !['browser', 'tab', 'browser_ui'].includes(t.type));
      for (const target of old) startupTargets.add(target.targetId);
      if (!old.length) {
        // Drain recursive auto-attachment before accepting the empty snapshot:
        // an existing owner may have created a descendant during the sweep.
        if (pending.size) { await Promise.all([...pending]); continue; }
        const live = new Set(targetInfos.map(t => t.targetId));
        for (const [id, state] of sessions) {
          if (!live.has(state.targetId)) { sessions.delete(id); if (targets.get(state.targetId) === state) targets.delete(state.targetId); }
        }
        if ([...quarantineFailures].some(id => live.has(id))) throw failed();
        quarantining = false;
        for (const state of sessions.values()) track(protect(state));
        return;
      }
      for (const target of old) {
        // Workers and OOPIFs disappear with their owning pages; Chrome rejects
        // closeTarget for dedicated workers. Require their browser-side absence.
        if (['worker', 'iframe'].includes(target.type) || closing.has(target.targetId)) continue;
        const result = await protocol.call('Target.closeTarget', { targetId: target.targetId });
        if (result.success !== true) throw failed();
        closing.add(target.targetId);
      }
      await delay(25);
    }
    throw failed();
  }
  const notify = () => { for (const callback of [...changed]) callback(); };
  const assertHealthy = () => { if (closed || unhealthy) throw failed(); };
  async function closeTarget(targetId: string): Promise<void> {
    try { await protocol.call('Target.closeTarget', { targetId }); } catch { /* Never resume an unguarded target. */ }
  }
  async function protect(state: TargetState): Promise<void> {
    try {
      state.guard = await createSessionRequestGuard(protocol, state.sessionId, extra, { worker: state.worker, waitingForDebugger: state.waitingForDebugger });
      if (closed || !sessions.has(state.sessionId)) { state.guard.close(); await closeTarget(state.targetId); return; }
      // Auto-attachment is recursive: a page's OOPIFs, popups and workers, and
      // their own descendants, must pause before running their first script.
      await protocol.call('Target.setAutoAttach', autoAttach, state.sessionId);
      assertHealthy();
      await protocol.call('Runtime.runIfWaitingForDebugger', {}, state.sessionId);
      assertHealthy();
      state.ready = true;
    } catch {
      state.guard?.close();
      // Navigation/startup cleanup can destroy a worker during initialization.
      // Ignore that race only after both detachment and browser-side absence;
      // a live unprotected target still makes the entire manager fail closed.
      if (!sessions.has(state.sessionId)) {
        try {
          const { targetInfos } = await protocol.call('Target.getTargets');
          if (Array.isArray(targetInfos) && !targetInfos.some(target => target.targetId === state.targetId)) return;
        } catch { /* No proof of disappearance: fail closed below. */ }
      }
      unhealthy = true;
      await closeTarget(state.targetId);
    } finally { notify(); }
  }
  const removeListener = protocol.onEvent(event => {
    if (closed) return;
    const params = event.params;
    if (event.method === 'Target.detachedFromTarget' && typeof params?.sessionId === 'string') {
      const state = sessions.get(params.sessionId);
      state?.guard?.close(); sessions.delete(params.sessionId);
      if (state && targets.get(state.targetId) === state) targets.delete(state.targetId);
      notify(); return;
    }
    if (event.method !== 'Target.attachedToTarget') return;
    const sessionId: unknown = params?.sessionId, targetId: unknown = params?.targetInfo?.targetId;
    if (typeof sessionId !== 'string' || !sessionId || typeof targetId !== 'string' || !targetId) { unhealthy = true; notify(); return; }
    if (sessions.has(sessionId)) return;
    // A queued attachment for a startup target cannot resurrect it after the
    // browser has proven disappearance. Never install or resume a stale owner.
    if (!quarantining && startupTargets.has(targetId)) { void closeTarget(targetId); return; }
    if (sessions.size >= 128 || unhealthy) { unhealthy = true; void closeTarget(targetId); notify(); return; }
    const state: TargetState = { sessionId, targetId, worker: !['page', 'iframe'].includes(params?.targetInfo?.type), waitingForDebugger: params?.waitingForDebugger === true, ready: false };
    sessions.set(sessionId, state); targets.set(targetId, state);
    if (quarantining) {
      if (targetId !== startupTargetId) startupTargets.add(targetId);
      track(quarantine(state));
    } else track(protect(state));
  });
  const close = () => {
    if (closed) return;
    closed = true; removeListener();
    for (const state of sessions.values()) state.guard?.close();
    sessions.clear(); targets.clear(); notify();
    // Interception stays enabled until the browser owner closes all targets.
  };
  try {
    await protocol.call('Target.setAutoAttach', autoAttach);
    if (quarantining) await cancelStartupTargets();
    while (pending.size) await Promise.all([...pending]);
    assertHealthy();
  } catch { close(); throw failed(); }
  return {
    assertHealthy, close,
    guard(sessionId) {
      assertHealthy(); const state = sessions.get(sessionId);
      if (!state?.ready || !state.guard) throw failed();
      return state.guard;
    },
    async createPage() {
      assertHealthy();
      let targetId: unknown;
      try { ({ targetId } = await protocol.call('Target.createTarget', { url: 'about:blank' })); } catch { unhealthy = true; throw failed(); }
      if (typeof targetId !== 'string' || !targetId) { unhealthy = true; throw failed(); }
      const id = targetId;
      try {
        return await new Promise<{ sessionId: string; targetId: string }>((resolve, reject) => {
          const timer = setTimeout(() => { unhealthy = true; finish(failed()); }, 10_000);
          const check = () => {
            try {
              assertHealthy();
              const state = targets.get(id);
              if (state?.ready) finish(undefined, { targetId: id, sessionId: state.sessionId });
            } catch { finish(failed()); }
          };
          const finish = (error?: Error, value?: { sessionId: string; targetId: string }) => {
            clearTimeout(timer); changed.delete(check);
            if (error) reject(error); else resolve(value!);
          };
          changed.add(check); check();
        });
      } catch { await closeTarget(id); throw failed(); }
    },
  };
}
