import { normalizeSelectedSiteUrl } from './session/policy.js';
import { MICROSOFT_SIGN_IN_URL } from './session/login.js';
import { startBrowserEgressProxy } from './session/egress.js';
import { getSessionTargetGuards, type SessionTargetGuards } from './session/targetGuards.js';
import { createHash } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { access, mkdir, rmdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { assertPrivateDir, ensurePrivateDir, writePrivateFileExclusive } from '../secureFs.js';
import { PerchError } from '../errors.js';
import type { BrowserAction, SessionBrowser } from './sessionViewer.js';

export function sessionProfileId(label: string): string {
  if (!label.trim() || label.length > 120 || /[\u0000-\u001f\u007f-\u009f]/.test(label)) throw new PerchError('Use a label of 1-120 characters without control characters.', 'usage');
  return `ms-session-${createHash('sha256').update(label).digest('hex').slice(0, 24)}`;
}
export async function openSessionProfile(dataDir: string, label: string, options: {existing?:boolean} = {}): Promise<{ path: string; id: string; release(): Promise<void> }> {
  const id = sessionProfileId(label);
  const directory = options.existing ? assertPrivateDir : ensurePrivateDir;
  await directory(dataDir);
  const root = path.join(dataDir, 'microsoft-sessions');
  await directory(root);
  const dir = path.join(root, id);
  await directory(dir);
  if(options.existing)await assertPrivateDir(path.join(dir,'browser'));
  const lock = path.join(dir, 'login.lock');
  try { await mkdir(lock, { mode: 0o700 }); }
  catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') throw new PerchError(`This session profile is already in use (or a previous process crashed). Check that its browser has stopped before manually removing the empty lock directory: ${lock}`, 'locked');
    throw err;
  }
  let released = false;
  const release = async () => { if (!released) { released = true; await rmdir(lock); } };
  try {
    await writePrivateFileExclusive(path.join(dir, 'profile.json'), Buffer.from(JSON.stringify({ version: 1, id, label, status: 'unverified' })));
    const profile = path.join(dir, 'browser');
    await ensurePrivateDir(profile);
    return { path: profile, id, release };
  } catch (err) { await release(); throw err; }
}
export function browserArguments(profile: string, proxy?: string): string[] {
  if(proxy){const u=new URL(proxy);if(u.protocol!=='http:'||u.hostname!=='127.0.0.1'||!u.port||u.username||u.password||u.search||u.hash||u.pathname!=='/')throw new PerchError('Invalid private browser proxy.','bad_config');}
  return [...(proxy?[`--proxy-server=${proxy}`,'--proxy-bypass-list=<-loopback>','--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp']:[]),'--disable-background-networking', '--headless=new', '--restore-last-session', '--remote-debugging-pipe', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-component-extensions-with-background-pages', '--window-size=1100,780', 'about:blank'];
}
export async function findSessionBrowser(env: NodeJS.ProcessEnv): Promise<string> {
  if (process.platform !== 'linux') throw new PerchError('Microsoft server sessions currently require Linux with Chrome/Chromium. Start the command in the Linux server terminal; it will provide the local Chrome login command.', 'bad_config');
  if (process.getuid?.() === 0) throw new PerchError('Run as your regular Perch server user, not root. Chrome sandbox must remain enabled.', 'bad_config');
  const specified = env.PERCH_MICROSOFT_BROWSER;
  const candidates = specified ? [specified] : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  for (const candidate of candidates) {
    if (!path.isAbsolute(candidate)) continue;
    try { await access(candidate, constants.X_OK); return candidate; } catch { /* try the next installed browser */ }
  }
  throw new PerchError('No executable Chrome/Chromium found. Install a supported browser using your distribution instructions, then rerun. Or set PERCH_MICROSOFT_BROWSER to its absolute executable path. Perch installs no system packages and never disables the sandbox.', 'bad_config');
}

/** Private CDP pipes: no TCP debug port, protocol messages or browser stderr in logs. */
export interface BrowserEvent { method: string; params?: any; sessionId?: string }
export interface SessionProtocol {
  call(method: string, params?: Record<string, unknown>, sessionId?: string): Promise<any>;
  onEvent(listener: (event: BrowserEvent) => void): () => void;
}
export interface ServerSessionBrowser extends SessionBrowser { protocol: SessionProtocol; mainSessionId: string; blockedHosts?(): string[]; allowDiscoveredSite?(url: string): void }
export class BrowserPipe implements SessionProtocol {
  private listeners = new Set<(event: BrowserEvent) => void>();
  onEvent(listener: (event: BrowserEvent) => void): () => void {
    this.listeners.add(listener); return () => { this.listeners.delete(listener); };
  }
  private next = 0;
  private buffer = Buffer.alloc(0);
  private pending = new Map<number, { resolve: (v: any) => void; reject: (err: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  private dead = false;
  constructor(private child: ChildProcess) {
    (child.stdio[4] as Readable).on('data', (chunk: Buffer) => this.receive(chunk));
    (child.stdio[4] as Readable).on('error', () => this.fail());
    (child.stdio[3] as Writable).on('error', () => this.fail());
    child.on('error', () => this.fail());
    child.on('exit', () => this.fail());
  }
  private fail() {
    this.dead = true;
    for (const item of this.pending.values()) { clearTimeout(item.timer); item.reject(new PerchError('Server browser stopped. Check browser installation and sandbox support; resume using the same label.', 'browser_failed')); }
    this.pending.clear();
  }
  private receive(chunk: Buffer) {
    if (this.dead) return;
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > 16 * 1024 * 1024) { this.child.kill('SIGTERM'); this.fail(); return; }
    let end: number;
    while ((end = this.buffer.indexOf(0)) >= 0) {
      const raw = this.buffer.subarray(0, end);
      this.buffer = this.buffer.subarray(end + 1);
      try {
        const message = JSON.parse(raw.toString('utf8'));
        if (typeof message.method === 'string') {
          for (const listener of this.listeners) { try { listener(message); } catch { /* observers cannot break the protocol */ } }
          continue;
        }
        const item = this.pending.get(message.id);
        if (!item) continue;
        this.pending.delete(message.id); clearTimeout(item.timer);
        if (message.error) item.reject(new PerchError('Server browser operation failed.', 'browser_failed'));
        else item.resolve(message.result);
      } catch { this.fail(); }
    }
  }
  call(method: string, params: Record<string, unknown> = {}, sessionId?: string): Promise<any> {
    if (this.dead) return Promise.reject(new PerchError('Server browser stopped.', 'browser_failed'));
    const id = ++this.next;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new PerchError('Server browser timed out. Check the login page or resume.', 'browser_failed')); }, 10_000);
      this.pending.set(id, { resolve, reject, timer });
      (this.child.stdio[3] as Writable).write(`${JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })}\0`);
    });
  }
}
/** Cancel every startup target while the proxy is closed, then guard a fresh page. */
export async function prepareWorkerBrowser(protocol: SessionProtocol): Promise<{ sessionId: string; targetId: string; guards: SessionTargetGuards }> {
  const { targetId: blankId } = await protocol.call('Target.createTarget', { url: 'about:blank' });
  if (typeof blankId !== 'string' || !blankId) throw new PerchError('Could not isolate Microsoft worker startup.', 'browser_failed');
  // The proxy stays closed while the manager pauses descendants and cancels
  // restored renderers without evaluating code in their navigating documents.
  const guards = await getSessionTargetGuards(protocol, { startupTargetId: blankId });
  try {
    const main = await guards.createPage();
    const closed = await protocol.call('Target.closeTarget', { targetId: blankId });
    if (closed.success !== true) throw new PerchError('Could not stop the Microsoft startup keeper.', 'browser_failed');
    guards.assertHealthy();
    return { ...main, guards };
  } catch (error) { guards.close(); throw error; }
}
export async function launchSessionBrowser(executable: string, profile: string, initialUrl = MICROSOFT_SIGN_IN_URL, options: {selectedHosts?:string[];extraHosts?:string[];workerMode?:boolean} = {}): Promise<ServerSessionBrowser> {
  const blocked=new Set<string>();
  const proxy=await startBrowserEgressProxy({paused:options.workerMode,selectedHosts:options.selectedHosts,extraHosts:options.extraHosts??(process.env.PERCH_MICROSOFT_ALLOWED_HOSTS??'').split(',').map(s=>s.trim()).filter(Boolean)},host=>{if(blocked.size<20)blocked.add(host);});
  const child = spawn(executable, browserArguments(profile,proxy.url), { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
  const pipe = new BrowserPipe(child);
  let targetGuards: SessionTargetGuards | undefined;
  let closing: Promise<void> | undefined;
  const close = () => closing ??= new Promise<void>((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null || !child.pid) { resolve(); return; }
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    child.once('exit', () => { clearTimeout(timer); resolve(); });
    // Chrome flushes cookies/profile state during its normal shutdown. SIGTERM
    // immediately after import can lose even persistent cookies on Linux.
    void pipe.call('Browser.close').catch(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); });
  }).finally(()=>{targetGuards?.close();return proxy.close();});
  child.once('exit',()=>{void proxy.close();});
  try {
    await pipe.call('Browser.setDownloadBehavior', { behavior: 'deny' });
    let targetId: string, sessionId: string;
    if (options.workerMode) {
      const prepared = await prepareWorkerBrowser(pipe);
      ({ targetId, sessionId, guards: targetGuards } = prepared);
      proxy.resume();
    } else {
      const targets = await pipe.call('Target.getTargets');
      targetId = targets.targetInfos.find((t: { type: string }) => t.type === 'page')?.targetId ?? (await pipe.call('Target.createTarget', { url: 'about:blank' })).targetId;
      ({ sessionId } = await pipe.call('Target.attachToTarget', { targetId, flatten: true }));
    }
    const call = (method: string, params: Record<string, unknown> = {}) => pipe.call(method, params, sessionId);
    await call('Page.enable');
    await call('Emulation.setDeviceMetricsOverride', { width: 1100, height: 780, deviceScaleFactor: 1, mobile: false });
    await call('Page.navigate', { url: initialUrl });
    return {
      protocol: pipe, mainSessionId: sessionId, blockedHosts:()=>[...blocked], close,
      allowDiscoveredSite(url) { proxy.allowSelectedHost(new URL(normalizeSelectedSiteUrl(url)).hostname); },
      async snapshot() {
        const { targetInfo } = await pipe.call('Target.getTargetInfo', { targetId });
        const { data } = await call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
        let host = ''; try { host = new URL(targetInfo.url).hostname; } catch { /* loading */ }
        return { image: data, host, blockedHosts:[...blocked] };
      },
      async action(action: BrowserAction) {
        switch (action.type) {
          case 'navigate': {
            const host=new URL(action.url).hostname;
            if (/\.sharepoint\.(com|de)$/.test(host)) proxy.allowSelectedHost(host);
            await call('Page.navigate', { url: action.url }); break;
          }
          case 'reload': await call('Page.reload'); break;
          case 'back': {
            const h = await call('Page.getNavigationHistory');
            const entry = h.entries[h.currentIndex - 1];
            if (entry) await call('Page.navigateToHistoryEntry', { entryId: entry.id });
            break;
          }
          case 'text': await call('Input.insertText', { text: action.text }); break;
          case 'click':
            await call('Input.dispatchMouseEvent', { type: 'mousePressed', x: action.x, y: action.y, button: 'left', clickCount: 1 });
            await call('Input.dispatchMouseEvent', { type: 'mouseReleased', x: action.x, y: action.y, button: 'left', clickCount: 1 });
            break;
          case 'wheel': await call('Input.dispatchMouseEvent', { type: 'mouseWheel', x: action.x, y: action.y, deltaX: 0, deltaY: action.deltaY }); break;
          case 'key': {
            const codes: Record<string, number> = { Enter: 13, Tab: 9, Escape: 27, Backspace: 8, Delete: 46, ArrowLeft: 37, ArrowRight: 39, ArrowUp: 38, ArrowDown: 40, Home: 36, End: 35 };
            const key = { key: action.key, code: action.key, windowsVirtualKeyCode: codes[action.key], modifiers: action.shift ? 8 : 0 };
            await call('Input.dispatchKeyEvent', { ...key, type: 'keyDown', ...(action.key === 'Enter' ? { text: '\r' } : {}) });
            await call('Input.dispatchKeyEvent', { ...key, type: 'keyUp' });
          }
        }
      },
    };
  } catch (err) { await close(); throw err; }
}
