import { describe, expect, it, vi } from 'vitest';
import { getSessionTargetGuards } from '../src/microsoft/session/targetGuards.js';
import type { BrowserEvent, SessionProtocol } from '../src/microsoft/sessionBrowser.js';
function harness() {
  const listeners = new Set<(event: BrowserEvent) => void>();
  const emit = (event: BrowserEvent) => { for (const listener of listeners) listener(event); };
  let next = 0;
  const call = vi.fn(async (method: string, _params?: Record<string, unknown>, _session?: string): Promise<any> => {
    if (method === 'Runtime.evaluate' && String(_params?.expression).includes('PerchDisabledChannel')) return { result: { value: true } };
    if (method === 'Target.createTarget') {
      const targetId = `target${++next}`;
      emit({ method: 'Target.attachedToTarget', params: { sessionId: `page${next}`, targetInfo: { targetId, type: 'page' }, waitingForDebugger: true } });
      return { targetId };
    }
    return {};
  });
  const protocol: SessionProtocol = { call, onEvent(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; } };
  const flush = async () => { for (let i = 0; i < 16; i++) await Promise.resolve(); };
  return { protocol, call, emit, listeners, flush };
}
describe('Microsoft target guard coverage', () => {
  it('shares initialization and creates only autoattached guarded pages', async () => {
    const h = harness(); const [a, b] = await Promise.all([getSessionTargetGuards(h.protocol), getSessionTargetGuards(h.protocol)]);
    expect(a).toBe(b);
    const page = await a.createPage();
    expect(page).toEqual({ targetId: 'target1', sessionId: 'page1' });
    expect(a.guard(page.sessionId)).toBeDefined(); a.assertHealthy();
    expect(h.call.mock.calls.filter(c => c[0] === 'Target.setAutoAttach' && !c[2])).toHaveLength(1);
    expect(h.call.mock.calls.some(c => c[0] === 'Target.attachToTarget')).toBe(false);
    const methods = h.call.mock.calls.filter(c => c[2] === 'page1').map(c => c[0]);
    expect(methods.indexOf('Fetch.enable')).toBeLessThan(methods.indexOf('Runtime.runIfWaitingForDebugger'));
    expect(methods.indexOf('Target.setAutoAttach')).toBeLessThan(methods.indexOf('Runtime.runIfWaitingForDebugger'));
    a.close();
  });
  it('guards iframes, popup pages and every worker before resuming and covers descendants recursively', async () => {
    const h = harness(); const manager = await getSessionTargetGuards(h.protocol);
    for (const type of ['page', 'iframe', 'worker', 'service_worker', 'shared_worker', 'worklet']) h.emit({ method: 'Target.attachedToTarget', sessionId: 'parent', params: { sessionId: type, targetInfo: { targetId: `target-${type}`, type }, waitingForDebugger: true } });
    await h.flush();
    for (const type of ['page', 'iframe', 'worker', 'service_worker', 'shared_worker', 'worklet']) {
      expect(manager.guard(type)).toBeDefined();
      const methods = h.call.mock.calls.filter(c => c[2] === type).map(c => c[0]);
      expect(methods).toContain('Target.setAutoAttach');
      if (['page', 'iframe'].includes(type)) expect(methods.indexOf('Fetch.enable')).toBeLessThan(methods.indexOf('Runtime.runIfWaitingForDebugger'));
      else {
        expect(methods).not.toContain('Fetch.enable');
        expect(methods).not.toContain('Page.addScriptToEvaluateOnNewDocument');
        expect(h.call.mock.calls.find(c => c[0] === 'Network.setBlockedURLs' && c[2] === type)?.[1]).toMatchObject({ urlPatterns: expect.arrayContaining([{ urlPattern: 'https://*:*/*', block: true }, { urlPattern: 'http://*:*/*', block: true }]) });
        expect(() => manager.guard(type).prepare({ url: 'https://outlook.office.com/api/v2.0/me', method: 'GET' })).toThrow();
      }
      if (['page', 'iframe'].includes(type)) {
        expect(methods).not.toContain('Runtime.evaluate');
        expect(h.call.mock.calls.find(c => c[0] === 'Page.addScriptToEvaluateOnNewDocument' && c[2] === type)?.[1]).toMatchObject({ runImmediately: true });
      } else expect(methods.indexOf('Runtime.evaluate')).toBeLessThan(methods.indexOf('Runtime.runIfWaitingForDebugger'));
    }
    manager.close(); expect(h.listeners.size).toBe(0);
  });
  it('does not resume a target while its guard installation is pending', async () => {
    const h = harness(); const original = h.call.getMockImplementation()!;
    let release!: () => void; const blocked = new Promise<void>(resolve => { release = resolve; });
    h.call.mockImplementation(async (method, params, session) => { if (method === 'Fetch.enable') await blocked; return original(method, params, session); });
    const manager = await getSessionTargetGuards(h.protocol); const creating = manager.createPage();
    await h.flush();
    expect(h.call.mock.calls.some(c => c[0] === 'Runtime.runIfWaitingForDebugger')).toBe(false);
    expect(() => manager.guard('page1')).toThrow();
    release(); expect(await creating).toMatchObject({ sessionId: 'page1' }); manager.close();
  });
  it('fails closed and closes a target if any guard or recursive attachment setup fails', async () => {
    for (const failure of ['Fetch.enable', 'Target.setAutoAttach']) {
      const h = harness(); const original = h.call.getMockImplementation()!;
      h.call.mockImplementation(async (method, params, session) => { if (method === failure && session) throw Error('private detail'); return original(method, params, session); });
      const manager = await getSessionTargetGuards(h.protocol);
      await expect(manager.createPage()).rejects.toMatchObject({ code: 'browser_failed' });
      expect(h.call.mock.calls.some(c => c[0] === 'Runtime.runIfWaitingForDebugger')).toBe(false);
      expect(h.call).toHaveBeenCalledWith('Target.closeTarget', { targetId: 'target1' });
      expect(() => manager.assertHealthy()).toThrow(); manager.close();
    }
  });
  it('never resumes a target if the manager closes while guard setup is pending', async () => {
    const h = harness(); const original = h.call.getMockImplementation()!;
    let release!: () => void; const blocked = new Promise<void>(resolve => { release = resolve; });
    h.call.mockImplementation(async (method, params, session) => { if (method === 'Fetch.enable') await blocked; return original(method, params, session); });
    const manager = await getSessionTargetGuards(h.protocol);
    const creating = manager.createPage();
    const rejected = expect(creating).rejects.toMatchObject({ code: 'browser_failed' });
    await h.flush(); manager.close(); release(); await rejected; await h.flush();
    expect(h.listeners.size).toBe(0);
    expect(h.call.mock.calls.some(c => c[0] === 'Runtime.runIfWaitingForDebugger')).toBe(false);
    expect(h.call).toHaveBeenCalledWith('Target.closeTarget', { targetId: 'target1' });
  });
  it('cleans listeners if initial autoattachment fails', async () => {
    const h = harness(); h.call.mockRejectedValueOnce(Error('private details'));
    await expect(getSessionTargetGuards(h.protocol)).rejects.toMatchObject({ code: 'browser_failed' });
    expect(h.listeners.size).toBe(0);
  });
  it('removes detached guards and closes idempotently without unpausing requests', async () => {
    const h = harness(); const manager = await getSessionTargetGuards(h.protocol); await manager.createPage();
    h.emit({ method: 'Target.detachedFromTarget', params: { sessionId: 'page1' } });
    expect(() => manager.guard('page1')).toThrow();
    manager.close(); manager.close(); expect(h.listeners.size).toBe(0);
    await expect(manager.createPage()).rejects.toThrow();
    expect(h.call.mock.calls.some(c => c[0] === 'Fetch.disable')).toBe(false);
  });
});
it.each([false,true])('handles a detached target during guard setup, still present=%s',async(stillPresent)=>{
 const h=harness();const original=h.call.getMockImplementation()!;
 let fail!:()=>void;const pending=new Promise<void>((_,reject)=>{fail=()=>reject(Error('session gone'));});
 h.call.mockImplementation(async(method,params,session)=>{
  if(method==='Network.enable'&&session==='ephemeral')await pending;
  if(method==='Target.getTargets')return{targetInfos:stillPresent?[{targetId:'ephemeral-target',type:'worker'}]:[]};
  return original(method,params,session);
 });
 const manager=await getSessionTargetGuards(h.protocol);
 h.emit({method:'Target.attachedToTarget',params:{sessionId:'ephemeral',targetInfo:{targetId:'ephemeral-target',type:'worker'},waitingForDebugger:true}});
 h.emit({method:'Target.detachedFromTarget',params:{sessionId:'ephemeral'}});fail();await h.flush();
 if(stillPresent)expect(()=>manager.assertHealthy()).toThrow();
 else{manager.assertHealthy();expect(await manager.createPage()).toMatchObject({sessionId:'page1'});}
 expect(h.call.mock.calls.some(c=>c[0]==='Runtime.runIfWaitingForDebugger'&&c[2]==='ephemeral')).toBe(false);
 manager.close();
});
