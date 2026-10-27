import { it, expect, vi } from 'vitest';
import { getSessionTargetGuards } from '../src/microsoft/session/targetGuards.js';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { BrowserPipe } from '../src/microsoft/sessionBrowser.js';
it('routes private CDP events by target without logging or resolving unrelated commands', async () => {
  const child = new EventEmitter() as any;
  child.stdio = [null,null,null,new PassThrough(),new PassThrough()]; child.kill = () => {};
  const pipe = new BrowserPipe(child);
  const seen: unknown[] = [];
  const off = pipe.onEvent(event => seen.push(event));
  const pending = pipe.call('Network.enable', {}, 'target1');
  child.stdio[4].write(Buffer.from(JSON.stringify({method:'Network.requestWillBeSent',params:{requestId:'one'},sessionId:'target1'})+'\0'));
  child.stdio[4].write(Buffer.from(JSON.stringify({id:1,result:{ok:true}})+'\0'));
  expect(await pending).toEqual({ok:true});
  expect(seen).toEqual([{method:'Network.requestWillBeSent',params:{requestId:'one'},sessionId:'target1'}]);
  off(); child.stdio[4].write(Buffer.from(JSON.stringify({method:'Ignored'})+'\0'));
  expect(seen).toHaveLength(1);
});

import { browserArguments } from '../src/microsoft/sessionBrowser.js';
it('routes Chrome traffic through the local pinned egress proxy without direct QUIC or loopback bypass',()=>{
 const args=browserArguments('/profile','http://127.0.0.1:12345');
 expect(args).toContain('--proxy-server=http://127.0.0.1:12345');expect(args).toContain('--proxy-bypass-list=<-loopback>');expect(args).toContain('--disable-quic');
 expect(args).toContain('--force-webrtc-ip-handling-policy=disable_non_proxied_udp');
 expect(args).toContain('--disable-component-extensions-with-background-pages');
 expect(()=>browserArguments('/profile','http://evil.test:1234')).toThrow();
});

import {mkdtemp,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {openSessionProfile} from '../src/microsoft/sessionBrowser.js';
it('does not recreate a removed profile for a queued worker',async()=>{
 const root=await mkdtemp(path.join(tmpdir(),'perch-ms-existing-'));
 try{await expect(openSessionProfile(root,'Removed',{existing:true})).rejects.toThrow();await expect(stat(path.join(root,'microsoft-sessions'))).rejects.toThrow();}
 finally{await rm(root,{recursive:true,force:true});}
});

import { prepareWorkerBrowser, type SessionProtocol, type BrowserEvent } from '../src/microsoft/sessionBrowser.js';
it('installs auto-attachment before sweeping restored targets and creates a guarded worker page',async()=>{
 const listeners=new Set<(event:BrowserEvent)=>void>();const log:string[]=[];let targets=[{targetId:'restored',type:'page'},{targetId:'persisted',type:'service_worker'},{targetId:'chrome-ui',type:'browser_ui'}];let next=0;
 const protocol:SessionProtocol={onEvent(fn){listeners.add(fn);return()=>listeners.delete(fn)},async call(method,params={},sessionId){
  log.push(`${method}:${String(params.targetId??sessionId??'')}`);
  if(method==='Target.createTarget'){const targetId=`fresh${++next}`;targets.push({targetId,type:'page'});if(next>1)for(const fn of listeners)fn({method:'Target.attachedToTarget',params:{sessionId:targetId,targetInfo:{targetId,type:'page'}}});return{targetId};}
  if(method==='Target.getTargets')return{targetInfos:targets};
  if(method==='Target.closeTarget'){setTimeout(()=>{targets=targets.filter(t=>t.targetId!==params.targetId);},40);return{success:true};}
  if(method==='Runtime.evaluate')return{result:{value:true}};
  return{};
 }};
 const ready=await prepareWorkerBrowser(protocol);
 expect(log).not.toContain('Target.closeTarget:chrome-ui');
 expect(ready.targetId).toBe('fresh2');expect(log.indexOf('Target.setAutoAttach:')).toBeLessThan(log.indexOf('Target.closeTarget:persisted'));
 expect(log.indexOf('Target.closeTarget:persisted')).toBeLessThan(log.indexOf('Fetch.enable:fresh2'));
 expect(log.filter(entry=>entry==='Target.closeTarget:persisted')).toHaveLength(1);
 expect(log.indexOf('Fetch.enable:fresh2')).toBeLessThan(log.indexOf('Runtime.runIfWaitingForDebugger:fresh2'));
 ready.guards.close();
});
it('fails closed when a restored startup target cannot be stopped',async()=>{
 const calls:string[]=[];const protocol:SessionProtocol={onEvent(){return()=>{}},async call(method){calls.push(method);if(method==='Target.createTarget')return{targetId:'blank'};if(method==='Target.getTargets')return{targetInfos:[{targetId:'old',type:'page'}]};return{success:false};}};
 await expect(prepareWorkerBrowser(protocol)).rejects.toMatchObject({code:'browser_failed'});
 expect(calls.filter(method=>method==='Target.createTarget')).toHaveLength(1);
});
it('closes restored owner pages before waiting for their non-closeable workers to disappear',async()=>{
 const listeners=new Set<(event:BrowserEvent)=>void>();let next=0;let targets=[{targetId:'worker',type:'worker'},{targetId:'owner',type:'page'}];
 const closed:string[]=[];
 const protocol:SessionProtocol={onEvent(fn){listeners.add(fn);return()=>listeners.delete(fn)},async call(method,p={},sid){
  if(method==='Target.createTarget'){const targetId=`blank${++next}`;targets.push({targetId,type:'page'});if(next>1)for(const fn of listeners)fn({method:'Target.attachedToTarget',params:{sessionId:targetId,targetInfo:{targetId,type:'page'},waitingForDebugger:true}});return{targetId};}
  if(method==='Target.getTargets')return{targetInfos:targets};
  if(method==='Target.closeTarget'){if(p.targetId==='worker')throw Error("Specified target doesn't support closing");closed.push(String(p.targetId));targets=targets.filter(t=>t.targetId!==p.targetId);if(p.targetId==='owner')setTimeout(()=>{targets=targets.filter(t=>t.targetId!=='worker');},30);return{success:true};}
  if(method==='Runtime.evaluate')return{result:{value:true}};return{};
 }};
 const ready=await prepareWorkerBrowser(protocol);expect(closed).toContain('owner');expect(closed).not.toContain('worker');ready.guards.close();
});

function restoredStartupHarness(failFreshGuard = false) {
  const listeners = new Set<(event: BrowserEvent) => void>();
  const calls: Array<{ method: string; params: Record<string, unknown>; session?: string }> = [];
  const emit = (event: BrowserEvent) => { for (const fn of listeners) fn(event); };
  let targets = [{ targetId: 'restored', type: 'page' }];
  let next = 0, attached = false, spawned = false;
  const attach = (targetId: string, type: string, waitingForDebugger: boolean) => emit({ method: 'Target.attachedToTarget', params: { sessionId: targetId, targetInfo: { targetId, type }, waitingForDebugger } });
  const protocol: SessionProtocol = { onEvent(fn) { listeners.add(fn); return () => { listeners.delete(fn); }; }, async call(method, params = {}, session) {
    calls.push({ method, params, session });
    if (method === 'Target.createTarget') {
      const targetId = `fresh${++next}`;
      targets.push({ targetId, type: 'page' });
      if (attached) attach(targetId, 'page', true);
      return { targetId };
    }
    if (method === 'Target.setAutoAttach' && !session && !attached) {
      attached = true;
      for (const target of [...targets]) attach(target.targetId, target.type, false);
    }
    if (method === 'Target.setAutoAttach' && session === 'restored' && !spawned) {
      spawned = true;
      targets.push({ targetId: 'child', type: 'worker' });
      attach('child', 'worker', true);
    }
    if (method === 'Target.getTargets') return { targetInfos: [...targets] };
    if (method === 'Target.closeTarget') {
      const ids = params.targetId === 'restored' ? ['restored', 'child'] : [params.targetId];
      targets = targets.filter(t => !ids.includes(t.targetId));
      for (const sessionId of ids) emit({ method: 'Target.detachedFromTarget', params: { sessionId } });
      return { success: true };
    }
    // Reproduce a real restored renderer navigating during channel lockdown.
    if (method === 'Runtime.evaluate' && session === 'restored') throw Error('Execution context was destroyed');
    if (method === 'Fetch.enable' && session === 'fresh2' && failFreshGuard) throw Error('Cannot protect live renderer');
    if (method === 'Runtime.evaluate') return { result: { value: true } };
    return {};
  } };
  return { protocol, calls, emit, attach, listeners, targets: () => targets };
}
it('quarantines navigating restored pages and descendants without installing or resuming their guards', async () => {
  const h = restoredStartupHarness();
  const ready = await prepareWorkerBrowser(h.protocol);
  expect(ready.targetId).toBe('fresh2');
  expect(h.calls.filter(c => ['restored', 'child'].includes(c.session ?? '')).map(c => c.method)).toEqual(['Target.setAutoAttach', 'Target.setAutoAttach']);
  expect(h.calls.some(c => c.method === 'Target.setAutoAttach' && c.session === 'restored' && c.params.waitForDebuggerOnStart === true)).toBe(true);
  const firstGuard = h.calls.findIndex(c => c.method === 'Fetch.enable');
  const cancelled = h.calls.findIndex(c => c.method === 'Target.closeTarget' && c.params.targetId === 'restored');
  expect(firstGuard).toBeGreaterThan(cancelled);
  expect(h.targets()).toEqual([{ targetId: 'fresh2', type: 'page' }]);
  expect(await getSessionTargetGuards(h.protocol)).toBe(ready.guards);
  ready.guards.assertHealthy(); ready.guards.close();
  expect(h.listeners.size).toBe(0);
});
it('still fails closed on a fresh live renderer protection failure after quarantine', async () => {
  const h = restoredStartupHarness(true);
  await expect(prepareWorkerBrowser(h.protocol)).rejects.toMatchObject({ code: 'browser_failed' });
  expect(h.calls.some(c => c.method === 'Runtime.runIfWaitingForDebugger' && c.session === 'fresh2')).toBe(false);
  expect(h.calls.some(c => c.method === 'Target.closeTarget' && c.params.targetId === 'fresh2')).toBe(true);
});

it('cancels a popup created by a restored owner during the cleanup sweep', async () => {
  const h = restoredStartupHarness();
  const call = h.protocol.call;
  h.protocol.call = async (method, params, session) => {
    if (method === 'Target.closeTarget' && params?.targetId === 'restored') {
      h.targets().push({ targetId: 'late-popup', type: 'page' });
      h.attach('late-popup', 'page', true);
    }
    if (method === 'Runtime.evaluate' && session === 'late-popup') throw Error('Navigating restored popup');
    return call(method, params, session);
  };
  const ready = await prepareWorkerBrowser(h.protocol);
  expect(h.calls.some(c => c.method === 'Target.closeTarget' && c.params.targetId === 'late-popup')).toBe(true);
  expect(h.calls.filter(c => c.session === 'late-popup').map(c => c.method)).toEqual(['Target.setAutoAttach']);
  expect(h.targets()).toEqual([{ targetId: 'fresh2', type: 'page' }]);
  ready.guards.close();
});
it.each(['restored', 'fresh1'])('tolerates quarantine attachment failure only after target disappearance: %s', async target => {
  const h = restoredStartupHarness();
  const call = h.protocol.call;
  h.protocol.call = async (method, params, session) => {
    if (method === 'Target.setAutoAttach' && session === target) throw Error('Target disappeared');
    return call(method, params, session);
  };
  if (target === 'restored') {
    const ready = await prepareWorkerBrowser(h.protocol);
    ready.guards.assertHealthy(); ready.guards.close();
  } else {
    await expect(prepareWorkerBrowser(h.protocol)).rejects.toMatchObject({ code: 'browser_failed' });
    expect(h.calls.some(c => c.method === 'Runtime.runIfWaitingForDebugger')).toBe(false);
  }
  expect(h.listeners.size).toBe(0);
});
it('never finishes quarantine while an orphaned worker remains alive', async () => {
  const h = restoredStartupHarness();
  const call = h.protocol.call;
  let timestamp = 1000;
  const now = vi.spyOn(Date, 'now').mockImplementation(() => timestamp);
  h.protocol.call = async (method, params, session) => {
    const result = await call(method, params, session);
    if (method === 'Target.closeTarget' && params?.targetId === 'restored') {
      h.targets().push({ targetId: 'orphan', type: 'worker' });
      timestamp += 10001;
    }
    return result;
  };
  try {
    await expect(prepareWorkerBrowser(h.protocol)).rejects.toMatchObject({ code: 'browser_failed' });
    expect(h.calls.some(c => c.method === 'Runtime.runIfWaitingForDebugger')).toBe(false);
    expect(h.calls.filter(c => c.method === 'Target.createTarget')).toHaveLength(1);
    expect(h.listeners.size).toBe(0);
  } finally { now.mockRestore(); }
});
it('does not guard or resume a delayed attachment for a proven-removed restored target', async () => {
  const h = restoredStartupHarness();
  const ready = await prepareWorkerBrowser(h.protocol);
  h.attach('restored', 'page', false);
  await Promise.resolve();
  ready.guards.assertHealthy();
  expect(h.calls.filter(c => c.session === 'restored').map(c => c.method)).toEqual(['Target.setAutoAttach']);
  ready.guards.close();
});
