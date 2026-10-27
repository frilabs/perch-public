import {it,expect} from 'vitest';
import {SessionBrowserLease} from '../src/microsoft/session/lifecycle.js';
it('waits for a pending launch and closes Chrome before releasing its profile lock',async()=>{
 const events:string[]=[];let resolve!:(browser:{close():Promise<void>})=>void;
 const pending=new Promise<{close():Promise<void>}>(r=>{resolve=r});
 const lease=new SessionBrowserLease(async()=>{events.push('release')});
 const start=lease.start(()=>pending);const outcome=start.catch(e=>e.code);
 const close=lease.close();await Promise.resolve();expect(events).toEqual([]);
 resolve({close:async()=>{events.push('close')}});await close;
 expect(await outcome).toBe('cancelled');expect(events).toEqual(['close','release']);await lease.close();expect(events).toHaveLength(2);
});
it('releases the lock after a failed launch without requiring a browser handle',async()=>{
 let released=0;const lease=new SessionBrowserLease(async()=>{released++});
 await expect(lease.start(async()=>{throw new Error('launch failed')})).rejects.toThrow('launch failed');await lease.close();expect(released).toBe(1);
});
