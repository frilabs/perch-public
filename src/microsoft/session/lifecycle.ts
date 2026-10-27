import { PerchError } from '../../errors.js';
/** A profile lock outlives every browser launch, including cancellation while launch is pending. */
export class SessionBrowserLease<T extends {close():Promise<void>}> {
 private launching?:Promise<T>;
 private closing?:Promise<void>;
 constructor(private release:()=>Promise<void>){}
 async start(launch:()=>Promise<T>):Promise<T>{
  if(this.launching||this.closing)throw new PerchError('Microsoft browser launch cancelled or already started.','cancelled');
  this.launching=launch();const browser=await this.launching;
  if(this.closing)throw new PerchError('Microsoft browser launch was cancelled.','cancelled');
  return browser;
 }
 close():Promise<void>{return this.closing??=(async()=>{
  const browser=await this.launching?.catch(()=>undefined);
  try{await browser?.close();}finally{await this.release();}
 })();}
}
