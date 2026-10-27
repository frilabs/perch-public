import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PerchError } from '../../errors.js';
import type { CredentialStore, StorePaths } from '../../store/credentialStore.js';
import { teamsOperations } from './teams.js';
import { outlookOperations } from './outlook.js';
import { filesOperations } from './files.js';
import type { SessionCaller, MicrosoftIdentity, MicrosoftService, MicrosoftSessionGroup, SelectedSite } from './model.js';
import type { SessionOperations } from './contracts.js';
export const sessionOperations:SessionOperations={...teamsOperations,...outlookOperations,...filesOperations};
export interface SessionProbeReport {
 discovery?:import('./discovery.js').DiscoverySource[]; fileErrors?:Array<{siteId:string;code:string}>;
 blockedHosts?:string[];identity:MicrosoftIdentity;email:string;displayName?:string;services:MicrosoftSessionGroup['services'];sites:SelectedSite[];
 libraries:Array<{siteId:string;drives:Array<{id:string;name?:string}>;hasMore?:boolean}>;
}
export type SessionJob={paths:StorePaths}&(
 {kind:'execute';accountId:string;operation:string;args:unknown;revision:string;allowInvites:boolean;caller?:SessionCaller}|
 {kind:'probe';label:string;sites:SelectedSite[];expected?:MicrosoftIdentity;discover?:boolean});
export type SessionJobRunner=(job:SessionJob,onProgress?:(step:string)=>void)=>Promise<unknown>;
function workerRunner(env:NodeJS.ProcessEnv):SessionJobRunner {
 return (job,onProgress)=>new Promise((resolve,reject)=>{
  const child=fork(fileURLToPath(new URL('./worker.js',import.meta.url)),[],{stdio:['ignore','ignore','ignore','ipc'],env,serialization:'advanced',execArgv:[]});
  let settled=false;let killTimer:ReturnType<typeof setTimeout>|undefined;
  const finish=(error?:Error,value?:unknown)=>{if(settled)return;settled=true;clearTimeout(timer);if(killTimer)clearTimeout(killTimer);if(error){child.kill('SIGTERM');killTimer=setTimeout(()=>child.kill('SIGKILL'),7000);killTimer.unref();reject(error);}else resolve(value);};
  const timer=setTimeout(()=>finish(new PerchError('Microsoft session worker timed out. A write may have completed; inspect its recorded status before retrying.','browser_timeout')),job.kind==='probe'?480_000:90_000);
  child.on('message',(message:any)=>{
   if(message?.type==='progress'&&['mail','teams','calendar','files','identity'].includes(message.service))onProgress?.(`Checking Microsoft ${message.service} …`);
   if(message?.type==='result')finish(undefined,message.value);
   if(message?.type==='error')finish(new PerchError(typeof message.message==='string'?message.message.slice(0,1500):'Microsoft session operation failed.',typeof message.code==='string'&&/^[a-z_]{1,64}$/.test(message.code)?message.code:'browser_failed'));
  });
  child.once('error',()=>finish(new PerchError('Could not start Microsoft session worker. Build Perch before running it.','browser_failed')));
  child.once('exit',()=>{if(killTimer)clearTimeout(killTimer);if(!settled)finish(new PerchError('Microsoft session worker stopped unexpectedly.','browser_failed'));});
  child.send(job,error=>{if(error)finish(new PerchError('Could not contact Microsoft session worker.','browser_failed'));});
 });
}
export function serviceForAccount(group:MicrosoftSessionGroup,accountId:string):MicrosoftService|undefined {
 return (Object.keys(group.members) as MicrosoftService[]).find(service=>group.members[service]===accountId);
}
export function authorizeSessionOperation(group:MicrosoftSessionGroup,accountId:string,operation:string):MicrosoftService {
 const op=Object.hasOwn(sessionOperations,operation)?sessionOperations[operation]:undefined;if(!op||op.internalOnly)throw new PerchError('Unknown Microsoft operation.','bad_argument');
 const service=serviceForAccount(group,accountId);
 if(service!==op.service||!group.services[service].enabled||(op.mode!=='read'&&!group.services[service].write))throw new PerchError('This Microsoft service or operation is not enabled.','capability_denied');
 if(service==='mail'&&group.services.mail.draftsOnly&&op.mode!=='read'&&operation!=='mail.createDraft')throw new PerchError('This Microsoft mailbox permits drafts only.','capability_denied');
 return service;
}
export class SessionRuntime {
 private run:SessionJobRunner;
 private queues=new Map<string,Promise<unknown>>();
 constructor(private store:CredentialStore,options:{env?:NodeJS.ProcessEnv;run?:SessionJobRunner}={}){this.run=options.run??workerRunner(options.env??process.env);}
 private async queued<T>(key:string,task:()=>Promise<T>):Promise<T>{
  const previous=this.queues.get(key)??Promise.resolve();const current=previous.catch(()=>{}).then(task);this.queues.set(key,current);
  try{return await current;}finally{if(this.queues.get(key)===current)this.queues.delete(key);}
 }
 async execute(accountId:string,operation:string,args:unknown,options:{allowInvites?:boolean;caller?:SessionCaller;expectedRevision?:string}={}):Promise<unknown>{
  if(!Object.hasOwn(sessionOperations,operation)||sessionOperations[operation]!.internalOnly)throw new PerchError('Unknown Microsoft operation.','bad_argument');
  const op=sessionOperations[operation]!;const parsed=op.schema.safeParse(args);if(!parsed.success)throw new PerchError('Invalid Microsoft operation arguments.','bad_argument');
  const find=async()=>{const group=(await this.store.read()).microsoftSessions?.find(g=>Object.values(g.members).includes(accountId));if(!group)throw new PerchError('Unknown Microsoft service account.','unknown_account');authorizeSessionOperation(group,accountId,operation);return group;};
  const initial=await find();
  if(options.expectedRevision!==undefined&&initial.revision!==options.expectedRevision)throw new PerchError('Microsoft account changed before dispatch.','account_changed');
  const binding=(g:MicrosoftSessionGroup)=>JSON.stringify([g.id,g.revision,g.profileId,g.identity,g.members,g.services.teams.enabled,g.services.teams.write,g.services.mail.enabled,g.services.mail.write,g.services.mail.draftsOnly,g.services.calendar.enabled,g.services.calendar.write,g.services.calendar.invite,g.services.files.enabled,g.services.files.write,g.sites]);
  return this.queued(initial.profileId,async()=>{
   const group=await find();if(binding(group)!==binding(initial))throw new PerchError('Microsoft account changed while waiting for its browser.','account_changed');const service=op.service;
   try {
    const result=await this.run({kind:'execute',paths:this.store.storePaths,accountId,operation,args:parsed.data,revision:group.revision,caller:options.caller,allowInvites:options.allowInvites===true&&group.services.calendar.invite});
    await this.status(group,service,'ready');return result;
   }catch(error){
    const code=error instanceof PerchError?error.code:'browser_failed';
    await this.status(group,service,code==='reauth_required'?'reauth_required':code==='access_denied'?'blocked_by_policy':'degraded',code).catch(()=>{});throw error;
   }
  });
 }
 private async status(group:MicrosoftSessionGroup,service:MicrosoftService,status:MicrosoftSessionGroup['services']['mail']['status'],code?:string){
  await this.store.update(data=>{const current=data.microsoftSessions?.find(g=>g.id===group.id&&g.revision===group.revision);if(!current)return;current.services[service].status=status;current.services[service].checkedAt=new Date().toISOString();current.services[service].errorCode=code&&/^[a-z_]{1,64}$/.test(code)?code:undefined;});
 }
 async probeProfile(label:string,sites:SelectedSite[],expected?:MicrosoftIdentity,onProgress?:(step:string)=>void,discover=false):Promise<SessionProbeReport>{
  return this.queued(`probe:${label}`,()=>this.run({kind:'probe',paths:this.store.storePaths,label,sites,expected,discover},onProgress)) as Promise<SessionProbeReport>;
 }
}
