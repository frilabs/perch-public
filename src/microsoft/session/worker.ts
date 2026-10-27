import { discoverSessionSites, type DiscoverySource } from './discovery.js';
import { normalizeSelectedSiteUrl } from './policy.js';
import { fileURLToPath } from 'node:url';
import { READONLY_PRINCIPAL, currentPrincipal, assertMailCapability, assertMicrosoftSessionCapability } from '../../auth/grants.js';
import { SessionBrowserLease } from './lifecycle.js';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import { PerchError } from '../../errors.js';
import { CredentialStore } from '../../store/credentialStore.js';
import { findSessionBrowser, launchSessionBrowser, openSessionProfile, sessionProfileId } from '../sessionBrowser.js';
import { BrowserSessionTransport } from './browserTransport.js';
import { checkedJson, type OperationContext } from './contracts.js';
import { MicrosoftIdentitySchema, MICROSOFT_SERVICES, SelectedSiteSchema, type MicrosoftIdentity, type MicrosoftSessionGroup } from './model.js';
import { authorizeSessionOperation, sessionOperations, type SessionJob, type SessionProbeReport } from './runtime.js';

const paths=z.object({dataDir:z.string().min(1),keyFile:z.string().min(1)}).passthrough();
const jobSchema=z.discriminatedUnion('kind',[
 z.object({kind:z.literal('execute'),paths,accountId:z.string().regex(/^ms(mail|teams|calendar|files)-[a-f0-9]{8}$/),operation:z.string().max(100),args:z.unknown(),revision:z.string().regex(/^[a-f0-9]{8,64}$/),allowInvites:z.boolean(),caller:z.object({kind:z.enum(['operator_readonly','client']),clientId:z.string().regex(/^client-[a-f0-9]{8}$/).optional(),tokenSha256:z.string().regex(/^[a-f0-9]{64}$/).optional()}).strict().optional()}).strict(),
 z.object({kind:z.literal('probe'),paths,label:z.string().min(1).max(100),sites:z.array(SelectedSiteSchema).max(100),expected:MicrosoftIdentitySchema.optional(),discover:z.boolean().optional()}).strict(),
]);
const errorCode=(error:unknown)=>error instanceof PerchError&&/^[a-z_]{1,64}$/.test(error.code)?error.code:'browser_failed';
function sameIdentity(expected:MicrosoftIdentity,actual:MicrosoftIdentity|undefined):void {
 if(!actual||actual.tenantId!==expected.tenantId||actual.objectId!==expected.objectId)throw new PerchError('Microsoft returned a different account identity.','identity_mismatch');
}
async function readGroup(store:CredentialStore,job:Extract<SessionJob,{kind:'execute'}>):Promise<MicrosoftSessionGroup>{
 const group=(await store.read()).microsoftSessions?.find(g=>Object.values(g.members).includes(job.accountId));
 if(!group||group.revision!==job.revision)throw new PerchError('Microsoft account was removed or changed.','account_changed');
 if(group.profileId!==sessionProfileId(group.label))throw new PerchError('Microsoft profile binding is invalid.','identity_mismatch');
 authorizeSessionOperation(group,job.accountId,job.operation);return group;
}
async function authorizeCaller(store:CredentialStore,job:Extract<SessionJob,{kind:'execute'}>,group:MicrosoftSessionGroup):Promise<boolean>{
 const principal=job.caller?.kind==='client'?await currentPrincipal(store,{...READONLY_PRINCIPAL,...job.caller}):READONLY_PRINCIPAL;
 const op=sessionOperations[job.operation]!;
 if(op.service==='mail'){
  const cap=op.mode==='read'?'read':job.operation==='mail.createDraft'?'draft':['mail.send','mail.sendDraft'].includes(job.operation)?'send':'modify';
  assertMailCapability(principal,job.accountId,cap);
 }else {
  const cap=op.service==='teams'?(op.mode==='read'?'microsoft_teams_read':'microsoft_teams_send'):op.service==='calendar'?(op.mode==='read'?'microsoft_calendar_read':'microsoft_calendar_write'):(op.mode==='read'?'microsoft_files_read':'microsoft_files_write');
  assertMicrosoftSessionCapability(principal,op.service,job.accountId,cap);
 }
 if(!job.allowInvites||!group.services.calendar.invite)return false;
 try{assertMicrosoftSessionCapability(principal,'calendar',group.members.calendar,'microsoft_calendar_invite');return true;}catch{return false;}
}
export async function runSessionJob(raw:unknown,onProgress:(service:string)=>void=()=>{}):Promise<unknown>{
 const parsed=jobSchema.safeParse(raw);if(!parsed.success)throw new PerchError('Invalid private Microsoft session job.','bad_argument');
 const job=parsed.data as SessionJob;
 const store=await CredentialStore.open(job.paths);
 const group=job.kind==='execute'?await readGroup(store,job):undefined;
 if(job.kind==='execute')await authorizeCaller(store,job,group!);
 const label=group?.label??(job as Extract<SessionJob,{kind:'probe'}>).label;
 const sites=group?.sites??(job as Extract<SessionJob,{kind:'probe'}>).sites;
 const expected=group?.identity??(job as Extract<SessionJob,{kind:'probe'}>).expected;
 const executable=await findSessionBrowser(process.env);
 // Shared profile lock serializes CLI and every MCP process. No browser profile is copied or imported.
 let profile:Awaited<ReturnType<typeof openSessionProfile>>|undefined;
 const deadline=Date.now()+30_000;
 while(!profile){try{profile=await openSessionProfile(job.paths.dataDir,label,{existing:true});}catch(error){if(!(error instanceof PerchError)||error.code!=='locked'||Date.now()>deadline)throw error;await delay(250);}}
 let browser:Awaited<ReturnType<typeof launchSessionBrowser>>|undefined;
 let transport:BrowserSessionTransport|undefined;
 const lease=new SessionBrowserLease<Awaited<ReturnType<typeof launchSessionBrowser>>>(()=>profile!.release());
 let stopping:Promise<void>|undefined;
 const cleanup=()=>stopping??=(async()=>{transport?.close();await lease.close();})();
 const stop=()=>{void cleanup().finally(()=>process.exit(1));};
 process.once('SIGTERM',stop);process.once('SIGINT',stop);process.once('disconnect',stop);
 try {
  if(job.kind==='execute'){const current=await readGroup(store,job);await authorizeCaller(store,job,current);}
  browser=await lease.start(()=>launchSessionBrowser(executable,profile!.path,'about:blank',{workerMode:true,selectedHosts:sites.map(s=>new URL(normalizeSelectedSiteUrl(s.url)).hostname)}));
  transport=new BrowserSessionTransport(browser.protocol,sites,expected,{beforeMutation:async()=>{
   if(job.kind==='execute'){const current=await readGroup(store,job);const invites=await authorizeCaller(store,job,current);if(job.allowInvites&&!invites)throw new PerchError('Calendar invitation permission changed before submission.','capability_denied');}
  }});
  const t=transport;
  if(job.kind==='execute') {
   const op=sessionOperations[job.operation]!;const args=op.schema.parse(job.args) as any;
   await t.open(op.service,args.siteId);
   const ctx:OperationContext={request:r=>t.request(r),identity:group!.identity,sites,cursors:store,displayName:group!.displayName,allowInvites:await authorizeCaller(store,job,group!)};
   if(op.service==='mail'||op.service==='calendar') {
    const me=await sessionOperations['mail.profile']!.run(ctx,{} ) as any;
    sameIdentity(group!.identity,t.identity);
    if(group!.identity.mailboxId&&(me.mailboxId??me.id)!==group!.identity.mailboxId)throw new PerchError('Microsoft mailbox identity changed.','identity_mismatch');
   } else if(op.service==='teams') {
    await sessionOperations['teams.listChats']!.run(ctx,{limit:1});sameIdentity(group!.identity,t.identity);
   } else await sessionOperations['files.probeSite']!.run(ctx,{siteId:args.siteId});
   // Re-read after browser navigation and identity probes, immediately before dispatch.
   const current=await readGroup(store,job);ctx.allowInvites=await authorizeCaller(store,job,current);
   return await op.run(ctx,args);
  }
  const services=Object.fromEntries(MICROSOFT_SERVICES.map(service=>[service,{enabled:true,write:false,invite:false,status:'unverified'}])) as MicrosoftSessionGroup['services'];
  const libraries:SessionProbeReport['libraries']=[];
  let identity:MicrosoftIdentity|undefined=expected,email:string|undefined,displayName:string|undefined;
  const refreshIdentity=()=>{if(t.identity){if(expected)sameIdentity(expected,t.identity);identity={...t.identity,...(identity?.mailboxId?{mailboxId:identity.mailboxId}:{})};}};
  const ctx=():OperationContext=>({request:r=>t.request(r),identity:identity!,sites,cursors:store});
  for(const service of ['mail','teams','calendar'] as const){
   onProgress(service);
   try{
    await t.open(service);
    if(service==='mail'){
     const me=checkedJson(await t.request({resource:'outlook',path:'/api/v2.0/me'}));refreshIdentity();
     if(!identity)throw new PerchError('No verified Microsoft identity.','identity_mismatch');
     const mailbox=me.MailboxGuid??me.Id;if(typeof mailbox!=='string'||!mailbox||mailbox.length>512)throw new PerchError('Mailbox identity is missing.','identity_mismatch');
     if(expected?.mailboxId&&expected.mailboxId!==mailbox)throw new PerchError('Mailbox identity changed.','identity_mismatch');
     identity={...identity,mailboxId:mailbox};email=z.string().email().safeParse(me.EmailAddress).success?me.EmailAddress:undefined;displayName=typeof me.DisplayName==='string'?me.DisplayName.slice(0,300):undefined;
     await sessionOperations['mail.listFolders']!.run(ctx(),{pageSize:1});
    }else if(service==='teams'){
     // Only bootstrap CSA when this transport has not already verified the account.
     // A saved expected identity alone does not prove this browser's current identity.
     if(!t.identity){
      try{checkedJson(await t.request({resource:'csa',path:'/api/v3/teams/users/me',query:{isPrefetch:'false',enableMembershipSummary:'true'}}));refreshIdentity();}catch(error){if(errorCode(error)==='identity_mismatch')throw error;}
     }
     if(!identity)throw new PerchError('Teams did not establish a stable Microsoft identity.','identity_mismatch');
     await sessionOperations['teams.listChats']!.run(ctx(),{limit:1});refreshIdentity();
    }else{
     if(!identity)throw new PerchError('Calendar identity is unavailable.','identity_mismatch');
     await sessionOperations['calendar.listCalendars']!.run(ctx(),{pageSize:1});refreshIdentity();
    }
    services[service].status='ready';
   }catch(error){const code=errorCode(error);if(code==='identity_mismatch'&&expected)throw error;services[service].status=code==='reauth_required'?'reauth_required':code==='access_denied'?'blocked_by_policy':'unavailable';services[service].errorCode=code;}
   services[service].checkedAt=new Date().toISOString();
  }
  const metadata=(t as BrowserSessionTransport&{metadata?:{email?:string;displayName?:string}}).metadata;
  email??=metadata?.email;displayName??=metadata?.displayName;
  if(!identity||!email){
   onProgress('identity');await t.open('graph');const me=checkedJson(await t.request({resource:'graph',path:'/v1.0/me'}));refreshIdentity();
   if(!identity||typeof me.id!=='string'||me.id.toLowerCase()!==identity.objectId)throw new PerchError('Microsoft identity could not be verified.','identity_mismatch');
   email??=me.mail??me.userPrincipalName;displayName??=me.displayName;
  }
  if(!identity||!z.string().email().safeParse(email).success)throw new PerchError('No usable account identity; finish the Microsoft login and retry.','reauth_required');
  onProgress('files');
  let discovery:DiscoverySource[]|undefined;
  if(job.discover){
   try {
    // Verify the same immutable account at the discovery API, even if mail already succeeded.
    await t.open('graph');
    const me=checkedJson(await t.request({resource:'graph',path:'/v1.0/me'}));refreshIdentity();
    if(typeof me.id!=='string'||me.id.toLowerCase()!==identity.objectId.toLowerCase())throw new PerchError('Discovery belongs to a different Microsoft identity.','identity_mismatch');
    const found=await discoverSessionSites(r=>t.request(r),sites);
    for(const site of found.sites){
     if(!sites.some(s=>s.url===site.url)){
      if(!browser.allowDiscoveredSite)throw new PerchError('Browser discovery protection is unavailable.','browser_failed');
      browser.allowDiscoveredSite(site.url);sites.push(site);
     }
    }
    discovery=found.sources;
   }catch(error){
    const code=errorCode(error);if(code==='identity_mismatch')throw error;
    discovery=(['onedrive','followed','search'] as const).map(source=>({source,status:'unavailable',code}));
   }
  }
  let selectedReady=0;let failures=0;
  const fileErrors:Array<{siteId:string;code:string}>=[];
  const fileDeadline=Date.now()+120_000;
  for(const site of sites){
   try{
    if(Date.now()>=fileDeadline)throw new PerchError('File discovery time limit reached.','discovery_limit');
    await t.open('files',site.id);
    const result=await sessionOperations['files.probeSite']!.run(ctx(),{siteId:site.id}) as SessionProbeReport['libraries'][number];libraries.push(result);
    if(site.driveIds.length){await sessionOperations['files.listDrives']!.run(ctx(),{siteId:site.id});selectedReady++;}
    else if(job.discover&&result.drives.length)selectedReady++;
   }catch(error){failures++;const code=errorCode(error);services.files.errorCode=code;fileErrors.push({siteId:site.id,code});}
  }
  services.files.enabled=selectedReady>0;
  services.files.status=selectedReady>0?'ready':failures?'degraded':'unavailable';services.files.checkedAt=new Date().toISOString();
  return {identity,email:email!,displayName,services,sites,libraries,discovery,fileErrors,blockedHosts:browser.blockedHosts?.()??[]} satisfies SessionProbeReport;
 }catch(error){
  const hosts=browser?.blockedHosts?.()??[];
  if(hosts.length&&error instanceof PerchError)throw new PerchError(`${error.message} Browser blocked hosts: ${hosts.join(', ')}. Review these names before explicitly configuring PERCH_MICROSOFT_ALLOWED_HOSTS; no host is automatically approved.`,error.code);
  throw error;
 }finally{process.removeListener('SIGTERM',stop);process.removeListener('SIGINT',stop);process.removeListener('disconnect',stop);await cleanup();}
}
if(process.send&&process.argv[1]===fileURLToPath(import.meta.url)){
 process.once('message',job=>{void runSessionJob(job,service=>process.send?.({type:'progress',service})).then(value=>process.send?.({type:'result',value},()=>process.disconnect?.()),error=>process.send?.({type:'error',code:errorCode(error),message:error instanceof PerchError?error.message:'Microsoft session worker failed.'},()=>process.disconnect?.()));});
}
