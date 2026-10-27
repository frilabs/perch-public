import { randomBytes } from 'node:crypto';
import { cp, lstat, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { openSessionProfile } from '../sessionBrowser.js';
import { PerchError } from '../../errors.js';
/** Reconnect copies only Perch's own private server profile. The working profile stays locked and unchanged until verification succeeds. */
export async function stageSessionProfile(dataDir:string,label:string,options:{empty?:boolean}={}){
 const original=await openSessionProfile(dataDir,label);
 const probeLabel=`reconnect-${randomBytes(16).toString('hex')}`;
 let candidate:Awaited<ReturnType<typeof openSessionProfile>>|undefined;
 let finished=false;
 const backup=path.join(path.dirname(original.path),`browser-previous-${randomBytes(8).toString('hex')}`);
 try{
  candidate=await openSessionProfile(dataDir,probeLabel);
  if(!options.empty)await cp(original.path,candidate.path,{recursive:true,force:true,filter:async source=>{
   if(['SingletonLock','SingletonCookie','SingletonSocket'].includes(path.basename(source)))return false;
   const stat=await lstat(source);return !stat.isSymbolicLink()&&(stat.isDirectory()||stat.isFile());
  }});
 }catch(error){await candidate?.release();if(candidate)await rm(path.dirname(candidate.path),{recursive:true,force:true});await original.release();throw error;}
 const staged=candidate;
 const discard=async()=>{
  if(finished)return;finished=true;
  try{await staged.release();await rm(path.dirname(staged.path),{recursive:true,force:true});}finally{await original.release();}
 };
 return {
  path:staged.path,id:original.id,probeLabel,release:staged.release,
  async commit(){
   if(finished)throw new PerchError('Reconnect candidate is already closed.','cancelled');
   await staged.release();
   const guard=await openSessionProfile(dataDir,probeLabel);
   let moved=false;
   try{
    await rename(original.path,backup);
    try{await rename(staged.path,original.path);moved=true;}catch(error){await rename(backup,original.path);throw error;}
    await rm(backup,{recursive:true,force:true});
   }finally{
    await guard.release();
    if(moved){finished=true;try{await rm(path.dirname(staged.path),{recursive:true,force:true});}finally{await original.release();}}
   }
  },discard,
 };
}
