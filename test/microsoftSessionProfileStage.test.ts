import {it,expect} from 'vitest';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {openSessionProfile} from '../src/microsoft/sessionBrowser.js';
import {stageSessionProfile} from '../src/microsoft/session/profileStage.js';
it('keeps the original profile unchanged on cancelled reconnect and commits only the verified candidate',async()=>{
 const root=await mkdtemp(path.join(tmpdir(),'perch-ms-stage-'));
 try{
 const original=await openSessionProfile(root,'Work');await writeFile(path.join(original.path,'session.txt'),'original');await original.release();
 const cancelled=await stageSessionProfile(root,'Work');expect(await readFile(path.join(cancelled.path,'session.txt'),'utf8')).toBe('original');await writeFile(path.join(cancelled.path,'session.txt'),'wrong');await cancelled.release();await cancelled.discard();
 expect(await readFile(path.join(original.path,'session.txt'),'utf8')).toBe('original');
 const candidate=await stageSessionProfile(root,'Work');await writeFile(path.join(candidate.path,'session.txt'),'verified');await candidate.release();
 await expect(openSessionProfile(root,'Work')).rejects.toMatchObject({code:'locked'});
 await candidate.commit();expect(await readFile(path.join(original.path,'session.txt'),'utf8')).toBe('verified');await candidate.discard();
 const resumed=await openSessionProfile(root,'Work');await resumed.release();
 }finally{await rm(root,{recursive:true,force:true});}
});

it('imports into an empty candidate without mixing previous credentials',async()=>{
 const root=await mkdtemp(path.join(tmpdir(),'perch-ms-stage-'));
 try{
  const original=await openSessionProfile(root,'Work');await writeFile(path.join(original.path,'old.txt'),'old');await original.release();
  const candidate=await stageSessionProfile(root,'Work',{empty:true});
  await expect(readFile(path.join(candidate.path,'old.txt'))).rejects.toMatchObject({code:'ENOENT'});
  await writeFile(path.join(candidate.path,'new.txt'),'verified');await candidate.release();await candidate.commit();
  await expect(readFile(path.join(original.path,'old.txt'))).rejects.toMatchObject({code:'ENOENT'});
  expect(await readFile(path.join(original.path,'new.txt'),'utf8')).toBe('verified');
 }finally{await rm(root,{recursive:true,force:true});}
});
