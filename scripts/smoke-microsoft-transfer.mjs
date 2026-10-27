// Opt-in Linux Chrome smoke. Synthetic state only; never uses an account or existing profile.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const base=path.resolve(process.argv[2]??'.');
const {launchSessionBrowser,findSessionBrowser,openSessionProfile}=await import(pathToFileURL(path.join(base,'dist/microsoft/sessionBrowser.js')));
const {importPortableState,parsePortableState}=await import(pathToFileURL(path.join(base,'dist/microsoft/session/portableState.js')));
const root=await mkdtemp(path.join(tmpdir(),'perch-transfer-smoke-'));
const profile=await openSessionProfile(root,'SyntheticTransfer');
const executable=await findSessionBrowser(process.env);
let browser;
const origin='https://login.microsoftonline.com';
try {
 browser=await launchSessionBrowser(executable,profile.path,'about:blank');
 const cookie={name:'perch_synthetic_persistent',value:'synthetic',domain:'login.microsoftonline.com',path:'/',secure:true,httpOnly:true,sameSite:'Lax',expires:Math.floor(Date.now()/1000)+600};
 await importPortableState(browser,parsePortableState({version:1,cookies:[cookie,{...cookie,name:'perch_synthetic_session',expires:-1}],origins:[{origin,localStorage:[{name:'perch_synthetic',value:'retained'}],sessionStorage:[]}]}));
 const before=(await browser.protocol.call('Storage.getCookies')).cookies;
 assert.equal(before.filter(c=>c.name.startsWith('perch_synthetic')).length,2);
 await browser.close();
 browser=await launchSessionBrowser(executable,profile.path,'about:blank');
 const cookies=(await browser.protocol.call('Storage.getCookies')).cookies;
 assert.equal(cookies.find(c=>c.name==='perch_synthetic_session')?.value,'synthetic','session cookie lost on reopen');
 assert.equal(cookies.find(c=>c.name==='perch_synthetic_persistent')?.value,'synthetic','persistent cookie lost on reopen');
 // Reopen a synthetic origin document to read storage; no network response is used.
 await importPortableState(browser,parsePortableState({version:1,cookies:[],origins:[{origin,localStorage:[],sessionStorage:[]}]}));
 const storage=await browser.protocol.call('Runtime.evaluate',{expression:'localStorage.getItem("perch_synthetic")',returnByValue:true},browser.mainSessionId);
 assert.equal(storage.result?.value,'retained','localStorage lost on reopen');
 await browser.close();
 browser=await launchSessionBrowser(executable,profile.path,'about:blank',{workerMode:true});
 assert.equal((await browser.protocol.call('Storage.getCookies')).cookies.filter(c=>c.name.startsWith('perch_synthetic')).length,2,'worker startup lost cookies');
 console.log(JSON.stringify({persistentCookie:true,localStorage:true,sessionCookie:!!cookies.find(c=>c.name==='perch_synthetic_session'),syntheticOnly:true}));
} finally {await browser?.close();await profile.release();await rm(root,{recursive:true,force:true});}
