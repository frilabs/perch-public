import { expect, it, vi } from 'vitest';
import { initStore, CredentialStore } from '../src/store/credentialStore.js';
import { makeTempDirs } from './support/fixtures.js';
import { SessionRuntime } from '../src/microsoft/session/runtime.js';
import { MicrosoftSessionGroupSchema } from '../src/microsoft/session/model.js';
const fixture=()=>MicrosoftSessionGroupSchema.parse({id:'mgroup-12345678',label:'Work',email:'test@example.test',profileId:'ms-session-0123456789abcdef01234567',identity:{tenantId:'11111111-1111-4111-8111-111111111111',objectId:'22222222-2222-4222-8222-222222222222',kind:'organization'},members:{teams:'msteams-12345678',mail:'msmail-12345678',calendar:'mscalendar-12345678',files:'msfiles-12345678'},services:Object.fromEntries(['teams','mail','calendar','files'].map(s=>[s,{enabled:true,write:false,invite:false,status:'unverified'}])),sites:[],createdAt:'2026-10-26T00:00:00.000Z',updatedAt:'2026-10-26T00:00:00.000Z',revision:'12345678'});
it('dispatches only typed operations for the selected enabled member and refreshes stored state',async()=>{
 const dirs=await makeTempDirs();try{
 await initStore(dirs);const store=await CredentialStore.open(dirs);await store.update(d=>{d.microsoftSessions=[fixture()]});
 const run=vi.fn(async()=>({chats:[]}));const runtime=new SessionRuntime(store,{run});
 await expect(runtime.execute('msteams-12345678','mail.search',{})).rejects.toMatchObject({code:'capability_denied'});
 await expect(runtime.execute('msteams-12345678','teams.send',{conversationId:'19:one@thread.v2',text:'test'})).rejects.toMatchObject({code:'capability_denied'});
 await expect(runtime.execute('msteams-12345678','fetch',{url:'https://evil.test'})).rejects.toMatchObject({code:'bad_argument'});
 expect(run).not.toHaveBeenCalled();
 await runtime.execute('msteams-12345678','teams.listChats',{});expect(run).toHaveBeenCalledTimes(1);
 expect((await store.read()).microsoftSessions?.[0]?.services.teams.status).toBe('ready');
 await store.update(d=>{d.microsoftSessions![0]!.services.teams.enabled=false});
 await expect(runtime.execute('msteams-12345678','teams.listChats',{})).rejects.toMatchObject({code:'capability_denied'});
 expect(run).toHaveBeenCalledTimes(1);
 }finally{await dirs.cleanup()}
});
it('records expired sessions without retrying a write or accepting arbitrary worker errors',async()=>{
 const dirs=await makeTempDirs();try{await initStore(dirs);const store=await CredentialStore.open(dirs);const g=fixture();g.services.teams.write=true;await store.update(d=>{d.microsoftSessions=[g]});
 const {PerchError}=await import('../src/errors.js');const run=vi.fn(async()=>{throw new PerchError('Expired','reauth_required')});const runtime=new SessionRuntime(store,{run});
 await expect(runtime.execute(g.members.teams,'teams.send',{conversationId:'19:one@thread.v2',text:'test'})).rejects.toMatchObject({code:'reauth_required'});
 expect(run).toHaveBeenCalledTimes(1);expect((await store.read()).microsoftSessions?.[0]?.services.teams.status).toBe('reauth_required');
 }finally{await dirs.cleanup()}
});

it('rejects a queued job when its account revision changes while an earlier job runs', async () => {
  const dirs = await makeTempDirs();
  let release!: () => void;
  try {
    await initStore(dirs); const store = await CredentialStore.open(dirs); const group = fixture();
    await store.update((data) => { data.microsoftSessions = [group]; });
    let started!: () => void;
    const firstStarted = new Promise<void>((resolve) => { started = resolve; });
    const pending = new Promise<void>((resolve) => { release = resolve; });
    const run = vi.fn(async () => { started(); await pending; return { chats: [] }; });
    const runtime = new SessionRuntime(store, { run });
    const first = runtime.execute(group.members.teams, 'teams.listChats', {});
    await firstStarted;
    let initialRead!: () => void;
    const readCompleted = new Promise<void>((resolve) => { initialRead = resolve; });
    const read = store.read.bind(store);
    vi.spyOn(store, 'read').mockImplementationOnce(async () => { const data = await read(); initialRead(); return data; });
    const second = runtime.execute(group.members.teams, 'teams.listChats', {}, { expectedRevision: group.revision }).then((value) => ({ value }), (error: unknown) => ({ error }));
    await readCompleted;
    await store.update((data) => { data.microsoftSessions![0]!.revision = '87654321'; });
    release(); await first;
    expect(await second).toMatchObject({ error: { code: 'account_changed' } });
    expect(run).toHaveBeenCalledTimes(1);
  } finally { release?.(); await dirs.cleanup(); }
});
it('rejects an already changed caller revision before dispatch', async () => {
  const dirs = await makeTempDirs();
  try {
    await initStore(dirs); const store = await CredentialStore.open(dirs); const group = fixture();
    await store.update((data) => { data.microsoftSessions = [group]; });
    const run = vi.fn(async () => ({ chats: [] })); const runtime = new SessionRuntime(store, { run });
    await expect(runtime.execute(group.members.teams, 'teams.listChats', {}, { expectedRevision: '87654321' })).rejects.toMatchObject({ code: 'account_changed' });
    expect(run).not.toHaveBeenCalled();
  } finally { await dirs.cleanup(); }
});

it('draft-only Microsoft mail permits drafts but denies every send and organization operation', async () => {
  const { authorizeSessionOperation } = await import('../src/microsoft/session/runtime.js');
  const { sessionMailAccounts } = await import('../src/microsoft/session/model.js');
  const group = fixture();
  group.services.mail.write = true;
  group.services.mail.draftsOnly = true;
  expect(sessionMailAccounts([group])[0]).toMatchObject({ allowDrafts: true, allowSend: false, allowModify: false });
  expect(authorizeSessionOperation(group, group.members.mail, 'mail.search')).toBe('mail');
  expect(authorizeSessionOperation(group, group.members.mail, 'mail.createDraft')).toBe('mail');
  for (const operation of ['mail.send', 'mail.sendDraft', 'mail.mark', 'mail.move', 'mail.trash', 'mail.restore']) {
    expect(() => authorizeSessionOperation(group, group.members.mail, operation)).toThrow(/drafts only/);
  }
  group.services.mail.write = false;
  expect(() => authorizeSessionOperation(group, group.members.mail, 'mail.createDraft')).toThrow(/not enabled/);
});
