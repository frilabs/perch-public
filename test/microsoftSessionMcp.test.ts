import path from 'node:path';
import { createClientGrant, principalFromGrant, READONLY_PRINCIPAL } from '../src/auth/grants.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { it, expect } from 'vitest';
import { createPerchContext } from '../src/context.js';
import { createMcpServer } from '../src/mcp/server.js';
import { CredentialStore, initStore } from '../src/store/credentialStore.js';
import { makeTempDirs } from './support/fixtures.js';
it.each(['operator', 'read-all'])('exposes Microsoft reads without write tools for %s through actual MCP transport',async(kind)=>{
 const dirs=await makeTempDirs();let client:Client|undefined;let server:ReturnType<typeof createMcpServer>|undefined;
 try{await initStore(dirs);const store=await CredentialStore.open(dirs);const ctx=createPerchContext(store);const principal=kind==='operator'?READONLY_PRINCIPAL:principalFromGrant((await createClientGrant(store,{label:'Reader',capabilities:[],accountIds:[],readAll:true,tokenFile:path.join(dirs.dataDir,'reader.token')})).client);server=createMcpServer(ctx,principal);client=new Client({name:'session-test',version:'1'});
 const [a,b]=InMemoryTransport.createLinkedPair();await Promise.all([server.connect(a),client.connect(b)]);
 const names=(await client.listTools()).tools.map(t=>t.name);
 expect(names).toContain('microsoft_teams_list_chats');expect(names).toContain('microsoft_calendar_list_events');expect(names).toContain('microsoft_files_list_files');
 expect(names).not.toContain('microsoft_teams_send');expect(names).not.toContain('microsoft_calendar_create_event');expect(names).not.toContain('microsoft_files_upload');expect(names).not.toContain('microsoft_files_probe_site');
 const result=await client.callTool({name:'perch_list_accounts',arguments:{}});expect(JSON.stringify(result)).toContain('microsoftSession');
 }finally{await client?.close();await server?.close();await dirs.cleanup();}
});
