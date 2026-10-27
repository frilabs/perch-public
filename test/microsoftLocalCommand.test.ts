import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { expect, it } from 'vitest';
import { localLoginCommand } from '../src/cli/microsoftSession.js';
it('executes only the pinned helper and passes the validated SSH arguments exactly',()=>{
 const source='export async function run(args){process.stdout.write(JSON.stringify(args))}';
 const hash=createHash('sha256').update(source).digest('hex');
 const command=localLoginCommand(8783,'a'.repeat(64),hash,'operator@example-server');
 expect(command).toContain("ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes 'operator@example-server'");
 const runner=command.split(' | ')[1]!;
 const good=spawnSync('/bin/sh',['-c',runner],{input:source,encoding:'utf8'});
 expect(good.status,good.stderr).toBe(0);
 expect(JSON.parse(good.stdout)).toEqual(['--ssh','operator@example-server','--port','8783','--token','a'.repeat(64)]);
 const changed=spawnSync('/bin/sh',['-c',runner],{input:source+';process.stdout.write("UNTRUSTED")',encoding:'utf8'});
 expect(changed.status).not.toBe(0);expect(changed.stdout).toBe('');
});
it('rejects options, shell substitutions, unsafe ports and malformed helper pins',()=>{
 for(const host of ['-oProxyCommand=x','home;touch x','$(false)','home ts'])expect(()=>localLoginCommand(8783,'a'.repeat(64),'b'.repeat(64),host)).toThrow();
 expect(()=>localLoginCommand(0,'a'.repeat(64),'b'.repeat(64),'home')).toThrow();
 expect(()=>localLoginCommand(8783,'a'.repeat(64),'wrong','home')).toThrow();
});
