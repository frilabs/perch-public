// Subprocess worker for cross-process mail workflow tests. Uses the compiled sources from argv[2].
// The mail provider is a MOCK: "sending" appends one line to <sendLog>; nothing touches the network.
// Modes:
//   send <dataDir> <keyFile> <tokenFile> <sendLog> <goFile> <requestId>
//        waits until <goFile> exists (start barrier), sends once, prints the JSON outcome
//   hang <dataDir> <keyFile> <tokenFile> <sendLog> <goFile> <requestId>
//        like send, but the MOCK provider never returns after recording the attempt (killed by the test)
import { appendFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [buildDir, mode, dataDir, keyFile, tokenFile, sendLog, goFile, requestId] = process.argv.slice(2);
const load = (p) => import(pathToFileURL(path.join(buildDir, p)).href);
const { CredentialStore } = await load('store/credentialStore.js');
const { principalForClientToken } = await load('auth/grants.js');
const { MailService } = await load('mail/service.js');
const { readFileSync } = await import('node:fs');

const store = await CredentialStore.open({ dataDir, keyFile });
const principal = await principalForClientToken(store, readFileSync(tokenFile, 'utf8').trim());

const provider = {
  kind: 'imap',
  providerCapabilities: () => ({ draft: true, send: true }),
  replyContext: async () => ({ references: [] }),
  send: async () => {
    appendFileSync(sendLog, `${process.pid}\n`);
    if (mode === 'hang') return new Promise(() => {});
    await new Promise((r) => setTimeout(r, 30));
    return { status: 'accepted', detail: 'MOCK accepted' };
  },
};
const service = new MailService(store, { gmail: provider, microsoft: provider, imap: provider });

while (!existsSync(goFile)) await new Promise((r) => setTimeout(r, 2));
if (mode === 'hang') process.stdout.write('started\n');
const result = await service.send(principal, {
  accountId: 'imap-0000000a',
  requestId,
  to: ['friend@example.test'],
  subject: 'Cross-process',
  text: 'Body',
});
process.stdout.write(`${JSON.stringify({ status: result.status, replayed: result.replayed, requestState: result.requestState })}\n`);
