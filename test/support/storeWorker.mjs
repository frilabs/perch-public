// Subprocess worker for cross-process store tests. Uses the compiled store from argv[2].
// Modes:
//   update <dataDir> <keyFile> <count> <tag>  -> appends <count> dummy Notion entries
//   init   <dataDir> <keyFile>                -> runs initStore, prints JSON result
//   hold   <dataDir> <keyFile>                -> acquires the store lock, prints "held", never releases
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [buildDir, mode, dataDir, keyFile, count, tag] = process.argv.slice(2);
const { CredentialStore, initStore } = await import(pathToFileURL(path.join(buildDir, 'store', 'credentialStore.js')).href);
const paths = { dataDir, keyFile };

if (mode === 'init') {
  process.stdout.write(JSON.stringify(await initStore(paths)));
} else if (mode === 'update') {
  const store = await CredentialStore.open(paths);
  for (let i = 0; i < Number(count); i++) {
    await store.update((d) => {
      const now = new Date().toISOString();
      d.notion.push({
        id: `notion-${randomBytes(4).toString('hex')}`,
        label: `${tag}-${i}`,
        token: `DUMMY-TEST-PAT-${randomBytes(8).toString('hex')}`,
        createdAt: now,
        updatedAt: now,
      });
    });
  }
} else if (mode === 'hold') {
  const store = await CredentialStore.open(paths);
  await store.update(() => {
    process.stdout.write('held\n');
    return new Promise(() => {});
  });
}
