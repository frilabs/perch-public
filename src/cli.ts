#!/usr/bin/env node
import { readLineFromTty, readPastedLineFromTty, readSecretFromTty, readSecretJsonFromTty } from './cli/prompt.js';
import { detectEnvFile, tailscaleFunnelStatus } from './cli/publicSetup.js';
import { runCli } from './cli/run.js';

process.umask(0o077);

runCli(process.argv.slice(2), {
  env: process.env,
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
  readSecret: readSecretFromTty,
  readLine: readLineFromTty,
  readSecretJson: (prompt, maxBytes) => readSecretJsonFromTty(prompt, maxBytes),
  readPastedUrl: (prompt, signal) => readPastedLineFromTty(prompt, signal),
  stdoutIsTTY: process.stdout.isTTY === true,
  ...(process.stdout.columns ? { stdoutColumns: process.stdout.columns } : {}),
  ...(() => {
    const envFile = detectEnvFile(process.execArgv, process.env);
    return envFile ? { envFile } : {};
  })(),
  funnelStatus: tailscaleFunnelStatus,
}).then(
  (code) => process.exit(code),
  () => {
    process.stderr.write('perch: fatal error\n');
    process.exit(1);
  },
);
