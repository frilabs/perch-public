// TEST-ONLY network guard for the smoke child processes. It is loaded with `node --import` (via
// NODE_OPTIONS in the smoke test env), so it runs before dist/cli.js and on every supported Node
// version (>=22.12). The production code and its fetch are untouched; nothing in src/ reads this.
//
// - globalThis.fetch is replaced: every call is recorded and rejected before any socket exists.
// - net.Socket#connect (used by http/https/tls/undici and the IMAP/SMTP clients) throws, so nothing
//   else can open an outbound TCP connection.
// - Every node:dns API (callback, promises and Resolver instances, e.g. nodemailer's own resolve4/
//   resolve6/lookup before it connects) fails with ENOTFOUND before any query is sent.
// Every blocked attempt is appended as one JSON line to PERCH_SMOKE_GUARD_LOG (if set), so the tests
// can prove the guard is active (probe) and that the real smoke run made zero attempts.
import dns from 'node:dns';
import { appendFileSync } from 'node:fs';
import net from 'node:net';

const logFile = process.env.PERCH_SMOKE_GUARD_LOG;

function record(kind, target) {
  if (logFile) appendFileSync(logFile, `${JSON.stringify({ pid: process.pid, kind, target: String(target) })}\n`);
}

function targetOf(input) {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input?.url ?? '(unknown)';
}

globalThis.fetch = async function perchSmokeOfflineFetch(input) {
  const target = targetOf(input);
  record('fetch', target);
  throw new TypeError(`perch smoke offline guard: blocked fetch to ${target}`);
};

net.Socket.prototype.connect = function perchSmokeOfflineConnect(...args) {
  const o = args[0];
  const target = Array.isArray(o) ? JSON.stringify(o[0]) : typeof o === 'object' && o ? `${o.host ?? o.path ?? ''}:${o.port ?? ''}` : `${args[1] ?? ''}:${o}`;
  record('connect', target);
  throw new Error(`perch smoke offline guard: blocked socket connect to ${target}`);
};

const DNS_FUNCTIONS = [
  'lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCaa', 'resolveCname', 'resolveMx',
  'resolveNaptr', 'resolveNs', 'resolvePtr', 'resolveSoa', 'resolveSrv', 'resolveTlsa', 'resolveTxt', 'reverse',
];

function blockedDns(fn, host) {
  record('dns', `${fn} ${host}`);
  return Object.assign(new Error(`perch smoke offline guard: blocked dns ${fn} ${host}`), { code: 'ENOTFOUND' });
}

// Numeric hosts (e.g. the 127.0.0.1 bind address of `serve --http`, which net.Server#listen looks up)
// never cause a DNS query, so lookups of IP literals keep working; every name lookup is blocked.
const originalLookup = dns.lookup;
const callbackDns = (fn) =>
  function perchSmokeOfflineDns(host, ...rest) {
    if (fn === 'lookup' && net.isIP(String(host))) return originalLookup.call(dns, host, ...rest);
    const err = blockedDns(fn, host);
    const cb = [...rest].reverse().find((a) => typeof a === 'function');
    if (cb) return void process.nextTick(cb, err);
    throw err;
  };
const promiseDns = (fn) =>
  async function perchSmokeOfflineDnsPromise(host) {
    throw blockedDns(fn, host);
  };

for (const fn of DNS_FUNCTIONS) {
  if (typeof dns[fn] === 'function') dns[fn] = callbackDns(fn);
  if (typeof dns.Resolver?.prototype[fn] === 'function') dns.Resolver.prototype[fn] = callbackDns(fn);
  if (typeof dns.promises[fn] === 'function') dns.promises[fn] = promiseDns(fn);
  if (typeof dns.promises.Resolver?.prototype[fn] === 'function') dns.promises.Resolver.prototype[fn] = promiseDns(fn);
}
