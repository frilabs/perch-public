// `perch whatsapp install` (docs/WHATSAPP_INSTALL_SPEC.md). MOCK download (synthetic ZIP built here), MOCK
// systemctl, MOCK GOWA. Nothing is downloaded from GitHub and nothing is installed on this machine; the
// production SHA-256 pins stay untouched (tests inject their own pin for the synthetic ZIP).
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { crc32, deflateRawSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runCli, type CliIo } from '../src/cli/run.js';
import { PerchError } from '../src/errors.js';
import { CredentialStore } from '../src/store/credentialStore.js';
import {
  defaultInstallDeps,
  envFileContent,
  GOWA_PINS,
  gowaDownloadUrl,
  installGowa,
  legacyUnitFileContents,
  MAX_ARCHIVE_BYTES,
  rotateGowaPassword,
  unitFileContent,
  type InstallDeps,
  type RunResult,
} from '../src/whatsapp/install.js';
import { extractZipEntry, listZipEntries } from '../src/whatsapp/zip.js';
import { makeTempDirs, rejection, type TempDirs } from './support/fixtures.js';
import { MockGowa } from './support/mockGowa.js';

// ---------- synthetic ZIP ----------

interface ZipEntrySpec {
  name: string;
  data: Buffer;
  method?: 0 | 8;
  /** Lie in the central directory (hostile archives). */
  declaredSize?: number;
  crc?: number;
}

function buildZip(entries: ZipEntrySpec[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const method = e.method ?? 8;
    const body = method === 8 ? deflateRawSync(e.data) : e.data;
    const name = Buffer.from(e.name, 'utf8');
    const crc = e.crc ?? crc32(e.data);
    const size = e.declaredSize ?? e.data.length;
    const loc = Buffer.alloc(30);
    loc.writeUInt32LE(0x04034b50, 0);
    loc.writeUInt16LE(20, 4);
    loc.writeUInt16LE(method, 8);
    loc.writeUInt32LE(crc, 14);
    loc.writeUInt32LE(body.length, 18);
    loc.writeUInt32LE(size, 22);
    loc.writeUInt16LE(name.length, 26);
    locals.push(loc, name, body);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(0x031e, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(method, 10);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(body.length, 20);
    cen.writeUInt32LE(size, 24);
    cen.writeUInt16LE(name.length, 28);
    cen.writeUInt32LE(offset, 42);
    centrals.push(cen, name);
    offset += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const BINARY = Buffer.from('#!/bin/sh\n# MOCK GOWA binary for tests\n'.repeat(50));
const goodZip = () =>
  buildZip([
    { name: 'readme.md', data: Buffer.from('MOCK readme') },
    { name: 'linux-amd64', data: BINARY },
  ]);
const PASSWORD = `DUMMY-TEST-GOWA-${'ab12'.repeat(8)}`;
const ASSET_URL = 'https://release-assets.githubusercontent.com/github-production-release-asset/1/mock?sig=x';

// ---------- harness ----------

let dirs: TempDirs;
let home: string;
let fetched: string[];
let runs: string[][];
let stored: Array<[string, string, string]>;
let out: string[];
let clock: number;
let sleeps: number;
let systemdVersion: number;

beforeEach(async () => {
  dirs = await makeTempDirs();
  home = path.join(dirs.root, 'home');
  await mkdir(home, { recursive: true, mode: 0o700 });
  fetched = [];
  runs = [];
  stored = [];
  out = [];
  clock = 0;
  sleeps = 0;
  systemdVersion = 255;
});
afterEach(async () => {
  await dirs.cleanup();
});

/** MOCK GitHub: the release URL redirects to the asset host, which serves `zip`. */
function githubFetch(zip: Buffer, redirectTo = ASSET_URL): InstallDeps['fetch'] {
  return async (url) => {
    fetched.push(url);
    if (url.startsWith('https://github.com/')) return new Response(null, { status: 302, headers: { location: redirectTo } });
    if (url === redirectTo) return new Response(new Uint8Array(zip), { status: 200, headers: { 'content-length': String(zip.length) } });
    return new Response('not found', { status: 404 });
  };
}

function deps(over: Partial<InstallDeps> = {}, zip = goodZip()): InstallDeps {
  return {
    platform: 'linux',
    arch: 'x64',
    uid: 1000,
    home,
    fetch: githubFetch(zip),
    run: async (cmd, args): Promise<RunResult> => {
      runs.push([cmd, ...args]);
      return { code: 0, stdout: args[0] === '--version' ? `systemd ${systemdVersion} (${systemdVersion}.4-1ubuntu8)\n+PAM +AUDIT\n` : '', stderr: '' };
    },
    probe: async (origin, user, pw) => {
      if (user !== 'perch' || pw.length < 32 || !origin.startsWith('http://127.0.0.1:')) throw new Error('MOCK: 401');
    },
    store: async (o, u, p) => void stored.push([o, u, p]),
    configuredOrigin: async () => stored.at(-1)?.[0],
    ask: async () => 'y',
    out: (s) => void out.push(s),
    sleep: async (ms) => {
      sleeps++;
      clock += ms;
    },
    now: () => clock,
    password: () => PASSWORD,
    healthTimeoutMs: 5000,
    pollIntervalMs: 1000,
    pins: { linux_amd64: { sha256: sha(zip), entry: 'linux-amd64' } },
    ...over,
  };
}

const gowaDir = () => path.join(home, 'gowa');
const unitPath = () => path.join(home, '.config', 'systemd', 'user', 'gowa.service');
const mode = async (p: string) => (await stat(p)).mode & 0o777;
const exists = async (p: string) =>
  stat(p).then(
    () => true,
    () => false,
  );
const codeOf = async (p: Promise<unknown>) => ((await rejection(p)) as PerchError).code;

// ---------- tests ----------

describe('pins', () => {
  it('pins v9.6.0 with the release hashes from the spec and only GitHub HTTPS URLs', () => {
    expect(GOWA_PINS.linux_amd64.sha256).toBe('96173e28d963f591a13907d6abfee7a83b18c15c6bad25c193cdbc6fab088154');
    expect(GOWA_PINS.linux_arm64.sha256).toBe('4999212cdc7fe39753ea85a18cb52a0477ae694cf7a8966d5cb182b621d4e035');
    expect(gowaDownloadUrl('linux_arm64')).toBe(
      'https://github.com/aldinokemal/go-whatsapp-web-multidevice/releases/download/v9.6.0/whatsapp_9.6.0_linux_arm64.zip',
    );
  });

  it('without the test seam, the production pin rejects the synthetic ZIP', async () => {
    const d = deps();
    delete d.pins;
    expect(await codeOf(installGowa({ yes: true }, d))).toBe('hash_mismatch');
    expect(await exists(gowaDir())).toBe(false);
  });
});

describe('fresh install [MOCK download, MOCK systemctl]', () => {
  it('installs the program, .env and unit with private modes, starts the service and stores the bridge', async () => {
    const r = await installGowa({ yes: false }, deps());
    expect(r).toEqual({ status: 'installed', origin: 'http://127.0.0.1:3000', dir: gowaDir() });
    expect(fetched).toEqual([gowaDownloadUrl('linux_amd64'), ASSET_URL]);
    expect(await mode(gowaDir())).toBe(0o700);
    expect(await mode(path.join(gowaDir(), 'whatsapp'))).toBe(0o700);
    expect(await readFile(path.join(gowaDir(), 'whatsapp'))).toEqual(BINARY);
    expect(await mode(path.join(gowaDir(), '.env'))).toBe(0o600);
    expect((await readdir(gowaDir())).sort()).toEqual(['.env', '.perch-gowa.json', 'whatsapp']); // no readme, no temp files
    const env = await readFile(path.join(gowaDir(), '.env'), 'utf8');
    for (const line of [
      'APP_HOST=127.0.0.1',
      'APP_PORT=3000',
      `APP_BASIC_AUTH=perch:${PASSWORD}`,
      'APP_UI_ENABLED=false',
      'APP_UI_AUTO_UPDATE=false',
      'MCP_ENABLED=false',
      'WHATSAPP_AUTO_MARK_READ=false',
      'WHATSAPP_AUTO_DOWNLOAD_MEDIA=false',
      'WHATSAPP_WEBHOOK=',
      'WHATSAPP_PRESENCE_ON_CONNECT=unavailable',
    ]) {
      expect(env.split('\n')).toContain(line);
    }
    expect(await readFile(unitPath(), 'utf8')).toBe(
      '[Unit]\nDescription=GOWA WhatsApp bridge (localhost only)\n\n[Service]\nWorkingDirectory=%h/gowa\nExecStart=%h/gowa/whatsapp rest\n' +
        'Restart=on-failure\nUMask=0077\n' +
        '# GOWA logs its configuration incl. the basic-auth password at startup; keep that line out of the journal (systemd >= 253)\n' +
        'LogFilterPatterns=~app_basic_auth\n\n[Install]\nWantedBy=default.target\n',
    );
    expect(runs).toEqual([
      ['systemctl', '--version'],
      ['systemctl', '--user', 'daemon-reload'],
      ['systemctl', '--user', 'enable', '--now', 'gowa'],
    ]);
    expect(stored).toEqual([['http://127.0.0.1:3000', 'perch', PASSWORD]]);
    expect(out.join('')).toMatch(/UNOFFICIAL/);
    expect(out.join('')).not.toContain(PASSWORD);
  });

  it('honours --dir and --port (absolute paths in the unit)', async () => {
    const dir = path.join(dirs.root, 'bridge');
    const r = await installGowa({ yes: true, dir, port: 3111 }, deps());
    expect(r.origin).toBe('http://127.0.0.1:3111');
    expect(await readFile(path.join(dir, '.env'), 'utf8')).toContain('APP_PORT=3111\n');
    const unit = await readFile(unitPath(), 'utf8');
    expect(unit).toContain(`WorkingDirectory=${dir}\n`);
    expect(unit).toContain(`ExecStart=${dir}/whatsapp rest\n`);
    expect(stored[0]![0]).toBe('http://127.0.0.1:3111');
  });

  it('extracts stored (uncompressed) entries too', async () => {
    const zip = buildZip([{ name: 'linux-amd64', data: BINARY, method: 0 }]);
    await installGowa({ yes: true }, deps({}, zip));
    expect(await readFile(path.join(gowaDir(), 'whatsapp'))).toEqual(BINARY);
  });

  it('a re-run on a complete installation changes nothing and only checks', async () => {
    await installGowa({ yes: true }, deps());
    const before = await Promise.all(['whatsapp', '.env', '.perch-gowa.json'].map((f) => stat(path.join(gowaDir(), f))));
    const unitBefore = await stat(unitPath());
    fetched = [];
    runs = [];
    stored = [];
    const r = await installGowa({ yes: false }, deps({ ask: undefined, password: () => 'X'.repeat(40) }));
    expect(r.status).toBe('already_installed');
    expect(fetched).toEqual([]);
    expect(runs).toEqual([]);
    expect(stored).toEqual([['http://127.0.0.1:3000', 'perch', PASSWORD]]); // credentials from the existing .env
    const after = await Promise.all(['whatsapp', '.env', '.perch-gowa.json'].map((f) => stat(path.join(gowaDir(), f))));
    expect(after.map((s) => s.mtimeMs)).toEqual(before.map((s) => s.mtimeMs));
    expect((await stat(unitPath())).mtimeMs).toBe(unitBefore.mtimeMs);
    expect(out.join('')).toMatch(/already installed/);
    expect(out.join('')).not.toContain(PASSWORD);
  });

  it('a re-run with a different --port is refused', async () => {
    await installGowa({ yes: true }, deps());
    expect(await codeOf(installGowa({ yes: true, port: 3999 }, deps()))).toBe('foreign_files');
  });

  it('a re-run completes a missing unit without re-downloading or touching .env', async () => {
    await installGowa({ yes: true }, deps());
    await (await import('node:fs/promises')).unlink(unitPath());
    fetched = [];
    runs = [];
    await installGowa({ yes: true }, deps({ password: () => 'Y'.repeat(40) }));
    expect(fetched).toEqual([]);
    expect(await exists(unitPath())).toBe(true);
    expect(await readFile(path.join(gowaDir(), '.env'), 'utf8')).toContain(PASSWORD);
    expect(runs).toEqual([
      ['systemctl', '--version'],
      ['systemctl', '--user', 'daemon-reload'],
      ['systemctl', '--user', 'enable', '--now', 'gowa'],
    ]);
  });

  it('leaves a different configured bridge alone', async () => {
    const r = await installGowa({ yes: true }, deps({ configuredOrigin: async () => 'http://127.0.0.1:4000' }));
    expect(r.status).toBe('installed');
    expect(stored).toEqual([]);
    expect(out.join('')).toMatch(/already uses the bridge http:\/\/127\.0\.0\.1:4000/);
  });
});

describe('download and archive checks', () => {
  it('hash mismatch: nothing is extracted or written, systemctl is not called', async () => {
    const d = deps({ pins: { linux_amd64: { sha256: 'f'.repeat(64), entry: 'linux-amd64' } } });
    const err = await rejection(installGowa({ yes: true }, d));
    expect((err as PerchError).code).toBe('hash_mismatch');
    expect(err.message).toMatch(/Nothing was installed/);
    expect(await exists(gowaDir())).toBe(false);
    expect(await exists(unitPath())).toBe(false);
    expect(runs).toEqual([]);
    expect(stored).toEqual([]);
  });

  it('refuses redirects away from GitHub release hosts and plain HTTP', async () => {
    for (const target of ['https://evil.example.com/x.zip', 'http://release-assets.githubusercontent.com/x.zip', 'https://release-assets.githubusercontent.com:8443/x']) {
      fetched = [];
      const d = deps({ fetch: githubFetch(goodZip(), target) });
      expect(await codeOf(installGowa({ yes: true }, d))).toBe('download_refused');
      expect(fetched).toHaveLength(1); // the hostile target is never requested
    }
    expect(await exists(gowaDir())).toBe(false);
  });

  it('refuses an oversized download (declared and streamed)', async () => {
    const declared: InstallDeps['fetch'] = async () => new Response('x', { status: 200, headers: { 'content-length': String(MAX_ARCHIVE_BYTES + 1) } });
    expect(await codeOf(installGowa({ yes: true }, deps({ fetch: declared })))).toBe('download_too_large');
    const chunk = new Uint8Array(1024 * 1024);
    let n = 0;
    const streamed: InstallDeps['fetch'] = async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          pull(c) {
            if (n++ > 65) c.close();
            else c.enqueue(chunk);
          },
        }),
        { status: 200 },
      );
    expect(await codeOf(installGowa({ yes: true }, deps({ fetch: streamed })))).toBe('download_too_large');
    expect(await exists(gowaDir())).toBe(false);
  });

  it('a hostile archive with the pinned hash is still refused, nothing written', async () => {
    const zip = buildZip([
      { name: '../evil', data: Buffer.from('x') },
      { name: 'linux-amd64', data: BINARY },
    ]);
    expect(await codeOf(installGowa({ yes: true }, deps({}, zip)))).toBe('bad_archive');
    expect(await exists(gowaDir())).toBe(false);
    expect(await exists(path.join(dirs.root, 'evil'))).toBe(false);
  });

  it('ZIP reader: traversal, absolute names, missing/duplicate entries, oversize, bombs and CRC errors', () => {
    const ok = buildZip([{ name: 'linux-amd64', data: BINARY }]);
    expect(extractZipEntry(ok, 'linux-amd64', 1 << 20)).toEqual(BINARY);
    expect(listZipEntries(ok)).toEqual(['linux-amd64']);
    for (const name of ['../x', 'a/../../x', '/etc/passwd', 'C:\\x', 'a\\..\\x']) {
      expect(() => extractZipEntry(buildZip([{ name, data: Buffer.from('x') }, { name: 'linux-amd64', data: BINARY }]), 'linux-amd64', 1 << 20)).toThrow(/unsafe entry name/);
    }
    expect(() => extractZipEntry(ok, 'whatsapp', 1 << 20)).toThrow(/missing/);
    expect(() => extractZipEntry(buildZip([{ name: 'whatsapp', data: BINARY }]), 'linux-amd64', 1 << 20)).toThrow(/missing/);
    const dup = buildZip([
      { name: 'linux-amd64', data: BINARY },
      { name: 'linux-amd64', data: Buffer.from('other') },
    ]);
    expect(() => extractZipEntry(dup, 'linux-amd64', 1 << 20)).toThrow(/more than once/);
    expect(() => extractZipEntry(ok, 'linux-amd64', 100)).toThrow(/exceeds/);
    // A deflate bomb that lies about its size: declared small, inflates past the limit.
    const bomb = buildZip([{ name: 'linux-amd64', data: Buffer.alloc(5 * 1024 * 1024), declaredSize: 10 }]);
    expect(() => extractZipEntry(bomb, 'linux-amd64', 1024 * 1024)).toThrow(/could not be decompressed|exceeds|does not match/);
    expect(() => extractZipEntry(buildZip([{ name: 'linux-amd64', data: BINARY, crc: 1 }]), 'linux-amd64', 1 << 20)).toThrow(/CRC-32/);
    expect(() => extractZipEntry(Buffer.from('not a zip at all, definitely not'), 'linux-amd64', 1 << 20)).toThrow(/end of central directory/);
    expect(() => extractZipEntry(ok, '../x', 1 << 20)).toThrow();
  });
});

describe('refusals', () => {
  it('refuses non-Linux, unsupported CPUs and root before any download', async () => {
    expect(await codeOf(installGowa({ yes: true }, deps({ platform: 'darwin' })))).toBe('unsupported_platform');
    expect(await codeOf(installGowa({ yes: true }, deps({ arch: 'ia32' })))).toBe('unsupported_platform');
    const root = await rejection(installGowa({ yes: true }, deps({ uid: 0 })));
    expect((root as PerchError).code).toBe('refused_root');
    expect(fetched).toEqual([]);
  });

  it('arm64 uses the arm64 asset and entry', async () => {
    const zip = buildZip([{ name: 'linux-arm64', data: BINARY }]);
    const d = deps({ arch: 'arm64', pins: { linux_arm64: { sha256: sha(zip), entry: 'linux-arm64' } } }, zip);
    await installGowa({ yes: true }, d);
    expect(fetched[0]).toBe(gowaDownloadUrl('linux_arm64'));
  });

  it('without a terminal and without --yes nothing happens; "no" aborts too', async () => {
    expect(await codeOf(installGowa({ yes: false }, deps({ ask: undefined })))).toBe('no_tty');
    expect(await codeOf(installGowa({ yes: false }, deps({ ask: async () => Promise.reject(new Error('no TTY')) })))).toBe('no_tty');
    expect(await codeOf(installGowa({ yes: false }, deps({ ask: async () => 'n' })))).toBe('aborted');
    expect(await codeOf(installGowa({ yes: false }, deps({ ask: async () => '' })))).toBe('aborted');
    expect(fetched).toEqual([]);
    expect(await exists(gowaDir())).toBe(false);
  });

  it('refuses foreign files, another version and a different unit', async () => {
    await mkdir(gowaDir(), { mode: 0o700 });
    await writeFile(path.join(gowaDir(), 'notes.txt'), 'mine');
    expect(await codeOf(installGowa({ yes: true }, deps()))).toBe('foreign_files');
    await (await import('node:fs/promises')).rm(gowaDir(), { recursive: true });

    await mkdir(gowaDir(), { mode: 0o700 });
    await writeFile(path.join(gowaDir(), '.perch-gowa.json'), JSON.stringify({ version: '9.5.0', arch: 'linux_amd64' }), { mode: 0o600 });
    const other = await rejection(installGowa({ yes: true }, deps()));
    expect((other as PerchError).code).toBe('other_version');
    expect(other.message).toMatch(/9\.5\.0/);
    await (await import('node:fs/promises')).rm(gowaDir(), { recursive: true });

    await mkdir(path.dirname(unitPath()), { recursive: true });
    await writeFile(unitPath(), '[Service]\nExecStart=/somewhere/else\n');
    expect(await codeOf(installGowa({ yes: true }, deps()))).toBe('foreign_files');
    expect(fetched).toEqual([]);
  });

  it('accepts an existing empty private directory', async () => {
    await mkdir(gowaDir(), { mode: 0o700 });
    expect((await installGowa({ yes: true }, deps())).status).toBe('installed');
  });
});

describe('service start and health poll', () => {
  it('waits until GET /devices answers', async () => {
    let calls = 0;
    const r = await installGowa(
      { yes: true },
      deps({
        probe: async () => {
          if (++calls < 4) throw new Error('MOCK: connection refused');
        },
      }),
    );
    expect(r.status).toBe('installed');
    expect(calls).toBe(4);
    expect(sleeps).toBe(3);
  });

  it('times out with a journalctl hint and does not store the bridge', async () => {
    const err = await rejection(installGowa({ yes: true }, deps({ probe: async () => Promise.reject(new Error('MOCK: refused')) })));
    expect((err as PerchError).code).toBe('gowa_unhealthy');
    expect(err.message).toContain('journalctl --user -u gowa -n 50');
    expect(err.message).not.toContain(PASSWORD);
    expect(stored).toEqual([]);
  });

  it('explains a missing user bus (XDG_RUNTIME_DIR)', async () => {
    const run = async (cmd: string, args: string[]): Promise<RunResult> => {
      runs.push([cmd, ...args]);
      return { code: 1, stdout: '', stderr: 'Failed to connect to bus: No medium found\n' };
    };
    const err = await rejection(installGowa({ yes: true }, deps({ run })));
    expect((err as PerchError).code).toBe('systemd_failed');
    expect(err.message).toMatch(/XDG_RUNTIME_DIR/);
    expect(err.message).toMatch(/enable-linger/);
    expect(stored).toEqual([]);
  });
});

describe('first live run: no bare "Internal error" after the health wait', () => {
  it('regression: defaultInstallDeps keeps a real sleep when the CLI passes sleep: undefined (production io)', async () => {
    const base = {
      home,
      sleep: undefined,
      out: () => {},
      probe: async () => {},
      store: async () => {},
      configuredOrigin: async () => undefined,
    };
    const d = defaultInstallDeps(base);
    expect(typeof d.sleep).toBe('function');
    await d.sleep(1);
  });

  it('store is retried until the health deadline (plain errors), then succeeds', async () => {
    let calls = 0;
    const r = await installGowa(
      { yes: true },
      deps({
        store: async (o, u, p) => {
          if (++calls < 3) throw new TypeError('MOCK: store not ready');
          stored.push([o, u, p]);
        },
      }),
    );
    expect(r.status).toBe('installed');
    expect(calls).toBe(3);
    expect(sleeps).toBe(2);
    expect(stored).toHaveLength(1);
  });

  it('a non-PerchError while storing ends as a PerchError naming the step, without secrets', async () => {
    const err = await rejection(installGowa({ yes: true }, deps({ store: async () => Promise.reject(new Error(`MOCK: boom ${PASSWORD}`)) })));
    expect(err).toBeInstanceOf(PerchError);
    expect((err as PerchError).code).toBe('whatsapp_install_failed');
    expect(err.message).toContain('Storing the bridge in Perch failed (step: store)');
    expect(err.message).not.toContain(PASSWORD);
    expect(err.message).not.toContain('boom');
    expect(sleeps).toBeGreaterThan(0); // retried before giving up
  });

  it('a TypeError from configuredOrigin is reported as the store step too', async () => {
    const err = await rejection(
      installGowa(
        { yes: true },
        deps({
          configuredOrigin: async () => {
            throw new TypeError("Cannot read properties of undefined (reading 'origin')");
          },
        }),
      ),
    );
    expect((err as PerchError).code).toBe('whatsapp_install_failed');
    expect(err.message).toMatch(/\(step: store\)/);
  });

  it('a PerchError from storing keeps its code and safe message, prefixed with the step', async () => {
    const err = await rejection(installGowa({ yes: true }, deps({ store: async () => Promise.reject(new PerchError('Store is locked', 'store_locked')) })));
    expect((err as PerchError).code).toBe('store_locked');
    expect(err.message).toBe('Storing the bridge in Perch failed (step: store): Store is locked');
  });

  it('plain errors in other steps name the step and an errno code only', async () => {
    const err = await rejection(
      installGowa(
        { yes: true },
        deps({
          run: async () => {
            throw Object.assign(new Error(`spawn failed ${PASSWORD}`), { code: 'EACCES' });
          },
        }),
      ),
    );
    expect((err as PerchError).code).toBe('whatsapp_install_failed');
    expect(err.message).toMatch(/^Starting the GOWA service failed \(step: systemd\) \(EACCES\)\./);
    expect(err.message).not.toContain(PASSWORD);
    await (await import('node:fs/promises')).rm(gowaDir(), { recursive: true });
    await (await import('node:fs/promises')).unlink(unitPath());
    const probeErr = await rejection(
      installGowa(
        { yes: true },
        deps({
          sleep: undefined as unknown as InstallDeps['sleep'], // the original bug: deps.sleep missing
          probe: async () => Promise.reject(new Error('MOCK: refused')),
        }),
      ),
    );
    expect((probeErr as PerchError).code).toBe('whatsapp_install_failed');
    expect(probeErr.message).toMatch(/\(step: health\)/);
  });
});

describe('log filter and units written by an older Perch', () => {
  const legacyUnit = (dir = '%h/gowa') =>
    `[Unit]\nDescription=GOWA WhatsApp bridge (localhost only)\n\n[Service]\nWorkingDirectory=${dir}\nExecStart=${dir}/whatsapp rest\n` +
    'Restart=on-failure\nUMask=0077\n\n[Install]\nWantedBy=default.target\n';

  it('the old unit content is exactly what earlier Perch versions wrote', () => {
    expect(legacyUnitFileContents(path.join(home, 'gowa'), home)).toEqual([legacyUnit()]);
    expect(unitFileContent(path.join(home, 'gowa'), home)).toContain('\nLogFilterPatterns=~app_basic_auth\n');
  });

  it('a re-run on a complete installation replaces the older Perch unit, reloads and restarts GOWA', async () => {
    await installGowa({ yes: true }, deps());
    await writeFile(unitPath(), legacyUnit());
    runs = [];
    stored = [];
    fetched = [];
    const r = await installGowa({ yes: false }, deps({ ask: undefined }));
    expect(r.status).toBe('unit_updated');
    expect(fetched).toEqual([]);
    expect(await readFile(unitPath(), 'utf8')).toBe(unitFileContent(gowaDir(), home));
    expect(runs).toEqual([
      ['systemctl', '--version'],
      ['systemctl', '--user', 'daemon-reload'],
      ['systemctl', '--user', 'restart', 'gowa'],
    ]);
    expect(stored).toEqual([['http://127.0.0.1:3000', 'perch', PASSWORD]]);
    expect(out.join('')).toMatch(/rotate-password/);
    expect(out.join('')).not.toContain(PASSWORD);
    // and a further re-run is a plain check again
    runs = [];
    expect((await installGowa({ yes: true }, deps())).status).toBe('already_installed');
    expect(runs).toEqual([]);
  });

  it('an older Perch unit next to an incomplete installation is replaced during the install (restart included)', async () => {
    await mkdir(path.dirname(unitPath()), { recursive: true });
    await writeFile(unitPath(), legacyUnit());
    const r = await installGowa({ yes: true }, deps());
    expect(r.status).toBe('installed');
    expect(await readFile(unitPath(), 'utf8')).toBe(unitFileContent(gowaDir(), home));
    expect(runs.slice(1)).toEqual([
      ['systemctl', '--user', 'daemon-reload'],
      ['systemctl', '--user', 'enable', '--now', 'gowa'],
      ['systemctl', '--user', 'restart', 'gowa'],
    ]);
  });

  it('foreign units stay refused, including an old Perch unit for another directory', async () => {
    await mkdir(path.dirname(unitPath()), { recursive: true });
    await writeFile(unitPath(), legacyUnit('/opt/elsewhere'));
    expect(await codeOf(installGowa({ yes: true }, deps()))).toBe('foreign_files');
    await writeFile(unitPath(), `${legacyUnit()}# my change\n`);
    expect(await codeOf(installGowa({ yes: true }, deps()))).toBe('foreign_files');
    expect(await readFile(unitPath(), 'utf8')).toBe(`${legacyUnit()}# my change\n`);
    expect(fetched).toEqual([]);
  });

  it('warns on systemd older than 253 and when the version is unknown; silent on 253+', async () => {
    systemdVersion = 252;
    await installGowa({ yes: true }, deps());
    expect(out.join('')).toMatch(/Warning: systemd 252 is older than 253; LogFilterPatterns= needs systemd 253/);
    out = [];
    await (await import('node:fs/promises')).rm(gowaDir(), { recursive: true });
    await (await import('node:fs/promises')).unlink(unitPath());
    const run = async (cmd: string, args: string[]): Promise<RunResult> => {
      runs.push([cmd, ...args]);
      return args[0] === '--version' ? { code: 1, stdout: '', stderr: 'nope' } : { code: 0, stdout: '', stderr: '' };
    };
    await installGowa({ yes: true }, deps({ run }));
    expect(out.join('')).toMatch(/Warning: could not determine the systemd version/);
    out = [];
    systemdVersion = 253;
    await (await import('node:fs/promises')).rm(gowaDir(), { recursive: true });
    await (await import('node:fs/promises')).unlink(unitPath());
    await installGowa({ yes: true }, deps());
    expect(out.join('')).not.toMatch(/Warning/);
  });
});

describe('perch whatsapp rotate-password [MOCK systemctl, MOCK GOWA]', () => {
  const NEW = `DUMMY-TEST-NEWPW-${'cd34'.repeat(8)}`;
  let probes: string[];
  const rotDeps = (over: Partial<InstallDeps> = {}) =>
    deps({
      password: () => NEW,
      probe: async (_o, _u, pw) => {
        probes.push(pw);
        if (pw !== NEW) throw new Error('MOCK: 401');
      },
      ...over,
    });

  beforeEach(() => {
    probes = [];
  });

  it('writes a new password to .env (0600), restarts GOWA, waits for it and stores it; devices untouched', async () => {
    await installGowa({ yes: true }, deps());
    await mkdir(path.join(gowaDir(), 'storages'), { mode: 0o700 });
    await writeFile(path.join(gowaDir(), 'storages', 'whatsapp.db'), 'MOCK device store');
    const envBefore = await readFile(path.join(gowaDir(), '.env'), 'utf8');
    runs = [];
    stored = [];
    out = [];
    const r = await rotateGowaPassword({}, rotDeps());
    expect(r).toEqual({ origin: 'http://127.0.0.1:3000', dir: gowaDir(), stored: true });
    const env = await readFile(path.join(gowaDir(), '.env'), 'utf8');
    expect(env).toBe(envBefore.replace(`APP_BASIC_AUTH=perch:${PASSWORD}`, `APP_BASIC_AUTH=perch:${NEW}`));
    expect(await mode(path.join(gowaDir(), '.env'))).toBe(0o600);
    expect((await readdir(gowaDir())).sort()).toEqual(['.env', '.perch-gowa.json', 'storages', 'whatsapp']); // no temp files
    expect(await readFile(path.join(gowaDir(), 'storages', 'whatsapp.db'), 'utf8')).toBe('MOCK device store');
    expect(runs).toEqual([
      ['systemctl', '--version'],
      ['systemctl', '--user', 'restart', 'gowa'],
    ]);
    expect(probes.at(-1)).toBe(NEW);
    expect(stored).toEqual([['http://127.0.0.1:3000', 'perch', NEW]]);
    const text = out.join('');
    expect(text).not.toContain(NEW);
    expect(text).not.toContain(PASSWORD);
    expect(text).toContain('sudo journalctl --rotate && sudo journalctl --vacuum-time=1s');
    expect(text).toMatch(/paired devices stay linked/);
  });

  it('waits until GOWA accepts the new password', async () => {
    await installGowa({ yes: true }, deps());
    let n = 0;
    sleeps = 0;
    await rotateGowaPassword(
      {},
      rotDeps({
        probe: async (_o, _u, pw) => {
          if (++n < 3 || pw !== NEW) throw new Error('MOCK: still restarting');
        },
      }),
    );
    expect(n).toBe(3);
    expect(sleeps).toBe(2);
  });

  it('refuses a GOWA without the Perch marker (manual install) and changes nothing', async () => {
    expect(await codeOf(rotateGowaPassword({}, rotDeps()))).toBe('not_perch_gowa');
    await mkdir(gowaDir(), { mode: 0o700 });
    await writeFile(path.join(gowaDir(), '.env'), envFileContent(3000, PASSWORD), { mode: 0o600 });
    const err = await rejection(rotateGowaPassword({}, rotDeps()));
    expect((err as PerchError).code).toBe('not_perch_gowa');
    expect(err.message).toMatch(/perch whatsapp instance set/);
    expect(await readFile(path.join(gowaDir(), '.env'), 'utf8')).toContain(PASSWORD);
    expect(runs).toEqual([]);
    expect(stored).toEqual([]);
  });

  it('refuses when the unit is missing or foreign; non-Linux and root too', async () => {
    await installGowa({ yes: true }, deps());
    await writeFile(unitPath(), '[Service]\nExecStart=/somewhere/else\n');
    runs = [];
    expect(await codeOf(rotateGowaPassword({}, rotDeps()))).toBe('not_perch_gowa');
    await (await import('node:fs/promises')).unlink(unitPath());
    expect(await codeOf(rotateGowaPassword({}, rotDeps()))).toBe('not_perch_gowa');
    expect(await readFile(path.join(gowaDir(), '.env'), 'utf8')).toContain(PASSWORD);
    expect(runs).toEqual([]);
    expect(await codeOf(rotateGowaPassword({}, rotDeps({ platform: 'darwin' })))).toBe('unsupported_platform');
    expect(await codeOf(rotateGowaPassword({}, rotDeps({ uid: 0 })))).toBe('refused_root');
  });

  it('replaces an older Perch unit on the way (daemon-reload before the restart)', async () => {
    await installGowa({ yes: true }, deps());
    await writeFile(unitPath(), legacyUnitFileContents(gowaDir(), home)[0]!);
    runs = [];
    await rotateGowaPassword({}, rotDeps());
    expect(await readFile(unitPath(), 'utf8')).toBe(unitFileContent(gowaDir(), home));
    expect(runs).toEqual([
      ['systemctl', '--version'],
      ['systemctl', '--user', 'daemon-reload'],
      ['systemctl', '--user', 'restart', 'gowa'],
    ]);
  });

  it('a failed restart or health check says that .env already holds the new password', async () => {
    await installGowa({ yes: true }, deps());
    const run = async (cmd: string, args: string[]): Promise<RunResult> => {
      runs.push([cmd, ...args]);
      return args.includes('restart') ? { code: 1, stdout: '', stderr: 'Job failed\n' } : { code: 0, stdout: 'systemd 255\n', stderr: '' };
    };
    const err = await rejection(rotateGowaPassword({}, rotDeps({ run })));
    expect((err as PerchError).code).toBe('systemd_failed');
    expect(err.message).toMatch(/already holds the new password/);
    const unhealthy = await rejection(rotateGowaPassword({}, rotDeps({ password: () => 'Z'.repeat(40), probe: async () => Promise.reject(new Error('x')) })));
    expect((unhealthy as PerchError).code).toBe('gowa_unhealthy');
    expect(unhealthy.message).not.toContain('Z'.repeat(40));
  });
});

// ---------- CLI and setup ----------

describe('perch whatsapp install / perch setup [MOCK GOWA]', () => {
  let gowa: MockGowa;
  let cliOut: string;
  let cliErr: string;

  function io(answers: string[] = [], extra: Partial<CliIo> = {}): CliIo {
    return {
      env: { PERCH_DATA_DIR: dirs.dataDir, PERCH_KEY_FILE: dirs.keyFile, PERCH_HTTP_TOKEN_FILE: dirs.tokenFile, HOME: home },
      stdout: (s) => void (cliOut += s),
      stderr: (s) => void (cliErr += s),
      readSecret: async () => {
        throw new Error('no TTY in tests');
      },
      readLine: async () => {
        const a = answers.shift();
        if (a === undefined) throw new Error('MOCK: no more answers');
        return a;
      },
      transport: (req) => gowa.transport(req), // late-bound: rotate-password swaps the MOCK bridge
      sleep: async () => {},
      whatsappInstall: (() => {
        const d = deps();
        // The CLI supplies probe/store/configuredOrigin/ask/out itself (real Perch store, MOCK GOWA transport).
        return { platform: d.platform, arch: d.arch, uid: d.uid, fetch: d.fetch, run: d.run, sleep: d.sleep, now: d.now, password: d.password, pins: d.pins, healthTimeoutMs: 1000 };
      })(),
      ...extra,
    };
  }
  const openStore = () => CredentialStore.open({ dataDir: dirs.dataDir, keyFile: dirs.keyFile });

  beforeEach(async () => {
    gowa = new MockGowa('http://127.0.0.1:3000', 'perch', PASSWORD);
    cliOut = '';
    cliErr = '';
    expect(await runCli(['init'], io())).toBe(0);
    cliOut = '';
  });

  it('installs, verifies against the bridge and stores it like instance set; the password is never printed', async () => {
    expect(await runCli(['whatsapp', 'install', '--yes'], io()), cliErr).toBe(0);
    const inst = (await (await openStore()).read()).whatsappInstance;
    expect(inst).toMatchObject({ origin: 'http://127.0.0.1:3000', username: 'perch', password: PASSWORD });
    expect(gowa.calls.some((c) => c.url.pathname === '/devices' && c.method === 'GET')).toBe(true);
    expect(cliOut).toMatch(/Next: perch whatsapp add --label NAME --phone/);
    expect(cliOut + cliErr).not.toContain(PASSWORD);
    cliOut = '';
    expect(await runCli(['whatsapp', 'install'], io())).toBe(0); // re-run: no prompt needed
    expect(cliOut).toMatch(/already installed/);
    expect(cliOut + cliErr).not.toContain(PASSWORD);
  });

  it('regression (first live run): production io without sleep, GOWA not ready at first -> still installs (no "Internal error")', async () => {
    let refused = 0;
    const flaky: CliIo['transport'] = async (req) => {
      if (req.url.pathname === '/devices' && refused < 2) {
        refused++;
        throw new Error('MOCK: connect ECONNREFUSED 127.0.0.1:3000');
      }
      return gowa.transport(req);
    };
    const base = io().whatsappInstall!;
    const { sleep: _sleep, now: _now, ...noTimers } = base;
    const code = await runCli(['whatsapp', 'install', '--yes'], io([], { sleep: undefined, transport: flaky, whatsappInstall: { ...noTimers, pollIntervalMs: 1 } }));
    expect(cliErr).not.toMatch(/Internal error/);
    expect(code, cliErr).toBe(0);
    expect(refused).toBe(2);
    expect((await (await openStore()).read()).whatsappInstance?.origin).toBe('http://127.0.0.1:3000');
  });

  it('perch whatsapp rotate-password stores the new password; it is never printed', async () => {
    expect(await runCli(['whatsapp', 'install', '--yes'], io()), cliErr).toBe(0);
    const NEW = `DUMMY-TEST-ROTATED-${'ef56'.repeat(8)}`;
    const base = io().whatsappInstall!;
    const run = async (cmd: string, args: string[]): Promise<RunResult> => {
      if (args.includes('restart')) gowa = new MockGowa('http://127.0.0.1:3000', 'perch', NEW); // GOWA now expects the new password
      return base.run!(cmd, args);
    };
    cliOut = '';
    expect(await runCli(['whatsapp', 'rotate-password'], io([], { whatsappInstall: { ...base, run, password: () => NEW } })), cliErr).toBe(0);
    const inst = (await (await openStore()).read()).whatsappInstance;
    expect(inst).toMatchObject({ origin: 'http://127.0.0.1:3000', username: 'perch', password: NEW });
    expect(await readFile(path.join(gowaDir(), '.env'), 'utf8')).toContain(`APP_BASIC_AUTH=perch:${NEW}\n`);
    expect(cliOut).toContain('sudo journalctl --rotate && sudo journalctl --vacuum-time=1s');
    expect(cliOut + cliErr).not.toContain(NEW);
    expect(cliOut + cliErr).not.toContain(PASSWORD);
    expect(await runCli(['whatsapp', 'rotate-password', 'now'], io())).toBe(2);
  });

  it('perch whatsapp rotate-password without a Perch-installed GOWA fails clearly', async () => {
    expect(await runCli(['whatsapp', 'rotate-password'], io())).toBe(1);
    expect(cliErr).toMatch(/No Perch-installed GOWA/);
  });

  it('aborts without a terminal and without --yes', async () => {
    expect(await runCli(['whatsapp', 'install'], io([], { readLine: undefined }))).toBe(1);
    expect(cliErr).toMatch(/No interactive terminal/);
    expect(await exists(gowaDir())).toBe(false);
  });

  it('validates --port and refuses extra positionals', async () => {
    expect(await runCli(['whatsapp', 'install', '--yes', '--port', '70000'], io())).toBe(2);
    expect(await runCli(['whatsapp', 'install', 'now'], io())).toBe(2);
  });

  it('perch setup offers the install when no bridge is configured, then pairs', async () => {
    const answers = [
      'n', // Google account (Drive, Gmail, Calendar, Contacts)
      'n', // Outlook
      'n', // IMAP
      'n', // Notion
      'n', // Slack
      'y', // WhatsApp
      'y', // install GOWA (warning shown)
      'Private', // label
      '+4366012345678', // phone
      'n', // another WhatsApp account
      'n', // Luma
      'n', // X
      'n', // full-access client
    ];
    expect(await runCli(['setup'], io(answers)), cliErr).toBe(0);
    expect(answers).toHaveLength(0);
    expect(cliOut).toMatch(/Install the WhatsApp bridge on this server/);
    expect(cliOut).toMatch(/UNOFFICIAL/);
    expect(cliOut).toContain('Pairing code: ABCD-1234');
    const data = await (await openStore()).read();
    expect(data.whatsappInstance?.origin).toBe('http://127.0.0.1:3000');
    expect(data.whatsapp).toHaveLength(1);
    expect(cliOut + cliErr).not.toContain(PASSWORD);
  });

  it('perch setup skips WhatsApp when the install is declined', async () => {
    const answers = ['n', 'n', 'n', 'n', 'n', 'y', 'n', 'n', 'n', 'n'];
    expect(await runCli(['setup'], io(answers)), cliErr).toBe(0);
    expect(answers).toHaveLength(0);
    expect(cliOut).toMatch(/WhatsApp skipped/);
    expect(await exists(gowaDir())).toBe(false);
    expect((await (await openStore()).read()).whatsapp).toHaveLength(0);
  });
});
