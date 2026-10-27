import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  classifyLicenseText,
  collectInventory,
  normalizeRepositoryUrl,
  runLicenses,
} from '../scripts/licenses.mjs';

// Verbatim license bodies (SPDX templates with a concrete copyright line) used to build fixtures.
const MIT = `MIT License

Copyright (c) 2020 Example Author

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;

const MIT_0 = `MIT No Attribution

Copyright 2020 Example Author

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
`;

// The MIT grant with "subject to the following conditions:" but the condition paragraph removed
// (the shape actually shipped by imapflow 2.2.5 and nodemailer 10.0.14).
const MIT_TRUNCATED = MIT.replace(
  /The above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\n/,
  '',
).replace('MIT License\n\n', '');

const ISC = `ISC License

Copyright (c) 2020 Example Author

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
`;

const BSD_2 = `Copyright (c) 2020 Example Author
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
`;

const BSD_3 = BSD_2.replace(
  'THIS SOFTWARE',
  `3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE`,
);

const GPL = `GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License.
`;

describe('classifyLicenseText', () => {
  it('recognises the permissive texts by their operative clauses', () => {
    expect(classifyLicenseText(MIT)).toBe('MIT');
    expect(classifyLicenseText(MIT_0)).toBe('MIT-0');
    expect(classifyLicenseText(ISC)).toBe('ISC');
    expect(classifyLicenseText(BSD_2)).toBe('BSD-2-Clause');
    expect(classifyLicenseText(BSD_3)).toBe('BSD-3-Clause');
  });

  it('flags an MIT grant whose announced conditions are missing as MIT-truncated, not MIT or MIT-0', () => {
    expect(classifyLicenseText(MIT_TRUNCATED)).toBe('MIT-truncated');
  });

  it('is whitespace- and line-ending-insensitive', () => {
    expect(classifyLicenseText(MIT.replace(/\n/g, '\r\n').replace(/ /g, '   '))).toBe('MIT');
  });

  it('returns UNKNOWN for anything else (fail closed)', () => {
    expect(classifyLicenseText(GPL)).toBe('UNKNOWN');
    expect(classifyLicenseText('')).toBe('UNKNOWN');
    expect(classifyLicenseText('All rights reserved.')).toBe('UNKNOWN');
  });
});

// Real-world restriction shapes that clause-presence matching used to accept.
const JSON_LICENSE = MIT.replace(
  'copies or substantial portions of the Software.\n',
  'copies or substantial portions of the Software.\n\nThe Software shall be used for Good, not Evil.\n',
);
const MIT_COMMONS_CLAUSE = `${MIT}
"Commons Clause" License Condition v1.0

The Software is provided to you by the Licensor under the License, as defined below, subject to the
following condition. Without limiting other conditions in the License, the grant of rights under the
License will not include, and the License does not grant to you, the right to Sell the Software.
`;
const BSD_4_ADVERTISING = BSD_3.replace(
  '3. Neither the name',
  `3. All advertising materials mentioning features or use of this software must display the
   following acknowledgement: This product includes software developed by Example Author.

4. Neither the name`,
);
// The jshttp/express form of MIT: "(The MIT License)" title, 'Software' and 'AS IS' in single quotes.
const MIT_JSHTTP = MIT.replace('MIT License', '(The MIT License)')
  .replace('(the "Software")', "(the\n'Software')")
  .replace('"AS IS"', "'AS IS'");

describe('classifyLicenseText: template matching rejects extra terms', () => {
  it('rejects the JSON license ("Good, not Evil") instead of reading it as MIT', () => {
    expect(classifyLicenseText(JSON_LICENSE)).toBe('UNKNOWN');
  });

  it('flags MIT with an appended Commons Clause as MIT+extra, not MIT', () => {
    expect(classifyLicenseText(MIT_COMMONS_CLAUSE)).toBe('MIT+extra');
  });

  it('rejects a BSD text with the advertising clause instead of reading it as BSD-3-Clause', () => {
    expect(classifyLicenseText(BSD_4_ADVERTISING)).toBe('UNKNOWN');
  });

  it('rejects operative restrictions placed before the grant', () => {
    expect(classifyLicenseText(MIT.replace('MIT License', 'MIT License\n\nNon-commercial use only.'))).toBe('UNKNOWN');
  });

  it('still accepts the common benign variants (title, quotes, named holder in BSD clauses)', () => {
    expect(classifyLicenseText(MIT_JSHTTP)).toBe('MIT');
    expect(
      classifyLicenseText(
        BSD_3.replace('the name of the copyright holder', 'the name of Example Org')
          .replace('BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS', 'BY EXAMPLE ORG')
          .replace('SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS', 'SHALL EXAMPLE ORG'),
      ),
    ).toBe('BSD-3-Clause');
    expect(classifyLicenseText(`BSD 2-Clause License\n\n${BSD_2}`)).toBe('BSD-2-Clause');
  });
});

describe('normalizeRepositoryUrl', () => {
  it('turns npm repository shorthands and git URLs into https source URLs', () => {
    expect(normalizeRepositoryUrl('jshttp/accepts')).toBe('https://github.com/jshttp/accepts');
    expect(normalizeRepositoryUrl({ type: 'git', url: 'git+https://github.com/a/b.git' })).toBe(
      'https://github.com/a/b',
    );
    expect(normalizeRepositoryUrl('git://github.com/a/b.git')).toBe('https://github.com/a/b');
    expect(normalizeRepositoryUrl('git@github.com:a/b.git')).toBe('https://github.com/a/b');
    expect(normalizeRepositoryUrl('git+ssh://git@github.com/a/b.git')).toBe('https://github.com/a/b');
    expect(normalizeRepositoryUrl('git://git@github.com/a/b.git')).toBe('https://github.com/a/b');
    expect(normalizeRepositoryUrl('https://github.com/a/b')).toBe('https://github.com/a/b');
  });

  it('returns null for missing or unrecognised repository metadata', () => {
    expect(normalizeRepositoryUrl(undefined)).toBeNull();
    expect(normalizeRepositoryUrl('')).toBeNull();
    expect(normalizeRepositoryUrl({ type: 'git' })).toBeNull();
    expect(normalizeRepositoryUrl('file:../local')).toBeNull();
  });
});

// ---------------------------------------------------------------------------------------------------
// Fixture: a throwaway project root with package.json, package-lock.json (v3) and an installed
// node_modules tree. `install: false` simulates a lock entry that npm ci did not install.
type FixturePackage = {
  lock: Record<string, unknown>;
  manifest?: Record<string, unknown>;
  files?: Record<string, string>;
  install?: boolean;
};

const roots: string[] = [];
afterEach(() => {
  while (roots.length) rmSync(roots.pop()!, { recursive: true, force: true });
});

function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function makeFixture(opts: {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  packages: Record<string, FixturePackage>;
  lockfileVersion?: number;
  rootLicense?: string;
}): string {
  const root = mkdtempSync(join(tmpdir(), 'perch-licenses-'));
  roots.push(root);
  const rootManifest = {
    name: 'fixture',
    version: '1.0.0',
    private: true,
    license: opts.rootLicense ?? 'MIT',
    dependencies: opts.dependencies ?? {},
    devDependencies: opts.devDependencies ?? {},
  };
  write(join(root, 'package.json'), JSON.stringify(rootManifest, null, 2));
  const lockPackages: Record<string, unknown> = {
    '': {
      name: 'fixture',
      version: '1.0.0',
      license: rootManifest.license,
      dependencies: rootManifest.dependencies,
      devDependencies: rootManifest.devDependencies,
    },
  };
  for (const [path, pkg] of Object.entries(opts.packages)) {
    lockPackages[path] = pkg.lock;
    if (pkg.install === false) continue;
    const name = path.split('node_modules/').pop()!;
    const manifest = pkg.manifest ?? {
      name,
      version: pkg.lock.version,
      license: pkg.lock.license,
      repository: `example/${name.replace('@', '').replace('/', '-')}`,
    };
    write(join(root, path, 'package.json'), JSON.stringify(manifest, null, 2));
    for (const [rel, content] of Object.entries(pkg.files ?? { LICENSE: MIT })) write(join(root, path, rel), content);
  }
  write(
    join(root, 'package-lock.json'),
    JSON.stringify(
      { name: 'fixture', version: '1.0.0', lockfileVersion: opts.lockfileVersion ?? 3, requires: true, packages: lockPackages },
      null,
      2,
    ),
  );
  return root;
}

const lockEntry = (version: string, license: string | undefined, extra: Record<string, unknown> = {}) => ({
  version,
  resolved: `https://registry.npmjs.org/x/-/x-${version}.tgz`,
  integrity: `sha512-${version}`,
  ...(license === undefined ? {} : { license }),
  ...extra,
});

/** a -> b, a -> c (nested c@2 under a), root -> c@1, dev d. */
function basicPackages(): Record<string, FixturePackage> {
  return {
    'node_modules/a': { lock: lockEntry('1.0.0', 'MIT', { dependencies: { b: '^1', c: '^2' } }) },
    'node_modules/b': { lock: lockEntry('1.1.0', 'ISC'), files: { LICENSE: ISC } },
    'node_modules/c': { lock: lockEntry('1.0.0', 'MIT') },
    'node_modules/a/node_modules/c': { lock: lockEntry('2.0.0', 'MIT') },
    'node_modules/d': { lock: lockEntry('3.0.0', 'Apache-2.0', { dev: true }), install: false },
  };
}

describe('collectInventory', () => {
  it('derives the production closure from the lockfile and verifies it against installed manifests', () => {
    const root = makeFixture({ dependencies: { a: '^1', c: '^1' }, devDependencies: { d: '^3' }, packages: basicPackages() });
    const inv = collectInventory(root);
    expect(inv.errors).toEqual([]);
    expect(inv.production.map((p) => p.key)).toEqual(['a@1.0.0', 'b@1.1.0', 'c@1.0.0', 'c@2.0.0']);
    const b = inv.production.find((p) => p.key === 'b@1.1.0');
    expect(b).toMatchObject({ declared: 'ISC', sourceUrl: 'https://github.com/example/b', paths: ['node_modules/b'] });
    expect(inv.development).toEqual([
      expect.objectContaining({ name: 'd', version: '3.0.0', license: 'Apache-2.0', paths: ['node_modules/d'] }),
    ]);
  });

  it('groups one name@version installed at several locations', () => {
    const packages = basicPackages();
    packages['node_modules/b/node_modules/c'] = { lock: lockEntry('2.0.0', 'MIT') };
    (packages['node_modules/b']!.lock as { dependencies?: object }).dependencies = { c: '^2' };
    const root = makeFixture({ dependencies: { a: '^1', c: '^1' }, packages });
    const inv = collectInventory(root);
    expect(inv.errors).toEqual([]);
    expect(inv.production.find((p) => p.key === 'c@2.0.0')?.paths).toEqual([
      'node_modules/a/node_modules/c',
      'node_modules/b/node_modules/c',
    ]);
  });

  it('fails closed when a production lock entry is not installed', () => {
    const packages = basicPackages();
    packages['node_modules/b']!.install = false;
    const inv = collectInventory(makeFixture({ dependencies: { a: '^1', c: '^1' }, packages }));
    expect(inv.errors).toContainEqual(expect.stringMatching(/node_modules\/b.*not installed.*npm ci/));
  });

  it('fails closed on version or license drift between the lockfile and the installed manifest', () => {
    const packages = basicPackages();
    packages['node_modules/b']!.manifest = { name: 'b', version: '1.2.0', license: 'ISC', repository: 'x/b' };
    packages['node_modules/c']!.manifest = { name: 'c', version: '1.0.0', license: 'GPL-3.0', repository: 'x/c' };
    const inv = collectInventory(makeFixture({ dependencies: { a: '^1', c: '^1' }, packages }));
    expect(inv.errors).toContainEqual(expect.stringMatching(/node_modules\/b.*version 1\.2\.0.*lockfile 1\.1\.0/));
    expect(inv.errors).toContainEqual(expect.stringMatching(/node_modules\/c.*license "GPL-3.0".*lockfile "MIT"/));
  });

  it('fails closed on missing or non-SPDX license metadata', () => {
    const packages = basicPackages();
    packages['node_modules/b'] = { lock: lockEntry('1.1.0', undefined), manifest: { name: 'b', version: '1.1.0', repository: 'x/b' } };
    packages['node_modules/c'] = {
      lock: lockEntry('1.0.0', undefined),
      manifest: { name: 'c', version: '1.0.0', licenses: [{ type: 'MIT' }], repository: 'x/c' },
    };
    const inv = collectInventory(makeFixture({ dependencies: { a: '^1', c: '^1' }, packages }));
    expect(inv.errors).toContainEqual(expect.stringMatching(/b@1\.1\.0.*no SPDX license/));
    expect(inv.errors).toContainEqual(expect.stringMatching(/c@1\.0\.0.*no SPDX license/));
  });

  it('fails closed when the lockfile dev flags disagree with the dependency graph', () => {
    const packages = basicPackages();
    // b is required by production package a but flagged dev; e is non-dev but unreachable.
    (packages['node_modules/b']!.lock as { dev?: boolean }).dev = true;
    packages['node_modules/e'] = { lock: lockEntry('1.0.0', 'MIT') };
    const inv = collectInventory(makeFixture({ dependencies: { a: '^1', c: '^1' }, packages }));
    expect(inv.errors).toContainEqual(expect.stringMatching(/node_modules\/b.*flagged dev.*required by production/));
    expect(inv.errors).toContainEqual(expect.stringMatching(/node_modules\/e.*not reachable/));
  });

  it('fails closed when a required dependency cannot be resolved, but tolerates absent optional ones', () => {
    const packages = basicPackages();
    (packages['node_modules/a']!.lock as Record<string, unknown>).optionalDependencies = { fsevents: '^2' };
    (packages['node_modules/a']!.lock as Record<string, unknown>).peerDependencies = { opt: '^1', zz: '^1' };
    (packages['node_modules/a']!.lock as Record<string, unknown>).peerDependenciesMeta = { opt: { optional: true } };
    const inv = collectInventory(makeFixture({ dependencies: { a: '^1', c: '^1' }, packages }));
    expect(inv.errors).toEqual([expect.stringMatching(/node_modules\/a.*requires "zz".*not in the lockfile/)]);
  });

  it('rejects lockfiles older than v2 and linked packages', () => {
    expect(collectInventory(makeFixture({ packages: {}, lockfileVersion: 1 })).errors).toContainEqual(
      expect.stringMatching(/lockfileVersion 1.*unsupported/),
    );
    const packages = basicPackages();
    packages['node_modules/c'] = { lock: { resolved: '../local-c', link: true }, install: false };
    expect(collectInventory(makeFixture({ dependencies: { a: '^1', c: '^1' }, packages })).errors).toContainEqual(
      expect.stringMatching(/node_modules\/c.*linked/),
    );
  });
});

// ---------------------------------------------------------------------------------------------------
const OWNER_LICENSE = MIT.replace('Copyright (c) 2020 Example Author', 'Copyright (c) 2026 Example Owner');
const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

type Policy = Record<string, unknown>;
function basePolicy(extra: Policy = {}): Policy {
  return {
    project: { license: 'MIT', copyright: 'Copyright (c) 2026 Example Owner' },
    production: { allowed: ['MIT', 'MIT-0', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause'] },
    development: { allowed: ['MIT', 'ISC', 'Apache-2.0'] },
    elections: [],
    textOverrides: [],
    embedded: [],
    ...extra,
  };
}

function makeProject(
  packages: Record<string, FixturePackage>,
  policy: Policy = basePolicy(),
  opts: { license?: string | null; rootLicense?: string } = {},
): string {
  const root = makeFixture({ dependencies: { a: '^1', c: '^1' }, devDependencies: { d: '^3' }, packages, rootLicense: opts.rootLicense });
  if (opts.license !== null) write(join(root, 'LICENSE'), opts.license ?? OWNER_LICENSE);
  write(join(root, 'licenses', 'policy.json'), JSON.stringify(policy, null, 2));
  return root;
}

const errorsOf = (root: string) => runLicenses(root, 'check').errors as string[];
const generated = (root: string) => readFileSync(join(root, 'THIRD_PARTY_NOTICES.md'), 'utf8');

describe('runLicenses: production license policy', () => {
  it('generates notices for a compliant closure and then checks clean', () => {
    const root = makeProject(basicPackages());
    const gen = runLicenses(root, 'generate');
    expect(gen.errors).toEqual([]);
    expect(gen.ok).toBe(true);
    expect(runLicenses(root, 'check')).toMatchObject({ ok: true, errors: [] });
    const notices = generated(root);
    expect(notices).toContain('## a@1.0.0');
    expect(notices).toContain('## c@2.0.0');
    expect(notices).toContain('Permission to use, copy, modify, and/or distribute this software'); // b's ISC text verbatim
    expect(notices).toContain('https://github.com/example/b');
    expect(notices).toContain('sha512-1.1.0');
    expect(notices).not.toContain('## d@3.0.0');
    const dev = readFileSync(join(root, 'licenses', 'DEV_DEPENDENCIES.md'), 'utf8');
    expect(dev).toMatch(/\| d \| 3\.0\.0 \| Apache-2\.0 \|/);
  });

  it('rejects a license that is not on the production allowlist', () => {
    const packages = basicPackages();
    packages['node_modules/c']!.lock.license = 'GPL-3.0-only';
    packages['node_modules/c']!.files = { LICENSE: GPL };
    expect(errorsOf(makeProject(packages))).toContainEqual(expect.stringMatching(/c@1\.0\.0.*GPL-3\.0-only.*not allowed/));
  });

  it('rejects a package without any bundled license file', () => {
    const packages = basicPackages();
    packages['node_modules/c']!.files = { 'index.js': 'module.exports = 1;\n' };
    expect(errorsOf(makeProject(packages))).toContainEqual(expect.stringMatching(/c@1\.0\.0.*no bundled license file/));
  });

  it('rejects a license text that does not match the declared SPDX id', () => {
    const packages = basicPackages();
    packages['node_modules/c']!.files = { LICENSE: ISC };
    expect(errorsOf(makeProject(packages))).toContainEqual(
      expect.stringMatching(/c@1\.0\.0.*LICENSE.*reads as ISC.*declared MIT/),
    );
  });

  it('requires a reviewed override for an ambiguous (truncated) MIT text, and rejects stale overrides', () => {
    const packages = basicPackages();
    packages['node_modules/c']!.files = { 'LICENSE.txt': MIT_TRUNCATED };
    expect(errorsOf(makeProject(packages))).toContainEqual(expect.stringMatching(/c@1\.0\.0.*LICENSE\.txt.*reads as MIT-truncated/));

    const override = { package: 'c@1.0.0', file: 'LICENSE.txt', detected: 'MIT-truncated', note: 'Reviewed: notice retained.' };
    const root = makeProject(packages, basePolicy({ textOverrides: [override] }));
    expect(runLicenses(root, 'generate').errors).toEqual([]);
    expect(generated(root)).toContain('Reviewed: notice retained.');

    const stale = { package: 'zzz@9.9.9', file: 'LICENSE', detected: 'MIT-truncated', note: 'x' };
    expect(errorsOf(makeProject(basicPackages(), basePolicy({ textOverrides: [stale] })))).toContainEqual(
      expect.stringMatching(/policy textOverrides.*zzz@9\.9\.9.*stale/),
    );
  });

  it('requires an explicit election for SPDX expressions and reproduces only the elected texts', () => {
    const packages = basicPackages();
    packages['node_modules/c']!.lock.license = '(MIT OR EUPL-1.1+)';
    packages['node_modules/c']!.files = { 'LICENSE.MIT': MIT, 'LICENSE.EUPL-1.2': 'EUROPEAN UNION PUBLIC LICENCE v. 1.2\n' };
    expect(errorsOf(makeProject(packages))).toContainEqual(expect.stringMatching(/c@1\.0\.0.*\(MIT OR EUPL-1\.1\+\).*election/));

    const election = { package: 'c@1.0.0', expression: '(MIT OR EUPL-1.1+)', elected: 'MIT', licenseFiles: ['LICENSE.MIT'], note: 'MIT elected.' };
    const root = makeProject(packages, basePolicy({ elections: [election] }));
    expect(runLicenses(root, 'generate').errors).toEqual([]);
    const notices = generated(root);
    expect(notices).toMatch(/## c@1\.0\.0[\s\S]*MIT \(elected from `\(MIT OR EUPL-1\.1\+\)`\)/);
    expect(notices).not.toContain('EUROPEAN UNION PUBLIC LICENCE');

    const wrong = { ...election, elected: 'EUPL-1.1+' };
    expect(errorsOf(makeProject(packages, basePolicy({ elections: [wrong] })))).toContainEqual(
      expect.stringMatching(/c@1\.0\.0.*elected "EUPL-1\.1\+".*not allowed/),
    );
  });

  it('rejects a production package without a resolvable source repository', () => {
    const packages = basicPackages();
    packages['node_modules/c']!.manifest = { name: 'c', version: '1.0.0', license: 'MIT' };
    expect(errorsOf(makeProject(packages))).toContainEqual(expect.stringMatching(/c@1\.0\.0.*no source repository/));
  });
});

describe('runLicenses: embedded third-party notices', () => {
  const VENDORED = `'use strict';
/*! Copied from https://example.org/vendored
 * Copyright Someone Else
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 */
module.exports = 1;
`;
  const excerpt = VENDORED.split('\n').slice(1, 5).join('\n');

  function withVendored(): Record<string, FixturePackage> {
    const packages = basicPackages();
    packages['node_modules/c']!.files = {
      LICENSE: MIT,
      'dist/x.js': VENDORED,
      'lib/self.js': '/*!\n * c\n * MIT Licensed\n */\n/** @license MIT */\n/** Extra options, copied from the auth object */\n',
    };
    return packages;
  }

  it('fails on an unreviewed embedded license grant but ignores self-references to the package license', () => {
    const errors = errorsOf(makeProject(withVendored()));
    expect(errors).toContainEqual(expect.stringMatching(/c@1\.0\.0.*dist\/x\.js:4.*unreviewed embedded license/));
    expect(errors.join('\n')).not.toContain('lib/self.js');
  });

  it('reproduces a reviewed excerpt pinned by line range and sha256', () => {
    const entry = { package: 'c@1.0.0', file: 'dist/x.js', lines: [2, 5], sha256: sha256(excerpt), action: 'reproduce', note: 'Vendored code.' };
    const root = makeProject(withVendored(), basePolicy({ embedded: [entry] }));
    expect(runLicenses(root, 'generate').errors).toEqual([]);
    expect(generated(root)).toContain(excerpt);
    expect(generated(root)).toContain('Vendored code.');
  });

  it('accepts a reviewed "covered" excerpt without reproducing it again', () => {
    const entry = { package: 'c@1.0.0', file: 'dist/x.js', lines: [2, 5], sha256: sha256(excerpt), action: 'covered', note: 'Same text as LICENSE.' };
    const root = makeProject(withVendored(), basePolicy({ embedded: [entry] }));
    expect(runLicenses(root, 'generate').errors).toEqual([]);
    expect(generated(root)).not.toContain('Copied from https://example.org/vendored');
    expect(generated(root)).toContain('Same text as LICENSE.');
  });

  it('fails when the pinned excerpt changed, or the entry is stale', () => {
    const entry = { package: 'c@1.0.0', file: 'dist/x.js', lines: [2, 5], sha256: sha256('other'), action: 'reproduce', note: 'x' };
    expect(errorsOf(makeProject(withVendored(), basePolicy({ embedded: [entry] })))).toContainEqual(
      expect.stringMatching(/c@1\.0\.0.*dist\/x\.js.*sha256 mismatch/),
    );
    const stale = { ...entry, package: 'c@0.9.0', sha256: sha256(excerpt) };
    expect(errorsOf(makeProject(withVendored(), basePolicy({ embedded: [stale] })))).toContainEqual(
      expect.stringMatching(/policy embedded.*c@0\.9\.0.*stale/),
    );
  });

  it('fails on an unreviewed license file nested inside a package', () => {
    const packages = basicPackages();
    packages['node_modules/c']!.files = { LICENSE: MIT, 'vendor/thing/LICENSE': MIT };
    expect(errorsOf(makeProject(packages))).toContainEqual(expect.stringMatching(/c@1\.0\.0.*vendor\/thing\/LICENSE:1.*unreviewed/));
  });
});

describe('runLicenses: bare copyright lines and non-SPDX grants', () => {
  // Shape of the Masanao Izumo Base64 header vendored by encoding-japanese 2.4.0 (src/util.js:229-236).
  const IZUMO = `exports.x = 1;

// Base64
/* Copyright (C) 1999 Masanao Izumo <iz@onicos.co.jp>
 * Version: 1.0
 * LastModified: Dec 25 1999
 * This library is free.  You can redistribute it and/or modify it.
 */
// -- Masanao Izumo Copyright 1999 "free"
// Added binary array support for the Encoding.js
`;
  const izumoExcerpt = IZUMO.split('\n').slice(3, 10).join('\n');

  function withBareCopyright(extra: Record<string, string> = {}): Record<string, FixturePackage> {
    const packages = basicPackages();
    packages['node_modules/c']!.files = {
      LICENSE: MIT,
      'src/util.js': IZUMO,
      // The package's own holder (named in its LICENSE) is a self-reference, not third-party text.
      'lib/own.js': "/*!\n * c\n * Copyright(c) 2020-2024 Example Author <author@example.org>\n * MIT Licensed\n */\n",
      // A bare copyright sign in data (e.g. a charset table) is not a notice.
      'lib/table.js': 'module.exports = { chars: "¨©ª«" };\n',
      ...extra,
    };
    return packages;
  }

  it('fails on a bare third-party copyright line that carries no license marker', () => {
    const errors = errorsOf(makeProject(withBareCopyright()));
    expect(errors).toContainEqual(expect.stringMatching(/c@1\.0\.0.*src\/util\.js:4 unreviewed embedded/));
    expect(errors).toContainEqual(expect.stringMatching(/c@1\.0\.0.*src\/util\.js:9 unreviewed embedded/));
    expect(errors.join('\n')).not.toMatch(/lib\/own\.js|lib\/table\.js/);
  });

  it('does not treat license prose as a holder that the package license already names', () => {
    const isc = 'Permission to use, copy, modify, and/or distribute this software for any\npurpose with or without fee is hereby granted, provided that the above\ncopyright notice and this permission notice appear in all copies.\n';
    const errors = errorsOf(makeProject(withBareCopyright({ 'lib/isc.js': `/*\n${isc}*/\n` })));
    expect(errors).toContainEqual(expect.stringMatching(/lib\/isc\.js:2 unreviewed/));
    expect(errors).toContainEqual(expect.stringMatching(/lib\/isc\.js:4 unreviewed/));
  });

  it('reproduces a pinned non-SPDX grant and labels it separately from the SPDX inventory', () => {
    const entry = {
      package: 'c@1.0.0',
      file: 'src/util.js',
      lines: [4, 10],
      sha256: sha256(izumoExcerpt),
      action: 'reproduce',
      nonSpdxGrant: 'This library is free. You can redistribute it and/or modify it.',
      note: 'Vendored Base64 code.',
    };
    const root = makeProject(withBareCopyright(), basePolicy({ embedded: [entry] }));
    expect(runLicenses(root, 'generate').errors).toEqual([]);
    const notices = generated(root);
    expect(notices).toContain('Copyright (C) 1999 Masanao Izumo <iz@onicos.co.jp>');
    expect(notices).toContain('Embedded grants without an SPDX identifier (not covered by the SPDX allowlist): 1');
    expect(notices).toContain('Non-SPDX grant (verbatim, not an SPDX license; reviewed manually): "This library is free. You can redistribute it and/or modify it."');
  });

  it('rejects a non-SPDX grant that does not occur in the pinned excerpt', () => {
    const entry = {
      package: 'c@1.0.0',
      file: 'src/util.js',
      lines: [4, 10],
      sha256: sha256(izumoExcerpt),
      action: 'reproduce',
      nonSpdxGrant: 'Public domain.',
      note: 'x',
    };
    expect(errorsOf(makeProject(withBareCopyright(), basePolicy({ embedded: [entry] })))).toContainEqual(
      expect.stringMatching(/c@1\.0\.0.*src\/util\.js.*nonSpdxGrant.*not found in the pinned excerpt/),
    );
  });

  it('rejects a declared-MIT license text with appended extra terms unless reviewed', () => {
    const packages = basicPackages();
    packages['node_modules/c']!.files = { LICENSE: MIT_COMMONS_CLAUSE };
    expect(errorsOf(makeProject(packages))).toContainEqual(expect.stringMatching(/c@1\.0\.0: LICENSE reads as MIT\+extra but declared MIT/));
  });
});

describe('runLicenses: filesystem hardening', () => {
  it('fails closed on a symlink inside a production package', () => {
    const root = makeProject(basicPackages());
    symlinkSync('/etc/hostname', join(root, 'node_modules/c/linked.js'));
    expect(errorsOf(root)).toContainEqual(expect.stringMatching(/c@1\.0\.0: linked\.js is a symlink/));
  });

  it('rejects embedded policy paths that escape the package directory', () => {
    const entry = { package: 'c@1.0.0', file: '../b/LICENSE', lines: [1, 1], sha256: sha256('x'), action: 'covered', note: 'x' };
    expect(errorsOf(makeProject(basicPackages(), basePolicy({ embedded: [entry] })))).toContainEqual(
      expect.stringMatching(/policy embedded: c@1\.0\.0 \.\.\/b\/LICENSE escapes the package directory/),
    );
  });
});

describe('runLicenses: development inventory', () => {
  it('rejects dev licenses outside the development allowlist or missing', () => {
    const packages = basicPackages();
    packages['node_modules/d']!.lock.license = 'GPL-3.0-only';
    packages['node_modules/e'] = { lock: lockEntry('1.0.0', undefined, { dev: true }), install: false };
    const errors = errorsOf(makeProject(packages));
    expect(errors).toContainEqual(expect.stringMatching(/dev d@3\.0\.0.*GPL-3\.0-only.*not allowed/));
    expect(errors).toContainEqual(expect.stringMatching(/dev e@1\.0\.0.*no license/));
  });
});

describe('runLicenses: project license metadata', () => {
  it('requires package.json/package-lock MIT, private=true and a LICENSE with the configured copyright', () => {
    expect(errorsOf(makeProject(basicPackages(), basePolicy(), { rootLicense: 'UNLICENSED' }))).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/package\.json: license "UNLICENSED".*expected "MIT"/),
        expect.stringMatching(/package-lock\.json: root license "UNLICENSED".*expected "MIT"/),
      ]),
    );
    expect(errorsOf(makeProject(basicPackages(), basePolicy(), { license: null }))).toContainEqual(
      expect.stringMatching(/LICENSE: missing/),
    );
    expect(errorsOf(makeProject(basicPackages(), basePolicy(), { license: MIT }))).toContainEqual(
      expect.stringMatching(/LICENSE: .*Copyright \(c\) 2026 Example Owner/),
    );
    expect(errorsOf(makeProject(basicPackages(), basePolicy(), { license: ISC.replace('2020 Example Author', '2026 Example Owner') }))).toContainEqual(
      expect.stringMatching(/LICENSE: reads as ISC, expected MIT/),
    );
    const root = makeProject(basicPackages());
    const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    write(join(root, 'package.json'), JSON.stringify({ ...manifest, private: false }));
    expect(errorsOf(root)).toContainEqual(expect.stringMatching(/package\.json: "private": true is required/));
  });
});

describe('runLicenses: drift and generation', () => {
  it('check fails when the lockfile closure changes after generation (lockfile-sensitive)', () => {
    const root = makeProject(basicPackages());
    expect(runLicenses(root, 'generate').ok).toBe(true);
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
    lock.packages['node_modules/a'].dependencies.f = '^1';
    lock.packages['node_modules/f'] = lockEntry('1.0.0', 'MIT');
    write(join(root, 'package-lock.json'), JSON.stringify(lock));
    write(join(root, 'node_modules/f/package.json'), JSON.stringify({ name: 'f', version: '1.0.0', license: 'MIT', repository: 'x/f' }));
    write(join(root, 'node_modules/f/LICENSE'), MIT);
    expect(errorsOf(root)).toEqual([expect.stringMatching(/THIRD_PARTY_NOTICES\.md is out of date.*licenses:generate/)]);
    expect(runLicenses(root, 'generate').ok).toBe(true);
    expect(generated(root)).toContain('## f@1.0.0');
  });

  it('check fails when a generated file was edited by hand or is missing', () => {
    const root = makeProject(basicPackages());
    runLicenses(root, 'generate');
    write(join(root, 'THIRD_PARTY_NOTICES.md'), generated(root).replace('## b@1.1.0', '## b@1.1.1'));
    expect(errorsOf(root)).toContainEqual(expect.stringMatching(/THIRD_PARTY_NOTICES\.md is out of date/));
    rmSync(join(root, 'licenses', 'DEV_DEPENDENCIES.md'));
    expect(errorsOf(root)).toContainEqual(expect.stringMatching(/licenses\/DEV_DEPENDENCIES\.md is out of date/));
  });

  it('generate refuses to write notices while policy errors exist', () => {
    const packages = basicPackages();
    packages['node_modules/c']!.files = { LICENSE: ISC };
    const root = makeProject(packages);
    const result = runLicenses(root, 'generate');
    expect(result.ok).toBe(false);
    expect(() => generated(root)).toThrow();
  });

  it('runs as a CLI with a non-zero exit code on failure', () => {
    const script = resolve(__dirname, '../scripts/licenses.mjs');
    const good = makeProject(basicPackages());
    expect(spawnSync(process.execPath, [script, 'generate', '--root', good], { encoding: 'utf8' }).status).toBe(0);
    const ok = spawnSync(process.execPath, [script, 'check', '--root', good], { encoding: 'utf8' });
    expect(ok.status).toBe(0);
    expect(ok.stdout).toMatch(/licenses: OK.*4 production package versions.*1 development/);

    const packages = basicPackages();
    packages['node_modules/c']!.files = { LICENSE: ISC };
    const bad = spawnSync(process.execPath, [script, 'check', '--root', makeProject(packages)], { encoding: 'utf8' });
    expect(bad.status).toBe(1);
    expect(bad.stderr).toMatch(/reads as ISC/);

    expect(spawnSync(process.execPath, [script, 'bogus'], { encoding: 'utf8' }).status).toBe(2);
  });
});

describe('runLicenses: rendering', () => {
  it('strips trailing whitespace from reproduced lines so the output passes git diff --check', () => {
    const packages = basicPackages();
    packages['node_modules/c']!.files = { LICENSE: MIT.replace('Copyright (c) 2020 Example Author', 'Copyright (c) 2019 \t') };
    const root = makeProject(packages);
    expect(runLicenses(root, 'generate').errors).toEqual([]);
    expect(generated(root)).toContain('Copyright (c) 2019\n');
    expect(generated(root)).not.toMatch(/[ \t]$/m);
  });
});

describe('collectInventory ordering', () => {
  it('orders by package name, then version (not by the name@version string)', () => {
    const packages: Record<string, FixturePackage> = {
      'node_modules/a': { lock: lockEntry('1.0.0', 'MIT') },
      'node_modules/a-b': { lock: lockEntry('1.0.0', 'MIT') },
    };
    const inv = collectInventory(makeFixture({ dependencies: { a: '^1', 'a-b': '^1' }, packages }));
    expect(inv.production.map((p) => p.key)).toEqual(['a@1.0.0', 'a-b@1.0.0']);
  });
});

// Lockfile-sensitive checks against this repository's real `npm ci` install.
describe('this repository (npm ci install)', () => {
  const repo = resolve(__dirname, '..');

  it('derives the same production closure as npm\'s own resolver (npm query .prod)', () => {
    const query = spawnSync('npm', ['query', '.prod'], { cwd: repo, encoding: 'utf8', shell: process.platform === 'win32' });
    expect(query.status).toBe(0);
    const npmView = (JSON.parse(query.stdout) as { location: string; name: string; version: string }[])
      .filter((node) => node.location !== '')
      .map((node) => `${node.location} ${node.name}@${node.version}`)
      .sort();
    const inv = collectInventory(repo);
    expect(inv.errors).toEqual([]);
    const ours = inv.production
      .flatMap((p) => p.paths.map((path) => `${path} ${p.key}`))
      .sort();
    expect(ours).toEqual(npmView);
  });

  it('reproduces the Masanao Izumo Base64 notice from both encoding-japanese locations, labelled non-SPDX', () => {
    const notices = readFileSync(join(repo, 'THIRD_PARTY_NOTICES.md'), 'utf8');
    const section = notices.slice(notices.indexOf('## encoding-japanese@2.4.0'), notices.indexOf('\n## ', notices.indexOf('## encoding-japanese@2.4.0') + 1));
    for (const where of ['Embedded in src/util.js (lines 229-236)', 'Embedded in encoding.js (lines 6124-6131)']) {
      expect(section).toContain(where);
    }
    expect(section.match(/Copyright \(C\) 1999 Masanao Izumo <iz@onicos\.co\.jp>/g)).toHaveLength(2);
    expect(section.match(/This library is free\. {2}You can redistribute it and\/or modify it\./g)).toHaveLength(2);
    expect(section).toContain('Non-SPDX grant (verbatim, not an SPDX license; reviewed manually)');
    expect(notices).toContain('Embedded grants without an SPDX identifier (not covered by the SPDX allowlist): 2');
  });

  it('passes the license policy with current LICENSE, notices and dev inventory', () => {
    const result = runLicenses(repo, 'check');
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });
});
