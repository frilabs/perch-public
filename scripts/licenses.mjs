#!/usr/bin/env node
// Dependency license policy check and third-party notice generator.
//
// Source of truth: package-lock.json (production closure = entries without `dev`, verified by walking the
// dependency graph from the root) plus the license files bundled in the `npm ci`-installed packages.
// Fail closed: missing/unrecognised/disallowed licenses, unreviewed SPDX expressions, license texts that do
// not match the declared SPDX id, unreviewed embedded third-party notices, stale policy entries and drift of
// the generated files are all errors. Uses only Node built-ins.
//
//   node scripts/licenses.mjs check     [--root DIR]   verify policy + that generated files are current
//   node scripts/licenses.mjs generate  [--root DIR]   rewrite generated files (refuses on policy errors)

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, posix, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Both quote styles are canonicalised to `"` so that 'Software' and "Software" variants compare equal.
const normalize = (text) =>
  text
    .replace(/[‘’“”']/g, '"')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();

// Placeholders in the templates below: {holder} matches a short holder name (BSD/ISC disclaimers and the
// BSD-3 endorsement clause name it), {item} an optional list marker such as "1." or "*".
const template = (text) =>
  new RegExp(
    `^${normalize(text)
      .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\\\{holder\\\}/g, '.{1,120}?')
      .replace(/ ?\\\{item\\\} ?/g, ' (?:(?:\\d+|[a-z]|\\*|-)[.)]? )?')}`,
  );
const MIT_START = 'Permission is hereby granted, free of charge, to any person obtaining a copy of this software';
const MIT_GRANT = `${MIT_START} and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so`;
const MIT_DISCLAIMER =
  'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.';
const ISC_START = 'Permission to use, copy, modify, and/or distribute this software';
const BSD_START = 'Redistribution and use in source and binary forms';
const BSD_CLAUSES =
  `${BSD_START}, with or without modification, are permitted provided that the following conditions are met: {item} Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. {item} Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.`;
const BSD_DISCLAIMER =
  'THIS SOFTWARE IS PROVIDED BY {holder} "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL {holder} BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.';
// Each shape is the full license body from its grant to the end of its disclaimer (SPDX template wording).
const SHAPES = [
  { id: 'MIT', start: MIT_START, body: template(`${MIT_GRANT}, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. ${MIT_DISCLAIMER}`) },
  { id: 'MIT-truncated', start: MIT_START, body: template(`${MIT_GRANT}, subject to the following conditions: ${MIT_DISCLAIMER}`) },
  { id: 'MIT-0', start: MIT_START, body: template(`${MIT_GRANT}. ${MIT_DISCLAIMER}`) },
  {
    id: 'ISC',
    start: ISC_START,
    body: template(
      `${ISC_START} for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies. THE SOFTWARE IS PROVIDED "AS IS" AND {holder} DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL {holder} BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.`,
    ),
  },
  {
    id: 'BSD-3-Clause',
    start: BSD_START,
    body: template(`${BSD_CLAUSES} {item} Neither the name of {holder} nor the names of {holder} may be used to endorse or promote products derived from this software without specific prior written permission. ${BSD_DISCLAIMER}`),
  },
  { id: 'BSD-2-Clause', start: BSD_START, body: template(`${BSD_CLAUSES} ${BSD_DISCLAIMER}`) },
];
// Text before the grant may only be a title and copyright lines; operative-sounding words there block.
const RESTRICTIVE_HEADER = /\b(shall|must|may not|only|provided|conditions?|restrict\w*|prohibit\w*|commercial|evil|except|sell|permission)\b/;
const FOREIGN = ['general public license', 'mozilla public license', 'apache license', 'eupl', 'european union public licen'];

/**
 * Classifies a license file against the full body of the known permissive templates (MIT, MIT-0, ISC,
 * BSD-2-Clause, BSD-3-Clause, plus the MIT-truncated shape). Before the grant only a title and copyright
 * lines are accepted; extra material after a complete body yields `<id>+extra`; anything else is UNKNOWN.
 * This is an engineering heuristic, not SPDX license matching: the holder placeholders and list markers are
 * wildcards, and every result still needs the reviewed policy plus the pinned, drift-checked notices.
 */
export function classifyLicenseText(text) {
  const n = normalize(text);
  if (!n || FOREIGN.some((marker) => n.includes(marker))) return 'UNKNOWN';
  for (const { id, start, body } of SHAPES) {
    const at = n.indexOf(normalize(start));
    if (at < 0) continue;
    const match = body.exec(n.slice(at));
    if (!match) continue;
    if (RESTRICTIVE_HEADER.test(n.slice(0, at))) return 'UNKNOWN';
    return n.slice(at + match[0].length).trim() ? `${id}+extra` : id;
  }
  return 'UNKNOWN';
}

/** Turns package.json `repository` metadata into an https source URL, or null. */
export function normalizeRepositoryUrl(repository) {
  const raw = typeof repository === 'string' ? repository : repository?.url;
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  let url = raw.trim();
  if (/^[\w.-]+\/[\w.-]+$/.test(url)) return `https://github.com/${url}`;
  const scp = /^git@([^:/]+):(.+)$/.exec(url);
  if (scp) url = `https://${scp[1]}/${scp[2]}`;
  url = url.replace(/^git\+/, '').replace(/^(git|ssh):\/\//, 'https://').replace(/^https:\/\/[^@/]+@/, 'https://');
  if (!/^https?:\/\/[^/]+\/.+/.test(url)) return null;
  return url.replace(/^http:/, 'https:').replace(/\.git$/, '').replace(/\/$/, '');
}

const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const byCodePoint = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const packageNameOf = (lockPath, entry) => entry.name ?? lockPath.slice(lockPath.lastIndexOf('node_modules/') + 13);

/** Resolves `dep` from `fromPath` the way Node does: nearest node_modules upwards, then the root. */
function resolveLockPath(packages, fromPath, dep) {
  let base = fromPath;
  for (;;) {
    const candidate = base ? `${base}/node_modules/${dep}` : `node_modules/${dep}`;
    if (packages[candidate]) return candidate;
    if (!base) return null;
    base = base.slice(0, base.lastIndexOf('node_modules/')).replace(/\/$/, '');
  }
}

/** Runtime edges of a lock entry: dependencies, optionalDependencies and non-optional peers. */
function edgesOf(entry) {
  const edges = [];
  for (const dep of Object.keys(entry.dependencies ?? {})) edges.push({ dep, optional: false });
  for (const dep of Object.keys(entry.optionalDependencies ?? {})) edges.push({ dep, optional: true });
  for (const dep of Object.keys(entry.peerDependencies ?? {})) {
    edges.push({ dep, optional: entry.peerDependenciesMeta?.[dep]?.optional === true });
  }
  return edges;
}

/**
 * Reads package-lock.json and the installed node_modules under `root`.
 * Returns the production closure (grouped by name@version, verified against installed manifests),
 * the lockfile-only development inventory, and every inconsistency found as an error string.
 */
export function collectInventory(root) {
  const errors = [];
  const lock = readJson(join(root, 'package-lock.json'));
  const result = { lockfileVersion: lock.lockfileVersion, production: [], development: [], errors };
  if (!(lock.lockfileVersion >= 2) || typeof lock.packages !== 'object') {
    errors.push(`package-lock.json: lockfileVersion ${lock.lockfileVersion} is unsupported (need v2/v3 "packages")`);
    return result;
  }
  const packages = lock.packages;

  // Walk the runtime graph from the root's production dependencies.
  const reachable = new Set();
  const queue = [''];
  while (queue.length) {
    const from = queue.shift();
    // devDependencies are deliberately not edges: the root's dev tools are not part of the closure.
    for (const { dep, optional } of edgesOf(packages[from] ?? {})) {
      const target = resolveLockPath(packages, from, dep);
      if (!target) {
        if (!optional) errors.push(`${from || 'package.json'}: requires "${dep}" which is not in the lockfile`);
        continue;
      }
      if (packages[target].dev) {
        errors.push(`${target}: flagged dev in the lockfile but required by production package ${from || 'package.json'}`);
      }
      if (!reachable.has(target)) {
        reachable.add(target);
        queue.push(target);
      }
    }
  }

  const production = new Map();
  const development = new Map();
  for (const [path, entry] of Object.entries(packages)) {
    if (path === '') continue;
    if (entry.link) {
      errors.push(`${path}: linked packages are unsupported (fail closed)`);
      continue;
    }
    const name = packageNameOf(path, entry);
    const key = `${name}@${entry.version}`;
    if (entry.dev) {
      const item = development.get(key) ?? { key, name, version: entry.version, license: entry.license ?? null, optional: !!entry.optional, resolved: entry.resolved ?? null, paths: [] };
      item.paths.push(path);
      development.set(key, item);
      continue;
    }
    if (!reachable.has(path)) {
      errors.push(`${path}: lockfile marks it production but it is not reachable from package.json dependencies`);
      continue;
    }
    const manifestPath = join(root, path, 'package.json');
    if (!existsSync(manifestPath)) {
      errors.push(`${path}: production package not installed; run npm ci before checking licenses`);
      continue;
    }
    const manifest = readJson(manifestPath);
    if (manifest.name !== name) errors.push(`${path}: installed name "${manifest.name}" differs from lockfile "${name}"`);
    if (manifest.version !== entry.version) {
      errors.push(`${path}: installed version ${manifest.version} differs from lockfile ${entry.version}`);
    }
    const declared = typeof manifest.license === 'string' && manifest.license.trim() ? manifest.license.trim() : null;
    if (!declared) errors.push(`${key} (${path}): no SPDX license in package.json (fail closed)`);
    else if (entry.license !== declared) {
      errors.push(`${path}: installed license "${declared}" differs from lockfile "${entry.license}"`);
    }
    const item = production.get(key) ?? {
      key,
      name,
      version: entry.version,
      declared,
      sourceUrl: normalizeRepositoryUrl(manifest.repository),
      resolved: entry.resolved ?? null,
      integrity: entry.integrity ?? null,
      paths: [],
    };
    if (item.declared !== declared || item.integrity !== (entry.integrity ?? null)) {
      errors.push(`${key}: installed copies differ (${item.paths[0]} vs ${path})`);
    }
    item.paths.push(path);
    production.set(key, item);
  }
  const sorted = (map) => [...map.values()].map((p) => ({ ...p, paths: p.paths.sort(byCodePoint) })).sort((a, b) => byCodePoint(a.name, b.name) || byCodePoint(a.version, b.version));
  result.production = sorted(production);
  result.development = sorted(development);
  return result;
}

const LICENSE_FILE = /^(licen[cs]e|copying|notice)([.-][\w.-]*)?$/i;
const NOTICE_FILE = /^notice([.-][\w.-]*)?$/i;
const CODE_FILE = /\.(c|m)?(j|t)sx?$/;
const SIMPLE_SPDX = /^[A-Za-z0-9.-]+$/;
// Phrases that indicate license or attribution text embedded in shipped code. Deliberately broad: every
// hit must be covered by a reviewed, sha256-pinned entry in licenses/policy.json "embedded".
const EMBEDDED_MARKER =
  /Permission is hereby granted|Permission to use, copy, modify|Redistribution and use in source|Apache License|Mozilla Public License|General Public License|\bEUPL\b|European Union Public Licen|@license|@preserve|SPDX-License-Identifier|Licensed under|MIT License|BSD License|ISC License|Creative Commons|\bUnlicense\b|public domain|Copied from\s+https?:|All rights reserved/i;
// A copyright line is third-party text unless its holder is already named in the package's own reproduced
// license file (e.g. jshttp headers repeating the LICENSE holders). A bare "©" only counts before a year,
// because charset tables contain the sign as data.
const COPYRIGHT_MARKER = /\bcopyright\b|\(c\)\s*\d{4}|©\s*\d{4}/i;
const LICENSE_PROSE = /notice|permission|redistribut|warrant|liab|licen[cs]|software|disclaim|condition/i;
const GENERATED_NOTICE = '<!-- Generated by scripts/licenses.mjs (npm run licenses:generate). Do not edit by hand: npm run licenses:check fails on drift. -->';
export const OUTPUTS = { notices: 'THIRD_PARTY_NOTICES.md', development: 'licenses/DEV_DEPENDENCIES.md' };

/** Normalised text of a code excerpt with per-line comment markers removed. */
const commentText = (excerpt) => normalize(excerpt.split('\n').map((line) => line.replace(/^\s*(\/\/+|\/?\*+\/?|#)?/, '').replace(/\*+\/\s*$/, '')).join(' '));
const sha256 = (text) => createHash('sha256').update(text).digest('hex');
const readText = (path) => readFileSync(path, 'utf8').replace(/\r\n?/g, '\n');
const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Files below `dir` (nested node_modules excluded); symlinks are collected separately so callers fail closed. */
function listFiles(dir, rel = '', symlinks = []) {
  const files = [];
  for (const entry of readdirSync(join(dir, rel), { withFileTypes: true }).sort((a, b) => byCodePoint(a.name, b.name))) {
    const path = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) symlinks.push(path);
    else if (entry.isDirectory()) {
      if (entry.name !== 'node_modules') files.push(...listFiles(dir, path, symlinks).files);
    } else if (entry.isFile()) files.push(path);
  }
  return { files, symlinks };
}

/** The holder named by a copyright line, without comment markers, years, e-mails, URLs and "(c)". */
function copyrightHolder(line) {
  return normalize(
    line
      .replace(/^[\s/*!#-]+|[\s/*]+$/g, '')
      .replace(/copyright|©|all rights reserved\.?/gi, ' ')
      .replace(/<[^>]*>|\([^)]*\)|https?:\/\/\S+|\S+@\S+/g, ' ')
      .replace(/\b\d{4}\b(\s*[-–,]\s*(\d{4}|present))*/gi, ' ')
      .replace(/^\s*by\s+/i, ''),
  ).replace(/^[\s,.;:-]+|[\s,.;:-]+$/g, '');
}

/**
 * Lines in shipped files that look like license/attribution text: marker phrases (minus self-references to
 * `license`) and copyright lines whose holder is not named in `ownLicenseText` (the reproduced license files).
 */
function scanEmbedded(dir, license, ownLicenseText) {
  const selfReference = new RegExp(`^(@license\\s+${escapeRegExp(license)}|${escapeRegExp(license)}\\s+licen[cs]ed)$`, 'i');
  const own = normalize(ownLicenseText);
  const ownHolder = (text) => {
    const holder = copyrightHolder(text);
    return holder.length >= 3 && !LICENSE_PROSE.test(holder) && own.includes(holder);
  };
  const { files, symlinks } = listFiles(dir);
  const hits = symlinks.map((file) => ({ file, line: 0, symlink: true }));
  for (const file of files) {
    const base = posix.basename(file);
    if (!file.includes('/') && (LICENSE_FILE.test(base) || base === 'package.json')) continue;
    if (LICENSE_FILE.test(base)) {
      hits.push({ file, line: 1 });
      continue;
    }
    if (!CODE_FILE.test(base)) continue;
    readText(join(dir, file))
      .split('\n')
      .forEach((text, i) => {
        const marker = EMBEDDED_MARKER.test(text) && !selfReference.test(text.replace(/^[\s/*!#]+|[\s/*]+$/g, ''));
        if (marker || (COPYRIGHT_MARKER.test(text) && !ownHolder(text))) hits.push({ file, line: i + 1 });
      });
  }
  return hits;
}

/** Resolves the license that applies to `pkg`: a simple allowed SPDX id, or an explicit reviewed election. */
function appliedLicense(pkg, policy, errors) {
  const allowed = policy.production.allowed;
  const election = policy.elections.find((e) => e.package === pkg.key);
  if (SIMPLE_SPDX.test(pkg.declared)) {
    if (election) errors.push(`policy elections: ${pkg.key} is stale (license is the simple id "${pkg.declared}")`);
    if (!allowed.includes(pkg.declared)) errors.push(`${pkg.key}: license "${pkg.declared}" is not allowed for production`);
    return { license: pkg.declared, election: null };
  }
  if (!election) {
    errors.push(`${pkg.key}: license expression "${pkg.declared}" needs an explicit reviewed election in licenses/policy.json`);
    return null;
  }
  if (election.expression !== pkg.declared) {
    errors.push(`policy elections: ${pkg.key} reviewed "${election.expression}" but the package declares "${pkg.declared}"`);
    return null;
  }
  const alternatives = pkg.declared.replace(/^\(|\)$/g, '').split(/\s+OR\s+/);
  if (alternatives.some((alt) => !/^[A-Za-z0-9.+-]+$/.test(alt)) || !alternatives.includes(election.elected)) {
    errors.push(`${pkg.key}: elected "${election.elected}" is not a top-level OR alternative of "${pkg.declared}"`);
    return null;
  }
  if (!allowed.includes(election.elected)) {
    errors.push(`${pkg.key}: elected "${election.elected}" is not allowed for production`);
    return null;
  }
  return { license: election.elected, election };
}

function evaluateProduction(root, inventory, policy, errors) {
  const used = { textOverrides: new Set(), embedded: new Set() };
  const entries = [];
  for (const pkg of inventory.production) {
    const dir = join(root, pkg.paths[0]);
    if (!pkg.sourceUrl) errors.push(`${pkg.key}: no source repository URL in package.json (fail closed)`);
    if (!pkg.declared) continue;
    const applied = appliedLicense(pkg, policy, errors);
    if (!applied) continue;

    const present = readdirSync(dir).filter((f) => LICENSE_FILE.test(f) && statSync(join(dir, f)).isFile()).sort(byCodePoint);
    const files = applied.election?.licenseFiles ?? present;
    if (files.length === 0) errors.push(`${pkg.key}: no bundled license file (fail closed)`);
    const texts = [];
    const notes = [];
    for (const file of files) {
      if (!present.includes(file)) {
        errors.push(`${pkg.key}: license file ${file} named in licenses/policy.json is not bundled`);
        continue;
      }
      const text = readText(join(dir, file));
      texts.push({ file, text });
      if (NOTICE_FILE.test(file)) continue;
      const detected = classifyLicenseText(text);
      if (detected === applied.license) continue;
      const index = policy.textOverrides.findIndex((o) => o.package === pkg.key && o.file === file);
      if (index >= 0 && policy.textOverrides[index].detected === detected) {
        used.textOverrides.add(index);
        notes.push(policy.textOverrides[index].note);
      } else {
        errors.push(`${pkg.key}: ${file} reads as ${detected} but declared ${applied.license} (needs manual review)`);
      }
    }

    const reviewed = policy.embedded.map((e, index) => ({ ...e, index })).filter((e) => e.package === pkg.key);
    const excerpts = [];
    for (const entry of reviewed) {
      const path = resolve(dir, String(entry.file));
      const inside = relative(dir, path);
      if (!inside || inside.startsWith('..') || isAbsolute(inside)) {
        errors.push(`policy embedded: ${pkg.key} ${entry.file} escapes the package directory`);
        continue;
      }
      const [start, end] = entry.lines ?? [];
      if (!existsSync(path) || !(start >= 1 && end >= start)) {
        errors.push(`policy embedded: ${pkg.key} ${entry.file} lines ${entry.lines} does not exist`);
        continue;
      }
      const excerpt = readText(path).split('\n').slice(start - 1, end).join('\n');
      if (sha256(excerpt) !== entry.sha256) {
        errors.push(`${pkg.key}: ${entry.file} lines ${start}-${end} sha256 mismatch (embedded text changed; re-review)`);
      } else if (entry.action !== 'reproduce' && entry.action !== 'covered') {
        errors.push(`policy embedded: ${pkg.key} ${entry.file} has unknown action "${entry.action}"`);
      } else if (entry.nonSpdxGrant !== undefined && !commentText(excerpt).includes(normalize(String(entry.nonSpdxGrant)))) {
        errors.push(`policy embedded: ${pkg.key} ${entry.file} nonSpdxGrant "${entry.nonSpdxGrant}" not found in the pinned excerpt`);
      } else {
        excerpts.push({ ...entry, excerpt });
      }
    }
    for (const hit of scanEmbedded(dir, applied.license, texts.map((t) => t.text).join('\n'))) {
      if (hit.symlink) {
        errors.push(`${pkg.key}: ${hit.file} is a symlink (fail closed: not scanned, may point outside the package)`);
        continue;
      }
      const cover = reviewed.find((e) => e.file === hit.file && e.lines?.[0] <= hit.line && hit.line <= e.lines?.[1]);
      if (cover) used.embedded.add(cover.index);
      else {
        errors.push(`${pkg.key}: ${hit.file}:${hit.line} unreviewed embedded license/notice text (review and pin it in licenses/policy.json "embedded")`);
      }
    }
    entries.push({ ...pkg, applied, texts, notes, excerpts });
  }

  policy.textOverrides.forEach((o, i) => {
    if (!used.textOverrides.has(i)) errors.push(`policy textOverrides: ${o.package} ${o.file} is stale (no matching license text in the production closure)`);
  });
  policy.embedded.forEach((e, i) => {
    if (!used.embedded.has(i)) errors.push(`policy embedded: ${e.package} ${e.file} is stale (no matching embedded text in the production closure)`);
  });
  const keys = new Set(inventory.production.map((p) => p.key));
  for (const e of policy.elections) {
    if (!keys.has(e.package)) errors.push(`policy elections: ${e.package} is stale (not in the production closure)`);
  }
  return entries;
}

function checkDevelopment(inventory, policy, errors) {
  for (const dev of inventory.development) {
    if (!dev.license) errors.push(`dev ${dev.key}: no license in package-lock.json (fail closed)`);
    else if (!SIMPLE_SPDX.test(dev.license) || !policy.development.allowed.includes(dev.license)) {
      errors.push(`dev ${dev.key}: license "${dev.license}" is not allowed for development dependencies`);
    }
  }
}

function checkProject(root, policy, errors) {
  const { license, copyright } = policy.project;
  const manifest = readJson(join(root, 'package.json'));
  if (manifest.license !== license) errors.push(`package.json: license "${manifest.license}" but expected "${license}"`);
  if (manifest.private !== true) errors.push('package.json: "private": true is required (publishing is not authorised)');
  const lockRoot = readJson(join(root, 'package-lock.json')).packages?.['']?.license;
  if (lockRoot !== license) errors.push(`package-lock.json: root license "${lockRoot}" but expected "${license}"`);
  const path = join(root, 'LICENSE');
  if (!existsSync(path)) {
    errors.push('LICENSE: missing');
    return;
  }
  const text = readText(path);
  const detected = classifyLicenseText(text);
  if (detected !== license) errors.push(`LICENSE: reads as ${detected}, expected ${license}`);
  if (!text.includes(copyright)) errors.push(`LICENSE: does not contain "${copyright}"`);
}

const fenced = (text) => {
  const longest = Math.max(0, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return `${fence}text\n${text.replace(/[ \t]+$/gm, '').replace(/\n+$/, '')}\n${fence}`;
};
const countBy = (items, key) => {
  const counts = new Map();
  for (const item of items) counts.set(key(item), (counts.get(key(item)) ?? 0) + 1);
  return [...counts].sort((a, b) => b[1] - a[1] || byCodePoint(a[0], b[0]));
};
const appliedLabel = (e) => (e.applied.election ? `${e.applied.license} (elected from \`${e.declared}\`)` : e.applied.license);

function renderNotices(entries, lockfileVersion) {
  const locations = entries.reduce((n, e) => n + e.paths.length, 0);
  const out = [
    '# Third-party notices',
    '',
    GENERATED_NOTICE,
    '',
    'Perch itself is licensed under the MIT License (see `LICENSE`). This file covers the **production dependency',
    `closure** that \`npm ci --omit=dev\` installs from \`package-lock.json\` (lockfileVersion ${lockfileVersion}). These packages are`,
    'not part of the Perch source tree and are **not relicensed**: each remains under its own license. The license and',
    'notice files below are reproduced verbatim from the installed packages, together with reviewed attribution text',
    'embedded in their code (only trailing whitespace on each line is stripped). Development-only tooling is',
    'inventoried separately in `licenses/DEV_DEPENDENCIES.md`.',
    '',
    'The license column is the SPDX id from package metadata, checked against the bundled license file. Attribution',
    'embedded in code is reviewed separately; where it carries its own grant without an SPDX identifier, that grant is',
    'quoted verbatim at the excerpt and is not part of the SPDX allowlist check.',
    '',
    '**Downloaded at runtime, not bundled:** `perch whatsapp install` downloads the GOWA bridge',
    '([go-whatsapp-web-multidevice](https://github.com/aldinokemal/go-whatsapp-web-multidevice), MIT License, by',
    'Aldino Kemal) from its GitHub release (version and SHA-256 pinned in `src/whatsapp/install.ts`) onto the',
    "operator's server. GOWA is not part of the Perch source tree or package and is not covered by this inventory;",
    'its MIT license text is published in that repository.',
    '',
    '## Summary',
    '',
    `- Production package versions: ${entries.length} (${locations} installed locations)`,
    `- Licenses applied: ${countBy(entries, (e) => e.applied.license).map(([l, n]) => `${l} ${n}`).join(', ')}`,
    `- Embedded grants without an SPDX identifier (not covered by the SPDX allowlist): ${entries.reduce((n, e) => n + e.excerpts.filter((x) => x.nonSpdxGrant !== undefined).length, 0)}`,
    '',
    '| Package | Version | License | Source |',
    '| --- | --- | --- | --- |',
    ...entries.map((e) => `| ${e.name} | ${e.version} | ${appliedLabel(e)} | ${e.sourceUrl} |`),
  ];
  for (const e of entries) {
    out.push('', '---', '', `## ${e.key}`, '');
    out.push(`- License: ${appliedLabel(e)}`);
    if (e.applied.election) out.push(`- Election: ${e.applied.election.note}`);
    out.push(`- Source: ${e.sourceUrl}`);
    out.push(`- Distribution: ${e.resolved ?? 'n/a'}`);
    out.push(`- Integrity: ${e.integrity ?? 'n/a'}`);
    out.push(`- Installed at: ${e.paths.map((p) => `\`${p}\``).join(', ')}`);
    for (const note of e.notes) out.push(`- Review note: ${note}`);
    for (const { file, text } of e.texts) out.push('', `### ${file}`, '', fenced(text));
    for (const x of e.excerpts) {
      out.push('', `### Embedded in ${x.file} (lines ${x.lines[0]}-${x.lines[1]})`, '', `Review note: ${x.note}`);
      if (x.nonSpdxGrant !== undefined) {
        out.push('', `Non-SPDX grant (verbatim, not an SPDX license; reviewed manually): "${x.nonSpdxGrant}"`);
      }
      if (x.action === 'reproduce') out.push('', fenced(x.excerpt));
    }
  }
  return `${out.join('\n')}\n`;
}

function renderDevelopment(inventory) {
  const dev = inventory.development;
  return `${[
    '# Development dependency inventory',
    '',
    GENERATED_NOTICE,
    '',
    'Build and test tooling from `package-lock.json` entries flagged `dev`. These packages are **not distributed**',
    'with Perch (not part of `npm ci --omit=dev`, not bundled into `dist/`), so their license texts are not',
    'reproduced here. The list is taken from the lockfile only and is therefore platform independent: it includes',
    'optional platform-specific binaries that `npm ci` installs only on a matching OS/CPU.',
    '',
    `- Development package versions: ${dev.length}`,
    `- Licenses (lockfile metadata): ${countBy(dev, (d) => d.license).map(([l, n]) => `${l} ${n}`).join(', ')}`,
    '',
    '| Package | Version | License (lockfile) | Optional | Distribution |',
    '| --- | --- | --- | --- | --- |',
    ...dev.map((d) => `| ${d.name} | ${d.version} | ${d.license} | ${d.optional ? 'yes' : 'no'} | ${d.resolved ?? 'n/a'} |`),
  ].join('\n')}\n`;
}

/** Runs the full policy check; `generate` rewrites the generated files, `check` compares them. */
export function runLicenses(root, mode) {
  const errors = [];
  const policyPath = join(root, 'licenses', 'policy.json');
  if (!existsSync(policyPath)) return { ok: false, errors: ['licenses/policy.json: missing'] };
  const policy = { elections: [], textOverrides: [], embedded: [], ...readJson(policyPath) };
  const inventory = collectInventory(root);
  errors.push(...inventory.errors);
  checkProject(root, policy, errors);
  const entries = evaluateProduction(root, inventory, policy, errors);
  checkDevelopment(inventory, policy, errors);
  const summary = {
    production: inventory.production.length,
    locations: inventory.production.reduce((n, p) => n + p.paths.length, 0),
    development: inventory.development.length,
    licenses: countBy(entries, (e) => e.applied.license),
  };
  if (errors.length) return { ok: false, errors, ...summary };

  const outputs = {
    [OUTPUTS.notices]: renderNotices(entries, inventory.lockfileVersion),
    [OUTPUTS.development]: renderDevelopment(inventory),
  };
  for (const [rel, content] of Object.entries(outputs)) {
    const path = join(root, rel);
    if (mode === 'generate') writeFileSync(path, content);
    else if (!existsSync(path) || readFileSync(path, 'utf8') !== content) {
      errors.push(`${rel} is out of date; run npm run licenses:generate and review the diff`);
    }
  }
  return { ok: errors.length === 0, errors, ...summary };
}

function main(argv) {
  const [mode, ...rest] = argv;
  const rootFlag = rest.indexOf('--root');
  if ((mode !== 'check' && mode !== 'generate') || (rootFlag >= 0 && !rest[rootFlag + 1])) {
    process.stderr.write('usage: node scripts/licenses.mjs <check|generate> [--root DIR]\n');
    return 2;
  }
  const root = resolve(rootFlag >= 0 ? rest[rootFlag + 1] : '.');
  const result = runLicenses(root, mode);
  if (!result.ok) {
    for (const error of result.errors) process.stderr.write(`${error}\n`);
    process.stderr.write(`licenses: FAILED (${result.errors.length} problem(s))\n`);
    return 1;
  }
  const licenses = result.licenses.map(([l, n]) => `${l} ${n}`).join(', ');
  process.stdout.write(
    `licenses: OK${mode === 'generate' ? ' (generated)' : ''}: ${result.production} production package versions ` +
      `(${result.locations} locations; ${licenses}), ${result.development} development entries\n`,
  );
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
