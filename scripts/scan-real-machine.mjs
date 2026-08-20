#!/usr/bin/env node
/**
 * PHASE 3: run the real scanners against the extensions actually installed on this machine.
 *
 * The point is not to demonstrate that it finds things. It is to find out what it says about
 * a machine we believe to be clean, because every hard finding here is a false positive until
 * proven otherwise, and false positives are what get a security tool uninstalled.
 *
 *   node scripts/scan-real-machine.mjs [--json]
 */
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const OUT = path.join(process.cwd(), 'out', 'scanner');
for (const f of ['threatFeed.js', 'secretScanner.js', 'permissionScanner.js']) {
  if (!existsSync(path.join(OUT, f))) {
    console.error(`Compiled output missing: ${path.join(OUT, f)}\nRun: npx tsc -p ./`);
    process.exit(2);
  }
}
const threat = require(path.join(OUT, 'threatFeed.js'));
const secrets = require(path.join(OUT, 'secretScanner.js'));
const perms = require(path.join(OUT, 'permissionScanner.js'));

const HOME = os.homedir();
const EDITORS = {
  'VS Code': path.join(HOME, '.vscode', 'extensions'),
  'VS Code Insiders': path.join(HOME, '.vscode-insiders', 'extensions'),
  Cursor: path.join(HOME, '.cursor', 'extensions'),
  Windsurf: path.join(HOME, '.windsurf', 'extensions'),
};

const info = threat.feedInfo();
console.log(`threat feed: ${info.loaded ? 'loaded' : 'NOT LOADED'}  ` +
  `malicious=${info.counts.malicious} risky=${info.counts.risky} publishers=${info.counts.publishers}  ` +
  `generated ${info.generatedUtc}`);
if (!info.loaded) { console.error('Refusing to report: the feed did not load, so a clean result would be meaningless.'); process.exit(2); }

const results = [];
const seenIds = new Map();

for (const [editor, root] of Object.entries(EDITORS)) {
  if (!existsSync(root)) continue;
  for (const d of readdirSync(root, { withFileTypes: true })) {
    if (!d.isDirectory() || d.name.startsWith('.')) continue;
    const dir = path.join(root, d.name);
    const pkgPath = path.join(dir, 'package.json');
    if (!existsSync(pkgPath)) continue;

    let pkg;
    try { pkg = JSON.parse(readFileSync(pkgPath, 'utf8')); } catch { continue; }
    if (!pkg.publisher || !pkg.name) continue;

    const id = `${pkg.publisher}.${pkg.name}`;
    seenIds.set(id.toLowerCase(), (seenIds.get(id.toLowerCase()) || 0) + 1);

    const t0 = Date.now();
    const malicious = threat.checkMalicious(id);
    const capability = threat.checkCapability(id);
    let permAlerts = [];
    try { permAlerts = perms.scanPermissions(pkg) || []; } catch (e) { permAlerts = [{ severity: 'error', message: `permission scan threw: ${e.message}` }]; }

    let secretFindings = [];
    try { secretFindings = secrets.scanDirectory(dir) || []; } catch (e) { secretFindings = [{ severity: 'error', type: 'scanner-error', line: 0, file: '', match: e.message }]; }

    results.push({
      editor, id, version: pkg.version, dir,
      malicious, capability,
      permAlerts, secretFindings,
      ms: Date.now() - t0,
    });
  }
}

const totalMs = results.reduce((n, r) => n + r.ms, 0);
console.log(`scanned ${results.length} installed extensions in ${(totalMs / 1000).toFixed(1)}s\n`);

// ── the number that decides whether this ships ─────────────────────────────────
const maliciousHits = results.filter((r) => r.malicious);
console.log('== MALICIOUS FEED MATCHES (hard findings) ==');
if (!maliciousHits.length) console.log('  none  <- expected on a clean machine');
for (const r of maliciousHits) {
  console.log(`  ${r.id} ${r.version}  [${r.malicious.category}/${r.malicious.severity}]${r.malicious.publisherBlocked ? ' PUBLISHER BLOCKED' : ''}`);
}

console.log('\n== SECRET FINDINGS (hard findings) ==');
const withSecrets = results.filter((r) => r.secretFindings.length);
if (!withSecrets.length) console.log('  none');
for (const r of withSecrets) {
  console.log(`  ${r.id} ${r.version}  ${r.secretFindings.length} finding(s)`);
  for (const f of r.secretFindings.slice(0, 6)) {
    const where = f.file ? `${f.file}:${f.line}` : '(unknown)';
    console.log(`      [${f.severity || '?'}] ${f.type || '?'}  ${where}`);
  }
  if (r.secretFindings.length > 6) console.log(`      ... +${r.secretFindings.length - 6} more`);
}

console.log('\n== PERMISSION / CAPABILITY ALERTS (advisory) ==');
const alertCounts = {};
for (const r of results) for (const a of r.permAlerts) {
  const k = `${a.severity || '?'} | ${a.message || a.type || '?'}`;
  alertCounts[k] = (alertCounts[k] || 0) + 1;
}
for (const [k, v] of Object.entries(alertCounts).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${String(v).padStart(3)}x  ${k.slice(0, 110)}`);
}

console.log('\n== KNOWN HIGH-CAPABILITY (informational, must NOT be a finding) ==');
const caps = results.filter((r) => r.capability);
if (!caps.length) console.log('  none');
for (const r of caps) console.log(`  ${r.id}  [${r.capability.category}]`);

console.log('\n== STALE DUPLICATE VERSIONS ==');
const dupes = [...seenIds.entries()].filter(([, n]) => n > 1);
if (!dupes.length) console.log('  none');
for (const [id, n] of dupes) {
  const copies = results.filter((r) => r.id.toLowerCase() === id);
  const bytes = copies.reduce((s, c) => s + dirSize(c.dir), 0);
  console.log(`  ${id}  ${n} copies  ${(bytes / 1048576).toFixed(0)} MB  versions: ${copies.map((c) => c.version).join(', ')}`);
}

function dirSize(dir, depth = 0) {
  if (depth > 5) return 0;
  let total = 0;
  let entries = [];
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return 0; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    try { total += e.isDirectory() ? dirSize(p, depth + 1) : statSync(p).size; } catch { /* skip */ }
  }
  return total;
}

console.log('\n== VERDICT ==');
// Only critical and high count as hard findings. Medium behaviour signals ("this file calls
// child_process") are advisory context rather than accusations, and a clean machine is
// expected to have some. Counting them as failures makes the target unreachable, and a
// target you cannot hit is a target you start ignoring.
const allFindings = results.flatMap((r) => r.secretFindings);
const hard = allFindings.filter((f) => f.severity === 'critical' || f.severity === 'high');
const advisory = allFindings.filter((f) => f.severity === 'medium');

console.log(`extensions scanned         : ${results.length}`);
console.log(`malicious feed matches     : ${maliciousHits.length}`);
console.log(`hard findings (crit/high)  : ${hard.length}`);
console.log(`advisory findings (medium) : ${advisory.length} across ${new Set(advisory.map((f) => f.file)).size} files`);

const clean = maliciousHits.length === 0 && hard.length === 0;
console.log('\n' + (clean
  ? 'PASS - zero hard findings on a machine believed clean.'
  : 'REVIEW EACH - every hard finding is a false positive until proven otherwise.'));
for (const f of hard) console.log(`  [${f.severity}] ${f.file}:${f.line}  ${f.description}`);

if (process.argv.includes('--json')) {
  const { writeFileSync } = await import('node:fs');
  writeFileSync('scan-results.json', JSON.stringify(results, null, 2));
  console.log('\nfull results written to scan-results.json');
}
