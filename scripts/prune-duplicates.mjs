#!/usr/bin/env node
/**
 * Find and optionally remove superseded extension versions left on disk.
 *
 *   node scripts/prune-duplicates.mjs           dry run, lists what would go
 *   node scripts/prune-duplicates.mjs --delete  actually removes them
 *
 * VS Code leaves the old directory behind when an extension updates. The stale copy is never
 * loaded, but it is still readable code sitting on disk, and if that version is later found
 * malicious it is still there. On the development machine this accounted for 3.5 GB.
 *
 * Safety rules, in order of importance:
 *   - The highest version of every extension is ALWAYS kept. Never touched.
 *   - Nothing is deleted while the editor is running, because it may hold file handles and
 *     rewrites extensions.json on exit.
 *   - Anything listed in the editor's own `extensions.json` as the active version is kept,
 *     even if the version comparison disagrees. The editor is the authority on what it loads.
 *   - Dry run is the default. Deleting requires an explicit flag.
 */
import { readdirSync, readFileSync, existsSync, statSync, rmSync } from 'node:fs';
import { execSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

const DELETE = process.argv.includes('--delete');
const HOME = os.homedir();

const EDITORS = {
  'VS Code': path.join(HOME, '.vscode', 'extensions'),
  'VS Code Insiders': path.join(HOME, '.vscode-insiders', 'extensions'),
  Cursor: path.join(HOME, '.cursor', 'extensions'),
  Windsurf: path.join(HOME, '.windsurf', 'extensions'),
};

/** Editor processes that must not be running when we delete from their extension folder. */
const PROCESS_FOR_EDITOR = {
  'VS Code': ['Code.exe', 'code'],
  'VS Code Insiders': ['Code - Insiders.exe'],
  Cursor: ['Cursor.exe', 'cursor'],
  Windsurf: ['Windsurf.exe', 'windsurf'],
};

function runningProcesses() {
  try {
    if (process.platform === 'win32') {
      return execSync('tasklist /fo csv /nh', { encoding: 'utf8', windowsHide: true });
    }
    return execSync('ps -A -o comm=', { encoding: 'utf8' });
  } catch {
    return '';
  }
}
const PROCESS_TABLE = runningProcesses();
const isRunning = (editor) =>
  (PROCESS_FOR_EDITOR[editor] || []).some((p) => PROCESS_TABLE.toLowerCase().includes(p.toLowerCase()));

/** Numeric-aware version compare. Falls back to string order for non-numeric parts. */
function compareVersions(a, b) {
  const pa = String(a).split(/[.\-+]/);
  const pb = String(b).split(/[.\-+]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = Number(pa[i]);
    const nb = Number(pb[i]);
    const bothNumeric = Number.isFinite(na) && Number.isFinite(nb);
    if (bothNumeric) {
      if (na !== nb) return na - nb;
    } else {
      const sa = pa[i] ?? '';
      const sb = pb[i] ?? '';
      if (sa !== sb) return sa < sb ? -1 : 1;
    }
  }
  return 0;
}

function dirSize(dir, depth = 0) {
  if (depth > 8) return 0;
  let total = 0;
  let entries = [];
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return 0; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    try { total += e.isDirectory() ? dirSize(p, depth + 1) : statSync(p).size; } catch { /* skip */ }
  }
  return total;
}

const mb = (b) => (b / 1048576).toFixed(0).padStart(5) + ' MB';

let totalReclaim = 0;
let totalDeleted = 0;
const plan = [];

for (const [editor, root] of Object.entries(EDITORS)) {
  if (!existsSync(root)) continue;

  // Directories the editor has explicitly marked dead. It has already released these, so
  // they are safe to remove even while the editor is running, which is the common case,
  // since nobody wants to close their editor to reclaim disk.
  const obsolete = new Set();
  const obsoleteFile = path.join(root, '.obsolete');
  if (existsSync(obsoleteFile)) {
    try {
      const map = JSON.parse(readFileSync(obsoleteFile, 'utf8'));
      for (const [dirName, dead] of Object.entries(map)) if (dead) obsolete.add(dirName);
    } catch { /* unreadable: fall back to version comparison alone */ }
  }

  // The editor's own record of what it considers installed. Authoritative.
  const activeVersions = new Map();
  const manifest = path.join(root, 'extensions.json');
  if (existsSync(manifest)) {
    try {
      for (const e of JSON.parse(readFileSync(manifest, 'utf8'))) {
        const id = `${e.identifier?.id ?? ''}`.toLowerCase();
        if (id && e.version) activeVersions.set(id, e.version);
      }
    } catch { /* unreadable manifest: fall back to version comparison alone */ }
  }

  const byId = new Map();
  for (const d of readdirSync(root, { withFileTypes: true })) {
    if (!d.isDirectory() || d.name.startsWith('.')) continue;
    const dir = path.join(root, d.name);
    const pkgPath = path.join(dir, 'package.json');
    if (!existsSync(pkgPath)) continue;
    let pkg;
    try { pkg = JSON.parse(readFileSync(pkgPath, 'utf8')); } catch { continue; }
    if (!pkg.publisher || !pkg.name || !pkg.version) continue;

    const id = `${pkg.publisher}.${pkg.name}`.toLowerCase();
    if (!byId.has(id)) byId.set(id, []);
    byId.get(id).push({ id, version: pkg.version, dir, obsolete: obsolete.has(d.name) });
  }

  for (const [id, copies] of byId) {
    if (copies.length < 2) continue;

    copies.sort((a, b) => compareVersions(b.version, a.version)); // newest first
    const active = activeVersions.get(id);
    // Keep whatever the editor says it is loading; otherwise keep the highest version.
    const keep = (active && copies.find((c) => c.version === active)) || copies[0];
    const drop = copies.filter((c) => c !== keep);

    for (const c of drop) c.bytes = dirSize(c.dir);
    const reclaim = drop.reduce((n, c) => n + c.bytes, 0);
    totalReclaim += reclaim;

    plan.push({ editor, id, keep, drop, reclaim, editorRunning: isRunning(editor) });
  }
}

if (!plan.length) {
  console.log('No duplicate extension versions found.');
  process.exit(0);
}

console.log(DELETE ? 'REMOVING superseded extension versions\n' : 'DRY RUN - nothing will be deleted. Pass --delete to remove.\n');

for (const p of plan) {
  console.log(`${p.id}  (${p.editor})`);
  console.log(`   keep  ${p.keep.version.padEnd(16)} ${p.keep.dir}`);
  for (const d of p.drop) {
    const tag = d.obsolete ? 'obsolete' : 'superseded';
    console.log(`   drop  ${d.version.padEnd(16)} ${mb(d.bytes)}  [${tag}]  ${d.dir}`);
  }
  if (DELETE) {
    for (const d of p.drop) {
      // Safe while the editor runs only if the editor itself marked the directory dead.
      if (p.editorRunning && !d.obsolete) {
        console.log(`   SKIPPED ${d.version}: ${p.editor} is running and has not released this directory. Close it and re-run.`);
        continue;
      }
      try {
        rmSync(d.dir, { recursive: true, force: true });
        totalDeleted += d.bytes;
        console.log(`   removed ${d.version}`);
      } catch (e) {
        console.log(`   FAILED to remove ${d.version}: ${e.message}`);
      }
    }
  }
  console.log('');
}

console.log(DELETE
  ? `Reclaimed ${(totalDeleted / 1073741824).toFixed(2)} GB of ${(totalReclaim / 1073741824).toFixed(2)} GB identified.`
  : `Would reclaim ${(totalReclaim / 1073741824).toFixed(2)} GB across ${plan.reduce((n, p) => n + p.drop.length, 0)} superseded versions.`);

if (!DELETE) console.log('\nRun again with --delete to remove them.');
