import * as fs from 'fs';
import * as path from 'path';

/**
 * Stale extension versions left on disk.
 *
 * When an extension updates, the editor leaves the previous directory behind and records it in
 * `.obsolete`. The old copy is never loaded, but it is still readable code: if that version is
 * later found malicious, it is still sitting there. On the development machine this accounted
 * for several gigabytes across three copies of one extension.
 *
 * Deliberately free of any `vscode` import so it can be tested against fixture directories.
 */

export interface ExtensionCopy {
  id: string;
  version: string;
  dir: string;
  /** The editor marked this directory dead in `.obsolete`, so it has released its handles. */
  obsolete: boolean;
  bytes: number;
}

export interface DuplicateGroup {
  id: string;
  /** The version to keep. Never proposed for deletion. */
  keep: ExtensionCopy;
  /** Superseded copies, safe to remove. */
  drop: ExtensionCopy[];
  reclaimableBytes: number;
}

/** Numeric-aware comparison. Falls back to string order for non-numeric segments. */
export function compareVersions(a: string, b: string): number {
  const pa = String(a).split(/[.\-+]/);
  const pb = String(b).split(/[.\-+]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = Number(pa[i]);
    const nb = Number(pb[i]);
    if (Number.isFinite(na) && Number.isFinite(nb)) {
      if (na !== nb) return na - nb;
    } else {
      const sa = pa[i] ?? '';
      const sb = pb[i] ?? '';
      if (sa !== sb) return sa < sb ? -1 : 1;
    }
  }
  return 0;
}

export function directorySize(dir: string, depth = 0): number {
  if (depth > 8) return 0;
  let total = 0;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return 0;
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    try {
      total += e.isDirectory() ? directorySize(p, depth + 1) : fs.statSync(p).size;
    } catch {
      // unreadable entry: skip
    }
  }
  return total;
}

/**
 * Find duplicate versions in one extensions root.
 *
 * The highest version is always kept, unless the editor's own `extensions.json` names a
 * different one as active, in which case the editor wins. It is the authority on what it
 * actually loads, and disagreeing with it risks deleting the live copy.
 */
export function findDuplicates(extensionsRoot: string): DuplicateGroup[] {
  if (!fs.existsSync(extensionsRoot)) return [];

  const obsolete = new Set<string>();
  const obsoleteFile = path.join(extensionsRoot, '.obsolete');
  if (fs.existsSync(obsoleteFile)) {
    try {
      const map = JSON.parse(fs.readFileSync(obsoleteFile, 'utf8')) as Record<string, boolean>;
      for (const [dirName, dead] of Object.entries(map)) if (dead) obsolete.add(dirName);
    } catch {
      // unreadable: fall back to version comparison alone
    }
  }

  const activeVersions = new Map<string, string>();
  const manifest = path.join(extensionsRoot, 'extensions.json');
  if (fs.existsSync(manifest)) {
    try {
      const list = JSON.parse(fs.readFileSync(manifest, 'utf8')) as Array<{ identifier?: { id?: string }; version?: string }>;
      for (const e of list) {
        const id = String(e.identifier?.id ?? '').toLowerCase();
        if (id && e.version) activeVersions.set(id, e.version);
      }
    } catch {
      // unreadable: fall back to version comparison alone
    }
  }

  const byId = new Map<string, ExtensionCopy[]>();
  let dirs: fs.Dirent[];
  try {
    dirs = fs.readdirSync(extensionsRoot, { withFileTypes: true });
  } catch {
    return [];
  }

  for (const d of dirs) {
    if (!d.isDirectory() || d.name.startsWith('.')) continue;
    const dir = path.join(extensionsRoot, d.name);
    const pkgPath = path.join(dir, 'package.json');
    if (!fs.existsSync(pkgPath)) continue;

    let pkg: { publisher?: string; name?: string; version?: string };
    try {
      pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    } catch {
      continue;
    }
    if (!pkg.publisher || !pkg.name || !pkg.version) continue;

    const id = `${pkg.publisher}.${pkg.name}`.toLowerCase();
    if (!byId.has(id)) byId.set(id, []);
    byId.get(id)!.push({ id, version: pkg.version, dir, obsolete: obsolete.has(d.name), bytes: 0 });
  }

  const groups: DuplicateGroup[] = [];
  for (const [id, copies] of byId) {
    if (copies.length < 2) continue;

    copies.sort((a, b) => compareVersions(b.version, a.version));
    const active = activeVersions.get(id);
    const keep = (active && copies.find((c) => c.version === active)) || copies[0];
    const drop = copies.filter((c) => c !== keep);
    for (const c of drop) c.bytes = directorySize(c.dir);

    groups.push({ id, keep, drop, reclaimableBytes: drop.reduce((n, c) => n + c.bytes, 0) });
  }

  groups.sort((a, b) => b.reclaimableBytes - a.reclaimableBytes);
  return groups;
}

export interface RemovalResult {
  removed: ExtensionCopy[];
  skipped: Array<{ copy: ExtensionCopy; reason: string }>;
  bytesReclaimed: number;
}

/**
 * Remove superseded copies.
 *
 * A copy is only removed when the editor has released it, which is what `.obsolete` records.
 * Deleting a directory the editor still holds open risks breaking a loaded extension, and the
 * few megabytes are not worth that.
 */
export function removeDuplicates(groups: DuplicateGroup[], opts: { editorRunning: boolean }): RemovalResult {
  const removed: ExtensionCopy[] = [];
  const skipped: Array<{ copy: ExtensionCopy; reason: string }> = [];
  let bytesReclaimed = 0;

  for (const group of groups) {
    for (const copy of group.drop) {
      if (opts.editorRunning && !copy.obsolete) {
        skipped.push({ copy, reason: 'the editor has not released this directory; restart and try again' });
        continue;
      }
      try {
        fs.rmSync(copy.dir, { recursive: true, force: true });
        removed.push(copy);
        bytesReclaimed += copy.bytes;
      } catch (err) {
        skipped.push({ copy, reason: err instanceof Error ? err.message : String(err) });
      }
    }
  }

  return { removed, skipped, bytesReclaimed };
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${Math.round(bytes / 1048576)} MB`;
  return `${Math.round(bytes / 1024)} KB`;
}
