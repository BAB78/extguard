#!/usr/bin/env node
/**
 * tsc emits JavaScript and nothing else, so the bundled threat snapshot never reaches out/.
 * Without this the packaged extension loads zero threat data and reports every machine clean,
 * which is the worst possible failure for a security tool: confidently wrong, silently.
 */
import { cpSync, existsSync, mkdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const assets = [['src/scanner/data', 'out/scanner/data']];

for (const [from, to] of assets) {
  const src = path.join(root, from);
  const dest = path.join(root, to);
  if (!existsSync(src)) {
    console.error(`missing asset: ${from}  (run: node scripts/update-threat-feed.mjs)`);
    process.exitCode = 1;
    continue;
  }
  mkdirSync(path.dirname(dest), { recursive: true });
  cpSync(src, dest, { recursive: true });
  const snap = path.join(dest, 'threat-snapshot.json');
  const kb = existsSync(snap) ? (statSync(snap).size / 1024).toFixed(0) + ' KB' : '';
  console.log(`copied ${from} -> ${to}  ${kb}`);
}
