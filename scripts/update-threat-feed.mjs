#!/usr/bin/env node
/**
 * Regenerate the bundled threat snapshot from the VSXSentry feeds.
 *
 *   node scripts/update-threat-feed.mjs
 *
 * ExtGuard ships a snapshot so a first run works offline and before any network consent is
 * given. At runtime the extension may refresh it, but it must never *depend* on the network
 * to be useful.
 *
 * The malicious and risky feeds are kept strictly apart, and only the malicious one produces
 * findings. The risky feed is a capability catalogue, not a threat list: it contains GitLens,
 * Microsoft's PowerShell extension and Jupyter, because those execute code by design.
 * Treating it as a blocklist would flag a clean machine on first run.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const BASE = 'https://raw.githubusercontent.com/vsxsentry/vsxsentry.github.io/main/feeds/';
const OUT = path.join(path.dirname(path.dirname(fileURLToPath(import.meta.url))), 'src', 'scanner', 'data');

const get = async (file, asJson = false) => {
  const res = await fetch(BASE + file, { headers: { 'user-agent': 'extguard-feed-updater' } });
  if (!res.ok) throw new Error(`${file}: HTTP ${res.status}`);
  return asJson ? res.json() : res.text();
};

const idOf = (e) => String(e.extension_id || e.id || e.extensionId || '').toLowerCase();
const arrayOf = (j) => (Array.isArray(j) ? j : j.records || j.extensions || j.data || []);

console.log('fetching VSXSentry feeds...');
const [malRaw, riskyRaw, pubsRaw, statsRaw] = await Promise.all([
  get('vsxsentry_malicious_feed.json', true),
  get('vsxsentry_risky_feed.json', true),
  get('ioc_block_publishers.txt'),
  get('stats.json', true),
]);

const malicious = {};
for (const e of arrayOf(malRaw)) {
  const id = idOf(e);
  if (!id) continue;
  // Compact on purpose: this ships inside the .vsix, so store only what a finding needs.
  malicious[id] = {
    c: e.metadata_category || 'unknown',
    s: (e.metadata_severity || 'high').toLowerCase(),
    r: e.metadata_reference || '',
  };
}

const risky = {};
for (const e of arrayOf(riskyRaw)) {
  const id = idOf(e);
  if (!id) continue;
  risky[id] = {
    c: e.metadata_category || 'unknown',
    // The comment explains *why* the capability exists, which is what makes this
    // informational rather than accusatory in the UI.
    n: String(e.metadata_comment || '').slice(0, 160),
  };
}

const publishers = [...new Set(
  pubsRaw.split(/\r?\n/).map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith('#'))
)];

// A publisher blocked wholesale is meaningless if it is also a legitimate publisher of
// something on the risky list. Guard against the feeds disagreeing with each other.
const riskyPublishers = new Set(Object.keys(risky).map((id) => id.split('.')[0]));
const conflicts = publishers.filter((p) => riskyPublishers.has(p));
if (conflicts.length) {
  console.warn(`WARNING: ${conflicts.length} publisher(s) appear in both blocked and risky lists: ${conflicts.join(', ')}`);
}

const snapshot = {
  source: 'https://vsxsentry.github.io/',
  generatedUtc: statsRaw?.generated_utc || new Date().toISOString(),
  fetchedUtc: new Date().toISOString(),
  counts: {
    malicious: Object.keys(malicious).length,
    risky: Object.keys(risky).length,
    publishers: publishers.length,
  },
  malicious,
  risky,
  publishers,
};

mkdirSync(OUT, { recursive: true });
const file = path.join(OUT, 'threat-snapshot.json');
writeFileSync(file, JSON.stringify(snapshot));

const kb = (Buffer.byteLength(JSON.stringify(snapshot)) / 1024).toFixed(0);
console.log(`wrote ${path.relative(process.cwd(), file)}  ${kb} KB`);
console.log(`  malicious : ${snapshot.counts.malicious}`);
console.log(`  risky     : ${snapshot.counts.risky}  (informational only, never a finding)`);
console.log(`  publishers: ${snapshot.counts.publishers}`);
console.log(`  generated : ${snapshot.generatedUtc}`);
