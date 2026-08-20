#!/usr/bin/env node
/**
 * Release preflight. Fails loudly on the mistakes that are expensive after publishing rather
 * than before: a placeholder publisher ID that becomes permanent, a missing threat snapshot
 * that would make the extension report every machine clean, and stale threat data.
 *
 *   node scripts/preflight.mjs
 */
import { readFileSync, existsSync, statSync } from 'node:fs';

const fail = [];
const warn = [];

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));

const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
const lockRoot = lock.packages?.[''];
if (lockRoot?.name !== pkg.name || lockRoot?.version !== pkg.version) {
  fail.push(`package-lock root is ${lockRoot?.name}@${lockRoot?.version}, but package.json is ${pkg.name}@${pkg.version}.`);
}

if (!pkg.publisher || pkg.publisher === 'extguard-team') {
  fail.push(`publisher is "${pkg.publisher}", which is a placeholder. It becomes permanent on first publish. Register a real publisher ID first.`);
}
if (!pkg.icon || !existsSync(pkg.icon)) fail.push('icon is missing; the Marketplace requires a PNG.');
if (!pkg.repository?.url) warn.push('no repository URL, so relative links in README will break on the listing page.');
if (!existsSync('LICENSE')) fail.push('LICENSE is missing even though package.json declares a license.');
if (!existsSync('CHANGELOG.md')) fail.push('CHANGELOG.md is missing.');

if (pkg.repository?.url) {
  const publicRepositoryUrl = pkg.repository.url
    .replace(/^git\+/, '')
    .replace(/\.git$/, '');
  try {
    const response = await fetch(publicRepositoryUrl, {
      method: 'HEAD',
      redirect: 'follow',
      headers: { 'user-agent': 'ExtGuard-release-preflight' },
    });
    if (response.status === 404) {
      fail.push(`repository URL returns 404 (${publicRepositoryUrl}); README images and security links will be broken on the Marketplace.`);
    } else if (!response.ok) {
      warn.push(`could not verify repository URL: HTTP ${response.status} from ${publicRepositoryUrl}.`);
    }
  } catch (error) {
    warn.push(`could not verify repository URL (${publicRepositoryUrl}): ${error.message}`);
  }
}

for (const screenshot of [
  'media/screenshots/01-extension-overview.png',
  'media/screenshots/02-finding-with-file-line.png',
  'media/screenshots/03-capability-explained.png',
]) {
  if (!existsSync(screenshot)) fail.push(`Marketplace screenshot is missing: ${screenshot}`);
}

// The 1.0.0 Marketplace identity used these IDs. If both Marketplace identities are
// installed, reusing them makes one extension fail activation with "command already exists".
const contributedCommands = (pkg.contributes?.commands || []).map((entry) => entry.command);
if (contributedCommands.some((id) => id.startsWith('extguard.'))) {
  fail.push('a command still uses the legacy extguard.* namespace and will collide with babstudios.extguard.');
}
const containers = Object.keys(pkg.contributes?.views || {});
const views = Object.values(pkg.contributes?.views || {}).flat().map((entry) => entry.id);
if (containers.includes('extguard-sidebar') || views.includes('extguard-risks')) {
  fail.push('a view still uses the legacy ExtGuard ID and will collide with babstudios.extguard.');
}

const landing = readFileSync('landing/index.html', 'utf8');
const marketplaceId = `${pkg.publisher}.${pkg.name}`;
if (!landing.includes(`itemName=${marketplaceId}`) || landing.includes('itemName=extguard.extguard')) {
  fail.push(`landing page does not point at the current Marketplace identity (${marketplaceId}).`);
}

const snapPath = 'src/scanner/data/threat-snapshot.json';
if (!existsSync(snapPath)) {
  fail.push('threat snapshot missing. Run: npm run feed');
} else {
  const snap = JSON.parse(readFileSync(snapPath, 'utf8'));
  if (!snap.counts?.malicious) {
    fail.push('threat snapshot contains no malicious records, so every machine would report clean.');
  }
  const ageDays = (Date.now() - Date.parse(snap.generatedUtc)) / 86400000;
  if (Number.isFinite(ageDays) && ageDays > 14) {
    warn.push(`threat data is ${Math.round(ageDays)} days old. Run: npm run feed`);
  }
  // The built copy is what actually ships.
  const outSnap = 'out/scanner/data/threat-snapshot.json';
  if (!existsSync(outSnap)) fail.push('out/ has no threat snapshot. Run: npm run compile');
  else if (statSync(outSnap).size !== statSync(snapPath).size) warn.push('out/ snapshot differs from src/. Run: npm run compile');
}

for (const w of warn) console.log(`WARN  ${w}`);
for (const f of fail) console.log(`FAIL  ${f}`);

if (fail.length) {
  console.log(`\n${fail.length} blocker(s). Not safe to publish.`);
  process.exitCode = 1;
} else {
  console.log(`\nPreflight passed${warn.length ? ` with ${warn.length} warning(s)` : ''}. Safe to publish.`);
}
