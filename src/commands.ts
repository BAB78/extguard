import * as vscode from 'vscode';
import * as os from 'os';
import * as path from 'path';
import { scanVsix } from './scanner/secretScanner';
import { findDuplicates, removeDuplicates, formatBytes, DuplicateGroup } from './scanner/duplicates';
import { feedInfo } from './scanner/threatFeed';

/**
 * User-facing commands beyond the scan itself.
 *
 * Two of these wire up code that already existed but had no way to reach it: scanning a .vsix
 * before installing, and reporting the age of the bundled threat data.
 */

/** Extension directories for every editor built on the VS Code API. */
export function extensionRoots(): Array<{ editor: string; root: string }> {
  const home = os.homedir();
  return [
    { editor: 'VS Code', root: path.join(home, '.vscode', 'extensions') },
    { editor: 'VS Code Insiders', root: path.join(home, '.vscode-insiders', 'extensions') },
    { editor: 'Cursor', root: path.join(home, '.cursor', 'extensions') },
    { editor: 'Windsurf', root: path.join(home, '.windsurf', 'extensions') },
    { editor: 'VSCodium', root: path.join(home, '.vscode-oss', 'extensions') },
  ];
}

/**
 * Vet a .vsix before it is ever installed.
 *
 * This is the only point at which a user can act on a finding without already having run the
 * code. Once an extension is installed and activated it has already had its chance.
 */
export async function scanVsixCommand(): Promise<void> {
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel: 'Scan for secrets and risky behaviour',
    filters: { 'VS Code extension': ['vsix'] },
  });
  if (!picked?.length) return;

  const file = picked[0].fsPath;
  const findings = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `ExtGuard: scanning ${path.basename(file)}` },
    async () => scanVsix(file)
  );

  if (!findings.length) {
    vscode.window.showInformationMessage(
      `ExtGuard: no secrets or risky behaviour found in ${path.basename(file)}. ` +
      'This means these checks found nothing, not that the extension is safe.'
    );
    return;
  }

  const doc = await vscode.workspace.openTextDocument({
    language: 'markdown',
    content: renderVsixReport(file, findings),
  });
  await vscode.window.showTextDocument(doc, { preview: false });
}

function renderVsixReport(file: string, findings: ReturnType<typeof scanVsix>): string {
  const bySeverity = { critical: 0, high: 0, medium: 0 } as Record<string, number>;
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;

  const lines = [
    `# ExtGuard: ${path.basename(file)}`,
    '',
    `${findings.length} finding(s): ${bySeverity.critical ?? 0} critical, ${bySeverity.high ?? 0} high, ${bySeverity.medium ?? 0} medium.`,
    '',
    '| Severity | Finding | Location |',
    '|---|---|---|',
  ];
  for (const f of findings) {
    lines.push(`| ${f.severity} | ${f.description} | \`${f.file}:${f.line}\` |`);
  }
  lines.push('', '_Medium findings describe capability, such as spawning a process, and are common in legitimate extensions. Critical and high findings point at credentials._');
  return lines.join('\n');
}

/**
 * Report and optionally remove stale extension versions.
 *
 * Superseded directories are never loaded, but they remain readable on disk. If a version is
 * later found malicious, that copy is still there.
 */
export async function cleanDuplicatesCommand(): Promise<void> {
  const groups: Array<DuplicateGroup & { editor: string }> = [];
  for (const { editor, root } of extensionRoots()) {
    for (const g of findDuplicates(root)) groups.push({ ...g, editor });
  }

  if (!groups.length) {
    vscode.window.showInformationMessage('ExtGuard: no stale extension versions found.');
    return;
  }

  const total = groups.reduce((n, g) => n + g.reclaimableBytes, 0);
  const copies = groups.reduce((n, g) => n + g.drop.length, 0);
  const detail = groups
    .slice(0, 8)
    .map((g) => `${g.id}: keeping ${g.keep.version}, removing ${g.drop.map((d) => d.version).join(', ')}`)
    .join('\n');

  const choice = await vscode.window.showWarningMessage(
    `ExtGuard found ${copies} superseded extension version(s) using ${formatBytes(total)}.`,
    { modal: true, detail: `${detail}${groups.length > 8 ? `\n...and ${groups.length - 8} more` : ''}\n\nThe newest version of each extension is always kept.` },
    'Delete superseded versions'
  );
  if (choice !== 'Delete superseded versions') return;

  const result = removeDuplicates(groups, { editorRunning: true });

  if (result.removed.length) {
    vscode.window.showInformationMessage(
      `ExtGuard reclaimed ${formatBytes(result.bytesReclaimed)} from ${result.removed.length} superseded version(s).`
    );
  }
  if (result.skipped.length) {
    vscode.window.showWarningMessage(
      `ExtGuard could not remove ${result.skipped.length} directory/directories. ` +
      'The editor has not released them yet; restart it and run the command again.'
    );
  }
}

/** Show how fresh the bundled threat data is, so nobody assumes it is current. */
export async function showFeedInfoCommand(): Promise<void> {
  const info = feedInfo();
  if (!info.loaded) {
    vscode.window.showErrorMessage(
      `ExtGuard: the threat database failed to load${info.error ? ` (${info.error})` : ''}. ` +
      'Malicious-extension checks are NOT running. Reinstall the extension.'
    );
    return;
  }

  const generated = info.generatedUtc ? new Date(info.generatedUtc) : null;
  const ageDays = generated ? Math.floor((Date.now() - generated.getTime()) / 86400000) : null;

  vscode.window.showInformationMessage(
    `ExtGuard threat data: ${info.counts.malicious.toLocaleString()} malicious records, ` +
    `${info.counts.publishers.toLocaleString()} blocked publishers` +
    (generated ? `, generated ${generated.toISOString().slice(0, 10)} (${ageDays} days ago).` : '.') +
    ' The database ships with the extension, so update ExtGuard to refresh it.'
  );
}
