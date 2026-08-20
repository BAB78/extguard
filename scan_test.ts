/**
 * ExtGuard Phase 3: Real Extension Scan Test
 * Runs the scanner against all installed VS Code extensions
 * and outputs a report of findings.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { scanPermissions } from './src/scanner/permissionScanner';
import { scanDirectory } from './src/scanner/secretScanner';
import { isBlocklisted } from './src/scanner/blocklistScanner';

const extensionsDir = path.join(os.homedir(), '.vscode', 'extensions');

interface ScanResult {
    id: string;
    score: number;
    permissionAlerts: number;
    codeFindings: number;
    topIssues: string[];
}

const results: ScanResult[] = [];

try {
    const dirs = fs.readdirSync(extensionsDir).filter(d => {
        const full = path.join(extensionsDir, d);
        return fs.statSync(full).isDirectory() && !d.startsWith('.');
    });

    console.log(`Scanning ${dirs.length} extensions...\n`);

    for (const dir of dirs) {
        const extPath = path.join(extensionsDir, dir);
        const pkgPath = path.join(extPath, 'package.json');

        let score = 0;
        const topIssues: string[] = [];
        let permCount = 0;
        let codeCount = 0;

        // Check blocklist
        if (isBlocklisted(dir)) {
            score = 10;
            topIssues.push('BLOCKLISTED');
        }

        // Scan manifest
        if (fs.existsSync(pkgPath)) {
            try {
                const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
                const alerts = scanPermissions(pkg);
                permCount = alerts.length;
                for (const a of alerts) {
                    if (a.severity === 'high') score = Math.max(score, 7);
                    else if (a.severity === 'medium') score = Math.max(score, 4);
                    else if (a.severity === 'low') score = Math.max(score, 2);
                    topIssues.push(`[PERM] ${a.message}`);
                }
            } catch {}
        }

        // Scan code (limit to first 100 findings to avoid slowness)
        const findings = scanDirectory(extPath);
        codeCount = findings.length;
        for (const f of findings.slice(0, 5)) {
            if (f.severity === 'critical') score = Math.max(score, 9);
            else if (f.severity === 'high') score = Math.max(score, 7);
            else if (f.severity === 'medium') score = Math.max(score, 5);
            topIssues.push(`[CODE:${f.severity}] ${f.description} (${f.file}:${f.line})`);
        }
        // Ensure score reflects remaining findings too
        for (const f of findings.slice(5)) {
            if (f.severity === 'critical') score = Math.max(score, 9);
            else if (f.severity === 'high') score = Math.max(score, 7);
            else if (f.severity === 'medium') score = Math.max(score, 5);
        }

        results.push({ id: dir, score, permissionAlerts: permCount, codeFindings: codeCount, topIssues });
    }

    // Sort by score descending
    results.sort((a, b) => b.score - a.score);

    // Output report
    console.log('='.repeat(80));
    console.log('EXTGUARD SCAN REPORT');
    console.log('='.repeat(80));
    console.log(`Total extensions scanned: ${results.length}\n`);

    const critical = results.filter(r => r.score >= 9);
    const high = results.filter(r => r.score >= 7 && r.score < 9);
    const medium = results.filter(r => r.score >= 4 && r.score < 7);
    const low = results.filter(r => r.score >= 1 && r.score < 4);
    const safe = results.filter(r => r.score === 0);

    console.log(`Critical (9-10): ${critical.length}`);
    console.log(`High (7-8):      ${high.length}`);
    console.log(`Medium (4-6):    ${medium.length}`);
    console.log(`Low (1-3):       ${low.length}`);
    console.log(`Safe (0):        ${safe.length}`);
    console.log('');

    // Print top 20 riskiest
    console.log('-'.repeat(80));
    console.log('TOP FINDINGS (score > 0):');
    console.log('-'.repeat(80));

    for (const r of results.filter(r => r.score > 0).slice(0, 25)) {
        console.log(`\n[Score: ${r.score}/10] ${r.id}`);
        console.log(`  Permissions: ${r.permissionAlerts} alerts | Code: ${r.codeFindings} findings`);
        for (const issue of r.topIssues.slice(0, 3)) {
            console.log(`  → ${issue}`);
        }
    }

} catch (err) {
    console.error('Scan failed:', err);
}
