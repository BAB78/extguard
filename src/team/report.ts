import { createHash } from 'crypto';
import type {
  TeamExtensionSummary,
  TeamFindingCategory,
  TeamFindingSeverity,
  TeamFindingSummary,
  TeamScanReport,
} from './licensingClient';

const MACHINE_ID_DOMAIN = 'extguard-team-machine-id:v1\0';

export interface ReportableCodeFinding {
  category: 'secret' | 'process' | 'network' | 'dynamic_eval' | 'sensitive_file';
  severity: 'medium' | 'high' | 'critical';
}

export interface ReportableExtension {
  id: string;
  name: string;
  riskScore: number;
  malicious: boolean;
  removedFromMarketplace: boolean;
  truncated: boolean;
  permissionSeverities: ReadonlyArray<'low' | 'medium' | 'high'>;
  codeFindings: ReadonlyArray<ReportableCodeFinding>;
}

/** Derive a stable, product-scoped identifier without transmitting VS Code's raw machine ID. */
export function hashMachineId(rawMachineId: string): string {
  if (!rawMachineId) throw new Error('VS Code did not provide a machine identifier.');
  return createHash('sha256').update(MACHINE_ID_DOMAIN, 'utf8').update(rawMachineId, 'utf8').digest('hex');
}

/**
 * Build the only scan data shape that may cross the network.
 *
 * The input intentionally cannot carry source snippets, matched secret values, file paths,
 * publishers, or usernames. Findings are reduced to fixed category/severity counters here,
 * before the licensing service sees the report.
 */
export function buildTeamScanReport(
  machineId: string,
  scannedAt: Date,
  results: readonly ReportableExtension[]
): TeamScanReport {
  if (!/^[a-f0-9]{64}$/.test(machineId)) {
    throw new Error('Team reports require a SHA-256 machine identifier.');
  }

  const totals: Record<TeamFindingSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let findings = 0;

  const extensions: TeamExtensionSummary[] = results.map((result) => {
    const grouped = new Map<string, TeamFindingSummary>();
    const add = (category: TeamFindingCategory, severity: TeamFindingSeverity): void => {
      const key = `${category}:${severity}`;
      const existing = grouped.get(key);
      if (existing) existing.count++;
      else grouped.set(key, { category, severity, count: 1 });
      totals[severity]++;
      findings++;
    };

    if (result.malicious) add('malicious', 'critical');
    if (result.removedFromMarketplace) add('marketplace', 'high');
    if (result.truncated) add('partial', 'info');
    for (const severity of result.permissionSeverities) add('permission', severity);
    for (const finding of result.codeFindings) add(reportCategory(finding.category), finding.severity);

    return {
      id: cleanLabel(result.id),
      name: cleanLabel(result.name),
      riskScore: Math.max(0, Math.min(10, Math.round(result.riskScore))),
      findings: [...grouped.values()],
    };
  });

  return {
    schemaVersion: 1,
    machineId,
    snapshotAt: scannedAt.toISOString(),
    summary: {
      extensionsScanned: extensions.length,
      findings,
      critical: totals.critical,
      high: totals.high,
      medium: totals.medium,
      low: totals.low,
      info: totals.info,
    },
    extensions,
  };
}

function reportCategory(category: ReportableCodeFinding['category']): TeamFindingCategory {
  if (category === 'secret') return 'secret';
  if (category === 'sensitive_file') return 'sensitive_file';
  return 'behavior';
}

function cleanLabel(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 200);
}
