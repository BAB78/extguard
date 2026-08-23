import { buildTeamScanReport, hashMachineId, ReportableExtension } from './report';

describe('Team report privacy boundary', () => {
  test('hashes VS Code machine IDs deterministically into lowercase SHA-256', () => {
    const first = hashMachineId('raw-vscode-machine-id');
    const second = hashMachineId('raw-vscode-machine-id');

    expect(first).toBe(second);
    expect(first).toMatch(/^[a-f0-9]{64}$/);
    expect(first).not.toContain('raw-vscode-machine-id');
    expect(hashMachineId('another-machine')).not.toBe(first);
  });

  test('includes only fixed summaries and cannot serialize paths, values, or usernames', () => {
    const rawMachineId = 'raw-machine-id-must-never-leave-device';
    const source = {
      id: 'example.extension',
      name: 'Example Extension',
      riskScore: 9,
      malicious: true,
      removedFromMarketplace: true,
      truncated: true,
      permissionSeverities: ['high', 'low'],
      codeFindings: [
        {
          category: 'secret',
          severity: 'critical',
          file: 'C:\\Users\\private-user\\project\\token.ts',
          description: 'github_pat_DO_NOT_UPLOAD',
          value: 'sk_live_DO_NOT_UPLOAD',
        },
        { category: 'network', severity: 'medium', line: 99 },
      ],
      absolutePath: 'C:\\Users\\private-user',
      username: 'private-user',
    } as unknown as ReportableExtension;

    const report = buildTeamScanReport(hashMachineId(rawMachineId), new Date('2026-08-21T12:00:00.000Z'), [source]);
    const serialized = JSON.stringify(report);

    expect(report.summary).toEqual({
      extensionsScanned: 1,
      findings: 7,
      critical: 2,
      high: 2,
      medium: 1,
      low: 1,
      info: 1,
    });
    expect(report.extensions[0].findings).toEqual(expect.arrayContaining([
      { category: 'secret', severity: 'critical', count: 1 },
      { category: 'behavior', severity: 'medium', count: 1 },
    ]));
    for (const forbidden of [rawMachineId, 'C:\\Users', 'private-user', 'github_pat_DO_NOT_UPLOAD', 'sk_live_DO_NOT_UPLOAD']) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  test('rejects a raw or malformed machine identifier', () => {
    expect(() => buildTeamScanReport('raw-machine-id', new Date(), [])).toThrow(/SHA-256/i);
  });
});
