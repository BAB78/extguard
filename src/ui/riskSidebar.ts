import * as vscode from 'vscode';
import * as fs from 'fs';
import { checkMalicious, checkCapability } from '../scanner/blocklistScanner';
import type { MaliciousMatch, CapabilityNote } from '../scanner/blocklistScanner';
import { scanPermissions, PermissionAlert } from '../scanner/permissionScanner';
import { scanDirectoryAsync, Finding } from '../scanner/secretScanner';
import { checkMarketplaceStatus, MarketplaceStatus } from '../scanner/marketplace';
import type { ReportableExtension } from '../team/report';
import type { TeamController } from '../team/teamController';
import type { TeamState } from '../team/teamSession';

export class RiskTreeProvider implements vscode.TreeDataProvider<RiskTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<RiskTreeItem | undefined | null | void> = new vscode.EventEmitter<RiskTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<RiskTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private cachedResults: Map<string, ExtensionAuditResult> = new Map();
    private isScanning = false;
    private marketplace: Map<string, MarketplaceStatus> = new Map();
    private scanRevision = 0;
    private lastReportedRevision = -1;

    constructor(private readonly team?: TeamController) {}

    refresh(): void {
        this.cachedResults.clear();
        this.scanRevision++;
        this._onDidChangeTreeData.fire();
    }

    refreshTeamState(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: RiskTreeItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: RiskTreeItem): Promise<RiskTreeItem[]> {
        if (this.isScanning) {
            return [];
        }

        if (!element) {
            // Root elements: Show all installed extensions
            this.isScanning = true;
            try {
                const extensions = vscode.extensions.all;
                const items: ExtensionItem[] = [];

                const allowedPublishers = vscode.workspace.getConfiguration('extguard').get<string[]>('allowedPublishers') || [];
                const allowedSet = new Set(allowedPublishers.map(p => p.toLowerCase()));

                const toScan = extensions.filter(e => !e.packageJSON.isBuiltin);

                // Opt-in, and the only network call in the product. One batched request for
                // every id rather than one per extension, so enabling it costs a single
                // round trip.
                const config = vscode.workspace.getConfiguration('extguard');
                if (config.get<boolean>('checkMarketplace')) {
                    try {
                        this.marketplace = await checkMarketplaceStatus(toScan.map(e => e.id));
                    } catch {
                        this.marketplace = new Map();
                    }
                } else {
                    this.marketplace = new Map();
                }

                // Scanning is I/O heavy and was previously synchronous, which froze the editor
                // for 27 seconds across 77 extensions (12.5 of those on dart-code alone).
                // Progress plus a cancellable, yielding scan keeps the window usable.
                await vscode.window.withProgress({
                    location: vscode.ProgressLocation.Window,
                    title: 'ExtGuard',
                    cancellable: true,
                }, async (progress, token) => {
                    let done = 0;
                    for (const ext of toScan) {
                        if (token.isCancellationRequested) break;

                        const allowed = allowedSet.has(ext.packageJSON.publisher.toLowerCase());
                        const cached = this.cachedResults.get(ext.id);
                        if (cached) {
                            items.push(new ExtensionItem(ext, cached, allowed));
                            done++;
                            continue;
                        }

                        progress.report({
                            message: `scanning ${++done}/${toScan.length}: ${ext.packageJSON.displayName || ext.id}`,
                        });

                        const result = await this.auditExtension(ext, token);
                        this.cachedResults.set(ext.id, result);
                        items.push(new ExtensionItem(ext, result, allowed));
                    }
                });

                // Sort: Highest risk score first, then name
                items.sort((a, b) => {
                    const scoreDiff = b.result.score - a.result.score;
                    if (scoreDiff !== 0) {
                        return scoreDiff;
                    }
                    return String(a.label ?? '').localeCompare(String(b.label ?? ''));
                });

                if (this.team && this.lastReportedRevision !== this.scanRevision) {
                    this.lastReportedRevision = this.scanRevision;
                    // Team reporting is deliberately downstream of the complete local scan.
                    // It is fire-and-forget so entitlement or network failures can never gate,
                    // delay, or weaken the free results rendered below.
                    void this.team.uploadScan(items.map(toReportableExtension)).catch(() => undefined);
                }

                return this.team ? [new TeamStatusItem(this.team.state), ...items] : items;
            } finally {
                this.isScanning = false;
            }
        } else if (element instanceof ExtensionItem) {
            // Child elements: Show findings
            return element.getFindingItems();
        }

        return [];
    }

    private async auditExtension(ext: vscode.Extension<any>, token?: vscode.CancellationToken): Promise<ExtensionAuditResult> {
        const id = ext.id;
        const packageJson = ext.packageJSON;
        const extPath = ext.extensionPath;

        const issues: string[] = [];
        const permissionAlerts = scanPermissions(packageJson);
        let codeFindings: Finding[] = [];

        // A confirmed match on the malicious feed. This is the only thing that alone justifies
        // the top of the scale.
        const malicious = checkMalicious(id);

        // Installed but no longer published means Microsoft removed it or the publisher
        // withdrew it. That is the strongest signal available and it comes from the first
        // party, so it catches threats the aggregated feeds have not seen yet.
        // 'unknown' is a failed lookup and must never be treated as removal: being offline
        // is not evidence against an extension.
        const market = this.marketplace.get(id);
        const removedFromMarketplace = market?.state === 'not-found';

        // Known high-capability extension (Jupyter, PowerShell, GitLens, an AI agent). This is
        // NOT a risk signal. It is the explanation the user needs for why something legitimate
        // has broad reach, and it must never contribute to the score.
        const capability = checkCapability(id);

        let truncated = false;
        if (fs.existsSync(extPath)) {
            const scan = await scanDirectoryAsync(extPath, undefined, token);
            codeFindings = scan.findings;
            truncated = scan.truncated;
        }

        // Scoring, 0 (clean) to 10 (confirmed malicious).
        //
        // Rebalanced after scanning 82 real extensions. Behaviour findings ("this file calls
        // child_process") previously scored 5, which put six ordinary extensions into the
        // Medium band for shipping build scripts. A tool that rates most of a clean machine
        // as mid-risk teaches the user that the rating means nothing.
        let score = 0;
        const raise = (n: number) => { score = Math.max(score, n); };

        if (malicious) {
            raise(10);
            issues.push(`On the malicious feed (${malicious.category})`);
        }

        if (removedFromMarketplace) {
            // The API cannot distinguish "removed by Microsoft" from "never published", so a
            // sideloaded or internal extension lands here too. Scored below a confirmed feed
            // match for that reason, and worded so it asks a question rather than making an
            // accusation the data does not support.
            raise(8);
            issues.push('Not currently published on the Marketplace');
        }

        for (const finding of codeFindings) {
            if (finding.category === 'secret') {
                // A real credential in shipped code is the strongest local signal there is.
                raise(finding.severity === 'critical' ? 9 : 7);
            } else if (finding.category === 'sensitive_file') {
                raise(7); // reading ~/.ssh or ~/.aws is not ordinary behaviour
            } else {
                raise(2); // process/network/eval: context, not an accusation
            }
        }

        for (const alert of permissionAlerts) {
            if (alert.severity === 'high') raise(6);
            else if (alert.severity === 'medium') raise(3);
            else raise(1);
        }

        if (truncated) {
            issues.push('Scan stopped early: this extension is larger than the per-extension budget, so the result is partial.');
        }

        return {
            id,
            score,
            malicious,
            capability,
            issues,
            truncated,
            marketplace: market,
            permissionAlerts,
            codeFindings
        };
    }
}

interface ExtensionAuditResult {
    id: string;
    score: number;
    malicious: MaliciousMatch | null;
    capability: CapabilityNote | null;
    issues: string[];
    truncated: boolean;
    marketplace?: MarketplaceStatus;
    permissionAlerts: PermissionAlert[];
    codeFindings: Finding[];
}

export type RiskTreeItem = TeamStatusItem | ExtensionItem | FindingItem;

class TeamStatusItem extends vscode.TreeItem {
    constructor(state: TeamState) {
        super(teamLabel(state), vscode.TreeItemCollapsibleState.None);
        this.command = {
            command: 'extguardSecurity.teamStatus',
            title: 'Show ExtGuard Team status',
        };
        this.contextValue = `extguardTeam.${state.kind}`;

        if (state.kind === 'active') {
            this.description = `${state.entitlement.activeSeats}/${state.entitlement.seats} seats`;
            this.tooltip = 'Team reporting is active. Click to validate entitlement or deactivate this device.';
            this.iconPath = new vscode.ThemeIcon('organization', new vscode.ThemeColor('testing.iconPassed'));
        } else if (state.kind === 'checking') {
            this.description = 'Checking entitlement';
            this.tooltip = 'Free local scanning remains available while Team entitlement is checked.';
            this.iconPath = new vscode.ThemeIcon('sync~spin');
        } else if (state.kind === 'free') {
            this.description = 'Local scanning active';
            this.tooltip = 'ExtGuard Free local scanning is active. Click to activate Team reporting.';
            this.iconPath = new vscode.ThemeIcon('shield');
        } else {
            this.description = state.kind === 'inactive' ? 'Activation required' : 'Could not verify';
            this.tooltip = `${state.message} Free local scanning remains available.`;
            this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        }
    }
}

class ExtensionItem extends vscode.TreeItem {
    constructor(
        public readonly extension: vscode.Extension<any>,
        public readonly result: ExtensionAuditResult,
        public readonly isAllowed: boolean
    ) {
        super(
            extension.packageJSON.displayName || extension.packageJSON.name,
            (result.malicious || result.capability || result.permissionAlerts.length > 0 || result.codeFindings.length > 0) && !isAllowed
                ? vscode.TreeItemCollapsibleState.Collapsed
                : vscode.TreeItemCollapsibleState.None
        );

        const score = isAllowed ? 0 : result.score;
        this.tooltip = `${this.label} (${extension.id})\nPublisher: ${extension.packageJSON.publisher}\nRisk Score: ${score}/10`;
        
        let severity = 'Safe';
        if (score >= 9) {
            severity = 'Critical';
            this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('problemsErrorIcon.foreground'));
        } else if (score >= 7) {
            severity = 'High';
            this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        } else if (score >= 4) {
            severity = 'Medium';
            this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        } else if (score >= 1) {
            severity = 'Low';
            this.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('problemsInfoIcon.foreground'));
        } else {
            this.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
        }

        this.description = isAllowed ? `[Allowlisted] (Score: 0/10)` : `(Score: ${score}/10 - ${severity})`;
    }

    getFindingItems(): FindingItem[] {
        if (this.isAllowed) {
            return [];
        }

        const items: FindingItem[] = [];

        if (this.result.truncated) {
            items.push(new FindingItem(
                'Partial scan',
                'info',
                'This extension exceeded the scan budget, so absence of findings is not evidence of absence.'
            ));
        }

        const market = this.result.marketplace;
        if (market?.state === 'not-found') {
            items.push(new FindingItem(
                'Not on the Marketplace',
                'high',
                'Either removed by Microsoft, withdrawn by its publisher, or installed from a .vsix and never published. Expected for internal and sideloaded extensions.'
            ));
        } else if (market?.state === 'published' && market.publisherVerified === false) {
            items.push(new FindingItem(
                'Publisher domain not verified',
                'info',
                `${market.publisherDisplayName ?? 'Publisher'} has not verified a domain. Common for small publishers and not a problem on its own.`
            ));
        }

        if (this.result.malicious) {
            const m = this.result.malicious;
            items.push(new FindingItem(
                `Known malicious: ${m.category}`,
                'critical',
                m.publisherBlocked ? 'Publisher is blocked wholesale' : (m.reference || 'Listed on the public malicious feed')
            ));
        }

        // Rendered as information, deliberately not as a finding severity, so a legitimate
        // high-capability extension does not look like a problem.
        if (this.result.capability) {
            items.push(new FindingItem(
                `Capability: ${this.result.capability.category}`,
                'info',
                this.result.capability.note || 'Broad capability by design, not a defect'
            ));
        }

        for (const alert of this.result.permissionAlerts) {
            items.push(new FindingItem(`Perm: ${alert.message}`, alert.severity, 'Manifest Alert'));
        }

        for (const finding of this.result.codeFindings) {
            items.push(new FindingItem(
                `Code: ${finding.description}`,
                finding.severity,
                `${finding.file}:${finding.line}`
            ));
        }

        return items;
    }
}

class FindingItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical',
        public readonly detail: string
    ) {
        super(label, vscode.TreeItemCollapsibleState.None);
        this.description = detail;
        this.tooltip = `${label}\nSeverity: ${severity}\nDetail: ${detail}`;

        // 'info' is not a severity: it marks a row that explains something rather than
        // reporting a problem, so a legitimate high-capability extension is not dressed
        // up as a defect.
        if (severity === 'info') {
            this.iconPath = new vscode.ThemeIcon('lightbulb', new vscode.ThemeColor('descriptionForeground'));
        } else if (severity === 'critical') {
            this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('problemsErrorIcon.foreground'));
        } else if (severity === 'high') {
            this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        } else if (severity === 'medium') {
            this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        } else {
            this.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('problemsInfoIcon.foreground'));
        }
    }
}

function teamLabel(state: TeamState): string {
    if (state.kind === 'active') return 'ExtGuard Team';
    if (state.kind === 'checking') return 'ExtGuard Team';
    if (state.kind === 'free') return 'ExtGuard Free';
    return 'ExtGuard Team inactive';
}

function toReportableExtension(item: ExtensionItem): ReportableExtension {
    const allowed = item.isAllowed;
    return {
        id: item.extension.id,
        name: item.extension.packageJSON.displayName || item.extension.packageJSON.name || item.extension.id,
        riskScore: allowed ? 0 : item.result.score,
        malicious: !allowed && Boolean(item.result.malicious),
        removedFromMarketplace: !allowed && item.result.marketplace?.state === 'not-found',
        truncated: !allowed && item.result.truncated,
        permissionSeverities: allowed ? [] : item.result.permissionAlerts.map((finding) => finding.severity),
        codeFindings: allowed ? [] : item.result.codeFindings.map((finding) => ({
            category: finding.category,
            severity: finding.severity,
        })),
    };
}
