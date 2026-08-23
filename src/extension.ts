import * as vscode from 'vscode';
import { RiskTreeProvider } from './ui/riskSidebar';
import { scanVsixCommand, cleanDuplicatesCommand, showFeedInfoCommand } from './commands';
import { TeamController } from './team/teamController';
import type { TeamState } from './team/teamSession';

export function activate(context: vscode.ExtensionContext) {
    const team = new TeamController(context);
    context.subscriptions.push(team);
    const riskTreeProvider = new RiskTreeProvider(team);

    // 1.0.1 moved from the original Marketplace identity, babstudios.extguard, to
    // babstudios.extguard-security. VS Code treats those as two unrelated extensions and can
    // leave the original installed. The new IDs below deliberately do not collide with the
    // legacy build; this notice gives existing users a clear migration path instead of an
    // "command already exists" activation failure.
    const legacy = vscode.extensions.getExtension('babstudios.extguard');
    if (legacy && !context.globalState.get<boolean>('legacyMigrationNoticeShown')) {
        void context.globalState.update('legacyMigrationNoticeShown', true);
        void vscode.window.showWarningMessage(
            'ExtGuard Security detected the legacy "babstudios.extguard" extension. Uninstall the legacy copy to avoid duplicate shields and scans.',
            'Show Legacy Extension'
        ).then((choice) => {
            if (choice === 'Show Legacy Extension') {
                void vscode.commands.executeCommand('workbench.extensions.search', '@id:babstudios.extguard');
            }
        });
    }

    // Register Tree View
    const treeView = vscode.window.registerTreeDataProvider('extguard-security-risks', riskTreeProvider);
    context.subscriptions.push(treeView);

    // A status refresh must not clear scan results. Only meaningful, settled Team changes
    // redraw the sidebar; routine JWT rotation therefore cannot create a refresh/report loop.
    let lastTeamSignature = '';
    context.subscriptions.push(team.onDidChangeState((state) => {
        if (state.kind === 'checking') return;
        const signature = teamStateSignature(state);
        if (signature !== lastTeamSignature) {
            lastTeamSignature = signature;
            riskTreeProvider.refreshTeamState();
        }
    }));
    void team.initialize().catch((error: unknown) => {
        const message = error instanceof Error ? error.message : 'Unknown error.';
        void vscode.window.showWarningMessage(`ExtGuard Team status could not be initialized: ${message} Free local scanning is unaffected.`);
    });

    // Register Scan Command
    const scanCommand = vscode.commands.registerCommand('extguardSecurity.scan', () => {
        riskTreeProvider.refresh();
        vscode.window.showInformationMessage('ExtGuard: Scanning installed extensions...');
    });
    context.subscriptions.push(scanCommand);

    // Register Allowlist Publisher Command
    const allowlistCommand = vscode.commands.registerCommand('extguardSecurity.allowlistPublisher', async () => {
        const publisherInput = await vscode.window.showInputBox({
            prompt: 'Enter the publisher ID to allowlist (case-insensitive)',
            placeHolder: 'e.g. microsoft'
        });

        if (publisherInput) {
            const trimmed = publisherInput.trim();
            if (trimmed) {
                const config = vscode.workspace.getConfiguration('extguard');
                const allowed = config.get<string[]>('allowedPublishers') || [];
                
                if (!allowed.map(p => p.toLowerCase()).includes(trimmed.toLowerCase())) {
                    allowed.push(trimmed);
                    await config.update('allowedPublishers', allowed, vscode.ConfigurationTarget.Global);
                    vscode.window.showInformationMessage(`ExtGuard: Added publisher "${trimmed}" to the allowlist.`);
                    riskTreeProvider.refresh();
                } else {
                    vscode.window.showWarningMessage(`ExtGuard: Publisher "${trimmed}" is already on the allowlist.`);
                }
            }
        }
    });
    context.subscriptions.push(allowlistCommand);

    // Vet a .vsix before installing it. This is the only point where a user can act on a
    // finding without having already run the code.
    context.subscriptions.push(
        vscode.commands.registerCommand('extguardSecurity.scanVsix', scanVsixCommand)
    );

    // Superseded versions are never loaded but remain readable on disk.
    context.subscriptions.push(
        vscode.commands.registerCommand('extguardSecurity.cleanDuplicates', cleanDuplicatesCommand)
    );

    // Threat data ships bundled, so its age matters and should never be guessed at.
    context.subscriptions.push(
        vscode.commands.registerCommand('extguardSecurity.showFeedInfo', showFeedInfoCommand)
    );
}

export function deactivate() {}

function teamStateSignature(state: TeamState): string {
    if (state.kind === 'active') {
        return `${state.kind}:${state.entitlement.status}:${state.entitlement.activeSeats}:${state.entitlement.seats}:${state.entitlement.currentPeriodEnd ?? ''}`;
    }
    if (state.kind === 'inactive' || state.kind === 'unavailable') return `${state.kind}:${state.message}`;
    return state.kind;
}
