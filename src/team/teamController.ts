import * as vscode from 'vscode';
import { LicensingClient, normalizeApiBaseUrl } from './licensingClient';
import type { ReportableExtension } from './report';
import { TeamSession, TeamState } from './teamSession';

export const TEAM_API_BASE_URL_SETTING = 'team.apiBaseUrl';
export const ACTIVATE_TEAM_COMMAND = 'extguardSecurity.activateTeam';
export const DEACTIVATE_TEAM_COMMAND = 'extguardSecurity.deactivateTeam';
export const TEAM_STATUS_COMMAND = 'extguardSecurity.teamStatus';

export class TeamController implements vscode.Disposable {
  readonly session: TeamSession;
  private readonly statusBar: vscode.StatusBarItem;
  private readonly disposables: vscode.Disposable[] = [];

  constructor(context: vscode.ExtensionContext) {
    this.session = new TeamSession(
      context.secrets,
      () => new LicensingClient(this.apiBaseUrl()),
      vscode.env.machineId
    );

    this.statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 90);
    this.statusBar.command = TEAM_STATUS_COMMAND;
    this.statusBar.name = 'ExtGuard Team status';
    this.renderStatus(this.session.state);
    this.statusBar.show();

    this.disposables.push(
      this.statusBar,
      this.session.onDidChangeState((state) => this.renderStatus(state)),
      vscode.commands.registerCommand(ACTIVATE_TEAM_COMMAND, () => this.activateTeam()),
      vscode.commands.registerCommand(DEACTIVATE_TEAM_COMMAND, () => this.deactivateTeam()),
      vscode.commands.registerCommand(TEAM_STATUS_COMMAND, () => this.showTeamStatus()),
      vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration(`extguard.${TEAM_API_BASE_URL_SETTING}`)) {
          void this.session.refresh();
        }
      })
    );
  }

  get state(): TeamState {
    return this.session.state;
  }

  async initialize(): Promise<void> {
    await this.session.initialize();
  }

  async uploadScan(results: readonly ReportableExtension[], scannedAt?: Date): Promise<boolean> {
    return this.session.uploadScan(results, scannedAt);
  }

  onDidChangeState(listener: (state: TeamState) => void): vscode.Disposable {
    return this.session.onDidChangeState(listener);
  }

  dispose(): void {
    for (const disposable of this.disposables) disposable.dispose();
  }

  private async activateTeam(): Promise<void> {
    try {
      normalizeApiBaseUrl(this.apiBaseUrl());
    } catch (error) {
      const choice = await vscode.window.showWarningMessage(
        `${errorMessage(error)} Free local scanning remains available.`,
        'Team Settings'
      );
      if (choice === 'Team Settings') await vscode.commands.executeCommand('workbench.action.openSettings', 'extguard.team.apiBaseUrl');
      return;
    }

    const licenseKey = await vscode.window.showInputBox({
      title: 'Activate ExtGuard Team',
      prompt: 'Enter your Team license key. While Team is active, each completed scan automatically uploads a privacy-minimized summary. Local scanning stays free.',
      placeHolder: 'ExtGuard Team license key',
      password: true,
      ignoreFocusOut: true,
      validateInput: (value) => value.trim() ? undefined : 'Enter a license key.',
    });
    if (licenseKey === undefined) return;

    try {
      const state = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'ExtGuard: activating Team…' },
        () => this.session.activate(licenseKey)
      );
      if (state.kind === 'active') {
        void vscode.window.showInformationMessage(
          `ExtGuard Team is active on this device (${state.entitlement.activeSeats}/${state.entitlement.seats} seats in use).`
        );
      }
    } catch (error) {
      void vscode.window.showErrorMessage(`ExtGuard Team activation failed: ${errorMessage(error)}`);
    }
  }

  private async deactivateTeam(): Promise<void> {
    const choice = await vscode.window.showWarningMessage(
      'Deactivate ExtGuard Team on this device? Free local scanning will continue.',
      { modal: true },
      'Deactivate Team'
    );
    if (choice !== 'Deactivate Team') return;

    try {
      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'ExtGuard: deactivating Team…' },
        () => this.session.deactivate()
      );
      void vscode.window.showInformationMessage('ExtGuard Team was deactivated on this device. Free local scanning is still available.');
    } catch (error) {
      void vscode.window.showErrorMessage(`ExtGuard Team deactivation failed: ${errorMessage(error)}`);
    }
  }

  private async showTeamStatus(): Promise<void> {
    const state = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: 'ExtGuard: checking Team status' },
      () => this.session.refresh()
    );

    if (state.kind === 'active') {
      const period = state.entitlement.currentPeriodEnd
        ? ` Current period ends ${new Date(state.entitlement.currentPeriodEnd).toLocaleDateString()}.`
        : '';
      const choice = await vscode.window.showInformationMessage(
        `ExtGuard Team is ${state.entitlement.status} (${state.entitlement.activeSeats}/${state.entitlement.seats} seats in use).${period}`,
        'Deactivate This Device'
      );
      if (choice === 'Deactivate This Device') await vscode.commands.executeCommand(DEACTIVATE_TEAM_COMMAND);
      return;
    }

    const message = state.kind === 'free'
      ? 'ExtGuard Free is active. Local extension scanning is fully available.'
      : `ExtGuard Team is not active: ${state.kind === 'checking' ? 'status is still being checked.' : state.message} Free local scanning remains available.`;
    const choice = state.kind === 'unavailable'
      ? await vscode.window.showWarningMessage(message, 'Activate Team', 'Team Settings')
      : await vscode.window.showInformationMessage(message, 'Activate Team', 'Team Settings');
    if (choice === 'Activate Team') await vscode.commands.executeCommand(ACTIVATE_TEAM_COMMAND);
    if (choice === 'Team Settings') await vscode.commands.executeCommand('workbench.action.openSettings', 'extguard.team');
  }

  private renderStatus(state: TeamState): void {
    if (state.kind === 'active') {
      this.statusBar.text = '$(organization) ExtGuard Team';
      this.statusBar.tooltip = `Team ${state.entitlement.status}; ${state.entitlement.activeSeats}/${state.entitlement.seats} seats. Click to refresh status.`;
      this.statusBar.backgroundColor = undefined;
      return;
    }
    if (state.kind === 'checking') {
      this.statusBar.text = '$(sync~spin) ExtGuard Team';
      this.statusBar.tooltip = 'Checking Team entitlement. Free local scanning remains available.';
      this.statusBar.backgroundColor = undefined;
      return;
    }
    if (state.kind === 'free') {
      this.statusBar.text = '$(shield) ExtGuard Free';
      this.statusBar.tooltip = 'Free local scanning is active. Click to activate or inspect Team status.';
      this.statusBar.backgroundColor = undefined;
      return;
    }

    this.statusBar.text = '$(warning) ExtGuard Team';
    this.statusBar.tooltip = `${state.message} Free local scanning remains available.`;
    this.statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  }

  private apiBaseUrl(): string {
    return vscode.workspace.getConfiguration('extguard').get<string>(TEAM_API_BASE_URL_SETTING, '');
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unknown error.';
}
