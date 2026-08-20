export interface PermissionAlert {
    type: 'workspaceTrust' | 'proposedApi' | 'activation' | 'tasks';
    severity: 'low' | 'medium' | 'high';
    message: string;
}

/**
 * Scans an extension's package.json content for potential permission risks.
 * @param packageJson The parsed package.json object
 */
export function scanPermissions(packageJson: any): PermissionAlert[] {
    const alerts: PermissionAlert[] = [];

    if (!packageJson) {
        return alerts;
    }

    // 1. Workspace Trust
    const untrustedWorkspaces = packageJson.capabilities?.untrustedWorkspaces;
    if (untrustedWorkspaces) {
        if (untrustedWorkspaces.supported === true) {
            alerts.push({
                type: 'workspaceTrust',
                severity: 'low',
                message: 'Runs in untrusted workspaces without restrictions (workspaceTrust.supported is true).'
            });
        }
    }

    // 2. Proposed APIs
    const proposedApis = packageJson.enabledApiProposals;
    if (Array.isArray(proposedApis) && proposedApis.length > 0) {
        alerts.push({
          type: 'proposedApi',
          severity: 'medium',
          message: `Uses proposed (unstable) VS Code APIs: ${proposedApis.join(', ')}.`
        });
    }

    // 3. Eager Activation
    const activationEvents = packageJson.activationEvents;
    if (Array.isArray(activationEvents)) {
        const eagerEvents = activationEvents.filter(e => e === '*' || e === 'onStartupFinished');
        if (eagerEvents.length > 0) {
            alerts.push({
                type: 'activation',
                severity: 'low',
                message: `Activates automatically on startup (eager events: ${eagerEvents.join(', ')}).`
            });
        }
    }

    // 4. Custom Task / Terminal contributions
    const taskDefinitions = packageJson.contributes?.taskDefinitions;
    if (taskDefinitions && Object.keys(taskDefinitions).length > 0) {
        alerts.push({
            type: 'tasks',
            severity: 'low',
            message: 'Registers custom tasks/terminal definitions which can execute shell operations.'
        });
    }

    return alerts;
}
