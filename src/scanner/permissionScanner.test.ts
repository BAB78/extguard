import { scanPermissions } from './permissionScanner';

describe('permissionScanner', () => {
    describe('scanPermissions', () => {
        it('should return empty array for null/undefined input', () => {
            expect(scanPermissions(null)).toEqual([]);
            expect(scanPermissions(undefined)).toEqual([]);
        });

        it('should return empty array for a minimal safe package.json', () => {
            const pkg = {
                name: 'safe-extension',
                version: '1.0.0',
                publisher: 'trusted-dev'
            };
            expect(scanPermissions(pkg)).toEqual([]);
        });

        it('should flag untrusted workspace support', () => {
            const pkg = {
                name: 'workspace-ext',
                capabilities: {
                    untrustedWorkspaces: { supported: true }
                }
            };
            const alerts = scanPermissions(pkg);
            expect(alerts).toHaveLength(1);
            expect(alerts[0].type).toBe('workspaceTrust');
            expect(alerts[0].severity).toBe('low');
        });

        it('should NOT flag when untrustedWorkspaces.supported is false', () => {
            const pkg = {
                capabilities: {
                    untrustedWorkspaces: { supported: false }
                }
            };
            const alerts = scanPermissions(pkg);
            const workspaceTrustAlerts = alerts.filter(a => a.type === 'workspaceTrust');
            expect(workspaceTrustAlerts).toHaveLength(0);
        });

        it('should flag proposed API usage', () => {
            const pkg = {
                enabledApiProposals: ['fileSearchProvider', 'textSearchProvider']
            };
            const alerts = scanPermissions(pkg);
            expect(alerts).toHaveLength(1);
            expect(alerts[0].type).toBe('proposedApi');
            expect(alerts[0].severity).toBe('medium');
            expect(alerts[0].message).toContain('fileSearchProvider');
            expect(alerts[0].message).toContain('textSearchProvider');
        });

        it('should NOT flag empty proposed API list', () => {
            const pkg = {
                enabledApiProposals: []
            };
            expect(scanPermissions(pkg)).toEqual([]);
        });

        it('should flag wildcard activation event', () => {
            const pkg = {
                activationEvents: ['*']
            };
            const alerts = scanPermissions(pkg);
            expect(alerts).toHaveLength(1);
            expect(alerts[0].type).toBe('activation');
            expect(alerts[0].severity).toBe('low');
            expect(alerts[0].message).toContain('*');
        });

        it('should flag onStartupFinished activation event', () => {
            const pkg = {
                activationEvents: ['onStartupFinished']
            };
            const alerts = scanPermissions(pkg);
            expect(alerts).toHaveLength(1);
            expect(alerts[0].type).toBe('activation');
        });

        it('should NOT flag normal activation events like onCommand', () => {
            const pkg = {
                activationEvents: ['onCommand:myExtension.start', 'onLanguage:python']
            };
            expect(scanPermissions(pkg)).toEqual([]);
        });

        it('should flag custom task definitions', () => {
            const pkg = {
                contributes: {
                    taskDefinitions: [
                        { type: 'myBuild', required: ['command'] }
                    ]
                }
            };
            const alerts = scanPermissions(pkg);
            expect(alerts).toHaveLength(1);
            expect(alerts[0].type).toBe('tasks');
            expect(alerts[0].severity).toBe('low');
        });

        it('should detect multiple issues simultaneously', () => {
            const pkg = {
                capabilities: {
                    untrustedWorkspaces: { supported: true }
                },
                enabledApiProposals: ['terminalDataWriteEvent'],
                activationEvents: ['*'],
                contributes: {
                    taskDefinitions: [{ type: 'shell' }]
                }
            };
            const alerts = scanPermissions(pkg);
            expect(alerts).toHaveLength(4);
            const types = alerts.map(a => a.type);
            expect(types).toContain('workspaceTrust');
            expect(types).toContain('proposedApi');
            expect(types).toContain('activation');
            expect(types).toContain('tasks');
        });

        it('should handle missing nested properties gracefully', () => {
            const pkg = {
                capabilities: {},
                contributes: {}
            };
            expect(scanPermissions(pkg)).toEqual([]);
        });
    });
});
