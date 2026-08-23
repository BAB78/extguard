import type { TeamApi, TeamAuthResult, TeamEntitlement } from './licensingClient';
import { LicensingApiError } from './licensingClient';
import { buildTeamScanReport, hashMachineId, ReportableExtension } from './report';

export const TEAM_LICENSE_KEY_SECRET = 'extguard.team.licenseKey';
export const TEAM_ACCESS_TOKEN_SECRET = 'extguard.team.accessToken';

export interface SecretStore {
  get(key: string): PromiseLike<string | undefined>;
  store(key: string, value: string): PromiseLike<void>;
  delete(key: string): PromiseLike<void>;
}

export type TeamState =
  | { kind: 'checking' }
  | { kind: 'free' }
  | { kind: 'active'; entitlement: TeamEntitlement; checkedAt: string }
  | { kind: 'inactive'; message: string }
  | { kind: 'unavailable'; message: string };

export type TeamStateListener = (state: TeamState) => void;
export type TeamApiProvider = () => TeamApi;

export class TeamSession {
  private _state: TeamState = { kind: 'checking' };
  private readonly listeners = new Set<TeamStateListener>();
  private validationInFlight: Promise<boolean> | undefined;
  readonly machineId: string;

  constructor(
    private readonly secrets: SecretStore,
    private readonly apiProvider: TeamApiProvider,
    rawMachineId: string
  ) {
    this.machineId = hashMachineId(rawMachineId);
  }

  get state(): TeamState {
    return this._state;
  }

  onDidChangeState(listener: TeamStateListener): { dispose(): void } {
    this.listeners.add(listener);
    return { dispose: () => this.listeners.delete(listener) };
  }

  async initialize(): Promise<void> {
    await this.refresh();
  }

  async activate(licenseKey: string): Promise<TeamState> {
    const normalizedKey = licenseKey.trim();
    if (!normalizedKey) throw new Error('Enter an ExtGuard Team license key.');

    this.setState({ kind: 'checking' });
    try {
      const auth = await this.apiProvider().activate(normalizedKey, this.machineId);
      await this.secrets.store(TEAM_LICENSE_KEY_SECRET, normalizedKey);
      await this.secrets.store(TEAM_ACCESS_TOKEN_SECRET, auth.accessToken);
      return this.applyAuth(auth);
    } catch (error) {
      this.setFailure(error);
      throw error;
    }
  }

  async refresh(): Promise<TeamState> {
    this.setState({ kind: 'checking' });
    try {
      const entitled = await this.ensureEntitled();
      if (!entitled && this._state.kind === 'checking') this.setState({ kind: 'free' });
    } catch (error) {
      this.setFailure(error);
    }
    return this._state;
  }

  async deactivate(): Promise<void> {
    const accessToken = await this.secrets.get(TEAM_ACCESS_TOKEN_SECRET);
    if (!accessToken) {
      await this.clearCredentials();
      this.setState({ kind: 'free' });
      return;
    }

    this.setState({ kind: 'checking' });
    try {
      await this.apiProvider().deactivate(accessToken);
      await this.clearCredentials();
      this.setState({ kind: 'free' });
    } catch (error) {
      // An invalid token cannot identify an active local session. Clear it so it is never
      // reused; network failures retain both credentials so the user can retry deactivation.
      if (error instanceof LicensingApiError && error.isAuthenticationError) {
        await this.clearCredentials();
        this.setState({ kind: 'free' });
        return;
      }
      this.setFailure(error);
      throw error;
    }
  }

  /** Validate entitlement first; a Free or unverifiable session never reaches report upload. */
  async uploadScan(results: readonly ReportableExtension[], scannedAt = new Date()): Promise<boolean> {
    try {
      if (!await this.ensureEntitled()) return false;
    } catch (error) {
      this.setFailure(error);
      return false;
    }

    const token = await this.secrets.get(TEAM_ACCESS_TOKEN_SECRET);
    if (!token || this._state.kind !== 'active') return false;

    const report = buildTeamScanReport(this.machineId, scannedAt, results);
    try {
      await this.apiProvider().uploadReport(token, report);
      return true;
    } catch (error) {
      if (error instanceof LicensingApiError && error.isAuthenticationError) {
        if (!await this.renewWithLicenseKey()) return false;
        const renewedToken = await this.secrets.get(TEAM_ACCESS_TOKEN_SECRET);
        if (renewedToken && this._state.kind === 'active') {
          try {
            await this.apiProvider().uploadReport(renewedToken, report);
            return true;
          } catch (retryError) {
            this.setFailure(retryError);
            return false;
          }
        }
      }
      this.setFailure(error);
      return false;
    }
  }

  private async ensureEntitled(): Promise<boolean> {
    if (this.validationInFlight) return this.validationInFlight;
    this.validationInFlight = this.validateOrRenew();
    try {
      return await this.validationInFlight;
    } finally {
      this.validationInFlight = undefined;
    }
  }

  private async validateOrRenew(): Promise<boolean> {
    const accessToken = await this.secrets.get(TEAM_ACCESS_TOKEN_SECRET);
    if (!accessToken) return this.renewWithLicenseKey();

    try {
      const auth = await this.apiProvider().validate(accessToken);
      await this.secrets.store(TEAM_ACCESS_TOKEN_SECRET, auth.accessToken);
      this.applyAuth(auth);
      return true;
    } catch (error) {
      if (error instanceof LicensingApiError && error.isAuthenticationError) {
        await this.secrets.delete(TEAM_ACCESS_TOKEN_SECRET);
        return this.renewWithLicenseKey();
      }
      this.setFailure(error);
      return false;
    }
  }

  private async renewWithLicenseKey(): Promise<boolean> {
    const licenseKey = await this.secrets.get(TEAM_LICENSE_KEY_SECRET);
    if (!licenseKey) {
      this.setState({ kind: 'free' });
      return false;
    }

    try {
      const auth = await this.apiProvider().activate(licenseKey, this.machineId);
      await this.secrets.store(TEAM_ACCESS_TOKEN_SECRET, auth.accessToken);
      this.applyAuth(auth);
      return true;
    } catch (error) {
      if (error instanceof LicensingApiError && error.isAuthenticationError) {
        await this.secrets.delete(TEAM_ACCESS_TOKEN_SECRET);
      }
      this.setFailure(error);
      return false;
    }
  }

  private applyAuth(auth: TeamAuthResult): TeamState {
    const state: TeamState = {
      kind: 'active',
      entitlement: auth.entitlement,
      checkedAt: new Date().toISOString(),
    };
    this.setState(state);
    return state;
  }

  private setFailure(error: unknown): void {
    const message = error instanceof Error ? error.message : 'ExtGuard Team could not verify this device.';
    if (error instanceof LicensingApiError && (error.isAuthenticationError || error.code === 'seat_limit_reached')) {
      this.setState({ kind: 'inactive', message });
    } else {
      this.setState({ kind: 'unavailable', message });
    }
  }

  private async clearCredentials(): Promise<void> {
    await this.secrets.delete(TEAM_ACCESS_TOKEN_SECRET);
    await this.secrets.delete(TEAM_LICENSE_KEY_SECRET);
  }

  private setState(state: TeamState): void {
    this._state = state;
    for (const listener of this.listeners) listener(state);
  }
}
