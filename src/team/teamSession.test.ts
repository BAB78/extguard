import {
  LicensingApiError,
  TeamApi,
  TeamAuthResult,
  TeamReportResult,
  TeamScanReport,
} from './licensingClient';
import {
  SecretStore,
  TEAM_ACCESS_TOKEN_SECRET,
  TEAM_LICENSE_KEY_SECRET,
  TeamSession,
} from './teamSession';

const authResult: TeamAuthResult = {
  valid: true,
  accessToken: 'new-token',
  tokenExpiresAt: '2026-08-22T12:00:00.000Z',
  entitlement: {
    entitled: true,
    plan: 'team',
    status: 'active',
    seats: 3,
    activeSeats: 1,
    currentPeriodEnd: '2026-09-21T12:00:00.000Z',
  },
};

class MemorySecrets implements SecretStore {
  readonly values = new Map<string, string>();

  async get(key: string): Promise<string | undefined> {
    return this.values.get(key);
  }

  async store(key: string, value: string): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.values.delete(key);
  }
}

function mockApi(): jest.Mocked<TeamApi> {
  return {
    activate: jest.fn<Promise<TeamAuthResult>, [string, string]>(),
    validate: jest.fn<Promise<TeamAuthResult>, [string]>(),
    deactivate: jest.fn<Promise<void>, [string]>(),
    uploadReport: jest.fn<Promise<TeamReportResult>, [string, TeamScanReport]>(),
  };
}

describe('TeamSession', () => {
  test('keeps Free mode local and makes no API calls without stored credentials', async () => {
    const secrets = new MemorySecrets();
    const api = mockApi();
    const session = new TeamSession(secrets, () => api, 'raw-machine-id');

    await session.initialize();
    const uploaded = await session.uploadScan([]);

    expect(session.state.kind).toBe('free');
    expect(uploaded).toBe(false);
    expect(api.activate).not.toHaveBeenCalled();
    expect(api.validate).not.toHaveBeenCalled();
    expect(api.uploadReport).not.toHaveBeenCalled();
  });

  test('stores the license and token only through SecretStorage after activation', async () => {
    const secrets = new MemorySecrets();
    const api = mockApi();
    api.activate.mockResolvedValue(authResult);
    const session = new TeamSession(secrets, () => api, 'raw-machine-id');

    await session.activate('  license-secret  ');

    expect(api.activate).toHaveBeenCalledWith('license-secret', expect.stringMatching(/^[a-f0-9]{64}$/));
    expect(secrets.values.get(TEAM_LICENSE_KEY_SECRET)).toBe('license-secret');
    expect(secrets.values.get(TEAM_ACCESS_TOKEN_SECRET)).toBe('new-token');
    expect(session.state.kind).toBe('active');
  });

  test('renews an expired JWT with the securely stored license key', async () => {
    const secrets = new MemorySecrets();
    secrets.values.set(TEAM_LICENSE_KEY_SECRET, 'stored-license');
    secrets.values.set(TEAM_ACCESS_TOKEN_SECRET, 'expired-token');
    const api = mockApi();
    api.validate.mockRejectedValue(new LicensingApiError('Expired token.', 401, 'token_expired'));
    api.activate.mockResolvedValue(authResult);
    const session = new TeamSession(secrets, () => api, 'raw-machine-id');

    await session.initialize();

    expect(api.validate).toHaveBeenCalledWith('expired-token');
    expect(api.activate).toHaveBeenCalledWith('stored-license', session.machineId);
    expect(secrets.values.get(TEAM_ACCESS_TOKEN_SECRET)).toBe('new-token');
    expect(session.state.kind).toBe('active');
  });

  test('validates entitlement before uploading and never includes the raw machine ID', async () => {
    const secrets = new MemorySecrets();
    secrets.values.set(TEAM_LICENSE_KEY_SECRET, 'stored-license');
    secrets.values.set(TEAM_ACCESS_TOKEN_SECRET, 'old-token');
    const api = mockApi();
    api.validate.mockResolvedValue(authResult);
    api.uploadReport.mockResolvedValue({ id: 'report-1', acceptedAt: '2026-08-21T12:00:00.000Z' });
    const session = new TeamSession(secrets, () => api, 'raw-machine-id');

    const uploaded = await session.uploadScan([], new Date('2026-08-21T12:00:00.000Z'));

    expect(uploaded).toBe(true);
    expect(api.validate).toHaveBeenCalledWith('old-token');
    expect(api.uploadReport).toHaveBeenCalledWith('new-token', expect.objectContaining({ machineId: session.machineId }));
    expect(JSON.stringify(api.uploadReport.mock.calls[0][1])).not.toContain('raw-machine-id');
  });

  test('fails closed for reporting when entitlement cannot be verified', async () => {
    const secrets = new MemorySecrets();
    secrets.values.set(TEAM_ACCESS_TOKEN_SECRET, 'old-token');
    const api = mockApi();
    api.validate.mockRejectedValue(new LicensingApiError('Service unavailable.', 503, 'unavailable'));
    const session = new TeamSession(secrets, () => api, 'raw-machine-id');

    const uploaded = await session.uploadScan([]);

    expect(uploaded).toBe(false);
    expect(session.state.kind).toBe('unavailable');
    expect(api.uploadReport).not.toHaveBeenCalled();
  });

  test('deactivation clears both secrets only after the server accepts it', async () => {
    const secrets = new MemorySecrets();
    secrets.values.set(TEAM_LICENSE_KEY_SECRET, 'stored-license');
    secrets.values.set(TEAM_ACCESS_TOKEN_SECRET, 'signed-token');
    const api = mockApi();
    api.deactivate.mockResolvedValue(undefined);
    const session = new TeamSession(secrets, () => api, 'raw-machine-id');

    await session.deactivate();

    expect(api.deactivate).toHaveBeenCalledWith('signed-token');
    expect(secrets.values.size).toBe(0);
    expect(session.state.kind).toBe('free');
  });
});
