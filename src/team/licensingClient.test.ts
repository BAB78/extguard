import {
  HttpRequest,
  HttpTransport,
  LicensingApiError,
  LicensingClient,
  normalizeApiBaseUrl,
  TeamScanReport,
} from './licensingClient';

const activeResponse = {
  valid: true,
  accessToken: 'signed-jwt',
  tokenExpiresAt: '2026-08-22T12:00:00.000Z',
  entitlement: {
    plan: 'team',
    status: 'active',
    seats: 5,
    activeSeats: 2,
    currentPeriodEnd: '2026-09-21T12:00:00.000Z',
  },
};

describe('normalizeApiBaseUrl', () => {
  test('requires HTTPS for remote services', () => {
    expect(normalizeApiBaseUrl('https://api.extguard.dev/')).toBe('https://api.extguard.dev');
    expect(() => normalizeApiBaseUrl('http://api.extguard.dev')).toThrow(/must use HTTPS/i);
  });

  test.each(['http://localhost:3000', 'http://127.0.0.1:3000', 'http://[::1]:3000'])(
    'allows exact loopback development URL %s',
    (url) => expect(normalizeApiBaseUrl(url)).toBe(url)
  );

  test('rejects lookalikes, embedded credentials, queries, and fragments', () => {
    expect(() => normalizeApiBaseUrl('http://localhost.example.com')).toThrow(/must use HTTPS/i);
    expect(() => normalizeApiBaseUrl('https://user:password@api.extguard.dev')).toThrow(/cannot contain/i);
    expect(() => normalizeApiBaseUrl('https://api.extguard.dev?token=value')).toThrow(/cannot contain/i);
    expect(() => normalizeApiBaseUrl('https://api.extguard.dev/#fragment')).toThrow(/cannot contain/i);
  });
});

describe('LicensingClient', () => {
  test('activates with only the license key and hashed machine ID', async () => {
    const requests: HttpRequest[] = [];
    const transport: HttpTransport = async (request) => {
      requests.push(request);
      return { status: 200, body: JSON.stringify(activeResponse) };
    };
    const client = new LicensingClient('https://api.extguard.dev', transport);

    const result = await client.activate('license-secret', 'a'.repeat(64));

    expect(result.accessToken).toBe('signed-jwt');
    expect(requests).toHaveLength(1);
    expect(requests[0].url).toBe('https://api.extguard.dev/api/v1/licenses/activate');
    expect(requests[0].headers.authorization).toBeUndefined();
    expect(JSON.parse(requests[0].body)).toEqual({ licenseKey: 'license-secret', machineId: 'a'.repeat(64) });
  });

  test('validates with Bearer auth, an empty body, and accepts the rotated token', async () => {
    let request: HttpRequest | undefined;
    const client = new LicensingClient('https://api.extguard.dev', async (value) => {
      request = value;
      return { status: 200, body: JSON.stringify({ ...activeResponse, accessToken: 'rotated-jwt' }) };
    });

    const result = await client.validate('old-jwt');

    expect(result.accessToken).toBe('rotated-jwt');
    expect(request?.url).toBe('https://api.extguard.dev/api/v1/licenses/validate');
    expect(request?.headers.authorization).toBe('Bearer old-jwt');
    expect(request?.body).toBe('{}');
  });

  test('deactivates with Bearer auth and no license in the URL or body', async () => {
    let request: HttpRequest | undefined;
    const client = new LicensingClient('https://api.extguard.dev', async (value) => {
      request = value;
      return { status: 200, body: JSON.stringify({ success: true }) };
    });

    await client.deactivate('signed-jwt');

    expect(request?.url).toBe('https://api.extguard.dev/api/v1/licenses/deactivate');
    expect(request?.headers.authorization).toBe('Bearer signed-jwt');
    expect(request?.body).toBe('{}');
  });

  test('uploads the approved report shape with Bearer auth', async () => {
    let request: HttpRequest | undefined;
    const client = new LicensingClient('https://api.extguard.dev', async (value) => {
      request = value;
      return { status: 201, body: JSON.stringify({ id: 'report-1', acceptedAt: '2026-08-21T12:00:00.000Z' }) };
    });
    const report: TeamScanReport = {
      schemaVersion: 1,
      machineId: 'b'.repeat(64),
      snapshotAt: '2026-08-21T12:00:00.000Z',
      summary: { extensionsScanned: 0, findings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      extensions: [],
    };

    const response = await client.uploadReport('signed-jwt', report);

    expect(response.id).toBe('report-1');
    expect(request?.url).toBe('https://api.extguard.dev/api/v1/reports');
    expect(request?.headers.authorization).toBe('Bearer signed-jwt');
    expect(JSON.parse(request?.body ?? '{}')).toEqual(report);
  });

  test('surfaces structured API errors without exposing the request secret', async () => {
    const client = new LicensingClient('https://api.extguard.dev', async () => ({
      status: 409,
      body: JSON.stringify({ error: { code: 'seat_limit_reached', message: 'No Team seats are available.' } }),
    }));

    await expect(client.activate('never-echo-this-key', 'c'.repeat(64))).rejects.toMatchObject<Partial<LicensingApiError>>({
      status: 409,
      code: 'seat_limit_reached',
      message: 'No Team seats are available.',
    });
  });
});
