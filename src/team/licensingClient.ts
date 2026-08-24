import * as http from 'http';
import * as https from 'https';

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

export type EntitlementStatus =
  | 'active'
  | 'trialing';

export interface TeamEntitlement {
  entitled: true;
  status: EntitlementStatus;
  plan: 'team';
  seats: number;
  activeSeats: number;
  currentPeriodEnd: string | null;
}

export interface TeamAuthResult {
  valid: true;
  accessToken: string;
  tokenExpiresAt: string;
  entitlement: TeamEntitlement;
}

export type TeamFindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type TeamFindingCategory =
  | 'malicious'
  | 'marketplace'
  | 'permission'
  | 'secret'
  | 'sensitive_file'
  | 'behavior'
  | 'partial';

export interface TeamFindingSummary {
  category: TeamFindingCategory;
  severity: TeamFindingSeverity;
  count: number;
}

export interface TeamExtensionSummary {
  id: string;
  name: string;
  riskScore: number;
  findings: TeamFindingSummary[];
}

export interface TeamScanReport {
  schemaVersion: 1;
  machineId: string;
  snapshotAt: string;
  summary: {
    extensionsScanned: number;
    findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  extensions: TeamExtensionSummary[];
}

export interface TeamReportResult {
  id: string;
  acceptedAt: string;
}

export interface HttpRequest {
  method: 'POST';
  url: string;
  headers: Readonly<Record<string, string>>;
  body: string;
}

export interface HttpResponse {
  status: number;
  body: string;
}

export type HttpTransport = (request: HttpRequest) => Promise<HttpResponse>;

export interface TeamApi {
  activate(licenseKey: string, machineId: string): Promise<TeamAuthResult>;
  validate(accessToken: string): Promise<TeamAuthResult>;
  deactivate(accessToken: string): Promise<void>;
  uploadReport(accessToken: string, report: TeamScanReport): Promise<TeamReportResult>;
}

export class LicensingApiError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly code?: string
  ) {
    super(message);
    this.name = 'LicensingApiError';
  }

  get isAuthenticationError(): boolean {
    return this.status === 401 || this.status === 403;
  }
}

/**
 * Validate and normalize the configured service URL.
 *
 * Team traffic must be encrypted. Plain HTTP is accepted only for an exact loopback host so
 * developers can run the API locally without weakening production configuration.
 */
export function normalizeApiBaseUrl(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new LicensingApiError('Set extguard.team.apiBaseUrl before using ExtGuard Team.', undefined, 'invalid_api_url');
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new LicensingApiError('The ExtGuard Team API URL is not valid.', undefined, 'invalid_api_url');
  }

  const isLoopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopback)) {
    throw new LicensingApiError(
      'The ExtGuard Team API must use HTTPS (plain HTTP is allowed only on localhost).',
      undefined,
      'insecure_api_url'
    );
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new LicensingApiError(
      'The ExtGuard Team API URL cannot contain credentials, a query, or a fragment.',
      undefined,
      'invalid_api_url'
    );
  }

  return parsed.toString().replace(/\/$/, '');
}

export class LicensingClient implements TeamApi {
  private readonly baseUrl: string;

  constructor(apiBaseUrl: string, private readonly transport: HttpTransport = nodeHttpTransport) {
    this.baseUrl = normalizeApiBaseUrl(apiBaseUrl);
  }

  async activate(licenseKey: string, machineId: string): Promise<TeamAuthResult> {
    const payload = await this.post('/api/v1/licenses/activate', { licenseKey, machineId });
    return parseAuthResult(payload);
  }

  async validate(accessToken: string): Promise<TeamAuthResult> {
    const payload = await this.post('/api/v1/licenses/validate', {}, accessToken);
    return parseAuthResult(payload, 'validation');
  }

  async deactivate(accessToken: string): Promise<void> {
    await this.post('/api/v1/licenses/deactivate', {}, accessToken);
  }

  async uploadReport(accessToken: string, report: TeamScanReport): Promise<TeamReportResult> {
    const payload = await this.post('/api/v1/reports', report, accessToken);
    const record = asRecord(payload, 'The Team API returned an invalid report response.');
    return {
      id: requiredString(record.id, 'The Team API report response did not include an id.'),
      acceptedAt: requiredString(record.acceptedAt, 'The Team API report response did not include an acceptance time.'),
    };
  }

  private async post(path: string, body: unknown, accessToken?: string): Promise<unknown> {
    const serialized = JSON.stringify(body);
    const headers: Record<string, string> = {
      accept: 'application/json',
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(serialized)),
    };
    if (accessToken) headers.authorization = `Bearer ${accessToken}`;

    let response: HttpResponse;
    try {
      response = await this.transport({
        method: 'POST',
        url: `${this.baseUrl}${path}`,
        headers,
        body: serialized,
      });
    } catch (error) {
      if (error instanceof LicensingApiError) throw error;
      throw new LicensingApiError(
        error instanceof Error ? `Could not reach the ExtGuard Team API: ${error.message}` : 'Could not reach the ExtGuard Team API.',
        undefined,
        'network_error'
      );
    }

    const payload = parseJson(response.body);
    if (response.status < 200 || response.status >= 300) {
      const record = isRecord(payload) ? payload : undefined;
      const nestedError = isRecord(record?.error) ? record.error : undefined;
      const message = optionalString(nestedError?.message) ?? `ExtGuard Team request failed (${response.status}).`;
      throw new LicensingApiError(message.slice(0, 300), response.status, optionalString(nestedError?.code));
    }
    return payload;
  }
}

export const nodeHttpTransport: HttpTransport = async (request) => new Promise<HttpResponse>((resolve, reject) => {
  const url = new URL(request.url);
  const adapter = url.protocol === 'https:' ? https : http;
  const outgoing = adapter.request(url, {
    method: request.method,
    headers: request.headers,
  }, (incoming) => {
    const chunks: Buffer[] = [];
    let bytes = 0;

    incoming.on('data', (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.length;
      if (bytes > MAX_RESPONSE_BYTES) {
        outgoing.destroy(new Error('The ExtGuard Team API response was too large.'));
        return;
      }
      chunks.push(buffer);
    });
    incoming.on('end', () => {
      resolve({
        status: incoming.statusCode ?? 0,
        body: Buffer.concat(chunks).toString('utf8'),
      });
    });
  });

  outgoing.setTimeout(DEFAULT_TIMEOUT_MS, () => {
    outgoing.destroy(new Error('The ExtGuard Team API request timed out.'));
  });
  outgoing.on('error', reject);
  outgoing.end(request.body);
});

function parseAuthResult(value: unknown, operation = 'activation'): TeamAuthResult {
  const record = asRecord(value, `The Team API returned an invalid ${operation} response.`);
  if (record.valid !== true) {
    throw new LicensingApiError(`The Team API returned an invalid ${operation} response.`, undefined, 'invalid_response');
  }
  const accessToken = requiredString(record.accessToken, `The Team API ${operation} response did not include an access token.`);
  return {
    valid: true,
    accessToken,
    tokenExpiresAt: requiredString(record.tokenExpiresAt, `The Team API ${operation} response did not include a token expiry.`),
    entitlement: parseEntitlement(record.entitlement),
  };
}

function parseEntitlement(value: unknown): TeamEntitlement {
  const record = asRecord(value, 'The Team API returned an invalid entitlement.');
  const status = requiredString(record.status, 'The Team API entitlement has no status.') as EntitlementStatus;
  const allowedStatuses: readonly string[] = ['active', 'trialing'];
  if (!allowedStatuses.includes(status)) {
    throw new LicensingApiError('The Team API returned an unknown entitlement status.', undefined, 'invalid_response');
  }

  const seats = record.seats;
  const activeSeats = record.activeSeats;
  if (!Number.isInteger(seats) || (seats as number) < 1 || !Number.isInteger(activeSeats) || (activeSeats as number) < 0) {
    throw new LicensingApiError('The Team API returned an invalid seat count.', undefined, 'invalid_response');
  }
  if (record.plan !== 'team') {
    throw new LicensingApiError('The Team API returned an unknown plan.', undefined, 'invalid_response');
  }
  const currentPeriodEnd = record.currentPeriodEnd;
  if (currentPeriodEnd !== null && typeof currentPeriodEnd !== 'string') {
    throw new LicensingApiError('The Team API returned an invalid subscription period.', undefined, 'invalid_response');
  }

  return {
    entitled: true,
    status,
    plan: 'team',
    seats: seats as number,
    activeSeats: activeSeats as number,
    currentPeriodEnd,
  };
}

function parseJson(body: string): unknown {
  if (!body) return {};
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new LicensingApiError('The Team API returned malformed JSON.', undefined, 'invalid_response');
  }
}

function asRecord(value: unknown, message: string): Record<string, unknown> {
  if (!isRecord(value)) throw new LicensingApiError(message, undefined, 'invalid_response');
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requiredString(value: unknown, message: string): string {
  if (typeof value !== 'string' || !value) {
    throw new LicensingApiError(message, undefined, 'invalid_response');
  }
  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value ? value : undefined;
}
