import { Pool, PoolClient, QueryResultRow } from 'pg';
import {
  ActivationResult,
  AuthenticatedActivation,
  BillingWebhook,
  isPaidStatus,
  LicenseMaterial,
  LicenseRecord,
  ProvisionLicenseInput,
  ReportInput,
  ReportPage,
  StoredReport,
  SubscriptionStatus,
} from './domain';
import { Repository } from './repository';

function mapLicense(row: QueryResultRow): LicenseRecord {
  return {
    id: String(row.id),
    email: String(row.email),
    status: row.status as SubscriptionStatus,
    seats: Number(row.seats),
    activeSeats: Number(row.active_seats ?? 0),
    stripeCustomerId: String(row.stripe_customer_id),
    stripeSubscriptionId: String(row.stripe_subscription_id),
    stripeCheckoutSessionId: row.stripe_checkout_session_id
      ? String(row.stripe_checkout_session_id)
      : null,
    keyHash: String(row.license_key_hash),
    keyCiphertext: String(row.license_key_ciphertext),
    currentPeriodEnd: row.current_period_end ? new Date(row.current_period_end) : null,
  };
}

const licenseSelect = `
  SELECT l.*,
    (SELECT count(*)::int FROM activations a
      WHERE a.license_id = l.id AND a.deactivated_at IS NULL) AS active_seats
  FROM licenses l`;

export class PostgresRepository implements Repository {
  constructor(private readonly pool: Pool) {}

  async health(): Promise<void> {
    await this.pool.query('SELECT 1');
  }

  async provisionLicense(
    input: ProvisionLicenseInput,
    material: LicenseMaterial,
  ): Promise<LicenseRecord> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const licenseId = await this.upsertLicense(client, input, material);
      const result = await client.query(`${licenseSelect} WHERE l.id = $1`, [licenseId]);
      await client.query('COMMIT');
      const row = result.rows[0];
      if (!row) throw new Error('License provisioning did not return a row');
      return mapLicense(row);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async findLicenseByCheckoutSession(sessionId: string): Promise<LicenseRecord | null> {
    const result = await this.pool.query(
      `${licenseSelect} WHERE l.stripe_checkout_session_id = $1`,
      [sessionId],
    );
    return result.rows[0] ? mapLicense(result.rows[0]) : null;
  }

  async applyWebhook(webhook: BillingWebhook, material: LicenseMaterial): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const eventInsert = await client.query(
        `INSERT INTO stripe_events (stripe_event_id, event_type, stripe_created_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (stripe_event_id) DO NOTHING
         RETURNING stripe_event_id`,
        [webhook.id, webhook.type, webhook.createdAt],
      );
      if (eventInsert.rowCount === 0) {
        await client.query('ROLLBACK');
        return false;
      }

      if (webhook.mutation.kind === 'upsert') {
        await this.upsertLicense(client, webhook.mutation, material);
      } else if (webhook.mutation.kind === 'update') {
        const mutation = webhook.mutation;
        await client.query(
          `UPDATE licenses
             SET status = $2,
                 seats = COALESCE($3, seats),
                 current_period_end = CASE WHEN $4::boolean THEN $5 ELSE current_period_end END,
                 stripe_customer_id = COALESCE($6, stripe_customer_id),
                 updated_at = now()
           WHERE stripe_subscription_id = $1`,
          [
            mutation.stripeSubscriptionId,
            mutation.status,
            mutation.seats ?? null,
            mutation.currentPeriodEnd !== undefined,
            mutation.currentPeriodEnd ?? null,
            mutation.stripeCustomerId ?? null,
          ],
        );
      }

      await client.query('COMMIT');
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async activateLicense(keyHash: string, machineHash: string): Promise<ActivationResult> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const licenseResult = await client.query(
        'SELECT * FROM licenses WHERE license_key_hash = $1 FOR UPDATE',
        [keyHash],
      );
      const row = licenseResult.rows[0];
      if (!row) {
        await client.query('ROLLBACK');
        return { outcome: 'invalid' };
      }
      if (!isPaidStatus(row.status as SubscriptionStatus)) {
        await client.query('ROLLBACK');
        return { outcome: 'inactive' };
      }

      const existing = await client.query(
        `SELECT id, deactivated_at FROM activations
          WHERE license_id = $1 AND machine_id_hash = $2
          FOR UPDATE`,
        [row.id, machineHash],
      );
      let activationId: string;
      if (existing.rows[0]?.deactivated_at == null && existing.rows[0]) {
        activationId = String(existing.rows[0].id);
        await client.query(
          'UPDATE activations SET last_validated_at = now() WHERE id = $1',
          [activationId],
        );
      } else {
        const countResult = await client.query(
          `SELECT count(*)::int AS active_seats FROM activations
            WHERE license_id = $1 AND deactivated_at IS NULL`,
          [row.id],
        );
        if (Number(countResult.rows[0]?.active_seats ?? 0) >= Number(row.seats)) {
          await client.query('ROLLBACK');
          return { outcome: 'seat_limit' };
        }
        if (existing.rows[0]) {
          activationId = String(existing.rows[0].id);
          await client.query(
            `UPDATE activations
                SET deactivated_at = NULL, activated_at = now(), last_validated_at = now()
              WHERE id = $1`,
            [activationId],
          );
        } else {
          const inserted = await client.query(
            `INSERT INTO activations (license_id, machine_id_hash)
             VALUES ($1, $2)
             RETURNING id`,
            [row.id, machineHash],
          );
          activationId = String(inserted.rows[0]?.id);
        }
      }

      const hydrated = await client.query(`${licenseSelect} WHERE l.id = $1`, [row.id]);
      await client.query('COMMIT');
      return {
        outcome: 'ok',
        activationId,
        machineHash,
        license: mapLicense(hydrated.rows[0]),
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async getAuthenticatedActivation(
    licenseId: string,
    activationId: string,
    machineHash: string,
  ): Promise<AuthenticatedActivation | null> {
    const result = await this.pool.query(
      `${licenseSelect}
       JOIN activations auth_activation
         ON auth_activation.license_id = l.id
        AND auth_activation.id = $2
        AND auth_activation.machine_id_hash = $3
        AND auth_activation.deactivated_at IS NULL
       WHERE l.id = $1 AND l.status IN ('active', 'trialing')`,
      [licenseId, activationId, machineHash],
    );
    if (!result.rows[0]) return null;
    await this.pool.query(
      'UPDATE activations SET last_validated_at = now() WHERE id = $1',
      [activationId],
    );
    return { activationId, machineHash, license: mapLicense(result.rows[0]) };
  }

  async deactivateActivation(licenseId: string, activationId: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE activations SET deactivated_at = now()
        WHERE id = $1 AND license_id = $2 AND deactivated_at IS NULL`,
      [activationId, licenseId],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async createReport(auth: AuthenticatedActivation, input: ReportInput): Promise<StoredReport> {
    const result = await this.pool.query(
      `INSERT INTO reports
        (license_id, activation_id, schema_version, machine_id_hash, snapshot_at, payload)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)
       RETURNING id, created_at`,
      [
        auth.license.id,
        auth.activationId,
        input.schemaVersion,
        auth.machineHash,
        input.snapshotAt,
        JSON.stringify(input),
      ],
    );
    return {
      id: String(result.rows[0]?.id),
      ...input,
      receivedAt: new Date(result.rows[0]?.created_at).toISOString(),
    };
  }

  async listReports(licenseId: string, limit: number, cursor: string | null): Promise<ReportPage> {
    let cursorDate: Date | null = null;
    let cursorId: string | null = null;
    if (cursor) {
      try {
        const decoded = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as {
          at?: unknown;
          id?: unknown;
        };
        if (typeof decoded.at !== 'string' || typeof decoded.id !== 'string') throw new Error();
        cursorDate = new Date(decoded.at);
        if (Number.isNaN(cursorDate.getTime())) throw new Error();
        cursorId = decoded.id;
      } catch {
        throw new InvalidCursorError();
      }
    }

    const result = await this.pool.query(
      `SELECT id, payload, created_at
         FROM reports
        WHERE license_id = $1
          AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3::uuid))
        ORDER BY created_at DESC, id DESC
        LIMIT $4`,
      [licenseId, cursorDate, cursorId, limit + 1],
    );
    const hasMore = result.rows.length > limit;
    const pageRows = result.rows.slice(0, limit);
    const reports = pageRows.map((row) => ({
      id: String(row.id),
      ...(row.payload as ReportInput),
      receivedAt: new Date(row.created_at).toISOString(),
    }));
    const last = pageRows.at(-1);
    const nextCursor = hasMore && last
      ? Buffer.from(JSON.stringify({ at: new Date(last.created_at).toISOString(), id: last.id })).toString('base64url')
      : null;
    return { reports, nextCursor };
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  private async upsertLicense(
    client: PoolClient,
    input: ProvisionLicenseInput,
    material: LicenseMaterial,
  ): Promise<string> {
    const result = await client.query(
      `INSERT INTO licenses
        (email, status, seats, stripe_customer_id, stripe_subscription_id,
         stripe_checkout_session_id, license_key_hash, license_key_ciphertext, current_period_end)
       VALUES (lower($1), $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (stripe_subscription_id) DO UPDATE SET
         email = EXCLUDED.email,
         status = EXCLUDED.status,
         seats = EXCLUDED.seats,
         stripe_customer_id = EXCLUDED.stripe_customer_id,
         stripe_checkout_session_id = COALESCE(
           EXCLUDED.stripe_checkout_session_id,
           licenses.stripe_checkout_session_id
         ),
         current_period_end = EXCLUDED.current_period_end,
         updated_at = now()
       RETURNING id`,
      [
        input.email,
        input.status,
        input.seats,
        input.stripeCustomerId,
        input.stripeSubscriptionId,
        input.stripeCheckoutSessionId ?? null,
        material.keyHash,
        material.keyCiphertext,
        input.currentPeriodEnd,
      ],
    );
    const id = result.rows[0]?.id;
    if (!id) throw new Error('License upsert did not return an id');
    return String(id);
  }
}

export class InvalidCursorError extends Error {
  constructor() {
    super('Invalid report cursor');
    this.name = 'InvalidCursorError';
  }
}
