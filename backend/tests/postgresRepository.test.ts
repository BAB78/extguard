import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { promisify } from 'node:util';
import EmbeddedPostgres from 'embedded-postgres';
import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BillingWebhook, LicenseMaterial, ProvisionLicenseInput } from '../src/domain';
import { PostgresRepository } from '../src/postgresRepository';

/**
 * These tests exercise the real SQL against a real PostgreSQL cluster.
 *
 * The suite in app.test.ts runs against MemoryRepository, which means the row locking, the
 * ON CONFLICT replay guard and the seat accounting in postgresRepository.ts were previously
 * only ever verified by reading them. Those are exactly the parts where being wrong costs
 * money: a seat limit that does not hold under concurrency sells one licence to a whole team,
 * and a webhook that is not idempotent reissues licence keys on Stripe automatic retries.
 */

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(__dirname, '..');
const PORT = 54329;
const DATA_DIR = path.join(ROOT, '.pgdata-test');
const DATABASE_URL = `postgresql://postgres:postgres@127.0.0.1:${PORT}/extguard_test`;

let postgres: EmbeddedPostgres;
let pool: Pool;
let repository: PostgresRepository;

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');
const machine = (label: string): string => sha256(`machine:${label}`);

function licenseMaterial(label: string): LicenseMaterial {
  return { keyHash: sha256(`key:${label}`), keyCiphertext: `v1.${label}` };
}

function provisionInput(label: string, seats: number): ProvisionLicenseInput {
  const suffix = label.replace(/[^a-z0-9]/gi, '').slice(0, 20);
  return {
    email: `${suffix}@example.com`.toLowerCase(),
    status: 'active',
    seats,
    stripeCustomerId: `cus_${suffix}`,
    stripeSubscriptionId: `sub_${suffix}`,
    stripeCheckoutSessionId: `cs_test_${suffix}`,
    currentPeriodEnd: new Date('2030-01-01T00:00:00.000Z'),
  };
}

async function runMigrations(): Promise<string> {
  const { stdout } = await execFileAsync(process.execPath, [path.join(ROOT, 'dist', 'migrate.js')], {
    env: { ...process.env, DATABASE_URL, DATABASE_SSL: 'false' },
    cwd: ROOT,
  });
  return stdout;
}

beforeAll(async () => {
  postgres = new EmbeddedPostgres({
    databaseDir: DATA_DIR,
    user: 'postgres',
    password: 'postgres',
    port: PORT,
    persistent: false,
  });
  await postgres.initialise();
  await postgres.start();
  await postgres.createDatabase('extguard_test');

  // Compile first so the migration runner under test is the same file the container executes.
  await execFileAsync('npm', ['run', 'build'], { cwd: ROOT, shell: true });

  pool = new Pool({ connectionString: DATABASE_URL, max: 10 });
  repository = new PostgresRepository(pool);
}, 300_000);

afterAll(async () => {
  await pool?.end();
  await postgres?.stop();
});

describe('migration runner', () => {
  it('applies the schema and stays idempotent when the container restarts', async () => {
    const first = await runMigrations();
    expect(first).toContain('migrations.complete');

    // The Dockerfile CMD runs migrate on every boot, so a second run must be a no-op rather
    // than a crash loop. Railway restarts on failure up to five times before giving up.
    const second = await runMigrations();
    expect(second).toContain('migrations.complete');

    const applied = await pool.query('SELECT filename FROM extguard_schema_migrations');
    expect(applied.rows).toHaveLength(1);
    await expect(repository.health()).resolves.toBeUndefined();
  }, 120_000);

  it('refuses to run when an already-applied migration has been edited', async () => {
    const { rows } = await pool.query(
      `SELECT checksum FROM extguard_schema_migrations WHERE filename = '001_initial.sql'`,
    );
    const realChecksum = String(rows[0].checksum);

    await pool.query(
      `UPDATE extguard_schema_migrations SET checksum = $1 WHERE filename = '001_initial.sql'`,
      ['0'.repeat(64)],
    );

    const output = await runMigrations().then(
      (stdout) => stdout,
      (error: { stdout?: string; stderr?: string }) => `${error.stdout ?? ''}${error.stderr ?? ''}`,
    );
    expect(output).toContain('migrations.failed');
    expect(output).not.toContain('migrations.complete');

    // Restore the genuine checksum rather than clearing the row. Deleting the tracking record
    // would make the runner replay 001_initial.sql over tables that already exist, which fails
    // for an entirely different reason and would hide a regression in this check.
    await pool.query(
      `UPDATE extguard_schema_migrations SET checksum = $1 WHERE filename = '001_initial.sql'`,
      [realChecksum],
    );
    expect(await runMigrations()).toContain('migrations.complete');
  }, 120_000);
});

describe('licence provisioning and webhook replay', () => {
  it('provisions a licence that is retrievable by checkout session', async () => {
    const input = provisionInput('provision', 3);
    const license = await repository.provisionLicense(input, licenseMaterial('provision'));
    expect(license.seats).toBe(3);
    expect(license.activeSeats).toBe(0);
    expect(license.status).toBe('active');

    const found = await repository.findLicenseByCheckoutSession(input.stripeCheckoutSessionId!);
    expect(found?.id).toBe(license.id);
  });

  it('processes a webhook once and ignores Stripe retries of the same event', async () => {
    const webhook: BillingWebhook = {
      id: `evt_${randomUUID().replace(/-/g, '')}`,
      type: 'checkout.session.completed',
      createdAt: new Date(),
      mutation: { kind: 'upsert', ...provisionInput('replay', 2) },
    };

    expect(await repository.applyWebhook(webhook, licenseMaterial('replay'))).toBe(true);
    // Stripe retries until it gets a 2xx, so the same event id arrives more than once.
    expect(await repository.applyWebhook(webhook, licenseMaterial('replaysecond'))).toBe(false);

    const license = await repository.findLicenseByCheckoutSession('cs_test_replay');
    // The replay must not have swapped the licence key out from under the customer.
    expect(license?.keyHash).toBe(licenseMaterial('replay').keyHash);
  });

  it('cancels a subscription through an update mutation', async () => {
    const input = provisionInput('cancelme', 1);
    await repository.provisionLicense(input, licenseMaterial('cancelme'));
    const processed = await repository.applyWebhook({
      id: `evt_${randomUUID().replace(/-/g, '')}`,
      type: 'customer.subscription.deleted',
      createdAt: new Date(),
      mutation: {
        kind: 'update',
        stripeSubscriptionId: input.stripeSubscriptionId,
        status: 'canceled',
      },
    }, licenseMaterial('cancelmeunused'));
    expect(processed).toBe(true);

    const result = await repository.activateLicense(
      licenseMaterial('cancelme').keyHash,
      machine('cancelled-box'),
    );
    expect(result.outcome).toBe('inactive');
  });
});

describe('seat enforcement', () => {
  it('rejects an unknown licence key', async () => {
    const result = await repository.activateLicense(sha256('nobody'), machine('ghost'));
    expect(result.outcome).toBe('invalid');
  });

  it('holds the seat limit and frees a seat on deactivation', async () => {
    const material = licenseMaterial('seats');
    await repository.provisionLicense(provisionInput('seats', 1), material);

    const first = await repository.activateLicense(material.keyHash, machine('laptop'));
    expect(first.outcome).toBe('ok');

    const second = await repository.activateLicense(material.keyHash, machine('desktop'));
    expect(second.outcome).toBe('seat_limit');

    // Re-activating the same machine is a renewal, not a new seat.
    const repeat = await repository.activateLicense(material.keyHash, machine('laptop'));
    expect(repeat.outcome).toBe('ok');
    if (repeat.outcome === 'ok') expect(repeat.license.activeSeats).toBe(1);

    if (first.outcome !== 'ok') throw new Error('expected the first activation to succeed');
    expect(await repository.deactivateActivation(first.license.id, first.activationId)).toBe(true);
    // Deactivating twice must not release a seat that was already released.
    expect(await repository.deactivateActivation(first.license.id, first.activationId)).toBe(false);

    const afterRelease = await repository.activateLicense(material.keyHash, machine('desktop'));
    expect(afterRelease.outcome).toBe('ok');
  });

  it('never oversells seats when activations arrive concurrently', async () => {
    const material = licenseMaterial('race');
    await repository.provisionLicense(provisionInput('race', 2), material);

    // The whole point of SELECT ... FOR UPDATE. Without the row lock these interleave and
    // every caller reads the same pre-insert seat count, handing out unlimited seats.
    const attempts = await Promise.all(
      Array.from({ length: 12 }, (_unused, index) =>
        repository.activateLicense(material.keyHash, machine(`racer-${index}`))),
    );

    const granted = attempts.filter((attempt) => attempt.outcome === 'ok');
    const refused = attempts.filter((attempt) => attempt.outcome === 'seat_limit');
    expect(granted).toHaveLength(2);
    expect(refused).toHaveLength(10);

    const active = await pool.query(
      `SELECT count(*)::int AS n FROM activations a
        JOIN licenses l ON l.id = a.license_id
       WHERE l.license_key_hash = $1 AND a.deactivated_at IS NULL`,
      [material.keyHash],
    );
    expect(active.rows[0].n).toBe(2);
  }, 60_000);
});

describe('authenticated activation and reports', () => {
  it('authenticates only the exact activation and machine pairing', async () => {
    const material = licenseMaterial('auth');
    await repository.provisionLicense(provisionInput('auth', 2), material);
    const activation = await repository.activateLicense(material.keyHash, machine('auth-box'));
    if (activation.outcome !== 'ok') throw new Error('activation failed');

    const authenticated = await repository.getAuthenticatedActivation(
      activation.license.id,
      activation.activationId,
      activation.machineHash,
    );
    expect(authenticated?.license.id).toBe(activation.license.id);

    // A valid token bound to a different machine must not authenticate.
    expect(await repository.getAuthenticatedActivation(
      activation.license.id,
      activation.activationId,
      machine('someone-elses-box'),
    )).toBeNull();

    // A deactivated seat must stop authenticating immediately.
    await repository.deactivateActivation(activation.license.id, activation.activationId);
    expect(await repository.getAuthenticatedActivation(
      activation.license.id,
      activation.activationId,
      activation.machineHash,
    )).toBeNull();
  });

  it('stores reports and pages through them without overlap or leakage', async () => {
    const material = licenseMaterial('reports');
    await repository.provisionLicense(provisionInput('reports', 1), material);
    const activation = await repository.activateLicense(material.keyHash, machine('report-box'));
    if (activation.outcome !== 'ok') throw new Error('activation failed');
    const auth = {
      activationId: activation.activationId,
      machineHash: activation.machineHash,
      license: activation.license,
    };

    for (let index = 0; index < 3; index++) {
      await repository.createReport(auth, {
        schemaVersion: 1,
        machineId: activation.machineHash,
        snapshotAt: new Date(Date.UTC(2026, 0, index + 1)).toISOString(),
        summary: {
          extensionsScanned: 1,
          findings: 1,
          critical: 0,
          high: 1,
          medium: 0,
          low: 0,
          info: 0,
        },
        extensions: [{
          id: 'publisher.extension',
          name: `Report ${index}`,
          riskScore: index,
          findings: [{ category: 'permission', severity: 'high', count: 1 }],
        }],
      });
    }

    const firstPage = await repository.listReports(activation.license.id, 2, null);
    expect(firstPage.reports).toHaveLength(2);
    expect(firstPage.nextCursor).toBeTruthy();

    const secondPage = await repository.listReports(activation.license.id, 2, firstPage.nextCursor);
    expect(secondPage.reports).toHaveLength(1);
    expect(secondPage.nextCursor).toBeNull();

    // No report may appear on both pages.
    const ids = [...firstPage.reports, ...secondPage.reports].map((report) => report.id);
    expect(new Set(ids).size).toBe(3);

    // Another licence must never see these reports.
    const otherMaterial = licenseMaterial('othertenant');
    const other = await repository.provisionLicense(provisionInput('othertenant', 1), otherMaterial);
    const isolated = await repository.listReports(other.id, 25, null);
    expect(isolated.reports).toHaveLength(0);
  }, 60_000);
});
