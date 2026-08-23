import 'dotenv/config';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { Pool } from 'pg';
import { databaseConnectionConfig } from './config';

async function migrate(): Promise<void> {
  const pool = new Pool({
    ...databaseConnectionConfig(),
    max: 1,
    connectionTimeoutMillis: 10_000,
    application_name: 'extguard-migrations',
  });
  const client = await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock(hashtext('extguard-schema-migrations'))");
    await client.query(`
      CREATE TABLE IF NOT EXISTS extguard_schema_migrations (
        filename text PRIMARY KEY,
        checksum character(64) NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    const migrationDirectory = path.resolve(__dirname, '..', 'migrations');
    const filenames = (await fs.readdir(migrationDirectory))
      .filter((filename) => /^\d+_[a-z0-9_]+\.sql$/.test(filename))
      .sort();
    for (const filename of filenames) {
      const sql = await fs.readFile(path.join(migrationDirectory, filename), 'utf8');
      const checksum = createHash('sha256').update(sql).digest('hex');
      const existing = await client.query(
        'SELECT checksum FROM extguard_schema_migrations WHERE filename = $1',
        [filename],
      );
      if (existing.rows[0]) {
        if (existing.rows[0].checksum !== checksum) {
          throw new Error(`Applied migration ${filename} has changed`);
        }
        continue;
      }

      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query(
          'INSERT INTO extguard_schema_migrations (filename, checksum) VALUES ($1, $2)',
          [filename, checksum],
        );
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    await client.query("SELECT pg_advisory_unlock(hashtext('extguard-schema-migrations'))").catch(() => undefined);
    client.release();
    await pool.end();
  }
}

void migrate().then(
  () => console.log(JSON.stringify({ level: 'info', event: 'migrations.complete' })),
  (error: unknown) => {
    console.error(JSON.stringify({
      level: 'error',
      event: 'migrations.failed',
      errorType: error instanceof Error ? error.name : 'UnknownError',
    }));
    process.exitCode = 1;
  },
);
