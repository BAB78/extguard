#!/usr/bin/env node
/**
 * Local development database.
 *
 *   node scripts/devdb.mjs
 *
 * Boots a PostgreSQL cluster on the port that .env points at and leaves it running until
 * interrupted. Unlike the test and smoke clusters this one is persistent, so a licence issued
 * during a Stripe test run is still there after a restart.
 *
 * This exists so the whole payment flow can be exercised locally with no hosting account and
 * no monthly bill. Nothing here is production infrastructure.
 */
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import EmbeddedPostgres from 'embedded-postgres';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DATA_DIR = path.join(ROOT, '.pgdata-dev');
const PORT = Number(process.env.DEV_DB_PORT || 54331);
const DATABASE = 'extguard_dev';
const RESET = process.argv.includes('--reset');

const postgres = new EmbeddedPostgres({
  databaseDir: DATA_DIR,
  user: 'postgres',
  password: 'postgres',
  port: PORT,
  persistent: true,
});

if (RESET) {
  await rm(DATA_DIR, { recursive: true, force: true });
  console.log('reset: previous development data removed');
}

let initialised = false;
try {
  await postgres.initialise();
  initialised = true;
} catch (error) {
  // Already initialised from a previous run, which is the normal case.
  if (!/exists but is not empty/i.test(String(error))) throw error;
}

await postgres.start();
console.log(`postgres listening on 127.0.0.1:${PORT}`);

if (initialised) {
  await postgres.createDatabase(DATABASE);
  console.log(`created database ${DATABASE}`);
} else {
  try {
    await postgres.createDatabase(DATABASE);
    console.log(`created database ${DATABASE}`);
  } catch {
    console.log(`database ${DATABASE} already present`);
  }
}

console.log(`DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:${PORT}/${DATABASE}`);
console.log('leave this running; press Ctrl+C to stop');

const shutdown = async () => {
  console.log('\nstopping postgres');
  await postgres.stop().catch(() => undefined);
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Hold the process open.
setInterval(() => undefined, 1 << 30);
