#!/usr/bin/env node
/**
 * Deployment smoke test: run the exact sequence the container runs.
 *
 *   node scripts/smoke.mjs
 *
 * The unit and integration suites import createApp directly, so nothing exercises server.ts,
 * config.ts loading from a real environment, or the migrate-then-boot ordering in the
 * Dockerfile CMD. Those are the parts that fail on Railway rather than on a laptop, and they
 * fail after a deploy rather than in review.
 *
 * This boots a throwaway PostgreSQL, migrates it, starts the compiled server, waits for the
 * healthcheck Railway is configured to poll, and then checks that SIGTERM shuts the process
 * down cleanly rather than being killed after the grace period.
 *
 * Stripe is never contacted. The credentials below are syntactically valid but fake, which is
 * enough to construct the client; no route that calls Stripe is exercised here.
 */
import { spawn, execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import EmbeddedPostgres from 'embedded-postgres';

const execFileAsync = promisify(execFile);
const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const PG_PORT = 54330;
const API_PORT = 3999;
const DATA_DIR = path.join(ROOT, '.pgdata-smoke');
const DATABASE_URL = `postgresql://postgres:postgres@127.0.0.1:${PG_PORT}/extguard_smoke`;

const env = {
  ...process.env,
  NODE_ENV: 'production',
  PORT: String(API_PORT),
  TRUST_PROXY: '1',
  LOG_LEVEL: 'info',
  DATABASE_URL,
  DATABASE_SSL: 'false',
  STRIPE_SECRET_KEY: 'sk_test_smoke_not_a_real_key',
  STRIPE_WEBHOOK_SECRET: 'whsec_smoke_not_a_real_secret',
  STRIPE_PRICE_ID: 'price_smoke',
  CHECKOUT_SUCCESS_URL: 'https://example.com/success?session_id={CHECKOUT_SESSION_ID}',
  CHECKOUT_CANCEL_URL: 'https://example.com/pricing',
  BILLING_PORTAL_RETURN_URL: 'https://example.com/account',
  JWT_SECRET: randomBytes(32).toString('hex'),
  JWT_TTL_SECONDS: '86400',
  LICENSE_KEY_PEPPER: randomBytes(32).toString('hex'),
  LICENSE_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  CORS_ALLOWED_ORIGINS: 'https://example.com',
};

const steps = [];
const record = (name, ok = true, detail = '') => {
  steps.push({ name, ok, detail });
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
};
const skip = (name, why) => {
  steps.push({ name, ok: true, skipped: true, detail: why });
  console.log(`skip  ${name}  (${why})`);
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let postgres;
let server;

try {
  await rm(DATA_DIR, { recursive: true, force: true });

  postgres = new EmbeddedPostgres({
    databaseDir: DATA_DIR,
    user: 'postgres',
    password: 'postgres',
    port: PG_PORT,
    persistent: false,
  });
  await postgres.initialise();
  await postgres.start();
  await postgres.createDatabase('extguard_smoke');
  record('throwaway PostgreSQL started');

  await execFileAsync('npm', ['run', 'build'], { cwd: ROOT, shell: true });
  record('backend compiled');

  // Step one of the Dockerfile CMD.
  const migrate = await execFileAsync(process.execPath, [path.join(ROOT, 'dist', 'migrate.js')], { env, cwd: ROOT });
  record('migrations applied', migrate.stdout.includes('migrations.complete'));

  // Step two. Railway restarts the container, so this must survive a re-run.
  const again = await execFileAsync(process.execPath, [path.join(ROOT, 'dist', 'migrate.js')], { env, cwd: ROOT });
  record('migrations idempotent on restart', again.stdout.includes('migrations.complete'));

  server = spawn(process.execPath, [path.join(ROOT, 'dist', 'server.js')], { env, cwd: ROOT });
  let serverOutput = '';
  server.stdout.on('data', (chunk) => { serverOutput += chunk.toString(); });
  server.stderr.on('data', (chunk) => { serverOutput += chunk.toString(); });

  // Poll the healthcheck path Railway is configured to use in railway.json.
  let healthBody = null;
  let healthStatus = 0;
  for (let attempt = 0; attempt < 40; attempt++) {
    await sleep(250);
    if (server.exitCode !== null) break;
    try {
      const response = await fetch(`http://127.0.0.1:${API_PORT}/health`);
      healthStatus = response.status;
      healthBody = await response.json();
      break;
    } catch {
      // not listening yet
    }
  }
  if (server.exitCode !== null) throw new Error(`server exited early: ${serverOutput}`);
  record('server booted and /health returns ok', healthStatus === 200 && healthBody?.status === 'ok',
    `status ${healthStatus}`);

  const headers = await fetch(`http://127.0.0.1:${API_PORT}/health`).then((response) => response.headers);
  record('security headers present and framework fingerprint removed',
    Boolean(headers.get('x-request-id')) && !headers.get('x-powered-by'));

  const notFound = await fetch(`http://127.0.0.1:${API_PORT}/nope`);
  const notFoundBody = await notFound.json();
  record('unknown routes return the shared JSON error shape',
    notFound.status === 404 && notFoundBody?.error?.code === 'not_found');

  // An unsigned webhook must be rejected before any database work happens.
  const unsigned = await fetch(`http://127.0.0.1:${API_PORT}/api/v1/webhooks/stripe`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: 'evt_forged', type: 'checkout.session.completed' }),
  });
  record('unsigned Stripe webhook rejected', unsigned.status === 400);

  // Railway sends SIGTERM on redeploy and waits before killing. A server that ignores it
  // drops in-flight requests on every single deploy.
  //
  // Windows has no real SIGTERM: child.kill() calls TerminateProcess, so the handler in
  // server.ts never runs and the exit code always comes back null. Reporting that as a
  // failure would be a false alarm about the developer's laptop rather than a fact about the
  // Linux container, so the check is skipped rather than guessed at.
  if (process.platform === 'win32') {
    skip('SIGTERM shuts the server down gracefully', 'not observable on Windows; verify in the Linux container');
    server.kill('SIGKILL');
  } else {
    const exitCode = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve('timeout'), 8000);
      server.once('exit', (code) => { clearTimeout(timer); resolve(code); });
      server.kill('SIGTERM');
    });
    record('SIGTERM shuts the server down gracefully', exitCode === 0, `exit ${exitCode}`);
  }
  server = null;
} catch (error) {
  record('smoke run completed without throwing', false, error instanceof Error ? error.message : String(error));
} finally {
  if (server && server.exitCode === null) server.kill('SIGKILL');
  await postgres?.stop().catch(() => undefined);
  await rm(DATA_DIR, { recursive: true, force: true }).catch(() => undefined);
}

const failed = steps.filter((step) => !step.ok);
const skipped = steps.filter((step) => step.skipped);
const ran = steps.length - skipped.length;
console.log(`\n${ran - failed.length}/${ran} checks passed`
  + (skipped.length ? `, ${skipped.length} skipped on this platform` : ''));
if (failed.length) {
  console.log('The container would not deploy cleanly. Fix these before pushing to Railway.');
  process.exitCode = 1;
} else if (skipped.length) {
  console.log('The container boots, migrates, and serves its healthcheck. Shutdown behaviour was'
    + ' not exercised here; confirm it from the Railway deploy logs on the first redeploy.');
} else {
  console.log('The container boots, migrates, serves its healthcheck, and stops cleanly.');
}
