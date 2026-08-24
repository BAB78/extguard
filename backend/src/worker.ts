/**
 * Cloudflare Workers entry point.
 *
 * The Express application in app.ts is not modified or reimplemented here. Workers can run a
 * node:http server directly, so the same routes, middleware, validation and Stripe webhook
 * handling that the test suite covers are what actually serve production traffic. Only the
 * bootstrap differs from server.ts:
 *
 *   - configuration comes from Worker bindings rather than a .env file
 *   - the database connection string comes from Hyperdrive, which pools connections on
 *     Cloudflare's side. Without it every isolate would open its own connection to Postgres
 *     and exhaust the free tier's connection limit almost immediately
 *   - there is no migrate-then-listen step, because a Worker has no boot sequence. Migrations
 *     are applied out of band with `npm run migrate:remote` before deploying.
 */
import { createServer } from 'node:http';
import { httpServerHandler } from 'cloudflare:node';
import { env } from 'cloudflare:workers';
import { Pool } from 'pg';
import { createApp } from './app';
import { StripeBilling } from './billing';
import { loadConfig } from './config';
import { createLicenseCrypto } from './crypto';
import { createLogger } from './logger';
import { PostgresRepository } from './postgresRepository';

/** Port is a routing key inside the Workers runtime, not a real listening socket. */
const PORT = 8080;

interface HyperdriveBinding {
  connectionString: string;
}

function workerEnvironment(): NodeJS.ProcessEnv {
  const bindings = env as unknown as Record<string, unknown>;
  const plain: Record<string, string> = {};
  for (const [key, value] of Object.entries(bindings)) {
    if (typeof value === 'string') plain[key] = value;
  }

  const hyperdrive = bindings.HYPERDRIVE as HyperdriveBinding | undefined;
  if (hyperdrive?.connectionString) {
    plain.DATABASE_URL = hyperdrive.connectionString;
    // Hyperdrive terminates TLS to the origin database itself, so the Worker talks to it over
    // the local binding. Leaving SSL on here fails the handshake.
    plain.DATABASE_SSL = 'false';
  }

  return plain as NodeJS.ProcessEnv;
}

const environment = workerEnvironment();
const config = loadConfig(environment);
const logger = createLogger(config.logLevel);

const pool = new Pool({
  connectionString: config.databaseUrl,
  ssl: config.databaseSsl ? { rejectUnauthorized: false } : false,
  // Each isolate is short-lived and Hyperdrive does the real pooling, so a large local pool
  // buys nothing and risks holding connections open across requests.
  max: 5,
  connectionTimeoutMillis: 10_000,
  application_name: 'extguard-api-worker',
});
pool.on('error', (error) => logger.error('postgres.idle_client_error', { errorType: error.name }));

const app = createApp({
  config,
  repository: new PostgresRepository(pool),
  billing: new StripeBilling({
    secretKey: config.stripeSecretKey,
    webhookSecret: config.stripeWebhookSecret,
    priceId: config.stripePriceId,
    successUrl: config.checkoutSuccessUrl,
    cancelUrl: config.checkoutCancelUrl,
    portalReturnUrl: config.billingPortalReturnUrl,
  }),
  licenseCrypto: createLicenseCrypto(config.licenseKeyPepper, config.licenseEncryptionKey),
  logger,
});

const server = createServer(app);
server.listen(PORT);

export default httpServerHandler({ port: PORT });
