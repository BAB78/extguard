import 'dotenv/config';
import { Pool } from 'pg';
import { createApp } from './app';
import { StripeBilling } from './billing';
import { databaseConnectionConfig, loadConfig } from './config';
import { createLicenseCrypto } from './crypto';
import { createLogger } from './logger';
import { PostgresRepository } from './postgresRepository';

async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger(config.logLevel);
  const pool = new Pool({
    ...databaseConnectionConfig(),
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    application_name: 'extguard-api',
  });
  pool.on('error', (error) => logger.error('postgres.idle_client_error', { errorType: error.name }));

  const repository = new PostgresRepository(pool);
  const billing = new StripeBilling({
    secretKey: config.stripeSecretKey,
    webhookSecret: config.stripeWebhookSecret,
    priceId: config.stripePriceId,
    successUrl: config.checkoutSuccessUrl,
    cancelUrl: config.checkoutCancelUrl,
    portalReturnUrl: config.billingPortalReturnUrl,
  });
  const app = createApp({
    config,
    repository,
    billing,
    licenseCrypto: createLicenseCrypto(config.licenseKeyPepper, config.licenseEncryptionKey),
    logger,
  });
  const server = app.listen(config.port, () => logger.info('server.started', { port: config.port }));

  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info('server.shutdown_started', { signal });
    server.close(() => {
      void repository.close().finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

void main().catch((error: unknown) => {
  console.error(JSON.stringify({
    level: 'error',
    event: 'server.start_failed',
    errorType: error instanceof Error ? error.name : 'UnknownError',
  }));
  process.exit(1);
});
