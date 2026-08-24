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
import { Client, Pool, QueryResult } from 'pg';
import { createApp } from './app';
import { StripeBilling } from './billing';
import { loadConfig } from './config';
import { createLicenseCrypto } from './crypto';
import { createLogger, Logger } from './logger';
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

/**
 * Hands out a fresh Postgres connection per use instead of pooling them in the isolate.
 *
 * A long-lived pg.Pool is wrong on Workers. The runtime can freeze an isolate between
 * invocations, and a pooled socket does not survive that: the next request is handed a dead
 * connection, the query never settles, and the runtime cancels the request for producing no
 * response. It presents as alternating success and failure, because each failure retires the
 * bad socket and the following request opens a good one.
 *
 * Connecting per request is cheap here precisely because Hyperdrive is in front: the real
 * pooling happens on Cloudflare's side, so this opens a local connection to a warm pool rather
 * than a fresh session against Postgres itself.
 *
 * Shaped to match the small part of pg.Pool that PostgresRepository actually uses, so the
 * repository, its SQL, and its tests stay identical between Node and Workers.
 */
class PerRequestConnections {
  constructor(
    private readonly connectionString: string,
    private readonly ssl: boolean,
    private readonly logger: Logger,
  ) {}

  private create(): Client {
    return new Client({
      connectionString: this.connectionString,
      ssl: this.ssl ? { rejectUnauthorized: false } : false,
      connectionTimeoutMillis: 8_000,
      statement_timeout: 15_000,
      query_timeout: 15_000,
      application_name: 'extguard-api-worker',
    });
  }

  async query(text: string, values?: unknown[]): Promise<QueryResult> {
    const client = this.create();
    await client.connect();
    try {
      return await client.query(text, values as never);
    } finally {
      void client.end().catch(() => undefined);
    }
  }

  /**
   * Transactions need one connection held across several statements, so the caller keeps this
   * client until it calls release(). release() is synchronous in pg's contract, so the close
   * is started and not awaited.
   */
  async connect(): Promise<Client & { release: () => void }> {
    const client = this.create();
    await client.connect();
    return Object.assign(client, {
      release: () => {
        void client.end().catch((error: unknown) => this.logger.warn('postgres.close_failed', {
          errorType: error instanceof Error ? error.name : 'UnknownError',
        }));
      },
    });
  }

  on(): void {
    // pg.Pool emits idle-client errors. There are no idle clients here, so there is nothing
    // to listen for; the method exists only to satisfy the shape the caller expects.
  }

  async end(): Promise<void> {
    // Nothing is retained between requests, so there is nothing to shut down.
  }
}

let started: { server: ReturnType<typeof createServer> } | undefined;

/**
 * Build the application on first request rather than at module load.
 *
 * Workers forbid I/O, timers and random generation in global scope, and reading the Hyperdrive
 * binding's connection string counts as I/O. Constructing here also means a deploy with a
 * broken configuration fails as a request error that shows up in logs, instead of failing
 * startup validation and taking the whole Worker offline.
 */
function ensureStarted(): void {
  if (started) return;

  const config = loadConfig(workerEnvironment());
  const logger = createLogger(config.logLevel);

  const pool = new PerRequestConnections(config.databaseUrl, config.databaseSsl, logger);

  const app = createApp({
    config,
    // Structurally compatible with the slice of pg.Pool the repository uses.
    repository: new PostgresRepository(pool as unknown as Pool),
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
  started = { server };
}

const handler = httpServerHandler({ port: PORT }) as ExportedHandler;

export default {
  fetch(request, env, ctx) {
    ensureStarted();
    return handler.fetch!(request, env, ctx);
  },
} satisfies ExportedHandler;
