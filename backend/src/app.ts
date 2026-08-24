import { randomUUID } from 'node:crypto';
import cors from 'cors';
import express, { ErrorRequestHandler, NextFunction, Request, RequestHandler, Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { ZodError, ZodType } from 'zod';
import { createTokenService } from './auth';
import { BillingGateway, InvalidWebhookSignatureError } from './billing';
import { AppConfig } from './config';
import { LicenseCrypto } from './crypto';
import { AuthenticatedActivation, isPaidStatus, LicenseRecord, ReportInput } from './domain';
import { Logger } from './logger';
import { InvalidCursorError } from './postgresRepository';
import { Repository } from './repository';
import {
  activationSchema,
  checkoutSchema,
  checkoutSessionSchema,
  reportQuerySchema,
  reportSchema,
} from './schemas';

interface AppDependencies {
  config: AppConfig;
  repository: Repository;
  billing: BillingGateway;
  licenseCrypto: LicenseCrypto;
  logger: Logger;
}

class CorsDeniedError extends Error {
  constructor() {
    super('CORS origin denied');
    this.name = 'CorsDeniedError';
  }
}

const asyncHandler = (
  handler: (request: Request, response: Response, next: NextFunction) => Promise<void>,
): RequestHandler => (request, response, next) => {
  void handler(request, response, next).catch(next);
};

function errorResponse(response: Response, status: number, code: string, message: string): void {
  response.status(status).json({ error: { code, message } });
}

function parse<T>(schema: ZodType<T>, input: unknown): T {
  return schema.parse(input);
}

function entitlement(license: LicenseRecord) {
  return {
    plan: 'team' as const,
    status: license.status,
    seats: license.seats,
    activeSeats: license.activeSeats,
    currentPeriodEnd: license.currentPeriodEnd?.toISOString() ?? null,
  };
}

function noStore(response: Response): void {
  response.set({
    'Cache-Control': 'private, no-store, max-age=0',
    Pragma: 'no-cache',
    Expires: '0',
    'Referrer-Policy': 'no-referrer',
  });
}

export function createApp(dependencies: AppDependencies): express.Express {
  const { billing, config, licenseCrypto, logger, repository } = dependencies;
  const tokenService = createTokenService(config.jwtSecret, config.jwtTtlSeconds);
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);

  app.use(helmet({
    contentSecurityPolicy: false,
    hsts: config.nodeEnv === 'production' ? undefined : false,
  }));
  app.use((request, response, next) => {
    const requestId = randomUUID();
    response.locals.requestId = requestId;
    response.setHeader('X-Request-Id', requestId);
    const startedAt = Date.now();
    response.on('finish', () => logger.info('request.completed', {
      requestId,
      method: request.method,
      path: request.path,
      status: response.statusCode,
      durationMs: Date.now() - startedAt,
    }));
    next();
  });
  app.use(cors({
    credentials: false,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'Idempotency-Key', 'Stripe-Signature'],
    maxAge: 600,
    origin: (origin, callback) => {
      if (!origin || config.corsAllowedOrigins.includes(origin)) callback(null, true);
      else callback(new CorsDeniedError());
    },
  }));

  const limiter = (limit: number, windowMs: number): RequestHandler => {
    if (!config.rateLimitEnabled) return (_request, _response, next) => next();
    return rateLimit({
      windowMs,
      limit,
      standardHeaders: 'draft-7',
      legacyHeaders: false,
      // Cloudflare Workers have no socket, so request.ip is undefined and the default key
      // generator throws ERR_ERL_UNDEFINED_IP_ADDRESS on every request. That did not merely
      // log noise: it meant the limits guarding licence-key activation were not being applied
      // at all, which is the one endpoint where an attacker can guess in a loop.
      // CF-Connecting-IP is set by Cloudflare itself and cannot be spoofed by the client.
      keyGenerator: (request) => request.header('cf-connecting-ip')
        ?? request.header('x-real-ip')
        ?? request.ip
        ?? 'unknown',
      validate: { ip: false, xForwardedForHeader: false },
      handler: (_request, response) => errorResponse(
        response,
        429,
        'rate_limited',
        'Too many requests; try again later.',
      ),
    });
  };
  app.use(limiter(300, 15 * 60 * 1000));

  const freshMaterial = () => {
    const licenseKey = licenseCrypto.generateLicenseKey();
    return {
      licenseKey,
      material: {
        keyHash: licenseCrypto.hashLicenseKey(licenseKey),
        keyCiphertext: licenseCrypto.encryptLicenseKey(licenseKey),
      },
    };
  };

  app.post(
    '/api/v1/webhooks/stripe',
    limiter(180, 60 * 1000),
    express.raw({ type: 'application/json', limit: '1mb' }),
    asyncHandler(async (request, response) => {
      const signature = request.header('stripe-signature');
      // Stripe signs the exact bytes it sent, so the raw body must reach constructEvent
      // untouched. express.raw() yields a Node Buffer under Node, but a plain Uint8Array on
      // Cloudflare Workers, where Buffer is a polyfill. Testing only with Buffer.isBuffer
      // rejected every genuine webhook there with a 400 before the signature was ever checked,
      // which Stripe then retried indefinitely. Converting preserves the bytes; anything that
      // is not binary is still refused, because a parsed object would mean the body had been
      // re-serialised and the signature could never match.
      const body: unknown = request.body;
      const rawBody = Buffer.isBuffer(body)
        ? body
        : body instanceof Uint8Array
          ? Buffer.from(body)
          : null;
      if (!signature || !rawBody) {
        logger.warn('stripe.webhook_malformed', {
          requestId: response.locals.requestId,
          hasSignature: Boolean(signature),
          bodyType: body === null || body === undefined ? 'none' : typeof body,
        });
        errorResponse(response, 400, 'invalid_webhook', 'A signed JSON webhook is required.');
        return;
      }
      try {
        const webhook = await billing.parseWebhook(rawBody, signature);
        const { material } = freshMaterial();
        const processed = await repository.applyWebhook(webhook, material);
        response.status(200).json({ received: true, duplicate: !processed });
      } catch (error) {
        if (error instanceof InvalidWebhookSignatureError) {
          errorResponse(response, 400, 'invalid_webhook_signature', 'Webhook signature verification failed.');
          return;
        }
        logger.error('stripe.webhook_failed', {
          requestId: response.locals.requestId,
          errorType: error instanceof Error ? error.name : 'UnknownError',
        });
        errorResponse(response, 500, 'webhook_processing_failed', 'Webhook processing failed.');
      }
    }),
  );

  app.use(express.json({ limit: '512kb', strict: true }));

  // Liveness: answers without touching the database on purpose.
  //
  // The free Postgres tier bills compute by the hour and wakes on any query, so pointing a
  // platform health check at a route that runs SELECT 1 every few minutes keeps the database
  // awake permanently and burns the monthly quota on nothing. Platform health checks and any
  // keep-warm pinger should use this route; /health stays as the real readiness probe.
  app.get('/livez', (_request, response) => {
    response.status(200).json({ status: 'alive' });
  });

  app.get('/health', asyncHandler(async (_request, response) => {
    try {
      await repository.health();
      response.status(200).json({ status: 'ok' });
    } catch (error) {
      logger.error('health.database_unavailable', {
        requestId: response.locals.requestId,
        errorType: error instanceof Error ? error.name : 'UnknownError',
      });
      response.status(503).json({ status: 'unavailable' });
    }
  }));

  app.post('/api/v1/checkout', limiter(10, 15 * 60 * 1000), asyncHandler(async (request, response) => {
    const input = parse(checkoutSchema, request.body);
    const idempotencyKey = request.header('idempotency-key');
    if (idempotencyKey && !/^[A-Za-z0-9_.:-]{8,255}$/.test(idempotencyKey)) {
      errorResponse(response, 400, 'invalid_idempotency_key', 'Idempotency-Key has an invalid format.');
      return;
    }
    try {
      const session = await billing.createCheckout(input.email, input.seats, idempotencyKey);
      response.status(201).json({ url: session.url, sessionId: session.id });
    } catch (error) {
      logger.error('stripe.checkout_failed', {
        requestId: response.locals.requestId,
        errorType: error instanceof Error ? error.name : 'UnknownError',
      });
      errorResponse(response, 502, 'billing_unavailable', 'Checkout is temporarily unavailable.');
    }
  }));

  app.get('/api/v1/checkout/session', limiter(30, 15 * 60 * 1000), asyncHandler(async (request, response) => {
    noStore(response);
    const { session_id: sessionId } = parse(checkoutSessionSchema, request.query);
    let license = await repository.findLicenseByCheckoutSession(sessionId);
    if (!license) {
      let provision;
      try {
        provision = await billing.retrievePaidCheckoutSession(sessionId);
      } catch (error) {
        logger.warn('stripe.checkout_session_unavailable', {
          requestId: response.locals.requestId,
          errorType: error instanceof Error ? error.name : 'UnknownError',
        });
        errorResponse(response, 502, 'billing_unavailable', 'Checkout status is temporarily unavailable.');
        return;
      }
      if (!provision) {
        response.status(202).json({ status: 'processing' });
        return;
      }
      const { material } = freshMaterial();
      license = await repository.provisionLicense(provision, material);
    }
    if (!isPaidStatus(license.status)) {
      errorResponse(response, 403, 'subscription_inactive', 'The subscription is not active.');
      return;
    }
    response.status(200).json({
      licenseKey: licenseCrypto.decryptLicenseKey(license.keyCiphertext),
      entitlement: entitlement(license),
    });
  }));

  const authenticate: RequestHandler = asyncHandler(async (request, response, next) => {
    const authorization = request.header('authorization');
    if (!authorization?.startsWith('Bearer ') || authorization.length <= 7) {
      errorResponse(response, 401, 'authentication_required', 'A valid activation token is required.');
      return;
    }
    try {
      const claims = tokenService.verify(authorization.slice(7));
      const auth = await repository.getAuthenticatedActivation(
        claims.licenseId,
        claims.activationId,
        claims.machineHash,
      );
      if (!auth) {
        errorResponse(response, 401, 'activation_invalid', 'The activation is no longer valid.');
        return;
      }
      response.locals.auth = auth;
      next();
    } catch {
      errorResponse(response, 401, 'token_invalid', 'The activation token is invalid or expired.');
    }
  });

  app.post('/api/v1/licenses/activate', limiter(20, 15 * 60 * 1000), asyncHandler(async (request, response) => {
    noStore(response);
    const input = parse(activationSchema, request.body);
    const machineHash = licenseCrypto.hashMachineId(input.machineId);
    const result = await repository.activateLicense(
      licenseCrypto.hashLicenseKey(input.licenseKey),
      machineHash,
    );
    if (result.outcome === 'invalid') {
      errorResponse(response, 401, 'license_invalid', 'The license key is invalid.');
      return;
    }
    if (result.outcome === 'inactive') {
      errorResponse(response, 403, 'license_inactive', 'The subscription is not active.');
      return;
    }
    if (result.outcome === 'seat_limit') {
      errorResponse(response, 409, 'seat_limit_reached', 'All licensed seats are currently active.');
      return;
    }
    const token = tokenService.issue({
      licenseId: result.license.id,
      activationId: result.activationId,
      machineHash: result.machineHash,
    });
    response.status(200).json({
      valid: true,
      ...token,
      entitlement: entitlement(result.license),
    });
  }));

  app.post('/api/v1/licenses/validate', authenticate, asyncHandler(async (_request, response) => {
    noStore(response);
    const auth = response.locals.auth as AuthenticatedActivation;
    const token = tokenService.issue({
      licenseId: auth.license.id,
      activationId: auth.activationId,
      machineHash: auth.machineHash,
    });
    response.status(200).json({ valid: true, ...token, entitlement: entitlement(auth.license) });
  }));

  app.post('/api/v1/licenses/deactivate', authenticate, asyncHandler(async (_request, response) => {
    noStore(response);
    const auth = response.locals.auth as AuthenticatedActivation;
    await repository.deactivateActivation(auth.license.id, auth.activationId);
    response.status(200).json({ success: true });
  }));

  app.post('/api/v1/reports', limiter(120, 15 * 60 * 1000), authenticate, asyncHandler(async (request, response) => {
    const auth = response.locals.auth as AuthenticatedActivation;
    const input = parse(reportSchema, request.body) as ReportInput;
    const submittedMachineHash = licenseCrypto.hashMachineId(input.machineId);
    if (!licenseCrypto.hashesEqual(submittedMachineHash, auth.machineHash)) {
      errorResponse(response, 403, 'machine_mismatch', 'The report does not match this activation.');
      return;
    }
    const report = await repository.createReport(auth, input);
    response.status(201).json({ id: report.id, acceptedAt: report.receivedAt });
  }));

  app.get('/api/v1/reports', authenticate, asyncHandler(async (request, response) => {
    noStore(response);
    const auth = response.locals.auth as AuthenticatedActivation;
    const query = parse(reportQuerySchema, request.query);
    try {
      const page = await repository.listReports(
        auth.license.id,
        query.limit ?? 25,
        query.cursor ?? null,
      );
      response.status(200).json(page);
    } catch (error) {
      if (error instanceof InvalidCursorError) {
        errorResponse(response, 400, 'invalid_cursor', 'The report cursor is invalid.');
        return;
      }
      throw error;
    }
  }));

  app.post('/api/v1/billing/portal', limiter(20, 15 * 60 * 1000), authenticate, asyncHandler(async (_request, response) => {
    noStore(response);
    const auth = response.locals.auth as AuthenticatedActivation;
    try {
      const url = await billing.createPortal(auth.license.stripeCustomerId);
      response.status(200).json({ url });
    } catch (error) {
      logger.error('stripe.portal_failed', {
        requestId: response.locals.requestId,
        errorType: error instanceof Error ? error.name : 'UnknownError',
      });
      errorResponse(response, 502, 'billing_unavailable', 'The billing portal is temporarily unavailable.');
    }
  }));

  app.use((_request, response) => {
    errorResponse(response, 404, 'not_found', 'The requested resource was not found.');
  });

  const errorHandler: ErrorRequestHandler = (error, _request, response, _next) => {
    if (response.headersSent) return;
    if (error instanceof ZodError) {
      response.status(400).json({
        error: {
          code: 'validation_error',
          message: 'The request is invalid.',
          fields: error.issues.map((issue) => ({
            path: issue.path.join('.'),
            message: issue.message,
          })),
        },
      });
      return;
    }
    if (error instanceof CorsDeniedError) {
      errorResponse(response, 403, 'origin_not_allowed', 'This browser origin is not allowed.');
      return;
    }
    const entityError = error as { type?: unknown };
    if (entityError.type === 'entity.parse.failed') {
      errorResponse(response, 400, 'invalid_json', 'The request body is not valid JSON.');
      return;
    }
    if (entityError.type === 'entity.too.large') {
      errorResponse(response, 413, 'payload_too_large', 'The request body is too large.');
      return;
    }
    logger.error('request.unhandled_error', {
      requestId: response.locals.requestId,
      errorType: error instanceof Error ? error.name : 'UnknownError',
    });
    errorResponse(response, 500, 'internal_error', 'An unexpected error occurred.');
  };
  app.use(errorHandler);
  return app;
}
