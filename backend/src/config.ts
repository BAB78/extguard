import { z } from 'zod';

const booleanString = z
  .enum(['true', 'false'])
  .transform((value) => value === 'true');

const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    TRUST_PROXY: z.coerce.number().int().min(0).max(10).default(1),
    LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    DATABASE_URL: z.string().min(1),
    DATABASE_SSL: booleanString.default('true'),
    // Restricted keys (rk_) are the least-privilege option and are preferred in live mode.
    STRIPE_SECRET_KEY: z.string().regex(/^(sk|rk)_(test|live)_/),
    STRIPE_WEBHOOK_SECRET: z.string().regex(/^whsec_/),
    STRIPE_PRICE_ID: z.string().regex(/^price_/),
    CHECKOUT_SUCCESS_URL: z.string().url().refine(
      (url) => url.includes('{CHECKOUT_SESSION_ID}'),
      'must contain {CHECKOUT_SESSION_ID}',
    ),
    CHECKOUT_CANCEL_URL: z.string().url(),
    BILLING_PORTAL_RETURN_URL: z.string().url(),
    JWT_SECRET: z.string().min(32),
    JWT_TTL_SECONDS: z.coerce.number().int().min(300).max(604800).default(86400),
    LICENSE_KEY_PEPPER: z.string().min(32),
    LICENSE_ENCRYPTION_KEY: z.string().refine((value) => {
      try {
        return Buffer.from(value, 'base64').length === 32;
      } catch {
        return false;
      }
    }, 'must be a base64-encoded 32-byte value'),
    CORS_ALLOWED_ORIGINS: z.string().min(1),
  })
  .superRefine((env, context) => {
    // Must match rk_live_ as well as sk_live_. Checking only the sk_ form meant a restricted
    // live key was read as test mode, which quietly skipped the HTTPS requirement below on
    // exactly the setup that handles real money.
    const stripeMode = /^(sk|rk)_live_/.test(env.STRIPE_SECRET_KEY) ? 'live' : 'test';
    if (env.NODE_ENV === 'production' && stripeMode === 'live') {
      for (const [name, url] of [
        ['CHECKOUT_SUCCESS_URL', env.CHECKOUT_SUCCESS_URL],
        ['CHECKOUT_CANCEL_URL', env.CHECKOUT_CANCEL_URL],
        ['BILLING_PORTAL_RETURN_URL', env.BILLING_PORTAL_RETURN_URL],
      ] as const) {
        if (!url.startsWith('https://')) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: [name],
            message: 'must use HTTPS with live Stripe credentials',
          });
        }
      }
    }
  });

export interface AppConfig {
  nodeEnv: 'development' | 'test' | 'production';
  port: number;
  trustProxy: number;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  databaseUrl: string;
  databaseSsl: boolean;
  stripeSecretKey: string;
  stripeWebhookSecret: string;
  stripePriceId: string;
  checkoutSuccessUrl: string;
  checkoutCancelUrl: string;
  billingPortalReturnUrl: string;
  jwtSecret: string;
  jwtTtlSeconds: number;
  licenseKeyPepper: string;
  licenseEncryptionKey: Buffer;
  corsAllowedOrigins: string[];
  rateLimitEnabled: boolean;
}

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.safeParse(environment);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('; ');
    throw new Error(`Invalid environment configuration: ${details}`);
  }

  const env = parsed.data;
  const corsAllowedOrigins = [...new Set(
    env.CORS_ALLOWED_ORIGINS.split(',').map((origin) => origin.trim()).filter(Boolean),
  )];
  if (corsAllowedOrigins.some((origin) => origin === '*')) {
    throw new Error('Invalid environment configuration: wildcard CORS origins are not allowed');
  }
  for (const origin of corsAllowedOrigins) {
    const url = new URL(origin);
    if (url.origin !== origin || !['http:', 'https:'].includes(url.protocol)) {
      throw new Error(`Invalid environment configuration: invalid CORS origin ${origin}`);
    }
  }

  return {
    nodeEnv: env.NODE_ENV,
    port: env.PORT,
    trustProxy: env.TRUST_PROXY,
    logLevel: env.LOG_LEVEL,
    databaseUrl: env.DATABASE_URL,
    databaseSsl: env.DATABASE_SSL,
    stripeSecretKey: env.STRIPE_SECRET_KEY,
    stripeWebhookSecret: env.STRIPE_WEBHOOK_SECRET,
    stripePriceId: env.STRIPE_PRICE_ID,
    checkoutSuccessUrl: env.CHECKOUT_SUCCESS_URL,
    checkoutCancelUrl: env.CHECKOUT_CANCEL_URL,
    billingPortalReturnUrl: env.BILLING_PORTAL_RETURN_URL,
    jwtSecret: env.JWT_SECRET,
    jwtTtlSeconds: env.JWT_TTL_SECONDS,
    licenseKeyPepper: env.LICENSE_KEY_PEPPER,
    licenseEncryptionKey: Buffer.from(env.LICENSE_ENCRYPTION_KEY, 'base64'),
    corsAllowedOrigins,
    rateLimitEnabled: env.NODE_ENV !== 'test',
  };
}

export function databaseConnectionConfig(environment: NodeJS.ProcessEnv = process.env): {
  connectionString: string;
  ssl: false | { rejectUnauthorized: boolean };
} {
  const databaseUrl = environment.DATABASE_URL;
  if (!databaseUrl) throw new Error('DATABASE_URL is required');
  const databaseSsl = environment.DATABASE_SSL !== 'false';
  return {
    connectionString: databaseUrl,
    ssl: databaseSsl ? { rejectUnauthorized: false } : false,
  };
}
