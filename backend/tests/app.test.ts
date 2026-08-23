import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import {
  BillingGateway,
  CheckoutResult,
  InvalidWebhookSignatureError,
} from '../src/billing';
import { AppConfig } from '../src/config';
import { createLicenseCrypto, LicenseCrypto } from '../src/crypto';
import { BillingWebhook, ProvisionLicenseInput } from '../src/domain';
import { silentLogger } from '../src/logger';
import { MemoryRepository } from '../src/repository';

const machineA = 'a'.repeat(64);
const machineB = 'b'.repeat(64);

const config: AppConfig = {
  nodeEnv: 'test',
  port: 3000,
  trustProxy: 0,
  logLevel: 'error',
  databaseUrl: 'postgresql://unused',
  databaseSsl: false,
  stripeSecretKey: 'sk_test_unused',
  stripeWebhookSecret: 'whsec_unused',
  stripePriceId: 'price_team',
  checkoutSuccessUrl: 'https://app.example/success?session_id={CHECKOUT_SESSION_ID}',
  checkoutCancelUrl: 'https://app.example/pricing',
  billingPortalReturnUrl: 'https://app.example/account',
  jwtSecret: 'j'.repeat(64),
  jwtTtlSeconds: 3600,
  licenseKeyPepper: 'p'.repeat(64),
  licenseEncryptionKey: Buffer.alloc(32, 7),
  corsAllowedOrigins: ['https://app.example'],
  rateLimitEnabled: false,
};

const paidSession: ProvisionLicenseInput = {
  email: 'buyer@example.com',
  status: 'active',
  seats: 1,
  stripeCustomerId: 'cus_test123',
  stripeSubscriptionId: 'sub_test123',
  stripeCheckoutSessionId: 'cs_test_paid123',
  currentPeriodEnd: new Date('2030-01-01T00:00:00.000Z'),
};

class MockBilling implements BillingGateway {
  checkoutCalls: Array<{ email: string; seats: number; idempotencyKey?: string }> = [];
  checkoutResult: CheckoutResult = {
    id: 'cs_test_checkout123',
    url: 'https://checkout.stripe.com/c/pay/test',
  };
  session: ProvisionLicenseInput | null = paidSession;
  webhook: BillingWebhook = {
    id: 'evt_test123',
    type: 'customer.subscription.updated',
    createdAt: new Date('2026-08-21T00:00:00.000Z'),
    mutation: { kind: 'none' },
  };
  webhookPayload: Buffer | null = null;
  portalCustomer: string | null = null;

  async createCheckout(email: string, seats: number, idempotencyKey?: string): Promise<CheckoutResult> {
    this.checkoutCalls.push({ email, seats, idempotencyKey });
    return this.checkoutResult;
  }

  async retrievePaidCheckoutSession(sessionId: string): Promise<ProvisionLicenseInput | null> {
    return sessionId === this.session?.stripeCheckoutSessionId ? this.session : null;
  }

  async parseWebhook(payload: Buffer, signature: string): Promise<BillingWebhook> {
    if (signature !== 'valid-signature') throw new InvalidWebhookSignatureError();
    this.webhookPayload = payload;
    return this.webhook;
  }

  async createPortal(stripeCustomerId: string): Promise<string> {
    this.portalCustomer = stripeCustomerId;
    return 'https://billing.stripe.com/p/session/test';
  }
}

interface Harness {
  app: ReturnType<typeof createApp>;
  repository: MemoryRepository;
  billing: MockBilling;
  crypto: LicenseCrypto;
}

function harness(): Harness {
  const repository = new MemoryRepository();
  const billing = new MockBilling();
  const crypto = createLicenseCrypto(config.licenseKeyPepper, config.licenseEncryptionKey);
  return {
    app: createApp({ config, repository, billing, licenseCrypto: crypto, logger: silentLogger }),
    repository,
    billing,
    crypto,
  };
}

async function revealLicense(test: Harness): Promise<string> {
  const response = await request(test.app)
    .get('/api/v1/checkout/session')
    .query({ session_id: 'cs_test_paid123' })
    .expect(200);
  return response.body.licenseKey as string;
}

async function activate(test: Harness, licenseKey: string, machineId = machineA): Promise<string> {
  const response = await request(test.app)
    .post('/api/v1/licenses/activate')
    .send({ licenseKey, machineId })
    .expect(200);
  return response.body.accessToken as string;
}

describe('ExtGuard Team API', () => {
  let test: Harness;

  beforeEach(() => {
    test = harness();
  });

  it('reports database health and applies security headers', async () => {
    const response = await request(test.app).get('/health').expect(200);
    expect(response.body).toEqual({ status: 'ok' });
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-powered-by']).toBeUndefined();
    expect(response.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('enforces the browser CORS allowlist while allowing a configured origin', async () => {
    await request(test.app)
      .get('/health')
      .set('Origin', 'https://attacker.example')
      .expect(403)
      .expect(({ body }) => expect(body.error.code).toBe('origin_not_allowed'));

    const allowed = await request(test.app)
      .get('/health')
      .set('Origin', 'https://app.example')
      .expect(200);
    expect(allowed.headers['access-control-allow-origin']).toBe('https://app.example');
  });

  it('validates checkout input and forwards a safe idempotency key', async () => {
    await request(test.app)
      .post('/api/v1/checkout')
      .send({ email: 'not-email', seats: 0, extra: true })
      .expect(400)
      .expect(({ body }) => expect(body.error.code).toBe('validation_error'));

    const response = await request(test.app)
      .post('/api/v1/checkout')
      .set('Idempotency-Key', 'checkout.test-123')
      .send({ email: 'BUYER@EXAMPLE.COM', seats: 3 })
      .expect(201);
    expect(response.body).toEqual({
      url: 'https://checkout.stripe.com/c/pay/test',
      sessionId: 'cs_test_checkout123',
    });
    expect(test.billing.checkoutCalls).toEqual([{
      email: 'buyer@example.com',
      seats: 3,
      idempotencyKey: 'checkout.test-123',
    }]);
  });

  it('returns processing until Checkout is paid, then reveals the same encrypted-at-rest key', async () => {
    test.billing.session = null;
    await request(test.app)
      .get('/api/v1/checkout/session?session_id=cs_test_paid123')
      .expect(202)
      .expect('Cache-Control', /no-store/)
      .expect({ status: 'processing' });

    test.billing.session = paidSession;
    const first = await request(test.app)
      .get('/api/v1/checkout/session?session_id=cs_test_paid123')
      .expect(200)
      .expect('Cache-Control', /no-store/);
    const second = await request(test.app)
      .get('/api/v1/checkout/session?session_id=cs_test_paid123')
      .expect(200);
    expect(first.body.licenseKey).toMatch(/^EXTG_/);
    expect(second.body.licenseKey).toBe(first.body.licenseKey);
    expect(first.body.entitlement).toMatchObject({
      plan: 'team',
      status: 'active',
      seats: 1,
      activeSeats: 0,
    });
  });

  it('enforces seat uniqueness, rotates validation tokens, and frees a deactivated seat', async () => {
    const licenseKey = await revealLicense(test);
    const firstToken = await activate(test, licenseKey);

    const repeated = await request(test.app)
      .post('/api/v1/licenses/activate')
      .send({ licenseKey, machineId: machineA })
      .expect(200);
    expect(repeated.body.entitlement.activeSeats).toBe(1);

    await request(test.app)
      .post('/api/v1/licenses/activate')
      .send({ licenseKey, machineId: machineB })
      .expect(409)
      .expect(({ body }) => expect(body.error.code).toBe('seat_limit_reached'));

    const validated = await request(test.app)
      .post('/api/v1/licenses/validate')
      .set('Authorization', `Bearer ${firstToken}`)
      .send({})
      .expect(200);
    expect(validated.body.valid).toBe(true);
    expect(validated.body.accessToken).toEqual(expect.any(String));

    await request(test.app)
      .post('/api/v1/licenses/deactivate')
      .set('Authorization', `Bearer ${firstToken}`)
      .send({})
      .expect(200)
      .expect({ success: true });
    await request(test.app)
      .post('/api/v1/licenses/validate')
      .set('Authorization', `Bearer ${firstToken}`)
      .send({})
      .expect(401);
    await activate(test, licenseKey, machineB);
  });

  it('accepts only aggregate privacy-safe reports from the authenticated machine', async () => {
    const token = await activate(test, await revealLicense(test));
    const report = {
      schemaVersion: 1,
      machineId: machineA,
      snapshotAt: new Date().toISOString(),
      summary: {
        extensionsScanned: 1,
        findings: 2,
        critical: 0,
        high: 1,
        medium: 1,
        low: 0,
        info: 0,
      },
      extensions: [{
        id: 'publisher.extension',
        name: 'Example Extension',
        riskScore: 70,
        findings: [
          { category: 'network', severity: 'high', count: 1 },
          { category: 'process', severity: 'medium', count: 1 },
        ],
      }],
    };
    const created = await request(test.app)
      .post('/api/v1/reports')
      .set('Authorization', `Bearer ${token}`)
      .send(report)
      .expect(201);
    expect(created.body.id).toEqual(expect.any(String));

    await request(test.app)
      .post('/api/v1/reports')
      .set('Authorization', `Bearer ${token}`)
      .send({ ...report, machineId: machineB })
      .expect(403)
      .expect(({ body }) => expect(body.error.code).toBe('machine_mismatch'));

    await request(test.app)
      .post('/api/v1/reports')
      .set('Authorization', `Bearer ${token}`)
      .send({ ...report, sourceCode: 'secret' })
      .expect(400);

    const page = await request(test.app)
      .get('/api/v1/reports?limit=10')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect('Cache-Control', /no-store/);
    expect(page.body.reports).toHaveLength(1);
    expect(page.body.reports[0]).toMatchObject(report);
    expect(page.body.nextCursor).toBeNull();
  });

  it('verifies the raw webhook body and handles replay idempotently', async () => {
    const payload = '{"id":"evt_test123"}';
    await request(test.app)
      .post('/api/v1/webhooks/stripe')
      .set('Content-Type', 'application/json')
      .set('Stripe-Signature', 'bad-signature')
      .send(payload)
      .expect(400)
      .expect(({ body }) => expect(body.error.code).toBe('invalid_webhook_signature'));

    const first = await request(test.app)
      .post('/api/v1/webhooks/stripe')
      .set('Content-Type', 'application/json')
      .set('Stripe-Signature', 'valid-signature')
      .send(payload)
      .expect(200);
    const replay = await request(test.app)
      .post('/api/v1/webhooks/stripe')
      .set('Content-Type', 'application/json')
      .set('Stripe-Signature', 'valid-signature')
      .send(payload)
      .expect(200);
    expect(first.body).toEqual({ received: true, duplicate: false });
    expect(replay.body).toEqual({ received: true, duplicate: true });
    expect(test.billing.webhookPayload).toBeInstanceOf(Buffer);
    expect(test.billing.webhookPayload?.toString('utf8')).toBe(payload);
  });

  it('invalidates active tokens after a subscription lifecycle cancellation', async () => {
    const token = await activate(test, await revealLicense(test));
    test.billing.webhook = {
      id: 'evt_cancel123',
      type: 'customer.subscription.deleted',
      createdAt: new Date(),
      mutation: {
        kind: 'update',
        stripeSubscriptionId: 'sub_test123',
        status: 'canceled',
      },
    };
    await request(test.app)
      .post('/api/v1/webhooks/stripe')
      .set('Content-Type', 'application/json')
      .set('Stripe-Signature', 'valid-signature')
      .send('{}')
      .expect(200);
    await request(test.app)
      .post('/api/v1/licenses/validate')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(401)
      .expect(({ body }) => expect(body.error.code).toBe('activation_invalid'));
  });

  it('requires an active activation for the Stripe billing portal', async () => {
    await request(test.app).post('/api/v1/billing/portal').send({}).expect(401);
    const token = await activate(test, await revealLicense(test));
    const response = await request(test.app)
      .post('/api/v1/billing/portal')
      .set('Authorization', `Bearer ${token}`)
      .send({})
      .expect(200);
    expect(response.body.url).toBe('https://billing.stripe.com/p/session/test');
    expect(test.billing.portalCustomer).toBe('cus_test123');
  });

  it('returns stable JSON errors for malformed JSON and unknown routes', async () => {
    await request(test.app)
      .post('/api/v1/checkout')
      .set('Content-Type', 'application/json')
      .send('{bad')
      .expect(400)
      .expect(({ body }) => expect(body.error.code).toBe('invalid_json'));
    await request(test.app)
      .get('/api/v1/does-not-exist')
      .expect(404)
      .expect(({ body }) => expect(body.error.code).toBe('not_found'));
  });
});
