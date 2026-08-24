import Stripe from 'stripe';
import { BillingWebhook, ProvisionLicenseInput, SubscriptionStatus } from './domain';

export interface CheckoutResult {
  id: string;
  url: string;
}

export interface BillingGateway {
  createCheckout(email: string, seats: number, idempotencyKey?: string): Promise<CheckoutResult>;
  retrievePaidCheckoutSession(sessionId: string): Promise<ProvisionLicenseInput | null>;
  parseWebhook(payload: Buffer, signature: string): Promise<BillingWebhook>;
  createPortal(stripeCustomerId: string): Promise<string>;
}

export class InvalidWebhookSignatureError extends Error {
  constructor() {
    super('Invalid Stripe webhook signature');
    this.name = 'InvalidWebhookSignatureError';
  }
}

interface StripeBillingOptions {
  secretKey: string;
  webhookSecret: string;
  priceId: string;
  successUrl: string;
  cancelUrl: string;
  portalReturnUrl: string;
}

const knownStatuses = new Set<SubscriptionStatus>([
  'active',
  'trialing',
  'past_due',
  'unpaid',
  'canceled',
  'incomplete',
  'incomplete_expired',
  'paused',
]);

function statusOf(value: unknown): SubscriptionStatus {
  return knownStatuses.has(value as SubscriptionStatus)
    ? value as SubscriptionStatus
    : 'incomplete';
}

function stringId(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && 'id' in value && typeof value.id === 'string') {
    return value.id;
  }
  return null;
}

function unixDate(value: unknown): Date | null {
  return typeof value === 'number' && Number.isFinite(value) ? new Date(value * 1000) : null;
}

export class StripeBilling implements BillingGateway {
  private readonly stripe: Stripe;

  /** WebCrypto-backed signing, so webhook verification works on Workers as well as Node. */
  private readonly cryptoProvider = Stripe.createSubtleCryptoProvider();

  constructor(private readonly options: StripeBillingOptions) {
    this.stripe = new Stripe(options.secretKey, {
      maxNetworkRetries: 2,
      timeout: 15_000,
      telemetry: false,
    });
  }

  async createCheckout(email: string, seats: number, idempotencyKey?: string): Promise<CheckoutResult> {
    const session = await this.stripe.checkout.sessions.create(
      {
        mode: 'subscription',
        customer_email: email,
        line_items: [{ price: this.options.priceId, quantity: seats }],
        success_url: this.options.successUrl,
        cancel_url: this.options.cancelUrl,
        allow_promotion_codes: true,
        billing_address_collection: 'auto',
        metadata: { product: 'extguard-team', seats: String(seats) },
        subscription_data: { metadata: { product: 'extguard-team' } },
      },
      idempotencyKey ? { idempotencyKey } : undefined,
    );
    if (!session.url) throw new Error('Stripe did not return a Checkout URL');
    return { id: session.id, url: session.url };
  }

  async retrievePaidCheckoutSession(sessionId: string): Promise<ProvisionLicenseInput | null> {
    const session = await this.stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['subscription', 'line_items.data.price'],
    });
    return this.provisioningFromSession(session);
  }

  async parseWebhook(payload: Buffer, signature: string): Promise<BillingWebhook> {
    let event: Stripe.Event;
    try {
      // constructEventAsync rather than constructEvent, and with an explicit crypto provider.
      //
      // The synchronous form computes its HMAC through Node's crypto module, which the
      // Cloudflare Workers runtime does not provide in the shape the SDK expects. There it
      // fails for every genuine webhook, and it fails as a signature mismatch, which reads
      // exactly like a misconfigured signing secret. That cost a real debugging detour:
      // replacing the secret repeatedly could never have fixed it.
      //
      // WebCrypto is available on both runtimes, so this single path serves Workers and Node
      // alike and the behaviour under test is the behaviour in production.
      event = await this.stripe.webhooks.constructEventAsync(
        payload,
        signature,
        this.options.webhookSecret,
        undefined,
        this.cryptoProvider,
      );
    } catch {
      throw new InvalidWebhookSignatureError();
    }

    if (
      event.type === 'checkout.session.completed'
      || event.type === 'checkout.session.async_payment_succeeded'
    ) {
      const eventSession = event.data.object as Stripe.Checkout.Session;
      const session = await this.stripe.checkout.sessions.retrieve(eventSession.id, {
        expand: ['subscription', 'line_items.data.price'],
      });
      const provision = this.provisioningFromSession(session);
      return {
        id: event.id,
        type: event.type,
        createdAt: new Date(event.created * 1000),
        mutation: provision ? { kind: 'upsert', ...provision } : { kind: 'none' },
      };
    }

    if (
      event.type === 'customer.subscription.created'
      || event.type === 'customer.subscription.updated'
      || event.type === 'customer.subscription.deleted'
    ) {
      const subscription = event.data.object as Stripe.Subscription;
      return {
        id: event.id,
        type: event.type,
        createdAt: new Date(event.created * 1000),
        mutation: this.subscriptionMutation(subscription, event.type === 'customer.subscription.deleted'),
      };
    }

    if (event.type === 'invoice.payment_failed' || event.type === 'invoice.paid') {
      const invoice = event.data.object as unknown as Record<string, unknown>;
      const parent = invoice.parent as Record<string, unknown> | undefined;
      const subscriptionDetails = parent?.subscription_details as Record<string, unknown> | undefined;
      const subscriptionId = stringId(invoice.subscription) ?? stringId(subscriptionDetails?.subscription);
      if (subscriptionId) {
        const subscription = await this.stripe.subscriptions.retrieve(subscriptionId);
        return {
          id: event.id,
          type: event.type,
          createdAt: new Date(event.created * 1000),
          mutation: this.subscriptionMutation(subscription, false),
        };
      }
    }

    return {
      id: event.id,
      type: event.type,
      createdAt: new Date(event.created * 1000),
      mutation: { kind: 'none' },
    };
  }

  async createPortal(stripeCustomerId: string): Promise<string> {
    const session = await this.stripe.billingPortal.sessions.create({
      customer: stripeCustomerId,
      return_url: this.options.portalReturnUrl,
    });
    return session.url;
  }

  private provisioningFromSession(session: Stripe.Checkout.Session): ProvisionLicenseInput | null {
    if (session.mode !== 'subscription') return null;
    if (session.payment_status !== 'paid' && session.payment_status !== 'no_payment_required') return null;

    const subscription = session.subscription;
    if (!subscription || typeof subscription === 'string') return null;
    const normalized = this.subscriptionValues(subscription);
    if (!normalized || (normalized.status !== 'active' && normalized.status !== 'trialing')) return null;

    const lineItems = session.line_items?.data ?? [];
    if (!lineItems.some((item) => stringId(item.price) === this.options.priceId)) return null;
    const email = session.customer_details?.email ?? session.customer_email;
    const customerId = stringId(session.customer) ?? normalized.customerId;
    if (!email || !customerId) return null;

    return {
      email,
      status: normalized.status,
      seats: normalized.seats,
      stripeCustomerId: customerId,
      stripeSubscriptionId: subscription.id,
      stripeCheckoutSessionId: session.id,
      currentPeriodEnd: normalized.currentPeriodEnd,
    };
  }

  private subscriptionMutation(subscription: Stripe.Subscription, deleted: boolean) {
    const values = this.subscriptionValues(subscription);
    return {
      kind: 'update' as const,
      stripeSubscriptionId: subscription.id,
      stripeCustomerId: values?.customerId ?? undefined,
      status: deleted ? 'canceled' as const : values?.status ?? 'incomplete' as const,
      seats: values?.seats,
      currentPeriodEnd: values?.currentPeriodEnd,
    };
  }

  private subscriptionValues(subscription: Stripe.Subscription): {
    customerId: string;
    status: SubscriptionStatus;
    seats: number;
    currentPeriodEnd: Date | null;
  } | null {
    const customerId = stringId(subscription.customer);
    if (!customerId) return null;
    const relevantItems = subscription.items.data.filter(
      (item) => stringId(item.price) === this.options.priceId,
    );
    if (relevantItems.length === 0) return null;
    const seats = relevantItems.reduce((sum, item) => sum + (item.quantity ?? 0), 0);
    if (!Number.isSafeInteger(seats) || seats < 1) return null;

    const raw = subscription as unknown as Record<string, unknown>;
    const itemPeriodEnds = relevantItems
      .map((item) => unixDate((item as unknown as Record<string, unknown>).current_period_end))
      .filter((date): date is Date => date !== null);
    const currentPeriodEnd = unixDate(raw.current_period_end)
      ?? itemPeriodEnds.sort((left, right) => right.getTime() - left.getTime())[0]
      ?? null;
    return { customerId, status: statusOf(subscription.status), seats, currentPeriodEnd };
  }
}
