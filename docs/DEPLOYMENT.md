# ExtGuard Team deployment

This guide keeps Stripe in test mode until the complete payment and licensing matrix passes.
Do not place any secret in this repository or in `landing/config.js`.

## Prerequisites

- A Stripe account with test mode enabled.
- A Railway account connected to `BAB78/extguard`.
- The Team code merged into the deployment branch.
- A public HTTPS origin for the landing files.
- Owner and qualified legal review of the preliminary privacy policy and terms before public checkout.

Railway should contain three services in one project:

1. PostgreSQL.
2. `extguard-api`, sourced from the GitHub repository with Root Directory `/backend`.
3. An optional static landing service, or another static host for `landing/`.

Railway documents the root directory requirement for isolated monorepos at
<https://docs.railway.com/deployments/monorepo>.

## 0. Run the local gate first

Before touching a hosted account, confirm the container sequence works on your machine. This
boots a throwaway PostgreSQL, runs the migration exactly as the Dockerfile CMD does, starts the
compiled server, and polls the same `/health` path Railway is configured to use:

```bash
cd backend
npm test        # 20 tests, including the real-database suite
npm run smoke   # migrate, boot, healthcheck, shutdown
```

Both must pass before you deploy. Nothing here contacts Stripe or Railway, and no account is
needed. Graceful shutdown is skipped on Windows because Windows has no real SIGTERM; confirm it
from the Railway logs on your first redeploy instead.

## 1. Create the Stripe test product

In Stripe test mode:

1. Create a product named `ExtGuard Team`.
2. Add a recurring monthly price of USD 9 per unit.
3. Copy the `price_...` identifier.
4. Enable the Stripe customer portal for subscription cancellation and seat quantity changes.

Do not create live objects until the test flow passes. Test and live product IDs, prices, API keys,
and webhook secrets are separate sets and must never be mixed.

### Managed Payments requires a product tax code

If Managed Payments is enabled (Stripe acts as merchant of record and handles VAT), every
product must carry a `tax_code` or Checkout fails outright with:

```
Invalid line_items[0]: the product tax code is missing.
```

ExtGuard Team uses **`txcd_10103101`** (Software as a service, electronic download, business
use). That is the correct classification because the extension is downloaded by the buyer and
the Team tier is a cloud subscription sold to companies. `txcd_10103001` is the wrong one: it
explicitly covers SaaS where the buyer downloads nothing.

```bash
stripe products update <product_id> --tax-code=txcd_10103101
```

Verified against a live sandbox purchase: 3 seats at $9 charged $27.00, licence provisioned,
seat limit enforced at 3, and cancellation revoked access immediately.

## 2. Create Railway services

1. Create an empty Railway project.
2. Add PostgreSQL.
3. Add an empty service named `extguard-api`.
4. Connect `BAB78/extguard` as its source.
5. Set Root Directory to `/backend`.
6. Generate a public HTTPS domain.

The `backend/Dockerfile` compiles TypeScript, runs database migrations before server startup, and
runs as a non-root user. `backend/railway.json` selects the Dockerfile, checks `/health`, and
restarts failed processes.

## 3. Configure API variables

Set these on the API service:

| Variable | Value |
|---|---|
| `NODE_ENV` | `production` |
| `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` |
| `DATABASE_SSL` | `true` |
| `STRIPE_SECRET_KEY` | Stripe test secret key during testing |
| `STRIPE_WEBHOOK_SECRET` | Added in the next section |
| `STRIPE_PRICE_ID` | The test recurring price ID |
| `CHECKOUT_SUCCESS_URL` | `https://LANDING/success.html?session_id={CHECKOUT_SESSION_ID}` |
| `CHECKOUT_CANCEL_URL` | `https://LANDING/cancel.html` |
| `BILLING_PORTAL_RETURN_URL` | `https://LANDING/` |
| `CORS_ALLOWED_ORIGINS` | Exact comma-separated landing origins |
| `JWT_SECRET` | Independent random value, at least 32 characters |
| `LICENSE_KEY_PEPPER` | Different independent random value, at least 32 characters |
| `LICENSE_ENCRYPTION_KEY` | Base64 encoding of exactly 32 random bytes |
| `JWT_TTL_SECONDS` | `86400` or a shorter approved lifetime |
| `TRUST_PROXY` | `1` on Railway |
| `LOG_LEVEL` | `info` |

Generate independent secrets on a trusted machine. Keep the outputs in a password manager and paste
them directly into Railway:

```powershell
& 'C:\Program Files\nodejs\node.exe' -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
& 'C:\Program Files\nodejs\node.exe' -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
& 'C:\Program Files\nodejs\node.exe' -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Use the first two values for `JWT_SECRET` and `LICENSE_KEY_PEPPER`. Use the final value for
`LICENSE_ENCRYPTION_KEY`.

## 4. Configure the Stripe webhook

Create a Stripe webhook destination pointing to:

```text
https://API_DOMAIN/api/v1/webhooks/stripe
```

Subscribe only to the events used by the backend:

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.paid`
- `invoice.payment_failed`

Copy the endpoint signing secret to Railway as `STRIPE_WEBHOOK_SECRET`, then redeploy. Stripe requires
signature verification against the unmodified raw request body. The backend mounts this route before
the JSON parser for that reason.

## 5. Configure the landing page

Deploy the contents of `landing/` to an HTTPS static host. In the deployed copy of
`landing/config.js`, set only the public API origin:

```javascript
window.EXTGUARD_CONFIG = Object.freeze({
  apiBaseUrl: "https://API_DOMAIN",
});
```

This value is public configuration, not a secret. Keep the repository value empty until the hosted
test environment is healthy. The checkout button remains disabled when the value is empty.

## 6. Verify deployment

1. Confirm `GET /health` returns a healthy database result.
2. Confirm an origin not listed in `CORS_ALLOWED_ORIGINS` is rejected.
3. Complete every case in [PAYMENT_TESTING.md](PAYMENT_TESTING.md).
4. Inspect Railway logs and confirm no keys, JWTs, emails, Stripe payloads, or report bodies appear.
5. Back up PostgreSQL and test restoration before accepting live payments.
6. Record approval of the deployed privacy policy and terms. The repository drafts are not legal advice.

## 7. Move to live mode

Create a live Stripe price and live webhook. Replace all Stripe test variables together, repeat the
complete test matrix with a controlled live purchase, then enable public checkout. Do not change only
one Stripe variable because mixed test and live credentials fail in misleading ways.

## Rollback

If activation or billing fails after launch:

1. Set the deployed landing `apiBaseUrl` to an empty string to disable new checkout immediately.
2. Keep the free extension available.
3. Roll the API service back to the last healthy Railway deployment.
4. Leave Stripe webhooks enabled so subscription state is not lost.
5. Reconcile failed webhook events before re-enabling checkout.
