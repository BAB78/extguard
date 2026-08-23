# ExtGuard Team architecture

ExtGuard Team adds optional licensing and sanitized report storage without changing the free
scanner. Free scans continue to work without an account, a license, or a network connection.

## Trust boundaries

1. **Free scanner:** reads installed extension files locally and produces the full finding view.
2. **Team client:** activates only after a user enters a Team license. It reduces scan results to
   fixed counters before making a network request.
3. **Team API:** validates subscriptions, enforces seat limits, accepts reduced reports, and talks
   to Stripe and PostgreSQL.
4. **Stripe:** hosts card collection and the billing portal. Card numbers never pass through the
   ExtGuard API.

## Data sent by Team

Team report uploads contain only:

- a schema version and scan timestamp;
- a product-scoped SHA-256 machine identifier;
- extension identifiers and display names;
- risk scores from 0 to 10;
- finding category, severity, and count;
- aggregate counts.

The report builder cannot accept source text, matched credential values, descriptions, file paths,
publishers, usernames, or the raw VS Code machine identifier.

## Activation lifecycle

1. Stripe confirms a paid or trialing subscription.
2. The API provisions a random license key. Only an encrypted copy and a keyed hash are stored.
3. The customer retrieves the key from the no-store checkout result page.
4. The extension sends the key and its product-scoped machine digest to the activation endpoint.
5. The API atomically reserves a seat and returns a short-lived, activation-bound JWT.
6. The extension stores the key and JWT only in VS Code `SecretStorage`.
7. Validation checks the current subscription and activation on every Team report upload.
8. Deactivation releases the seat and deletes local credentials.

## API surface

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| `GET` | `/health` | None | Process and database readiness. |
| `POST` | `/api/v1/checkout` | None, rate limited | Create a Stripe subscription Checkout Session. |
| `GET` | `/api/v1/checkout/session` | Stripe session ID | Return a paid license or a processing response. |
| `POST` | `/api/v1/webhooks/stripe` | Stripe signature | Apply billing events idempotently. |
| `POST` | `/api/v1/licenses/activate` | License key | Reserve a seat and issue an activation JWT. |
| `POST` | `/api/v1/licenses/validate` | Bearer JWT | Validate and rotate the activation JWT. |
| `POST` | `/api/v1/licenses/deactivate` | Bearer JWT | Release the current activation. |
| `POST` | `/api/v1/reports` | Bearer JWT | Store one sanitized scan report. |
| `GET` | `/api/v1/reports` | Bearer JWT | Read paginated reports for that license. |
| `POST` | `/api/v1/billing/portal` | Bearer JWT | Create a short-lived Stripe billing portal link. |

Errors use `{ "error": { "code": "...", "message": "..." } }`. License keys, JWTs,
Stripe secrets, webhook bodies, and report bodies must never be logged.

## Subscription state

Only Stripe `active` and `trialing` subscriptions are entitled. Past due, unpaid, canceled,
incomplete, expired, and paused subscriptions cannot validate or upload reports. Webhook event IDs
are stored before completion so retries cannot apply the same billing mutation twice.

## Free tier guarantee

Team failure must not break or limit free scanning. An unreachable API produces an unavailable Team
status while all local commands and sidebar findings continue working. Team code must not turn a
clean local scan into a network dependency.
