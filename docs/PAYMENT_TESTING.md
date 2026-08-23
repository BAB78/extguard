# Stripe test-mode release gate

Public checkout stays disabled until every case below passes against the hosted Railway test
environment. Use Stripe test mode and Stripe's documented test cards from
<https://docs.stripe.com/testing>.

## Baseline

- [ ] `/health` reports a healthy database.
- [ ] The landing origin is allowed and a different origin is rejected by CORS.
- [ ] Invalid checkout email and seat values return validation errors.
- [ ] API logs contain no license keys, JWTs, report bodies, or Stripe request bodies.

## Successful purchase

- [ ] Start Checkout for one seat.
- [ ] Complete payment with Stripe test card `4242 4242 4242 4242`, any future expiry, and any CVC.
- [ ] Confirm Stripe delivers `checkout.session.completed` successfully.
- [ ] Confirm the success page receives the session ID and displays one license key.
- [ ] Refresh the success page and confirm the same paid license is returned without creating another.
- [ ] Confirm responses use `Cache-Control: no-store`.

## Seat enforcement

- [ ] Activate the license on device A.
- [ ] Validate the returned token and upload one sanitized report.
- [ ] Attempt activation on device B and confirm the one-seat license is rejected.
- [ ] Deactivate device A, then activate device B successfully.
- [ ] Repeat activation on device B and confirm it is idempotent and does not consume another seat.

## Report privacy

- [ ] Confirm the stored report contains only the schema documented in [TEAM.md](TEAM.md).
- [ ] Confirm no source text, detected secret value, description, username, or absolute path is present.
- [ ] Confirm a malformed or oversized report is rejected.
- [ ] Confirm an expired, altered, or deactivated JWT cannot upload or list reports.

## Subscription changes

- [ ] Open the Stripe customer portal through the authenticated endpoint.
- [ ] Increase quantity and confirm the webhook updates the seat limit.
- [ ] Simulate a failed renewal and confirm Team validation stops for the resulting inactive status.
- [ ] Restore payment and confirm validation resumes.
- [ ] Cancel the subscription and confirm activation, validation, reports, and portal access follow the
      intended cancellation policy.

## Webhook safety

- [ ] Send a request with no Stripe signature and confirm HTTP 400.
- [ ] Send a request with an invalid signature and confirm HTTP 400.
- [ ] Replay the same signed event and confirm the database applies it once.
- [ ] Deliver subscription events out of order and confirm older events do not overwrite newer state.
- [ ] Confirm unhandled valid Stripe events return success without changing entitlement.

## Failure recovery

- [ ] Stop PostgreSQL and confirm readiness fails without logging the connection string.
- [ ] Restore PostgreSQL and confirm the API recovers.
- [ ] Interrupt the success-page request before its webhook arrives and confirm a retry returns either
      processing or the provisioned license.
- [ ] Roll back one Railway deployment and confirm migrations remain compatible.

## Launch decision

Checkout may be enabled only when all boxes pass, the test evidence is retained, database backups are
configured, the exact live Stripe objects have been verified, and the owner has approved the deployed
privacy policy and terms with qualified legal advice where appropriate. The repository legal pages are
preliminary drafts. A successful unit test suite alone is not a payment launch approval.
