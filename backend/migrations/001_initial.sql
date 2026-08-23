CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE licenses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
  status text NOT NULL CHECK (status IN (
    'active', 'trialing', 'past_due', 'unpaid', 'canceled',
    'incomplete', 'incomplete_expired', 'paused'
  )),
  seats integer NOT NULL CHECK (seats BETWEEN 1 AND 500),
  stripe_customer_id text NOT NULL UNIQUE CHECK (stripe_customer_id LIKE 'cus_%'),
  stripe_subscription_id text NOT NULL UNIQUE CHECK (stripe_subscription_id LIKE 'sub_%'),
  stripe_checkout_session_id text UNIQUE CHECK (
    stripe_checkout_session_id IS NULL OR stripe_checkout_session_id LIKE 'cs_%'
  ),
  license_key_hash character(64) NOT NULL UNIQUE CHECK (license_key_hash ~ '^[a-f0-9]{64}$'),
  license_key_ciphertext text NOT NULL CHECK (license_key_ciphertext LIKE 'v1.%'),
  current_period_end timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE activations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  machine_id_hash character(64) NOT NULL CHECK (machine_id_hash ~ '^[a-f0-9]{64}$'),
  activated_at timestamptz NOT NULL DEFAULT now(),
  last_validated_at timestamptz NOT NULL DEFAULT now(),
  deactivated_at timestamptz,
  UNIQUE (license_id, machine_id_hash)
);

CREATE INDEX activations_active_license_idx
  ON activations (license_id)
  WHERE deactivated_at IS NULL;

CREATE TABLE reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id uuid NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  activation_id uuid NOT NULL REFERENCES activations(id) ON DELETE CASCADE,
  schema_version smallint NOT NULL CHECK (schema_version = 1),
  machine_id_hash character(64) NOT NULL CHECK (machine_id_hash ~ '^[a-f0-9]{64}$'),
  snapshot_at timestamptz NOT NULL,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX reports_license_created_idx ON reports (license_id, created_at DESC, id DESC);

CREATE TABLE stripe_events (
  stripe_event_id text PRIMARY KEY CHECK (stripe_event_id LIKE 'evt_%'),
  event_type text NOT NULL,
  stripe_created_at timestamptz NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX stripe_events_processed_idx ON stripe_events (processed_at);
