CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), provider text NOT NULL,
  event_id text NOT NULL, event_type text NOT NULL, source_ip inet NOT NULL,
  amount numeric(20,4), currency char(3), order_id text, signature text NOT NULL,
  signature_valid boolean NOT NULL, payload jsonb NOT NULL,
  payload_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS events_created_at_idx ON events(created_at);
CREATE INDEX IF NOT EXISTS events_ip_created_idx ON events(source_ip, created_at);
CREATE INDEX IF NOT EXISTS events_provider_event_idx ON events(provider, event_id);
CREATE TABLE IF NOT EXISTS alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), rule_id text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical','high','medium','low')),
  triggered_at timestamptz NOT NULL DEFAULT now(), event_ids uuid[] NOT NULL,
  context jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved')),
  ai_explanation text, fingerprint text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS alerts_triggered_at_idx ON alerts(triggered_at DESC);
CREATE TABLE IF NOT EXISTS detector_state (key text PRIMARY KEY, value text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
