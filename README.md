# Payments Fraud & Abuse Detection Platform

[![CI](https://github.com/Agenda-X-PR/payments-detection/actions/workflows/ci.yml/badge.svg)](https://github.com/Agenda-X-PR/payments-detection/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)

A runnable, single-tenant **security demo** that receives webhook-like payment events, applies versioned detection rules, writes deduplicated alerts, and displays them in an operations dashboard. Includes a synthetic attack harness, a written threat model, and Docker Compose for the full local stack.

**This is not a payment processor.** It does not handle real funds, card data, or PII. See [Security boundaries and limitations](#security-boundaries-and-limitations).

---

## Contents

- [Architecture](#architecture)
- [Detection rules](#detection-rules)
- [Threat model](#threat-model)
- [Quick start](#quick-start)
- [Demo: attack scenarios](#demo-attack-scenarios)
- [API reference](#api-reference)
- [Observability](#observability)
- [Security boundaries and limitations](#security-boundaries-and-limitations)
- [Out of scope](#out-of-scope)
- [Project structure](#project-structure)
- [Development notes](#development-notes)
- [License](#license)

---

## Architecture

```
              [Harness / Provider]  (synthetic or sandbox only)
                       │
                       │  HTTP POST  /webhooks/{provider}
                       │  X-Webhook-Signature: HMAC-SHA256(raw body)
                       ▼
              ┌────────────────────┐
              │  alert-api         │  verifies HMAC, persists to Postgres,
              │  (FastAPI)         │  serves /alerts and /metrics
              └─────────┬──────────┘
                        │ SQL
                        ▼
              ┌────────────────────┐
              │  PostgreSQL 16     │  events, alerts, detector_state
              └─────────┬──────────┘
                        │ SQL
                        ▼
              ┌────────────────────┐
              │  detector          │  loads rules/*.yml, evaluates,
              │  (Python worker)   │  writes deduplicated alerts
              └─────────┬──────────┘
                        │
                        ▼
              ┌────────────────────┐
              │  dashboard         │  Nginx serves static UI,
              │  (Nginx)           │  proxies /api/* → alert-api
              └────────────────────┘
```

The stack runs with a single `docker compose up --build`. Redis is provisioned for future stateful detections; the current rules use durable Postgres queries so restarts do not lose detection windows.

---

## Detection rules

Four versioned rules live in [`rules/`](rules/). Each is a YAML file with a matching fixture JSON that proves the trigger and non-trigger cases.

| Rule ID | Severity | Detects |
| :--- | :--- | :--- |
| `pay-velocity-001` | high | More than 10 payment events from one source IP in a rolling 60-second window |
| `pay-replay-001` | critical | The same `(provider, event_id)` observed with different signatures or body hashes |
| `pay-sigfail-001` | high | More than 5 invalid-signature events from one source IP in 60 seconds |
| `pay-amount-001` | medium | Successful payment is non-positive, or exceeds trailing 24h mean + 3σ (minimum 10 samples) |

### Rule format

Rules use **Sigma-inspired YAML with project-specific `aggregation` extensions** — they are not directly executable by a generic Sigma engine. That distinction is intentional: the base spec has no portable syntax for sliding windows or baseline statistics, so we extend it and document the extension in each file.

```yaml
# rules/velocity-burst.yml
title: Payment Velocity Burst
id: pay-velocity-001
level: high
description: More than 10 payment events from the same source IP in a rolling 60-second window.
aggregation:
  kind: count_by
  field: source_ip
  window_seconds: 60
  threshold: 10
condition: payment_event
falsepositives:
  - Legitimate bulk payment processors
```

### Evaluation strategy

| Rule kind | Implementation |
| :--- | :--- |
| `count_by` | SQL group over `events` filtered by rolling window |
| `count_invalid_by` | Same, filtered to `signature_valid = false` |
| `replay_by` | Group by `(provider, event_id)`; fire when distinct signature or payload hash > 1 |
| `amount_baseline` | 24h sample mean/stddev from `events`; z-score threshold |

Alerts are deduplicated by `(rule_id, fingerprint)` where the fingerprint includes the detection window bucket, so the same attack does not spam the queue every poll.

---

## Threat model

Uses **STRIDE**. Attacker controls request bodies, event IDs, signature headers, and request frequency. The demo assumes the application host and Docker network are trusted and single-tenant.

### Trust boundaries

```
[Harness / Provider] ──HTTP(S)──▶ [webhook-ingest API] ──SQL──▶ [PostgreSQL]
   untrusted event data              HMAC check                     │
                                       │                             ▼
                                [detector worker] ──────────▶ [alerts table]
                                       │                             │
                                [optional model*]              [dashboard/API]
```

\* No model call is enabled by default. Without `GROQ_API_KEY`, the API serves deterministic rule-based explanations.

### STRIDE analysis

| Category | Threat | In scope | Mitigation / residual risk |
|---|---|:---:|---|
| **Spoofing** | Forged provider webhook | Yes | HMAC-SHA256 over exact raw body; source IP is informational only. Demo secret must be replaced. Provider-specific signature schemes are out of scope. |
| **Tampering** | Amount or event fields altered in transit | Yes | HTTPS expected at any non-local boundary; HMAC detects body changes. Compose binds ports to loopback. |
| **Repudiation** | Sender disputes content or timing | Partial | Persisted rows retain signature status, body hash, and server timestamp. Not cryptographically immutable — DB admins can alter records. |
| **Information disclosure** | PII or secrets in logs, alert details, or model context | Yes | No request-body logging; payload key-name redaction in detail responses; bounded values. Model calls disabled by default; when enabled, only rule ID, severity, and numeric context are sent — never payloads or identifiers. |
| **Denial of service** | Flood exhausts API, DB, or detector | Yes | 256 KB body cap, local-only port binding, bounded detector query horizon. Production needs rate limiting, backpressure, and capacity planning. |
| **Elevation of privilege** | Prompt injection via log payload causes unsafe model behavior | Partial | Current explanation is deterministic. Payload is treated as untrusted. An optional LLM path would need isolated structured prompting, output validation, and adversarial tests before activation. |

### Explicitly out of scope

Insider and physical threats, provider-side compromise, multi-tenant isolation, production PCI-DSS compliance, real gateway integrations, public unauthenticated deployment, formal immutability guarantees, and ML-based fraud scoring. **The dashboard has no authentication** — keep it on loopback or a private, authenticated network.

---

## Quick start

Requirements: **Docker Engine** and **Docker Compose v2**.

```bash
# 1. Configure
cp .env.example .env
# edit .env and set a private WEBHOOK_SECRET (32+ random characters)

# 2. Run the full stack
docker compose up --build

# 3. Open the dashboard
#    http://localhost:5173
#    API docs: http://localhost:8002/docs
#    Metrics:  http://localhost:8002/metrics
```

The first build takes 3–5 minutes. On subsequent runs, `docker compose up` starts in seconds.

### Environment variables

| Variable | Required | Purpose |
| :--- | :---: | :--- |
| `POSTGRES_PASSWORD` | yes | Postgres password (default is dev-only; change for any shared host) |
| `WEBHOOK_SECRET` | yes | HMAC-SHA256 signing secret shared with the harness |
| `GROQ_API_KEY` | no | Enables LLM-generated alert explanations via Groq |
| `GROQ_MODEL` | no | Model name for Groq (default: `openai/gpt-oss-120b`) |

---

## Demo: attack scenarios

The harness submits **synthetic events to the local API only**. Never point it at a real payment endpoint.

```bash
# Create a virtualenv and install the harness dependencies
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r services/test-harness/requirements.txt

# Load the same secret the stack is using
set -a; source .env; set +a     # Windows: $env:WEBHOOK_SECRET="..."
export PYTHONPATH=services/test-harness
```

Then run any scenario:

| Scenario | Command | Expected result |
| :--- | :--- | :--- |
| Baseline traffic | `python -m harness normal --rate 20/min --duration 15s` | No alerts (unless a rule genuinely fires) |
| Velocity burst | `python -m harness attack velocity --count 15 --window 10s` | `pay-velocity-001` (high) with source IP and count |
| Replay | `python -m harness attack replay --event-id evt_demo_replay` | `pay-replay-001` (critical) with distinct-signature context |
| Invalid signatures | `python -m harness attack sigfail --count 6` | `pay-sigfail-001` (high) with source IP and count |
| Amount anomaly | `python -m harness attack amount --value 10000000` | `pay-amount-001` (medium) with baseline context |

Detection latency is normally one detector poll interval (2s) plus query time. The detector logs compact JSON on each alert creation. Inspect the dashboard at `http://localhost:5173` or query `http://localhost:8002/alerts` directly.

---

## API reference

Full OpenAPI spec at `http://localhost:8002/docs`. Key endpoints:

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `POST` | `/webhooks/{provider}` | Signed webhook ingest; verifies HMAC, persists event |
| `GET` | `/alerts` | List alerts, optional `?status=` filter |
| `GET` | `/alerts/{id}` | Full alert detail including linked event evidence |
| `POST` | `/alerts/{id}/explain` | Generate or retrieve AI explanation |
| `PATCH` | `/alerts/{id}` | Update status (`open` / `acknowledged` / `resolved`) |
| `GET` | `/health` | Readiness probe |
| `GET` | `/metrics` | Prometheus text format |

### Webhook contract

The server expects the following headers on `POST /webhooks/{provider}`:

| Header | Required | Notes |
| :--- | :---: | :--- |
| `Content-Type: application/json` | yes | |
| `X-Webhook-Signature` | yes | Hex-encoded HMAC-SHA256 of the raw body |
| `X-Event-Id` | yes | Provider event ID (used for replay detection) |
| `X-Event-Type` | yes | e.g. `payment.success`, `payment.failed` |
| `X-Source-IP` | no | Recorded for velocity rules; informational only |

---

## Observability

### Prometheus metrics

`GET /metrics` exposes:

| Metric | Type | Meaning |
| :--- | :--- | :--- |
| `payments_events_received_total{provider,event_type}` | counter | Accepted events since process start |
| `payments_alerts_fired_total{rule_id,severity}` | counter | Persisted alerts by rule and severity |
| `payments_llm_calls_total{provider,status}` | counter | LLM requests (zero when using deterministic fallback) |

The event counter is **process-local** and resets on restart. Alert totals are read from the database and reflect persisted state.

### Logs

All services log JSON lines. The detector emits `event=alerts_fired` and `event=detector_error` records with `rule_id`, `duration_ms`, and `severity` as top-level fields. Raw payloads, signature headers, secrets, and personal data are never logged.

For production monitoring, add durable event counters, request-latency histograms, queue lag, database saturation, rate-limit outcomes, and alert-delivery failure tracking.

---

## Security boundaries and limitations

This is a **portfolio and development demo**, not production payment infrastructure.

- **No user authentication** on dashboard or API. Bind only to localhost, or place behind an authenticated private network (VPN, reverse proxy with auth, or cloud IAM).
- **Secrets must be changed** from development defaults before exposing the service beyond your machine.
- **HMAC verification uses the exact raw request body.** Production deployments need provider-specific canonicalization.
- **No TLS termination** is included. Any non-loopback deployment must terminate TLS at a reverse proxy.
- **No retention, backup, or migration tooling** beyond the initial schema.
- **No rate limiting** on webhook ingest.
- **Do not send cardholder data or PII** to this service. The optional LLM path sends only rule ID, severity, and numeric context — never payloads or identifiers — but prompt filtering is not a security guarantee.

---

## Out of scope

Explicit decisions to not build, and why:

- **Authentication** — assumes network isolation; a real deployment would need SSO or API keys
- **Multi-tenant isolation** — single-tenant demo
- **Real provider integrations** — synthetic events only; sandbox integration is a separate exercise
- **ML-based detection** — rules are the point; ML would obscure the detection-engineering signal
- **Kubernetes** — Docker Compose is the right level for a portfolio demo
- **Terraform / IaC** — Compose is declarative enough for a single-host deploy
- **PCI-DSS compliance** — not a payment processor
- **Alert acknowledgement UI** — the DB field exists and the API supports `PATCH`, but the dashboard does not surface a resolved-state view

---

## Project structure

```
.
├── docker-compose.yml
├── .env.example
├── migrations/
│   └── 001_init.sql                  # Idempotent schema
├── rules/
│   ├── velocity-burst.yml
│   ├── replay-attack.yml
│   ├── signature-failure-spike.yml
│   ├── amount-anomaly.yml
│   └── test-fixtures/                # Positive + negative cases per rule
│       ├── velocity-burst.json
│       ├── replay-attack.json
│       ├── signature-failure-spike.json
│       └── amount-anomaly.json
├── services/
│   ├── alert-api/                    # FastAPI webhook ingest + alert API
│   │   ├── main.py
│   │   ├── requirements.txt
│   │   ├── test_security.py
│   │   └── Dockerfile
│   ├── detector/                     # Python rule-evaluation worker
│   │   ├── main.py
│   │   └── Dockerfile
│   ├── dashboard/                    # Static UI served by Nginx
│   │   ├── index.html
│   │   ├── app.js
│   │   ├── style.css
│   │   ├── nginx.conf
│   │   └── Dockerfile
│   └── test-harness/                 # Local synthetic traffic generator
│       ├── harness/
│       │   ├── __init__.py
│       │   └── __main__.py
│       └── requirements.txt
└── .github/
    └── workflows/
        └── ci.yml                    # Compile check + YAML validation + tests
```

---

## Development notes

The Compose stack was authored and structurally validated (YAML syntax, Python compile check across all services, schema migration review, and CI) but **not executed end-to-end on the authoring machine** because Docker was not installed locally.

Anyone with Docker Engine and Compose v2 can run `docker compose up --build` to verify the full pipeline. If you find a configuration issue, please open an issue on the repository — that feedback is welcome.

### Local development without Docker

If you want to develop a single service without the full stack:

1. Run Postgres locally (`docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=dev postgres:16-alpine`)
2. Apply the schema: `psql -f migrations/001_init.sql`
3. Start the alert-api: `cd services/alert-api && uvicorn main:app --reload`
4. Start the detector: `cd services/detector && python main.py`

The dashboard is static; open `services/dashboard/index.html` after configuring the API URL in `app.js`.

---

## License

MIT — see `LICENSE` for details. If you don't see a `LICENSE` file in the repository yet, add one; the MIT text is standard and takes 30 seconds.