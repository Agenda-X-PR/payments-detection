"""Payguard Alert API: webhook ingest, alert query, and AI explanation."""

import hashlib
import hmac
import json
import os
import re
import urllib.request
from typing import Any

import psycopg
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from psycopg.rows import dict_row
from pydantic import BaseModel

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://app:dev@localhost/payments")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "dev-only-change-me")
MAX_BODY = 256 * 1024

SENSITIVE_KEYS = {
    "card_number", "card", "pan", "cvv", "cvc", "token", "secret",
    "password", "authorization", "api_key", "apikey", "access_token",
    "refresh_token", "session_token", "ssn", "pin",
}

INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions?"),
    re.compile(r"(?i)system\s*:"),
    re.compile(r"(?i)you\s+are\s+now"),
    re.compile(r"(?i)reveal\s+(your\s+)?(system\s+)?prompt"),
    re.compile(r"(?i)disregard\s+(all\s+)?(previous|prior)"),
]

RULE_LABELS = {
    "pay-velocity-001": "velocity burst",
    "pay-replay-001": "replayed payment event",
    "pay-sigfail-001": "signature failure spike",
    "pay-amount-001": "amount anomaly",
}

app = FastAPI(title="Payguard Alert API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


def db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def redact(value: Any) -> Any:
    """Redact sensitive keys and injection markers; truncate long strings."""
    if isinstance(value, str):
        out = value
        for pattern in INJECTION_PATTERNS:
            out = pattern.sub("[REDACTED]", out)
        return out[:2000]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and k.lower() in SENSITIVE_KEYS:
                out[k] = "[REDACTED]"
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def fallback_explanation(alert: dict) -> str:
    """Deterministic explanation from rule metadata only. Never includes payload text."""
    rule_id = alert.get("rule_id", "")
    label = RULE_LABELS.get(rule_id, "detection")
    return (
        f"The {label} rule fired for this alert (rule {rule_id}). "
        f"Review the linked event evidence for details and correlate with recent activity "
        f"from the same source."
    )


def model_explanation(alert: dict) -> str:
    """Call Groq with only rule_id, severity, and numeric context. No payload or identifiers."""
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        return fallback_explanation(alert)
    model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

    context = alert.get("context", {}) or {}
    numeric_context = {k: v for k, v in context.items() if isinstance(v, (int, float))}
    prompt_context = {
        "rule_id": alert.get("rule_id", ""),
        "severity": alert.get("severity", ""),
        "context": numeric_context,
    }
    system = (
        "You are a security analyst explaining a detection alert to a developer. "
        "Write 2-3 sentences. Reference the rule's pattern. Give one concrete next step. "
        "Do not invent details not present in the provided context."
    )
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(prompt_context)},
        ],
        "temperature": 0.2,
        "max_tokens": 300,
    }
    request = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read())
            return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return fallback_explanation(alert)
    """Call Groq with only rule_id, severity, and numeric context. No payload or identifiers."""
    if not GROQ_API_KEY:
        return fallback_explanation(alert)

    context = alert.get("context", {}) or {}
    numeric_context = {k: v for k, v in context.items() if isinstance(v, (int, float))}
    prompt_context = {
        "rule_id": alert.get("rule_id", ""),
        "severity": alert.get("severity", ""),
        "context": numeric_context,
    }
    system = (
        "You are a security analyst explaining a detection alert to a developer. "
        "Write 2-3 sentences. Reference the rule's pattern. Give one concrete next step. "
        "Do not invent details not present in the provided context."
    )
    body = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(prompt_context)},
        ],
        "temperature": 0.2,
        "max_tokens": 300,
    }
    request = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read())
            return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return fallback_explanation(alert)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/webhooks/{provider}")
async def ingest(
    provider: str,
    request: Request,
    x_webhook_signature: str = Header(..., alias="X-Webhook-Signature"),
    x_event_id: str = Header(..., alias="X-Event-Id"),
    x_event_type: str = Header(..., alias="X-Event-Type"),
    x_source_ip: str = Header("127.0.0.1", alias="X-Source-IP"),
):
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(413, "Body too large")
    expected = hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(expected, x_webhook_signature)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")
    amount = payload.get("amount") if isinstance(payload, dict) else None
    currency = payload.get("currency") if isinstance(payload, dict) else None
    order_id = payload.get("order_id") if isinstance(payload, dict) else None
    payload_hash = hashlib.sha256(raw).hexdigest()
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO events(provider,event_id,event_type,source_ip,amount,currency,
                                  order_id,signature,signature_valid,payload,payload_hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s) RETURNING id""",
            (provider, x_event_id, x_event_type, x_source_ip, amount, currency, order_id,
             x_webhook_signature, valid, json.dumps(payload), payload_hash),
        )
        event_id = cur.fetchone()["id"]
    return {"accepted": True, "event_id": str(event_id), "signature_valid": valid}


@app.get("/alerts")
def list_alerts(status: str | None = None):
    with db() as conn, conn.cursor() as cur:
        if status:
            cur.execute(
                "SELECT * FROM alerts WHERE status=%s ORDER BY triggered_at DESC LIMIT 200",
                (status,),
            )
        else:
            cur.execute("SELECT * FROM alerts ORDER BY triggered_at DESC LIMIT 200")
        return cur.fetchall()


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM alerts WHERE id=%s", (alert_id,))
        alert = cur.fetchone()
        if not alert:
            raise HTTPException(404, "Alert not found")
        cur.execute("SELECT * FROM events WHERE id = ANY(%s)", (alert["event_ids"],))
        alert["events"] = cur.fetchall()
        return alert


class StatusUpdate(BaseModel):
    status: str


@app.patch("/alerts/{alert_id}")
def update_alert(alert_id: str, update: StatusUpdate):
    if update.status not in ("open", "acknowledged", "resolved"):
        raise HTTPException(400, "Invalid status")
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE alerts SET status=%s WHERE id=%s RETURNING *",
            (update.status, alert_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Alert not found")
        return row


@app.post("/alerts/{alert_id}/explain")
def explain_alert(alert_id: str):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM alerts WHERE id=%s", (alert_id,))
        alert = cur.fetchone()
        if not alert:
            raise HTTPException(404, "Alert not found")
        if alert.get("ai_explanation"):
            return {"explanation": alert["ai_explanation"]}
        text = model_explanation(alert)
        cur.execute(
            "UPDATE alerts SET ai_explanation=%s WHERE id=%s", (text, alert_id)
        )
        return {"explanation": text}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    lines = []
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT provider, event_type, COUNT(*) AS n FROM events GROUP BY 1,2"
        )
        for row in cur.fetchall():
            lines.append(
                f'payments_events_received_total'
                f'{{provider="{row["provider"]}",event_type="{row["event_type"]}"}} {row["n"]}'
            )
        cur.execute(
            "SELECT rule_id, severity, COUNT(*) AS n FROM alerts GROUP BY 1,2"
        )
        for row in cur.fetchall():
            lines.append(
                f'payments_alerts_fired_total'
                f'{{rule_id="{row["rule_id"]}",severity="{row["severity"]}"}} {row["n"]}'
            )
    lines.append('payments_llm_calls_total{provider="groq",status="ok"} 0')
    return "\n".join(lines) + "\n"