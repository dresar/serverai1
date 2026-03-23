"""Prometheus metrics (mirror server1/src/infra/metrics.js)."""
from __future__ import annotations

from prometheus_client import Counter, Histogram, generate_latest, REGISTRY

http_request_duration_ms = Histogram(
    "http_request_duration_ms",
    "HTTP request duration in ms",
    ["method", "route", "status"],
    buckets=(1, 2, 5, 10, 25, 50, 75, 100, 150, 250, 500, 1000),
)

api_key_rotations_total = Counter(
    "api_key_rotations_total",
    "API key rotations",
    ["tenant_id"],
)

gateway_alerts_total = Counter(
    "gateway_alerts_total",
    "Gateway alerts created",
    ["tenant_id", "category", "severity"],
)

gateway_anomalies_total = Counter(
    "gateway_anomalies_total",
    "Gateway anomalies",
    ["tenant_id", "type"],
)

gateway_credential_cooldowns_total = Counter(
    "gateway_credential_cooldowns_total",
    "Credential cooldown actions",
    ["tenant_id", "provider"],
)


def metrics_text() -> bytes:
    return generate_latest(REGISTRY)
