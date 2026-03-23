"""Port server1/src/services/observability.js (inti)."""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from app.db import Database
from app.metrics_prometheus import gateway_alerts_total, gateway_anomalies_total, gateway_credential_cooldowns_total

BURST_THRESHOLD_WARNING = 80
BURST_THRESHOLD_CRITICAL = 160
LEAK_DOMAIN_THRESHOLD = 2
PROVIDER_INCIDENT_THRESHOLD = 5
PROVIDER_OUTAGE_THRESHOLD = 8
RATE_LIMIT_COOLDOWN_SECONDS = 120
OUTAGE_COOLDOWN_SECONDS = 60


def parse_json_safe(value: Any, fallback: dict | None = None) -> dict:
    if fallback is None:
        fallback = {}
    try:
        if value is None:
            return fallback
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        pass
    return fallback


def trim_message(value: Any, max_len: int = 240) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    return text[: max_len - 1] + "…" if len(text) > max_len else text


def classify_error_type(
    *,
    status_code: int | None,
    error_message: str = "",
    rate_limited: bool = False,
) -> str:
    msg = str(error_message or "").lower()
    if not status_code or status_code < 400:
        return "success"
    if rate_limited or status_code == 429 or "rate limit" in msg:
        return "provider_rate_limit"
    if "timeout" in msg:
        return "upstream_timeout"
    if "api key not valid" in msg or "invalid api key" in msg or "invalid signature" in msg:
        return "provider_auth"
    if "credential" in msg and "not found" in msg:
        return "credential_missing"
    if status_code in (401, 403):
        return "auth_rejected"
    if status_code >= 500:
        return "upstream_unavailable"
    return "client_error"


def to_json(value: Any) -> str:
    return json.dumps(value if value is not None else {})


def push_unique(items: list, value: Any) -> list:
    if value and value not in items:
        items.append(value)
    return items


@dataclass
class ObsContext:
    db: Database
    gateway_log_mode: str
    ws_broadcast: Callable[[str, dict], Awaitable[None]] | None


async def upsert_provider_credential_stats(db: Database, *, credential_id: str | None, success: bool) -> None:
    if not credential_id:
        return
    try:
        await db.query(
            """update public.provider_credentials
               set total_requests = total_requests + 1,
                   failed_requests = failed_requests + $2
               where id = $1""",
            (credential_id, 0 if success else 1),
        )
    except Exception:
        pass


async def get_recent_api_key_stats(db: Database, *, api_key_id: str) -> dict:
    r = await db.query(
        """select count(*)::int as requests,
                  count(distinct origin_domain) filter (where origin_domain is not null and origin_domain <> '')::int as domains
             from public.gateway_request_logs
            where api_key_id = $1 and created_at >= now() - interval '10 minutes'""",
        (api_key_id,),
    )
    row = r.rows[0] if r.rows else {}
    return {"requests": int(row.get("requests") or 0), "domains": int(row.get("domains") or 0)}


async def get_recent_burst_count(db: Database, *, api_key_id: str) -> int:
    r = await db.query(
        """select count(*)::int as requests from public.gateway_request_logs
            where api_key_id = $1 and created_at >= now() - interval '5 seconds'""",
        (api_key_id,),
    )
    return int(r.rows[0].get("requests") or 0) if r.rows else 0


async def get_provider_error_stats(db: Database, *, tenant_id: str, provider: str) -> dict:
    r = await db.query(
        """select count(*)::int as errors,
                  count(*) filter (where status_code = 429)::int as rate_limited,
                  count(*) filter (where status_code >= 500)::int as server_errors
             from public.gateway_request_logs
            where tenant_id = $1 and provider = $2 and status_code >= 400
              and created_at >= now() - interval '2 minutes'""",
        (tenant_id, provider),
    )
    row = r.rows[0] if r.rows else {}
    return {
        "errors": int(row.get("errors") or 0),
        "rateLimited": int(row.get("rate_limited") or 0),
        "serverErrors": int(row.get("server_errors") or 0),
    }


async def reactivate_expired_credential_cooldowns(db: Database, *, user_id: str, provider: str | None = None) -> None:
    params: list = [user_id]
    sql = """update public.provider_credentials
        set status = 'active', cooldown_until = null
      where user_id = $1 and status = 'cooldown'
        and cooldown_until is not null and cooldown_until <= now()"""
    if provider:
        params.append(provider)
        sql += " and provider_name = $2"
    try:
        await db.query(sql, tuple(params))
    except Exception:
        pass


async def get_provider_availability(db: Database, *, user_id: str, provider: str) -> dict:
    await reactivate_expired_credential_cooldowns(db, user_id=user_id, provider=provider)
    r = await db.query(
        """select count(*)::int as total,
                  count(*) filter (where status = 'active')::int as active,
                  count(*) filter (where status = 'cooldown')::int as cooldown
             from public.provider_credentials
            where user_id = $1 and provider_name = $2""",
        (user_id, provider),
    )
    row = r.rows[0] if r.rows else {}
    return {
        "total": int(row.get("total") or 0),
        "active": int(row.get("active") or 0),
        "cooldown": int(row.get("cooldown") or 0),
    }


def detect_leak_risk(*, burst_count: int, distinct_domains: int, recent_requests: int) -> str | None:
    if burst_count >= BURST_THRESHOLD_CRITICAL and distinct_domains >= LEAK_DOMAIN_THRESHOLD:
        return "critical"
    if (
        burst_count >= BURST_THRESHOLD_WARNING
        and distinct_domains >= LEAK_DOMAIN_THRESHOLD
        and recent_requests >= BURST_THRESHOLD_WARNING
    ):
        return "warning"
    return None


def get_remediation_policy(*, error_type: str, anomaly_types: list) -> str:
    if "possible_api_key_leak" in anomaly_types:
        return "rotate_api_key"
    if error_type in ("provider_rate_limit", "upstream_timeout", "upstream_unavailable"):
        return "cooldown_credential"
    return "none"


async def create_alert(ctx: ObsContext, inp: dict) -> dict | None:
    metadata = inp.get("metadata") or {}
    dedupe_key = inp.get("dedupeKey")
    tenant_id = inp["tenantId"]
    if dedupe_key:
        ex = await ctx.db.query(
            """select id, metadata from public.gateway_alerts
                where tenant_id = $1 and dedupe_key = $2 and status = 'active'
                  and created_at >= now() - interval '15 minutes'
                order by created_at desc limit 1""",
            (tenant_id, dedupe_key),
        )
        if ex.rows:
            existing = ex.rows[0]
            previous = parse_json_safe(existing.get("metadata"), {})
            occ = int(previous.get("occurrence_count") or 1) + 1
            merged = {**previous, **metadata, "occurrence_count": occ}
            u = await ctx.db.query(
                """update public.gateway_alerts set updated_at = now(), metadata = $2::jsonb, message = $3
                    where id = $1 returning *""",
                (existing["id"], to_json(merged), inp["message"]),
            )
            return u.rows[0] if u.rows else None
    ins = await ctx.db.query(
        """insert into public.gateway_alerts
          (tenant_id, severity, category, title, message, provider, api_key_id, credential_id, status, dedupe_key, metadata)
         values ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $10::jsonb) returning *""",
        (
            tenant_id,
            inp["severity"],
            inp["category"],
            inp["title"],
            inp["message"],
            inp.get("provider"),
            inp.get("apiKeyId"),
            inp.get("credentialId"),
            dedupe_key,
            to_json(metadata),
        ),
    )
    alert = ins.rows[0] if ins.rows else None
    if alert:
        gateway_alerts_total.labels(
            tenant_id=str(tenant_id), category=inp["category"], severity=inp["severity"]
        ).inc()
        if ctx.ws_broadcast:
            await ctx.ws_broadcast(
                str(tenant_id),
                {"type": "alert.created", "tenantId": str(tenant_id), "at": int(time.time() * 1000), "alert": alert},
            )
    return alert


async def mark_credential_cooldown(
    ctx: ObsContext,
    *,
    tenant_id: str,
    credential_id: str,
    provider: str,
    seconds: int,
    reason: str,
    api_key_id: str | None,
) -> dict | None:
    if not credential_id:
        return None
    import datetime as dt

    cooldown_until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).isoformat()
    r = await ctx.db.query(
        """update public.provider_credentials
            set status = 'cooldown', cooldown_until = $2, failed_requests = failed_requests + 1
          where id = $1
          returning id, provider_name, cooldown_until""",
        (credential_id, cooldown_until),
    )
    if not r.rows:
        return None
    gateway_credential_cooldowns_total.labels(tenant_id=str(tenant_id), provider=provider).inc()
    await create_alert(
        ctx,
        {
            "tenantId": tenant_id,
            "severity": "warning" if reason == "provider_rate_limit" else "critical",
            "category": "credential_cooldown_started",
            "title": f"Credential {provider} cooldown",
            "message": f"Credential {provider} masuk cooldown sampai {cooldown_until}.",
            "provider": provider,
            "apiKeyId": api_key_id,
            "credentialId": credential_id,
            "dedupeKey": f"cooldown:{credential_id}:{reason}",
            "metadata": {"reason": reason, "cooldown_until": cooldown_until},
        },
    )
    if ctx.ws_broadcast:
        await ctx.ws_broadcast(
            str(tenant_id),
            {
                "type": "credential.cooldown",
                "tenantId": str(tenant_id),
                "at": int(time.time() * 1000),
                "provider": provider,
                "credentialId": credential_id,
                "cooldownUntil": cooldown_until,
                "reason": reason,
            },
        )
    return r.rows[0]


async def log_gateway_request(ctx: ObsContext, event: dict) -> dict:
    log_mode = ctx.gateway_log_mode or "full"
    err_t = classify_error_type(
        status_code=event.get("statusCode"),
        error_message=str(event.get("errorMessage") or ""),
        rate_limited=bool(event.get("rateLimited")),
    )
    base_meta = event.get("metadata") or {}
    ins = await ctx.db.query(
        """insert into public.gateway_request_logs
          (api_key_id, tenant_id, provider, method, status_code, response_time_ms, origin_domain, request_path,
           error_type, error_message, credential_id, client_auth_used, rate_limited, breaker_open, upstream_status, detected_anomaly_types, metadata)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::jsonb)
         returning *""",
        (
            event.get("apiKeyId"),
            event.get("tenantId"),
            event.get("provider"),
            event.get("method"),
            event.get("statusCode"),
            event.get("responseTimeMs"),
            event.get("originDomain"),
            event.get("requestPath"),
            err_t,
            trim_message(event.get("errorMessage")),
            event.get("credentialId"),
            bool(event.get("clientAuthUsed")),
            bool(event.get("rateLimited")),
            bool(event.get("breakerOpen")),
            event.get("upstreamStatus"),
            [],
            to_json(base_meta),
        ),
    )
    log_row = ins.rows[0] if ins.rows else {}
    await upsert_provider_credential_stats(
        ctx.db,
        credential_id=event.get("credentialId"),
        success=not event.get("statusCode") or int(event.get("statusCode") or 0) < 400,
    )
    if log_mode != "full":
        return {"log": log_row, "anomalyTypes": [], "alerts": []}

    anomaly_types: list = []
    alerts: list = []
    api_key_id = event.get("apiKeyId")
    tenant_id = event.get("tenantId")
    burst_count = await get_recent_burst_count(ctx.db, api_key_id=api_key_id) if api_key_id else 0
    recent_stats = await get_recent_api_key_stats(ctx.db, api_key_id=api_key_id) if api_key_id else {"requests": 0, "domains": 0}

    if burst_count >= BURST_THRESHOLD_WARNING and api_key_id:
        push_unique(anomaly_types, "burst_traffic")
        gateway_anomalies_total.labels(tenant_id=str(tenant_id), type="burst_traffic").inc()
        a = await create_alert(
            ctx,
            {
                "tenantId": tenant_id,
                "severity": "critical" if burst_count >= BURST_THRESHOLD_CRITICAL else "warning",
                "category": "burst_traffic",
                "title": "Lonjakan request terdeteksi",
                "message": f"API key menerima {burst_count} request dalam 5 detik terakhir.",
                "provider": event.get("provider"),
                "apiKeyId": api_key_id,
                "credentialId": event.get("credentialId"),
                "dedupeKey": f"burst:{api_key_id}",
                "metadata": {"burst_count": burst_count, "recent_requests": recent_stats["requests"]},
            },
        )
        if a:
            alerts.append(a)

    leak = detect_leak_risk(
        burst_count=burst_count,
        distinct_domains=recent_stats["domains"],
        recent_requests=recent_stats["requests"],
    )
    if leak and api_key_id:
        push_unique(anomaly_types, "possible_api_key_leak")
        gateway_anomalies_total.labels(tenant_id=str(tenant_id), type="possible_api_key_leak").inc()
        a = await create_alert(
            ctx,
            {
                "tenantId": tenant_id,
                "severity": "critical" if leak == "critical" else "warning",
                "category": "possible_api_key_leak",
                "title": "Indikasi API key bocor",
                "message": f"Aktivitas tidak wajar terdeteksi untuk API key ini dari {recent_stats['domains']} domain dalam 10 menit terakhir.",
                "provider": event.get("provider"),
                "apiKeyId": api_key_id,
                "credentialId": event.get("credentialId"),
                "dedupeKey": f"leak:{api_key_id}",
                "metadata": {
                    "distinct_domains": recent_stats["domains"],
                    "burst_count": burst_count,
                    "recent_requests": recent_stats["requests"],
                },
            },
        )
        if a:
            alerts.append(a)

    if err_t != "success" and event.get("provider"):
        prov_stats = await get_provider_error_stats(ctx.db, tenant_id=str(tenant_id), provider=str(event["provider"]))
        if prov_stats["errors"] >= PROVIDER_INCIDENT_THRESHOLD:
            push_unique(anomaly_types, "provider_incident")
            gateway_anomalies_total.labels(tenant_id=str(tenant_id), type="provider_incident").inc()
            a = await create_alert(
                ctx,
                {
                    "tenantId": tenant_id,
                    "severity": "critical" if prov_stats["errors"] >= PROVIDER_OUTAGE_THRESHOLD else "warning",
                    "category": "provider_incident",
                    "title": f"Insiden provider {event['provider']}",
                    "message": f"{prov_stats['errors']} error terdeteksi pada provider {event['provider']} dalam 2 menit terakhir.",
                    "provider": event.get("provider"),
                    "apiKeyId": api_key_id,
                    "credentialId": event.get("credentialId"),
                    "dedupeKey": f"incident:{tenant_id}:{event['provider']}",
                    "metadata": prov_stats,
                },
            )
            if a:
                alerts.append(a)
        rem = get_remediation_policy(error_type=err_t, anomaly_types=anomaly_types)
        if rem == "cooldown_credential" and event.get("credentialId"):
            sec = RATE_LIMIT_COOLDOWN_SECONDS if err_t == "provider_rate_limit" else OUTAGE_COOLDOWN_SECONDS
            await mark_credential_cooldown(
                ctx,
                tenant_id=str(tenant_id),
                credential_id=str(event["credentialId"]),
                provider=str(event["provider"]),
                seconds=sec,
                reason=err_t,
                api_key_id=str(api_key_id) if api_key_id else None,
            )
            push_unique(anomaly_types, "credential_cooldown")
        if rem == "rotate_api_key" and leak == "critical" and api_key_id:
            await create_alert(
                ctx,
                {
                    "tenantId": tenant_id,
                    "severity": "critical",
                    "category": "auto_rotation_skipped",
                    "title": "Auto-rotation dinonaktifkan sementara",
                    "message": f"Indikasi kebocoran terdeteksi untuk {event.get('provider')}, tetapi auto-rotation lintas instance dimatikan.",
                    "provider": event.get("provider"),
                    "apiKeyId": api_key_id,
                    "credentialId": event.get("credentialId"),
                    "dedupeKey": f"auto-rotate-skipped:{api_key_id}",
                    "metadata": {"leak_risk": leak, "reason": "local_memory_mode"},
                },
            )

    if anomaly_types and log_row.get("id"):
        try:
            await ctx.db.query(
                "update public.gateway_request_logs set detected_anomaly_types = $2 where id = $1",
                (log_row["id"], anomaly_types),
            )
        except Exception:
            pass

    return {"log": log_row, "anomalyTypes": anomaly_types, "alerts": alerts}


async def list_gateway_logs(
    db: Database,
    *,
    tenant_id: str,
    limit: int = 100,
    provider: str | None = None,
    api_key_id: str | None = None,
    status: str | None = None,
    search: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list:
    params: list = [tenant_id]
    where = ["g.tenant_id = $1"]
    if provider:
        params.append(provider)
        where.append(f"g.provider = ${len(params)}")
    if api_key_id:
        params.append(api_key_id)
        where.append(f"g.api_key_id = ${len(params)}")
    if status == "success":
        where.append("coalesce(g.status_code, 0) < 400")
    if status == "error":
        where.append("coalesce(g.status_code, 0) >= 400")
    if date_from:
        params.append(date_from)
        where.append(f"g.created_at >= ${len(params)}")
    if date_to:
        params.append(date_to)
        where.append(f"g.created_at <= ${len(params)}")
    if search:
        params.append(f"%{search}%")
        si = len(params)
        where.append(
            f"""(coalesce(g.error_message, '') ilike ${si}
            or coalesce(g.origin_domain, '') ilike ${si}
            or coalesce(g.request_path, '') ilike ${si}
            or coalesce(k.name, '') ilike ${si})"""
        )
    lim = min(limit or 100, 500)
    params.append(lim)
    r = await db.query(
        f"""select g.id, g.provider as provider_name, 'gateway' as provider_type,
            g.request_path as endpoint, g.method, g.status_code, g.response_time_ms,
            g.error_message, g.error_type, g.origin_domain, g.request_path,
            g.detected_anomaly_types, g.created_at, g.api_key_id, g.credential_id,
            k.name as api_key_name
       from public.gateway_request_logs g
       left join public.api_keys k on k.id = g.api_key_id
      where {" and ".join(where)}
      order by g.created_at desc
      limit ${len(params)}""",
        tuple(params),
    )
    return r.rows


async def list_gateway_alerts(db: Database, *, tenant_id: str, status: str = "active", limit: int = 25) -> list:
    params: list = [tenant_id]
    where = ["tenant_id = $1"]
    if status and status != "all":
        params.append(status)
        where.append(f"status = ${len(params)}")
    lim = min(limit or 25, 100)
    params.append(lim)
    r = await db.query(
        f"""select * from public.gateway_alerts where {" and ".join(where)}
            order by created_at desc limit ${len(params)}""",
        tuple(params),
    )
    rows = []
    for row in r.rows:
        d = dict(row)
        d["metadata"] = parse_json_safe(d.get("metadata"), {})
        rows.append(d)
    return rows


async def acknowledge_alert(db: Database, *, tenant_id: str, alert_id: str) -> dict | None:
    r = await db.query(
        """update public.gateway_alerts
            set acknowledged_at = coalesce(acknowledged_at, now()),
                read_at = coalesce(read_at, now()),
                status = case when status = 'active' then 'acknowledged' else status end,
                updated_at = now()
          where id = $1 and tenant_id = $2 returning *""",
        (alert_id, tenant_id),
    )
    return r.rows[0] if r.rows else None


async def get_monitoring_overview(db: Database, *, tenant_id: str) -> dict:
    request_rows, alert_rows, provider_rows, key_rows = await asyncio.gather(
        db.query(
            """select count(*)::int as total_requests,
                      count(*) filter (where status_code >= 400)::int as total_errors,
                      coalesce(avg(response_time_ms), 0)::int as avg_latency_ms
                 from public.gateway_request_logs
                where tenant_id = $1 and created_at >= now() - interval '24 hours'""",
            (tenant_id,),
        ),
        db.query(
            """select count(*) filter (where status = 'active')::int as active_alerts,
                      count(*) filter (where severity = 'critical' and status = 'active')::int as critical_alerts
                 from public.gateway_alerts
                where tenant_id = $1 and created_at >= now() - interval '7 days'""",
            (tenant_id,),
        ),
        db.query(
            """select provider_name as provider,
                      count(*)::int as total_credentials,
                      count(*) filter (where status = 'active')::int as active_credentials,
                      count(*) filter (where status = 'cooldown')::int as cooldown_credentials
                 from public.provider_credentials
                where user_id = $1
                group by provider_name
                order by provider_name""",
            (tenant_id,),
        ),
        db.query(
            """select g.api_key_id, coalesce(k.name, 'Unnamed') as api_key_name,
                      count(*)::int as requests,
                      count(*) filter (where g.status_code >= 400)::int as errors,
                      count(distinct g.origin_domain) filter (where g.origin_domain is not null and g.origin_domain <> '')::int as domains
                 from public.gateway_request_logs g
                 left join public.api_keys k on k.id = g.api_key_id
                where g.tenant_id = $1 and g.created_at >= now() - interval '24 hours'
                group by g.api_key_id, k.name
                order by requests desc
                limit 5""",
            (tenant_id,),
        ),
    )
    rq = request_rows.rows[0] if request_rows.rows else {}
    aq = alert_rows.rows[0] if alert_rows.rows else {}
    return {
        "totals": {
            "totalRequests24h": int(rq.get("total_requests") or 0),
            "totalErrors24h": int(rq.get("total_errors") or 0),
            "avgLatencyMs24h": int(rq.get("avg_latency_ms") or 0),
            "activeAlerts": int(aq.get("active_alerts") or 0),
            "criticalAlerts": int(aq.get("critical_alerts") or 0),
        },
        "providerHealth": provider_rows.rows,
        "noisyKeys": key_rows.rows,
    }


async def get_api_key_analytics(db: Database, *, tenant_id: str, api_key_id: str) -> dict:
    summary_rows, series_rows, alert_rows = await asyncio.gather(
        db.query(
            """select count(*)::int as requests,
                      count(*) filter (where status_code >= 400)::int as errors,
                      coalesce(avg(response_time_ms), 0)::int as avg_latency_ms,
                      count(distinct origin_domain) filter (where origin_domain is not null and origin_domain <> '')::int as domains
                 from public.gateway_request_logs
                where tenant_id = $1 and api_key_id = $2 and created_at >= now() - interval '7 days'""",
            (tenant_id, api_key_id),
        ),
        db.query(
            """select date_trunc('hour', created_at at time zone 'UTC') as bucket,
                      count(*)::int as requests,
                      count(*) filter (where status_code >= 400)::int as errors,
                      coalesce(avg(response_time_ms), 0)::int as avg_latency_ms
                 from public.gateway_request_logs
                where tenant_id = $1 and api_key_id = $2 and created_at >= now() - interval '24 hours'
                group by 1 order by 1""",
            (tenant_id, api_key_id),
        ),
        db.query(
            """select * from public.gateway_alerts
                where tenant_id = $1 and api_key_id = $2
                order by created_at desc limit 10""",
            (tenant_id, api_key_id),
        ),
    )
    s0 = summary_rows.rows[0] if summary_rows.rows else {}
    alerts = []
    for row in alert_rows.rows:
        d = dict(row)
        d["metadata"] = parse_json_safe(d.get("metadata"), {})
        alerts.append(d)
    return {
        "summary": {
            "requests": int(s0.get("requests") or 0),
            "errors": int(s0.get("errors") or 0),
            "avgLatencyMs": int(s0.get("avg_latency_ms") or 0),
            "domains": int(s0.get("domains") or 0),
        },
        "series": series_rows.rows,
        "alerts": alerts,
    }
