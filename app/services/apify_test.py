"""Port server1/src/services/apifyTest.js + callApifyHelper logic."""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from app.config import get_settings
from app.db import Database
from app.gateway import credentials as cred_util
from app.services import observability as obs
from app.services.observability import ObsContext


def parse_credential_json(value: Any) -> dict:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return {}


def get_apify_token_from_credential(credential_row: dict | None) -> str:
    if not credential_row:
        return ""
    creds = parse_credential_json(credential_row.get("credentials"))
    return str(creds.get("api_token") or creds.get("apiToken") or "").strip()


def normalize_apify_run(payload: Any) -> dict:
    data = payload.get("data", payload) if isinstance(payload, dict) else {}
    if not isinstance(data, dict):
        data = {}
    return {
        "id": data.get("id"),
        "status": data.get("status"),
        "actId": data.get("actId"),
        "actorTaskId": data.get("actorTaskId"),
        "startedAt": data.get("startedAt"),
        "finishedAt": data.get("finishedAt"),
        "defaultDatasetId": data.get("defaultDatasetId"),
        "defaultKeyValueStoreId": data.get("defaultKeyValueStoreId"),
        "usageTotalUsd": data.get("usageTotalUsd"),
        "origin": data.get("origin"),
        "raw": payload if isinstance(payload, dict) else data,
    }


def normalize_apify_collection(payload: Any) -> dict:
    if isinstance(payload, dict):
        items = payload.get("data", {}).get("items") if isinstance(payload.get("data"), dict) else None
        if items is None:
            items = payload.get("items")
    else:
        items = None
    if not isinstance(items, list):
        items = payload if isinstance(payload, list) else []
    pdata = payload if isinstance(payload, dict) else {}
    data_block = pdata.get("data") if isinstance(pdata.get("data"), dict) else {}
    return {
        "total": int(
            data_block.get("total")
            or pdata.get("total")
            or (len(items) if items else 0)
            or 0
        ),
        "count": len(items),
        "offset": int(data_block.get("offset") or pdata.get("offset") or 0),
        "limit": int(data_block.get("limit") or pdata.get("limit") or len(items) or 0),
        "items": items,
        "raw": payload,
    }


def normalize_apify_smoke(*, verify_ok: bool, actors: dict, tasks: dict) -> dict:
    ai = actors.get("items") or []
    ti = tasks.get("items") or []
    return {
        "verifyOk": verify_ok,
        "actorsCount": actors.get("count"),
        "tasksCount": tasks.get("count"),
        "actorPreview": [
            {"id": x.get("id"), "name": x.get("name"), "title": x.get("title")} for x in ai[:5]
        ],
        "taskPreview": [
            {"id": x.get("id"), "name": x.get("name"), "title": x.get("title")} for x in ti[:5]
        ],
    }


async def get_owned_gateway_key_for_provider(
    db: Database, *, tenant_id: str, api_key_id: str, provider: str
) -> dict | None:
    r = await db.query(
        """select id, tenant_id, key_hash, client_username, allowed_providers, name, quota_per_minute
             from public.api_keys
            where id = $1 and tenant_id = $2 and $3 = any(coalesce(allowed_providers, '{}'::text[]))
            limit 1""",
        (api_key_id, tenant_id, provider),
    )
    return r.rows[0] if r.rows else None


def _build_apify_url(path: str, query: dict) -> str:
    s = get_settings()
    base = s.provider_upstreams.get("apify", "https://api.apify.com/v2")
    u = urlparse(base)
    p = path if path.startswith("/") else f"/{path}"
    q = {k: v for k, v in query.items() if v is not None and v != ""}
    qs = urlencode({k: str(v) for k, v in q.items()})
    return urlunparse((u.scheme, u.netloc, p, "", qs, ""))


async def call_apify_helper(
    *,
    ctx: ObsContext,
    tenant_id: str,
    api_key: dict,
    path: str,
    method: str = "GET",
    query: dict | None = None,
    body: Any = None,
    request_path: str | None = None,
) -> dict:
    query = query or {}
    rp = request_path or path
    credential = await cred_util.find_latest_active_credential(ctx.db, user_id=tenant_id, provider="apify")
    if not credential:
        await obs.log_gateway_request(
            ctx,
            {
                "tenantId": tenant_id,
                "apiKeyId": api_key["id"],
                "provider": "apify",
                "method": method,
                "statusCode": 404,
                "responseTimeMs": 1,
                "originDomain": "dashboard-internal",
                "requestPath": rp,
                "errorMessage": "Credential Apify aktif tidak ditemukan.",
                "clientAuthUsed": bool(api_key.get("client_username")),
                "upstreamStatus": 404,
                "metadata": {"helper_test": True, "query": query},
            },
        )
        return {
            "ok": False,
            "status": 404,
            "error": "Credential Apify aktif tidak ditemukan. Tambahkan credential Apify di halaman Credentials.",
        }
    token = get_apify_token_from_credential(credential)
    if not token:
        await obs.log_gateway_request(
            ctx,
            {
                "tenantId": tenant_id,
                "apiKeyId": api_key["id"],
                "provider": "apify",
                "method": method,
                "statusCode": 400,
                "responseTimeMs": 1,
                "originDomain": "dashboard-internal",
                "requestPath": rp,
                "errorMessage": "Credential Apify belum berisi api_token yang valid.",
                "credentialId": credential["id"],
                "clientAuthUsed": bool(api_key.get("client_username")),
                "upstreamStatus": 400,
                "metadata": {"helper_test": True, "query": query},
            },
        )
        return {"ok": False, "status": 400, "error": "Credential Apify belum berisi api_token yang valid."}

    url = _build_apify_url(path, query)
    headers: dict[str, str] = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    import time as _t

    started = _t.time()
    s = get_settings()
    try:
        async with httpx.AsyncClient(timeout=s.BREAKER_TIMEOUT_MS / 1000.0) as client:
            res = await client.request(
                method,
                url,
                headers=headers,
                content=json.dumps(body) if body is not None else None,
            )
    except Exception as e:
        await obs.log_gateway_request(
            ctx,
            {
                "tenantId": tenant_id,
                "apiKeyId": api_key["id"],
                "provider": "apify",
                "method": method,
                "statusCode": 503,
                "responseTimeMs": int((_t.time() - started) * 1000),
                "originDomain": "dashboard-internal",
                "requestPath": rp,
                "errorMessage": str(e),
                "credentialId": credential["id"],
                "clientAuthUsed": bool(api_key.get("client_username")),
                "upstreamStatus": 503,
                "metadata": {"helper_test": True, "query": query},
            },
        )
        return {"ok": False, "status": 503, "error": str(e)}

    latency_ms = int((_t.time() - started) * 1000)
    ct = res.headers.get("content-type") or ""
    if "application/json" in ct:
        payload = res.json()
    else:
        payload = res.text
    err_msg = None
    if not res.is_success:
        if isinstance(payload, str):
            err_msg = payload[:240]
        elif isinstance(payload, dict):
            err_msg = str(payload.get("error", {}).get("message") or payload.get("error") or "Apify request failed")

    await obs.log_gateway_request(
        ctx,
        {
            "tenantId": tenant_id,
            "apiKeyId": api_key["id"],
            "provider": "apify",
            "method": method,
            "statusCode": res.status_code,
            "responseTimeMs": latency_ms,
            "originDomain": "dashboard-internal",
            "requestPath": rp,
            "errorMessage": err_msg,
            "credentialId": credential["id"],
            "clientAuthUsed": bool(api_key.get("client_username")),
            "upstreamStatus": res.status_code,
            "metadata": {"helper_test": True, "upstream": path, "query": query},
        },
    )
    if not res.is_success:
        return {"ok": False, "status": res.status_code, "error": err_msg or "Apify request failed", "payload": payload}
    return {"ok": True, "status": res.status_code, "payload": payload}