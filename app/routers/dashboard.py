"""Rute dashboard terproteksi JWT (mirror server1 protectedApi)."""
from __future__ import annotations

import json
import time
from typing import Any

import bcrypt
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.deps import get_current_user, rate_limit_default
from app.db import get_db
from app.gateway import credentials as cred_util
from app.metrics_prometheus import api_key_rotations_total
from app.services import ai_models as ai_models_svc
from app.services import apify_test as apify
from app.services import observability as obs
from app.services import playground as pgw
from app.services import api_keys as api_keys_svc
from app.state import get_state

router = APIRouter(dependencies=[Depends(rate_limit_default)])


@router.get("/api/auth/me")
async def auth_me(user: dict = Depends(get_current_user)) -> dict:
    return user


@router.patch("/api/profile")
async def patch_profile(request: Request, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    body = await request.json()
    display_name = body.get("displayName") if body else None
    if display_name is None and body:
        display_name = body.get("display_name")
    email = None
    if body and body.get("email"):
        email = str(body["email"]).strip().lower()
    uid = user["id"]
    if display_name is not None:
        await db.query("update public.users set display_name = $1 where id = $2", (display_name, uid))
    if email and email != user.get("email"):
        ex = await db.query("select id from public.users where email = $1 and id != $2", (email, uid))
        if ex.rows:
            raise HTTPException(status_code=409, detail="Email sudah dipakai")
        await db.query("update public.users set email = $1 where id = $2", (email, uid))
    r = await db.query("select id, email, display_name from public.users where id = $1", (uid,))
    u = r.rows[0]
    return {"id": str(u["id"]), "email": u["email"], "displayName": u.get("display_name")}


@router.post("/api/auth/change-password")
async def change_password(request: Request, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    body = await request.json()
    current = body.get("current_password") or body.get("currentPassword")
    nxt = body.get("new_password") or body.get("newPassword")
    if not current or not nxt:
        raise HTTPException(status_code=400, detail="current_password dan new_password wajib")
    if len(str(nxt)) < 8:
        raise HTTPException(status_code=400, detail="Password baru minimal 8 karakter")
    r = await db.query("select password_hash from public.users where id = $1", (user["id"],))
    ph = r.rows[0]["password_hash"] if r.rows else ""
    if not bcrypt.checkpw(str(current).encode("utf-8"), str(ph).encode("utf-8")):
        raise HTTPException(status_code=401, detail="Password lama salah")
    nh = bcrypt.hashpw(str(nxt).encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
    await db.query("update public.users set password_hash = $1 where id = $2", (nh, user["id"]))
    return {"success": True}


@router.get("/api/keys")
async def list_keys(user: dict = Depends(get_current_user)) -> list:
    return await api_keys_svc.list_api_keys(get_db(), tenant_id=user["id"])


@router.post("/api/keys")
async def create_key(request: Request, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    body = await request.json()
    state = get_state()
    created = await api_keys_svc.create_api_key(
        db,
        tenant_id=user["id"],
        quota_per_minute=body.get("quota_per_minute"),
        allowed_providers=body.get("allowed_providers"),
        name=body.get("name"),
        client_username=body.get("client_username"),
        client_password=body.get("client_password"),
    )
    await state.ws.broadcast_to_tenant(
        user["id"],
        {"type": "api_key.created", "at": int(time.time() * 1000), "tenantId": user["id"], "apiKeyId": created["id"]},
    )
    return created


@router.post("/api/keys/{key_id}/rotate")
async def rotate_key(key_id: str, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    state = get_state()
    r = await db.query(
        "select key_hash from public.api_keys where id = $1 and tenant_id = $2",
        (key_id, user["id"]),
    )
    old_hash = r.rows[0]["key_hash"] if r.rows else None
    rotated = await api_keys_svc.rotate_api_key(
        db, state.l1, state.l2, api_key_id=key_id, tenant_id=user["id"], old_key_hash=old_hash
    )
    api_key_rotations_total.labels(tenant_id=user["id"]).inc()
    await state.ws.broadcast_to_tenant(
        user["id"],
        {
            "type": "api_key.rotated",
            "at": int(time.time() * 1000),
            "tenantId": user["id"],
            "oldApiKeyId": key_id,
            "newApiKeyId": rotated["id"],
        },
    )
    return rotated


@router.get("/api/keys/{key_id}/health")
async def key_health(key_id: str, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    r = await db.query(
        """select response_time_ms as last_latency_ms,
                  status_code as last_status,
                  created_at as checked_at
             from public.gateway_request_logs
            where tenant_id = $1 and api_key_id = $2
            order by created_at desc
            limit 1""",
        (user["id"], key_id),
    )
    latest = r.rows[0] if r.rows else None
    return {
        "id": key_id,
        "last_latency_ms": latest.get("last_latency_ms") if latest else None,
        "last_status": latest.get("last_status") if latest else None,
        "checked_at": latest.get("checked_at") if latest else None,
        "remaining": None,
    }


@router.patch("/api/keys/{key_id}")
async def patch_key(key_id: str, request: Request, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    body = await request.json()
    if isinstance(body.get("name"), str):
        await db.query(
            "update public.api_keys set name = $1, updated_at = now() where id = $2 and tenant_id = $3",
            (body["name"].strip() or None, key_id, user["id"]),
        )
    r = await db.query(
        "select id, tenant_id, status, quota_per_minute, allowed_providers, name, created_at from public.api_keys where id = $1 and tenant_id = $2",
        (key_id, user["id"]),
    )
    return r.rows[0] if r.rows else {}


@router.delete("/api/keys/{key_id}", status_code=204)
async def delete_key(key_id: str, user: dict = Depends(get_current_user)) -> Response:
    await get_db().query(
        "delete from public.api_keys where id = $1 and tenant_id = $2",
        (key_id, user["id"]),
    )
    return Response(status_code=204)


@router.get("/api/keys/{key_id}/stats")
async def key_stats(key_id: str, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    o = await db.query("select 1 from public.api_keys where id = $1 and tenant_id = $2", (key_id, user["id"]))
    if not o.rows:
        raise HTTPException(status_code=404, detail="Not found")
    days = 7
    r = await db.query(
        """select date_trunc('day', created_at at time zone 'UTC')::date as day, count(*)::int as requests,
                  count(*) filter (where status_code >= 400)::int as errors
             from public.gateway_request_logs where api_key_id = $1 and created_at >= now() - interval '1 day' * $2
            group by 1 order by 1""",
        (key_id, days),
    )
    daily = [{"date": row["day"], "requests": row["requests"], "errors": row["errors"]} for row in r.rows]
    return {"daily": daily}


@router.get("/api/keys/{key_id}/analytics")
async def key_analytics(key_id: str, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    o = await db.query("select 1 from public.api_keys where id = $1 and tenant_id = $2", (key_id, user["id"]))
    if not o.rows:
        raise HTTPException(status_code=404, detail="Not found")
    return await obs.get_api_key_analytics(db, tenant_id=user["id"], api_key_id=key_id)


@router.get("/api/keys/{key_id}/domains")
async def key_domains(key_id: str, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    o = await db.query("select 1 from public.api_keys where id = $1 and tenant_id = $2", (key_id, user["id"]))
    if not o.rows:
        raise HTTPException(status_code=404, detail="Not found")
    r = await db.query(
        "select distinct origin_domain as domain from public.gateway_request_logs where api_key_id = $1 and origin_domain is not null order by 1",
        (key_id,),
    )
    return {"domains": [row["domain"] for row in r.rows]}


@router.get("/api/dashboard/keys")
async def dashboard_keys(user: dict = Depends(get_current_user)) -> list:
    db = get_db()
    keys = await api_keys_svc.list_api_keys(db, tenant_id=user["id"])
    hr = await db.query(
        """select distinct on (api_key_id)
                api_key_id,
                response_time_ms as last_latency_ms,
                status_code as last_status,
                created_at as checked_at
           from public.gateway_request_logs
          where tenant_id = $1
          order by api_key_id, created_at desc""",
        (user["id"],),
    )
    health_by = {row["api_key_id"]: row for row in hr.rows}
    out = []
    for k in keys:
        h = health_by.get(k["id"])
        out.append({**k, "health": h, "remaining": h.get("remaining") if h else None})
    return out


@router.get("/api/stats")
async def stats(user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    uid = user["id"]
    creds, clients, requests, alerts = await __import__("asyncio").gather(
        db.query("select status, total_requests from public.provider_credentials where user_id = $1", (uid,)),
        db.query("select count(*)::int as n from public.api_clients where user_id = $1", (uid,)),
        db.query(
            """select count(*)::int as total,
                      count(*) filter (where status_code >= 400 and created_at > now() - interval '24 hours')::int as errors
                 from public.gateway_request_logs where tenant_id = $1""",
            (uid,),
        ),
        db.query(
            """select count(*) filter (where status = 'active')::int as active from public.gateway_alerts where tenant_id = $1""",
            (uid,),
        ),
    )
    cr = creds.rows
    total_credentials = len(cr)
    active_credentials = len([x for x in cr if x.get("status") == "active"])
    cooldown_credentials = len([x for x in cr if x.get("status") == "cooldown"])
    total_requests = sum(int(x.get("total_requests") or 0) for x in cr)
    return {
        "totalCredentials": total_credentials,
        "activeCredentials": active_credentials,
        "cooldownCredentials": cooldown_credentials,
        "totalClients": clients.rows[0]["n"] if clients.rows else 0,
        "totalRequests": total_requests,
        "recentErrors": requests.rows[0]["errors"] if requests.rows else 0,
        "activeAlerts": alerts.rows[0]["active"] if alerts.rows else 0,
    }


@router.get("/api/stats/usage")
async def stats_usage(user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    days = 7
    r = await db.query(
        """select date_trunc('day', created_at at time zone 'UTC')::date as date,
                  count(*)::int as requests,
                  count(*) filter (where status_code >= 400)::int as errors
             from public.gateway_request_logs
            where tenant_id = $1 and created_at >= now() - interval '1 day' * $2
            group by 1 order by 1""",
        (user["id"], days),
    )
    return {"daily": r.rows}


@router.get("/api/monitoring/overview")
async def monitoring_overview(user: dict = Depends(get_current_user)) -> dict:
    return await obs.get_monitoring_overview(get_db(), tenant_id=user["id"])


@router.get("/api/logs")
async def logs(
    user: dict = Depends(get_current_user),
    limit: int | None = Query(None),
    provider: str | None = Query(None),
    apiKeyId: str | None = Query(None),
    status: str | None = Query(None),
    search: str | None = Query(None),
    from_: str | None = Query(None, alias="from"),
    to: str | None = Query(None),
) -> list:
    return await obs.list_gateway_logs(
        get_db(),
        tenant_id=user["id"],
        limit=int(limit or 100),
        provider=provider,
        api_key_id=apiKeyId,
        status=status,
        search=search,
        date_from=from_,
        date_to=to,
    )


@router.get("/api/alerts")
async def alerts(
    user: dict = Depends(get_current_user),
    status: str = Query("active"),
    limit: int | None = Query(25),
) -> list:
    return await obs.list_gateway_alerts(
        get_db(), tenant_id=user["id"], status=status, limit=int(limit or 25)
    )


@router.patch("/api/alerts/{alert_id}/ack")
async def ack_alert(alert_id: str, user: dict = Depends(get_current_user)) -> dict:
    a = await obs.acknowledge_alert(get_db(), tenant_id=user["id"], alert_id=alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="Not found")
    return a


@router.get("/api/credentials")
async def list_creds(user: dict = Depends(get_current_user)) -> list:
    r = await get_db().query(
        """select id, provider_name, provider_type, label, status, total_requests, failed_requests, cooldown_until, created_at
             from public.provider_credentials where user_id = $1 order by created_at desc""",
        (user["id"],),
    )
    return r.rows


@router.get("/api/credentials/export")
async def export_creds(user: dict = Depends(get_current_user)) -> list:
    s = get_settings()
    if not s.ALLOW_CREDENTIAL_EXPORT:
        raise HTTPException(status_code=403, detail="Ekspor credential dinonaktifkan di environment ini.")
    r = await get_db().query(
        """select id, provider_name, provider_type, label, credentials, status, total_requests, failed_requests, cooldown_until, created_at
             from public.provider_credentials where user_id = $1 order by created_at desc""",
        (user["id"],),
    )
    items = []
    for row in r.rows:
        creds = row.get("credentials")
        if isinstance(creds, str):
            try:
                creds = json.loads(creds)
            except json.JSONDecodeError:
                creds = {}
        items.append(
            {
                "provider_name": row.get("provider_name"),
                "provider_type": row.get("provider_type"),
                "label": row.get("label"),
                "credentials": creds if isinstance(creds, dict) else {},
                "status": row.get("status"),
            }
        )
    return items


@router.post("/api/credentials")
async def create_cred(request: Request, user: dict = Depends(get_current_user)) -> dict:
    body = await request.json()
    r = await get_db().query(
        """insert into public.provider_credentials (user_id, provider_name, provider_type, label, credentials)
           values ($1, $2, $3, $4, $5)
           returning id, provider_name, provider_type, label, status, total_requests, failed_requests, cooldown_until, created_at""",
        (
            user["id"],
            body.get("provider_name") or "",
            body.get("provider_type") or "ai",
            body.get("label"),
            json.dumps(body.get("credentials") or {}),
        ),
    )
    return r.rows[0]


@router.get("/api/credentials/{cred_id}")
async def get_cred(cred_id: str, user: dict = Depends(get_current_user)) -> dict:
    r = await get_db().query(
        """select id, provider_name, provider_type, label, credentials, status, total_requests, failed_requests, cooldown_until, created_at
             from public.provider_credentials where id = $1 and user_id = $2 limit 1""",
        (cred_id, user["id"]),
    )
    if not r.rows:
        raise HTTPException(status_code=404, detail="Not found")
    return r.rows[0]


@router.patch("/api/credentials/{cred_id}")
async def patch_cred(cred_id: str, request: Request, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    body = await request.json()
    if "label" in body:
        await db.query(
            "update public.provider_credentials set label = $1 where id = $2 and user_id = $3",
            (body.get("label"), cred_id, user["id"]),
        )
    if body.get("credentials") is not None and isinstance(body.get("credentials"), dict):
        await db.query(
            "update public.provider_credentials set credentials = $1 where id = $2 and user_id = $3",
            (json.dumps(body["credentials"]), cred_id, user["id"]),
        )
    r = await db.query(
        """select id, provider_name, provider_type, label, status, total_requests, failed_requests, cooldown_until, created_at
             from public.provider_credentials where id = $1 and user_id = $2""",
        (cred_id, user["id"]),
    )
    return r.rows[0] if r.rows else {}


@router.delete("/api/credentials/{cred_id}", status_code=204)
async def delete_cred(cred_id: str, user: dict = Depends(get_current_user)) -> Response:
    await get_db().query(
        "delete from public.provider_credentials where id = $1 and user_id = $2",
        (cred_id, user["id"]),
    )
    return Response(status_code=204)


@router.post("/api/credentials/{cred_id}/reactivate", status_code=204)
async def reactivate_cred(cred_id: str, user: dict = Depends(get_current_user)) -> Response:
    await get_db().query(
        "update public.provider_credentials set status = 'active', cooldown_until = null where id = $1 and user_id = $2",
        (cred_id, user["id"]),
    )
    return Response(status_code=204)


@router.post("/api/credentials/import")
async def import_creds(request: Request, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    body = await request.json()
    items = body.get("items") if isinstance(body, dict) else []
    if not isinstance(items, list):
        items = []
    for it in items:
        if not isinstance(it, dict):
            continue
        provider_name = it.get("provider_name") or it.get("providerName") or ""
        provider_type = it.get("provider_type") or it.get("providerType") or "ai"
        label = it.get("label")
        credentials = it.get("credentials") or it.get("creds") or {}
        if not provider_name:
            continue
        await db.query(
            """insert into public.provider_credentials (user_id, provider_name, provider_type, label, credentials)
               values ($1, $2, $3, $4, $5)""",
            (user["id"], provider_name, provider_type, label, json.dumps(credentials)),
        )
    return {"imported": len(items)}


@router.get("/api/clients")
async def list_clients(user: dict = Depends(get_current_user)) -> list:
    r = await get_db().query(
        """select id, name, api_key, is_active, rate_limit, allowed_providers, created_at
             from public.api_clients where user_id = $1 order by created_at desc""",
        (user["id"],),
    )
    return r.rows


@router.post("/api/clients")
async def create_client(request: Request, user: dict = Depends(get_current_user)) -> dict:
    body = await request.json()
    name = body.get("name") or "Unnamed"
    rate_limit = int(body.get("rate_limit") or 100)
    raw = body.get("allowed_providers")
    allowed: list[str] = []
    if isinstance(raw, list):
        allowed = [str(p).strip().lower() for p in raw if isinstance(p, str) and str(p).strip()]
    r = await get_db().query(
        """insert into public.api_clients (user_id, name, rate_limit, allowed_providers)
           values ($1, $2, $3, $4)
           returning id, name, api_key, is_active, rate_limit, allowed_providers, created_at""",
        (user["id"], name, rate_limit, allowed if allowed else []),
    )
    return r.rows[0]


@router.patch("/api/clients/{client_id}")
async def patch_client(client_id: str, request: Request, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    body = await request.json()
    if isinstance(body.get("is_active"), bool):
        await db.query(
            "update public.api_clients set is_active = $1 where id = $2 and user_id = $3",
            (body["is_active"], client_id, user["id"]),
        )
    raw = body.get("allowed_providers")
    if isinstance(raw, list):
        allowed = [str(p).strip().lower() for p in raw if isinstance(p, str) and str(p).strip()]
        await db.query(
            "update public.api_clients set allowed_providers = $1 where id = $2 and user_id = $3",
            (allowed, client_id, user["id"]),
        )
    r = await db.query(
        """select id, name, api_key, is_active, rate_limit, allowed_providers, created_at
             from public.api_clients where id = $1 and user_id = $2""",
        (client_id, user["id"]),
    )
    return r.rows[0] if r.rows else {}


@router.delete("/api/clients/{client_id}", status_code=204)
async def delete_client(client_id: str, user: dict = Depends(get_current_user)) -> Response:
    await get_db().query(
        "delete from public.api_clients where id = $1 and user_id = $2",
        (client_id, user["id"]),
    )
    return Response(status_code=204)


@router.get("/api/playground/models")
async def pg_models(provider: str | None = Query(None)) -> dict:
    if not provider or provider not in ("gemini", "groq"):
        raise HTTPException(status_code=400, detail="provider required (gemini or groq)")
    models = await ai_models_svc.list_models(get_db(), provider)
    return {"models": models}


@router.post("/api/playground/models", status_code=201)
async def pg_create_model(request: Request) -> JSONResponse:
    body = await request.json()
    provider = body.get("provider")
    model_id = body.get("model_id") or body.get("modelId")
    if not provider or not model_id:
        raise HTTPException(status_code=400, detail="provider dan model_id wajib")
    try:
        created = await ai_models_svc.create_model(
            get_db(),
            provider=provider,
            model_id=model_id,
            display_name=body.get("display_name") or body.get("displayName"),
            is_default=bool(body.get("is_default") or body.get("isDefault") or False),
            supports_vision=bool(body.get("supports_vision") or body.get("supportsVision") or False),
            sort_order=int(body.get("sort_order") or body.get("sortOrder") or 0),
        )
        return JSONResponse(created, status_code=201)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.delete("/api/playground/models/{model_id}", status_code=204)
async def pg_delete_model(model_id: str) -> Response:
    try:
        res = await ai_models_svc.delete_model_by_id(get_db(), model_id)
        if not res.get("deleted"):
            raise HTTPException(status_code=404, detail="Not found")
        return Response(status_code=204)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.patch("/api/playground/models/{model_id}")
async def pg_patch_model(model_id: str, request: Request) -> dict:
    body = await request.json()
    kw: dict = {}
    if "display_name" in body or "displayName" in body:
        kw["display_name"] = body.get("display_name") or body.get("displayName")
    if "supports_vision" in body or "supportsVision" in body:
        kw["supports_vision"] = body.get("supports_vision") if "supports_vision" in body else body.get("supportsVision")
    if "is_default" in body or "isDefault" in body:
        kw["is_default"] = body.get("is_default") if "is_default" in body else body.get("isDefault")
    try:
        updated = await ai_models_svc.update_model(get_db(), model_id, **kw)
        if not updated:
            raise HTTPException(status_code=404, detail="Not found")
        return updated
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/api/playground/chat")
async def pg_chat(request: Request, user: dict = Depends(get_current_user)) -> dict:
    body = await request.json()
    credential_id = body.get("credential_id") or body.get("credentialId")
    prompt = body.get("prompt") or ""
    image_b64 = body.get("image_base64") or body.get("imageBase64") or ""
    mid = body.get("model_id")
    model_id = str(mid).strip() if isinstance(mid, str) and mid.strip() else None
    if not credential_id:
        raise HTTPException(status_code=400, detail="credential_id required")
    result = await pgw.chat_with_provider(
        get_db(),
        user_id=user["id"],
        credential_id=credential_id,
        prompt=str(prompt),
        image_base64=str(image_b64),
        model_id=model_id,
    )
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/api/playground/upload")
async def pg_upload(
    user: dict = Depends(get_current_user),
    file: UploadFile = File(...),
    credential_id: str = Form(...),
    provider: str = Form("cloudinary"),
) -> dict:
    buf = await file.read()
    result = await pgw.upload_to_cloud(
        get_db(),
        user_id=user["id"],
        credential_id=credential_id,
        provider=provider or "cloudinary",
        buffer=buf,
        mime_type=file.content_type or "application/octet-stream",
        original_name=file.filename or "upload",
    )
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    if result.get("external_id"):
        from datetime import datetime, timedelta, timezone

        delete_at = datetime.now(timezone.utc) + timedelta(hours=1)
        try:
            await get_db().query(
                """insert into public.upload_expiry (tenant_id, credential_id, provider, external_id, delete_at)
                   values ($1, $2, $3, $4, $5)""",
                (user["id"], credential_id, provider, result["external_id"], delete_at),
            )
        except Exception:
            pass
    return result


@router.get("/api/settings")
async def get_settings_u(user: dict = Depends(get_current_user)) -> dict:
    r = await get_db().query(
        "select setting_key, setting_value from public.system_settings where user_id = $1",
        (user["id"],),
    )
    out: dict[str, Any] = {}
    for row in r.rows:
        raw = row.get("setting_value")
        try:
            out[row["setting_key"]] = json.loads(raw) if raw else None
        except (json.JSONDecodeError, TypeError):
            out[row["setting_key"]] = raw
    return out


@router.put("/api/settings")
async def put_settings(request: Request, user: dict = Depends(get_current_user)) -> dict:
    db = get_db()
    body = await request.json()
    data = body.get("settings") if isinstance(body.get("settings"), dict) else body
    if not isinstance(data, dict):
        data = {}
    for key, value in data.items():
        await db.query(
            """insert into public.system_settings (user_id, setting_key, setting_value)
               values ($1, $2, $3)
               on conflict (user_id, setting_key) do update set setting_value = $3""",
            (user["id"], key, json.dumps(value)),
        )
    r = await db.query(
        "select setting_key, setting_value from public.system_settings where user_id = $1",
        (user["id"],),
    )
    out: dict[str, Any] = {}
    for row in r.rows:
        raw = row.get("setting_value")
        try:
            out[row["setting_key"]] = json.loads(raw) if raw else None
        except (json.JSONDecodeError, TypeError):
            out[row["setting_key"]] = raw
    return out


def _register_apify_routes() -> None:
    s = get_settings()
    if not s.ENABLE_INTERNAL_TEST_ROUTES:
        return

    @router.post("/api/apify/test/verify")
    async def apify_verify(request: Request, user: dict = Depends(get_current_user)) -> dict:
        body = await request.json()
        api_key_id = body.get("api_key_id") or body.get("apiKeyId")
        if not api_key_id:
            raise HTTPException(status_code=400, detail="api_key_id wajib")
        db = get_db()
        state = get_state()
        ctx = state.obs_context()
        api_key = await apify.get_owned_gateway_key_for_provider(
            db, tenant_id=user["id"], api_key_id=api_key_id, provider="apify"
        )
        if not api_key:
            raise HTTPException(status_code=404, detail="Gateway API key Apify tidak ditemukan atau tidak diizinkan.")
        credential = await cred_util.find_latest_active_credential(db, user_id=user["id"], provider="apify")
        token = apify.get_apify_token_from_credential(credential)
        await obs.log_gateway_request(
            ctx,
            {
                "tenantId": user["id"],
                "apiKeyId": api_key["id"],
                "provider": "apify",
                "method": "GET",
                "statusCode": 200 if credential and token else 404,
                "responseTimeMs": 1,
                "originDomain": "dashboard-internal",
                "requestPath": "/verify",
                "errorMessage": None if credential and token else "Credential Apify aktif tidak ditemukan",
                "credentialId": credential["id"] if credential else None,
                "clientAuthUsed": bool(api_key.get("client_username")),
                "upstreamStatus": 200 if credential and token else 404,
                "metadata": {"helper_test": True, "verify_only": True},
            },
        )
        if not credential or not token:
            raise HTTPException(
                status_code=404,
                detail="Credential Apify aktif tidak ditemukan atau api_token kosong.",
            )
        return {
            "ok": True,
            "provider": "apify",
            "apiKey": {"id": api_key["id"], "name": api_key.get("name") or "Unnamed"},
            "credential": {"id": credential["id"]},
            "defaults": {
                "listActorsPath": "/acts?limit=10",
                "listTasksPath": "/actor-tasks?limit=10",
                "runActorPath": "/acts/:actorId/runs?waitForFinish=30",
                "runTaskPath": "/actor-tasks/:taskId/runs?waitForFinish=30",
            },
        }

    @router.get("/api/apify/test/actors")
    async def apify_actors(
        user: dict = Depends(get_current_user),
        apiKeyId: str = Query(...),
        limit: int = Query(10),
        offset: int = Query(0),
    ) -> dict:
        db = get_db()
        state = get_state()
        ctx = state.obs_context()
        api_key = await apify.get_owned_gateway_key_for_provider(
            db, tenant_id=user["id"], api_key_id=apiKeyId, provider="apify"
        )
        if not api_key:
            raise HTTPException(status_code=404, detail="Gateway API key Apify tidak ditemukan atau tidak diizinkan.")
        result = await apify.call_apify_helper(
            ctx=ctx,
            tenant_id=user["id"],
            api_key=api_key,
            path="/acts",
            query={"limit": limit, "offset": offset},
            request_path="/acts",
        )
        if not result["ok"]:
            raise HTTPException(status_code=result.get("status", 500), detail=result.get("error", "Gagal memuat actors."))
        return apify.normalize_apify_collection(result["payload"])

    @router.get("/api/apify/test/tasks")
    async def apify_tasks(
        user: dict = Depends(get_current_user),
        apiKeyId: str = Query(...),
        limit: int = Query(10),
        offset: int = Query(0),
    ) -> dict:
        db = get_db()
        state = get_state()
        ctx = state.obs_context()
        api_key = await apify.get_owned_gateway_key_for_provider(
            db, tenant_id=user["id"], api_key_id=apiKeyId, provider="apify"
        )
        if not api_key:
            raise HTTPException(status_code=404, detail="Gateway API key Apify tidak ditemukan atau tidak diizinkan.")
        result = await apify.call_apify_helper(
            ctx=ctx,
            tenant_id=user["id"],
            api_key=api_key,
            path="/actor-tasks",
            query={"limit": limit, "offset": offset},
            request_path="/actor-tasks",
        )
        if not result["ok"]:
            raise HTTPException(status_code=result.get("status", 500), detail=result.get("error", "Gagal memuat tasks."))
        return apify.normalize_apify_collection(result["payload"])

    @router.post("/api/apify/test/run")
    async def apify_run(request: Request, user: dict = Depends(get_current_user)) -> dict:
        body = await request.json()
        api_key_id = body.get("api_key_id") or body.get("apiKeyId")
        mode = "task" if body.get("mode") == "task" else "actor"
        target_id = str(body.get("target_id") or body.get("targetId") or "").strip()
        wait = int(body.get("wait_for_finish") or body.get("waitForFinish") or 30)
        inp = body.get("input") if isinstance(body.get("input"), dict) else {}
        if not api_key_id:
            raise HTTPException(status_code=400, detail="api_key_id wajib")
        if not target_id:
            raise HTTPException(status_code=400, detail="target_id wajib")
        db = get_db()
        state = get_state()
        ctx = state.obs_context()
        api_key = await apify.get_owned_gateway_key_for_provider(
            db, tenant_id=user["id"], api_key_id=api_key_id, provider="apify"
        )
        if not api_key:
            raise HTTPException(status_code=404, detail="Gateway API key Apify tidak ditemukan atau tidak diizinkan.")
        path = (
            f"/actor-tasks/{__import__('urllib.parse').quote(target_id, safe='')}/runs"
            if mode == "task"
            else f"/acts/{__import__('urllib.parse').quote(target_id, safe='')}/runs"
        )
        w = wait if wait > 0 and __import__("math").isfinite(wait) else 30
        result = await apify.call_apify_helper(
            ctx=ctx,
            tenant_id=user["id"],
            api_key=api_key,
            path=path,
            method="POST",
            query={"waitForFinish": w},
            body=inp,
            request_path=path,
        )
        if not result["ok"]:
            raise HTTPException(
                status_code=result.get("status", 500),
                detail=result.get("error", "Gagal menjalankan Apify run."),
            )
        return apify.normalize_apify_run(result["payload"])

    @router.get("/api/apify/test/runs/{run_id}")
    async def apify_run_get(
        run_id: str,
        user: dict = Depends(get_current_user),
        apiKeyId: str = Query(...),
    ) -> dict:
        db = get_db()
        state = get_state()
        ctx = state.obs_context()
        api_key = await apify.get_owned_gateway_key_for_provider(
            db, tenant_id=user["id"], api_key_id=apiKeyId, provider="apify"
        )
        if not api_key:
            raise HTTPException(status_code=404, detail="Gateway API key Apify tidak ditemukan atau tidak diizinkan.")
        path = f"/actor-runs/{__import__('urllib.parse').quote(run_id, safe='')}"
        result = await apify.call_apify_helper(
            ctx=ctx, tenant_id=user["id"], api_key=api_key, path=path, request_path=path
        )
        if not result["ok"]:
            raise HTTPException(
                status_code=result.get("status", 500),
                detail=result.get("error", "Gagal memuat status run."),
            )
        return apify.normalize_apify_run(result["payload"])

    @router.get("/api/apify/test/datasets/{dataset_id}/items")
    async def apify_dataset_items(
        dataset_id: str,
        user: dict = Depends(get_current_user),
        apiKeyId: str = Query(...),
        limit: int | None = Query(10),
        offset: int | None = Query(0),
        clean: int | None = Query(1),
    ) -> dict:
        db = get_db()
        state = get_state()
        ctx = state.obs_context()
        api_key = await apify.get_owned_gateway_key_for_provider(
            db, tenant_id=user["id"], api_key_id=apiKeyId, provider="apify"
        )
        if not api_key:
            raise HTTPException(status_code=404, detail="Gateway API key Apify tidak ditemukan atau tidak diizinkan.")
        path = f"/datasets/{__import__('urllib.parse').quote(dataset_id, safe='')}/items"
        result = await apify.call_apify_helper(
            ctx=ctx,
            tenant_id=user["id"],
            api_key=api_key,
            path=path,
            query={"limit": limit, "offset": offset, "clean": clean},
            request_path=path,
        )
        if not result["ok"]:
            raise HTTPException(
                status_code=result.get("status", 500),
                detail=result.get("error", "Gagal memuat data dataset."),
            )
        return apify.normalize_apify_collection(result["payload"])

    @router.post("/api/apify/test/smoke")
    async def apify_smoke(request: Request, user: dict = Depends(get_current_user)) -> dict:
        body = await request.json()
        api_key_id = body.get("api_key_id") or body.get("apiKeyId")
        if not api_key_id:
            raise HTTPException(status_code=400, detail="api_key_id wajib")
        db = get_db()
        state = get_state()
        ctx = state.obs_context()
        api_key = await apify.get_owned_gateway_key_for_provider(
            db, tenant_id=user["id"], api_key_id=api_key_id, provider="apify"
        )
        if not api_key:
            raise HTTPException(status_code=404, detail="Gateway API key Apify tidak ditemukan atau tidak diizinkan.")
        verify_ok = bool(await cred_util.find_latest_active_credential(db, user_id=user["id"], provider="apify"))
        ar, tr = await __import__("asyncio").gather(
            apify.call_apify_helper(
                ctx=ctx,
                tenant_id=user["id"],
                api_key=api_key,
                path="/acts",
                query={"limit": 10},
                request_path="/acts",
            ),
            apify.call_apify_helper(
                ctx=ctx,
                tenant_id=user["id"],
                api_key=api_key,
                path="/actor-tasks",
                query={"limit": 10},
                request_path="/actor-tasks",
            ),
        )
        if not ar["ok"]:
            raise HTTPException(status_code=ar.get("status", 500), detail=ar.get("error", "Verifikasi actor gagal."))
        if not tr["ok"]:
            raise HTTPException(status_code=tr.get("status", 500), detail=tr.get("error", "Verifikasi task gagal."))
        return apify.normalize_apify_smoke(
            verify_ok=verify_ok,
            actors=apify.normalize_apify_collection(ar["payload"]),
            tasks=apify.normalize_apify_collection(tr["payload"]),
        )


_register_apify_routes()
