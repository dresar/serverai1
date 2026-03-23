"""Gateway publik: API key, HMAC, proxy (mirror server1 app.js gateway)."""
from __future__ import annotations

import base64
import json
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import bcrypt
import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.db import Database
from app.gateway import credentials as cred_util
from app.security.hmac_util import safe_equal_hex, sha256_hex, sign_hmac_hex
from app.services import observability as obs
from app.services import playground as pgw
from app.services.api_keys import get_api_key, hash_api_key
from app.state import AppState, get_state

router = APIRouter(prefix="/gateway", tags=["gateway"])

# Provider data/news (perlu credential + injeksi query/header); rapidapi dipisah (host dinamis).
_GATEWAY_DATA_PROVIDERS = frozenset(
    {"newsapi", "gnews", "mediastack", "openweather", "alphavantage", "huggingface"}
)

_SUPPORTED_GATEWAY_PROXY = (
    "gemini, groq, apify, cloudinary, imagekit, newsapi, gnews, mediastack, openweather, "
    "alphavantage, huggingface, rapidapi"
)


def _parse_cred_blob(cred: dict | None) -> dict:
    if not cred or not cred.get("credentials"):
        return {}
    raw = cred["credentials"]
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _merge_url_query(url: str, extra: dict[str, str]) -> str:
    pu = urlparse(url)
    qs = parse_qs(pu.query)
    for k, v in extra.items():
        if v is not None and str(v).strip() != "":
            qs[k] = [str(v)]
    new_q = urlencode(qs, doseq=True)
    return urlunparse((pu.scheme, pu.netloc, pu.path, pu.params, new_q, pu.fragment))


def _extract_api_key(request: Request) -> str | None:
    h = request.headers.get("x-api-key")
    if h:
        return h.strip()
    auth = request.headers.get("authorization")
    if auth and auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def _get_state_dep() -> AppState:
    return get_state()


async def _resolve_api_key(request: Request, state: AppState) -> dict:
    plain = _extract_api_key(request)
    if not plain:
        raise HTTPException(status_code=401, detail="Missing API key (use X-API-Key or Authorization: Bearer <key>)")
    kh = hash_api_key(plain)
    row = await get_api_key(state.db, state.l1, state.l2, kh)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    now = time.time() * 1000
    if row.get("status") != "active":
        gu = row.get("grace_until")
        grace_until = gu.timestamp() * 1000 if hasattr(gu, "timestamp") else 0
        if not grace_until or now > grace_until:
            raise HTTPException(status_code=403, detail="API key disabled")
    if row.get("client_username") and row.get("client_password_hash"):
        auth = request.headers.get("authorization")
        if not auth or not auth.startswith("Basic "):
            raise HTTPException(
                status_code=401,
                detail="This API key requires Basic Auth (Authorization: Basic <base64(username:password)>)",
            )
        try:
            raw = base64.b64decode(auth[6:].strip()).decode("utf-8", errors="replace")
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid Basic Auth header")
        colon = raw.find(":")
        user = raw[:colon].strip() if colon >= 0 else raw.strip()
        pw = raw[colon + 1 :] if colon >= 0 else ""
        exp_user = str(row.get("client_username") or "").strip()
        if user != exp_user or not bcrypt.checkpw(
            pw.encode("utf-8"), str(row.get("client_password_hash") or "").encode("utf-8")
        ):
            raise HTTPException(status_code=401, detail="Invalid client username or password")
    return row


async def _hmac_secret_for_request(state: AppState, api_key: dict, request: Request) -> str | None:
    sig = request.headers.get("x-signature") or ""
    if not sig or len(sig) < 16:
        return None
    tid = api_key.get("tenant_id")
    cache_key = f"hmac:{tid}"
    c = state.l1.get(cache_key)
    if c:
        return c
    r = await state.db.query("select hmac_secret from public.users where id = $1 limit 1", (tid,))
    secret = r.rows[0].get("hmac_secret") if r.rows else None
    if not secret:
        import secrets

        secret = secrets.token_hex(32)
        await state.db.query("update public.users set hmac_secret = $1 where id = $2", (secret, tid))
    state.l1.set(cache_key, secret, 30 * 60 * 1000)
    return secret


async def _verify_hmac_if_present(state: AppState, api_key: dict, request: Request, body: bytes) -> None:
    if (request.headers.get("content-type") or "").startswith("multipart/form-data"):
        return
    sig = request.headers.get("x-signature") or ""
    if not sig or len(sig) < 16:
        return
    s = get_settings()
    secret = await _hmac_secret_for_request(state, api_key, request)
    if not secret:
        raise HTTPException(status_code=401, detail="Invalid signature")
    ts_raw = request.headers.get("x-timestamp") or ""
    nonce = request.headers.get("x-nonce") or ""
    try:
        ts = float(ts_raw)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid signature")
    if not nonce or len(nonce) < 8:
        raise HTTPException(status_code=401, detail="Invalid signature")
    if abs(time.time() * 1000 - ts) > s.HMAC_MAX_SKEW_MS:
        raise HTTPException(status_code=401, detail="Invalid signature")
    method = request.method.upper()
    url = request.url
    path = url.path + (f"?{url.query}" if url.query else "")
    bh = sha256_hex(body)
    message = f"{int(ts)}.{nonce}.{method}.{path}.{bh}"
    expected = sign_hmac_hex(secret, message)
    if not safe_equal_hex(expected, sig):
        raise HTTPException(status_code=401, detail="Invalid signature")


async def _gateway_rate_limit(state: AppState, api_key: dict, request: Request) -> None:
    s = get_settings()
    limit = int(api_key.get("quota_per_minute") or s.RATE_LIMIT_DEFAULT)
    key = f"rlk:{api_key.get('id')}:{request.url.path}"
    now = str(int(time.time() * 1000))
    res = await state.rate_store.eval("rl", 1, key, now, str(s.RATE_LIMIT_WINDOW_MS), str(limit))
    if int(res[0]) > limit:
        raise HTTPException(status_code=429, detail="Rate limited")


@router.get("/verify")
async def gateway_verify() -> dict:
    return {"ok": True}


@router.post("/cloudinary/upload")
async def gw_cloudinary_upload(
    request: Request,
    file: UploadFile = File(...),
    credential_id: str = Form(...),
    state: AppState = Depends(_get_state_dep),
) -> JSONResponse:
    api_key = await _resolve_api_key(request, state)
    allowed = api_key.get("allowed_providers") or []
    if allowed and "cloudinary" not in allowed:
        raise HTTPException(status_code=403, detail="Provider not allowed for this API key")
    await _verify_hmac_if_present(state, api_key, request, b"")
    await _gateway_rate_limit(state, api_key, request)
    buf = await file.read()
    s = get_settings()
    if len(buf) > s.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Ukuran file melebihi batas {s.MAX_UPLOAD_BYTES // (1024*1024)} MB.")
    tid = str(api_key["tenant_id"])
    result = await pgw.upload_to_cloud(
        state.db,
        user_id=tid,
        credential_id=credential_id,
        provider="cloudinary",
        buffer=buf,
        mime_type=file.content_type or "application/octet-stream",
        original_name=file.filename or "upload",
    )
    if result.get("error"):
        return JSONResponse({"error": result["error"]}, status_code=400)
    await obs.log_gateway_request(
        state.obs_context(),
        {
            "apiKeyId": str(api_key["id"]),
            "tenantId": tid,
            "provider": "cloudinary",
            "method": "POST",
            "statusCode": 200,
            "responseTimeMs": 0,
            "originDomain": _origin_domain(request),
            "requestPath": request.url.path,
            "credentialId": credential_id,
            "clientAuthUsed": bool(api_key.get("client_username")),
        },
    )
    return JSONResponse(result)


@router.post("/imagekit/upload")
async def gw_imagekit_upload(
    request: Request,
    file: UploadFile = File(...),
    credential_id: str = Form(...),
    state: AppState = Depends(_get_state_dep),
) -> JSONResponse:
    api_key = await _resolve_api_key(request, state)
    allowed = api_key.get("allowed_providers") or []
    if allowed and "imagekit" not in allowed:
        raise HTTPException(status_code=403, detail="Provider not allowed for this API key")
    await _verify_hmac_if_present(state, api_key, request, b"")
    await _gateway_rate_limit(state, api_key, request)
    buf = await file.read()
    s = get_settings()
    if len(buf) > s.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large")
    tid = str(api_key["tenant_id"])
    result = await pgw.upload_to_cloud(
        state.db,
        user_id=tid,
        credential_id=credential_id,
        provider="imagekit",
        buffer=buf,
        mime_type=file.content_type or "application/octet-stream",
        original_name=file.filename or "upload",
    )
    if result.get("error"):
        return JSONResponse({"error": result["error"]}, status_code=400)
    await obs.log_gateway_request(
        state.obs_context(),
        {
            "apiKeyId": str(api_key["id"]),
            "tenantId": tid,
            "provider": "imagekit",
            "method": "POST",
            "statusCode": 200,
            "responseTimeMs": 0,
            "originDomain": _origin_domain(request),
            "requestPath": request.url.path,
            "credentialId": credential_id,
            "clientAuthUsed": bool(api_key.get("client_username")),
        },
    )
    return JSONResponse(result)


def _origin_domain(request: Request) -> str | None:
    o = request.headers.get("origin") or request.headers.get("referer")
    if not o:
        return None
    try:
        return urlparse(o).hostname
    except Exception:
        return None


@router.post("/gemini/chat")
@router.post("/groq/chat")
async def gw_chat(request: Request, state: AppState = Depends(_get_state_dep)) -> JSONResponse:
    path = request.url.path
    provider = "gemini" if path.endswith("/gemini/chat") else "groq"
    api_key = await _resolve_api_key(request, state)
    allowed = api_key.get("allowed_providers") or []
    if allowed and provider not in allowed:
        raise HTTPException(status_code=403, detail="Provider not allowed for this API key")
    body = await request.body()
    await _verify_hmac_if_present(state, api_key, request, body)
    await _gateway_rate_limit(state, api_key, request)
    import json

    try:
        data = json.loads(body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        data = {}
    tid = str(api_key["tenant_id"])
    cred = await cred_util.find_latest_active_credential(state.db, user_id=tid, provider=provider)
    if not cred:
        return JSONResponse(
            {
                "error": f"No active {provider} credential with valid API key. Di Credentials, tambah atau edit credential {provider} dan isi API key (sama seperti yang dipakai di Playground)."
            },
            status_code=404,
        )
    start = time.time()
    result = await pgw.chat_with_provider(
        state.db,
        user_id=tid,
        credential_id=str(cred["id"]),
        prompt=str(data.get("prompt") or ""),
        image_base64=str(data.get("image_base64") or data.get("imageBase64") or ""),
        model_id=data.get("model_id") or data.get("modelId"),
    )
    ms = int((time.time() - start) * 1000)
    code = 400 if result.get("error") else 200
    await obs.log_gateway_request(
        state.obs_context(),
        {
            "apiKeyId": str(api_key["id"]),
            "tenantId": tid,
            "provider": provider,
            "method": "POST",
            "statusCode": code,
            "responseTimeMs": ms,
            "originDomain": _origin_domain(request),
            "requestPath": request.url.path,
            "errorMessage": result.get("error"),
            "credentialId": str(cred["id"]),
            "clientAuthUsed": bool(api_key.get("client_username")),
            "metadata": {} if result.get("error") else {"model": result.get("model")},
        },
    )
    if result.get("error"):
        return JSONResponse({"error": result["error"]}, status_code=400)
    return JSONResponse({"text": result.get("text"), "model": result.get("model")})


@router.api_route("/{provider}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def gw_proxy(provider: str, path: str, request: Request, state: AppState = Depends(_get_state_dep)) -> Response:
    api_key = await _resolve_api_key(request, state)
    allowed = api_key.get("allowed_providers") or []
    if allowed and provider not in allowed:
        raise HTTPException(status_code=403, detail="Provider not allowed for this API key")
    body = await request.body()
    await _verify_hmac_if_present(state, api_key, request, body)
    await _gateway_rate_limit(state, api_key, request)
    s = get_settings()
    if len(body) > s.MAX_PROXY_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large")
    upstreams = s.provider_upstreams
    tid = str(api_key["tenant_id"])
    cred = await cred_util.find_latest_active_credential(state.db, user_id=tid, provider=provider)
    cred_blob = _parse_cred_blob(cred)

    sub_path = "/" + path if path else "/"
    if not sub_path.startswith("/"):
        sub_path = "/" + sub_path
    client_q = request.url.query or ""

    headers: dict[str, str] = {}
    ct = request.headers.get("content-type") or "application/json"
    headers["content-type"] = ct

    if provider == "rapidapi":
        if not cred:
            return JSONResponse(
                {
                    "error": "Tidak ada credential RapidAPI aktif. Tambahkan di Credentials (api_key + rapidapi_host)."
                },
                status_code=404,
            )
        host = (cred_blob.get("rapidapi_host") or cred_blob.get("rapidapiHost") or "").strip()
        rkey = (cred_blob.get("api_key") or cred_blob.get("apiKey") or "").strip()
        if not host or not rkey:
            return JSONResponse(
                {"error": "Credential RapidAPI tidak lengkap (api_key + rapidapi_host)."},
                status_code=404,
            )
        host = host.replace("https://", "").replace("http://", "").strip().split("/")[0]
        target = f"https://{host}{sub_path}"
        if client_q:
            target = f"{target}?{client_q}"
        headers["X-RapidAPI-Key"] = rkey
        headers["X-RapidAPI-Host"] = host
        base = f"https://{host}"
    else:
        base = upstreams.get(provider)
        if not base:
            raise HTTPException(
                status_code=503,
                detail="No upstream untuk provider: " + provider + ". Didukung: " + _SUPPORTED_GATEWAY_PROXY,
            )
        u = urlparse(base)
        target = urlunparse((u.scheme, u.netloc, sub_path, "", client_q, ""))
        provider_api_key = cred_blob.get("api_key") or cred_blob.get("apiKey")

        if provider == "gemini" and provider_api_key:
            pu = urlparse(target)
            qs = parse_qs(pu.query)
            qs["key"] = [str(provider_api_key)]
            new_q = urlencode(qs, doseq=True)
            target = urlunparse((pu.scheme, pu.netloc, pu.path, pu.params, new_q, pu.fragment))
        elif provider == "groq" and provider_api_key:
            headers["Authorization"] = f"Bearer {provider_api_key}"
        elif provider in _GATEWAY_DATA_PROVIDERS:
            if not cred:
                return JSONResponse(
                    {"error": f"Tidak ada credential {provider} aktif. Tambahkan di Credentials."},
                    status_code=404,
                )
            extra: dict[str, str] = {}
            if provider == "newsapi":
                extra["apiKey"] = str(cred_blob.get("api_key") or cred_blob.get("apiKey") or "")
            elif provider == "gnews":
                extra["token"] = str(
                    cred_blob.get("token") or cred_blob.get("api_key") or cred_blob.get("apiKey") or ""
                )
            elif provider == "mediastack":
                extra["access_key"] = str(cred_blob.get("access_key") or cred_blob.get("accessKey") or "")
            elif provider == "openweather":
                extra["appid"] = str(cred_blob.get("appid") or cred_blob.get("appId") or "")
            elif provider == "alphavantage":
                extra["apikey"] = str(cred_blob.get("api_key") or cred_blob.get("apiKey") or "")
            elif provider == "huggingface":
                hfk = cred_blob.get("api_key") or cred_blob.get("apiKey")
                if hfk:
                    headers["Authorization"] = f"Bearer {hfk}"
            if extra:
                target = _merge_url_query(target, extra)

    method = request.method.upper()
    start = time.time()

    async def _do():
        async with httpx.AsyncClient(timeout=s.BREAKER_TIMEOUT_MS / 1000.0) as client:
            return await client.request(method, target, content=body if body else None, headers=headers)

    try:
        res = await state.breaker.run(f"{provider}:{base}", _do)
    except RuntimeError:
        return JSONResponse({"error": "Upstream gagal"}, status_code=503)
    except Exception as e:
        await obs.log_gateway_request(
            state.obs_context(),
            {
                "apiKeyId": str(api_key["id"]),
                "tenantId": tid,
                "provider": provider,
                "method": method,
                "statusCode": 503,
                "responseTimeMs": int((time.time() - start) * 1000),
                "originDomain": _origin_domain(request),
                "requestPath": sub_path,
                "errorMessage": str(e),
                "credentialId": str(cred["id"]) if cred else None,
                "clientAuthUsed": bool(api_key.get("client_username")),
                "breakerOpen": True,
                "upstreamStatus": 503,
            },
        )
        return JSONResponse({"error": "Upstream gagal"}, status_code=503)
    ms = int((time.time() - start) * 1000)
    err_msg = None
    if res.status_code >= 400:
        try:
            err_msg = res.text[:240]
        except Exception:
            err_msg = "error"
    await obs.log_gateway_request(
        state.obs_context(),
        {
            "apiKeyId": str(api_key["id"]),
            "tenantId": tid,
            "provider": provider,
            "method": method,
            "statusCode": res.status_code,
            "responseTimeMs": ms,
            "originDomain": _origin_domain(request),
            "requestPath": sub_path,
            "errorMessage": err_msg,
            "credentialId": str(cred["id"]) if cred else None,
            "clientAuthUsed": bool(api_key.get("client_username")),
            "upstreamStatus": res.status_code,
            "metadata": {"upstream": base},
        },
    )
    hop = {
        "connection",
        "transfer-encoding",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "upgrade",
    }
    h = {k: v for k, v in res.headers.items() if k.lower() not in hop}
    return Response(content=res.content, status_code=res.status_code, headers=h)
