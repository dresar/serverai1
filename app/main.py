"""FastAPI entrypoint — mirror server1 index.js + app.js."""
from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.cache_l1 import L1Cache
from app.cache_l2 import L2Cache
from app.circuit_breaker import CircuitBreaker
from app.config import assert_config, get_settings
from app.db import close_db, init_db
from app.gateway.router import router as gateway_router
from app.memory_store import MemoryStore
from app.metrics_prometheus import http_request_duration_ms
from app.routers import auth_public, dashboard, health
from app.security.jwt_tokens import verify_jwt
from app.services import api_keys as api_keys_svc
from app.services import ai_models as ai_models_svc
from app.services.migrations import run_all
from app.services.observability_schema import ensure_observability_schema
from app.state import AppState, set_state
from app.ws_hub import WsHub


async def _upload_expiry_loop(state: AppState) -> None:
    from app.services import playground as pgw

    while True:
        try:
            await asyncio.sleep(2 * 60)
            r = await state.db.query(
                """select id, tenant_id, credential_id, provider, external_id from public.upload_expiry
                    where delete_at <= now() limit 50"""
            )
            for row in r.rows:
                try:
                    await pgw.delete_from_cloud(
                        state.db,
                        credential_id=str(row["credential_id"]),
                        user_id=str(row["tenant_id"]),
                        provider=str(row["provider"]),
                        external_id=str(row["external_id"]),
                    )
                except Exception:
                    pass
                await state.db.query("delete from public.upload_expiry where id = $1", (row["id"],))
        except asyncio.CancelledError:
            raise
        except Exception:
            pass


async def _health_refresh_loop(state: AppState) -> None:
    while True:
        try:
            await asyncio.sleep(5)
            t0 = time.perf_counter()
            try:
                await state.db.query("select 1 as ok")
                state.health["dbOk"] = True
            except Exception:
                state.health["dbOk"] = False
            state.health["dbLatencyMs"] = int((time.perf_counter() - t0) * 1000)
            state.health["ok"] = bool(state.health.get("dbOk"))
            state.health["checkedAt"] = int(time.time() * 1000)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    assert_config()
    s = get_settings()
    db = await init_db(s)
    runtime_migrations = s.ENABLE_RUNTIME_MIGRATIONS and not s.is_serverless
    gateway_log_mode = "light" if s.is_serverless else "full"
    if runtime_migrations:
        await run_all(db)
        await api_keys_svc.ensure_api_key_schema(db)
        await ensure_observability_schema(db)
        await ai_models_svc.ensure_ai_models_schema(db)

    state = AppState(
        db=db,
        l1=L1Cache(),
        l2=L2Cache(),
        rate_store=MemoryStore(),
        breaker=CircuitBreaker(
            timeout_ms=s.BREAKER_TIMEOUT_MS,
            half_open_after_ms=s.BREAKER_HALF_OPEN_AFTER_MS,
        ),
        ws=WsHub(),
        health={
            "ok": True,
            "checkedAt": int(time.time() * 1000),
            "dbOk": True,
            "sharedStateOk": True,
            "sharedStateMode": "local-memory",
            "cacheMode": "local-memory",
            "rateLimitMode": "local-memory",
            "runtimeMigrationsEnabled": runtime_migrations,
            "observabilityMode": gateway_log_mode,
        },
        gateway_log_mode=gateway_log_mode,
    )
    set_state(state)

    bg_tasks: list[asyncio.Task] = []
    if not s.is_serverless:
        await state.db.query("select 1")
        bg_tasks.append(asyncio.create_task(_health_refresh_loop(state)))
        bg_tasks.append(asyncio.create_task(_upload_expiry_loop(state)))

    yield

    for t in bg_tasks:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass
    await close_db()


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(
        title="Unified AI Gateway API",
        version="1.0.0",
        lifespan=lifespan,
        openapi_url="/openapi.json" if s.EXPOSE_OPENAPI else None,
        docs_url="/docs" if s.EXPOSE_OPENAPI else None,
        redoc_url=None,
    )

    if s.CORS_ALLOW_ALL:
        app.add_middleware(
            CORSMiddleware,
            allow_origin_regex=".*",
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Signature", "X-Timestamp", "X-Nonce"],
        )
    else:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=s.cors_origins_list(),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Signature", "X-Timestamp", "X-Nonce"],
        )

    class SecurityHeadersMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            resp = await call_next(request)
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["X-XSS-Protection"] = "1; mode=block"
            resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            return resp

    app.add_middleware(SecurityHeadersMiddleware)

    class MetricsMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            t0 = time.perf_counter()
            resp = await call_next(request)
            ms = (time.perf_counter() - t0) * 1000
            route = request.url.path
            http_request_duration_ms.labels(
                method=request.method,
                route=route,
                status=str(resp.status_code),
            ).observe(ms)
            return resp

    app.add_middleware(MetricsMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse({"error": "Permintaan tidak valid."}, status_code=400)

    @app.exception_handler(StarletteHTTPException)
    async def starlette_http_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            return JSONResponse({"error": "Rute tidak ditemukan."}, status_code=404)
        d = exc.detail
        if isinstance(d, str):
            return JSONResponse({"error": d}, status_code=exc.status_code)
        return JSONResponse({"detail": d}, status_code=exc.status_code)

    app.include_router(health.router)
    app.include_router(auth_public.router)
    app.include_router(dashboard.router)
    app.include_router(gateway_router)

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        from app.state import get_state

        token = websocket.query_params.get("token") or ""
        try:
            payload = verify_jwt(token) if token else None
            tenant_id = str(payload["sub"]) if payload and payload.get("sub") else None
        except Exception:
            tenant_id = None
        if not tenant_id:
            await websocket.close(code=1008)
            return
        await websocket.accept()
        st = get_state()
        st.ws.register(websocket, tenant_id)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            st.ws.unregister(websocket)

    return app


app = create_app()
