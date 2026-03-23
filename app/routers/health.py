"""Health, metrics, root HTML."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.metrics_prometheus import metrics_text
from app.state import AppState, get_state

router = APIRouter(tags=["health"])


def _state_dep() -> AppState:
    return get_state()


@router.get("/")
async def root_html() -> Response:
    started = datetime.now(timezone.utc).isoformat()
    html = f"""<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8"/><title>Unified AI Gateway — API aktif</title></head>
<body><p>Online</p><h1>Unified AI Gateway</h1><p>Backend API berjalan.</p>
<ul><li><a href="/ping">/ping</a></li><li><a href="/healthz">/healthz</a></li></ul>
<p class="muted">{started}</p></body></html>"""
    return Response(content=html, media_type="text/html; charset=utf-8")


@router.get("/ping")
async def ping() -> dict:
    return {"ok": True}


@router.head("/ping")
async def ping_head() -> Response:
    """Beberapa client (mis. wait-on default `http://`) memakai HEAD."""
    return Response(status_code=200)


@router.get("/healthz")
async def healthz(state: AppState = Depends(_state_dep)) -> Response:
    s = get_settings()
    if s.is_serverless:
        try:
            await state.db.query("select 1")
            state.health["dbOk"] = True
        except Exception:
            state.health["dbOk"] = False
        state.health["ok"] = bool(state.health.get("dbOk"))
        state.health["checkedAt"] = int(datetime.now(timezone.utc).timestamp() * 1000)
    body = {**state.health}
    code = 200 if body.get("ok") else 503
    return JSONResponse(body, status_code=code)


@router.get("/metrics")
async def metrics() -> Response:
    s = get_settings()
    if not s.EXPOSE_METRICS or s.is_serverless:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return Response(content=metrics_text(), media_type="text/plain; version=0.0.4")
