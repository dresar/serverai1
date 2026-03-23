"""Dependencies FastAPI: auth JWT, rate limit."""
from __future__ import annotations

import time

from fastapi import Depends, Header, HTTPException, Request

from app.config import get_settings
from app.db import get_db
from app.security.jwt_tokens import verify_jwt
from app.state import get_state


async def get_current_user(authorization: str | None = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization[7:].strip()
    try:
        payload = verify_jwt(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")

    uid = str(payload["sub"])
    db = get_db()
    r = await db.query(
        "select id, email, display_name from public.users where id = $1::uuid limit 1",
        (uid,),
    )
    if not r.rows:
        raise HTTPException(
            status_code=401,
            detail="Sesi tidak valid: akun tidak ada di database ini. Logout lalu login atau daftar lagi (mis. setelah ganti DATABASE_URL / Neon).",
        )
    row = r.rows[0]
    return {
        "id": str(row["id"]),
        "email": row.get("email"),
        "displayName": row.get("display_name"),
    }


async def rate_limit_auth(request: Request, user: dict = Depends(get_current_user)) -> None:
    await _rate_limit(request, prefix="auth", id_part=user["id"], limit=10)


async def rate_limit_login_register(request: Request) -> None:
    """10 req / window untuk /api/auth/login|register|dev-login (anon, mirror Node)."""
    await _rate_limit(request, prefix="auth", id_part="anon", limit=10)


async def rate_limit_default(request: Request, user: dict = Depends(get_current_user)) -> None:
    s = get_settings()
    await _rate_limit(request, prefix="rl", id_part=user["id"], limit=s.RATE_LIMIT_DEFAULT)


async def _rate_limit(request: Request, *, prefix: str, id_part: str, limit: int) -> None:
    state = get_state()
    s = get_settings()
    route = str(request.url.path)
    key = f"{prefix}:{id_part}:{route}"
    now = str(int(time.time() * 1000))
    res = await state.rate_store.eval("rl", 1, key, now, str(s.RATE_LIMIT_WINDOW_MS), str(limit))
    current, _ttl, remaining = res[0], res[1], res[2]
    if int(current) > limit:
        raise HTTPException(status_code=429, detail="Rate limited")
