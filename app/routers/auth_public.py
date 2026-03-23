"""Auth publik: register, login, dev-login."""
from __future__ import annotations

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field

from app.config import get_settings
from app.deps import rate_limit_login_register
from app.db import get_db
from app.security.jwt_tokens import sign_jwt

router = APIRouter(prefix="/api/auth", tags=["auth"])


class AuthBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


@router.post("/register", dependencies=[Depends(rate_limit_login_register)])
async def register(request: Request, body: AuthBody) -> dict:
    s = get_settings()
    if not s.ENABLE_SELF_REGISTRATION:
        raise HTTPException(status_code=403, detail="Pendaftaran mandiri tidak tersedia.")
    db = get_db()
    password_hash = bcrypt.hashpw(body.password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
    import secrets

    hmac_secret = secrets.token_hex(32)
    try:
        r = await db.query(
            """insert into public.users (email, password_hash, hmac_secret)
               values ($1, $2, $3)
               returning id, email, display_name""",
            (body.email.strip().lower(), password_hash, hmac_secret),
        )
    except Exception as e:
        msg = str(e).lower()
        if "duplicate" in msg or "unique" in msg:
            raise HTTPException(status_code=409, detail="Email sudah terdaftar") from e
        raise HTTPException(status_code=500, detail="Gagal membuat user") from e
    user = r.rows[0]
    uid = str(user["id"])
    token = sign_jwt(sub=uid, email=user["email"], display_name=user.get("display_name"))
    return {
        "token": token,
        "user": {"id": uid, "email": user["email"], "displayName": user.get("display_name")},
    }


@router.post("/login", dependencies=[Depends(rate_limit_login_register)])
async def login(request: Request, body: AuthBody) -> dict:
    import time

    db = get_db()
    t0 = time.perf_counter()
    try:
        r = await db.query(
            "select id, email, display_name, password_hash from public.users where email = $1 limit 1",
            (body.email.strip().lower(),),
        )
        user = r.rows[0] if r.rows else None
        if not user:
            raise HTTPException(status_code=401, detail="Email atau password salah.")
        if not bcrypt.checkpw(body.password.encode("utf-8"), str(user["password_hash"]).encode("utf-8")):
            raise HTTPException(status_code=401, detail="Email atau password salah.")
        uid = str(user["id"])
        token = sign_jwt(sub=uid, email=user["email"], display_name=user.get("display_name"))
        return {
            "token": token,
            "user": {"id": uid, "email": user["email"], "displayName": user.get("display_name")},
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Login gagal karena layanan server sedang bermasalah.") from None


@router.post("/dev-login", dependencies=[Depends(rate_limit_login_register)])
async def dev_login(request: Request) -> dict:
    s = get_settings()
    if not s.ENABLE_DEV_LOGIN:
        raise HTTPException(status_code=404, detail="Not found")
    db = get_db()
    email = "admin@example.com"
    password = "password123"
    try:
        data = await request.json()
        if isinstance(data, dict):
            if data.get("email"):
                email = str(data["email"]).strip().lower()
            if data.get("password") is not None:
                password = str(data["password"])
    except Exception:
        pass
    r = await db.query(
        "select id, email, display_name, password_hash from public.users where email = $1 limit 1",
        (email,),
    )
    user = r.rows[0] if r.rows else None
    if not user:
        raise HTTPException(status_code=404, detail="User tidak ditemukan. Jalankan: npm run seed")
    if not bcrypt.checkpw(password.encode("utf-8"), str(user["password_hash"]).encode("utf-8")):
        raise HTTPException(status_code=401, detail="Kredensial tidak valid.")
    uid = str(user["id"])
    token = sign_jwt(sub=uid, email=user["email"], display_name=user.get("display_name"))
    return {
        "token": token,
        "user": {"id": uid, "email": user["email"], "displayName": user.get("display_name")},
    }
