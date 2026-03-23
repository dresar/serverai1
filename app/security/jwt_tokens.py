"""Kompatibel dengan server1/src/security/jwt.js (jose HS256, iss/aud, 7d)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from app.config import get_settings

ISS = "unified-ai-gateway"
AUD = "unified-ai-gateway"


def sign_jwt(*, sub: str, email: str, display_name: str | None) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "email": email,
        "displayName": display_name,
        "iss": ISS,
        "aud": AUD,
        "iat": now,
        "exp": now + timedelta(days=7),
    }
    return jwt.encode(payload, s.JWT_SECRET, algorithm="HS256")


def verify_jwt(token: str) -> dict:
    s = get_settings()
    return jwt.decode(
        token,
        s.JWT_SECRET,
        algorithms=["HS256"],
        audience=AUD,
        issuer=ISS,
    )
