"""python -m scripts.seed — mirror server1/seed.js (development only)."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets

import bcrypt

from app.config import get_settings
from app.db import Database, close_db, init_db


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


async def seed_database(db: Database) -> None:
    """
    Data dummy development:
    - User: admin@example.com (password default: password123)
    - Gateway API key plain: dev_apikey_change_me
    - Credentials: gemini, groq, imagekit (dummy)
    """
    email = os.getenv("SEED_ADMIN_EMAIL", "admin@example.com")
    password = os.getenv("SEED_ADMIN_PASSWORD", "password123")
    gateway_key = os.getenv("SEED_GATEWAY_API_KEY", "dev_apikey_change_me")

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
    hmac_secret = secrets.token_hex(32)
    print(f"Creating user: {email}")
    ur = await db.query(
        """insert into public.users (email, password_hash, display_name, hmac_secret)
           values ($1, $2, $3, $4)
           on conflict (email) do update set
             password_hash = excluded.password_hash,
             display_name = excluded.display_name,
             hmac_secret = coalesce(public.users.hmac_secret, excluded.hmac_secret)
           returning id""",
        (email, password_hash, "Admin User", hmac_secret),
    )
    user_id = str(ur.rows[0]["id"])
    key_hash = _sha256_hex(gateway_key)
    print("Creating development gateway API key")
    await db.query(
        """insert into public.api_keys (tenant_id, key_hash, status, quota_per_minute)
           values ($1, $2, 'active', 1000)
           on conflict (key_hash) do nothing""",
        (user_id, key_hash),
    )
    print("Creating dummy credentials...")
    creds = [
        ("gemini", "ai", {"api_key": "dummy_gemini_key"}),
        ("groq", "ai", {"api_key": "dummy_groq_key"}),
        (
            "imagekit",
            "media",
            {
                "public_key": "dummy_pk",
                "private_key": "dummy_sk",
                "url_endpoint": "https://ik.imagekit.io/dummy",
            },
        ),
    ]
    for name, ptype, cj in creds:
        await db.query(
            "delete from public.provider_credentials where user_id = $1 and provider_name = $2",
            (user_id, name),
        )
        await db.query(
            """insert into public.provider_credentials (user_id, provider_name, provider_type, credentials)
               values ($1, $2, $3, $4::jsonb)""",
            (user_id, name, ptype, json.dumps(cj)),
        )
    print("Seeding completed successfully!")
    print(f"  Login dashboard: {email} / {password}")
    print(f"  Gateway key (plain): {gateway_key}")
    print("  Gunakan email/password di atas pada form login frontend.")


async def main() -> None:
    s = get_settings()
    if s.is_production or os.getenv("ENABLE_DEV_SEED") != "true":
        print("Seeding hanya diizinkan untuk environment development dengan ENABLE_DEV_SEED=true.")
        raise SystemExit(1)
    if not s.DATABASE_URL:
        print("DATABASE_URL must be set")
        raise SystemExit(1)

    db = await init_db()
    try:
        await seed_database(db)
    finally:
        await close_db()


if __name__ == "__main__":
    asyncio.run(main())
