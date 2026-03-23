"""Credential lookup untuk gateway (mirror app.js getCredentialValiditySql + findLatestActiveCredential)."""
from __future__ import annotations

from app.db import Database
from app.services.observability import reactivate_expired_credential_cooldowns


def validity_sql(provider: str) -> str | None:
    p = (provider or "").lower()
    if p in ("gemini", "groq"):
        return "coalesce(credentials->>'api_key', credentials->>'apiKey', '') not in ('', 'dummy_gemini_key', 'dummy_groq_key')"
    if p == "apify":
        return "coalesce(credentials->>'api_token', credentials->>'apiToken', '') <> ''"
    if p == "cloudinary":
        return " and ".join(
            [
                "coalesce(credentials->>'cloud_name', credentials->>'cloudName', '') <> ''",
                "coalesce(credentials->>'api_key', credentials->>'apiKey', '') <> ''",
                "coalesce(credentials->>'api_secret', credentials->>'apiSecret', '') <> ''",
            ]
        )
    if p == "imagekit":
        return " and ".join(
            [
                "coalesce(credentials->>'public_key', credentials->>'publicKey', '') <> ''",
                "coalesce(credentials->>'private_key', credentials->>'privateKey', '') <> ''",
                "coalesce(credentials->>'url_endpoint', credentials->>'urlEndpoint', '') <> ''",
            ]
        )
    if p == "newsapi":
        return "coalesce(credentials->>'api_key', credentials->>'apiKey', '') <> ''"
    if p == "gnews":
        return "coalesce(credentials->>'api_key', credentials->>'apiKey', credentials->>'token', '') <> ''"
    if p == "mediastack":
        return "coalesce(credentials->>'access_key', credentials->>'accessKey', '') <> ''"
    if p == "openweather":
        return "coalesce(credentials->>'appid', credentials->>'appId', '') <> ''"
    if p == "alphavantage":
        return "coalesce(credentials->>'api_key', credentials->>'apiKey', '') <> ''"
    if p == "huggingface":
        return "coalesce(credentials->>'api_key', credentials->>'apiKey', '') <> ''"
    if p == "rapidapi":
        return " and ".join(
            [
                "coalesce(credentials->>'api_key', credentials->>'apiKey', '') <> ''",
                "coalesce(credentials->>'rapidapi_host', credentials->>'rapidapiHost', '') <> ''",
            ]
        )
    return None


async def find_latest_active_credential(db: Database, *, user_id: str, provider: str) -> dict | None:
    vs = validity_sql(provider)
    if not vs:
        return None
    await reactivate_expired_credential_cooldowns(db, user_id=user_id, provider=provider)
    r = await db.query(
        f"""select id, credentials from public.provider_credentials
            where user_id = $1 and provider_name = $2 and status = 'active'
              and ({vs})
            order by created_at desc limit 1""",
        (user_id, provider),
    )
    return r.rows[0] if r.rows else None
