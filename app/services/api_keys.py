"""Port server1/src/services/apiKeys.js"""
from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any

import bcrypt

from app.cache_l1 import L1Cache
from app.cache_l2 import L2Cache
from app.config import get_settings
from app.db import Database

CACHE_MISS: dict[str, Any] = {"__cacheMiss": True}
API_KEY_CACHE_TTL_MS = 5 * 60 * 1000
API_KEY_NEGATIVE_TTL_MS = 30 * 1000

LABELS = {
    "gemini": "Gemini",
    "groq": "Groq",
    "cloudinary": "Cloudinary",
    "imagekit": "ImageKit",
    "apify": "Apify",
}


def hash_api_key(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def generate_api_key(tenant_id: str, prefix: str = "eka") -> str:
    tenant_part = tenant_id.replace("-", "")[:6]
    secret = secrets.token_urlsafe(8)
    return f"{prefix}_{tenant_part}_{secret}"


async def ensure_api_key_schema(db: Database) -> None:
    await db.query(
        """create table if not exists public.api_keys (
      id uuid not null default gen_random_uuid() primary key,
      tenant_id uuid not null,
      key_hash text not null unique,
      api_key_plain text,
      status text not null default 'active',
      grace_until timestamp with time zone,
      rotated_from uuid references public.api_keys(id) on delete set null,
      quota_per_minute integer not null default 1000,
      allowed_providers text[] default '{}',
      name text,
      created_at timestamp with time zone not null default now(),
      updated_at timestamp with time zone not null default now()
    )"""
    )
    for alt in [
        """alter table public.api_keys add column if not exists allowed_providers text[] default '{}'""",
        """alter table public.api_keys add column if not exists name text""",
        """alter table public.api_keys add column if not exists api_key_plain text""",
        """alter table public.api_keys add column if not exists client_username text""",
        """alter table public.api_keys add column if not exists client_password_hash text""",
    ]:
        await db.query(alt)
    await db.query(
        """create index if not exists idx_api_keys_tenant on public.api_keys(tenant_id, created_at desc)"""
    )
    await db.query("""create index if not exists idx_api_keys_hash on public.api_keys(key_hash)""")
    await db.query(
        """create table if not exists public.gateway_request_logs (
      id uuid not null default gen_random_uuid() primary key,
      api_key_id uuid not null references public.api_keys(id) on delete cascade,
      tenant_id uuid not null references public.users(id) on delete cascade,
      provider text not null,
      method text not null default 'GET',
      status_code integer,
      response_time_ms integer,
      origin_domain text,
      created_at timestamp with time zone not null default now()
    )"""
    )
    await db.query(
        """create index if not exists idx_gateway_logs_api_key_created on public.gateway_request_logs(api_key_id, created_at desc)"""
    )
    await db.query(
        """create index if not exists idx_gateway_logs_tenant_created on public.gateway_request_logs(tenant_id, created_at desc)"""
    )


async def _next_name(db: Database, tenant_id: str, allowed_providers: list) -> str:
    base = "API Key"
    if isinstance(allowed_providers, list) and len(allowed_providers) == 1:
        p = str(allowed_providers[0] or "").strip().lower()
        if p in LABELS:
            base = LABELS[p]
    r = await db.query(
        "select name from public.api_keys where tenant_id = $1 and name is not null",
        (tenant_id,),
    )
    pat = re.compile(rf"^{re.escape(base)}\s+(\d+)$", re.I)
    max_n = 0
    for row in r.rows:
        m = pat.match(str(row.get("name") or "").strip())
        if m:
            max_n = max(max_n, int(m.group(1)))
    return f"{base} {max_n + 1}"


async def create_api_key(
    db: Database,
    *,
    tenant_id: str,
    quota_per_minute: int | None = None,
    allowed_providers: list | None = None,
    name: str | None = None,
    client_username: str | None = None,
    client_password: str | None = None,
) -> dict:
    plain = generate_api_key(tenant_id)
    key_hash = hash_api_key(plain)
    providers = list(allowed_providers) if allowed_providers else []
    raw_name = str(name).strip() if name is not None else ""
    key_name = raw_name or await _next_name(db, tenant_id, providers)
    client_user = None
    client_hash = None
    if client_username and str(client_username).strip() and client_password:
        client_user = str(client_username).strip()
        client_hash = bcrypt.hashpw(str(client_password).encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
    r = await db.query(
        """insert into public.api_keys (tenant_id, key_hash, quota_per_minute, allowed_providers, name, client_username, client_password_hash)
           values ($1, $2, $3, $4, $5, $6, $7)
           returning id, tenant_id, status, quota_per_minute, allowed_providers, name, created_at, client_username""",
        (tenant_id, key_hash, quota_per_minute or 1000, providers, key_name, client_user, client_hash),
    )
    row = r.rows[0]
    row["api_key"] = plain
    return row


async def list_api_keys(db: Database, *, tenant_id: str) -> list:
    r = await db.query(
        """select id, tenant_id, status, grace_until, rotated_from, quota_per_minute, allowed_providers, name, created_at, client_username
           from public.api_keys where tenant_id = $1 order by created_at desc""",
        (tenant_id,),
    )
    return r.rows


async def get_api_key(db: Database, l1: L1Cache, l2: L2Cache, key_hash: str) -> dict | None:
    l1_key = f"apikey:{key_hash}"
    l1_hit = l1.get(l1_key)
    if l1_hit is not None:
        return None if l1_hit.get("__cacheMiss") else l1_hit

    l2_hit = await l2.get_json(l1_key)
    if l2_hit is not None:
        ttl = API_KEY_NEGATIVE_TTL_MS if l2_hit.get("__cacheMiss") else API_KEY_CACHE_TTL_MS
        l1.set(l1_key, l2_hit, ttl)
        return None if l2_hit.get("__cacheMiss") else l2_hit

    r = await db.query(
        """select id, tenant_id, key_hash, status, grace_until, rotated_from, quota_per_minute, allowed_providers, name, client_username, client_password_hash
           from public.api_keys where key_hash = $1 limit 1""",
        (key_hash,),
    )
    api_key = r.rows[0] if r.rows else None
    if api_key:
        l1.set(l1_key, api_key, API_KEY_CACHE_TTL_MS)
        await l2.set_json(l1_key, api_key, API_KEY_CACHE_TTL_MS)
    else:
        l1.set(l1_key, CACHE_MISS, API_KEY_NEGATIVE_TTL_MS)
        await l2.set_json(l1_key, CACHE_MISS, API_KEY_NEGATIVE_TTL_MS)
    return api_key


async def rotate_api_key(
    db: Database,
    l1: L1Cache,
    l2: L2Cache,
    *,
    api_key_id: str,
    tenant_id: str,
    old_key_hash: str | None,
) -> dict:
    s = get_settings()
    grace_until_ms = int(s.API_KEY_GRACE_MS)
    import datetime as dt

    grace_until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(milliseconds=grace_until_ms)).isoformat()

    old = await db.query(
        "select allowed_providers, name from public.api_keys where id = $1 and tenant_id = $2",
        (api_key_id, tenant_id),
    )
    allowed = old.rows[0]["allowed_providers"] if old.rows else []
    nm = old.rows[0].get("name") if old.rows else None

    await db.query(
        "update public.api_keys set status = 'disabled', grace_until = $1 where id = $2 and tenant_id = $3",
        (grace_until, api_key_id, tenant_id),
    )
    created = await create_api_key(db, tenant_id=tenant_id, allowed_providers=allowed, name=nm)
    await db.query(
        "update public.api_keys set rotated_from = $1 where id = $2",
        (api_key_id, created["id"]),
    )
    if old_key_hash:
        lk = f"apikey:{old_key_hash}"
        l1.delete(lk)
        await l2.delete(lk)
    created["grace_until"] = grace_until
    return created
