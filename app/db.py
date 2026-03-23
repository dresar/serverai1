"""Pool asyncpg + helper query kompatibel dengan pola Node `{ rows }`."""
from __future__ import annotations

import ssl
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse
from uuid import UUID

import asyncpg

from app.config import Settings, get_settings


def _ssl_context_for_url(database_url: str) -> ssl.SSLContext | None:
    parsed = urlparse(database_url)
    host = (parsed.hostname or "").lower()
    qs = parse_qs(parsed.query)
    sslmode = (qs.get("sslmode") or [None])[0]
    if "neon.tech" in host or sslmode in ("require", "verify-full"):
        return ssl.create_default_context()
    if not host or host in ("localhost", "127.0.0.1", "::1"):
        return None
    if sslmode is None or sslmode != "disable":
        return ssl.create_default_context()
    return None


def _parse_execute_status(status: str) -> int:
    parts = status.split()
    if len(parts) >= 2 and parts[-1].isdigit():
        return int(parts[-1])
    return 0


def _row_to_dict(r: asyncpg.Record) -> dict:
    out = {}
    for k in r.keys():
        v = r[k]
        if isinstance(v, UUID):
            out[k] = str(v)
        else:
            out[k] = v
    return out


class Database:
    def __init__(self, pool: asyncpg.Pool):
        self._pool = pool

    @property
    def pool(self) -> asyncpg.Pool:
        return self._pool

    async def query(self, sql: str, args: tuple | list | None = None) -> SimpleNamespace:
        args = tuple(args or ())
        low = sql.strip().lower()
        if "returning" in low or low.startswith("select") or low.startswith("with"):
            async with self._pool.acquire() as conn:
                recs = await conn.fetch(sql, *args)
                rows = [_row_to_dict(r) for r in recs]
                return SimpleNamespace(rows=rows, rowcount=len(rows))

        async with self._pool.acquire() as conn:
            status = await conn.execute(sql, *args)
            return SimpleNamespace(rows=[], rowcount=_parse_execute_status(status))

    async def close(self) -> None:
        await self._pool.close()


_pool: asyncpg.Pool | None = None
_db: Database | None = None


async def init_db(settings: Settings | None = None) -> Database:
    global _pool, _db
    s = settings or get_settings()
    ssl_ctx = _ssl_context_for_url(s.DATABASE_URL)
    _pool = await asyncpg.create_pool(
        dsn=s.DATABASE_URL,
        min_size=1,
        max_size=s.DB_MAX_POOL,
        ssl=ssl_ctx,
        command_timeout=15,
    )
    _db = Database(_pool)
    return _db


async def close_db() -> None:
    global _pool, _db
    if _pool:
        await _pool.close()
        _pool = None
        _db = None


def get_db() -> Database:
    if _db is None:
        raise RuntimeError("Database not initialized")
    return _db
