"""Port server1/src/services/aiModels.js"""
from __future__ import annotations

from app.db import Database


async def ensure_ai_models_schema(db: Database) -> None:
    await db.query(
        """create table if not exists public.ai_models (
      id uuid not null default gen_random_uuid() primary key,
      provider text not null,
      model_id text not null,
      display_name text,
      is_default boolean not null default false,
      supports_vision boolean not null default false,
      sort_order int not null default 0,
      created_at timestamp with time zone not null default now(),
      unique(provider, model_id)
    )"""
    )
    await db.query(
        """create index if not exists idx_ai_models_provider on public.ai_models(provider, sort_order)"""
    )
    await db.query(
        """create unique index if not exists idx_ai_models_one_default on public.ai_models(provider) where (is_default = true)"""
    )
    r = await db.query("select 1 from public.ai_models limit 1")
    if not r.rows:
        await db.query(
            """insert into public.ai_models (provider, model_id, display_name, is_default, supports_vision, sort_order)
       values
         ('gemini', 'gemini-2.5-flash', 'Gemini 2.5 Flash', true, true, 0),
         ('groq', 'llama-3.2-3b-preview', 'Llama 3.2 3B Instant', true, false, 0),
         ('groq', 'llama-3.1-70b-versatile', 'Llama 3.1 70B Versatile', false, false, 1),
         ('groq', 'llama-3.2-90b-vision-preview', 'Llama 3.2 90B Vision', false, true, 2),
         ('groq', 'llama-3.1-8b-instant', 'Llama 3.1 8B Instant', false, false, 3)"""
        )


async def list_models(db: Database, provider: str) -> list:
    r = await db.query(
        """select id, provider, model_id, display_name, is_default, supports_vision, sort_order from public.ai_models
           where provider = $1 order by sort_order, model_id""",
        (provider,),
    )
    return r.rows


async def is_model_allowed(db: Database, provider: str, model_id: str) -> bool:
    if not provider or not model_id or not str(model_id).strip():
        return False
    r = await db.query(
        "select 1 from public.ai_models where provider = $1 and model_id = $2 limit 1",
        (provider, model_id.strip()),
    )
    return len(r.rows) > 0


async def get_default_model_id(db: Database, provider: str) -> str | None:
    r = await db.query(
        "select model_id from public.ai_models where provider = $1 and is_default = true limit 1",
        (provider,),
    )
    return r.rows[0]["model_id"] if r.rows else None


async def get_model_supports_vision(db: Database, provider: str, model_id: str) -> bool:
    r = await db.query(
        "select supports_vision from public.ai_models where provider = $1 and model_id = $2 limit 1",
        (provider, model_id),
    )
    return bool(r.rows[0]["supports_vision"]) if r.rows else False


async def get_vision_model_id(db: Database, provider: str) -> str | None:
    r = await db.query(
        """select model_id from public.ai_models where provider = $1 and supports_vision = true
           order by sort_order, model_id limit 1""",
        (provider,),
    )
    return r.rows[0]["model_id"] if r.rows else None


async def create_model(
    db: Database,
    *,
    provider: str,
    model_id: str,
    display_name: str | None = None,
    is_default: bool = False,
    supports_vision: bool = False,
    sort_order: int = 0,
) -> dict:
    prov = (provider or "").lower()
    if prov not in ("gemini", "groq"):
        raise ValueError("provider harus 'gemini' atau 'groq'")
    mid = str(model_id).strip()
    if not mid:
        raise ValueError("model_id wajib diisi")
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            if is_default:
                await conn.execute("update public.ai_models set is_default = false where provider = $1", prov)
            row = await conn.fetchrow(
                """insert into public.ai_models (provider, model_id, display_name, is_default, supports_vision, sort_order)
                   values ($1, $2, $3, $4, $5, $6)
                   returning id, provider, model_id, display_name, is_default, supports_vision, sort_order""",
                prov,
                mid,
                display_name,
                is_default,
                supports_vision,
                sort_order,
            )
            if not row:
                return {}
            d = dict(row)
            if "id" in d:
                d["id"] = str(d["id"])
            return d


async def delete_model_by_id(db: Database, mid: str) -> dict:
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            cur = await conn.fetchrow(
                "select provider, is_default from public.ai_models where id = $1 limit 1",
                mid,
            )
            if not cur:
                return {"deleted": False}
            prov = cur["provider"]
            was_def = cur["is_default"]
            await conn.execute("delete from public.ai_models where id = $1", mid)
            if was_def:
                other = await conn.fetchrow(
                    "select id from public.ai_models where provider = $1 order by sort_order, model_id limit 1",
                    prov,
                )
                if other:
                    await conn.execute(
                        "update public.ai_models set is_default = true where id = $1",
                        other["id"],
                    )
            return {"deleted": True}


async def update_model(
    db: Database,
    mid: str,
    *,
    display_name: str | None = None,
    supports_vision: bool | None = None,
    is_default: bool | None = None,
) -> dict | None:
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            cur = await conn.fetchrow("select provider from public.ai_models where id = $1 limit 1", mid)
            if not cur:
                return None
            prov = cur["provider"]
            if is_default is True:
                await conn.execute("update public.ai_models set is_default = false where provider = $1", prov)
            sets: list[str] = []
            args: list = []
            if display_name is not None:
                sets.append(f"display_name = ${len(args) + 1}")
                args.append(display_name)
            if supports_vision is not None:
                sets.append(f"supports_vision = ${len(args) + 1}")
                args.append(supports_vision)
            if is_default is not None:
                sets.append(f"is_default = ${len(args) + 1}")
                args.append(is_default)
            if sets:
                args.append(mid)
                q = f"update public.ai_models set {', '.join(sets)} where id = ${len(args)}"
                await conn.execute(q, *args)
            row = await conn.fetchrow(
                "select id, provider, model_id, display_name, is_default, supports_vision, sort_order from public.ai_models where id = $1",
                mid,
            )
            if not row:
                return None
            d = dict(row)
            d["id"] = str(d["id"])
            return d
