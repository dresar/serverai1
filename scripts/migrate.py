"""python -m scripts.migrate — mirror server1/migrate.js"""
from __future__ import annotations

import asyncio

from app.config import assert_config
from app.db import close_db, init_db
from app.services import ai_models as ai_models_svc
from app.services import api_keys as api_keys_svc
from app.services.migrations import run_all
from app.services.observability_schema import ensure_observability_schema


async def main() -> None:
    assert_config()
    db = await init_db()
    try:
        await run_all(db)
        await api_keys_svc.ensure_api_key_schema(db)
        await ensure_observability_schema(db)
        await ai_models_svc.ensure_ai_models_schema(db)
        print("Migration selesai")
    finally:
        await close_db()


if __name__ == "__main__":
    asyncio.run(main())
