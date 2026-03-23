"""
Hapus semua data aplikasi di PostgreSQL, jalankan migrasi/ensure schema, lalu seed dummy.

HANYA development — wajib ENABLE_DEV_RESET=true dan bukan production.

Usage:
  set ENABLE_DEV_RESET=true
  set ENABLE_DEV_SEED=true
  python -m scripts.reset_and_seed
"""
from __future__ import annotations

import asyncio
import os

from app.config import assert_config, get_settings
from app.db import close_db, init_db
from app.services import ai_models as ai_models_svc
from app.services import api_keys as api_keys_svc
from app.services.migrations import run_all
from app.services.observability_schema import ensure_observability_schema

from .seed import seed_database


async def truncate_all_user_data(db) -> None:
    """Kosongkan tabel data (bukan DROP). Urutan aman dengan CASCADE."""
    sql = """
    TRUNCATE TABLE
      public.gateway_request_logs,
      public.gateway_alerts,
      public.upload_expiry,
      public.api_keys,
      public.system_settings,
      public.request_logs,
      public.api_clients,
      public.provider_credentials,
      public.users,
      public.ai_models
    RESTART IDENTITY CASCADE;
    """
    await db.query(sql)
    print("TRUNCATE selesai (semua data aplikasi dikosongkan).")


async def main() -> None:
    assert_config()
    s = get_settings()

    if s.is_production:
        print("Reset database ditolak: MODE/NODE_ENV production.")
        raise SystemExit(1)
    if os.getenv("ENABLE_DEV_RESET") != "true":
        print(
            "Wajib set ENABLE_DEV_RESET=true (development saja).\n"
            "Ini akan menghapus SEMUA data di database target."
        )
        raise SystemExit(1)
    if os.getenv("ENABLE_DEV_SEED") != "true":
        print("Set juga ENABLE_DEV_SEED=true agar seed dummy jalan setelah reset.")
        raise SystemExit(1)

    db = await init_db()
    try:
        print("Menjalankan schema + ensure (aman jika sudah ada)...")
        await run_all(db)
        await api_keys_svc.ensure_api_key_schema(db)
        await ensure_observability_schema(db)
        await ai_models_svc.ensure_ai_models_schema(db)

        print("Mengosongkan data...")
        await truncate_all_user_data(db)

        print("Memastikan schema setelah truncate...")
        await run_all(db)
        await api_keys_svc.ensure_api_key_schema(db)
        await ensure_observability_schema(db)
        await ai_models_svc.ensure_ai_models_schema(db)

        print("Menanam data dummy...")
        await seed_database(db)
        print("\n=== Selesai: database bersih + data dummy siap dipakai. ===")
    finally:
        await close_db()


if __name__ == "__main__":
    asyncio.run(main())
