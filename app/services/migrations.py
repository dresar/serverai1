"""Jalankan schema.sql + ensure_* (mirror migrate.js)."""
from __future__ import annotations

from pathlib import Path

from app.db import Database
from app.services import ai_models as ai_models_svc
from app.services import api_keys as api_keys_svc
from app.services import observability_schema as obs_schema


ROOT = Path(__file__).resolve().parent.parent.parent


def _split_sql_statements(sql: str) -> list[str]:
    """Pisah per statement; abaikan `;` di dalam string '...' atau dollar-quote $$...$$."""
    parts: list[str] = []
    chunk: list[str] = []
    i, n = 0, len(sql)
    in_single = False
    in_dollar = False
    while i < n:
        c = sql[i]
        if not in_dollar and c == "'":
            if in_single and i + 1 < n and sql[i + 1] == "'":
                chunk.append("''")
                i += 2
                continue
            in_single = not in_single
            chunk.append(c)
            i += 1
            continue
        if not in_single and i + 1 < n and sql[i : i + 2] == "$$":
            in_dollar = not in_dollar
            chunk.extend(["$", "$"])
            i += 2
            continue
        if c == ";" and not in_single and not in_dollar:
            stmt = "".join(chunk).strip()
            if stmt:
                parts.append(stmt)
            chunk = []
            i += 1
            continue
        chunk.append(c)
        i += 1
    stmt = "".join(chunk).strip()
    if stmt:
        parts.append(stmt)
    return parts


async def run_schema_sql(db: Database) -> None:
    path = ROOT / "db" / "schema.sql"
    raw = path.read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if not ln.strip().startswith("--")]
    sql = "\n".join(lines)
    parts = [p for p in _split_sql_statements(sql) if p.strip()]
    for stmt in parts:
        await db.query(stmt)


async def run_all(db: Database) -> None:
    await run_schema_sql(db)
    await api_keys_svc.ensure_api_key_schema(db)
    await obs_schema.ensure_observability_schema(db)
    await ai_models_svc.ensure_ai_models_schema(db)
