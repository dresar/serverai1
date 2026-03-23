"""Port server1/src/cache/l2.js (in-memory JSON + response cache)."""
from __future__ import annotations

import base64
import json
import time
from typing import Any


class L2Cache:
    def __init__(self) -> None:
        self._store: dict[str, dict] = {}

    def _get_entry(self, key: str) -> dict | None:
        e = self._store.get(key)
        if not e:
            return None
        if e["expires_at"] <= time.time() * 1000:
            self._store.pop(key, None)
            return None
        return e

    def _set_entry(self, key: str, value: Any, ttl_ms: float) -> None:
        self._store[key] = {"value": value, "expires_at": time.time() * 1000 + max(1, ttl_ms)}

    async def get_json(self, key: str) -> Any:
        raw = self._get_entry(key)
        if not raw:
            return None
        return json.loads(raw["value"])

    async def set_json(self, key: str, value: Any, ttl_ms: float) -> None:
        self._set_entry(key, json.dumps(value, default=str), ttl_ms)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)

    async def get_response(self, key: str) -> dict | None:
        raw = self._get_entry(key)
        if not raw:
            return None
        parsed = json.loads(raw["value"])
        body = None
        b64 = parsed.get("body_base64")
        if b64:
            body = base64.b64decode(b64)
        return {**parsed, "body": body}

    async def set_response(self, key: str, value: dict, ttl_ms: float) -> None:
        body = value.get("body")
        b64 = base64.b64encode(body).decode("ascii") if body else None
        payload = {"status": value.get("status"), "headers": value.get("headers"), "body_base64": b64}
        self._set_entry(key, json.dumps(payload), ttl_ms)
