"""Port server1/src/infra/memoryStore.js — rate limit & KV lokal."""
from __future__ import annotations

import time
from typing import Any


class MemoryStore:
    def __init__(self) -> None:
        self._store: dict[str, Any] = {}
        self._expiry: dict[str, float] = {}
        self._numeric: dict[str, int] = {}

    def _get_expiry(self, key: str) -> float | None:
        t = self._expiry.get(key)
        if t is not None and t <= time.time() * 1000:
            self._store.pop(key, None)
            self._expiry.pop(key, None)
            self._numeric.pop(key, None)
            return None
        return t

    async def get(self, key: str) -> Any:
        self._get_expiry(key)
        return self._store.get(key)

    async def set(self, key: str, value: Any, opts: dict | None = None) -> str | None:
        opts = opts or {}
        if opts.get("NX") and key in self._store:
            self._get_expiry(key)
            if key in self._store:
                return None
        self._store[key] = value
        if opts.get("PX") is not None:
            self._expiry[key] = time.time() * 1000 + float(opts["PX"])
        elif opts.get("EX") is not None:
            self._expiry[key] = time.time() * 1000 + float(opts["EX"]) * 1000
        return "OK"

    async def delete(self, key: str) -> int:
        self._store.pop(key, None)
        self._expiry.pop(key, None)
        self._numeric.pop(key, None)
        return 1

    async def incr(self, key: str) -> int:
        self._get_expiry(key)
        cur = self._numeric.get(key)
        if cur is None:
            raw = self._store.get(key)
            try:
                cur = int(raw) if raw is not None else 0
            except (TypeError, ValueError):
                cur = 0
        n = cur + 1
        self._numeric[key] = n
        self._store[key] = str(n)
        return n

    async def eval(self, _script: str, num_keys: int, key: str, *args: str) -> list[int | float]:
        """Sliding window rate limit: args = [now_ms, window_ms, limit]."""
        if not key:
            return [0, 0, int(args[2]) if len(args) > 2 else 1000]
        window_ms = float(args[1]) if len(args) > 1 else 60000.0
        limit = int(float(args[2])) if len(args) > 2 else 1000
        current = await self.incr(key)
        if current == 1:
            self._expiry[key] = time.time() * 1000 + window_ms
        exp = self._expiry.get(key)
        ttl = max(0.0, (exp or 0) - time.time() * 1000) if exp else 0.0
        remaining = max(0, limit - current)
        return [current, ttl, remaining]
