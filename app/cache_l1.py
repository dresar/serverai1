"""Port server1/src/cache/l1.js"""
from __future__ import annotations

import time
from typing import Any


class L1Cache:
    def __init__(self, max_size: int = 1000) -> None:
        self._max_size = max_size
        self._map: dict[str, dict] = {}

    def get(self, key: str) -> Any:
        hit = self._map.get(key)
        if not hit:
            return None
        if hit["expires_at"] <= time.time() * 1000:
            self._map.pop(key, None)
            return None
        self._map.pop(key, None)
        self._map[key] = hit
        return hit["value"]

    def delete(self, key: str) -> None:
        self._map.pop(key, None)

    def set(self, key: str, value: Any, ttl_ms: float) -> None:
        if len(self._map) >= self._max_size:
            oldest = next(iter(self._map))
            self._map.pop(oldest, None)
        expires_at = time.time() * 1000 + ttl_ms
        self._map.pop(key, None)
        self._map[key] = {"value": value, "expires_at": expires_at}

    def get_stale(self, key: str) -> Any:
        hit = self._map.get(key)
        return hit["value"] if hit else None
