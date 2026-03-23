"""Port server1/src/lib/circuitBreaker.js"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T")


class CircuitBreaker:
    def __init__(self, timeout_ms: int = 8000, half_open_after_ms: int = 2000) -> None:
        self.timeout_ms = timeout_ms
        self.half_open_after_ms = half_open_after_ms
        self._state: dict[str, dict] = {}

    def get_state(self, key: str) -> dict:
        return self._state.get(key, {"mode": "closed", "opened_at": 0})

    def can_pass(self, key: str) -> bool:
        s = self.get_state(key)
        if s["mode"] == "closed":
            return True
        if s["mode"] == "open":
            if time.time() * 1000 - s["opened_at"] >= self.half_open_after_ms:
                self._state[key] = {"mode": "half-open", "opened_at": s["opened_at"]}
                return True
            return False
        return True

    def on_success(self, key: str) -> None:
        self._state[key] = {"mode": "closed", "opened_at": 0}

    def on_failure(self, key: str) -> None:
        s = self.get_state(key)
        if s["mode"] == "open":
            return
        self._state[key] = {"mode": "open", "opened_at": time.time() * 1000}

    async def run(self, key: str, fn: Callable[[], Awaitable[T]]) -> T:
        if not self.can_pass(key):
            raise RuntimeError("CircuitOpen")
        try:
            result = await asyncio.wait_for(fn(), timeout=self.timeout_ms / 1000.0)
            self.on_success(key)
            return result
        except Exception:
            self.on_failure(key)
            raise
