"""State aplikasi global (di-set saat lifespan)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.cache_l1 import L1Cache
from app.cache_l2 import L2Cache
from app.circuit_breaker import CircuitBreaker
from app.db import Database
from app.memory_store import MemoryStore
from app.services.observability import ObsContext
from app.ws_hub import WsHub

if TYPE_CHECKING:
    pass


@dataclass
class AppState:
    db: Database
    l1: L1Cache
    l2: L2Cache
    rate_store: MemoryStore
    breaker: CircuitBreaker
    ws: WsHub
    health: dict = field(default_factory=dict)
    gateway_log_mode: str = "full"

    def obs_context(self) -> ObsContext:
        async def _broadcast(tid: str, ev: dict) -> None:
            await self.ws.broadcast_to_tenant(tid, ev)

        return ObsContext(
            db=self.db,
            gateway_log_mode=self.gateway_log_mode,
            ws_broadcast=_broadcast,
        )


_state: AppState | None = None


def set_state(s: AppState) -> None:
    global _state
    _state = s


def get_state() -> AppState:
    if _state is None:
        raise RuntimeError("App not initialized")
    return _state
