"""Broadcast WebSocket ke tenant (mirror server1/src/infra/ws.js)."""
from __future__ import annotations

import json
from typing import Any

from starlette.websockets import WebSocket


class WsHub:
    def __init__(self) -> None:
        self._clients: dict[WebSocket, str] = {}

    def register(self, ws: WebSocket, tenant_id: str) -> None:
        self._clients[ws] = tenant_id

    def unregister(self, ws: WebSocket) -> None:
        self._clients.pop(ws, None)

    async def broadcast_to_tenant(self, tenant_id: str, event: dict) -> None:
        payload = json.dumps(event, default=str)
        for ws, tid in list(self._clients.items()):
            if tid != tenant_id:
                continue
            try:
                await ws.send_text(payload)
            except Exception:
                pass
