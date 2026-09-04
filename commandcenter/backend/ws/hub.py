"""WebSocket connection manager for live event streaming."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState

from commandcenter.backend.config import allowed_browser_origins, load_settings

logger = logging.getLogger("void.commandcenter.ws")


class ConnectionManager:
    """Track live WebSocket clients and their channel subscriptions."""

    VALID_CHANNELS = frozenset(
        {
            "warlog",
            "c2",
            "engagement",
            "integrity",
            "metrics",
            "attack_graph",
            "demo",
        }
    )

    def __init__(self) -> None:
        self._clients: dict[WebSocket, set[str]] = {}
        self._lock = asyncio.Lock()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, websocket: WebSocket, subprotocol: str | None = None) -> None:
        await websocket.accept(subprotocol=subprotocol)
        async with self._lock:
            # Default subscription: all channels
            self._clients[websocket] = set(self.VALID_CHANNELS)
        logger.info("WS client connected (total=%d)", len(self._clients))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.pop(websocket, None)
        logger.info("WS client disconnected (total=%d)", len(self._clients))

    async def subscribe(self, websocket: WebSocket, channels: list[str]) -> None:
        valid = {c for c in channels if c in self.VALID_CHANNELS}
        async with self._lock:
            if websocket in self._clients:
                self._clients[websocket] = valid or set(self.VALID_CHANNELS)

    async def broadcast(self, channel: str, message: dict[str, Any]) -> None:
        """Send message to all clients subscribed to channel."""
        payload = json.dumps(message, default=str)
        dead: list[WebSocket] = []
        async with self._lock:
            targets = [
                ws for ws, subs in self._clients.items() if channel in subs
            ]
        for ws in targets:
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_text(payload)
                else:
                    dead.append(ws)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)

    async def send_personal(
        self, websocket: WebSocket, message: dict[str, Any]
    ) -> None:
        try:
            await websocket.send_text(json.dumps(message, default=str))
        except Exception:
            await self.disconnect(websocket)


hub = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket, subprotocol: str | None = None) -> None:
    """Handle /ws/live connections."""
    # Validate Origin header against allowed CORS origins
    origin = websocket.headers.get("origin")
    if origin:
        settings = load_settings()
        if origin not in allowed_browser_origins(settings):
            logger.warning("WS rejected: origin %s not allowed", origin)
            await websocket.close(code=1008)
            return
    await hub.connect(websocket, subprotocol=subprotocol)
    # Initial hello
    await hub.send_personal(
        websocket,
        {
            "type": "connected",
            "data": {
                "ts": time.time(),
                "channels": list(ConnectionManager.VALID_CHANNELS),
            },
        },
    )
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await hub.send_personal(
                    websocket, {"type": "error", "data": {"detail": "invalid json"}}
                )
                continue
            msg_type = msg.get("type")
            if msg_type == "subscribe":
                channels = msg.get("channels") or []
                if isinstance(channels, str):
                    channels = [channels]
                await hub.subscribe(websocket, list(channels))
                await hub.send_personal(
                    websocket,
                    {
                        "type": "subscribed",
                        "data": {"channels": channels},
                    },
                )
            elif msg_type == "ping":
                await hub.send_personal(
                    websocket, {"type": "pong", "data": {"ts": time.time()}}
                )
            else:
                await hub.send_personal(
                    websocket,
                    {
                        "type": "error",
                        "data": {"detail": f"unknown type: {msg_type}"},
                    },
                )
    except WebSocketDisconnect:
        await hub.disconnect(websocket)
    except Exception as exc:
        logger.debug("WS error: %s", exc)
        await hub.disconnect(websocket)
