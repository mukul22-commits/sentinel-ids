"""In-memory WebSocket hub: per-user personal channels plus broadcast (Phase 4)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("sentinel.realtime")


class ConnectionManager:
    """Track authenticated WebSocket connections and fan out realtime events.

    Events are plain JSON dicts with a ``type`` discriminator; a ``payload``
    key carries the event data. Personal events (notifications) go to a single
    user; operational events (incident lifecycle) are broadcast to everyone.
    """

    def __init__(self) -> None:
        self._connections: dict[int, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_id: int) -> None:
        await websocket.accept()
        self._connections.setdefault(user_id, []).append(websocket)
        logger.info("websocket connected user=%s", user_id)

    def disconnect(self, websocket: WebSocket, user_id: int) -> None:
        sockets = self._connections.get(user_id, [])
        if websocket in sockets:
            sockets.remove(websocket)
        if not sockets:
            self._connections.pop(user_id, None)
        logger.info("websocket disconnected user=%s", user_id)

    @property
    def connection_count(self) -> int:
        return sum(len(sockets) for sockets in self._connections.values())

    async def send_to_user(self, user_id: int, event: dict[str, Any]) -> None:
        """Deliver an event to every socket owned by ``user_id``."""
        for websocket in list(self._connections.get(user_id, [])):
            await self._safe_send(websocket, event)

    async def broadcast(self, event: dict[str, Any]) -> None:
        """Deliver an event to every connected socket."""
        for sockets in list(self._connections.values()):
            for websocket in list(sockets):
                await self._safe_send(websocket, event)

    async def _safe_send(self, websocket: WebSocket, event: dict[str, Any]) -> None:
        try:
            await websocket.send_json(event)
        except Exception:
            logger.warning("dropping stale websocket connection", exc_info=True)


manager = ConnectionManager()
