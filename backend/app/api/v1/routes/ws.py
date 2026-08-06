"""Realtime WebSocket endpoints (Phase 4)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from app.api.v1.deps import get_ws_current_user
from app.models.user import User
from app.services.realtime import manager
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

ws_router = APIRouter()

WsUser = Annotated[User, Depends(get_ws_current_user)]


@ws_router.websocket("/ws/incidents")
async def incidents_ws(websocket: WebSocket, user: WsUser) -> None:
    """Stream incident lifecycle and notification events for ``user``.

    Authenticated via the ``token`` query parameter. Clients may send
    ``ping`` to receive a ``pong`` keepalive; anything else is ignored.
    """
    await manager.connect(websocket, user.id)
    try:
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_json(
                    {"type": "pong", "payload": {"ts": datetime.now(UTC).isoformat()}}
                )
    except WebSocketDisconnect:
        manager.disconnect(websocket, user.id)
