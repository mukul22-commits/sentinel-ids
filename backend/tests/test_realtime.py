"""Unit tests for the realtime WebSocket connection manager (Phase 4)."""

from __future__ import annotations

from typing import Any

import pytest
from app.services.realtime import ConnectionManager


class FakeWebSocket:
    """Minimal stand-in for a Starlette WebSocket that records sends."""

    def __init__(self, user_id: int) -> None:
        self.user_id = user_id
        self.sent: list[dict[str, Any]] = []

    async def accept(self) -> None:
        self.accepted = True

    async def send_json(self, message: dict[str, Any]) -> None:
        self.sent.append(message)


class TestConnectionManager:
    @pytest.mark.asyncio
    async def test_connect_then_disconnect(self) -> None:
        manager = ConnectionManager()
        socket = FakeWebSocket(1)
        await manager.connect(socket, 1)
        assert manager.connection_count == 1
        manager.disconnect(socket, 1)
        assert manager.connection_count == 0

    @pytest.mark.asyncio
    async def test_send_to_user_only_reaches_target(self) -> None:
        manager = ConnectionManager()
        target = FakeWebSocket(1)
        other = FakeWebSocket(2)
        await manager.connect(target, 1)
        await manager.connect(other, 2)

        await manager.send_to_user(1, {"type": "test", "payload": {"user": 1}})
        assert target.sent == [{"type": "test", "payload": {"user": 1}}]
        assert other.sent == []

    @pytest.mark.asyncio
    async def test_broadcast_reaches_every_connection(self) -> None:
        manager = ConnectionManager()
        sockets = [FakeWebSocket(i) for i in range(1, 4)]
        for socket in sockets:
            await manager.connect(socket, socket.user_id)

        await manager.broadcast({"type": "test", "payload": {"all": True}})
        for socket in sockets:
            assert socket.sent == [{"type": "test", "payload": {"all": True}}]

    @pytest.mark.asyncio
    async def test_disconnect_removes_only_that_socket(self) -> None:
        manager = ConnectionManager()
        first = FakeWebSocket(1)
        second = FakeWebSocket(1)
        await manager.connect(first, 1)
        await manager.connect(second, 1)
        assert manager.connection_count == 2

        manager.disconnect(first, 1)
        assert manager.connection_count == 1
        await manager.send_to_user(1, {"type": "ping", "payload": {}})
        assert first.sent == []
        assert second.sent == [{"type": "ping", "payload": {}}]

    @pytest.mark.asyncio
    async def test_disconnect_unknown_socket_is_noop(self) -> None:
        manager = ConnectionManager()
        socket = FakeWebSocket(1)
        await manager.connect(socket, 1)
        manager.disconnect(FakeWebSocket(2), 1)
        assert manager.connection_count == 1
