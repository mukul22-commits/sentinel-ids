"""Unit tests for the role/permission matrix (Phase 3)."""

from __future__ import annotations

from app.core.rbac import (
    PERMISSION_MANAGE_INCIDENTS,
    PERMISSION_MANAGE_RULES,
    PERMISSION_READ,
    PERMISSION_RESPOND,
    PERMISSION_VIEW_INCIDENTS,
    PERMISSION_VIEW_NOTIFICATIONS,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    has_permission,
    valid_role,
)


class TestPermissionMatrix:
    def test_admin_has_all(self) -> None:
        assert has_permission(ROLE_ADMIN, PERMISSION_READ)
        assert has_permission(ROLE_ADMIN, PERMISSION_RESPOND)
        assert has_permission(ROLE_ADMIN, PERMISSION_MANAGE_RULES)
        assert has_permission(ROLE_ADMIN, PERMISSION_MANAGE_INCIDENTS)
        assert has_permission(ROLE_ADMIN, PERMISSION_VIEW_NOTIFICATIONS)

    def test_analyst_can_respond_but_not_manage_users(self) -> None:
        assert has_permission(ROLE_ANALYST, PERMISSION_READ)
        assert has_permission(ROLE_ANALYST, PERMISSION_RESPOND)
        assert has_permission(ROLE_ANALYST, PERMISSION_VIEW_INCIDENTS)
        assert has_permission(ROLE_ANALYST, PERMISSION_MANAGE_INCIDENTS)
        assert has_permission(ROLE_ANALYST, PERMISSION_VIEW_NOTIFICATIONS)
        assert not has_permission(ROLE_ANALYST, PERMISSION_MANAGE_RULES)

    def test_viewer_is_read_only(self) -> None:
        assert has_permission(ROLE_VIEWER, PERMISSION_READ)
        assert has_permission(ROLE_VIEWER, PERMISSION_VIEW_INCIDENTS)
        assert has_permission(ROLE_VIEWER, PERMISSION_VIEW_NOTIFICATIONS)
        assert not has_permission(ROLE_VIEWER, PERMISSION_RESPOND)
        assert not has_permission(ROLE_VIEWER, PERMISSION_MANAGE_INCIDENTS)

    def test_unknown_role(self) -> None:
        assert not has_permission("root", PERMISSION_READ)
        assert not valid_role("root")

    def test_valid_roles(self) -> None:
        assert valid_role(ROLE_ADMIN)
        assert valid_role(ROLE_ANALYST)
        assert valid_role(ROLE_VIEWER)
