"""Role-based access control: roles and the permission matrix."""

from __future__ import annotations

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"
ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)

PERMISSION_READ = "read"
PERMISSION_RESPOND = "respond"
PERMISSION_MANAGE_USERS = "manage_users"
PERMISSION_MANAGE_RULES = "manage_rules"
PERMISSION_VIEW_RULES = "view_rules"
PERMISSION_TEST_RULES = "test_rules"
PERMISSION_MANAGE_IOCS = "manage_iocs"
PERMISSION_VIEW_IOCS = "view_iocs"
PERMISSION_MANAGE_ALERTS = "manage_alerts"
PERMISSION_VIEW_ALERTS = "view_alerts"
PERMISSION_MANAGE_SYSTEM = "manage_system"
PERMISSION_VIEW_INCIDENTS = "view_incidents"
PERMISSION_MANAGE_INCIDENTS = "manage_incidents"
PERMISSION_VIEW_NOTIFICATIONS = "view_notifications"

# admin = all; analyst = read + respond + incident handling; viewer = read-only.
PERMISSION_MATRIX: dict[str, frozenset[str]] = {
    ROLE_ADMIN: frozenset(
        {
            PERMISSION_READ,
            PERMISSION_RESPOND,
            PERMISSION_MANAGE_USERS,
            PERMISSION_MANAGE_RULES,
            PERMISSION_VIEW_RULES,
            PERMISSION_TEST_RULES,
            PERMISSION_MANAGE_IOCS,
            PERMISSION_VIEW_IOCS,
            PERMISSION_MANAGE_ALERTS,
            PERMISSION_VIEW_ALERTS,
            PERMISSION_MANAGE_SYSTEM,
            PERMISSION_VIEW_INCIDENTS,
            PERMISSION_MANAGE_INCIDENTS,
            PERMISSION_VIEW_NOTIFICATIONS,
        }
    ),
    ROLE_ANALYST: frozenset(
        {
            PERMISSION_READ,
            PERMISSION_RESPOND,
            PERMISSION_VIEW_RULES,
            PERMISSION_TEST_RULES,
            PERMISSION_VIEW_IOCS,
            PERMISSION_MANAGE_ALERTS,
            PERMISSION_VIEW_ALERTS,
            PERMISSION_VIEW_INCIDENTS,
            PERMISSION_MANAGE_INCIDENTS,
            PERMISSION_VIEW_NOTIFICATIONS,
        }
    ),
    ROLE_VIEWER: frozenset(
        {
            PERMISSION_READ,
            PERMISSION_VIEW_RULES,
            PERMISSION_VIEW_IOCS,
            PERMISSION_VIEW_ALERTS,
            PERMISSION_VIEW_INCIDENTS,
            PERMISSION_VIEW_NOTIFICATIONS,
        }
    ),
}


def has_permission(role: str, permission: str) -> bool:
    """Return True when ``role`` holds ``permission`` in the matrix."""
    return role in PERMISSION_MATRIX and permission in PERMISSION_MATRIX[role]


def valid_role(role: str) -> bool:
    return role in PERMISSION_MATRIX
