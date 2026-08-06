"""Domain constants for incident response orchestration (Phase 4)."""

from __future__ import annotations

INCIDENT_SEVERITIES = ("low", "medium", "high", "critical")
INCIDENT_STATUSES = ("open", "in_progress", "resolved", "closed")
INCIDENT_ALERTING_SEVERITIES = ("high", "critical")

RESPONSE_ACTION_TYPES = ("block", "quarantine", "notify")
RESPONSE_ACTION_TARGET_TYPES = ("ip", "port", "host", "email")
RESPONSE_ACTION_STATUSES = ("pending", "executing", "succeeded", "failed")

# --- Detection engine (Phase 5) ---
RULE_SEVERITIES = ("low", "medium", "high", "critical")
ALERT_STATUSES = ("new", "acknowledged", "resolved", "false_positive")
DETECTOR_SIGNATURE = "signature"
DETECTOR_ML = "ml"

IOC_TYPES = (
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "email",
    "file_hash_md5",
    "file_hash_sha1",
    "file_hash_sha256",
    "string",
)
