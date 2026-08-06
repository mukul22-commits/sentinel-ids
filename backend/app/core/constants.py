"""Domain constants for incident response orchestration (Phase 4)."""

from __future__ import annotations

INCIDENT_SEVERITIES = ("low", "medium", "high", "critical")
INCIDENT_STATUSES = ("open", "in_progress", "resolved", "closed")
INCIDENT_ALERTING_SEVERITIES = ("high", "critical")

RESPONSE_ACTION_TYPES = ("block", "quarantine", "notify")
RESPONSE_ACTION_TARGET_TYPES = ("ip", "port", "host", "email")
RESPONSE_ACTION_STATUSES = ("pending", "pending_approval", "executing", "succeeded", "failed")
RESPONSE_ACTION_EXECUTABLE_STATUSES = ("pending", "pending_approval", "failed")

# --- Detection engine (Phase 5) ---
RULE_SEVERITIES = ("low", "medium", "high", "critical")
ALERT_STATUSES = ("new", "acknowledged", "resolved", "false_positive")
DETECTOR_SIGNATURE = "signature"
DETECTOR_ML = "ml"

# --- Advanced detection (Phase 9) ---
DETECTOR_YARA = "yara"
DETECTOR_AUTOENCODER = "autoencoder"
DETECTOR_UEBA = "ueba"

# --- Live capture adapters (Phase 6) ---
CAPTURE_ADAPTER_SNIFF = "scapy_sniff"
CAPTURE_ADAPTER_SURICATA = "suricata_eve"
CAPTURE_ADAPTER_ZEEK = "zeek_conn"
CAPTURE_RUN_STATUSES = ("succeeded", "failed")

# --- Fleet / multi-sensor management (Phase 8) ---
SENSOR_STATUSES = ("online", "offline", "disabled")

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
