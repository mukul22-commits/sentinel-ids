"""ArcSight CEF (Common Event Format) rendering for external SIEM export (Phase 7).

Events are emitted as ``CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Ext``
lines, one alert per line, ready for a collector endpoint or log shipper.
"""

from __future__ import annotations

from typing import Any

from app.models.alert import Alert

CEF_DEVICE_VENDOR = "Sentinel IDS"
CEF_DEVICE_PRODUCT = "Sentinel"
CEF_DEVICE_VERSION = "3.0.0"

# Sentinel severities mapped onto the CEF 0-10 severity scale.
CEF_SEVERITY_MAP: dict[str, int] = {
    "low": 2,
    "medium": 5,
    "high": 8,
    "critical": 10,
}
CEF_DEFAULT_SEVERITY = 3


def cef_escape_header(value: str) -> str:
    """Escape a CEF header field (pipes and backslashes)."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def cef_escape_extension(value: Any) -> str:
    """Escape a CEF extension value (backslash, equals, newlines)."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def format_alert_cef(alert: Alert, *, version: str = CEF_DEVICE_VERSION) -> str:
    """Render one alert as a single CEF line."""
    signature_id = str(alert.rule_id) if alert.rule_id is not None else (alert.detector or "0")
    name = alert.title or alert.category
    severity = CEF_SEVERITY_MAP.get(alert.severity, CEF_DEFAULT_SEVERITY)
    created_ms = int(alert.created_at.timestamp() * 1000)

    extensions = [
        f"rt={cef_escape_extension(created_ms)}",
        f"src={cef_escape_extension(alert.src_ip)}",
        f"spt={cef_escape_extension(alert.src_port or 0)}",
        f"dst={cef_escape_extension(alert.dst_ip)}",
        f"dpt={cef_escape_extension(alert.dst_port or 0)}",
        f"deviceExternalId={cef_escape_extension(alert.id)}",
        f"cs1={cef_escape_extension(alert.detector or '')}",
        "cs1Label=Detector",
        f"cs2={cef_escape_extension(alert.category)}",
        "cs2Label=Category",
        f"cs3={cef_escape_extension(alert.status)}",
        "cs3Label=Status",
        f"cn1={cef_escape_extension(alert.risk_score)}",
        "cn1Label=RiskScore",
    ]
    header = "|".join(
        [
            "CEF:0",
            CEF_DEVICE_VENDOR,
            CEF_DEVICE_PRODUCT,
            version,
            cef_escape_header(signature_id),
            cef_escape_header(name),
            str(severity),
        ]
    )
    return f"{header}|{' '.join(extensions)}"


def build_test_cef_event(*, version: str = CEF_DEVICE_VERSION) -> str:
    """Render a fixed connectivity test event for SIEM endpoint validation."""
    return (
        "CEF:0|Sentinel IDS|Sentinel|"
        f"{version}|sentinel-ids-test|Sentinel IDS connectivity test|1|"
        "cs1Label=Source cs1=siem-test rt=0"
    )
