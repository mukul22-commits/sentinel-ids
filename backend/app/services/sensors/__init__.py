"""Fleet / multi-sensor management service (Phase 8)."""

from app.services.sensors.service import (
    create_sensor,
    delete_sensor,
    effective_config,
    find_sensor_by_token,
    fleet_summary,
    generate_sensor_token,
    get_sensor,
    hash_sensor_token,
    list_enabled_sensors,
    list_sensors,
    mark_stale_sensors,
    record_heartbeat,
    rotate_sensor_token,
    update_sensor,
)

__all__ = [
    "create_sensor",
    "delete_sensor",
    "effective_config",
    "find_sensor_by_token",
    "fleet_summary",
    "generate_sensor_token",
    "get_sensor",
    "hash_sensor_token",
    "list_enabled_sensors",
    "list_sensors",
    "mark_stale_sensors",
    "record_heartbeat",
    "rotate_sensor_token",
    "update_sensor",
]
