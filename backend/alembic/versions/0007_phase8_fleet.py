"""phase 8: multi-sensor fleet — sensors table + sensor_id columns

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-06 00:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "sensors",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.Text(), nullable=True),
        sa.Column("version", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), server_default=sa.text("'offline'"), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "config",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sensors_status", "sensors", ["status"])
    op.create_index("ix_sensors_name", "sensors", ["name"], unique=True)

    op.add_column("alerts", sa.Column("sensor_id", sa.BigInteger(), nullable=True))
    op.create_index("ix_alerts_sensor_id", "alerts", ["sensor_id"])

    op.add_column("capture_runs", sa.Column("sensor_id", sa.BigInteger(), nullable=True))
    op.create_index("ix_capture_runs_sensor_id", "capture_runs", ["sensor_id"])


def downgrade() -> None:
    op.drop_index("ix_capture_runs_sensor_id", table_name="capture_runs")
    op.drop_column("capture_runs", "sensor_id")

    op.drop_index("ix_alerts_sensor_id", table_name="alerts")
    op.drop_column("alerts", "sensor_id")

    op.drop_index("ix_sensors_name", table_name="sensors")
    op.drop_index("ix_sensors_status", table_name="sensors")
    op.drop_table("sensors")
