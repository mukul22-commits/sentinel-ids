"""detection engine: alert metadata columns (title, detector, details)

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-06 00:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("title", sa.Text(), nullable=True))
    op.add_column("alerts", sa.Column("detector", sa.Text(), nullable=True))
    op.add_column(
        "alerts",
        sa.Column(
            "details",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=True,
        ),
    )
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_detector", "alerts", ["detector"])


def downgrade() -> None:
    op.drop_index("ix_alerts_detector", table_name="alerts")
    op.drop_index("ix_alerts_rule_id", table_name="alerts")
    op.drop_column("alerts", "details")
    op.drop_column("alerts", "detector")
    op.drop_column("alerts", "title")
