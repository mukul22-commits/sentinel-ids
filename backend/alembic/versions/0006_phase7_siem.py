"""phase 7: SIEM export — alerts watermark + siem_exports table

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-06 00:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column("siem_exported_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_alerts_siem_pending",
        "alerts",
        ["id"],
        postgresql_where=sa.text("siem_exported_at IS NULL"),
    )

    op.create_table(
        "siem_exports",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("alerts_exported", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_siem_exports_status", "siem_exports", ["status"])
    op.create_index("ix_siem_exports_created_at", "siem_exports", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_siem_exports_created_at", table_name="siem_exports")
    op.drop_index("ix_siem_exports_status", table_name="siem_exports")
    op.drop_table("siem_exports")
    op.drop_index("ix_alerts_siem_pending", table_name="alerts")
    op.drop_column("alerts", "siem_exported_at")
