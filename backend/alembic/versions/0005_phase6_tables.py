"""phase 6: response_policies + capture_runs tables

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-06 00:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "response_policies",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "conditions",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "actions",
            postgresql.JSONB(),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("cooldown_seconds", sa.Integer(), server_default=sa.text("3600"), nullable=False),
        sa.Column("created_by", sa.BigInteger(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_response_policies_name", "response_policies", ["name"])

    op.create_table(
        "capture_runs",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("adapter", sa.Text(), nullable=False),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("packets_ingested", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("alerts_raised", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_capture_runs_adapter", "capture_runs", ["adapter"])
    op.create_index("ix_capture_runs_status", "capture_runs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_capture_runs_status", table_name="capture_runs")
    op.drop_index("ix_capture_runs_adapter", table_name="capture_runs")
    op.drop_table("capture_runs")
    op.drop_index("ix_response_policies_name", table_name="response_policies")
    op.drop_table("response_policies")
