"""reconcile users.full_name (present in the ORM model, missing from migrations)

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-08 00:00:00.000000

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("full_name", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "full_name")
