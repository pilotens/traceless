"""add per-attempt scan job lease token

Revision ID: d7a4c9e61f20
Revises: b2e8f0d5c731
Create Date: 2026-07-21 18:15:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d7a4c9e61f20"
down_revision: str | Sequence[str] | None = "b2e8f0d5c731"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan_jobs") as batch:
        batch.add_column(sa.Column("lease_token", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scan_jobs") as batch:
        batch.drop_column("lease_token")
