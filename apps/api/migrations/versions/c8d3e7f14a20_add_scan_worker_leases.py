"""add scan worker leases and cancellation

Revision ID: c8d3e7f14a20
Revises: b4f2a91d7c30
Create Date: 2026-07-21 11:45:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c8d3e7f14a20"
down_revision: str | Sequence[str] | None = "b4f2a91d7c30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan_jobs") as batch:
        batch.add_column(sa.Column("claimed_by", sa.String(length=160), nullable=True))
        batch.add_column(
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(
            sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3")
        )
        batch.add_column(
            sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.create_check_constraint("ck_scan_job_attempt_count", "attempt_count >= 0")
        batch.create_check_constraint(
            "ck_scan_job_max_attempts", "max_attempts >= 1 AND max_attempts <= 10"
        )
        batch.create_index("ix_scan_jobs_lease", ["status", "lease_expires_at"])


def downgrade() -> None:
    with op.batch_alter_table("scan_jobs") as batch:
        batch.drop_index("ix_scan_jobs_lease")
        batch.drop_constraint("ck_scan_job_max_attempts", type_="check")
        batch.drop_constraint("ck_scan_job_attempt_count", type_="check")
        batch.drop_column("cancel_requested_at")
        batch.drop_column("max_attempts")
        batch.drop_column("attempt_count")
        batch.drop_column("heartbeat_at")
        batch.drop_column("lease_expires_at")
        batch.drop_column("claimed_by")
