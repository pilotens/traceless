"""add tenant-bound durable background jobs

Revision ID: b2e8f0d5c731
Revises: a1d7e9c4b620
Create Date: 2026-07-21 16:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b2e8f0d5c731"
down_revision: str | Sequence[str] | None = "a1d7e9c4b620"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "background_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("job_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("payload_schema_version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key_sha256", sa.String(length=64), nullable=False),
        sa.Column("requested_by", sa.String(length=160), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_by", sa.String(length=160), nullable=True),
        sa.Column("lease_token", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("result_resource_type", sa.String(length=80), nullable=True),
        sa.Column("result_resource_id", sa.String(length=160), nullable=True),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "job_type IN ('normalized_vulnerability_import', 'report_generation')",
            name="ck_background_job_type",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_background_job_status",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0", name="ck_background_job_attempt_count"
        ),
        sa.CheckConstraint(
            "max_attempts >= 1 AND max_attempts <= 10",
            name="ck_background_job_max_attempts",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["systems_operational.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "idempotency_key_sha256",
            name="uq_background_job_org_idempotency",
        ),
    )
    op.create_index(
        "ix_background_jobs_status_available",
        "background_jobs",
        ["status", "available_at", "requested_at"],
        unique=False,
    )
    op.create_index(
        "ix_background_jobs_org_requested",
        "background_jobs",
        ["organization_id", "requested_at"],
        unique=False,
    )
    op.create_index(
        "ix_background_jobs_system_requested",
        "background_jobs",
        ["system_id", "requested_at"],
        unique=False,
    )
    op.create_index(
        "ix_background_jobs_lease",
        "background_jobs",
        ["status", "lease_expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_background_jobs_lease", table_name="background_jobs")
    op.drop_index("ix_background_jobs_system_requested", table_name="background_jobs")
    op.drop_index("ix_background_jobs_org_requested", table_name="background_jobs")
    op.drop_index("ix_background_jobs_status_available", table_name="background_jobs")
    op.drop_table("background_jobs")
