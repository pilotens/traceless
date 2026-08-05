"""add asset source snapshots

Revision ID: c3c7b207ec73
Revises: a8f62014e300
Create Date: 2026-07-17 23:05:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c3c7b207ec73"
down_revision: str | Sequence[str] | None = "a8f62014e300"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "asset_source_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=80), nullable=False),
        sa.Column("source_base_url", sa.String(length=2000), nullable=False),
        sa.Column("approval_state", sa.String(length=40), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("page_count", sa.Integer(), nullable=False),
        sa.Column("record_counts", sa.JSON(), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["system_id"],
            ["systems_operational.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "system_id",
            "provider",
            "manifest_sha256",
            name="uq_asset_source_snapshot_manifest",
        ),
    )
    op.create_index(
        "ix_asset_source_snapshots_system_created",
        "asset_source_snapshots",
        ["system_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_asset_source_snapshots_system_created",
        table_name="asset_source_snapshots",
    )
    op.drop_table("asset_source_snapshots")
