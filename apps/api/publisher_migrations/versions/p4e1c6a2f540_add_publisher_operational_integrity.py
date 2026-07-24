"""add publisher operational integrity and correct revision provenance

Revision ID: p4e1c6a2f540
Revises: p3d9b5c1e430
Create Date: 2026-07-24 17:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p4e1c6a2f540"
down_revision: str | Sequence[str] | None = "p3d9b5c1e430"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("publisher_revisions", sa.Column("source_kind", sa.String(24)))
    op.add_column("publisher_revisions", sa.Column("record_type", sa.String(32)))
    op.add_column("publisher_revisions", sa.Column("normalized_sha256", sa.String(64)))
    op.add_column("publisher_revisions", sa.Column("ai_analysis_sha256", sa.String(64)))
    op.execute(
        "UPDATE publisher_revisions AS revision "
        "SET source_kind = record.source_kind, record_type = record.record_type, "
        "normalized_sha256 = revision.analysis_sha256, "
        "ai_analysis_sha256 = revision.analysis_sha256 "
        "FROM publisher_records AS record "
        "WHERE record.id = revision.record_id"
        if op.get_bind().dialect.name == "postgresql"
        else "UPDATE publisher_revisions SET "
        "source_kind = (SELECT source_kind FROM publisher_records "
        "WHERE publisher_records.id = publisher_revisions.record_id), "
        "record_type = (SELECT record_type FROM publisher_records "
        "WHERE publisher_records.id = publisher_revisions.record_id), "
        "normalized_sha256 = analysis_sha256, ai_analysis_sha256 = analysis_sha256"
    )
    with op.batch_alter_table("publisher_revisions") as batch:
        batch.alter_column("source_kind", nullable=False)
        batch.alter_column("record_type", nullable=False)
        batch.alter_column("normalized_sha256", nullable=False)
        batch.alter_column("ai_analysis_sha256", nullable=False)
        batch.drop_constraint("ck_publisher_revision_hashes", type_="check")
        batch.create_check_constraint(
            "ck_publisher_revision_hashes",
            "length(source_sha256) = 64 AND length(analysis_sha256) = 64 "
            "AND length(normalized_sha256) = 64 AND length(ai_analysis_sha256) = 64 "
            "AND length(payload_sha256) = 64",
        )

    op.add_column(
        "publisher_installations",
        sa.Column("installation_key", sa.String(80), server_default="primary"),
    )
    op.add_column(
        "publisher_installations",
        sa.Column("environment", sa.String(32), server_default="production"),
    )
    op.add_column("publisher_installations", sa.Column("region", sa.String(80)))
    with op.batch_alter_table("publisher_installations") as batch:
        batch.alter_column("installation_key", nullable=False, server_default=None)
        batch.alter_column("environment", nullable=False, server_default=None)
        batch.create_unique_constraint(
            "uq_publisher_installation_account_key",
            ["account_id", "installation_key"],
        )
        batch.create_check_constraint(
            "ck_publisher_installation_environment",
            "environment IN ('production', 'test', 'development', 'disaster_recovery')",
        )

    op.add_column("publisher_import_runs", sa.Column("heartbeat_at", sa.DateTime(timezone=True)))
    op.add_column(
        "publisher_import_runs",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "publisher_import_runs",
        sa.Column("attempt_count", sa.Integer(), server_default="1"),
    )
    op.execute(
        "UPDATE publisher_import_runs SET heartbeat_at = created_at "
        "WHERE heartbeat_at IS NULL"
    )
    with op.batch_alter_table("publisher_import_runs") as batch:
        batch.alter_column("heartbeat_at", nullable=False)
        batch.alter_column("attempt_count", nullable=False, server_default=None)
        batch.drop_constraint("ck_publisher_import_run_status", type_="check")
        batch.create_check_constraint(
            "ck_publisher_import_run_status",
            "status IN ('running', 'completed', 'failed', 'abandoned')",
        )
        batch.create_check_constraint(
            "ck_publisher_import_run_attempt_count",
            "attempt_count >= 1",
        )
        batch.create_index(
            "ix_publisher_import_run_lease",
            ["status", "lease_expires_at"],
        )


def downgrade() -> None:
    with op.batch_alter_table("publisher_import_runs") as batch:
        batch.drop_index("ix_publisher_import_run_lease")
        batch.drop_constraint("ck_publisher_import_run_attempt_count", type_="check")
        batch.drop_constraint("ck_publisher_import_run_status", type_="check")
        batch.create_check_constraint(
            "ck_publisher_import_run_status",
            "status IN ('running', 'completed', 'failed')",
        )
        batch.drop_column("attempt_count")
        batch.drop_column("lease_expires_at")
        batch.drop_column("heartbeat_at")

    with op.batch_alter_table("publisher_installations") as batch:
        batch.drop_constraint("ck_publisher_installation_environment", type_="check")
        batch.drop_constraint("uq_publisher_installation_account_key", type_="unique")
        batch.drop_column("region")
        batch.drop_column("environment")
        batch.drop_column("installation_key")

    with op.batch_alter_table("publisher_revisions") as batch:
        batch.drop_constraint("ck_publisher_revision_hashes", type_="check")
        batch.create_check_constraint(
            "ck_publisher_revision_hashes",
            "length(source_sha256) = 64 AND length(analysis_sha256) = 64 "
            "AND length(payload_sha256) = 64",
        )
        batch.drop_column("ai_analysis_sha256")
        batch.drop_column("normalized_sha256")
        batch.drop_column("record_type")
        batch.drop_column("source_kind")
