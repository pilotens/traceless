"""add architecture editor and vulnerability scan imports

Revision ID: f7a19c2d4e61
Revises: d5e4a0b9f211
Create Date: 2026-07-18 18:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f7a19c2d4e61"
down_revision: str | Sequence[str] | None = "d5e4a0b9f211"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("architecture_snapshots") as batch:
        batch.alter_column(
            "source_scan_id", existing_type=sa.Uuid(), nullable=True
        )
        batch.add_column(sa.Column("base_snapshot_id", sa.Uuid(), nullable=True))
        batch.add_column(
            sa.Column(
                "source_type",
                sa.String(length=20),
                nullable=False,
                server_default="scan",
            )
        )
        batch.add_column(
            sa.Column(
                "title",
                sa.String(length=160),
                nullable=False,
                server_default="Skanningshärlett arkitekturutkast",
            )
        )
        batch.add_column(
            sa.Column("change_note", sa.Text(), nullable=False, server_default="")
        )
        batch.add_column(
            sa.Column(
                "created_by", sa.String(length=160), nullable=False, server_default="system"
            )
        )
        batch.create_foreign_key(
            "fk_architecture_base_snapshot",
            "architecture_snapshots",
            ["base_snapshot_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_check_constraint(
            "ck_architecture_source_type",
            "source_type IN ('scan', 'manual', 'import')",
        )

    op.create_table(
        "vulnerability_scan_imports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("source_format", sa.String(length=40), nullable=False),
        sa.Column("source_name", sa.String(length=255), nullable=False),
        sa.Column("scanner_version", sa.String(length=120), nullable=True),
        sa.Column("scan_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("imported_by", sa.String(length=160), nullable=False),
        sa.Column("raw_sha256", sa.String(length=64), nullable=False),
        sa.Column("report_metadata", sa.JSON(), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("asset_count", sa.Integer(), nullable=False),
        sa.Column("matched_asset_count", sa.Integer(), nullable=False),
        sa.Column("promoted_finding_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["system_id"], ["systems_operational.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "provider IN ('nessus', 'qualys', 'greenbone', 'rapid7', 'defender_vm', 'generic')",
            name="ck_vuln_import_provider",
        ),
        sa.CheckConstraint(
            "observation_count >= 0 AND asset_count >= 0 AND matched_asset_count >= 0 "
            "AND promoted_finding_count >= 0",
            name="ck_vuln_import_counts",
        ),
        sa.UniqueConstraint(
            "system_id", "raw_sha256", name="uq_vuln_import_system_digest"
        ),
    )
    op.create_index(
        "ix_vuln_import_system_imported",
        "vulnerability_scan_imports",
        ["system_id", "imported_at"],
        unique=False,
    )
    op.create_table(
        "vulnerability_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("import_id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("observation_key", sa.String(length=64), nullable=False),
        sa.Column("provider_finding_id", sa.String(length=160), nullable=False),
        sa.Column("asset_identifier", sa.String(length=500), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=20), nullable=True),
        sa.Column("service_name", sa.String(length=100), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("version", sa.String(length=120), nullable=True),
        sa.Column("cpes", sa.JSON(), nullable=False),
        sa.Column("cve_ids", sa.JSON(), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("solution", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=160), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("exploitable", sa.Boolean(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("matched_asset_id", sa.Uuid(), nullable=True),
        sa.Column("matched_service_id", sa.Uuid(), nullable=True),
        sa.Column("match_confidence", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "port IS NULL OR (port >= 0 AND port <= 65535)",
            name="ck_vuln_observation_port",
        ),
        sa.CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="ck_vuln_observation_cvss",
        ),
        sa.CheckConstraint(
            "match_confidence IS NULL OR (match_confidence >= 0 AND match_confidence <= 1)",
            name="ck_vuln_observation_confidence",
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_vuln_observation_severity",
        ),
        sa.CheckConstraint(
            "state IN ('open', 'fixed', 'reopened', 'accepted', 'unknown')",
            name="ck_vuln_observation_state",
        ),
        sa.ForeignKeyConstraint(
            ["import_id"], ["vulnerability_scan_imports.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["system_id"], ["systems_operational.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["matched_asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["matched_service_id"], ["services.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "import_id", "observation_key", name="uq_vuln_observation_import_key"
        ),
    )
    op.create_index(
        "ix_vuln_observation_system_severity",
        "vulnerability_observations",
        ["system_id", "severity"],
        unique=False,
    )
    op.create_index(
        "ix_vuln_observation_import",
        "vulnerability_observations",
        ["import_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_vuln_observation_import", table_name="vulnerability_observations")
    op.drop_index(
        "ix_vuln_observation_system_severity", table_name="vulnerability_observations"
    )
    op.drop_table("vulnerability_observations")
    op.drop_index(
        "ix_vuln_import_system_imported", table_name="vulnerability_scan_imports"
    )
    op.drop_table("vulnerability_scan_imports")

    # Manual versions intentionally have no source scan and cannot be represented
    # by the previous schema. A deliberate downgrade removes only those rows.
    op.execute(sa.text("DELETE FROM architecture_snapshots WHERE source_scan_id IS NULL"))
    with op.batch_alter_table("architecture_snapshots") as batch:
        batch.drop_constraint("ck_architecture_source_type", type_="check")
        batch.drop_constraint("fk_architecture_base_snapshot", type_="foreignkey")
        batch.drop_column("created_by")
        batch.drop_column("change_note")
        batch.drop_column("title")
        batch.drop_column("source_type")
        batch.drop_column("base_snapshot_id")
        batch.alter_column(
            "source_scan_id", existing_type=sa.Uuid(), nullable=False
        )
