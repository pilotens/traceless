"""stabilize asset, finding, evidence and architecture lifecycles

Revision ID: e9b6c4d2a801
Revises: f7a19c2d4e61
Create Date: 2026-07-21 10:30:00.000000
"""

import hashlib
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e9b6c4d2a801"
down_revision: str | Sequence[str] | None = "f7a19c2d4e61"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NAMING_CONVENTION = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
}


def _foreign_key_name(table: str, column: str, referred_table: str) -> str:
    inspector = sa.inspect(op.get_bind())
    for constraint in inspector.get_foreign_keys(table):
        if constraint.get("constrained_columns") == [column]:
            name = constraint.get("name")
            if isinstance(name, str):
                return name
    return f"fk_{table}_{column}_{referred_table}"


def upgrade() -> None:
    with op.batch_alter_table("assets") as batch:
        batch.add_column(
            sa.Column("observation_count", sa.Integer(), nullable=False, server_default="1")
        )

    with op.batch_alter_table("architecture_snapshots") as batch:
        batch.add_column(
            sa.Column("layer", sa.String(length=20), nullable=False, server_default="observed")
        )
        batch.create_check_constraint(
            "ck_architecture_layer",
            "layer IN ('manual', 'observed', 'proposal')",
        )
    op.execute(
        sa.text(
            "UPDATE architecture_snapshots SET layer = CASE "
            "WHEN source_type = 'manual' THEN 'manual' "
            "WHEN source_type = 'import' THEN 'proposal' ELSE 'observed' END"
        )
    )

    with op.batch_alter_table("vulnerability_observations") as batch:
        batch.drop_constraint("ck_vuln_observation_state", type_="check")
        batch.create_check_constraint(
            "ck_vuln_observation_state",
            "state IN ('open', 'fixed', 'reopened', 'accepted', "
            "'false_positive', 'out_of_scope', 'unknown')",
        )

    scan_fk = _foreign_key_name("findings_operational", "scan_job_id", "scan_jobs")
    service_fk = _foreign_key_name("findings_operational", "service_id", "services")
    with op.batch_alter_table(
        "findings_operational", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.drop_constraint("uq_finding_scan_service_cve", type_="unique")
        batch.drop_constraint(scan_fk, type_="foreignkey")
        batch.drop_constraint(service_fk, type_="foreignkey")
        batch.add_column(sa.Column("asset_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("stable_key", sa.String(length=500), nullable=True))
        batch.add_column(
            sa.Column(
                "finding_type",
                sa.String(length=32),
                nullable=False,
                server_default="vulnerability",
            )
        )
        batch.add_column(
            sa.Column(
                "lifecycle_status",
                sa.String(length=24),
                nullable=False,
                server_default="open",
            )
        )
        batch.add_column(
            sa.Column(
                "primary_evidence_strength", sa.Integer(), nullable=False, server_default="0"
            )
        )
        batch.add_column(sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("status_updated_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(
            sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1")
        )
        batch.alter_column("scan_job_id", existing_type=sa.Uuid(), nullable=True)
        batch.alter_column("service_id", existing_type=sa.Uuid(), nullable=True)
        batch.alter_column("cve_id", existing_type=sa.String(length=32), nullable=True)
        batch.create_foreign_key(
            "fk_finding_scan_job",
            "scan_jobs",
            ["scan_job_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_finding_asset",
            "assets",
            ["asset_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_finding_service",
            "services",
            ["service_id"],
            ["id"],
            ondelete="SET NULL",
        )

    bind = op.get_bind()
    rows = list(
        bind.execute(
            sa.text(
                "SELECT f.id, f.service_id, f.cve_id, f.created_at, "
                "s.asset_id, s.port, s.protocol "
                "FROM findings_operational f LEFT JOIN services s ON s.id = f.service_id"
            )
        ).mappings()
    )
    for row in rows:
        identity = "|".join(
            [
                "cve",
                str(row["asset_id"] or "unknown"),
                str(row["port"] or 0),
                str(row["protocol"] or "host").casefold(),
                str(row["cve_id"] or "non-cve").upper(),
            ]
        )
        bind.execute(
            sa.text(
                "UPDATE findings_operational SET asset_id = :asset_id, stable_key = :stable_key, "
                "first_seen_at = created_at, last_seen_at = created_at, "
                "status_updated_at = created_at WHERE id = :id"
            ),
            {
                "id": row["id"],
                "asset_id": row["asset_id"],
                "stable_key": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            },
        )

    duplicate_keys = list(
        bind.execute(
            sa.text(
                "SELECT stable_key, MIN(created_at) AS first_seen "
                "FROM findings_operational GROUP BY stable_key HAVING COUNT(*) > 1"
            )
        ).mappings()
    )
    for duplicate in duplicate_keys:
        duplicate_rows = list(
            bind.execute(
                sa.text(
                    "SELECT id FROM findings_operational WHERE stable_key = :stable_key "
                    "ORDER BY created_at DESC"
                ),
                {"stable_key": duplicate["stable_key"]},
            ).mappings()
        )
        canonical_id = duplicate_rows[0]["id"]
        bind.execute(
            sa.text(
                "UPDATE findings_operational SET first_seen_at = :first_seen "
                "WHERE id = :id"
            ),
            {"id": canonical_id, "first_seen": duplicate["first_seen"]},
        )
        for stale in duplicate_rows[1:]:
            bind.execute(
                sa.text("DELETE FROM risks_operational WHERE finding_id = :id"),
                {"id": stale["id"]},
            )
            bind.execute(
                sa.text("DELETE FROM findings_operational WHERE id = :id"),
                {"id": stale["id"]},
            )

    with op.batch_alter_table("findings_operational") as batch:
        batch.alter_column("stable_key", existing_type=sa.String(length=500), nullable=False)
        batch.alter_column(
            "first_seen_at", existing_type=sa.DateTime(timezone=True), nullable=False
        )
        batch.alter_column(
            "last_seen_at", existing_type=sa.DateTime(timezone=True), nullable=False
        )
        batch.alter_column(
            "status_updated_at", existing_type=sa.DateTime(timezone=True), nullable=False
        )
        batch.create_unique_constraint(
            "uq_finding_system_stable_key", ["system_id", "stable_key"]
        )
        batch.create_check_constraint(
            "ck_finding_lifecycle_status",
            "lifecycle_status IN ('open', 'fixed', 'accepted', 'false_positive', "
            "'out_of_scope', 'reopened')",
        )
        batch.create_check_constraint(
            "ck_finding_type",
            "finding_type IN ('vulnerability', 'misconfiguration', 'informational')",
        )
        batch.create_check_constraint(
            "ck_finding_evidence_strength",
            "primary_evidence_strength >= 0 AND primary_evidence_strength <= 100",
        )
        batch.create_check_constraint(
            "ck_finding_occurrence_count", "occurrence_count >= 1"
        )
    op.create_index(
        "ix_findings_system_lifecycle",
        "findings_operational",
        ["system_id", "lifecycle_status"],
        unique=False,
    )

    op.create_table(
        "finding_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("observation_id", sa.Uuid(), nullable=True),
        sa.Column("evidence_key", sa.String(length=500), nullable=False),
        sa.Column("source_kind", sa.String(length=40), nullable=False),
        sa.Column("source_name", sa.String(length=120), nullable=False),
        sa.Column("external_id", sa.String(length=200), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=24), nullable=False),
        sa.Column("strength", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings_operational.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["observation_id"], ["vulnerability_observations.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "evidence_key", name="uq_finding_evidence_key"),
        sa.CheckConstraint(
            "lifecycle_status IN ('open', 'fixed', 'accepted', 'false_positive', "
            "'out_of_scope', 'reopened')",
            name="ck_finding_evidence_lifecycle",
        ),
        sa.CheckConstraint("strength >= 0 AND strength <= 100", name="ck_evidence_strength"),
        sa.CheckConstraint("observation_count >= 1", name="ck_evidence_observation_count"),
    )
    op.create_index(
        "ix_finding_evidence_finding", "finding_evidence", ["finding_id"], unique=False
    )

    with op.batch_alter_table("risks_operational") as batch:
        batch.add_column(sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(sa.text("UPDATE risks_operational SET updated_at = created_at"))
    with op.batch_alter_table("risks_operational") as batch:
        batch.alter_column(
            "updated_at", existing_type=sa.DateTime(timezone=True), nullable=False
        )


def downgrade() -> None:
    with op.batch_alter_table("risks_operational") as batch:
        batch.drop_column("closed_at")
        batch.drop_column("updated_at")

    op.drop_index("ix_finding_evidence_finding", table_name="finding_evidence")
    op.drop_table("finding_evidence")
    op.drop_index("ix_findings_system_lifecycle", table_name="findings_operational")

    op.execute(
        sa.text(
            "DELETE FROM findings_operational WHERE scan_job_id IS NULL "
            "OR service_id IS NULL OR cve_id IS NULL"
        )
    )
    scan_fk = _foreign_key_name("findings_operational", "scan_job_id", "scan_jobs")
    service_fk = _foreign_key_name("findings_operational", "service_id", "services")
    asset_fk = _foreign_key_name("findings_operational", "asset_id", "assets")
    with op.batch_alter_table(
        "findings_operational", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.drop_constraint("uq_finding_system_stable_key", type_="unique")
        batch.drop_constraint("ck_finding_lifecycle_status", type_="check")
        batch.drop_constraint("ck_finding_type", type_="check")
        batch.drop_constraint("ck_finding_evidence_strength", type_="check")
        batch.drop_constraint("ck_finding_occurrence_count", type_="check")
        batch.drop_constraint(scan_fk, type_="foreignkey")
        batch.drop_constraint(service_fk, type_="foreignkey")
        batch.drop_constraint(asset_fk, type_="foreignkey")
        batch.alter_column("scan_job_id", existing_type=sa.Uuid(), nullable=False)
        batch.alter_column("service_id", existing_type=sa.Uuid(), nullable=False)
        batch.alter_column("cve_id", existing_type=sa.String(length=32), nullable=False)
        batch.create_foreign_key(
            "fk_finding_scan_job",
            "scan_jobs",
            ["scan_job_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_foreign_key(
            "fk_finding_service",
            "services",
            ["service_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_unique_constraint(
            "uq_finding_scan_service_cve", ["scan_job_id", "service_id", "cve_id"]
        )
        batch.drop_column("occurrence_count")
        batch.drop_column("resolved_at")
        batch.drop_column("status_updated_at")
        batch.drop_column("last_seen_at")
        batch.drop_column("first_seen_at")
        batch.drop_column("primary_evidence_strength")
        batch.drop_column("lifecycle_status")
        batch.drop_column("finding_type")
        batch.drop_column("stable_key")
        batch.drop_column("asset_id")

    op.execute(
        sa.text(
            "UPDATE vulnerability_observations SET state = CASE "
            "WHEN state = 'false_positive' THEN 'accepted' "
            "WHEN state = 'out_of_scope' THEN 'fixed' ELSE state END"
        )
    )
    with op.batch_alter_table("vulnerability_observations") as batch:
        batch.drop_constraint("ck_vuln_observation_state", type_="check")
        batch.create_check_constraint(
            "ck_vuln_observation_state",
            "state IN ('open', 'fixed', 'reopened', 'accepted', 'unknown')",
        )

    with op.batch_alter_table("architecture_snapshots") as batch:
        batch.drop_constraint("ck_architecture_layer", type_="check")
        batch.drop_column("layer")

    with op.batch_alter_table("assets") as batch:
        batch.drop_column("observation_count")
