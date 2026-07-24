"""add tenant-scoped reachable attack-chain analyses

Revision ID: a9c4e2b7d610
Revises: a6d4c2f81b90
Create Date: 2026-07-23 16:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a9c4e2b7d610"
down_revision: str | Sequence[str] | None = "a6d4c2f81b90"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_chain_analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("source_record_id", sa.Uuid(), nullable=True),
        sa.Column("source_title", sa.String(length=500), nullable=False),
        sa.Column("distribution_tlp", sa.String(length=24), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column("source_text", sa.Text(), nullable=True),
        sa.Column("source_text_retained", sa.Boolean(), nullable=False),
        sa.Column("pipeline_version", sa.String(length=120), nullable=False),
        sa.Column("vocabulary_version", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("reachable", sa.Boolean(), nullable=False),
        sa.Column("unit_count", sa.Integer(), nullable=False),
        sa.Column("path_count", sa.Integer(), nullable=False),
        sa.Column("issue_count", sa.Integer(), nullable=False),
        sa.Column("repair_rounds", sa.Integer(), nullable=False),
        sa.Column("analysis", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "distribution_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', "
            "'TLP:AMBER+STRICT')",
            name="ck_attack_chain_analysis_distribution_tlp",
        ),
        sa.CheckConstraint(
            "length(input_sha256) = 64 AND length(source_sha256) = 64",
            name="ck_attack_chain_analysis_hashes",
        ),
        sa.CheckConstraint(
            "unit_count >= 0 AND path_count >= 0 AND issue_count >= 0",
            name="ck_attack_chain_analysis_counts",
        ),
        sa.CheckConstraint(
            "repair_rounds >= 0 AND repair_rounds <= 2",
            name="ck_attack_chain_analysis_repair_rounds",
        ),
        sa.CheckConstraint(
            "status IN ('reachable', 'unreachable')",
            name="ck_attack_chain_analysis_status",
        ),
        sa.CheckConstraint(
            "(source_text_retained AND source_text IS NOT NULL) OR "
            "(NOT source_text_retained AND source_text IS NULL)",
            name="ck_attack_chain_analysis_source_retention",
        ),
        sa.CheckConstraint(
            "(status = 'reachable' AND reachable AND path_count >= 1) OR "
            "(status = 'unreachable' AND NOT reachable AND path_count = 0)",
            name="ck_attack_chain_analysis_reachability",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_record_id"],
            ["global_intel_records.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "input_sha256",
            name="uq_attack_chain_analysis_org_input",
        ),
    )
    op.create_index(
        "ix_attack_chain_analysis_org_created",
        "attack_chain_analyses",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_attack_chain_analysis_source_record",
        "attack_chain_analyses",
        ["source_record_id", "created_at"],
    )

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    predicate = "organization_id = traceless_current_organization_id()"
    op.execute("ALTER TABLE attack_chain_analyses ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE attack_chain_analyses FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY traceless_tenant_isolation ON attack_chain_analyses "
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON attack_chain_analyses "
        "TO traceless_api, traceless_worker"
    )
    op.execute(
        """
        CREATE FUNCTION traceless_enforce_attack_chain_source_tenant()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, pg_temp
        AS $$
        BEGIN
            IF NEW.source_record_id IS NOT NULL AND NOT EXISTS (
                SELECT 1
                FROM public.global_intel_records AS record
                WHERE record.id = NEW.source_record_id
                  AND record.organization_id = NEW.organization_id
            ) THEN
                RAISE EXCEPTION 'attack-chain source record belongs to another organization'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER traceless_attack_chain_source_tenant
        BEFORE INSERT OR UPDATE OF organization_id, source_record_id
        ON attack_chain_analyses
        FOR EACH ROW EXECUTE FUNCTION traceless_enforce_attack_chain_source_tenant()
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS traceless_attack_chain_source_tenant "
            "ON attack_chain_analyses"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS traceless_enforce_attack_chain_source_tenant()"
        )
    op.drop_index(
        "ix_attack_chain_analysis_source_record",
        table_name="attack_chain_analyses",
    )
    op.drop_index(
        "ix_attack_chain_analysis_org_created",
        table_name="attack_chain_analyses",
    )
    op.drop_table("attack_chain_analyses")
