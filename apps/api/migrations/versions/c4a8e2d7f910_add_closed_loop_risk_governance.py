"""add closed loop risk governance

Revision ID: c4a8e2d7f910
Revises: a9c4e2b7d610
Create Date: 2026-07-29 17:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4a8e2d7f910"
down_revision: str | Sequence[str] | None = "a9c4e2b7d610"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enable_system_policy(table: str) -> None:
    current_org = "traceless_current_organization_id()"
    predicate = (
        "EXISTS (SELECT 1 FROM systems_operational s "
        "JOIN projects p ON p.id = s.project_id "
        f"WHERE s.id = {table}.system_id AND p.organization_id = {current_org})"
    )
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY traceless_tenant_isolation ON "{table}" '
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )


def upgrade() -> None:
    op.create_table(
        "system_context_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("business_owner", sa.String(length=160), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("processes", sa.JSON(), nullable=False),
        sa.Column("data_categories", sa.JSON(), nullable=False),
        sa.Column("regulations", sa.JSON(), nullable=False),
        sa.Column("recovery_time_objective_hours", sa.Float(), nullable=True),
        sa.Column("recovery_point_objective_hours", sa.Float(), nullable=True),
        sa.Column("impact_profile", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_by", sa.String(length=160), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('draft', 'published', 'superseded')",
            name="ck_system_context_status",
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["systems_operational.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "system_id", "version", name="uq_system_context_system_version"
        ),
    )
    op.create_index(
        "ix_system_context_system_created",
        "system_context_versions",
        ["system_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ux_system_context_one_published",
        "system_context_versions",
        ["system_id"],
        unique=True,
        postgresql_where=sa.text("status = 'published'"),
        sqlite_where=sa.text("status = 'published'"),
    )

    op.create_table(
        "risk_evidence_links",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("risk_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_type", sa.String(length=32), nullable=False),
        sa.Column("evidence_id", sa.String(length=240), nullable=False),
        sa.Column("label", sa.String(length=500), nullable=False),
        sa.Column("source_version", sa.String(length=200), nullable=True),
        sa.Column("metadata_payload", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "evidence_type IN ('finding', 'threat', 'architecture', 'control', "
            "'attack_chain', 'manual')",
            name="ck_risk_evidence_type",
        ),
        sa.ForeignKeyConstraint(
            ["risk_id"], ["risks_operational.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "risk_id",
            "evidence_type",
            "evidence_id",
            name="uq_risk_evidence_identity",
        ),
    )
    op.create_index(
        "ix_risk_evidence_risk", "risk_evidence_links", ["risk_id"], unique=False
    )

    op.create_table(
        "risk_treatments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("risk_id", sa.Uuid(), nullable=False),
        sa.Column("strategy", sa.String(length=24), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(length=160), nullable=False),
        sa.Column("approver", sa.String(length=160), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("priority", sa.String(length=20), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sla_days", sa.Integer(), nullable=True),
        sa.Column("verification_criteria", sa.Text(), nullable=False),
        sa.Column("decision_note", sa.Text(), nullable=False),
        sa.Column("external_system", sa.String(length=80), nullable=True),
        sa.Column("external_key", sa.String(length=160), nullable=True),
        sa.Column("external_url", sa.String(length=2000), nullable=True),
        sa.Column("residual_likelihood", sa.Integer(), nullable=True),
        sa.Column("residual_impact", sa.Integer(), nullable=True),
        sa.Column("residual_score", sa.Integer(), nullable=True),
        sa.Column("residual_level", sa.String(length=20), nullable=True),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(length=160), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_by", sa.String(length=160), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "strategy IN ('mitigate', 'avoid', 'transfer', 'accept')",
            name="ck_risk_treatment_strategy",
        ),
        sa.CheckConstraint(
            "status IN ('proposed', 'approved', 'in_progress', 'verification', "
            "'closed', 'cancelled')",
            name="ck_risk_treatment_status",
        ),
        sa.CheckConstraint(
            "priority IN ('low', 'medium', 'high', 'critical')",
            name="ck_risk_treatment_priority",
        ),
        sa.ForeignKeyConstraint(
            ["risk_id"], ["risks_operational.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["systems_operational.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_risk_treatments_system_status",
        "risk_treatments",
        ["system_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_risk_treatments_risk", "risk_treatments", ["risk_id"], unique=False
    )
    op.create_index(
        "ix_risk_treatments_due", "risk_treatments", ["due_at"], unique=False
    )

    op.create_table(
        "controls_operational",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("control_key", sa.String(length=160), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("framework", sa.String(length=160), nullable=False),
        sa.Column("owner", sa.String(length=160), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('planned', 'implemented', 'retired')",
            name="ck_control_status",
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["systems_operational.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "system_id", "control_key", name="uq_control_system_key"
        ),
    )
    op.create_index(
        "ix_controls_system_status",
        "controls_operational",
        ["system_id", "status"],
        unique=False,
    )

    op.create_table(
        "control_assessments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column("design_effectiveness", sa.Float(), nullable=False),
        sa.Column("operating_effectiveness", sa.Float(), nullable=False),
        sa.Column("result", sa.String(length=24), nullable=False),
        sa.Column("evidence_reference", sa.Text(), nullable=False),
        sa.Column("assessed_by", sa.String(length=160), nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "design_effectiveness >= 0 AND design_effectiveness <= 1",
            name="ck_control_assessment_design",
        ),
        sa.CheckConstraint(
            "operating_effectiveness >= 0 AND operating_effectiveness <= 1",
            name="ck_control_assessment_operating",
        ),
        sa.CheckConstraint(
            "result IN ('effective', 'partial', 'ineffective', 'not_tested')",
            name="ck_control_assessment_result",
        ),
        sa.ForeignKeyConstraint(
            ["control_id"], ["controls_operational.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_control_assessments_control_assessed",
        "control_assessments",
        ["control_id", "assessed_at"],
        unique=False,
    )

    op.create_table(
        "analysis_manifests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.String(length=80), nullable=False),
        sa.Column("architecture_snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("system_context_version_id", sa.Uuid(), nullable=True),
        sa.Column("scan_job_id", sa.Uuid(), nullable=True),
        sa.Column("risk_policy_version", sa.String(length=120), nullable=False),
        sa.Column("source_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("components", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["architecture_snapshot_id"],
            ["architecture_snapshots.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"], ["scan_jobs.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["system_context_version_id"],
            ["system_context_versions.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["system_id"], ["systems_operational.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "system_id",
            "purpose",
            "source_fingerprint",
            name="uq_analysis_manifest_source",
        ),
    )
    op.create_index(
        "ix_analysis_manifests_system_created",
        "analysis_manifests",
        ["system_id", "created_at"],
        unique=False,
    )

    if op.get_bind().dialect.name != "postgresql":
        return

    for table in (
        "system_context_versions",
        "risk_treatments",
        "controls_operational",
        "analysis_manifests",
    ):
        _enable_system_policy(table)

    current_org = "traceless_current_organization_id()"
    risk_predicate = (
        "EXISTS (SELECT 1 FROM risks_operational r "
        "JOIN systems_operational s ON s.id = r.system_id "
        "JOIN projects p ON p.id = s.project_id "
        f"WHERE r.id = risk_evidence_links.risk_id AND p.organization_id = {current_org})"
    )
    op.execute('ALTER TABLE "risk_evidence_links" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "risk_evidence_links" FORCE ROW LEVEL SECURITY')
    op.execute(
        'CREATE POLICY traceless_tenant_isolation ON "risk_evidence_links" '
        f"USING ({risk_predicate}) WITH CHECK ({risk_predicate})"
    )

    control_predicate = (
        "EXISTS (SELECT 1 FROM controls_operational c "
        "JOIN systems_operational s ON s.id = c.system_id "
        "JOIN projects p ON p.id = s.project_id "
        f"WHERE c.id = control_assessments.control_id AND p.organization_id = {current_org})"
    )
    op.execute('ALTER TABLE "control_assessments" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "control_assessments" FORCE ROW LEVEL SECURITY')
    op.execute(
        'CREATE POLICY traceless_tenant_isolation ON "control_assessments" '
        f"USING ({control_predicate}) WITH CHECK ({control_predicate})"
    )


def downgrade() -> None:
    op.drop_index(
        "ix_analysis_manifests_system_created", table_name="analysis_manifests"
    )
    op.drop_table("analysis_manifests")
    op.drop_index(
        "ix_control_assessments_control_assessed", table_name="control_assessments"
    )
    op.drop_table("control_assessments")
    op.drop_index("ix_controls_system_status", table_name="controls_operational")
    op.drop_table("controls_operational")
    op.drop_index("ix_risk_treatments_due", table_name="risk_treatments")
    op.drop_index("ix_risk_treatments_risk", table_name="risk_treatments")
    op.drop_index("ix_risk_treatments_system_status", table_name="risk_treatments")
    op.drop_table("risk_treatments")
    op.drop_index("ix_risk_evidence_risk", table_name="risk_evidence_links")
    op.drop_table("risk_evidence_links")
    op.drop_index(
        "ux_system_context_one_published", table_name="system_context_versions"
    )
    op.drop_index(
        "ix_system_context_system_created", table_name="system_context_versions"
    )
    op.drop_table("system_context_versions")
