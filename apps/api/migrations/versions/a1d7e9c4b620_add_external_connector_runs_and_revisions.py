"""add tenant external connector runs and immutable intel revisions

Revision ID: a1d7e9c4b620
Revises: c8d3e7f14a20
Create Date: 2026-07-21 14:30:00.000000
"""

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "a1d7e9c4b620"
down_revision: str | Sequence[str] | None = "c8d3e7f14a20"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT_ORGANIZATION_ID = UUID("00000000-0000-4000-8000-000000000001")
NAMING_CONVENTION = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
}


def _foreign_key_name(table: str, column: str) -> str:
    inspector = sa.inspect(op.get_bind())
    for constraint in inspector.get_foreign_keys(table):
        if constraint.get("constrained_columns") == [column]:
            name = constraint.get("name")
            if isinstance(name, str):
                return name
    return f"fk_{table}_{column}_organizations"


def upgrade() -> None:
    op.create_table(
        "external_intelligence_connectors",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("endpoint", sa.String(length=2_000), nullable=False),
        sa.Column("auth_scheme", sa.String(length=20), nullable=False),
        sa.Column("credential_reference", sa.String(length=160), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("sync_interval_seconds", sa.Integer(), nullable=True),
        sa.Column("next_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("schedule_claim_token_sha256", sa.String(length=64), nullable=True),
        sa.Column("schedule_claimed_by", sa.String(length=160), nullable=True),
        sa.Column("schedule_claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("schedule_claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("schedule_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config_version", sa.Integer(), nullable=False),
        sa.Column("identity_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "auth_scheme IN ('Bearer', 'X-API-Key')",
            name="ck_external_intel_connector_auth_scheme",
        ),
        sa.CheckConstraint(
            "config_version >= 1", name="ck_external_intel_connector_config_version"
        ),
        sa.CheckConstraint(
            "length(identity_sha256) = 64",
            name="ck_external_intel_connector_identity_sha256",
        ),
        sa.CheckConstraint(
            "sync_interval_seconds IS NULL OR "
            "(sync_interval_seconds >= 60 AND sync_interval_seconds <= 2592000)",
            name="ck_external_intel_connector_sync_interval",
        ),
        sa.CheckConstraint(
            "next_sync_at IS NULL OR (enabled AND sync_interval_seconds IS NOT NULL)",
            name="ck_external_intel_connector_next_sync",
        ),
        sa.CheckConstraint(
            "(schedule_claim_token_sha256 IS NULL AND schedule_claimed_by IS NULL "
            "AND schedule_claimed_at IS NULL AND schedule_claim_expires_at IS NULL "
            "AND schedule_heartbeat_at IS NULL) OR "
            "(schedule_claim_token_sha256 IS NOT NULL AND schedule_claimed_by IS NOT NULL "
            "AND schedule_claimed_at IS NOT NULL AND schedule_claim_expires_at IS NOT NULL "
            "AND schedule_heartbeat_at IS NOT NULL)",
            name="ck_external_intel_connector_schedule_claim",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_external_intel_connector_org_name"),
    )
    op.create_index(
        "ix_external_intel_connector_organization",
        "external_intelligence_connectors",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_external_intel_connector_due",
        "external_intelligence_connectors",
        ["enabled", "next_sync_at"],
        unique=False,
    )
    op.create_index(
        "ux_external_intel_connector_schedule_claim",
        "external_intelligence_connectors",
        ["schedule_claim_token_sha256"],
        unique=True,
    )

    op.create_table(
        "external_intelligence_sync_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("connector_id", sa.Uuid(), nullable=False),
        sa.Column("connector_config_version", sa.Integer(), nullable=False),
        sa.Column("connector_identity_sha256", sa.String(length=64), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("started_by", sa.String(length=160), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_token_sha256", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("start_cursor_sha256", sa.String(length=64), nullable=True),
        sa.Column("next_cursor_sha256", sa.String(length=64), nullable=True),
        sa.Column("feed_id", sa.String(length=120), nullable=True),
        sa.Column("feed_version", sa.String(length=120), nullable=True),
        sa.Column("feed_generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pages_fetched", sa.Integer(), nullable=False),
        sa.Column("records_fetched", sa.Integer(), nullable=False),
        sa.Column("batch_pages_fetched", sa.Integer(), nullable=False),
        sa.Column("batch_records_fetched", sa.Integer(), nullable=False),
        sa.Column("created_count", sa.Integer(), nullable=False),
        sa.Column("updated_count", sa.Integer(), nullable=False),
        sa.Column("unchanged_count", sa.Integer(), nullable=False),
        sa.Column("quarantined_count", sa.Integer(), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "status IN ('running', 'partial', 'completed', 'failed', 'quarantined')",
            name="ck_external_intel_sync_status",
        ),
        sa.CheckConstraint(
            "pages_fetched >= 0 AND records_fetched >= 0 AND created_count >= 0 "
            "AND batch_pages_fetched >= 0 AND batch_records_fetched >= 0 "
            "AND updated_count >= 0 AND unchanged_count >= 0 AND quarantined_count >= 0",
            name="ck_external_intel_sync_counts",
        ),
        sa.CheckConstraint(
            "connector_config_version >= 1",
            name="ck_external_intel_sync_config_version",
        ),
        sa.CheckConstraint(
            "length(connector_identity_sha256) = 64",
            name="ck_external_intel_sync_identity_sha256",
        ),
        sa.CheckConstraint(
            "(status = 'running' AND completed_at IS NULL AND claim_token_sha256 IS NOT NULL "
            "AND lease_expires_at IS NOT NULL AND heartbeat_at IS NOT NULL) OR "
            "(status <> 'running' AND completed_at IS NOT NULL "
            "AND claim_token_sha256 IS NULL AND lease_expires_at IS NULL)",
            name="ck_external_intel_sync_lease_state",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["connector_id"],
            ["external_intelligence_connectors.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_external_intel_sync_org_started",
        "external_intelligence_sync_runs",
        ["organization_id", "started_at"],
        unique=False,
    )
    op.create_index(
        "ix_external_intel_sync_connector_started",
        "external_intelligence_sync_runs",
        ["connector_id", "started_at"],
        unique=False,
    )
    op.create_index(
        "ix_external_intel_sync_lease",
        "external_intelligence_sync_runs",
        ["status", "lease_expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_external_intel_sync_snapshot",
        "external_intelligence_sync_runs",
        ["connector_id", "snapshot_id"],
        unique=False,
    )
    op.create_index(
        "ux_external_intel_sync_running_connector",
        "external_intelligence_sync_runs",
        ["connector_id"],
        unique=True,
        postgresql_where=sa.text("status = 'running'"),
        sqlite_where=sa.text("status = 'running'"),
    )
    op.create_index(
        "ux_external_intel_sync_claim_token",
        "external_intelligence_sync_runs",
        ["claim_token_sha256"],
        unique=True,
    )

    op.create_table(
        "external_intelligence_sync_pages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("connector_config_version", sa.Integer(), nullable=False),
        sa.Column("connector_identity_sha256", sa.String(length=64), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("page_number", sa.Integer(), nullable=False),
        sa.Column("request_cursor_sha256", sa.String(length=64), nullable=True),
        sa.Column("raw_payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("feed_id", sa.String(length=120), nullable=False),
        sa.Column("feed_version", sa.String(length=120), nullable=False),
        sa.Column("feed_generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("page_number >= 1", name="ck_external_intel_page_number"),
        sa.CheckConstraint("item_count >= 0", name="ck_external_intel_page_item_count"),
        sa.CheckConstraint(
            "connector_config_version >= 1",
            name="ck_external_intel_page_config_version",
        ),
        sa.CheckConstraint(
            "length(connector_identity_sha256) = 64",
            name="ck_external_intel_page_identity_sha256",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["run_id"], ["external_intelligence_sync_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "page_number", name="uq_external_intel_sync_page"),
    )
    op.create_index(
        "ix_external_intel_sync_page_org",
        "external_intelligence_sync_pages",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_external_intel_sync_page_snapshot",
        "external_intelligence_sync_pages",
        ["snapshot_id", "page_number"],
        unique=False,
    )

    op.create_table(
        "external_intelligence_sync_identities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("connector_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("connector_config_version", sa.Integer(), nullable=False),
        sa.Column("connector_identity_sha256", sa.String(length=64), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("page_number", sa.Integer(), nullable=False),
        sa.Column("provider_key", sa.String(length=100), nullable=False),
        sa.Column("external_id", sa.String(length=160), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("page_number >= 1", name="ck_external_intel_identity_page"),
        sa.CheckConstraint(
            "connector_config_version >= 1",
            name="ck_external_intel_identity_config_version",
        ),
        sa.CheckConstraint(
            "length(connector_identity_sha256) = 64",
            name="ck_external_intel_identity_identity_sha256",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["connector_id"],
            ["external_intelligence_connectors.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["external_intelligence_sync_runs.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_external_intel_sync_identity_snapshot",
        "external_intelligence_sync_identities",
        ["snapshot_id", "provider_key", "external_id"],
        unique=False,
    )
    op.create_index(
        "ix_external_intel_sync_identity_run",
        "external_intelligence_sync_identities",
        ["run_id"],
        unique=False,
    )

    op.create_table(
        "external_intelligence_checkpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("connector_id", sa.Uuid(), nullable=False),
        sa.Column("last_run_id", sa.Uuid(), nullable=False),
        sa.Column("connector_config_version", sa.Integer(), nullable=False),
        sa.Column("connector_identity_sha256", sa.String(length=64), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("cursor", sa.String(length=2_048), nullable=False),
        sa.Column("cursor_sha256", sa.String(length=64), nullable=False),
        sa.Column("feed_id", sa.String(length=120), nullable=False),
        sa.Column("feed_version", sa.String(length=120), nullable=False),
        sa.Column("feed_generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pages_completed", sa.Integer(), nullable=False),
        sa.Column("records_completed", sa.Integer(), nullable=False),
        sa.Column("page_manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("identity_manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "pages_completed >= 1 AND records_completed >= 0",
            name="ck_external_intel_checkpoint_counts",
        ),
        sa.CheckConstraint(
            "connector_config_version >= 1",
            name="ck_external_intel_checkpoint_config_version",
        ),
        sa.CheckConstraint(
            "length(connector_identity_sha256) = 64",
            name="ck_external_intel_checkpoint_identity_sha256",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["connector_id"],
            ["external_intelligence_connectors.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["last_run_id"], ["external_intelligence_sync_runs.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("connector_id", name="uq_external_intel_checkpoint_connector"),
    )
    op.create_index(
        "ix_external_intel_checkpoint_org",
        "external_intelligence_checkpoints",
        ["organization_id"],
        unique=False,
    )

    op.create_table(
        "global_intel_revisions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=True),
        sa.Column("sync_run_id", sa.Uuid(), nullable=True),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("provider_key", sa.String(length=100), nullable=False),
        sa.Column("external_id", sa.String(length=160), nullable=False),
        sa.Column("feed_id", sa.String(length=120), nullable=False),
        sa.Column("feed_version", sa.String(length=120), nullable=False),
        sa.Column("feed_generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_modified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(length=24), nullable=False),
        sa.Column("quarantine_reason", sa.String(length=200), nullable=True),
        sa.Column("canonical_payload", sa.JSON(), nullable=False),
        sa.Column("raw_evidence", sa.JSON(), nullable=False),
        sa.Column("raw_sha256", sa.String(length=64), nullable=False),
        sa.Column("analysis_sha256", sa.String(length=64), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('applied', 'unchanged', 'superseded', 'quarantined')",
            name="ck_global_intel_revision_outcome",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["record_id"], ["global_intel_records.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["sync_run_id"], ["external_intelligence_sync_runs.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_global_intel_revision_identity",
        "global_intel_revisions",
        ["organization_id", "provider_key", "external_id", "received_at"],
        unique=False,
    )
    op.create_index(
        "ix_global_intel_revision_record",
        "global_intel_revisions",
        ["record_id"],
        unique=False,
    )
    op.create_index(
        "ix_global_intel_revision_run",
        "global_intel_revisions",
        ["sync_run_id"],
        unique=False,
    )

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            sa.text(
                "UPDATE audit_events AS a SET organization_id = p.organization_id "
                "FROM scan_jobs AS s JOIN systems_operational AS sy ON sy.id = s.system_id "
                "JOIN projects AS p ON p.id = sy.project_id "
                "WHERE a.organization_id IS NULL AND a.resource_type = 'scan' "
                "AND a.resource_id = CAST(s.id AS VARCHAR)"
            )
        )
    else:
        op.execute(
            sa.text(
                "UPDATE audit_events SET organization_id = ("
                "SELECT p.organization_id FROM scan_jobs s "
                "JOIN systems_operational sy ON sy.id = s.system_id "
                "JOIN projects p ON p.id = sy.project_id "
                "WHERE replace(audit_events.resource_id, '-', '') = s.id"
                ") WHERE organization_id IS NULL AND resource_type = 'scan'"
            )
        )
    # Pre-tenant audit records were assigned to the original local organization.
    # This fallback only covers unknown legacy resource types; new writes fail closed.
    op.execute(
        sa.text(
            "UPDATE audit_events SET organization_id = :organization_id "
            "WHERE organization_id IS NULL"
        ).bindparams(organization_id=DEFAULT_ORGANIZATION_ID)
    )
    old_audit_fk = _foreign_key_name("audit_events", "organization_id")
    with op.batch_alter_table("audit_events", naming_convention=NAMING_CONVENTION) as batch:
        batch.drop_constraint(old_audit_fk, type_="foreignkey")
        batch.alter_column("organization_id", existing_type=sa.Uuid(), nullable=False)
        batch.create_foreign_key(
            "fk_audit_events_organization_id_organizations",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="RESTRICT",
        )


def downgrade() -> None:
    audit_fk = _foreign_key_name("audit_events", "organization_id")
    with op.batch_alter_table("audit_events", naming_convention=NAMING_CONVENTION) as batch:
        batch.drop_constraint(audit_fk, type_="foreignkey")
        batch.alter_column("organization_id", existing_type=sa.Uuid(), nullable=True)
        batch.create_foreign_key(
            "fk_audit_events_organization_id_organizations",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="SET NULL",
        )

    op.drop_index("ix_global_intel_revision_run", table_name="global_intel_revisions")
    op.drop_index("ix_global_intel_revision_record", table_name="global_intel_revisions")
    op.drop_index("ix_global_intel_revision_identity", table_name="global_intel_revisions")
    op.drop_table("global_intel_revisions")
    op.drop_index(
        "ix_external_intel_checkpoint_org",
        table_name="external_intelligence_checkpoints",
    )
    op.drop_table("external_intelligence_checkpoints")
    op.drop_index(
        "ix_external_intel_sync_identity_run",
        table_name="external_intelligence_sync_identities",
    )
    op.drop_index(
        "ix_external_intel_sync_identity_snapshot",
        table_name="external_intelligence_sync_identities",
    )
    op.drop_table("external_intelligence_sync_identities")
    op.drop_index(
        "ix_external_intel_sync_page_snapshot",
        table_name="external_intelligence_sync_pages",
    )
    op.drop_index(
        "ix_external_intel_sync_page_org",
        table_name="external_intelligence_sync_pages",
    )
    op.drop_table("external_intelligence_sync_pages")
    op.drop_index(
        "ux_external_intel_sync_claim_token",
        table_name="external_intelligence_sync_runs",
    )
    op.drop_index(
        "ux_external_intel_sync_running_connector",
        table_name="external_intelligence_sync_runs",
    )
    op.drop_index(
        "ix_external_intel_sync_snapshot",
        table_name="external_intelligence_sync_runs",
    )
    op.drop_index(
        "ix_external_intel_sync_lease",
        table_name="external_intelligence_sync_runs",
    )
    op.drop_index(
        "ix_external_intel_sync_connector_started",
        table_name="external_intelligence_sync_runs",
    )
    op.drop_index(
        "ix_external_intel_sync_org_started",
        table_name="external_intelligence_sync_runs",
    )
    op.drop_table("external_intelligence_sync_runs")
    op.drop_index(
        "ux_external_intel_connector_schedule_claim",
        table_name="external_intelligence_connectors",
    )
    op.drop_index(
        "ix_external_intel_connector_organization",
        table_name="external_intelligence_connectors",
    )
    op.drop_table("external_intelligence_connectors")
