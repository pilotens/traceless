"""create central intelligence publisher

Revision ID: p1a6d4e2b810
Revises:
Create Date: 2026-07-23 18:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p1a6d4e2b810"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TLP_CHECK = (
    "max_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT')"
)
_DISTRIBUTION_TLP_CHECK = (
    "distribution_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', "
    "'TLP:AMBER+STRICT', 'TLP:RED')"
)


def upgrade() -> None:
    op.create_table(
        "publisher_clients",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("api_key_sha256", sa.String(length=64), nullable=False),
        sa.Column("token_version", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("max_tlp", sa.String(length=24), nullable=False),
        sa.Column("allowed_providers", sa.JSON(), nullable=False),
        sa.Column("allowed_source_kinds", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_TLP_CHECK, name="ck_publisher_client_max_tlp"),
        sa.CheckConstraint(
            "token_version >= 1",
            name="ck_publisher_client_token_version",
        ),
        sa.CheckConstraint(
            "length(api_key_sha256) = 64",
            name="ck_publisher_client_key_hash",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("api_key_sha256"),
        sa.UniqueConstraint("client_id"),
    )
    op.create_index(
        "ix_publisher_client_enabled",
        "publisher_clients",
        ["enabled", "client_id"],
    )

    op.create_table(
        "publisher_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("provider_key", sa.String(length=100), nullable=False),
        sa.Column("external_id", sa.String(length=160), nullable=False),
        sa.Column("source_kind", sa.String(length=24), nullable=False),
        sa.Column("record_type", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provider_key",
            "external_id",
            name="uq_publisher_record_provider_external_id",
        ),
    )
    op.create_index(
        "ix_publisher_record_updated",
        "publisher_records",
        ["updated_at", "id"],
    )

    op.create_table(
        "publisher_revisions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=20), nullable=False),
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("distribution_tlp", sa.String(length=24), nullable=False),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("feed_id", sa.String(length=120), nullable=False),
        sa.Column("feed_version", sa.String(length=120), nullable=False),
        sa.Column("feed_generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_record", sa.JSON(), nullable=False),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column("analysis_sha256", sa.String(length=64), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("publication_status", sa.String(length=20), nullable=False),
        sa.Column("imported_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "revision_number >= 1",
            name="ck_publisher_revision_number",
        ),
        sa.CheckConstraint(
            "lifecycle_status IN ('active', 'revoked', 'deleted')",
            name="ck_publisher_revision_lifecycle_status",
        ),
        sa.CheckConstraint(
            "publication_status IN ('staged', 'published', 'restricted', 'superseded', 'rejected')",
            name="ck_publisher_revision_publication_status",
        ),
        sa.CheckConstraint(
            _DISTRIBUTION_TLP_CHECK,
            name="ck_publisher_revision_distribution_tlp",
        ),
        sa.CheckConstraint(
            "length(source_sha256) = 64 AND length(analysis_sha256) = 64 "
            "AND length(payload_sha256) = 64",
            name="ck_publisher_revision_hashes",
        ),
        sa.ForeignKeyConstraint(
            ["record_id"],
            ["publisher_records.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "record_id",
            "revision_number",
            name="uq_publisher_revision_number",
        ),
    )
    op.create_index(
        "ix_publisher_revision_record_created",
        "publisher_revisions",
        ["record_id", "revision_number"],
    )
    op.create_index(
        "ix_publisher_revision_publication",
        "publisher_revisions",
        ["publication_status", "created_at"],
    )

    op.create_table(
        "publisher_changes",
        sa.Column("sequence", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("revision_id", sa.Uuid(), nullable=False),
        sa.Column("projection", sa.String(length=20), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("provider_key", sa.String(length=100), nullable=False),
        sa.Column("external_id", sa.String(length=160), nullable=False),
        sa.Column("source_kind", sa.String(length=24), nullable=False),
        sa.Column("record_type", sa.String(length=32), nullable=False),
        sa.Column("distribution_tlp", sa.String(length=24), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=20), nullable=False),
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("canonical_record", sa.JSON(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "projection IN ('canonical', 'withdrawal')",
            name="ck_publisher_change_projection",
        ),
        sa.CheckConstraint(
            "lifecycle_status IN ('active', 'revoked', 'deleted')",
            name="ck_publisher_change_lifecycle_status",
        ),
        sa.CheckConstraint(
            _DISTRIBUTION_TLP_CHECK,
            name="ck_publisher_change_distribution_tlp",
        ),
        sa.ForeignKeyConstraint(
            ["record_id"],
            ["publisher_records.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["revision_id"],
            ["publisher_revisions.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("sequence"),
        sa.UniqueConstraint(
            "revision_id",
            "projection",
            "distribution_tlp",
            name="uq_publisher_change_revision_projection_tlp",
        ),
    )
    op.create_index(
        "ix_publisher_change_identity_sequence",
        "publisher_changes",
        ["provider_key", "external_id", "sequence"],
    )
    op.create_index(
        "ix_publisher_change_published",
        "publisher_changes",
        ["published_at", "sequence"],
    )

    op.create_table(
        "publisher_audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("actor", sa.String(length=160), nullable=False),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("resource_type", sa.String(length=80), nullable=False),
        sa.Column("resource_id", sa.String(length=160), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_publisher_audit_created",
        "publisher_audit_events",
        ["created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_publisher_audit_created", table_name="publisher_audit_events")
    op.drop_table("publisher_audit_events")
    op.drop_index("ix_publisher_change_published", table_name="publisher_changes")
    op.drop_index("ix_publisher_change_identity_sequence", table_name="publisher_changes")
    op.drop_table("publisher_changes")
    op.drop_index("ix_publisher_revision_publication", table_name="publisher_revisions")
    op.drop_index("ix_publisher_revision_record_created", table_name="publisher_revisions")
    op.drop_table("publisher_revisions")
    op.drop_index("ix_publisher_record_updated", table_name="publisher_records")
    op.drop_table("publisher_records")
    op.drop_index("ix_publisher_client_enabled", table_name="publisher_clients")
    op.drop_table("publisher_clients")
