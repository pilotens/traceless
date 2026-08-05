"""add global intelligence hub

Revision ID: d5e4a0b9f211
Revises: c3c7b207ec73
Create Date: 2026-07-18 10:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d5e4a0b9f211"
down_revision: str | Sequence[str] | None = "c3c7b207ec73"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "global_intel_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_kind", sa.String(length=24), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("provider_key", sa.String(length=100), nullable=False),
        sa.Column("external_id", sa.String(length=160), nullable=False),
        sa.Column("record_type", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("source_url", sa.String(length=2000), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("cve_ids", sa.JSON(), nullable=False),
        sa.Column("cpes", sa.JSON(), nullable=False),
        sa.Column("affected_products", sa.JSON(), nullable=False),
        sa.Column("mitre_attack_ids", sa.JSON(), nullable=False),
        sa.Column("indicators", sa.JSON(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("sectors", sa.JSON(), nullable=False),
        sa.Column("regions", sa.JSON(), nullable=False),
        sa.Column("markings", sa.JSON(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("raw_evidence", sa.JSON(), nullable=False),
        sa.Column("raw_sha256", sa.String(length=64), nullable=False),
        sa.Column("ai_analysis", sa.JSON(), nullable=True),
        sa.Column("analysis_sha256", sa.String(length=64), nullable=True),
        sa.Column("vulnerability", sa.JSON(), nullable=True),
        sa.Column("feed_id", sa.String(length=120), nullable=False),
        sa.Column("feed_version", sa.String(length=120), nullable=False),
        sa.Column("feed_generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider_key", "external_id", name="uq_global_intel_provider_id"),
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_global_intel_confidence",
        ),
    )
    op.create_index(
        "ix_global_intel_modified", "global_intel_records", ["modified_at"], unique=False
    )
    op.create_index(
        "ix_global_intel_type_source",
        "global_intel_records",
        ["record_type", "source_kind"],
        unique=False,
    )
    op.create_index(
        "ix_global_intel_source_modified",
        "global_intel_records",
        ["source_kind", "modified_at"],
        unique=False,
    )
    op.create_table(
        "global_intel_observables",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("value_normalized", sa.String(length=500), nullable=False),
        sa.Column("value_display", sa.String(length=500), nullable=False),
        sa.ForeignKeyConstraint(
            ["record_id"], ["global_intel_records.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "record_id", "kind", "value_normalized", name="uq_global_intel_observable"
        ),
    )
    op.create_index(
        "ix_global_intel_observable_lookup",
        "global_intel_observables",
        ["kind", "value_normalized"],
        unique=False,
    )
    op.create_index(
        "ix_global_intel_observable_record",
        "global_intel_observables",
        ["record_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_global_intel_observable_record", table_name="global_intel_observables"
    )
    op.drop_index(
        "ix_global_intel_observable_lookup", table_name="global_intel_observables"
    )
    op.drop_table("global_intel_observables")
    op.drop_index("ix_global_intel_source_modified", table_name="global_intel_records")
    op.drop_index("ix_global_intel_type_source", table_name="global_intel_records")
    op.drop_index("ix_global_intel_modified", table_name="global_intel_records")
    op.drop_table("global_intel_records")
