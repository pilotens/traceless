"""add signed external-feed delta subscription state

Revision ID: b1d8f6a3c720
Revises: a9c4e2b7d610
Create Date: 2026-07-24 09:10:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b1d8f6a3c720"
down_revision: str | Sequence[str] | None = "a9c4e2b7d610"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "external_intelligence_subscription_state",
        sa.Column("connector_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("feed_id", sa.String(length=120), nullable=False),
        sa.Column("feed_epoch", sa.Integer(), nullable=False),
        sa.Column("next_sync_token", sa.Text(), nullable=False),
        sa.Column("next_sync_token_sha256", sa.String(length=64), nullable=False),
        sa.Column("through_sequence", sa.BigInteger(), nullable=False),
        sa.Column("entitlement_epoch", sa.Integer(), nullable=True),
        sa.Column("reset_generation", sa.Integer(), nullable=True),
        sa.Column("last_full_snapshot_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signing_key_id", sa.String(length=120), nullable=False),
        sa.Column("signature_verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "feed_epoch >= 1",
            name="ck_external_intel_subscription_epoch",
        ),
        sa.CheckConstraint(
            "through_sequence >= 0",
            name="ck_external_intel_subscription_sequence",
        ),
        sa.CheckConstraint(
            "length(next_sync_token_sha256) = 64",
            name="ck_external_intel_subscription_token_hash",
        ),
        sa.ForeignKeyConstraint(
            ["connector_id"],
            ["external_intelligence_connectors.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("connector_id"),
        sa.UniqueConstraint(
            "organization_id",
            "connector_id",
            name="uq_external_intel_subscription_org_connector",
        ),
    )
    op.create_index(
        "ix_external_intel_subscription_org_updated",
        "external_intelligence_subscription_state",
        ["organization_id", "updated_at"],
    )

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    predicate = "organization_id = traceless_current_organization_id()"
    op.execute(
        "ALTER TABLE external_intelligence_subscription_state ENABLE ROW LEVEL SECURITY"
    )
    op.execute(
        "ALTER TABLE external_intelligence_subscription_state FORCE ROW LEVEL SECURITY"
    )
    op.execute(
        "CREATE POLICY traceless_tenant_isolation "
        "ON external_intelligence_subscription_state "
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE "
        "ON external_intelligence_subscription_state TO traceless_api, traceless_worker"
    )


def downgrade() -> None:
    op.drop_index(
        "ix_external_intel_subscription_org_updated",
        table_name="external_intelligence_subscription_state",
    )
    op.drop_table("external_intelligence_subscription_state")
