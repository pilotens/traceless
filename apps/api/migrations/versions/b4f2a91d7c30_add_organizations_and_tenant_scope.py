"""add organizations and tenant scope

Revision ID: b4f2a91d7c30
Revises: e9b6c4d2a801
Create Date: 2026-07-21 11:15:00.000000
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID

import sqlalchemy as sa
from alembic import op

revision: str = "b4f2a91d7c30"
down_revision: str | Sequence[str] | None = "e9b6c4d2a801"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT_ORGANIZATION_ID = UUID("00000000-0000-4000-8000-000000000001")
NAMING_CONVENTION = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
}


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("external_key", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("external_key", name="uq_organizations_external_key"),
    )
    organizations = sa.table(
        "organizations",
        sa.column("id", sa.Uuid()),
        sa.column("external_key", sa.String()),
        sa.column("name", sa.String()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    now = datetime.now(UTC)
    op.bulk_insert(
        organizations,
        [
            {
                "id": DEFAULT_ORGANIZATION_ID,
                "external_key": "local-traceless",
                "name": "Local Traceless",
                "created_at": now,
                "updated_at": now,
            }
        ],
    )

    with op.batch_alter_table(
        "projects", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.add_column(sa.Column("organization_id", sa.Uuid(), nullable=True))
    op.execute(
        sa.text("UPDATE projects SET organization_id = :organization_id").bindparams(
            organization_id=DEFAULT_ORGANIZATION_ID
        )
    )
    with op.batch_alter_table(
        "projects", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.alter_column("organization_id", existing_type=sa.Uuid(), nullable=False)
        batch.create_foreign_key(
            "fk_projects_organization_id_organizations",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_index("ix_projects_organization", ["organization_id"])

    with op.batch_alter_table(
        "global_intel_records", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.add_column(sa.Column("organization_id", sa.Uuid(), nullable=True))
    op.execute(
        sa.text(
            "UPDATE global_intel_records SET organization_id = :organization_id"
        ).bindparams(organization_id=DEFAULT_ORGANIZATION_ID)
    )
    with op.batch_alter_table(
        "global_intel_records", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.alter_column("organization_id", existing_type=sa.Uuid(), nullable=False)
        batch.drop_constraint("uq_global_intel_provider_id", type_="unique")
        batch.create_unique_constraint(
            "uq_global_intel_org_provider_id",
            ["organization_id", "provider_key", "external_id"],
        )
        batch.create_foreign_key(
            "fk_global_intel_records_organization_id_organizations",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_index("ix_global_intel_organization", ["organization_id"])

    with op.batch_alter_table(
        "audit_events", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.add_column(sa.Column("organization_id", sa.Uuid(), nullable=True))
    op.execute(
        sa.text("UPDATE audit_events SET organization_id = :organization_id").bindparams(
            organization_id=DEFAULT_ORGANIZATION_ID
        )
    )
    with op.batch_alter_table(
        "audit_events", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.create_foreign_key(
            "fk_audit_events_organization_id_organizations",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_index("ix_audit_events_organization", ["organization_id"])


def downgrade() -> None:
    with op.batch_alter_table(
        "audit_events", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.drop_index("ix_audit_events_organization")
        batch.drop_constraint(
            "fk_audit_events_organization_id_organizations", type_="foreignkey"
        )
        batch.drop_column("organization_id")

    # The previous schema had one global namespace. Keep the oldest revision
    # for identities that exist in more than one organization before restoring
    # its two-column uniqueness constraint.
    op.execute(
        sa.text(
            "DELETE FROM global_intel_records WHERE id IN ("
            "SELECT id FROM ("
            "SELECT id, ROW_NUMBER() OVER ("
            "PARTITION BY provider_key, external_id ORDER BY first_ingested_at, id"
            ") AS duplicate_number FROM global_intel_records"
            ") AS duplicates WHERE duplicate_number > 1)"
        )
    )
    with op.batch_alter_table(
        "global_intel_records", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.drop_index("ix_global_intel_organization")
        batch.drop_constraint(
            "fk_global_intel_records_organization_id_organizations",
            type_="foreignkey",
        )
        batch.drop_constraint("uq_global_intel_org_provider_id", type_="unique")
        batch.create_unique_constraint(
            "uq_global_intel_provider_id", ["provider_key", "external_id"]
        )
        batch.drop_column("organization_id")

    with op.batch_alter_table(
        "projects", naming_convention=NAMING_CONVENTION
    ) as batch:
        batch.drop_index("ix_projects_organization")
        batch.drop_constraint(
            "fk_projects_organization_id_organizations", type_="foreignkey"
        )
        batch.drop_column("organization_id")

    op.drop_table("organizations")
