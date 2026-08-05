"""finalize publisher integrity and least-privilege history

Revision ID: p3d9b5c1e430
Revises: p2c7f4a8d920
Create Date: 2026-07-24 14:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p3d9b5c1e430"
down_revision: str | Sequence[str] | None = "p2c7f4a8d920"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    op.drop_table("publisher_delivery_state")
    if bind.dialect.name == "postgresql":
        op.drop_constraint(
            "ck_publisher_revision_publication_status",
            "publisher_revisions",
            type_="check",
        )
        op.create_check_constraint(
            "ck_publisher_revision_publication_status",
            "publisher_revisions",
            "publication_status IN ('staged', 'published', 'restricted', "
            "'superseded', 'rejected')",
        )
        op.drop_constraint(
            "publisher_revisions_record_id_fkey",
            "publisher_revisions",
            type_="foreignkey",
        )
        op.create_foreign_key(
            "publisher_revisions_record_id_fkey",
            "publisher_revisions",
            "publisher_records",
            ["record_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.drop_constraint(
            "publisher_changes_record_id_fkey",
            "publisher_changes",
            type_="foreignkey",
        )
        op.create_foreign_key(
            "publisher_changes_record_id_fkey",
            "publisher_changes",
            "publisher_records",
            ["record_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.drop_constraint(
            "publisher_changes_revision_id_fkey",
            "publisher_changes",
            type_="foreignkey",
        )
        op.create_foreign_key(
            "publisher_changes_revision_id_fkey",
            "publisher_changes",
            "publisher_revisions",
            ["revision_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.execute(
            "UPDATE publisher_client_credentials "
            "SET expires_at = created_at + INTERVAL '90 days' "
            "WHERE expires_at IS NULL"
        )
        op.execute(
            """
            CREATE FUNCTION traceless_publisher_reject_immutable_mutation()
            RETURNS trigger LANGUAGE plpgsql
            SET search_path = pg_catalog, pg_temp
            AS $$ BEGIN
                RAISE EXCEPTION 'publisher immutable history cannot be modified'
                    USING ERRCODE = '55000';
            END $$
            """
        )
        for table in (
            "publisher_changes",
            "publisher_publication_decisions",
            "publisher_audit_events",
        ):
            op.execute(
                f"CREATE TRIGGER traceless_publisher_no_update_{table} "
                f"BEFORE UPDATE ON {table} FOR EACH ROW "
                "EXECUTE FUNCTION traceless_publisher_reject_immutable_mutation()"
            )
        for table in (
            "publisher_publication_decisions",
            "publisher_audit_events",
            "publisher_import_runs",
            "publisher_signing_keys",
        ):
            op.execute(
                f"CREATE TRIGGER traceless_publisher_no_delete_{table} "
                f"BEFORE DELETE ON {table} FOR EACH ROW "
                "EXECUTE FUNCTION traceless_publisher_reject_history_delete()"
            )
    else:
        op.execute(
            "UPDATE publisher_client_credentials "
            "SET expires_at = datetime(created_at, '+90 days') "
            "WHERE expires_at IS NULL"
        )
        for table in (
            "publisher_changes",
            "publisher_publication_decisions",
            "publisher_audit_events",
        ):
            op.execute(
                f"CREATE TRIGGER traceless_publisher_no_update_{table} "
                f"BEFORE UPDATE ON {table} BEGIN "
                "SELECT RAISE(ABORT, 'publisher immutable history cannot be modified'); END"
            )
        for table in (
            "publisher_publication_decisions",
            "publisher_audit_events",
            "publisher_import_runs",
            "publisher_signing_keys",
        ):
            op.execute(
                f"CREATE TRIGGER traceless_publisher_no_delete_{table} "
                f"BEFORE DELETE ON {table} BEGIN "
                "SELECT RAISE(ABORT, 'publisher history is append-only'); END"
            )


def downgrade() -> None:
    bind = op.get_bind()
    op.create_table(
        "publisher_delivery_state",
        sa.Column("installation_id", sa.Uuid(), nullable=False),
        sa.Column("last_served_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_completed_sequence", sa.BigInteger(), nullable=False),
        sa.Column("feed_epoch", sa.Integer(), nullable=False),
        sa.Column("last_full_snapshot_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "last_served_sequence >= 0 AND last_completed_sequence >= 0 "
            "AND feed_epoch >= 1",
            name="ck_publisher_delivery_state_counts",
        ),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["publisher_installations.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("installation_id"),
    )
    for table in (
        "publisher_publication_decisions",
        "publisher_audit_events",
        "publisher_import_runs",
        "publisher_signing_keys",
    ):
        if bind.dialect.name == "postgresql":
            op.execute(
                f"DROP TRIGGER IF EXISTS traceless_publisher_no_delete_{table} ON {table}"
            )
        else:
            op.execute(f"DROP TRIGGER IF EXISTS traceless_publisher_no_delete_{table}")
    for table in (
        "publisher_changes",
        "publisher_publication_decisions",
        "publisher_audit_events",
    ):
        if bind.dialect.name == "postgresql":
            op.execute(
                f"DROP TRIGGER IF EXISTS traceless_publisher_no_update_{table} ON {table}"
            )
        else:
            op.execute(f"DROP TRIGGER IF EXISTS traceless_publisher_no_update_{table}")
    if bind.dialect.name == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS traceless_publisher_reject_immutable_mutation()")
        op.drop_constraint(
            "ck_publisher_revision_publication_status",
            "publisher_revisions",
            type_="check",
        )
        op.create_check_constraint(
            "ck_publisher_revision_publication_status",
            "publisher_revisions",
            "publication_status IN ('staged', 'published', 'restricted', 'superseded')",
        )
        op.drop_constraint(
            "publisher_changes_revision_id_fkey",
            "publisher_changes",
            type_="foreignkey",
        )
        op.create_foreign_key(
            "publisher_changes_revision_id_fkey",
            "publisher_changes",
            "publisher_revisions",
            ["revision_id"],
            ["id"],
            ondelete="CASCADE",
        )
        op.drop_constraint(
            "publisher_changes_record_id_fkey",
            "publisher_changes",
            type_="foreignkey",
        )
        op.create_foreign_key(
            "publisher_changes_record_id_fkey",
            "publisher_changes",
            "publisher_records",
            ["record_id"],
            ["id"],
            ondelete="CASCADE",
        )
        op.drop_constraint(
            "publisher_revisions_record_id_fkey",
            "publisher_revisions",
            type_="foreignkey",
        )
        op.create_foreign_key(
            "publisher_revisions_record_id_fkey",
            "publisher_revisions",
            "publisher_records",
            ["record_id"],
            ["id"],
            ondelete="CASCADE",
        )
