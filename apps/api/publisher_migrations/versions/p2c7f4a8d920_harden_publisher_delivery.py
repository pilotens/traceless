"""harden publisher credentials, review and delta delivery

Revision ID: p2c7f4a8d920
Revises: p1a6d4e2b810
Create Date: 2026-07-24 09:00:00.000000
"""

from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

revision: str = "p2c7f4a8d920"
down_revision: str | Sequence[str] | None = "p1a6d4e2b810"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TLP = "max_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT')"
_DISTRIBUTION_TLP = (
    "distribution_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', "
    "'TLP:AMBER+STRICT', 'TLP:RED')"
)


def upgrade() -> None:
    op.create_table(
        "publisher_accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("account_key", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_key"),
    )
    op.create_index(
        "ix_publisher_account_enabled",
        "publisher_accounts",
        ["enabled", "account_key"],
    )
    op.create_table(
        "publisher_installations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("max_tlp", sa.String(length=24), nullable=False),
        sa.Column("entitlement_epoch", sa.Integer(), nullable=False),
        sa.Column("reset_generation", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_TLP, name="ck_publisher_installation_max_tlp"),
        sa.CheckConstraint(
            "entitlement_epoch >= 1 AND reset_generation >= 1",
            name="ck_publisher_installation_epochs",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["publisher_accounts.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("client_id"),
    )
    op.create_index(
        "ix_publisher_installation_account",
        "publisher_installations",
        ["account_id", "enabled"],
    )
    op.create_table(
        "publisher_client_credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("installation_id", sa.Uuid(), nullable=False),
        sa.Column("key_sha256", sa.String(length=64), nullable=False),
        sa.Column("token_version", sa.Integer(), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("token_version >= 1", name="ck_publisher_credential_version"),
        sa.CheckConstraint(
            "length(key_sha256) = 64",
            name="ck_publisher_credential_key_hash",
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > not_before",
            name="ck_publisher_credential_expiry",
        ),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["publisher_installations.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_sha256"),
    )
    op.create_index(
        "ix_publisher_credential_installation_active",
        "publisher_client_credentials",
        ["installation_id", "revoked_at", "expires_at"],
    )
    op.create_table(
        "publisher_entitlements",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("installation_id", sa.Uuid(), nullable=False),
        sa.Column("scope_type", sa.String(length=24), nullable=False),
        sa.Column("scope_value", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "scope_type IN ('provider', 'source_kind')",
            name="ck_publisher_entitlement_scope_type",
        ),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["publisher_installations.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "installation_id",
            "scope_type",
            "scope_value",
            name="uq_publisher_entitlement_scope",
        ),
    )
    op.create_index(
        "ix_publisher_entitlement_lookup",
        "publisher_entitlements",
        ["installation_id", "scope_type", "scope_value"],
    )
    op.create_table(
        "publisher_import_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("feed_id", sa.String(length=120), nullable=False),
        sa.Column("feed_version", sa.String(length=120), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key_sha256", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("actor", sa.String(length=160), nullable=False),
        sa.Column("error_code", sa.String(length=120), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'failed')",
            name="ck_publisher_import_run_status",
        ),
        sa.CheckConstraint("item_count >= 0", name="ck_publisher_import_run_item_count"),
        sa.CheckConstraint(
            "length(manifest_sha256) = 64",
            name="ck_publisher_import_run_manifest",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key_sha256"),
    )
    op.create_index(
        "ix_publisher_import_run_created",
        "publisher_import_runs",
        ["created_at", "id"],
    )
    op.create_table(
        "publisher_publication_decisions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("revision_id", sa.Uuid(), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("actor", sa.String(length=160), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "decision IN ('published', 'rejected', 'emergency_withdrawal', 'automatic')",
            name="ck_publisher_publication_decision",
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
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_publisher_decision_record_created",
        "publisher_publication_decisions",
        ["record_id", "created_at"],
    )
    op.create_table(
        "publisher_current_projections",
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("revision_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
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
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            _DISTRIBUTION_TLP,
            name="ck_publisher_current_projection_tlp",
        ),
        sa.CheckConstraint(
            "lifecycle_status IN ('active', 'revoked', 'deleted')",
            name="ck_publisher_current_projection_lifecycle",
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
        sa.PrimaryKeyConstraint("record_id"),
        sa.UniqueConstraint("revision_id"),
    )
    op.create_index(
        "ix_publisher_current_projection_feed",
        "publisher_current_projections",
        ["distribution_tlp", "source_kind", "provider_key", "sequence"],
    )
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
            "last_served_sequence >= 0 AND last_completed_sequence >= 0 AND feed_epoch >= 1",
            name="ck_publisher_delivery_state_counts",
        ),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["publisher_installations.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("installation_id"),
    )
    op.create_table(
        "publisher_signing_keys",
        sa.Column("key_id", sa.String(length=120), nullable=False),
        sa.Column("public_key_base64", sa.String(length=128), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'retiring', 'retired')",
            name="ck_publisher_signing_key_status",
        ),
        sa.CheckConstraint(
            "length(fingerprint_sha256) = 64",
            name="ck_publisher_signing_key_fingerprint",
        ),
        sa.PrimaryKeyConstraint("key_id"),
        sa.UniqueConstraint("fingerprint_sha256"),
    )
    op.create_index(
        "ix_publisher_signing_key_status",
        "publisher_signing_keys",
        ["status", "not_before"],
    )

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.alter_column(
            "publisher_changes",
            "sequence",
            existing_type=sa.Integer(),
            type_=sa.BigInteger(),
            existing_nullable=False,
        )
    _backfill(bind)
    _protect_history(bind.dialect.name)
    if bind.dialect.name == "postgresql":
        op.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles "
            "WHERE rolname = 'publisher_feed_api') THEN "
            "GRANT INSERT ON publisher_audit_events TO publisher_feed_api; "
            "END IF; END $$"
        )


def _backfill(bind: sa.Connection) -> None:
    now = bind.scalar(sa.text("SELECT CURRENT_TIMESTAMP"))
    clients = list(
        bind.execute(
            sa.text(
                "SELECT client_id, name, api_key_sha256, token_version, enabled, max_tlp, "
                "allowed_providers, allowed_source_kinds, created_at, updated_at, last_seen_at "
                "FROM publisher_clients"
            )
        ).mappings()
    )
    for client in clients:
        account_id = uuid4()
        installation_id = uuid4()
        bind.execute(
            sa.text(
                "INSERT INTO publisher_accounts "
                "(id, account_key, name, enabled, created_at, updated_at) "
                "VALUES (:id, :key, :name, :enabled, :created, :updated)"
            ),
            {
                "id": account_id,
                "key": client["client_id"],
                "name": client["name"],
                "enabled": client["enabled"],
                "created": client["created_at"],
                "updated": client["updated_at"],
            },
        )
        bind.execute(
            sa.text(
                "INSERT INTO publisher_installations "
                "(id, account_id, client_id, name, enabled, max_tlp, entitlement_epoch, "
                "reset_generation, created_at, updated_at, last_seen_at) VALUES "
                "(:id, :account, :client, :name, :enabled, :tlp, 1, 1, :created, :updated, :seen)"
            ),
            {
                "id": installation_id,
                "account": account_id,
                "client": client["client_id"],
                "name": client["name"],
                "enabled": client["enabled"],
                "tlp": client["max_tlp"],
                "created": client["created_at"],
                "updated": client["updated_at"],
                "seen": client["last_seen_at"],
            },
        )
        bind.execute(
            sa.text(
                "INSERT INTO publisher_client_credentials "
                "(id, installation_id, key_sha256, token_version, not_before, expires_at, "
                "revoked_at, created_by, created_at) VALUES "
                "(:id, :installation, :key, :version, :not_before, NULL, NULL, :actor, :created)"
            ),
            {
                "id": uuid4(),
                "installation": installation_id,
                "key": client["api_key_sha256"],
                "version": client["token_version"],
                "not_before": client["created_at"],
                "actor": "migration:p2c7f4a8d920",
                "created": client["created_at"],
            },
        )
        providers = client["allowed_providers"] or []
        source_kinds = client["allowed_source_kinds"] or []
        if isinstance(providers, str):
            import json

            providers = json.loads(providers)
        if isinstance(source_kinds, str):
            import json

            source_kinds = json.loads(source_kinds)
        for scope_type, values in (
            ("provider", providers),
            ("source_kind", source_kinds),
        ):
            for value in values:
                bind.execute(
                    sa.text(
                        "INSERT INTO publisher_entitlements "
                        "(id, installation_id, scope_type, scope_value, created_at) "
                        "VALUES (:id, :installation, :type, :value, :created)"
                    ),
                    {
                        "id": uuid4(),
                        "installation": installation_id,
                        "type": scope_type,
                        "value": value.casefold() if scope_type == "provider" else value,
                        "created": now,
                    },
                )

    latest: dict[object, dict[str, object]] = {}
    for row in bind.execute(
        sa.text(
            "SELECT sequence, record_id, revision_id, projection, provider, provider_key, "
            "external_id, source_kind, record_type, distribution_tlp, lifecycle_status, "
            "status_changed_at, status_reason, canonical_record, published_at "
            "FROM publisher_changes ORDER BY sequence"
        )
    ).mappings():
        if row["projection"] == "canonical":
            latest[row["record_id"]] = dict(row)
        else:
            latest.pop(row["record_id"], None)
    for row in latest.values():
        bind.execute(
            sa.text(
                "INSERT INTO publisher_current_projections "
                "(record_id, revision_id, sequence, provider, provider_key, external_id, "
                "source_kind, record_type, distribution_tlp, lifecycle_status, "
                "status_changed_at, status_reason, canonical_record, updated_at) VALUES "
                "(:record_id, :revision_id, :sequence, :provider, :provider_key, :external_id, "
                ":source_kind, :record_type, :distribution_tlp, :lifecycle_status, "
                ":status_changed_at, :status_reason, :canonical_record, :updated_at)"
            ),
            {**row, "updated_at": row["published_at"]},
        )


def _protect_history(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute(
            """
            CREATE FUNCTION traceless_publisher_reject_history_delete()
            RETURNS trigger LANGUAGE plpgsql
            SET search_path = pg_catalog, pg_temp
            AS $$ BEGIN
                RAISE EXCEPTION 'publisher history is append-only' USING ERRCODE = '55000';
            END $$
            """
        )
        for table in ("publisher_records", "publisher_revisions", "publisher_changes"):
            op.execute(
                f"CREATE TRIGGER traceless_publisher_no_delete_{table} "
                f"BEFORE DELETE ON {table} FOR EACH ROW "
                "EXECUTE FUNCTION traceless_publisher_reject_history_delete()"
            )
    elif dialect == "sqlite":
        for table in ("publisher_records", "publisher_revisions", "publisher_changes"):
            op.execute(
                f"CREATE TRIGGER traceless_publisher_no_delete_{table} "
                f"BEFORE DELETE ON {table} BEGIN "
                "SELECT RAISE(ABORT, 'publisher history is append-only'); END"
            )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("publisher_records", "publisher_revisions", "publisher_changes"):
            op.execute(
                f"DROP TRIGGER IF EXISTS traceless_publisher_no_delete_{table} ON {table}"
            )
        op.execute("DROP FUNCTION IF EXISTS traceless_publisher_reject_history_delete()")
    elif bind.dialect.name == "sqlite":
        for table in ("publisher_records", "publisher_revisions", "publisher_changes"):
            op.execute(f"DROP TRIGGER IF EXISTS traceless_publisher_no_delete_{table}")

    op.drop_index("ix_publisher_signing_key_status", table_name="publisher_signing_keys")
    op.drop_table("publisher_signing_keys")
    op.drop_table("publisher_delivery_state")
    op.drop_index(
        "ix_publisher_current_projection_feed",
        table_name="publisher_current_projections",
    )
    op.drop_table("publisher_current_projections")
    op.drop_index(
        "ix_publisher_decision_record_created",
        table_name="publisher_publication_decisions",
    )
    op.drop_table("publisher_publication_decisions")
    op.drop_index("ix_publisher_import_run_created", table_name="publisher_import_runs")
    op.drop_table("publisher_import_runs")
    op.drop_index("ix_publisher_entitlement_lookup", table_name="publisher_entitlements")
    op.drop_table("publisher_entitlements")
    op.drop_index(
        "ix_publisher_credential_installation_active",
        table_name="publisher_client_credentials",
    )
    op.drop_table("publisher_client_credentials")
    op.drop_index(
        "ix_publisher_installation_account",
        table_name="publisher_installations",
    )
    op.drop_table("publisher_installations")
    op.drop_index("ix_publisher_account_enabled", table_name="publisher_accounts")
    op.drop_table("publisher_accounts")
    if bind.dialect.name == "postgresql":
        op.alter_column(
            "publisher_changes",
            "sequence",
            existing_type=sa.BigInteger(),
            type_=sa.Integer(),
            existing_nullable=False,
        )
