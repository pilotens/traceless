"""add authoritative scan generations and immutable asset observations

Revision ID: f2c91e7a4d30
Revises: d7a4c9e61f20
Create Date: 2026-07-21 20:15:00.000000
"""

import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

revision: str = "f2c91e7a4d30"
down_revision: str | Sequence[str] | None = "d7a4c9e61f20"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan_jobs") as batch:
        batch.add_column(sa.Column("source_started_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("source_completed_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("source_observed_at", sa.DateTime(timezone=True)))
        batch.add_column(
            sa.Column(
                "source_time_status",
                sa.String(length=20),
                nullable=False,
                server_default="missing",
            )
        )
        batch.add_column(sa.Column("scope_targets", sa.JSON(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("scope_sha256", sa.String(length=64)))
        batch.add_column(
            sa.Column(
                "scan_profile",
                sa.String(length=40),
                nullable=False,
                server_default="unknown",
            )
        )
        batch.add_column(
            sa.Column(
                "completeness",
                sa.String(length=20),
                nullable=False,
                server_default="partial",
            )
        )
        batch.add_column(
            sa.Column(
                "inventory_role",
                sa.String(length=20),
                nullable=False,
                server_default="supplemental",
            )
        )
        batch.add_column(
            sa.Column(
                "is_current_inventory",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch.create_check_constraint(
            "ck_scan_source_time_status",
            "source_time_status IN ('trusted', 'missing', 'stale', 'quarantined')",
        )
        batch.create_check_constraint(
            "ck_scan_completeness",
            "completeness IN ('complete', 'partial', 'discovery')",
        )
        batch.create_check_constraint(
            "ck_scan_inventory_role",
            "inventory_role IN ('authoritative', 'supplemental', 'historical')",
        )
    op.create_index(
        "ix_scan_jobs_current_inventory",
        "scan_jobs",
        ["system_id", "is_current_inventory", "source_observed_at"],
        unique=False,
    )

    # Preserve only an eligible Nmap service-inventory generation as the
    # initial baseline. Discovery/Naabu/unknown legacy jobs are deliberately
    # left supplemental until a new authoritative scan is ingested.
    bind = op.get_bind()
    authorizations = sa.table(
        "scan_authorizations",
        sa.column("id", sa.Uuid()),
        sa.column("targets", sa.JSON()),
        sa.column("profile", sa.String()),
        sa.column("scope_sha256", sa.String()),
    )
    scans = sa.table(
        "scan_jobs",
        sa.column("id", sa.Uuid()),
        sa.column("system_id", sa.Uuid()),
        sa.column("authorization_id", sa.Uuid()),
        sa.column("scanner", sa.String()),
        sa.column("status", sa.String()),
        sa.column("completed_at", sa.DateTime(timezone=True)),
        sa.column("source_observed_at", sa.DateTime(timezone=True)),
        sa.column("scope_targets", sa.JSON()),
        sa.column("scope_sha256", sa.String()),
        sa.column("scan_profile", sa.String()),
        sa.column("completeness", sa.String()),
        sa.column("inventory_role", sa.String()),
        sa.column("is_current_inventory", sa.Boolean()),
    )
    authorization_rows = {row.id: row for row in bind.execute(sa.select(authorizations)).mappings()}
    scan_rows = list(bind.execute(sa.select(scans)).mappings())
    for scan in scan_rows:
        authorization = authorization_rows.get(scan["authorization_id"])
        values: dict[str, object] = {}
        if authorization is not None:
            values.update(
                scope_targets=authorization["targets"] or [],
                scope_sha256=authorization["scope_sha256"],
                scan_profile=authorization["profile"] or "unknown",
            )
            if authorization["profile"] == "discovery":
                values["completeness"] = "discovery"
        if scan["status"] == "completed":
            values["source_observed_at"] = scan["completed_at"]
        if values:
            bind.execute(sa.update(scans).where(scans.c.id == scan["id"]).values(**values))

    completed_by_system: dict[object, list[object]] = {}
    for scan in scan_rows:
        authorization = authorization_rows.get(scan["authorization_id"])
        if (
            scan["status"] == "completed"
            and str(scan["scanner"]).casefold() == "nmap"
            and authorization is not None
            and authorization["profile"] == "service_inventory"
        ):
            completed_by_system.setdefault(scan["system_id"], []).append(scan)
    for rows in completed_by_system.values():
        current = max(
            rows,
            key=lambda row: (
                row["completed_at"] is not None,
                row["completed_at"] or datetime.min.replace(tzinfo=UTC),
                str(row["id"]),
            ),
        )
        bind.execute(
            sa.update(scans)
            .where(scans.c.id == current["id"])
            .values(
                completeness="complete",
                inventory_role="authoritative",
                is_current_inventory=True,
            )
        )
    op.create_index(
        "ux_scan_jobs_one_current_inventory",
        "scan_jobs",
        ["system_id"],
        unique=True,
        postgresql_where=sa.text("is_current_inventory"),
        sqlite_where=sa.text("is_current_inventory = 1"),
    )

    with op.batch_alter_table("assets") as batch:
        batch.add_column(
            sa.Column(
                "inventory_status",
                sa.String(length=20),
                nullable=False,
                server_default="stale",
            )
        )
        batch.create_check_constraint(
            "ck_asset_inventory_status",
            "inventory_status IN ('current', 'unobserved', 'stale')",
        )
    op.execute(
        sa.text(
            "UPDATE assets SET inventory_status = 'current' WHERE source_scan_id IN "
            "(SELECT id FROM scan_jobs WHERE is_current_inventory = true)"
        )
    )

    op.create_table(
        "asset_aliases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("value_normalized", sa.String(length=500), nullable=False),
        sa.Column("value_display", sa.String(length=500), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["system_id"], ["systems_operational.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "system_id", "kind", "value_normalized", name="uq_asset_alias_system_kind_value"
        ),
        sa.CheckConstraint("kind IN ('ip', 'mac', 'hostname')", name="ck_asset_alias_kind"),
    )
    op.create_index("ix_asset_alias_asset", "asset_aliases", ["asset_id"], unique=False)

    op.create_table(
        "asset_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("observation_key", sa.String(length=64), nullable=False),
        sa.Column("primary_ip", sa.String(length=45), nullable=False),
        sa.Column("hostname", sa.String(length=255)),
        sa.Column("mac_address", sa.String(length=32)),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("os_family", sa.String(length=120)),
        sa.Column("os_accuracy", sa.Integer()),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["system_id"], ["systems_operational.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_job_id", "observation_key", name="uq_asset_observation_scan_key"),
    )
    op.create_index(
        "ix_asset_observations_system_observed",
        "asset_observations",
        ["system_id", "observed_at"],
        unique=False,
    )
    op.create_index(
        "ix_asset_observations_asset_observed",
        "asset_observations",
        ["asset_id", "observed_at"],
        unique=False,
    )

    # Backfill one immutable observation and the unambiguous aliases that can
    # be derived from each legacy asset. Conflicting aliases are deliberately
    # left for the runtime merge path instead of guessing in a migration.
    assets = sa.table(
        "assets",
        sa.column("id", sa.Uuid()),
        sa.column("system_id", sa.Uuid()),
        sa.column("source_scan_id", sa.Uuid()),
        sa.column("primary_ip", sa.String()),
        sa.column("hostname", sa.String()),
        sa.column("mac_address", sa.String()),
        sa.column("state", sa.String()),
        sa.column("os_family", sa.String()),
        sa.column("os_accuracy", sa.Integer()),
        sa.column("last_seen_at", sa.DateTime(timezone=True)),
    )
    aliases = sa.table(
        "asset_aliases",
        sa.column("id", sa.Uuid()),
        sa.column("system_id", sa.Uuid()),
        sa.column("asset_id", sa.Uuid()),
        sa.column("kind", sa.String()),
        sa.column("value_normalized", sa.String()),
        sa.column("value_display", sa.String()),
        sa.column("first_seen_at", sa.DateTime(timezone=True)),
        sa.column("last_seen_at", sa.DateTime(timezone=True)),
    )
    observations = sa.table(
        "asset_observations",
        sa.column("id", sa.Uuid()),
        sa.column("system_id", sa.Uuid()),
        sa.column("scan_job_id", sa.Uuid()),
        sa.column("asset_id", sa.Uuid()),
        sa.column("observation_key", sa.String()),
        sa.column("primary_ip", sa.String()),
        sa.column("hostname", sa.String()),
        sa.column("mac_address", sa.String()),
        sa.column("state", sa.String()),
        sa.column("os_family", sa.String()),
        sa.column("os_accuracy", sa.Integer()),
        sa.column("observed_at", sa.DateTime(timezone=True)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    seen_aliases: set[tuple[object, str, str]] = set()
    for asset in bind.execute(sa.select(assets).order_by(assets.c.last_seen_at.desc())).mappings():
        observed_at = asset["last_seen_at"] or datetime.now(UTC)
        alias_values = [
            ("ip", str(asset["primary_ip"]).casefold(), str(asset["primary_ip"])),
        ]
        if asset["mac_address"]:
            alias_values.append(
                (
                    "mac",
                    str(asset["mac_address"]).replace("-", ":").casefold(),
                    str(asset["mac_address"]),
                )
            )
        if asset["hostname"]:
            alias_values.append(
                (
                    "hostname",
                    str(asset["hostname"]).casefold().rstrip("."),
                    str(asset["hostname"]),
                )
            )
        for kind, normalized, display in alias_values:
            key = (asset["system_id"], kind, normalized)
            if key in seen_aliases:
                continue
            seen_aliases.add(key)
            bind.execute(
                sa.insert(aliases).values(
                    id=uuid4(),
                    system_id=asset["system_id"],
                    asset_id=asset["id"],
                    kind=kind,
                    value_normalized=normalized,
                    value_display=display,
                    first_seen_at=observed_at,
                    last_seen_at=observed_at,
                )
            )
        material = json.dumps(
            [
                str(asset["id"]),
                asset["primary_ip"],
                asset["hostname"],
                asset["mac_address"],
                asset["state"],
                asset["os_family"],
                asset["os_accuracy"],
            ],
            separators=(",", ":"),
        )
        bind.execute(
            sa.insert(observations).values(
                id=uuid4(),
                system_id=asset["system_id"],
                scan_job_id=asset["source_scan_id"],
                asset_id=asset["id"],
                observation_key=hashlib.sha256(material.encode()).hexdigest(),
                primary_ip=asset["primary_ip"],
                hostname=asset["hostname"],
                mac_address=asset["mac_address"],
                state=asset["state"],
                os_family=asset["os_family"],
                os_accuracy=asset["os_accuracy"],
                observed_at=observed_at,
                created_at=observed_at,
            )
        )


def downgrade() -> None:
    op.drop_index("ix_asset_observations_asset_observed", table_name="asset_observations")
    op.drop_index("ix_asset_observations_system_observed", table_name="asset_observations")
    op.drop_table("asset_observations")
    op.drop_index("ix_asset_alias_asset", table_name="asset_aliases")
    op.drop_table("asset_aliases")
    with op.batch_alter_table("assets") as batch:
        batch.drop_constraint("ck_asset_inventory_status", type_="check")
        batch.drop_column("inventory_status")
    op.execute(sa.text("DROP INDEX IF EXISTS ux_scan_jobs_one_current_inventory"))
    op.execute(sa.text("DROP INDEX IF EXISTS ix_scan_jobs_current_inventory"))
    with op.batch_alter_table("scan_jobs") as batch:
        batch.drop_constraint("ck_scan_inventory_role", type_="check")
        batch.drop_constraint("ck_scan_completeness", type_="check")
        batch.drop_constraint("ck_scan_source_time_status", type_="check")
        batch.drop_column("is_current_inventory")
        batch.drop_column("inventory_role")
        batch.drop_column("completeness")
        batch.drop_column("scan_profile")
        batch.drop_column("scope_sha256")
        batch.drop_column("scope_targets")
        batch.drop_column("source_time_status")
        batch.drop_column("source_observed_at")
        batch.drop_column("source_completed_at")
        batch.drop_column("source_started_at")
