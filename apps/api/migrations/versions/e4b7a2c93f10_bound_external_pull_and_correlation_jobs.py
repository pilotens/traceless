"""bound external pull quotas and add correlation jobs

Revision ID: e4b7a2c93f10
Revises: f2c91e7a4d30
Create Date: 2026-07-21 21:10:00.000000
"""

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

revision: str = "e4b7a2c93f10"
down_revision: str | Sequence[str] | None = "f2c91e7a4d30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MIGRATION_ACTOR = "migration:e4b7a2c93f10"
_TLP_RESTRICTIVENESS = {
    "TLP:CLEAR": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}
_TLP_ALIASES = {
    "TLP:WHITE": "TLP:CLEAR",
    **{value: value for value in _TLP_RESTRICTIVENESS},
}


def _legacy_tlp(markings: object) -> str:
    """Derive one safe TLP label without trusting malformed legacy JSON."""

    if not isinstance(markings, list):
        return "TLP:RED"
    labels: list[str] = []
    for raw_value in markings:
        if not isinstance(raw_value, str) or not raw_value.strip():
            return "TLP:RED"
        value = raw_value.strip().upper()
        if value.startswith("TLP:") and value not in _TLP_ALIASES:
            return "TLP:RED"
        canonical = _TLP_ALIASES.get(value)
        if canonical is not None:
            labels.append(canonical)
    # Unmarked legacy intelligence stays inside its authenticated organization.
    return max(
        labels,
        key=_TLP_RESTRICTIVENESS.__getitem__,
        default="TLP:AMBER",
    )


def _as_aware_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _backfill_inventory_statuses(bind: sa.Connection) -> None:
    assets = sa.table(
        "assets",
        sa.column("id", sa.Uuid()),
        sa.column("system_id", sa.Uuid()),
        sa.column("inventory_status", sa.String()),
    )
    scans = sa.table(
        "scan_jobs",
        sa.column("id", sa.Uuid()),
        sa.column("system_id", sa.Uuid()),
        sa.column("is_current_inventory", sa.Boolean()),
    )
    observations = sa.table(
        "asset_observations",
        sa.column("scan_job_id", sa.Uuid()),
        sa.column("asset_id", sa.Uuid()),
    )
    services = sa.table(
        "services",
        sa.column("id", sa.Uuid()),
        sa.column("asset_id", sa.Uuid()),
        sa.column("scan_job_id", sa.Uuid()),
        sa.column("port", sa.Integer()),
        sa.column("protocol", sa.String()),
        sa.column("state", sa.String()),
    )
    findings = sa.table(
        "findings_operational",
        sa.column("id", sa.Uuid()),
        sa.column("system_id", sa.Uuid()),
        sa.column("asset_id", sa.Uuid()),
        sa.column("service_id", sa.Uuid()),
        sa.column("inventory_status", sa.String()),
    )
    threats = sa.table(
        "threats_operational",
        sa.column("id", sa.Uuid()),
        sa.column("system_id", sa.Uuid()),
        sa.column("matched_asset_ids", sa.JSON()),
        sa.column("provenance", sa.JSON()),
    )
    risks = sa.table(
        "risks_operational",
        sa.column("id", sa.Uuid()),
        sa.column("system_id", sa.Uuid()),
        sa.column("finding_id", sa.Uuid()),
        sa.column("threat_id", sa.Uuid()),
        sa.column("evidence_status", sa.String()),
    )

    asset_statuses = {
        str(row.id): row.inventory_status
        for row in bind.execute(sa.select(assets)).mappings()
    }
    asset_systems = {
        str(row.id): str(row.system_id)
        for row in bind.execute(sa.select(assets)).mappings()
    }
    scan_rows = {
        str(row.id): row
        for row in bind.execute(sa.select(scans)).mappings()
    }
    observed_pairs = {
        (str(row.scan_job_id), str(row.asset_id))
        for row in bind.execute(sa.select(observations)).mappings()
    }
    service_rows = {
        str(row.id): row for row in bind.execute(sa.select(services)).mappings()
    }
    open_endpoints = {
        (
            str(row.scan_job_id),
            str(row.asset_id),
            row.port,
            str(row.protocol).casefold(),
        )
        for row in service_rows.values()
        if str(row.state).casefold() == "open"
    }
    current_scan_by_system = {
        str(row.system_id): str(row.id)
        for row in scan_rows.values()
        if row.is_current_inventory
    }
    finding_statuses: dict[str, str] = {}
    finding_systems: dict[str, str] = {}
    for row in bind.execute(sa.select(findings)).mappings():
        status = (
            asset_statuses.get(str(row.asset_id), "unknown")
            if row.asset_id is not None
            and asset_systems.get(str(row.asset_id)) == str(row.system_id)
            else "unknown"
        )
        if status == "current" and row.service_id is not None:
            service = service_rows.get(str(row.service_id))
            current_scan_id = current_scan_by_system.get(str(row.system_id))
            endpoint_is_current = bool(
                service is not None
                and str(service.asset_id) == str(row.asset_id)
                and current_scan_id is not None
                and (
                    current_scan_id,
                    str(service.asset_id),
                    service.port,
                    str(service.protocol).casefold(),
                )
                in open_endpoints
            )
            if not endpoint_is_current:
                status = "unobserved"
        finding_statuses[str(row.id)] = status
        finding_systems[str(row.id)] = str(row.system_id)
        bind.execute(
            sa.update(findings)
            .where(findings.c.id == row.id)
            .values(inventory_status=status)
        )

    threat_statuses: dict[str, str] = {}
    threat_systems: dict[str, str] = {}
    for row in bind.execute(sa.select(threats)).mappings():
        provenance = row.provenance if isinstance(row.provenance, dict) else {}
        raw_scan_id = provenance.get("matched_scan_id")
        matched_asset_ids = (
            row.matched_asset_ids if isinstance(row.matched_asset_ids, list) else []
        )
        scan_id = str(raw_scan_id) if raw_scan_id else None
        scan = scan_rows.get(scan_id) if scan_id is not None else None
        if scan_id is None or scan is None:
            status = "unknown"
        elif (
            str(scan.system_id) != str(row.system_id)
            or not scan.is_current_inventory
            or not matched_asset_ids
        ):
            status = "stale"
        else:
            supported = any(
                asset_statuses.get(str(asset_id)) == "current"
                and asset_systems.get(str(asset_id)) == str(row.system_id)
                and (scan_id, str(asset_id)) in observed_pairs
                for asset_id in matched_asset_ids
            )
            status = "current" if supported else "stale"
        threat_statuses[str(row.id)] = status
        threat_systems[str(row.id)] = str(row.system_id)

    for row in bind.execute(sa.select(risks)).mappings():
        if (
            row.finding_id is not None
            and finding_systems.get(str(row.finding_id)) == str(row.system_id)
        ):
            status = finding_statuses.get(str(row.finding_id), "unknown")
        elif (
            row.threat_id is not None
            and threat_systems.get(str(row.threat_id)) == str(row.system_id)
        ):
            status = threat_statuses.get(str(row.threat_id), "unknown")
        else:
            status = "unknown"
        bind.execute(
            sa.update(risks)
            .where(risks.c.id == row.id)
            .values(evidence_status=status)
        )


def _backfill_global_intelligence_policy(bind: sa.Connection) -> None:
    records = sa.table(
        "global_intel_records",
        sa.column("id", sa.Uuid()),
        sa.column("markings", sa.JSON()),
        sa.column("distribution_tlp", sa.String()),
        sa.column("review_status", sa.String()),
        sa.column("reviewed_by", sa.String()),
        sa.column("reviewed_at", sa.DateTime(timezone=True)),
        sa.column("review_note", sa.Text()),
    )
    now = datetime.now(UTC)
    for row in bind.execute(sa.select(records)).mappings():
        distribution_tlp = _legacy_tlp(row.markings)
        rejected = distribution_tlp == "TLP:RED"
        bind.execute(
            sa.update(records)
            .where(records.c.id == row.id)
            .values(
                distribution_tlp=distribution_tlp,
                review_status="rejected" if rejected else "approved",
                reviewed_by=_MIGRATION_ACTOR,
                reviewed_at=now,
                review_note=(
                    "Legacy TLP:RED record excluded from tenant-wide automation "
                    "during review-gate migration."
                    if rejected
                    else "Legacy record approved during review-gate migration; "
                    "it predated mandatory analyst review."
                ),
            )
        )


def _seed_safe_legacy_sync_states(bind: sa.Connection) -> None:
    """Fence legacy provider revisions without inventing accepted content.

    KEV retains its exact full-catalogue hash. NVD and EPSS do not retain the
    new complete-snapshot/per-record manifest, so their migrated hashes are
    explicit sentinels. An older revision is rejected, an equal revision must
    be reviewed as a content conflict, and only a strictly newer provider
    revision may replace already-materialized legacy evidence.
    """

    findings = sa.table(
        "findings_operational",
        sa.column("system_id", sa.Uuid()),
        sa.column("cve_id", sa.String()),
        sa.column("sources", sa.JSON()),
    )
    sync_states = sa.table(
        "intelligence_sync_states",
        sa.column("id", sa.Uuid()),
        sa.column("system_id", sa.Uuid()),
        sa.column("provider", sa.String()),
        sa.column("scope_key", sa.String()),
        sa.column("source_updated_at", sa.DateTime(timezone=True)),
        sa.column("source_version", sa.String()),
        sa.column("payload_sha256", sa.String()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    now = datetime.now(UTC)
    future_cutoff = now + timedelta(minutes=5)
    candidates: dict[
        tuple[str, str, str],
        list[tuple[datetime, str, str, object]],
    ] = {}
    for row in bind.execute(sa.select(findings)).mappings():
        if not isinstance(row.sources, list):
            continue
        for source in row.sources:
            if not isinstance(source, dict):
                continue
            provider = source.get("provider")
            if provider not in {"cisa-kev", "nvd", "first-epss"}:
                continue
            raw_source_version = source.get("source_version")
            source_version = (
                raw_source_version
                if isinstance(raw_source_version, str)
                and raw_source_version
                and len(raw_source_version) <= 200
                else f"legacy-{provider}-watermark"
            )
            if provider == "cisa-kev":
                source_updated_at = _as_aware_datetime(
                    source.get("source_updated_at") or source.get("retrieved_at")
                )
                scope_key = "complete-catalog"
                payload_sha256 = source.get("payload_sha256")
                if (
                    not isinstance(payload_sha256, str)
                    or len(payload_sha256) != 64
                    or any(
                        character not in "0123456789abcdefABCDEF"
                        for character in payload_sha256
                    )
                ):
                    continue
                payload_sha256 = payload_sha256.lower()
            elif provider == "nvd":
                queried_cpe = source.get("queried_cpe")
                if not isinstance(queried_cpe, str) or not queried_cpe:
                    continue
                scope_key = f"cpe:{queried_cpe}"
                if len(scope_key) > 500:
                    continue
                timestamps = [
                    parsed
                    for raw_value in (
                        source.get("source_updated_at"),
                        source.get("retrieved_at"),
                    )
                    if (parsed := _as_aware_datetime(raw_value)) is not None
                ]
                source_updated_at = max(timestamps, default=None)
                source_version = "legacy-nvd-watermark"
                payload_sha256 = ""
            else:
                if not isinstance(row.cve_id, str) or not row.cve_id:
                    continue
                scope_key = f"cve:{row.cve_id}"
                source_updated_at = _as_aware_datetime(source.get("model_date"))
                source_version = "legacy-first-epss-watermark"
                payload_sha256 = ""
            if (
                source_updated_at is None
                or source_updated_at > future_cutoff
            ):
                continue
            if not payload_sha256:
                payload_sha256 = hashlib.sha256(
                    "\0".join(
                        (
                            "legacy-provider-watermark",
                            provider,
                            scope_key,
                            source_updated_at.isoformat(),
                        )
                    ).encode()
                ).hexdigest()
            candidate_key = (str(row.system_id), provider, scope_key)
            candidates.setdefault(candidate_key, []).append(
                (source_updated_at, source_version, payload_sha256, row.system_id)
            )

    for (_, provider, scope_key), system_candidates in candidates.items():
        latest_at = max(item[0] for item in system_candidates)
        latest = {
            (source_version, payload_sha256, system_id)
            for source_updated_at, source_version, payload_sha256, system_id in system_candidates
            if source_updated_at == latest_at
        }
        # Equal provider timestamps with different content cannot be ordered safely.
        if len(latest) != 1:
            continue
        source_version, payload_sha256, system_id = latest.pop()
        bind.execute(
            sa.insert(sync_states).values(
                id=uuid4(),
                system_id=system_id,
                provider=provider,
                scope_key=scope_key,
                source_updated_at=latest_at,
                source_version=source_version,
                payload_sha256=payload_sha256,
                created_at=now,
                updated_at=now,
            )
        )


def upgrade() -> None:
    op.create_table(
        "intelligence_sync_states",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("system_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=80), nullable=False),
        sa.Column("scope_key", sa.String(length=500), nullable=False),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_version", sa.String(length=200), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["system_id"], ["systems_operational.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "system_id",
            "provider",
            "scope_key",
            name="uq_intel_sync_state_scope",
        ),
    )
    op.create_index(
        "ix_intel_sync_state_system_provider",
        "intelligence_sync_states",
        ["system_id", "provider"],
        unique=False,
    )

    with op.batch_alter_table("findings_operational") as batch:
        batch.add_column(
            sa.Column(
                "inventory_status",
                sa.String(length=20),
                nullable=False,
                server_default="current",
            )
        )
        batch.create_check_constraint(
            "ck_finding_inventory_status",
            "inventory_status IN ('current', 'unobserved', 'stale', 'unknown')",
        )
    with op.batch_alter_table("risks_operational") as batch:
        batch.add_column(
            sa.Column(
                "evidence_status",
                sa.String(length=20),
                nullable=False,
                server_default="current",
            )
        )
        batch.create_check_constraint(
            "ck_risk_evidence_status",
            "evidence_status IN ('current', 'unobserved', 'stale', 'unknown')",
        )

    bind = op.get_bind()
    _backfill_inventory_statuses(bind)
    _seed_safe_legacy_sync_states(bind)
    with op.batch_alter_table("findings_operational") as batch:
        batch.alter_column("inventory_status", server_default=None)
    with op.batch_alter_table("risks_operational") as batch:
        batch.alter_column("evidence_status", server_default=None)

    with op.batch_alter_table("global_intel_records") as batch:
        batch.add_column(
            sa.Column(
                "distribution_tlp",
                sa.String(length=24),
                nullable=False,
                server_default="TLP:AMBER",
            )
        )
        batch.add_column(
            sa.Column(
                "review_status",
                sa.String(length=20),
                nullable=False,
                server_default="pending",
            )
        )
        batch.add_column(sa.Column("reviewed_by", sa.String(length=160)))
        batch.add_column(sa.Column("reviewed_at", sa.DateTime(timezone=True)))
        batch.add_column(sa.Column("review_note", sa.Text()))
        batch.create_check_constraint(
            "ck_global_intel_distribution_tlp",
            "distribution_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', "
            "'TLP:AMBER+STRICT', 'TLP:RED')",
        )
        batch.create_check_constraint(
            "ck_global_intel_review_status",
            "review_status IN ('pending', 'approved', 'rejected')",
        )
        batch.create_check_constraint(
            "ck_global_intel_review_state",
            "(review_status = 'pending' AND reviewed_by IS NULL AND reviewed_at IS NULL) OR "
            "(review_status IN ('approved', 'rejected') AND reviewed_by IS NOT NULL "
            "AND reviewed_at IS NOT NULL)",
        )
    _backfill_global_intelligence_policy(bind)
    with op.batch_alter_table("global_intel_records") as batch:
        batch.alter_column("distribution_tlp", server_default=None)
        batch.alter_column("review_status", server_default=None)
    op.create_index(
        "ix_global_intel_org_review",
        "global_intel_records",
        ["organization_id", "review_status", "modified_at"],
        unique=False,
    )
    op.create_index(
        "ix_global_intel_distribution_tlp",
        "global_intel_records",
        ["distribution_tlp"],
        unique=False,
    )

    with op.batch_alter_table("external_intelligence_sync_runs") as batch:
        batch.drop_constraint("ck_external_intel_sync_counts", type_="check")
        batch.add_column(
            sa.Column(
                "bytes_fetched",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch.add_column(
            sa.Column(
                "batch_bytes_fetched",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch.create_check_constraint(
            "ck_external_intel_sync_counts",
            "pages_fetched >= 0 AND records_fetched >= 0 AND created_count >= 0 "
            "AND bytes_fetched >= 0 AND batch_pages_fetched >= 0 "
            "AND batch_records_fetched >= 0 AND batch_bytes_fetched >= 0 "
            "AND updated_count >= 0 AND unchanged_count >= 0 "
            "AND quarantined_count >= 0",
        )
    with op.batch_alter_table("external_intelligence_sync_runs") as batch:
        batch.alter_column("bytes_fetched", server_default=None)
        batch.alter_column("batch_bytes_fetched", server_default=None)

    with op.batch_alter_table("external_intelligence_sync_pages") as batch:
        batch.add_column(
            sa.Column(
                "raw_payload_bytes",
                sa.Integer(),
                nullable=False,
                # Historical payload bodies were deliberately not retained.
                # One byte is an explicit unknown-size sentinel that preserves
                # checkpoint integrity; all new pages store the measured size.
                server_default="1",
            )
        )
        batch.create_check_constraint(
            "ck_external_intel_page_payload_bytes",
            "raw_payload_bytes >= 1",
        )
    with op.batch_alter_table("external_intelligence_sync_pages") as batch:
        batch.alter_column("raw_payload_bytes", server_default=None)

    with op.batch_alter_table("external_intelligence_checkpoints") as batch:
        batch.drop_constraint("ck_external_intel_checkpoint_counts", type_="check")
        batch.add_column(
            sa.Column(
                "bytes_completed",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )
    # Historical page sizes are represented by the same one-byte sentinel.
    op.execute(
        sa.text(
            "UPDATE external_intelligence_checkpoints "
            "SET bytes_completed = pages_completed"
        )
    )
    with op.batch_alter_table("external_intelligence_checkpoints") as batch:
        batch.create_check_constraint(
            "ck_external_intel_checkpoint_counts",
            "pages_completed >= 1 AND records_completed >= 0 "
            "AND bytes_completed >= 1",
        )
    with op.batch_alter_table("external_intelligence_checkpoints") as batch:
        batch.alter_column("bytes_completed", server_default=None)

    with op.batch_alter_table("background_jobs") as batch:
        batch.drop_constraint("ck_background_job_type", type_="check")
        batch.create_check_constraint(
            "ck_background_job_type",
            "job_type IN ('intelligence_correlation', "
            "'normalized_vulnerability_import', 'report_generation')",
        )


def downgrade() -> None:
    with op.batch_alter_table("risks_operational") as batch:
        batch.drop_constraint("ck_risk_evidence_status", type_="check")
        batch.drop_column("evidence_status")
    with op.batch_alter_table("findings_operational") as batch:
        batch.drop_constraint("ck_finding_inventory_status", type_="check")
        batch.drop_column("inventory_status")

    op.drop_index(
        "ix_intel_sync_state_system_provider",
        table_name="intelligence_sync_states",
    )
    op.drop_table("intelligence_sync_states")

    with op.batch_alter_table("background_jobs") as batch:
        batch.drop_constraint("ck_background_job_type", type_="check")
        batch.create_check_constraint(
            "ck_background_job_type",
            "job_type IN ('normalized_vulnerability_import', 'report_generation')",
        )

    with op.batch_alter_table("external_intelligence_checkpoints") as batch:
        batch.drop_constraint("ck_external_intel_checkpoint_counts", type_="check")
        batch.drop_column("bytes_completed")
        batch.create_check_constraint(
            "ck_external_intel_checkpoint_counts",
            "pages_completed >= 1 AND records_completed >= 0",
        )

    with op.batch_alter_table("external_intelligence_sync_pages") as batch:
        batch.drop_constraint("ck_external_intel_page_payload_bytes", type_="check")
        batch.drop_column("raw_payload_bytes")

    with op.batch_alter_table("external_intelligence_sync_runs") as batch:
        batch.drop_constraint("ck_external_intel_sync_counts", type_="check")
        batch.drop_column("batch_bytes_fetched")
        batch.drop_column("bytes_fetched")
        batch.create_check_constraint(
            "ck_external_intel_sync_counts",
            "pages_fetched >= 0 AND records_fetched >= 0 AND created_count >= 0 "
            "AND batch_pages_fetched >= 0 AND batch_records_fetched >= 0 "
            "AND updated_count >= 0 AND unchanged_count >= 0 "
            "AND quarantined_count >= 0",
        )

    op.drop_index(
        "ix_global_intel_distribution_tlp",
        table_name="global_intel_records",
    )
    op.drop_index(
        "ix_global_intel_org_review",
        table_name="global_intel_records",
    )
    with op.batch_alter_table("global_intel_records") as batch:
        batch.drop_constraint("ck_global_intel_review_state", type_="check")
        batch.drop_constraint("ck_global_intel_review_status", type_="check")
        batch.drop_constraint("ck_global_intel_distribution_tlp", type_="check")
        batch.drop_column("review_note")
        batch.drop_column("reviewed_at")
        batch.drop_column("reviewed_by")
        batch.drop_column("review_status")
        batch.drop_column("distribution_tlp")
