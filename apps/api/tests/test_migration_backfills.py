from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, Table, create_engine, insert, select

F2_REVISION = "f2c91e7a4d30"
E4_REVISION = "e4b7a2c93f10"
MIGRATION_ACTOR = f"migration:{E4_REVISION}"


def _config(api_root: Path) -> Config:
    return Config(str(api_root / "alembic.ini"))


def _tables(engine: object, *names: str) -> dict[str, Table]:
    metadata = MetaData()
    metadata.reflect(bind=engine, only=names)
    return {name: metadata.tables[name] for name in names}


def _seed_legacy_rows(database_url: str) -> dict[str, str]:
    engine = create_engine(database_url)
    tables = _tables(
        engine,
        "organizations",
        "projects",
        "systems_operational",
        "scan_authorizations",
        "scan_jobs",
        "assets",
        "asset_observations",
        "services",
        "findings_operational",
        "threats_operational",
        "risks_operational",
        "global_intel_records",
    )
    ids = {name: uuid4().hex for name in (
        "project",
        "system",
        "authorization",
        "current_scan",
        "old_scan",
        "current_asset",
        "stale_asset",
        "unobserved_asset",
        "unsupported_asset",
        "historical_service",
        "current_service",
        "missing_endpoint_service",
        "current_finding",
        "missing_endpoint_finding",
        "stale_finding",
        "unobserved_finding",
        "hostless_finding",
        "current_threat",
        "stale_threat",
        "unknown_threat",
        "unsupported_threat",
    )}
    now = datetime.now(UTC).replace(microsecond=0)
    with engine.begin() as connection:
        organization_id = connection.scalar(select(tables["organizations"].c.id))
        assert organization_id is not None
        connection.execute(
            insert(tables["projects"]),
            {
                "id": ids["project"],
                "organization_id": organization_id,
                "name": "Migration test",
                "description": "",
                "created_at": now,
                "updated_at": now,
            },
        )
        connection.execute(
            insert(tables["systems_operational"]),
            {
                "id": ids["system"],
                "project_id": ids["project"],
                "name": "Legacy system",
                "description": "",
                "owner": "migration-test",
                "criticality": "high",
                "created_at": now,
                "updated_at": now,
            },
        )
        connection.execute(
            insert(tables["scan_authorizations"]),
            {
                "id": ids["authorization"],
                "system_id": ids["system"],
                "targets": ["192.0.2.0/24"],
                "profile": "service_inventory",
                "approved_by": "migration-test",
                "purpose": "migration test",
                "expires_at": now + timedelta(days=1),
                "scope_sha256": "1" * 64,
                "status": "active",
                "created_at": now,
            },
        )
        for scan_id, is_current, observed_at in (
            (ids["old_scan"], False, now - timedelta(days=2)),
            (ids["current_scan"], True, now - timedelta(days=1)),
        ):
            connection.execute(
                insert(tables["scan_jobs"]),
                {
                    "id": scan_id,
                    "system_id": ids["system"],
                    "authorization_id": ids["authorization"],
                    "scanner": "nmap",
                    "mode": "import",
                    "status": "completed",
                    "requested_at": observed_at,
                    "started_at": observed_at,
                    "completed_at": observed_at,
                    "raw_evidence_sha256": "2" * 64,
                    "result_summary": {},
                    "attempt_count": 1,
                    "max_attempts": 3,
                    "source_observed_at": observed_at,
                    "source_time_status": "trusted",
                    "scope_targets": ["192.0.2.0/24"],
                    "scope_sha256": "1" * 64,
                    "scan_profile": "service_inventory",
                    "completeness": "complete",
                    "inventory_role": "authoritative" if is_current else "historical",
                    "is_current_inventory": is_current,
                },
            )

        asset_specs = (
            ("current_asset", "current", ids["current_scan"], "192.0.2.10"),
            ("stale_asset", "stale", ids["old_scan"], "192.0.2.11"),
            ("unobserved_asset", "unobserved", ids["old_scan"], "192.0.2.12"),
            ("unsupported_asset", "current", ids["old_scan"], "192.0.2.13"),
        )
        for key, status, scan_id, primary_ip in asset_specs:
            connection.execute(
                insert(tables["assets"]),
                {
                    "id": ids[key],
                    "system_id": ids["system"],
                    "source_scan_id": scan_id,
                    "stable_key": key,
                    "primary_ip": primary_ip,
                    "state": "up",
                    "first_seen_at": now - timedelta(days=2),
                    "last_seen_at": now - timedelta(days=1),
                    "observation_count": 1,
                    "inventory_status": status,
                },
            )
        for key, scan_key in (
            ("current_asset", "current_scan"),
            ("stale_asset", "old_scan"),
            ("unobserved_asset", "old_scan"),
            ("unsupported_asset", "old_scan"),
        ):
            connection.execute(
                insert(tables["asset_observations"]),
                {
                    "id": uuid4().hex,
                    "system_id": ids["system"],
                    "scan_job_id": ids[scan_key],
                    "asset_id": ids[key],
                    "observation_key": key.ljust(64, "0"),
                    "primary_ip": next(
                        spec[3] for spec in asset_specs if spec[0] == key
                    ),
                    "state": "up",
                    "observed_at": now - timedelta(days=1),
                    "created_at": now - timedelta(days=1),
                },
            )

        service_specs = (
            ("historical_service", "old_scan", 443, "open"),
            ("current_service", "current_scan", 443, "open"),
            ("missing_endpoint_service", "old_scan", 8443, "open"),
        )
        for key, scan_key, port, state in service_specs:
            connection.execute(
                insert(tables["services"]),
                {
                    "id": ids[key],
                    "asset_id": ids["current_asset"],
                    "scan_job_id": ids[scan_key],
                    "port": port,
                    "protocol": "tcp",
                    "state": state,
                    "service_name": "https",
                    "cpes": [],
                    "confidence": 1.0,
                },
            )

        valid_kev_source = {
            "provider": "cisa-kev",
            "source_version": "2026.07.20",
            "source_updated_at": (now - timedelta(hours=2)).isoformat(),
            "payload_sha256": "a" * 64,
        }
        ignored_sources = [
            {
                "provider": "cisa-kev",
                "source_version": "future",
                "source_updated_at": (now + timedelta(days=1)).isoformat(),
                "payload_sha256": "b" * 64,
            },
            {
                "provider": "nvd",
                "source_version": "2.0",
                "source_updated_at": (now - timedelta(hours=1)).isoformat(),
                "payload_sha256": "c" * 64,
                "queried_cpe": "cpe:2.3:a:example:app:1:*:*:*:*:*:*:*",
            },
            {
                "provider": "first-epss",
                "source_version": "2026-07-20",
                "model_date": "2026-07-20",
                "payload_sha256": "d" * 64,
            },
        ]
        finding_specs = (
            (
                "current_finding",
                "current_asset",
                "historical_service",
                [valid_kev_source, *ignored_sources],
            ),
            (
                "missing_endpoint_finding",
                "current_asset",
                "missing_endpoint_service",
                [],
            ),
            ("stale_finding", "stale_asset", None, []),
            ("unobserved_finding", "unobserved_asset", None, []),
            ("hostless_finding", None, None, []),
        )
        for key, asset_key, service_key, sources in finding_specs:
            connection.execute(
                insert(tables["findings_operational"]),
                {
                    "id": ids[key],
                    "system_id": ids["system"],
                    "scan_job_id": (
                        ids["old_scan"] if service_key else ids["current_scan"]
                    ) if asset_key else None,
                    "asset_id": ids[asset_key] if asset_key else None,
                    "service_id": ids[service_key] if service_key else None,
                    "stable_key": key,
                    "finding_type": "vulnerability",
                    "cve_id": "CVE-2099-0001",
                    "title": key,
                    "status": "candidate",
                    "lifecycle_status": "open",
                    "match_confidence": 0.8,
                    "match_reason": "migration test",
                    "is_kev": False,
                    "sources": sources,
                    "primary_evidence_strength": 10,
                    "first_seen_at": now,
                    "last_seen_at": now,
                    "status_updated_at": now,
                    "occurrence_count": 1,
                    "created_at": now,
                },
            )

        threat_specs = (
            (
                "current_threat",
                [str(UUID(hex=ids["current_asset"]))],
                {"matched_scan_id": str(UUID(hex=ids["current_scan"]))},
            ),
            (
                "stale_threat",
                [str(UUID(hex=ids["stale_asset"]))],
                {"matched_scan_id": str(UUID(hex=ids["old_scan"]))},
            ),
            ("unknown_threat", [str(UUID(hex=ids["current_asset"]))], {}),
            (
                "unsupported_threat",
                [str(UUID(hex=ids["unsupported_asset"]))],
                {"matched_scan_id": str(UUID(hex=ids["current_scan"]))},
            ),
        )
        for key, matched_asset_ids, provenance in threat_specs:
            connection.execute(
                insert(tables["threats_operational"]),
                {
                    "id": ids[key],
                    "system_id": ids["system"],
                    "source": "migration-test",
                    "external_id": key,
                    "title": key,
                    "description": key,
                    "severity": "high",
                    "confidence": 0.8,
                    "attack_patterns": [],
                    "affected_products": [],
                    "matched_asset_ids": matched_asset_ids,
                    "provenance": provenance,
                    "modified_at": now,
                    "ingested_at": now,
                },
            )

        risk_sources = [
            *(('finding', key) for key, _, _, _ in finding_specs),
            *(('threat', key) for key, _, _ in threat_specs),
        ]
        for source_kind, key in risk_sources:
            connection.execute(
                insert(tables["risks_operational"]),
                {
                    "id": uuid4().hex,
                    "system_id": ids["system"],
                    "finding_id": ids[key] if source_kind == "finding" else None,
                    "threat_id": ids[key] if source_kind == "threat" else None,
                    "title": key,
                    "likelihood": 3,
                    "impact": 4,
                    "score": 12,
                    "level": "high",
                    "status": "open",
                    "rationale": {},
                    "created_at": now,
                    "updated_at": now,
                },
            )

        marking_cases = {
            "white": ["TLP:WHITE"],
            "clear": ["tlp:clear"],
            "green": ["TLP:GREEN"],
            "amber": [],
            "strict": ["TLP:AMBER+STRICT"],
            "conflict": ["TLP:GREEN", "TLP:AMBER"],
            "red": ["TLP:RED"],
            "unknown": ["TLP:BLUE"],
        }
        for name, markings in marking_cases.items():
            connection.execute(
                insert(tables["global_intel_records"]),
                {
                    "id": uuid4().hex,
                    "organization_id": organization_id,
                    "source_kind": "external",
                    "provider": "migration-test",
                    "provider_key": "migration-test",
                    "external_id": name,
                    "record_type": "threat",
                    "title": name,
                    "summary": name,
                    "modified_at": now,
                    "retrieved_at": now,
                    "cve_ids": [],
                    "cpes": [],
                    "affected_products": [],
                    "mitre_attack_ids": [],
                    "indicators": [],
                    "tags": [],
                    "sectors": [],
                    "regions": [],
                    "markings": markings,
                    "revoked": False,
                    "raw_evidence": {},
                    "raw_sha256": "e" * 64,
                    "feed_id": "legacy-feed",
                    "feed_version": "1",
                    "feed_generated_at": now,
                    "first_ingested_at": now,
                    "last_ingested_at": now,
                },
            )
    return ids


def _assert_backfills(database_url: str, ids: dict[str, str]) -> None:
    engine = create_engine(database_url)
    tables = _tables(
        engine,
        "findings_operational",
        "risks_operational",
        "global_intel_records",
        "intelligence_sync_states",
    )
    with engine.connect() as connection:
        finding_statuses = {
            str(row.id): row.inventory_status
            for row in connection.execute(
                select(
                    tables["findings_operational"].c.id,
                    tables["findings_operational"].c.inventory_status,
                )
            ).mappings()
        }
        assert finding_statuses[str(ids["current_finding"])] == "current"
        assert (
            finding_statuses[str(ids["missing_endpoint_finding"])] == "unobserved"
        )
        assert finding_statuses[str(ids["stale_finding"])] == "stale"
        assert finding_statuses[str(ids["unobserved_finding"])] == "unobserved"
        assert finding_statuses[str(ids["hostless_finding"])] == "unknown"

        risk_statuses = {
            row.title: row.evidence_status
            for row in connection.execute(
                select(
                    tables["risks_operational"].c.title,
                    tables["risks_operational"].c.evidence_status,
                )
            ).mappings()
        }
        assert risk_statuses == {
            "current_finding": "current",
            "missing_endpoint_finding": "unobserved",
            "stale_finding": "stale",
            "unobserved_finding": "unobserved",
            "hostless_finding": "unknown",
            "current_threat": "current",
            "stale_threat": "stale",
            "unknown_threat": "unknown",
            "unsupported_threat": "stale",
        }

        policies = {
            row.external_id: row
            for row in connection.execute(
                select(tables["global_intel_records"])
            ).mappings()
        }
        assert {name: row.distribution_tlp for name, row in policies.items()} == {
            "white": "TLP:CLEAR",
            "clear": "TLP:CLEAR",
            "green": "TLP:GREEN",
            "amber": "TLP:AMBER",
            "strict": "TLP:AMBER+STRICT",
            "conflict": "TLP:AMBER",
            "red": "TLP:RED",
            "unknown": "TLP:RED",
        }
        assert all(row.reviewed_by == MIGRATION_ACTOR for row in policies.values())
        assert all(row.reviewed_at is not None for row in policies.values())
        assert policies["red"].review_status == "rejected"
        assert policies["unknown"].review_status == "rejected"
        assert all(
            row.review_status == "approved"
            for name, row in policies.items()
            if name not in {"red", "unknown"}
        )

        sync_states = list(
            connection.execute(select(tables["intelligence_sync_states"])).mappings()
        )
        assert len(sync_states) == 3
        state_by_provider = {row.provider: row for row in sync_states}
        assert state_by_provider["cisa-kev"].scope_key == "complete-catalog"
        assert state_by_provider["cisa-kev"].source_version == "2026.07.20"
        assert state_by_provider["cisa-kev"].payload_sha256 == "a" * 64
        assert state_by_provider["nvd"].scope_key == (
            "cpe:cpe:2.3:a:example:app:1:*:*:*:*:*:*:*"
        )
        assert state_by_provider["nvd"].source_version == "legacy-nvd-watermark"
        assert len(state_by_provider["nvd"].payload_sha256) == 64
        assert state_by_provider["first-epss"].scope_key == "cve:CVE-2099-0001"
        assert state_by_provider["first-epss"].source_version == (
            "legacy-first-epss-watermark"
        )
        assert len(state_by_provider["first-epss"].payload_sha256) == 64


def test_e4_migration_backfills_legacy_security_state_and_round_trips(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite+pysqlite:///{tmp_path / 'migration.db'}"
    monkeypatch.setenv("TRACELESS_DATABASE_URL", database_url)
    config = _config(api_root)

    command.upgrade(config, F2_REVISION)
    ids = _seed_legacy_rows(database_url)
    command.upgrade(config, E4_REVISION)
    _assert_backfills(database_url, ids)

    command.downgrade(config, F2_REVISION)
    command.upgrade(config, E4_REVISION)
    _assert_backfills(database_url, ids)
