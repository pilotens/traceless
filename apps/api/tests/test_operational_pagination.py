"""High-cardinality operational collections use compact, paginated contracts."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient

from traceless_api.core.tenancy import DEFAULT_ORGANIZATION_ID
from traceless_api.db.models import (
    AssetRow,
    FindingRow,
    RiskRow,
    ScanAuthorizationRow,
    ScanJobRow,
    ServiceRow,
    ThreatRow,
    VulnerabilityObservationRow,
    VulnerabilityScanImportRow,
)


def _system(client: TestClient) -> str:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Pagination", "description": "Collection contract tests"},
    )
    assert project.status_code == 201, project.text
    system = client.post(
        f"/api/v1/operational/projects/{project.json()['id']}/systems",
        json={
            "name": "Large system",
            "description": "Pagination test system",
            "owner": "Security",
            "criticality": "high",
        },
    )
    assert system.status_code == 201, system.text
    return system.json()["id"]


def _seed_collections(client: TestClient, system_id: str) -> tuple[str, str, str]:
    now = datetime.now(UTC)
    system_uuid = UUID(system_id)
    with client.app.state.session_factory() as session:
        finding = FindingRow(
            system_id=system_uuid,
            stable_key="finding-one",
            finding_type="misconfiguration",
            title="Verbose finding",
            status="candidate",
            lifecycle_status="open",
            match_confidence=0.95,
            match_reason="Exact source evidence",
            sources=[{"large": "evidence payload"}],
            primary_evidence_strength=95,
            first_seen_at=now,
            last_seen_at=now,
            status_updated_at=now,
        )
        session.add(finding)
        session.flush()
        risk = RiskRow(
            system_id=system_uuid,
            finding_id=finding.id,
            title="Verbose risk",
            likelihood=4,
            impact=4,
            score=16,
            level="high",
            status="open",
            rationale={"large": "risk rationale"},
        )
        imported = VulnerabilityScanImportRow(
            system_id=system_uuid,
            provider="generic",
            source_format="normalized-json",
            source_name="large.json",
            imported_by="test",
            raw_sha256="a" * 64,
            report_metadata={},
            observation_count=1,
            asset_count=1,
            matched_asset_count=0,
            promoted_finding_count=0,
        )
        session.add_all([risk, imported])
        session.flush()
        observation = VulnerabilityObservationRow(
            import_id=imported.id,
            system_id=system_uuid,
            observation_key="b" * 64,
            provider_finding_id="GEN-1",
            asset_identifier="host.example.test",
            title="Verbose observation",
            description="Large description loaded only on demand",
            solution="Large remediation loaded only on demand",
            severity="high",
            state="open",
            evidence={"large": "raw scanner evidence"},
        )
        session.add(observation)
        session.commit()
        return str(finding.id), str(risk.id), str(observation.id)


def _seed_inventory_and_threat(client: TestClient, system_id: str) -> tuple[str, str, str]:
    now = datetime.now(UTC)
    system_uuid = UUID(system_id)
    with client.app.state.session_factory() as session:
        authorization = ScanAuthorizationRow(
            system_id=system_uuid,
            targets=["100.64.0.10"],
            profile="service_inventory",
            approved_by="Security",
            purpose="Pagination tests",
            expires_at=now + timedelta(hours=1),
            scope_sha256="c" * 64,
            status="active",
        )
        session.add(authorization)
        session.flush()
        scan = ScanJobRow(
            organization_id=DEFAULT_ORGANIZATION_ID,
            system_id=system_uuid,
            authorization_id=authorization.id,
            scanner="nmap",
            mode="import",
            status="completed",
            completed_at=now,
            source_completed_at=now,
            source_observed_at=now,
            source_time_status="trusted",
            scope_targets=["100.64.0.10"],
            scope_sha256=authorization.scope_sha256,
            scan_profile="service_inventory",
            completeness="complete",
            inventory_role="authoritative",
            is_current_inventory=True,
        )
        session.add(scan)
        session.flush()
        asset = AssetRow(
            system_id=system_uuid,
            source_scan_id=scan.id,
            stable_key="asset-pagination",
            primary_ip="100.64.0.10",
            inventory_status="current",
        )
        other_asset = AssetRow(
            system_id=system_uuid,
            source_scan_id=scan.id,
            stable_key="asset-pagination-other",
            primary_ip="100.64.0.11",
            inventory_status="current",
        )
        session.add_all([asset, other_asset])
        session.flush()
        service = ServiceRow(
            asset_id=asset.id,
            scan_job_id=scan.id,
            port=443,
            protocol="tcp",
            state="open",
            service_name="https",
            confidence=0.98,
        )
        other_service = ServiceRow(
            asset_id=other_asset.id,
            scan_job_id=scan.id,
            port=8443,
            protocol="tcp",
            state="open",
            service_name="https-alt",
            confidence=0.90,
        )
        threat = ThreatRow(
            system_id=system_uuid,
            source="external-test",
            external_id="threat-pagination",
            title="Paginated threat",
            description="Large threat detail loaded only on demand",
            severity="high",
            confidence=0.85,
            attack_patterns=["T1190"],
            affected_products=["Gateway"],
            matched_asset_ids=[str(asset.id)],
            provenance={"large": "threat provenance", "matched_scan_id": str(scan.id)},
            modified_at=now,
        )
        session.add_all([service, other_service, threat])
        session.commit()
        return str(asset.id), str(service.id), str(threat.id)


def test_paginated_summaries_omit_large_detail_fields(client: TestClient) -> None:
    system_id = _system(client)
    finding_id, risk_id, observation_id = _seed_collections(client, system_id)

    findings = client.get(
        f"/api/v1/operational/systems/{system_id}/findings",
        params={
            "limit": 1,
            "offset": 0,
            "lifecycle_status": "open",
            "needs_review": True,
        },
    )
    risks = client.get(
        f"/api/v1/operational/systems/{system_id}/risks",
        params={"limit": 1, "status": "open"},
    )
    observations = client.get(
        f"/api/v1/operational/systems/{system_id}/vulnerability-observations/page",
        params={"limit": 1},
    )

    assert findings.status_code == 200, findings.text
    assert findings.json()["total"] == 1
    assert findings.json()["has_more"] is False
    assert findings.json()["items"][0]["id"] == finding_id
    assert "sources" not in findings.json()["items"][0]
    assert risks.json()["items"][0]["id"] == risk_id
    assert "rationale" not in risks.json()["items"][0]
    assert observations.json()["items"][0]["id"] == observation_id
    assert "evidence" not in observations.json()["items"][0]
    assert "description" not in observations.json()["items"][0]


def test_collection_details_are_loaded_on_demand(client: TestClient) -> None:
    system_id = _system(client)
    finding_id, risk_id, observation_id = _seed_collections(client, system_id)

    finding = client.get(f"/api/v1/operational/systems/{system_id}/findings/{finding_id}")
    risk = client.get(f"/api/v1/operational/systems/{system_id}/risks/{risk_id}")
    observation = client.get(
        f"/api/v1/operational/systems/{system_id}/vulnerability-observations/{observation_id}"
    )

    assert finding.json()["sources"] == [{"large": "evidence payload"}]
    assert risk.json()["rationale"] == {"large": "risk rationale"}
    assert observation.json()["evidence"] == {"large": "raw scanner evidence"}
    assert observation.json()["description"].startswith("Large description")


def test_inventory_and_threat_collections_are_bounded(client: TestClient) -> None:
    system_id = _system(client)
    asset_id, service_id, threat_id = _seed_inventory_and_threat(client, system_id)

    assets = client.get(
        f"/api/v1/operational/systems/{system_id}/assets/page",
        params={"limit": 1},
    )
    all_services = client.get(
        f"/api/v1/operational/systems/{system_id}/services/page",
        params={"limit": 1},
    )
    asset_services = client.get(
        f"/api/v1/operational/systems/{system_id}/services/page",
        params={"asset_id": asset_id, "limit": 1},
    )
    threats = client.get(
        f"/api/v1/operational/systems/{system_id}/threats",
        params={"limit": 1},
    )
    threat = client.get(f"/api/v1/operational/systems/{system_id}/threats/{threat_id}")

    assert assets.status_code == 200, assets.text
    assert assets.json()["items"][0]["id"] == asset_id
    assert all_services.json()["total"] == 2
    assert all_services.json()["has_more"] is True
    assert asset_services.json()["items"][0]["id"] == service_id
    assert asset_services.json()["total"] == 1
    assert asset_services.json()["has_more"] is False
    assert threats.json()["items"][0]["id"] == threat_id
    assert "provenance" not in threats.json()["items"][0]
    assert threat.json()["provenance"]["large"] == "threat provenance"
    assert UUID(threat.json()["provenance"]["matched_scan_id"])


def test_page_validation_and_empty_offsets(client: TestClient) -> None:
    system_id = _system(client)
    _seed_collections(client, system_id)

    invalid = client.get(f"/api/v1/operational/systems/{system_id}/findings", params={"limit": 201})
    invalid_risk_status = client.get(
        f"/api/v1/operational/systems/{system_id}/risks",
        params={"status": "not-a-risk-state"},
    )
    empty = client.get(
        f"/api/v1/operational/systems/{system_id}/findings",
        params={"limit": 10, "offset": 100},
    )

    assert invalid.status_code == 422
    assert invalid_risk_status.status_code == 422
    assert empty.json() == {
        "items": [],
        "total": 1,
        "limit": 10,
        "offset": 100,
        "has_more": False,
    }
