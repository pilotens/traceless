from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from traceless_api.db.models import FindingEvidenceRow, FindingRow, RiskRow
from traceless_api.models.operational import CveEnrichmentImport
from traceless_api.services.operational_repository import OperationalRepository

NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host><status state="up"/>
    <address addr="100.64.0.10" addrtype="ipv4"/>
    <hostnames><hostname name="payments.example.test" type="PTR"/></hostnames>
    <ports><port protocol="tcp" portid="443"><state state="open"/>
      <service name="https" product="Apache httpd" version="0.0.0">
        <cpe>cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*</cpe>
      </service>
    </port></ports>
  </host>
  <runstats><finished exit="success"/></runstats>
</nmaprun>"""

NMAP_WITHOUT_SERVICE_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host><status state="up"/>
    <address addr="100.64.0.10" addrtype="ipv4"/>
    <hostnames><hostname name="payments.example.test" type="PTR"/></hostnames>
    <ports></ports>
  </host>
  <runstats><finished exit="success"/></runstats>
</nmaprun>"""


def _create_system(client: TestClient) -> str:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Lifecycle project", "description": "Persistent security state"},
    ).json()
    response = client.post(
        f"/api/v1/operational/projects/{project['id']}/systems",
        json={
            "name": "Payment API",
            "description": "Lifecycle test",
            "owner": "Security Team",
            "criticality": "critical",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _import_nmap(
    client: TestClient,
    system_id: str,
    *,
    xml: bytes = NMAP_XML,
) -> dict[str, object]:
    authorization = client.post(
        f"/api/v1/operational/systems/{system_id}/scan-authorizations",
        json={
            "targets": ["100.64.0.10"],
            "profile": "service_inventory",
            "approved_by": "System owner",
            "purpose": "Authorized lifecycle inventory scan",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "confirmation": "Jag bekräftar att jag har tillstånd att skanna angivna mål.",
        },
    ).json()
    response = client.post(
        f"/api/v1/operational/systems/{system_id}/scans/import/nmap",
        params={"authorization_id": authorization["id"]},
        content=xml,
        headers={"Content-Type": "application/xml"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _vendor_import(
    client: TestClient,
    system_id: str,
    *,
    state: str,
    observed_at: str,
    provider_finding_id: str = "QID-12345",
    cve_ids: list[str] | None = None,
    title: str = "Authenticated scanner evidence",
    provider: str = "qualys",
    port: int = 443,
    cvss_score: float | None = None,
) -> dict[str, object]:
    response = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import",
        json={
            "provider": provider,
            "source_name": f"{provider}-{provider_finding_id}-{state}-{observed_at}.json",
            "scan_completed_at": observed_at,
            "observations": [
                {
                    "provider_finding_id": provider_finding_id,
                    "asset_identifier": "payments.example.test",
                    "ip_address": "100.64.0.10",
                    "hostname": "payments.example.test",
                    "port": port,
                    "protocol": "tcp",
                    "title": title,
                    "severity": "high",
                    "state": state,
                    "cve_ids": cve_ids or [],
                    "cvss_score": (
                        cvss_score if cvss_score is not None else (8.8 if cve_ids else None)
                    ),
                    "evidence": {"authenticated": True, "state": state},
                    "observed_at": observed_at,
                }
            ],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _manual_graph() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "publication_state": "draft",
        "zones": [],
        "nodes": [
            {
                "id": "node:manual-api",
                "name": "Curated payment API",
                "kind": "application",
                "position": {"x": 100, "y": 100},
                "properties": {"owner": "payments"},
            }
        ],
        "edges": [],
    }


def test_import_before_inventory_is_recorrelated_and_supports_non_cve_findings(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    imported = _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-18T10:00:00Z",
        cve_ids=["CVE-2099-12345"],
    )
    assert imported["promoted_findings"] == 0

    first_scan = _import_nmap(client, system_id)
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert len(overview["findings"]) == 1
    finding = overview["findings"][0]
    assert finding["cve_id"] == "CVE-2099-12345"
    assert finding["lifecycle_status"] == "open"
    assert finding["first_seen_at"] == "2026-07-18T10:00:00Z"
    assert finding["occurrence_count"] == 1
    first_finding_id = finding["id"]
    first_asset_id = overview["assets"][0]["id"]
    first_service_id = finding["service_id"]

    non_cve = _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-18T11:00:00Z",
        provider_finding_id="QID-TLS-001",
        title="Weak TLS configuration",
    )
    assert non_cve["promoted_findings"] == 1
    findings = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()[
        "findings"
    ]
    misconfiguration = next(item for item in findings if item["cve_id"] is None)
    assert misconfiguration["finding_type"] == "misconfiguration"

    second_scan = _import_nmap(client, system_id)
    refreshed = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    cve_finding = next(item for item in refreshed["findings"] if item["cve_id"])
    assert cve_finding["id"] == first_finding_id
    assert refreshed["assets"][0]["id"] == first_asset_id
    assert refreshed["assets"][0]["observation_count"] == 2
    assert cve_finding["scan_job_id"] == second_scan["id"]
    assert cve_finding["service_id"] != first_service_id
    assert first_scan["id"] != second_scan["id"]


def test_finding_fixed_reopened_and_analyst_decisions_drive_linked_risk(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-18T10:00:00Z",
        cve_ids=["CVE-2099-12345"],
    )
    initial = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    finding_id = initial["findings"][0]["id"]
    assert initial["risks"][0]["status"] == "open"

    _vendor_import(
        client,
        system_id,
        state="fixed",
        observed_at="2026-07-19T10:00:00Z",
        cve_ids=["CVE-2099-12345"],
    )
    fixed = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert fixed["findings"][0]["id"] == finding_id
    assert fixed["findings"][0]["lifecycle_status"] == "fixed"
    assert fixed["risks"][0]["status"] == "closed"

    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-20T10:00:00Z",
        cve_ids=["CVE-2099-12345"],
    )
    reopened = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert reopened["findings"][0]["lifecycle_status"] == "reopened"
    assert reopened["risks"][0]["status"] == "open"

    accepted = client.patch(
        f"/api/v1/operational/systems/{system_id}/findings/{finding_id}/lifecycle",
        json={"lifecycle_status": "accepted", "reason": "Approved temporary exception"},
        headers={"X-Actor": "risk-owner"},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["lifecycle_status"] == "accepted"
    assert accepted.json()["status"] == "confirmed"
    after_acceptance = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()
    assert after_acceptance["risks"][0]["status"] == "closed"

    reopened_by_analyst = client.patch(
        f"/api/v1/operational/systems/{system_id}/findings/{finding_id}/lifecycle",
        json={"lifecycle_status": "reopened", "reason": "Exception expired"},
        headers={"X-Actor": "risk-owner"},
    )
    assert reopened_by_analyst.status_code == 200
    analyst_reopened_at = datetime.fromisoformat(
        reopened_by_analyst.json()["status_updated_at"].replace("Z", "+00:00")
    )
    final = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert final["findings"][0]["lifecycle_status"] == "reopened"
    assert final["findings"][0]["status"] == "confirmed"
    assert final["risks"][0]["status"] == "open"

    _vendor_import(
        client,
        system_id,
        state="fixed",
        observed_at=(analyst_reopened_at + timedelta(seconds=1)).isoformat(),
        cve_ids=["CVE-2099-12345"],
    )
    reviewed = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()
    assert reviewed["findings"][0]["lifecycle_status"] == "fixed"
    assert reviewed["findings"][0]["status"] == "confirmed"
    assert reviewed["risks"][0]["status"] == "closed"
    evidence_response = client.get(
        f"/api/v1/operational/systems/{system_id}/findings/{finding_id}/evidence"
    )
    assert evidence_response.status_code == 200
    assert {item["source_kind"] for item in evidence_response.json()} == {
        "manual",
        "scanner",
    }

    with client.app.state.session_factory() as session:
        finding = session.get(FindingRow, UUID(finding_id))
        assert finding is not None
        assert finding.occurrence_count == 4
        assert session.scalar(
            select(func.count(FindingEvidenceRow.id)).where(
                FindingEvidenceRow.finding_id == finding.id
            )
        ) == 2
        risk = session.scalar(select(RiskRow).where(RiskRow.finding_id == finding.id))
        assert risk is not None and risk.closed_at is not None


def test_manual_fixed_survives_recorrelation_until_new_scanner_evidence(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    first_observed_at = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at=first_observed_at,
        cve_ids=["CVE-2099-12345"],
    )
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    finding_id = overview["findings"][0]["id"]

    fixed = client.patch(
        f"/api/v1/operational/systems/{system_id}/findings/{finding_id}/lifecycle",
        json={
            "lifecycle_status": "fixed",
            "reason": "Analyst verified the remediation",
        },
    )
    assert fixed.status_code == 200, fixed.text
    assert fixed.json()["lifecycle_status"] == "fixed"
    analyst_decision_at = datetime.fromisoformat(
        fixed.json()["status_updated_at"].replace("Z", "+00:00")
    )

    # A new inventory scan revisits the same immutable vendor observation. That
    # correlation pass is not new vulnerability evidence and must not reopen it.
    _import_nmap(client, system_id)
    after_recorrelation = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()
    assert after_recorrelation["findings"][0]["lifecycle_status"] == "fixed"
    assert after_recorrelation["risks"][0]["status"] == "closed"

    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at=(analyst_decision_at + timedelta(seconds=1)).isoformat(),
        cve_ids=["CVE-2099-12345"],
    )
    after_new_evidence = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()
    assert after_new_evidence["findings"][0]["lifecycle_status"] == "reopened"
    assert after_new_evidence["risks"][0]["status"] == "open"


def test_manual_reopen_survives_old_fixed_evidence_until_a_newer_scan(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    _vendor_import(
        client,
        system_id,
        state="fixed",
        observed_at=(datetime.now(UTC) - timedelta(hours=2)).isoformat(),
        cve_ids=["CVE-2099-12345"],
    )
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    finding_id = overview["findings"][0]["id"]
    reopened = client.patch(
        f"/api/v1/operational/systems/{system_id}/findings/{finding_id}/lifecycle",
        json={
            "lifecycle_status": "reopened",
            "reason": "Analyst found remaining exposure",
        },
        headers={"X-Actor": "reviewer-b"},
    )
    assert reopened.status_code == 200, reopened.text
    analyst_decision_at = datetime.fromisoformat(
        reopened.json()["status_updated_at"].replace("Z", "+00:00")
    )

    _import_nmap(client, system_id)
    after_recorrelation = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()
    assert after_recorrelation["findings"][0]["lifecycle_status"] == "reopened"
    assert after_recorrelation["risks"][0]["status"] == "open"

    _vendor_import(
        client,
        system_id,
        state="fixed",
        observed_at=(analyst_decision_at + timedelta(seconds=1)).isoformat(),
        cve_ids=["CVE-2099-12345"],
    )
    after_new_scan = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()
    assert after_new_scan["findings"][0]["lifecycle_status"] == "fixed"
    assert after_new_scan["risks"][0]["status"] == "closed"


def test_weaker_cpe_evidence_cannot_replace_authenticated_scanner_evidence(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-18T10:00:00Z",
        cve_ids=["CVE-2099-12345"],
        title="Authenticated scanner title",
    )
    payload = CveEnrichmentImport.model_validate(
        {
            "feed_name": "generic-cpe-feed",
            "feed_version": "1",
            "generated_at": "2026-07-20T12:00:00Z",
            "items": [
                {
                    "cve_id": "CVE-2099-12345",
                    "title": "Weaker CPE-only title",
                    "affected_cpes": [
                        "cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*"
                    ],
                    "cvss_score": 4.0,
                    "is_kev": False,
                    "source": "generic-feed",
                    "source_updated_at": "2026-07-20T12:00:00Z",
                }
            ],
        }
    )
    with client.app.state.session_factory() as session:
        matched, created = OperationalRepository(session).import_cve_enrichment(
            UUID(system_id), payload, "repository-test"
        )
        session.commit()
    assert (matched, created) == (1, 0)
    finding = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()[
        "findings"
    ][0]
    assert finding["title"] == "Authenticated scanner title"
    assert finding["cvss_score"] == 8.8
    assert finding["match_confidence"] == 0.99
    assert finding["primary_evidence_strength"] == 95
    assert {source.get("provider") for source in finding["sources"]} >= {
        "qualys",
        "cve-enrichment",
    }


def test_cve_requires_an_exact_current_service_endpoint(client: TestClient) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)

    imported = _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-18T10:00:00Z",
        cve_ids=["CVE-2099-84430"],
        port=8443,
    )

    assert imported["matched_assets"] == 1
    assert imported["matched_services"] == 0
    assert imported["promoted_findings"] == 0
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["findings"] == []
    assert overview["risks"] == []


def test_cve_evidence_tracks_exact_endpoint_across_inventory_changes(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-18T10:00:00Z",
        cve_ids=["CVE-2099-84431"],
    )

    _import_nmap(client, system_id, xml=NMAP_WITHOUT_SERVICE_XML)
    absent = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    finding = absent["findings"][0]
    assert finding["lifecycle_status"] == "open"
    assert finding["inventory_status"] == "unobserved"
    assert absent["risks"][0]["status"] == "open"
    assert absent["risks"][0]["evidence_status"] == "unobserved"
    assert absent["risks"][0]["rationale"]["context"]["reachable"] is None
    assert (
        absent["risks"][0]["rationale"]["context"]["provenance"][
            "current_endpoint_observed"
        ]
        is False
    )
    evidence = client.get(
        f"/api/v1/operational/systems/{system_id}/findings/{finding['id']}/evidence"
    ).json()[0]
    assert evidence["payload"]["correlation_resolution"]["reason"] == (
        "exact_endpoint_absent_from_current_inventory"
    )

    _import_nmap(client, system_id)
    restored = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert restored["findings"][0]["lifecycle_status"] == "open"
    assert restored["findings"][0]["inventory_status"] == "current"
    assert restored["risks"][0]["status"] == "open"


def test_scanner_sources_are_aggregated_and_cannot_set_analyst_states(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    cve_ids = ["CVE-2099-22222"]
    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-18T10:00:00Z",
        cve_ids=cve_ids,
        provider="qualys",
        provider_finding_id="QID-22222",
        title="Open Qualys evidence",
        cvss_score=5.0,
    )
    _vendor_import(
        client,
        system_id,
        state="fixed",
        observed_at="2026-07-18T11:00:00Z",
        cve_ids=cve_ids,
        provider="rapid7",
        provider_finding_id="R7-22222",
        title="Fixed Rapid7 evidence",
        cvss_score=9.8,
    )
    finding = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()[
        "findings"
    ][0]
    assert finding["lifecycle_status"] == "open"
    assert finding["title"] == "Open Qualys evidence"
    assert finding["cvss_score"] == 5.0
    assert finding["primary_evidence_strength"] == 95

    _vendor_import(
        client,
        system_id,
        state="fixed",
        observed_at="2026-07-18T12:00:00Z",
        cve_ids=cve_ids,
        provider="qualys",
        provider_finding_id="QID-22222",
    )
    finding = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()[
        "findings"
    ][0]
    assert finding["lifecycle_status"] == "fixed"

    _vendor_import(
        client,
        system_id,
        state="false_positive",
        observed_at="2026-07-18T13:00:00Z",
        cve_ids=cve_ids,
        provider="rapid7",
        provider_finding_id="R7-22222",
    )
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["findings"][0]["lifecycle_status"] == "reopened"
    assert overview["risks"][0]["status"] == "open"
    evidence = client.get(
        f"/api/v1/operational/systems/{system_id}/findings/{finding['id']}/evidence"
    ).json()
    scanner_states = {
        item["lifecycle_status"]
        for item in evidence
        if item["source_kind"] == "scanner"
    }
    assert scanner_states == {"open", "fixed"}
    assert len(evidence) == 2


def test_external_clocks_cannot_lock_lifecycle_or_degrade_current_metadata(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    cve_ids = ["CVE-2099-33333"]
    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-20T00:00:00Z",
        cve_ids=cve_ids,
        title="Current trusted scanner title",
        cvss_score=9.1,
    )
    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2099-01-01T00:00:00Z",
        cve_ids=cve_ids,
        title="Future-dated poisoned title",
        cvss_score=1.0,
    )
    _vendor_import(
        client,
        system_id,
        state="fixed",
        observed_at="2025-01-01T00:00:00Z",
        cve_ids=cve_ids,
        title="Stale report title",
        cvss_score=3.1,
    )

    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    finding = overview["findings"][0]
    assert finding["lifecycle_status"] == "open"
    assert finding["title"] == "Current trusted scanner title"
    assert finding["cvss_score"] == 9.1
    assert datetime.fromisoformat(finding["status_updated_at"].replace("Z", "+00:00")) < (
        datetime.now(UTC) + timedelta(minutes=1)
    )

    _vendor_import(
        client,
        system_id,
        state="fixed",
        observed_at="2026-07-20T12:00:00Z",
        cve_ids=cve_ids,
        title="Later legitimate fixed title",
        cvss_score=9.2,
    )
    closed = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    finding = closed["findings"][0]
    assert finding["lifecycle_status"] == "fixed"
    assert finding["title"] == "Later legitimate fixed title"
    assert finding["cvss_score"] == 9.2

    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-20T06:00:00Z",
        cve_ids=cve_ids,
        title="Historical reopen attempt",
        cvss_score=2.0,
    )
    still_closed = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()
    finding = still_closed["findings"][0]
    assert finding["lifecycle_status"] == "fixed"
    assert finding["title"] == "Later legitimate fixed title"

    _vendor_import(
        client,
        system_id,
        state="open",
        observed_at="2026-07-20T13:00:00Z",
        cve_ids=cve_ids,
        title="Newest legitimate scanner title",
        cvss_score=9.3,
    )
    final = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    finding = final["findings"][0]
    assert finding["lifecycle_status"] == "reopened"
    assert finding["title"] == "Newest legitimate scanner title"
    assert finding["cvss_score"] == 9.3
    evidence = client.get(
        f"/api/v1/operational/systems/{system_id}/findings/{finding['id']}/evidence"
    ).json()[0]
    assert evidence["payload"]["normalized_evidence"]["state"] == "open"
    assert evidence["payload"]["quarantined_revisions"][0]["reason"] == (
        "implausible_future_timestamp"
    )
    assert {
        revision["reason"]
        for revision in evidence["payload"]["superseded_revisions"]
    } == {"older_than_representative_evidence"}
    assert len(evidence["payload"]["superseded_revisions"]) == 2
    scanner_source = next(
        source for source in finding["sources"] if source["provider"] == "qualys"
    )
    assert scanner_source["timestamp_quarantined"] is False


def test_first_future_quarantined_fixed_observation_starts_open_not_reopened(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    _vendor_import(
        client,
        system_id,
        state="fixed",
        observed_at="2099-01-01T00:00:00Z",
        cve_ids=["CVE-2099-39999"],
        title="Future fixed state must be quarantined",
        cvss_score=8.0,
    )

    finding = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()["findings"][0]
    assert finding["lifecycle_status"] == "open"
    evidence = client.get(
        f"/api/v1/operational/systems/{system_id}/findings/{finding['id']}/evidence"
    ).json()[0]
    assert evidence["lifecycle_status"] == "open"
    assert evidence["payload"]["timestamp_quarantined"] is True


def _nessus_snapshot(
    *,
    name: str,
    completed: str,
    include_finding: bool,
    target_scope: str | None = "100.64.0.0/24",
    coverage_family: str | None = "Web Servers",
    include_host: bool = True,
) -> bytes:
    report_item = """
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="4"
        pluginID="999001" pluginName="Snapshot lifecycle vulnerability"
        pluginFamily="Web Servers">
        <cve>CVE-2099-44444</cve>
        <cvss3_base_score>9.8</cvss3_base_score>
        <description>Complete snapshot evidence.</description>
      </ReportItem>""" if include_finding else ""
    target_preference = (
        f"""<Preferences><ServerPreferences><preference>
      <name>TARGET</name><value>{target_scope}</value>
    </preference></ServerPreferences></Preferences>"""
        if target_scope is not None
        else ""
    )
    coverage = (
        f"""<FamilySelection><FamilyItem>
      <FamilyName>{coverage_family}</FamilyName><Status>enabled</Status>
    </FamilyItem></FamilySelection>"""
        if coverage_family is not None
        else ""
    )
    report_host = (
        f"""<ReportHost name="payments.example.test">
      <HostProperties>
        <tag name="host-ip">100.64.0.10</tag>
        <tag name="host-fqdn">payments.example.test</tag>
        <tag name="HOST_END">{completed}</tag>
      </HostProperties>{report_item}
    </ReportHost>"""
        if include_host
        else ""
    )
    return f"""<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>Complete scan</policyName>{target_preference}{coverage}</Policy>
  <Report name="{name}">
    {report_host}
  </Report>
</NessusClientData_v2>""".encode()


def test_complete_empty_nessus_snapshot_resolves_and_later_reopens(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    endpoint = f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/nessus"

    first = client.post(
        endpoint,
        params={"source_name": "snapshot-open.nessus"},
        content=_nessus_snapshot(
            name="payment-series", completed="Fri Jul 18 10:00:00 2026", include_finding=True
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert first.status_code == 201, first.text
    assert first.json()["promoted_findings"] == 1

    empty = client.post(
        endpoint,
        params={"source_name": "snapshot-empty.nessus"},
        content=_nessus_snapshot(
            name="payment-series", completed="Sat Jul 19 10:00:00 2026", include_finding=False
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert empty.status_code == 201, empty.text
    assert empty.json()["imported"] == 0
    resolved = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert resolved["findings"][0]["lifecycle_status"] == "fixed"
    assert resolved["risks"][0]["status"] == "closed"

    reopened = client.post(
        endpoint,
        params={"source_name": "snapshot-reopened.nessus"},
        content=_nessus_snapshot(
            name="payment-series", completed="Sun Jul 20 10:00:00 2026", include_finding=True
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert reopened.status_code == 201, reopened.text
    final = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert final["findings"][0]["lifecycle_status"] == "reopened"
    assert final["risks"][0]["status"] == "open"


def test_complete_nessus_snapshot_only_resolves_its_own_series(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    endpoint = f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/nessus"

    for target_scope, completed in (
        ("100.64.0.0/24", "Fri Jul 18 10:00:00 2026"),
        ("payments.example.test", "Fri Jul 18 11:00:00 2026"),
    ):
        response = client.post(
            endpoint,
            params={"source_name": f"{target_scope}.nessus"},
            content=_nessus_snapshot(
                name="shared-report-name",
                completed=completed,
                include_finding=True,
                target_scope=target_scope,
            ),
            headers={"Content-Type": "application/xml"},
        )
        assert response.status_code == 201, response.text

    empty_a = client.post(
        endpoint,
        params={"source_name": "scope-a-empty.nessus"},
        content=_nessus_snapshot(
            name="shared-report-name",
            completed="Sat Jul 19 10:00:00 2026",
            include_finding=False,
            target_scope="100.64.0.0/24",
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert empty_a.status_code == 201, empty_a.text

    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    finding = overview["findings"][0]
    assert finding["lifecycle_status"] == "open"
    evidence = client.get(
        f"/api/v1/operational/systems/{system_id}/findings/{finding['id']}/evidence"
    ).json()
    assert len(evidence) == 2
    assert {item["lifecycle_status"] for item in evidence} == {"open", "fixed"}
    assert len({item["payload"]["snapshot_series_id"] for item in evidence}) == 2


def test_ambiguous_nessus_scope_never_resolves_by_absence(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    endpoint = f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/nessus"

    opened = client.post(
        endpoint,
        params={"source_name": "ambiguous-open.nessus"},
        content=_nessus_snapshot(
            name="common-name",
            completed="Fri Jul 18 10:00:00 2026",
            include_finding=True,
            target_scope=None,
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert opened.status_code == 201, opened.text

    empty = client.post(
        endpoint,
        params={"source_name": "ambiguous-empty.nessus"},
        content=_nessus_snapshot(
            name="common-name",
            completed="Sat Jul 19 10:00:00 2026",
            include_finding=False,
            target_scope=None,
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert empty.status_code == 201, empty.text
    assert empty.json()["imported"] == 0

    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["findings"][0]["lifecycle_status"] == "open"
    imports = client.get(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans"
    ).json()
    assert imports[0]["report_metadata"]["snapshot_scope_status"] == "ambiguous"
    assert imports[0]["report_metadata"]["snapshot_complete"] is False
    assert "snapshot_series_id" not in imports[0]["report_metadata"]


def test_nessus_absence_requires_same_coverage_fingerprint(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    endpoint = f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/nessus"

    opened = client.post(
        endpoint,
        params={"source_name": "web-open.nessus"},
        content=_nessus_snapshot(
            name="common-name",
            completed="Sun Jul 20 10:00:00 2026",
            include_finding=True,
            coverage_family="Web Servers",
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert opened.status_code == 201, opened.text

    different_coverage = client.post(
        endpoint,
        params={"source_name": "database-empty.nessus"},
        content=_nessus_snapshot(
            name="common-name",
            completed="Mon Jul 21 10:00:00 2026",
            include_finding=False,
            coverage_family="Databases",
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert different_coverage.status_code == 201, different_coverage.text
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["findings"][0]["lifecycle_status"] == "open"

    same_coverage = client.post(
        endpoint,
        params={"source_name": "web-empty.nessus"},
        content=_nessus_snapshot(
            name="common-name",
            completed="Mon Jul 21 11:00:00 2026",
            include_finding=False,
            coverage_family="Web Servers",
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert same_coverage.status_code == 201, same_coverage.text
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["findings"][0]["lifecycle_status"] == "fixed"


def test_nessus_absence_requires_newer_trustworthy_completion_time(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    endpoint = f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/nessus"

    opened = client.post(
        endpoint,
        params={"source_name": "current-open.nessus"},
        content=_nessus_snapshot(
            name="ordered-series",
            completed="Mon Jul 20 10:00:00 2026",
            include_finding=True,
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert opened.status_code == 201, opened.text

    for source_name, report in (
        (
            "older-empty.nessus",
            _nessus_snapshot(
                name="ordered-series",
                completed="Sun Jul 19 10:00:00 2026",
                include_finding=False,
            ),
        ),
        (
            "undated-empty.nessus",
            _nessus_snapshot(
                name="ordered-series",
                completed="",
                include_finding=False,
                include_host=False,
            ),
        ),
        (
            "future-empty.nessus",
            _nessus_snapshot(
                name="ordered-series",
                completed="Thu Jan 01 10:00:00 2099",
                include_finding=False,
            ),
        ),
    ):
        imported = client.post(
            endpoint,
            params={"source_name": source_name},
            content=report,
            headers={"Content-Type": "application/xml"},
        )
        assert imported.status_code == 201, imported.text
        overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
        assert overview["findings"][0]["lifecycle_status"] == "open"

    newer = client.post(
        endpoint,
        params={"source_name": "newer-empty.nessus"},
        content=_nessus_snapshot(
            name="ordered-series",
            completed="Tue Jul 21 12:00:00 2026",
            include_finding=False,
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert newer.status_code == 201, newer.text
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["findings"][0]["lifecycle_status"] == "fixed"

    historical_open = client.post(
        endpoint,
        params={"source_name": "historical-open.nessus"},
        content=_nessus_snapshot(
            name="ordered-series",
            completed="Tue Jul 21 11:00:00 2026",
            include_finding=True,
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert historical_open.status_code == 201, historical_open.text
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["findings"][0]["lifecycle_status"] == "fixed"


def test_new_scans_update_observed_topology_without_replacing_manual_architecture(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    observed = client.get(
        f"/api/v1/operational/systems/{system_id}/architecture/observed/latest"
    ).json()
    manual = client.post(
        f"/api/v1/operational/systems/{system_id}/architecture/versions",
        json={
            "title": "Curated logical architecture",
            "base_snapshot_id": observed["id"],
            "graph": _manual_graph(),
        },
    )
    assert manual.status_code == 201, manual.text
    assert manual.json()["layer"] == "manual"

    _import_nmap(client, system_id)
    latest = client.get(
        f"/api/v1/operational/systems/{system_id}/architecture/latest"
    ).json()
    latest_observed = client.get(
        f"/api/v1/operational/systems/{system_id}/architecture/observed/latest"
    ).json()
    assert latest["id"] == manual.json()["id"]
    assert latest["graph"]["nodes"][0]["id"] == "node:manual-api"
    assert latest_observed["layer"] == "observed"
    assert latest_observed["id"] != observed["id"]


def test_first_manual_version_can_save_against_the_observed_base_actually_edited(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    _import_nmap(client, system_id)
    edited_observed = client.get(
        f"/api/v1/operational/systems/{system_id}/architecture/observed/latest"
    ).json()

    _import_nmap(client, system_id)
    newer_observed = client.get(
        f"/api/v1/operational/systems/{system_id}/architecture/observed/latest"
    ).json()
    assert newer_observed["id"] != edited_observed["id"]

    first_manual = client.post(
        f"/api/v1/operational/systems/{system_id}/architecture/versions",
        json={
            "title": "Manual work preserved across scan race",
            "base_snapshot_id": edited_observed["id"],
            "graph": _manual_graph(),
        },
    )
    assert first_manual.status_code == 201, first_manual.text
    assert first_manual.json()["base_snapshot_id"] == edited_observed["id"]
    assert first_manual.json()["source_scan_id"] == edited_observed["source_scan_id"]

    next_manual = client.post(
        f"/api/v1/operational/systems/{system_id}/architecture/versions",
        json={
            "title": "Strict manual successor",
            "base_snapshot_id": first_manual.json()["id"],
            "graph": _manual_graph(),
        },
    )
    assert next_manual.status_code == 201, next_manual.text

    stale_observed_base = client.post(
        f"/api/v1/operational/systems/{system_id}/architecture/versions",
        json={
            "title": "Must not bypass manual concurrency",
            "base_snapshot_id": newer_observed["id"],
            "graph": _manual_graph(),
        },
    )
    assert stale_observed_base.status_code == 409
    assert "newer architecture version" in stale_observed_base.json()["detail"]
