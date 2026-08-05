from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select

from traceless_api.db.models import AuditEventRow, FindingEvidenceRow, GlobalIntelRecordRow
from traceless_api.job_worker import process_next_background_job

NMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.99">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="100.64.0.10" addrtype="ipv4"/>
    <hostnames><hostname name="payments.example.test" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Apache httpd" version="0.0.0" conf="10">
          <cpe>cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*</cpe>
        </service>
      </port>
    </ports>
  </host>
  <runstats><finished time="1784325600" exit="success"/></runstats>
</nmaprun>
"""


def _system_with_scan(
    client: TestClient,
    *,
    ip_address: str = "100.64.0.10",
    hostname: str = "payments.example.test",
    name: str = "Payment API",
) -> str:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Intel test", "description": "Global intelligence test"},
    ).json()
    system = client.post(
        f"/api/v1/operational/projects/{project['id']}/systems",
        json={
            "name": name,
            "description": "Observed Apache system",
            "owner": "Security Team",
            "criticality": "critical",
        },
    ).json()
    authorization = client.post(
        f"/api/v1/operational/systems/{system['id']}/scan-authorizations",
        json={
            "targets": [ip_address],
            "profile": "service_inventory",
            "approved_by": "System owner",
            "purpose": "Authorized inventory for intelligence correlation",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "confirmation": "Jag bekräftar att jag har tillstånd att skanna angivna mål.",
        },
    ).json()
    scan = client.post(
        f"/api/v1/operational/systems/{system['id']}/scans/import/nmap",
        params={"authorization_id": authorization["id"]},
        content=NMAP_XML.replace(b"100.64.0.10", ip_address.encode()).replace(
            b"payments.example.test", hostname.encode()
        ),
        headers={"Content-Type": "application/xml"},
    )
    assert scan.status_code == 201, scan.text
    return system["id"]


def _feed(now: datetime) -> dict[str, object]:
    cpe = "cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*"
    ai = {
        "model_name": "internal-classifier",
        "model_version": "2026-07",
        "prompt_version": "3",
        "taxonomy_version": "2",
        "analyzed_at": now.isoformat(),
        "confidence": 0.88,
        "categories": ["initial-access"],
        "extracted_entities": {"products": ["Apache httpd"]},
        "rationale": "Product and CVE explicitly named in the source.",
    }
    common = {
        "published_at": (now - timedelta(hours=1)).isoformat(),
        "modified_at": now.isoformat(),
        "retrieved_at": now.isoformat(),
        "valid_from": now.isoformat(),
        "valid_until": None,
        "revoked": False,
        "sectors": ["finance"],
        "regions": ["SE"],
        "markings": ["TLP:CLEAR"],
    }
    return {
        "schema_version": "1.0",
        "feed_id": "internal-cyber-pipeline",
        "feed_version": "42",
        "generated_at": now.isoformat(),
        "items": [
            {
                **common,
                "source_kind": "vulnerability",
                "provider": "internal-vulnerability-pipeline",
                "external_id": "CVE-2099-12345@42",
                "record_type": "vulnerability",
                "title": "Apache vulnerability from internal pipeline",
                "summary": "A normalized vulnerability record with explicit CPE evidence.",
                "source_url": "https://vulnerabilities.example.test/CVE-2099-12345",
                "severity": "critical",
                "confidence": 0.91,
                "cve_ids": ["CVE-2099-12345"],
                "cpes": [cpe],
                "affected_products": ["Apache httpd 0.0.0"],
                "mitre_attack_ids": [],
                "tags": ["remote-code-execution"],
                "raw_evidence": {
                    "source_id": "CVE-2099-12345",
                    "source_excerpt": "Affected package and version evidence",
                },
                "ai_analysis": ai,
                "vulnerability": {
                    "affected_cpes": [cpe],
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "epss_score": 0.72,
                    "epss_percentile": 0.98,
                    "cwe_ids": ["CWE-787"],
                    "exploit_status": "active",
                },
            },
            {
                **common,
                "source_kind": "news",
                "provider": "internal-cyber-scraper",
                "external_id": "article-42",
                "record_type": "threat",
                "title": "Campaign targeting vulnerable Apache services",
                "summary": "Current reporting tied to an explicit CVE and ATT&CK technique.",
                "source_url": "https://news.example.test/article-42",
                "severity": "high",
                "confidence": 0.88,
                "cve_ids": ["CVE-2099-12345"],
                "cpes": [],
                "affected_products": ["Apache httpd"],
                "mitre_attack_ids": ["T1190"],
                "tags": ["campaign"],
                "raw_evidence": {
                    "source_id": "article-42",
                    "source_excerpt": "Campaign evidence from source article",
                },
                "ai_analysis": ai,
                "vulnerability": None,
            },
            {
                **common,
                "source_kind": "misp",
                "provider": "internal-misp",
                "external_id": "event-uuid-42",
                "record_type": "indicator",
                "title": "MISP indicator observed on a scanned asset",
                "summary": "A source indicator with preserved marking and validity.",
                "source_url": "https://misp.example.test/events/view/event-uuid-42",
                "severity": "medium",
                "confidence": 0.80,
                "cve_ids": [],
                "cpes": [],
                "affected_products": [],
                "mitre_attack_ids": [],
                "indicators": [
                    {"type": "ipv4", "value": "100.64.0.10", "role": "host"},
                    {
                        "type": "domain",
                        "value": "payments.example.test",
                        "role": "source",
                    },
                ],
                "tags": ["misp:event"],
                "raw_evidence": {
                    "misp_event_uuid": "event-uuid-42",
                    "attribute_uuid": "attribute-uuid-42",
                },
                "ai_analysis": ai,
                "vulnerability": None,
            },
        ],
    }


def test_global_feed_is_deduplicated_searchable_and_correlated(client: TestClient) -> None:
    system_id = _system_with_scan(client)
    now = datetime.now(UTC)
    feed = _feed(now)

    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=feed,
        headers={"X-Actor": "feed-worker"},
    )
    assert imported.status_code == 200, imported.text
    assert imported.json() == {
        "imported": 3,
        "created": 3,
        "updated": 0,
        "unchanged": 0,
        "quarantined": 0,
        "warnings": [],
    }

    feed["items"][0]["provider"] = "INTERNAL-VULNERABILITY-PIPELINE"  # type: ignore[index]
    repeated = client.post("/api/v1/operational/intelligence/records/import", json=feed)
    assert repeated.status_code == 200
    assert repeated.json()["unchanged"] == 3
    assert repeated.json()["created"] == 0

    listed = client.get(
        "/api/v1/operational/intelligence/records",
        params={"source_kind": "news", "query": "Apache"},
    )
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 1
    record = listed.json()["items"][0]
    assert record["external_id"] == "article-42"
    assert len(record["raw_sha256"]) == 64
    assert len(record["analysis_sha256"]) == 64
    assert record["raw_evidence"] != record["ai_analysis"]
    assert record["review_status"] == "pending"
    assert record["reviewed_by"] is None
    detail = client.get(f"/api/v1/operational/intelligence/records/{record['id']}")
    assert detail.status_code == 200
    assert detail.json()["external_id"] == "article-42"

    pending = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending", "limit": 10},
    ).json()
    assert pending["total"] == 3
    for pending_record in pending["items"]:
        reviewed = client.patch(
            f"/api/v1/operational/intelligence/records/{pending_record['id']}/review",
            json={"decision": "approved", "note": "Source evidence verified."},
            headers={"X-Actor": "intel-analyst"},
        )
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["record"]["review_status"] == "approved"
        assert reviewed.json()["record"]["reviewed_by"] == "local:intel-analyst"
        assert len(reviewed.json()["correlation_job_ids"]) == 1
    assert client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending"},
    ).json()["total"] == 0

    correlated = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert correlated.status_code == 200, correlated.text
    result = correlated.json()
    assert result["records_considered"] == 3
    assert result["vulnerability_records_applied"] == 1
    assert result["finding_matches"] == 1
    assert result["findings_created"] == 1
    assert result["threat_records_matched"] == 2
    assert result["threats_created"] == 2
    assert result["risks_created"] == 3

    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert len(overview["findings"]) == 1
    assert overview["findings"][0]["cve_id"] == "CVE-2099-12345"
    assert overview["findings"][0]["is_kev"] is False
    assert len(overview["threats"]) == 2
    match_methods = [
        method["method"]
        for threat in overview["threats"]
        for methods in threat["provenance"]["match_methods_by_asset"].values()
        for method in methods
    ]
    assert "indicator:ipv4" in match_methods
    assert "indicator:domain" not in match_methods
    assert len(overview["risks"]) == 3

    repeated_correlation = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert repeated_correlation.status_code == 200
    assert repeated_correlation.json()["findings_created"] == 0
    assert repeated_correlation.json()["threats_created"] == 0
    assert repeated_correlation.json()["risks_created"] == 0

    revoked_feed = _feed(now + timedelta(seconds=1))
    for revoked_item in revoked_feed["items"]:  # type: ignore[union-attr]
        revoked_item["revoked"] = True
    updated = client.post(
        "/api/v1/operational/intelligence/records/import", json=revoked_feed
    )
    assert updated.status_code == 200
    assert updated.json()["updated"] == 3
    assert client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending"},
    ).json()["total"] == 3

    retired = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert retired.status_code == 200
    assert retired.json()["finding_matches"] == 0
    assert retired.json()["threat_records_matched"] == 0
    retired_overview = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()
    assert retired_overview["threats"] == []
    assert retired_overview["risks"][0]["status"] == "closed"


def test_feed_rejects_ai_output_without_required_vulnerability_evidence(
    client: TestClient,
) -> None:
    now = datetime.now(UTC)
    feed = _feed(now)
    item = feed["items"][0]  # type: ignore[index]
    item["vulnerability"] = None  # type: ignore[index]

    response = client.post("/api/v1/operational/intelligence/records/import", json=feed)
    assert response.status_code == 422
    assert "require cve_ids and vulnerability signals" in response.text


def test_older_feed_revision_cannot_overwrite_newer_source_evidence(client: TestClient) -> None:
    now = datetime.now(UTC)
    feed = _feed(now)
    imported = client.post("/api/v1/operational/intelligence/records/import", json=feed)
    assert imported.status_code == 200

    older = _feed(now - timedelta(days=1))
    older_item = older["items"][0]  # type: ignore[index]
    older_item["title"] = "Stale title"  # type: ignore[index]
    response = client.post("/api/v1/operational/intelligence/records/import", json=older)
    assert response.status_code == 200
    assert response.json()["unchanged"] == 3
    assert len(response.json()["warnings"]) == 3

    listed = client.get(
        "/api/v1/operational/intelligence/records", params={"query": "Stale title"}
    )
    assert listed.json()["total"] == 0


def test_intelligence_requires_an_explicit_analyst_review_decision(
    client: TestClient,
) -> None:
    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=_feed(datetime.now(UTC)),
    )
    assert imported.status_code == 200, imported.text
    pending = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending"},
    ).json()
    record_id = pending["items"][0]["id"]

    missing_reason = client.patch(
        f"/api/v1/operational/intelligence/records/{record_id}/review",
        json={"decision": "rejected"},
    )
    assert missing_reason.status_code == 422

    rejected = client.patch(
        f"/api/v1/operational/intelligence/records/{record_id}/review",
        json={"decision": "rejected", "note": "The source is not sufficiently specific."},
        headers={"X-Actor": "intel-reviewer"},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["record"]["review_status"] == "rejected"
    assert rejected.json()["record"]["reviewed_by"] == "local:intel-reviewer"
    assert rejected.json()["correlation_job_ids"] == []
    assert client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "rejected"},
    ).json()["total"] == 1


def test_approval_queues_and_executes_incremental_correlation(
    client: TestClient,
) -> None:
    system_id = _system_with_scan(client)
    imported_at = datetime.now(UTC)
    feed = _feed(imported_at)
    feed["items"] = [feed["items"][1]]  # type: ignore[index]
    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=feed,
    )
    assert imported.status_code == 200, imported.text
    record = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending"},
    ).json()["items"][0]

    approved = client.patch(
        f"/api/v1/operational/intelligence/records/{record['id']}/review",
        json={"decision": "approved", "note": "Correlate this verified source."},
    )
    assert approved.status_code == 200, approved.text
    assert len(approved.json()["correlation_job_ids"]) == 1
    job_id = approved.json()["correlation_job_ids"][0]

    job = client.get(f"/api/v1/operational/jobs/{job_id}")
    for _ in range(5):
        if job.json()["status"] == "completed":
            break
        assert process_next_background_job(
            settings=client.app.state.settings,
            session_factory=client.app.state.session_factory,
        )
        job = client.get(f"/api/v1/operational/jobs/{job_id}")
    assert job.status_code == 200, job.text
    assert job.json()["status"] == "completed"
    assert job.json()["job_type"] == "intelligence_correlation"
    assert job.json()["result_resource_type"] == "system_intelligence_correlation"
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert len(overview["threats"]) == 1
    assert len(overview["risks"]) == 1

    changed_feed = _feed(imported_at + timedelta(seconds=1))
    changed_feed["items"] = [changed_feed["items"][1]]  # type: ignore[index]
    changed = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=changed_feed,
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["updated"] == 1
    # An updated record returns to pending review. Its old effects disappear
    # synchronously; queue delay or failure cannot keep it active in the UI.
    pending_overview = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()
    assert pending_overview["threats"] == []
    assert pending_overview["risks"] == []
    immediate_report = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "json", "report_type": "management"},
    )
    assert immediate_report.status_code == 201, immediate_report.text
    rejected = client.patch(
        f"/api/v1/operational/intelligence/records/{record['id']}/review",
        json={"decision": "rejected", "note": "The revised source is no longer actionable."},
    )
    assert rejected.status_code == 200, rejected.text
    assert len(rejected.json()["correlation_job_ids"]) == 1
    repeated_rejection = client.patch(
        f"/api/v1/operational/intelligence/records/{record['id']}/review",
        json={"decision": "rejected", "note": "The revised source is no longer actionable."},
    )
    assert repeated_rejection.status_code == 200
    assert repeated_rejection.json()["correlation_job_ids"] == []
    assert process_next_background_job(
        settings=client.app.state.settings,
        session_factory=client.app.state.session_factory,
    )
    retired = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert retired["threats"] == []
    assert retired["risks"] == []


def test_rejected_global_vulnerability_retires_effects_before_worker_runs(
    client: TestClient,
) -> None:
    system_id = _system_with_scan(client)
    imported_at = datetime.now(UTC) - timedelta(minutes=1)
    feed = _feed(imported_at)
    feed["items"] = [feed["items"][0]]  # type: ignore[index]
    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=feed,
    )
    assert imported.status_code == 200, imported.text
    record = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending"},
    ).json()["items"][0]
    approved = client.patch(
        f"/api/v1/operational/intelligence/records/{record['id']}/review",
        json={"decision": "approved", "note": "Verified vulnerability source."},
    )
    assert approved.status_code == 200, approved.text
    job_id = approved.json()["correlation_job_ids"][0]
    for _ in range(5):
        job = client.get(f"/api/v1/operational/jobs/{job_id}").json()
        if job["status"] == "completed":
            break
        assert process_next_background_job(
            settings=client.app.state.settings,
            session_factory=client.app.state.session_factory,
        )
    active = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert active["findings"][0]["lifecycle_status"] == "open"
    assert active["risks"][0]["status"] == "open"

    rejected = client.patch(
        f"/api/v1/operational/intelligence/records/{record['id']}/review",
        json={"decision": "rejected", "note": "Applicability was disproven."},
    )
    assert rejected.status_code == 200, rejected.text
    immediate = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert immediate["findings"][0]["lifecycle_status"] == "fixed"
    assert immediate["risks"][0]["status"] == "closed"
    report = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "json", "report_type": "management"},
    )
    assert report.status_code == 201, report.text

    reapproved = client.patch(
        f"/api/v1/operational/intelligence/records/{record['id']}/review",
        json={"decision": "approved", "note": "Applicability was re-verified."},
    )
    assert reapproved.status_code == 200, reapproved.text
    recorrelated = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert recorrelated.status_code == 200, recorrelated.text
    reopened = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert reopened["findings"][0]["lifecycle_status"] == "reopened"
    assert reopened["risks"][0]["status"] == "open"


def test_expired_global_sources_fail_closed_without_temporal_worker(
    client: TestClient,
) -> None:
    system_id = _system_with_scan(client)
    imported_at = datetime.now(UTC) - timedelta(minutes=1)
    feed = _feed(imported_at)
    feed["items"] = [feed["items"][0], feed["items"][1]]  # type: ignore[index]
    for item in feed["items"]:  # type: ignore[union-attr]
        item["valid_until"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=feed,
    )
    assert imported.status_code == 200, imported.text
    pending = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending", "limit": 10},
    ).json()["items"]
    assert len(pending) == 2
    for record in pending:
        approved = client.patch(
            f"/api/v1/operational/intelligence/records/{record['id']}/review",
            json={"decision": "approved", "note": "Time-bounded test source."},
        )
        assert approved.status_code == 200, approved.text
    correlated = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert correlated.status_code == 200, correlated.text
    active = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert active["findings"][0]["lifecycle_status"] == "open"
    assert active["threats"]

    with client.app.state.session_factory() as session:
        records = list(
            session.scalars(
                select(GlobalIntelRecordRow).where(
                    GlobalIntelRecordRow.id.in_(
                        [UUID(record["id"]) for record in pending]
                    )
                )
            )
        )
        for record in records:
            record.valid_until = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    # No queued temporal job is processed. The current read itself enforces
    # the authoritative validity boundary and materializes retirement.
    expired = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert expired["findings"][0]["lifecycle_status"] == "fixed"
    assert expired["threats"] == []
    assert all(risk["status"] == "closed" for risk in expired["risks"])
    report = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "json", "report_type": "management"},
    )
    assert report.status_code == 201, report.text


def test_correlation_retires_pending_global_source_but_keeps_scanner_evidence(
    client: TestClient,
) -> None:
    system_id = _system_with_scan(client)
    imported_at = datetime.now(UTC) - timedelta(minutes=1)
    feed = _feed(imported_at)
    feed["items"] = [feed["items"][0]]  # type: ignore[index]
    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=feed,
    )
    assert imported.status_code == 200, imported.text
    record = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending"},
    ).json()["items"][0]
    approved = client.patch(
        f"/api/v1/operational/intelligence/records/{record['id']}/review",
        json={"decision": "approved", "note": "Verified global source."},
    )
    assert approved.status_code == 200, approved.text
    correlated = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert correlated.status_code == 200, correlated.text

    scanner = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import",
        json={
            "provider": "qualys",
            "source_name": "independent-scanner.json",
            "observations": [
                {
                    "provider_finding_id": "QID-independent-12345",
                    "asset_identifier": "payments.example.test",
                    "ip_address": "100.64.0.10",
                    "hostname": "payments.example.test",
                    "port": 443,
                    "protocol": "tcp",
                    "title": "Independent scanner evidence",
                    "severity": "high",
                    "state": "open",
                    "cve_ids": ["CVE-2099-12345"],
                    "cvss_score": 8.8,
                    "observed_at": datetime.now(UTC).isoformat(),
                }
            ],
        },
    )
    assert scanner.status_code == 201, scanner.text

    # Simulate the state visible to a delayed correlation worker immediately
    # after a new source revision returned to pending review. This exercises the
    # correlation boundary itself rather than relying on the synchronous API
    # retirement path to have run first.
    with client.app.state.session_factory() as session:
        row = session.get(GlobalIntelRecordRow, UUID(record["id"]))
        assert row is not None
        row.review_status = "pending"
        row.reviewed_by = None
        row.reviewed_at = None
        row.review_note = None
        session.commit()

    retired = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert retired.status_code == 200, retired.text
    assert retired.json()["warnings"] == [
        "CVE-2099-12345 retained other evidence after a global source retired; "
        "its selected metrics require analyst review."
    ]
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    finding = overview["findings"][0]
    assert finding["lifecycle_status"] == "open"
    assert overview["risks"][0]["status"] == "open"
    with client.app.state.session_factory() as session:
        evidence = list(
            session.scalars(
                select(FindingEvidenceRow).where(
                    FindingEvidenceRow.finding_id == UUID(finding["id"])
                )
            )
        )
    assert {(item.source_kind, item.lifecycle_status) for item in evidence} == {
        ("intelligence", "fixed"),
        ("scanner", "open"),
    }


def test_retirement_audit_lists_only_records_that_affected_each_system(
    client: TestClient,
) -> None:
    first_system_id = _system_with_scan(
        client,
        ip_address="100.64.0.10",
        hostname="first.example.test",
        name="First scoped system",
    )
    second_system_id = _system_with_scan(
        client,
        ip_address="100.64.0.11",
        hostname="second.example.test",
        name="Second scoped system",
    )
    imported_at = datetime.now(UTC) - timedelta(minutes=1)
    feed = _feed(imported_at)
    first_item = dict(feed["items"][2])  # type: ignore[index]
    first_item["external_id"] = "system-one-indicator"
    first_item["indicators"] = [
        {"type": "ipv4", "value": "100.64.0.10", "role": "host"}
    ]
    second_item = dict(feed["items"][2])  # type: ignore[index]
    second_item["external_id"] = "system-two-indicator"
    second_item["indicators"] = [
        {"type": "ipv4", "value": "100.64.0.11", "role": "host"}
    ]
    feed["items"] = [first_item, second_item]
    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=feed,
    )
    assert imported.status_code == 200, imported.text
    pending = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending", "limit": 10},
    ).json()["items"]
    assert len(pending) == 2
    record_ids = {item["external_id"]: item["id"] for item in pending}
    for item in pending:
        approved = client.patch(
            f"/api/v1/operational/intelligence/records/{item['id']}/review",
            json={"decision": "approved", "note": "Scoped indicator verified."},
        )
        assert approved.status_code == 200, approved.text
    for system_id in (first_system_id, second_system_id):
        correlated = client.post(
            f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
        )
        assert correlated.status_code == 200, correlated.text
        assert correlated.json()["threat_records_matched"] == 1

    revised = _feed(imported_at + timedelta(seconds=1))
    revised_first = dict(revised["items"][2])  # type: ignore[index]
    revised_first["external_id"] = "system-one-indicator"
    revised_first["indicators"] = first_item["indicators"]
    revised_first["revoked"] = True
    revised_second = dict(revised["items"][2])  # type: ignore[index]
    revised_second["external_id"] = "system-two-indicator"
    revised_second["indicators"] = second_item["indicators"]
    revised_second["revoked"] = True
    revised["items"] = [revised_first, revised_second]
    withdrawn = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=revised,
        headers={"X-Actor": "scope-retirement-test"},
    )
    assert withdrawn.status_code == 200, withdrawn.text
    assert withdrawn.json()["updated"] == 2

    with client.app.state.session_factory() as session:
        events = list(
            session.scalars(
                select(AuditEventRow).where(
                    AuditEventRow.action == "intelligence.effects_withdrawn",
                    AuditEventRow.resource_id.in_([first_system_id, second_system_id]),
                )
            )
        )
    assert len(events) == 2
    by_system = {event.resource_id: event.details["record_ids"] for event in events}
    assert by_system == {
        first_system_id: [record_ids["system-one-indicator"]],
        second_system_id: [record_ids["system-two-indicator"]],
    }


def test_correlation_requires_a_completed_scan(client: TestClient) -> None:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "No scan", "description": "Conflict test"},
    ).json()
    system = client.post(
        f"/api/v1/operational/projects/{project['id']}/systems",
        json={
            "name": "Unscanned system",
            "description": "No evidence yet",
            "owner": "Security Team",
            "criticality": "medium",
        },
    ).json()

    response = client.post(
        f"/api/v1/operational/systems/{system['id']}/intelligence/correlate"
    )
    assert response.status_code == 409
    assert "completed scan" in response.json()["detail"]
