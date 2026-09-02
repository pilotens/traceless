import json
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from uuid import UUID

from fastapi.testclient import TestClient
from pydantic import SecretStr

from traceless_api.db.models import ScanAuthorizationRow
from traceless_api.worker import process_next_scan

NMAP_SOURCE_TIME = int(datetime.now(UTC).timestamp()) - 300

NMAP_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.99">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="100.64.0.10" addrtype="ipv4"/>
    <address addr="02:42:AC:11:00:02" addrtype="mac" vendor="Example"/>
    <hostnames><hostname name="payments.example.test" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Apache httpd" version="0.0.0" conf="10">
          <cpe>cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*</cpe>
        </service>
      </port>
    </ports>
    <os><osmatch name="Linux 6.x" accuracy="96"/></os>
  </host>
  <runstats><finished time="{NMAP_SOURCE_TIME}" exit="success"/></runstats>
</nmaprun>
""".encode()

NMAP_EMPTY_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.99">
  <runstats><finished time="{NMAP_SOURCE_TIME + 60}" exit="success"/></runstats>
</nmaprun>
""".encode()

NETBOX_CREDENTIAL = token_urlsafe(32)


class _HttpResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.content = json.dumps(payload).encode()
        self.headers = {"Content-Type": "application/json"}
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None


class _HttpClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.response = _HttpResponse(payload)

    async def __aenter__(self) -> "_HttpClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def get(
        self,
        _: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = False,
    ) -> _HttpResponse:
        assert headers is not None
        assert timeout is not None
        assert follow_redirects is False
        return self.response


def _http_client_factory(payload: dict[str, object]):
    def factory() -> _HttpClient:
        return _HttpClient(payload)

    return factory


def _canonical_vulnerability(
    *,
    cve_id: str,
    title: str,
    affected_cpes: list[str],
    modified_at: datetime | None = None,
    cvss_score: float | None = None,
    cvss_vector: str | None = None,
    epss_score: float | None = None,
    epss_percentile: float | None = None,
) -> dict[str, object]:
    observed_at = modified_at or datetime.now(UTC)
    return {
        "source_kind": "vulnerability",
        "provider": "test-vulnerability-pipeline",
        "external_id": cve_id,
        "record_type": "vulnerability",
        "title": title,
        "summary": title,
        "modified_at": observed_at.isoformat(),
        "retrieved_at": observed_at.isoformat(),
        "severity": "critical",
        "confidence": 0.9,
        "cve_ids": [cve_id],
        "cpes": affected_cpes,
        "affected_products": [],
        "markings": ["TLP:CLEAR"],
        "raw_evidence": {"source_id": cve_id},
        "vulnerability": {
            "affected_cpes": affected_cpes,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "exploit_status": "unknown",
        },
    }


def _canonical_threat(
    *,
    external_id: str,
    title: str,
    affected_products: list[str],
    modified_at: datetime | None = None,
    cve_ids: list[str] | None = None,
) -> dict[str, object]:
    observed_at = modified_at or datetime.now(UTC)
    return {
        "source_kind": "news",
        "provider": "test-threat-pipeline",
        "external_id": external_id,
        "record_type": "threat",
        "title": title,
        "summary": "Test threat intelligence with preserved source evidence.",
        "modified_at": observed_at.isoformat(),
        "retrieved_at": observed_at.isoformat(),
        "severity": "high",
        "confidence": 0.87,
        "cve_ids": cve_ids or [],
        "affected_products": affected_products,
        "mitre_attack_ids": ["T1190"],
        "markings": ["TLP:CLEAR"],
        "raw_evidence": {"source_id": external_id},
    }


def _import_review_and_correlate(
    client: TestClient,
    system_id: str,
    items: list[dict[str, object]],
    *,
    feed_version: str = "1",
) -> dict[str, object]:
    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=_canonical_feed(items, feed_version=feed_version),
    )
    assert imported.status_code == 200, imported.text

    pending = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending", "limit": 200},
    )
    assert pending.status_code == 200, pending.text
    assert pending.json()["items"]
    for record in pending.json()["items"]:
        reviewed = client.patch(
            f"/api/v1/operational/intelligence/records/{record['id']}/review",
            json={"decision": "approved", "note": "Test evidence reviewed."},
        )
        assert reviewed.status_code == 200, reviewed.text

    correlated = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert correlated.status_code == 200, correlated.text
    return correlated.json()


def _canonical_feed(
    items: list[dict[str, object]], *, feed_version: str = "1"
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "feed_id": "test-canonical-intelligence",
        "feed_version": feed_version,
        "generated_at": datetime.now(UTC).isoformat(),
        "items": items,
    }


class _NetBoxHttpClient:
    def __init__(self) -> None:
        self.requests: list[str] = []

    async def __aenter__(self) -> "_NetBoxHttpClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = False,
    ) -> _HttpResponse:
        self.requests.append(url)
        assert headers is not None
        assert headers["Authorization"] == f"Bearer {NETBOX_CREDENTIAL}"
        assert params == {"limit": "100", "offset": "0", "ordering": "id"}
        assert timeout == 20.0
        assert follow_redirects is False
        records: list[dict[str, object]] = []
        if url.endswith("api/dcim/devices/"):
            records = [
                {
                    "id": 42,
                    "url": "https://netbox.example.test/api/dcim/devices/42/",
                    "display": "edge-01",
                    "name": "edge-01",
                    "status": {"value": "active", "label": "Active"},
                    "role": {"id": 5, "display": "Edge"},
                    "device_type": {"id": 9, "display": "Router 9000"},
                    "site": {"id": 3, "display": "Stockholm"},
                    "primary_ip4": {"id": 81, "address": "100.64.0.42/24"},
                    "serial": "SERIAL-42",
                    "tags": [{"id": 1, "name": "production"}],
                    "last_updated": "2026-07-17T11:45:00Z",
                }
            ]
        return _HttpResponse(
            {
                "count": len(records),
                "next": None,
                "previous": None,
                "results": records,
            }
        )


def _netbox_http_client_factory(client: _NetBoxHttpClient):
    def factory() -> _NetBoxHttpClient:
        return client

    return factory


def _nvd_payload() -> dict[str, object]:
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-07-17T11:55:00.000",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-54321",
                    "sourceIdentifier": "security@example.test",
                    "published": "2026-07-10T08:00:00.000",
                    "lastModified": "2026-07-17T11:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Test vulnerability returned for the observed Apache CPE.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": (
                                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                    ),
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ]
                    },
                    "references": [],
                }
            }
        ],
    }


def _create_system(client: TestClient) -> tuple[str, str]:
    project_response = client.post(
        "/api/v1/operational/projects",
        json={"name": "Betalplattform", "description": "Operativt testprojekt"},
    )
    assert project_response.status_code == 201
    project_id = project_response.json()["id"]
    system_response = client.post(
        f"/api/v1/operational/projects/{project_id}/systems",
        json={
            "name": "Payment API",
            "description": "Internetnära betalningsflöde",
            "owner": "Security Team",
            "criticality": "critical",
        },
    )
    assert system_response.status_code == 201
    return project_id, system_response.json()["id"]


def _authorize(client: TestClient, system_id: str, target: str = "100.64.0.10") -> str:
    response = client.post(
        f"/api/v1/operational/systems/{system_id}/scan-authorizations",
        json={
            "targets": [target],
            "profile": "service_inventory",
            "approved_by": "Systemägare",
            "purpose": "Godkänd säkerhetsinventering inför riskanalys",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "confirmation": "Jag bekräftar att jag har tillstånd att skanna angivna mål.",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _import_scan(client: TestClient, system_id: str, authorization_id: str) -> str:
    response = client.post(
        f"/api/v1/operational/systems/{system_id}/scans/import/nmap",
        params={"authorization_id": authorization_id},
        content=NMAP_XML,
        headers={"Content-Type": "application/xml", "X-Actor": "integration-test"},
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["result_summary"]["assets_observed"] == 1
    assert payload["result_summary"]["services_observed"] == 1
    assert payload["result_summary"]["raw_evidence_retained"] is False
    return payload["id"]


def test_persistent_scan_to_architecture_intelligence_risk_and_report(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_scan(client, system_id, authorization_id)

    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview")
    assert overview.status_code == 200
    payload = overview.json()
    assert payload["latest_architecture"]["status"] == "draft"
    assert payload["latest_architecture"]["graph"]["publication_state"] == "draft"
    assert payload["assets"][0]["primary_ip"] == "100.64.0.10"
    assert payload["services"][0]["product"] == "Apache httpd"

    correlation = _import_review_and_correlate(
        client,
        system_id,
        [
            _canonical_vulnerability(
                cve_id="CVE-2099-12345",
                title="Test vulnerability for an observed Apache version",
                affected_cpes=[
                    "cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*"
                ],
                cvss_score=9.1,
                cvss_vector=(
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                ),
                epss_score=0.72,
                epss_percentile=0.98,
            ),
            _canonical_threat(
                external_id="threat--payment-web-2026",
                title="Campaign targeting exposed Apache services",
                affected_products=["Apache httpd"],
                cve_ids=["CVE-2099-12345"],
            ),
        ],
    )
    assert correlation["findings_created"] == 1
    assert correlation["threats_created"] == 1

    enriched = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert enriched["findings"][0]["cve_id"] == "CVE-2099-12345"
    assert enriched["findings"][0]["is_kev"] is False
    assert enriched["findings"][0]["epss_score"] == 0.72
    assert len(enriched["threats"]) == 1
    assert len(enriched["risks"]) == 2
    assert enriched["risks"][0]["score"] == 20
    assert enriched["risks"][0]["rationale"]["signals"]["kev"] is False

    report_response = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "pdf", "report_type": "management"},
    )
    assert report_response.status_code == 201, report_response.text
    report = report_response.json()
    download = client.get(f"/api/v1/operational/reports/{report['id']}/download")
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/pdf"
    assert download.headers["x-content-sha256"] == report["sha256"]
    assert download.content.startswith(b"%PDF-")


def test_scan_authorization_rejects_public_forbidden_and_oversized_scope(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    for target in ["8.8.8.8", "127.0.0.1", "198.18.0.0/23"]:
        response = client.post(
            f"/api/v1/operational/systems/{system_id}/scan-authorizations",
            json={
                "targets": [target],
                "profile": "discovery",
                "approved_by": "Systemägare",
                "purpose": "Scope som ska nekas av säkerhetspolicyn",
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "confirmation": "Jag bekräftar att jag har tillstånd att skanna angivna mål.",
            },
        )
        assert response.status_code == 409, (target, response.text)


def test_import_rejects_observation_outside_authorized_scope(client: TestClient) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id, "100.64.0.11")
    response = client.post(
        f"/api/v1/operational/systems/{system_id}/scans/import/nmap",
        params={"authorization_id": authorization_id},
        content=NMAP_XML,
        headers={"Content-Type": "application/xml"},
    )
    assert response.status_code == 422
    scans = client.get(f"/api/v1/operational/systems/{system_id}/scans")
    assert scans.status_code == 200
    assert scans.json() == []


def test_naabu_fallback_is_retained_as_supplemental_not_current_inventory(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    response = client.post(
        f"/api/v1/operational/systems/{system_id}/scans/import/naabu",
        params={"authorization_id": authorization_id},
        content=b'{"ip":"100.64.0.10","port":443,"protocol":"tcp","tls":true}\n',
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["scanner"] == "naabu"
    assert response.json()["result_summary"]["completeness"] == "partial"
    assert response.json()["result_summary"]["inventory_role"] == "supplemental"
    assert response.json()["result_summary"]["is_current_inventory"] is False
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["assets"] == []
    assert overview["services"] == []


def test_isolated_worker_executes_only_the_reviewed_nmap_profile(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/scans",
        json={"authorization_id": authorization_id, "scanner": "nmap"},
    )
    assert queued.status_code == 202
    captured: list[str] = []

    def fake_runner(
        argv: list[str] | tuple[str, ...], timeout_seconds: int, max_output_bytes: int
    ) -> subprocess.CompletedProcess[bytes]:
        captured.extend(argv)
        assert timeout_seconds == 900
        assert max_output_bytes == 10_000_000
        return subprocess.CompletedProcess(argv, 0, stdout=NMAP_XML, stderr=b"")

    settings = client.app.state.settings.model_copy(update={"nmap_enabled": True})
    assert process_next_scan(
        settings=settings,
        session_factory=client.app.state.session_factory,
        runner=fake_runner,
    )
    assert captured[0] == "nmap"
    assert "-sT" in captured
    assert "-sV" in captured
    assert "--script" not in captured
    assert captured[-1] == "100.64.0.10/32"

    scan = client.get(f"/api/v1/operational/scans/{queued.json()['id']}")
    assert scan.status_code == 200
    assert scan.json()["status"] == "completed"


def test_worker_rejects_persisted_scope_tampering_before_execution(client: TestClient) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/scans",
        json={"authorization_id": authorization_id, "scanner": "nmap"},
    )
    assert queued.status_code == 202
    with client.app.state.session_factory() as session:
        authorization = session.get(ScanAuthorizationRow, UUID(authorization_id))
        assert authorization is not None
        authorization.targets = ["100.64.0.11/32"]
        session.commit()

    executed = False

    def runner(
        _: list[str] | tuple[str, ...],
        __: int,
        ___: int,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal executed
        executed = True
        return subprocess.CompletedProcess([], 0, stdout=NMAP_XML, stderr=b"")

    settings = client.app.state.settings.model_copy(update={"nmap_enabled": True})
    assert process_next_scan(
        settings=settings,
        session_factory=client.app.state.session_factory,
        runner=runner,
    )
    assert executed is False
    scan = client.get(f"/api/v1/operational/scans/{queued.json()['id']}")
    assert scan.json()["status"] == "failed"
    assert scan.json()["error_code"] == "authorization_integrity_failed"


def test_worker_rejects_revoked_authorization_and_records_scanner_failure(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    revoked_authorization_id = _authorize(client, system_id)
    revoked_job = client.post(
        f"/api/v1/operational/systems/{system_id}/scans",
        json={"authorization_id": revoked_authorization_id, "scanner": "nmap"},
    )
    with client.app.state.session_factory() as session:
        authorization = session.get(ScanAuthorizationRow, UUID(revoked_authorization_id))
        assert authorization is not None
        authorization.status = "revoked"
        session.commit()

    executed = False

    def must_not_run(
        _: list[str] | tuple[str, ...],
        __: int,
        ___: int,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal executed
        executed = True
        return subprocess.CompletedProcess([], 0, stdout=NMAP_XML, stderr=b"")

    settings = client.app.state.settings.model_copy(update={"nmap_enabled": True})
    assert process_next_scan(
        settings=settings,
        session_factory=client.app.state.session_factory,
        runner=must_not_run,
    )
    assert executed is False
    revoked_scan = client.get(f"/api/v1/operational/scans/{revoked_job.json()['id']}").json()
    assert revoked_scan["error_code"] == "authorization_inactive"

    active_authorization_id = _authorize(client, system_id)
    failed_job = client.post(
        f"/api/v1/operational/systems/{system_id}/scans",
        json={"authorization_id": active_authorization_id, "scanner": "nmap"},
    )

    def failed_scanner(
        argv: list[str] | tuple[str, ...],
        _: int,
        __: int,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 2, stdout=b"", stderr=b"permission denied")

    assert process_next_scan(
        settings=settings,
        session_factory=client.app.state.session_factory,
        runner=failed_scanner,
    )
    failed_scan = client.get(f"/api/v1/operational/scans/{failed_job.json()['id']}").json()
    assert failed_scan["status"] == "failed"
    assert failed_scan["error_code"] == "scanner_execution_failed"
    assert "status 2" in failed_scan["error_message"]


def test_configured_official_and_reviewed_canonical_intelligence_sync(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_scan(client, system_id, authorization_id)
    correlation = _import_review_and_correlate(
        client,
        system_id,
        [
            _canonical_vulnerability(
                cve_id="CVE-2099-12345",
                title="Observed-version candidate",
                affected_cpes=[
                    "cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*"
                ],
                cvss_score=8.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            )
        ],
    )
    assert correlation["findings_created"] == 1

    threat_observed_at = datetime.now(UTC) - timedelta(minutes=2)
    canonical_threat = _canonical_threat(
        external_id="campaign-indicator-2026",
        title="Current campaign indicator",
        affected_products=[],
        modified_at=threat_observed_at,
        cve_ids=["CVE-2099-12345"],
    )
    threat_correlation = _import_review_and_correlate(
        client,
        system_id,
        [canonical_threat],
        feed_version="2",
    )
    assert threat_correlation["threats_created"] == 1

    kev_payload: dict[str, object] = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.07.17",
        "dateReleased": "2026-07-17T09:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2099-12345",
                "vendorProject": "Apache",
                "product": "HTTP Server",
                "vulnerabilityName": "Fixture known exploited vulnerability",
                "dateAdded": "2026-07-15",
                "shortDescription": "Fixture entry.",
                "requiredAction": "Apply vendor guidance.",
                "dueDate": "2026-08-05",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
                "cwes": ["CWE-78"],
            }
        ],
    }
    client.app.state.http_client_factory = _http_client_factory(kev_payload)
    kev = client.post(f"/api/v1/operational/systems/{system_id}/intelligence/sync/kev")
    assert kev.status_code == 200, kev.text
    assert kev.json()["matched"] == 1
    assert "KEV is catalogue membership" in kev.json()["warnings"][0]

    epss_payload: dict[str, object] = {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "access": "public",
        "total": 1,
        "offset": 0,
        "limit": 100,
        "data": [
            {
                "cve": "CVE-2099-12345",
                "epss": "0.73425",
                "percentile": "0.98123",
                "date": "2026-07-17",
            }
        ],
    }
    client.app.state.http_client_factory = _http_client_factory(epss_payload)
    epss = client.post(f"/api/v1/operational/systems/{system_id}/intelligence/sync/epss")
    assert epss.status_code == 200, epss.text
    assert epss.json()["updated"] == 1

    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["findings"][0]["is_kev"] is True
    assert overview["findings"][0]["epss_score"] == 0.73425
    # KEV proves exploitation exists in the wild, not that this deployment is
    # reachable. Unknown exposure therefore remains likelihood 4 until context
    # confirms external reachability.
    assert overview["risks"][0]["score"] == 20
    assert overview["threats"][0]["attack_patterns"] == ["T1190"]

    client.app.state.http_client_factory = _http_client_factory(epss_payload)
    repeated_epss = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/epss"
    )
    assert repeated_epss.status_code == 200, repeated_epss.text
    deduplicated = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert (
        len(
            [
                source
                for source in deduplicated["findings"][0]["sources"]
                if source.get("provider") == "first-epss"
            ]
        )
        == 1
    )

    client.app.state.http_client_factory = _http_client_factory(kev_payload)
    assert (
        client.post(f"/api/v1/operational/systems/{system_id}/intelligence/sync/kev").status_code
        == 200
    )
    kev_deduplicated = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert (
        len(
            [
                source
                for source in kev_deduplicated["findings"][0]["sources"]
                if source.get("provider") == "cisa-kev"
            ]
        )
        == 1
    )

    empty_kev_payload: dict[str, object] = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.07.18",
        "dateReleased": "2026-07-18T09:00:00Z",
        "count": 0,
        "vulnerabilities": [],
    }
    client.app.state.http_client_factory = _http_client_factory(empty_kev_payload)
    empty_kev = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/kev"
    )
    assert empty_kev.status_code == 502
    still_kev = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()
    assert still_kev["findings"][0]["is_kev"] is True

    replacement_kev_payload = json.loads(json.dumps(kev_payload))
    replacement_kev_payload["catalogVersion"] = "2026.07.18"
    replacement_kev_payload["dateReleased"] = "2026-07-18T09:00:00Z"
    replacement_kev_payload["vulnerabilities"][0]["cveID"] = "CVE-2099-99999"
    client.app.state.http_client_factory = _http_client_factory(replacement_kev_payload)
    replacement = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/kev"
    )
    assert replacement.status_code == 200, replacement.text

    revoked_at = datetime.now(UTC) - timedelta(minutes=1)
    revoked_threat = {
        **canonical_threat,
        "modified_at": revoked_at.isoformat(),
        "retrieved_at": revoked_at.isoformat(),
        "revoked": True,
    }
    revoked_import = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=_canonical_feed([revoked_threat], feed_version="3"),
    )
    assert revoked_import.status_code == 200, revoked_import.text
    assert revoked_import.json()["updated"] == 1
    retired = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert retired.status_code == 200, retired.text
    current = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert current["findings"][0]["is_kev"] is False
    assert current["findings"][0]["kev_due_date"] is None
    assert current["threats"] == []
    assert len(current["risks"]) == 1
    assert current["risks"][0]["score"] == 20


def test_nvd_sync_creates_only_a_candidate_and_preserves_provider_evidence(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_scan(client, system_id, authorization_id)
    client.app.state.http_client_factory = _http_client_factory(_nvd_payload())

    response = client.post(f"/api/v1/operational/systems/{system_id}/intelligence/sync/nvd")

    assert response.status_code == 200, response.text
    assert response.json()["provider"] == "nvd"
    assert response.json()["updated"] == 1
    assert "not endorsed" in response.json()["warnings"][0]
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    finding = overview["findings"][0]
    assert finding["cve_id"] == "CVE-2099-54321"
    assert finding["status"] == "candidate"
    assert finding["match_confidence"] == 0.7
    assert finding["sources"][0]["cvss_metrics"][0]["metric_source"] == "nvd@nist.gov"
    assert "applicability" in finding["match_reason"]

    repeated = client.post(f"/api/v1/operational/systems/{system_id}/intelligence/sync/nvd")
    assert repeated.status_code == 200
    repeated_overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert len(repeated_overview["findings"]) == 1
    assert len(repeated_overview["risks"]) == 1
    assert (
        len(
            [
                source
                for source in repeated_overview["findings"][0]["sources"]
                if source.get("provider") == "nvd"
            ]
        )
        == 1
    )


def test_future_provider_revisions_do_not_lock_legitimate_followup_syncs(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_scan(client, system_id, authorization_id)
    _import_review_and_correlate(
        client,
        system_id,
        [
            _canonical_vulnerability(
                cve_id="CVE-2099-12345",
                title="Provider watermark recovery fixture",
                affected_cpes=[
                    "cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*"
                ],
            )
        ],
    )

    kev_record = {
        "cveID": "CVE-2099-12345",
        "vendorProject": "Apache",
        "product": "HTTP Server",
        "vulnerabilityName": "Provider clock recovery fixture",
        "dateAdded": "2026-07-15",
        "shortDescription": "Fixture entry.",
        "requiredAction": "Apply vendor guidance.",
        "dueDate": "2026-08-05",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
        "cwes": [],
    }
    future_kev = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2099.01.01",
        "dateReleased": "2099-01-01T00:00:00Z",
        "count": 1,
        "vulnerabilities": [kev_record],
    }
    client.app.state.http_client_factory = _http_client_factory(future_kev)
    rejected_kev = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/kev"
    )
    assert rejected_kev.status_code == 502

    legitimate_kev = {
        **future_kev,
        "catalogVersion": "2026.07.18",
        "dateReleased": "2026-07-18T09:00:00Z",
    }
    client.app.state.http_client_factory = _http_client_factory(legitimate_kev)
    recovered_kev = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/kev"
    )
    assert recovered_kev.status_code == 200, recovered_kev.text
    assert recovered_kev.json()["matched"] == 1

    future_epss = {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "access": "public",
        "total": 1,
        "offset": 0,
        "limit": 100,
        "data": [
            {
                "cve": "CVE-2099-12345",
                "epss": "0.99",
                "percentile": "0.99",
                "date": "2099-01-01",
            }
        ],
    }
    client.app.state.http_client_factory = _http_client_factory(future_epss)
    rejected_epss = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/epss"
    )
    assert rejected_epss.status_code == 502

    legitimate_epss = json.loads(json.dumps(future_epss))
    legitimate_epss["data"][0]["date"] = "2026-07-18"
    legitimate_epss["data"][0]["epss"] = "0.42"
    client.app.state.http_client_factory = _http_client_factory(legitimate_epss)
    recovered_epss = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/epss"
    )
    assert recovered_epss.status_code == 200, recovered_epss.text
    assert recovered_epss.json()["updated"] == 1

    future_nvd = json.loads(json.dumps(_nvd_payload()))
    future_nvd["timestamp"] = "2099-01-01T00:00:00.000"
    future_nvd["vulnerabilities"][0]["cve"]["lastModified"] = (
        "2099-01-01T00:00:00.000"
    )
    client.app.state.http_client_factory = _http_client_factory(future_nvd)
    rejected_nvd = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/nvd"
    )
    assert rejected_nvd.status_code == 502

    client.app.state.http_client_factory = _http_client_factory(_nvd_payload())
    recovered_nvd = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/nvd"
    )
    assert recovered_nvd.status_code == 200, recovered_nvd.text
    assert recovered_nvd.json()["updated"] == 1


def test_kev_and_epss_snapshots_reject_rollback_and_timestamp_reuse(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_scan(client, system_id, authorization_id)
    _import_review_and_correlate(
        client,
        system_id,
        [
            _canonical_vulnerability(
                cve_id="CVE-2099-12345",
                title="Monotonic provider fixture",
                affected_cpes=[
                    "cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*"
                ],
            )
        ],
    )
    kev_record = {
        "cveID": "CVE-2099-12345",
        "vendorProject": "Apache",
        "product": "HTTP Server",
        "vulnerabilityName": "Monotonic KEV fixture",
        "dateAdded": "2026-07-15",
        "shortDescription": "Fixture entry.",
        "requiredAction": "Apply vendor guidance.",
        "dueDate": "2026-08-05",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
        "cwes": [],
    }
    baseline_kev = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.07.17",
        "dateReleased": "2026-07-17T09:00:00Z",
        "count": 1,
        "vulnerabilities": [kev_record],
    }
    client.app.state.http_client_factory = _http_client_factory(baseline_kev)
    assert client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/kev"
    ).status_code == 200

    missing_record = {**kev_record, "cveID": "CVE-2099-99999"}
    stale_kev = {
        **baseline_kev,
        "catalogVersion": "2026.07.16",
        "dateReleased": "2026-07-16T09:00:00Z",
        "vulnerabilities": [missing_record],
    }
    client.app.state.http_client_factory = _http_client_factory(stale_kev)
    stale_response = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/kev"
    )
    assert stale_response.status_code == 200, stale_response.text
    assert stale_response.json()["updated"] == 0
    assert client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()["findings"][0]["is_kev"] is True

    reused_kev = {
        **baseline_kev,
        "vulnerabilities": [missing_record],
    }
    client.app.state.http_client_factory = _http_client_factory(reused_kev)
    assert client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/kev"
    ).status_code == 409

    baseline_epss = {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "access": "public",
        "total": 1,
        "offset": 0,
        "limit": 100,
        "data": [
            {
                "cve": "CVE-2099-12345",
                "epss": "0.70",
                "percentile": "0.90",
                "date": "2026-07-17",
            }
        ],
    }
    client.app.state.http_client_factory = _http_client_factory(baseline_epss)
    assert client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/epss"
    ).status_code == 200
    stale_epss = json.loads(json.dumps(baseline_epss))
    stale_epss["data"][0].update({"epss": "0.10", "date": "2026-07-16"})
    client.app.state.http_client_factory = _http_client_factory(stale_epss)
    stale_epss_response = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/epss"
    )
    assert stale_epss_response.status_code == 200, stale_epss_response.text
    assert stale_epss_response.json()["updated"] == 0
    assert client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()["findings"][0]["epss_score"] == 0.7
    reused_epss = json.loads(json.dumps(baseline_epss))
    reused_epss["data"][0]["epss"] = "0.20"
    client.app.state.http_client_factory = _http_client_factory(reused_epss)
    assert client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/epss"
    ).status_code == 409


def test_nvd_snapshot_rejects_rollback_and_reconciles_rejected_and_absent_cves(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_scan(client, system_id, authorization_id)
    baseline = _nvd_payload()
    client.app.state.http_client_factory = _http_client_factory(baseline)
    created = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/nvd"
    )
    assert created.status_code == 200, created.text

    stale = json.loads(json.dumps(baseline))
    stale["timestamp"] = "2026-07-16T11:55:00.000"
    stale["vulnerabilities"][0]["cve"]["lastModified"] = (
        "2026-07-16T11:00:00.000"
    )
    stale["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = (
        "Stale title must not replace current NVD evidence."
    )
    client.app.state.http_client_factory = _http_client_factory(stale)
    stale_response = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/nvd"
    )
    assert stale_response.status_code == 200, stale_response.text
    assert stale_response.json()["updated"] == 0
    current = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert "Stale title" not in current["findings"][0]["title"]

    reused = json.loads(json.dumps(baseline))
    reused["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = (
        "Different content at the same provider timestamp."
    )
    client.app.state.http_client_factory = _http_client_factory(reused)
    assert client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/nvd"
    ).status_code == 409

    rejected = json.loads(json.dumps(baseline))
    rejected["timestamp"] = "2026-07-18T11:55:00.000"
    rejected["vulnerabilities"][0]["cve"]["lastModified"] = (
        "2026-07-18T11:00:00.000"
    )
    rejected["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    client.app.state.http_client_factory = _http_client_factory(rejected)
    rejected_response = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/nvd"
    )
    assert rejected_response.status_code == 200, rejected_response.text
    retired = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert retired["findings"][0]["lifecycle_status"] == "fixed"
    assert retired["risks"][0]["status"] == "closed"

    restored = json.loads(json.dumps(baseline))
    restored["timestamp"] = "2026-07-19T11:55:00.000"
    restored["vulnerabilities"][0]["cve"]["lastModified"] = (
        "2026-07-19T11:00:00.000"
    )
    restored["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = (
        "Restored after NVD analysis resumed."
    )
    client.app.state.http_client_factory = _http_client_factory(restored)
    restored_response = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/nvd"
    )
    assert restored_response.status_code == 200, restored_response.text
    reopened = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert reopened["findings"][0]["lifecycle_status"] == "reopened"
    assert reopened["findings"][0]["title"] == "Restored after NVD analysis resumed."
    assert reopened["risks"][0]["status"] == "open"

    absent = {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-07-20T11:55:00.000",
        "vulnerabilities": [],
    }
    client.app.state.http_client_factory = _http_client_factory(absent)
    absent_response = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/nvd"
    )
    assert absent_response.status_code == 200, absent_response.text
    removed = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert removed["findings"][0]["lifecycle_status"] == "fixed"
    assert removed["risks"][0]["status"] == "closed"


def test_netbox_sync_persists_unreviewed_source_evidence_without_graph_promotion(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    fake_client = _NetBoxHttpClient()
    client.app.state.settings = client.app.state.settings.model_copy(
        update={
            "netbox_base_url": "https://netbox.example.test/",
            "netbox_token": SecretStr(NETBOX_CREDENTIAL),
            "netbox_allowed_hosts": ["netbox.example.test"],
        }
    )
    client.app.state.http_client_factory = _netbox_http_client_factory(fake_client)

    response = client.post(f"/api/v1/operational/systems/{system_id}/asset-sources/netbox/sync")

    assert response.status_code == 200, response.text
    snapshot = response.json()
    assert snapshot["approval_state"] == "unreviewed_source_snapshot"
    assert snapshot["record_count"] == 1
    assert snapshot["record_counts"] == {"device": 1}
    assert len(fake_client.requests) == 7
    assert NETBOX_CREDENTIAL not in response.text

    listing = client.get(f"/api/v1/operational/systems/{system_id}/asset-sources/snapshots")
    assert listing.status_code == 200
    assert listing.json() == [snapshot]
    detail = client.get(
        f"/api/v1/operational/systems/{system_id}/asset-sources/snapshots/{snapshot['id']}"
    )
    assert detail.status_code == 200
    assert detail.json()["records"][0]["kind"] == "device"
    assert detail.json()["records"][0]["source_only"] is True

    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["latest_architecture"] is None
    assert overview["assets"] == []


def test_canonical_import_cannot_self_assert_kev_or_use_universal_match_patterns(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_scan(client, system_id, authorization_id)
    valid_cpe = "cpe:2.3:a:apache:http_server:0.0.0:*:*:*:*:*:*:*"
    base_item = _canonical_vulnerability(
        cve_id="CVE-2099-99999",
        title="Untrusted generic enrichment",
        affected_cpes=[valid_cpe],
        cvss_score=9.9,
    )

    asserted_kev = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=_canonical_feed([{**base_item, "is_kev": True}]),
    )
    universal_cpe = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=_canonical_feed(
            [
                {
                    **base_item,
                    "cpes": ["*"],
                    "vulnerability": {
                        **base_item["vulnerability"],  # type: ignore[dict-item]
                        "affected_cpes": ["*"],
                    },
                }
            ]
        ),
    )
    empty_product = client.post(
        "/api/v1/operational/intelligence/records/import",
        json=_canonical_feed(
            [
                _canonical_threat(
                    external_id="threat--universal",
                    title="Universal product match",
                    affected_products=[""],
                )
            ]
        ),
    )

    assert asserted_kev.status_code == 422
    assert universal_cpe.status_code == 422
    assert empty_product.status_code == 422
    correlation = _import_review_and_correlate(
        client,
        system_id,
        [
            _canonical_threat(
                external_id="threat--substring-only",
                title="Ambiguous partial product name",
                affected_products=["Apache"],
            )
        ],
        feed_version="2",
    )
    assert correlation["threat_records_matched"] == 0
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["findings"] == []
    assert overview["risks"] == []


def test_legacy_per_system_intelligence_paths_are_not_exposed(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)

    for suffix in ("cves", "threats"):
        response = client.post(
            f"/api/v1/operational/systems/{system_id}/intelligence/{suffix}",
            json={},
        )
        assert response.status_code == 404

    internal_sync = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/internal"
    )
    assert internal_sync.status_code == 404
    assert internal_sync.json() == {"detail": "Not Found"}

    openapi_paths = client.get("/openapi.json").json()["paths"]
    assert (
        "/api/v1/operational/systems/{system_id}/intelligence/cves"
        not in openapi_paths
    )
    assert (
        "/api/v1/operational/systems/{system_id}/intelligence/threats"
        not in openapi_paths
    )
    assert (
        "/api/v1/operational/systems/{system_id}/intelligence/sync/internal"
        not in openapi_paths
    )


def test_latest_completed_scan_defines_current_graph_and_report_scope(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    first_scan_id = _import_scan(client, system_id, authorization_id)

    empty_scan = client.post(
        f"/api/v1/operational/systems/{system_id}/scans/import/nmap",
        params={"authorization_id": authorization_id},
        content=NMAP_EMPTY_XML,
        headers={"Content-Type": "application/xml"},
    )
    assert empty_scan.status_code == 201, empty_scan.text
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["assets"] == []
    assert overview["services"] == []
    assert overview["latest_architecture"]["graph"]["nodes"] == []

    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/scans",
        json={"authorization_id": authorization_id, "scanner": "nmap"},
    )
    assert queued.status_code == 202
    report = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "json", "report_type": "technical"},
    )
    download = client.get(f"/api/v1/operational/reports/{report.json()['id']}/download")
    report_snapshot = download.json()
    assert report_snapshot["latest_scan"]["id"] == empty_scan.json()["id"]
    assert report_snapshot["latest_scan"]["id"] != first_scan_id
    assert report_snapshot["latest_scan"]["id"] != queued.json()["id"]
    assert report_snapshot["assets"] == []


def test_identical_inventory_scan_recorrelates_existing_threats(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_scan(client, system_id, authorization_id)
    correlation = _import_review_and_correlate(
        client,
        system_id,
        [
            _canonical_threat(
                external_id="threat--old-snapshot",
                title="Threat correlated to the first scan",
                affected_products=["Apache httpd"],
            )
        ],
    )
    assert correlation["threats_created"] == 1
    first_overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert len(first_overview["threats"]) == 1
    assert len(first_overview["risks"]) == 1

    second_scan = client.post(
        f"/api/v1/operational/systems/{system_id}/scans/import/nmap",
        params={"authorization_id": authorization_id},
        content=NMAP_XML.replace(b'time="1784325600"', b'time="1784325720"'),
        headers={"Content-Type": "application/xml"},
    )
    assert second_scan.status_code == 201, second_scan.text

    current = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert len(current["assets"]) == 1
    assert len(current["threats"]) == 1
    assert len(current["risks"]) == 1

    register = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "json", "report_type": "risk_register"},
    )
    payload = client.get(
        f"/api/v1/operational/reports/{register.json()['id']}/download"
    ).json()
    assert payload["summary"] == {"closed": 0, "open": 1, "retired": 0, "total": 1}
    assert payload["risks"][0]["status"] == "open"
    assert payload["risks"][0]["recorded_status"] == "open"


def test_risk_register_retains_closed_risk_for_retired_threat(
    client: TestClient,
) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_scan(client, system_id, authorization_id)
    correlation = _import_review_and_correlate(
        client,
        system_id,
        [
            _canonical_threat(
                external_id="threat--retired-report-history",
                title="Threat retained in risk history",
                affected_products=["Apache httpd"],
            )
        ],
    )
    assert correlation["threats_created"] == 1

    empty_scan = client.post(
        f"/api/v1/operational/systems/{system_id}/scans/import/nmap",
        params={"authorization_id": authorization_id},
        content=NMAP_EMPTY_XML,
        headers={"Content-Type": "application/xml"},
    )
    assert empty_scan.status_code == 201, empty_scan.text
    retired = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert retired.status_code == 200, retired.text
    assert client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()["risks"] == []

    register = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "json", "report_type": "risk_register"},
    )
    register_payload = client.get(
        f"/api/v1/operational/reports/{register.json()['id']}/download"
    ).json()
    assert register_payload["summary"] == {
        "closed": 1,
        "open": 0,
        "retired": 0,
        "total": 1,
    }
    assert register_payload["risks"][0]["status"] == "closed"

    management = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "json", "report_type": "management"},
    )
    management_payload = client.get(
        f"/api/v1/operational/reports/{management.json()['id']}/download"
    ).json()
    assert management_payload["prioritized_open_risks"] == []
    assert management_payload["summary"]["open_risks"] == 0
    assert management_payload["summary"]["closed_risks"] == 1


def test_csv_report_neutralizes_formula_like_imported_titles(client: TestClient) -> None:
    _, system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_scan(client, system_id, authorization_id)
    correlation = _import_review_and_correlate(
        client,
        system_id,
        [
            _canonical_threat(
                external_id="threat--formula",
                title='=WEBSERVICE("https://invalid.example")',
                affected_products=["Apache httpd"],
            )
        ],
    )
    assert correlation["threats_created"] == 1
    report = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "csv", "report_type": "risk_register"},
    )
    download = client.get(f"/api/v1/operational/reports/{report.json()['id']}/download")

    assert download.status_code == 200
    assert "'=WEBSERVICE" in download.content.decode("utf-8-sig")
