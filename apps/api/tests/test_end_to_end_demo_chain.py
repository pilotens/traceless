import base64
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from pydantic import SecretStr

from traceless_api.core.config import ExternalIntelligenceCredentialBinding
from traceless_api.publisher.app import create_publisher_app
from traceless_api.publisher.config import PublisherSettings

ADMIN_KEY = "demo-e2e-admin-" + "a" * 32
INGEST_KEY = "demo-e2e-ingest-" + "b" * 32
REVIEWER_KEY = "demo-e2e-review-" + "c" * 32
CURSOR_SECRET = "demo-e2e-cursor-" + "d" * 32
SIGNING_SEED = base64.b64encode(bytes(range(32))).decode("ascii")
PUBLISHER_ORIGIN = "https://publisher.example.test"
PUBLISHER_ENDPOINT = f"{PUBLISHER_ORIGIN}/v2/datapoints"
CREDENTIAL_REFERENCE = "demo-publisher"

NMAP_SOURCE_TIME = int(datetime.now(UTC).timestamp()) - 300

NMAP_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.99">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="100.64.42.10" addrtype="ipv4"/>
    <address addr="02:42:AC:11:00:42" addrtype="mac" vendor="Traceless Demo"/>
    <hostnames><hostname name="demo-gateway.internal" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Example Gateway" version="1.0.0" conf="10">
          <cpe>cpe:2.3:a:example:gateway:1.0.0:*:*:*:*:*:*:*</cpe>
        </service>
      </port>
    </ports>
    <os><osmatch name="Linux 6.x" accuracy="96"/></os>
  </host>
  <runstats><finished time="{NMAP_SOURCE_TIME}" exit="success"/></runstats>
</nmaprun>
""".encode()


def _headers(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _publisher_item(
    *,
    external_id: str,
    source_kind: str,
    record_type: str,
    title: str,
    observed_at: datetime,
    vulnerability: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "status": "active",
        "status_changed_at": None,
        "status_reason": None,
        "record": {
            "source_kind": source_kind,
            "provider": "traceless-demo-publisher",
            "external_id": external_id,
            "record_type": record_type,
            "title": title,
            "summary": "Controlled, source-grounded end-to-end demo intelligence.",
            "modified_at": observed_at.isoformat(),
            "retrieved_at": observed_at.isoformat(),
            "severity": "critical" if record_type == "vulnerability" else "high",
            "cve_ids": ["CVE-2099-4242"],
            "cpes": (
                ["cpe:2.3:a:example:gateway:1.0.0:*:*:*:*:*:*:*"]
                if record_type == "vulnerability"
                else []
            ),
            "affected_products": ["Example Gateway"],
            "mitre_attack_ids": ["T1190"],
            "indicators": [],
            "tags": ["demo", "initial-access"],
            "sectors": [],
            "regions": ["SE"],
            "markings": ["TLP:CLEAR"],
            "revoked": False,
            "raw_evidence": {"demo": True, "external_id": external_id},
            "vulnerability": vulnerability,
        },
    }


@dataclass
class _PublisherResponse:
    content: bytes
    headers: dict[str, str]
    status_code: int

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"publisher returned {self.status_code}")

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        yield self.content


class _PublisherHttpClient:
    def __init__(self, publisher: TestClient) -> None:
        self.publisher = publisher
        self.requests: list[dict[str, object]] = []

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = False,
    ) -> AsyncIterator[_PublisherResponse]:
        assert method == "GET"
        assert url == PUBLISHER_ENDPOINT
        assert timeout is not None
        assert follow_redirects is False
        self.requests.append({"url": url, "params": dict(params or {})})
        response = self.publisher.get(
            "/v2/datapoints",
            headers=dict(headers or {}),
            params=dict(params or {}),
        )
        yield _PublisherResponse(
            content=response.content,
            headers=dict(response.headers),
            status_code=response.status_code,
        )


def test_publisher_to_customer_scan_correlation_risk_and_report(client: TestClient) -> None:
    publisher_app = create_publisher_app(
        PublisherSettings(
            environment="test",
            database_url="sqlite+pysqlite:///:memory:",
            auto_create_schema=True,
            admin_api_key=ADMIN_KEY,
            ingest_api_key=INGEST_KEY,
            reviewer_api_key=REVIEWER_KEY,
            cursor_secret=CURSOR_SECRET,
            signing_private_key=SIGNING_SEED,
            signing_key_id="demo-e2e-signing-key",
            allowed_hosts=["testserver"],
        )
    )

    with TestClient(publisher_app) as publisher:
        account = publisher.post(
            "/admin/v2/accounts",
            headers=_headers(ADMIN_KEY),
            json={"account_key": "demo-customer", "name": "Demo customer", "enabled": True},
        )
        assert account.status_code == 201, account.text
        installation = publisher.post(
            "/admin/v2/accounts/demo-customer/installations",
            headers=_headers(ADMIN_KEY),
            json={
                "client_id": "demo-customer-production",
                "installation_key": "production",
                "environment": "production",
                "region": "se-central",
                "name": "Demo production",
                "enabled": True,
                "max_tlp": "TLP:AMBER",
                "allowed_providers": ["traceless-demo-publisher"],
                "allowed_source_kinds": ["vulnerability", "news"],
            },
        )
        assert installation.status_code == 201, installation.text
        customer_key = installation.json()["api_key"]

        observed_at = datetime.now(UTC)
        imported = publisher.post(
            "/admin/v1/imports",
            headers=_headers(INGEST_KEY),
            json={
                "feed_id": "traceless-demo-feed",
                "feed_version": "demo-1",
                "generated_at": observed_at.isoformat(),
                "idempotency_key": "traceless-demo-e2e-1",
                "publish": False,
                "items": [
                    _publisher_item(
                        external_id="traceless-demo-cve-2099-4242",
                        source_kind="vulnerability",
                        record_type="vulnerability",
                        title="Demo gateway remote-code-execution exposure",
                        observed_at=observed_at,
                        vulnerability={
                            "affected_cpes": [
                                "cpe:2.3:a:example:gateway:1.0.0:*:*:*:*:*:*:*"
                            ],
                            "cvss_score": 9.8,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "epss_score": 0.91,
                            "epss_percentile": 0.99,
                            "exploit_status": "poc",
                        },
                    ),
                    _publisher_item(
                        external_id="traceless-demo-campaign-1",
                        source_kind="news",
                        record_type="threat",
                        title="Demo campaign targeting exposed gateways",
                        observed_at=observed_at + timedelta(seconds=1),
                    ),
                ],
            },
        )
        assert imported.status_code == 200, imported.text
        for record_id in imported.json()["record_ids"].values():
            published = publisher.post(
                f"/admin/v1/records/{record_id}/publish",
                headers=_headers(REVIEWER_KEY),
                json={"reason": "Controlled demo evidence reviewed for the end-to-end test."},
            )
            assert published.status_code == 200, published.text

        key_set = publisher.get("/.well-known/traceless-intelligence-signing-keys")
        assert key_set.status_code == 200
        public_key = key_set.json()["keys"][0]["public_key_base64"]

        organization_key = client.app.state.settings.operational_organization_key
        client.app.state.settings = client.app.state.settings.model_copy(
            update={
                "intelligence_allowed_hosts": [
                    *client.app.state.settings.intelligence_allowed_hosts,
                    "publisher.example.test",
                ],
                "external_intelligence_credentials": {
                    organization_key: {
                        CREDENTIAL_REFERENCE: ExternalIntelligenceCredentialBinding(
                            secret=SecretStr(customer_key),
                            origin=PUBLISHER_ORIGIN,
                            signing_keys={"demo-e2e-signing-key": public_key},
                            require_signature=True,
                        )
                    }
                },
            }
        )
        proxy = _PublisherHttpClient(publisher)

        @asynccontextmanager
        async def proxy_factory() -> AsyncIterator[_PublisherHttpClient]:
            yield proxy

        client.app.state.http_client_factory = proxy_factory
        configured = client.put(
            "/api/v1/operational/intelligence/connectors/external",
            json={
                "endpoint": PUBLISHER_ENDPOINT,
                "auth_scheme": "Bearer",
                "credential_reference": CREDENTIAL_REFERENCE,
                "enabled": True,
                "sync_interval_seconds": None,
            },
        )
        assert configured.status_code == 200, configured.text
        pulled = client.post(
            "/api/v1/operational/intelligence/sync/external",
            json={"max_pages": 10},
            headers={"X-Actor": "demo-e2e-test"},
        )
        assert pulled.status_code == 200, pulled.text
        assert pulled.json()["created"] == 2
        assert pulled.json()["complete"] is True
        assert proxy.requests

    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "[DEMO] Traceless end-to-end", "description": "E2E test project"},
    )
    assert project.status_code == 201, project.text
    system = client.post(
        f"/api/v1/operational/projects/{project.json()['id']}/systems",
        json={
            "name": "Demo Internet Gateway",
            "description": "Controlled full-chain test system",
            "owner": "Traceless Demo",
            "criticality": "critical",
        },
    )
    assert system.status_code == 201, system.text
    system_id = system.json()["id"]
    authorization = client.post(
        f"/api/v1/operational/systems/{system_id}/scan-authorizations",
        json={
            "targets": ["100.64.42.10/32"],
            "profile": "service_inventory",
            "approved_by": "Traceless Demo",
            "purpose": "Controlled imported inventory for an end-to-end test",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "confirmation": "Jag bekräftar att jag har tillstånd att skanna angivna mål.",
        },
    )
    assert authorization.status_code == 201, authorization.text
    scan = client.post(
        f"/api/v1/operational/systems/{system_id}/scans/import/nmap",
        params={"authorization_id": authorization.json()["id"]},
        content=NMAP_XML,
        headers={"Content-Type": "application/xml", "X-Actor": "demo-e2e-test"},
    )
    assert scan.status_code == 201, scan.text
    assert scan.json()["result_summary"]["assets_observed"] == 1
    assert scan.json()["result_summary"]["services_observed"] == 1

    pending = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending", "query": "traceless-demo", "limit": 20},
    )
    assert pending.status_code == 200, pending.text
    assert len(pending.json()["items"]) == 2
    for record in pending.json()["items"]:
        reviewed = client.patch(
            f"/api/v1/operational/intelligence/records/{record['id']}/review",
            json={
                "decision": "approved",
                "note": "Controlled publisher evidence approved by the end-to-end test.",
            },
        )
        assert reviewed.status_code == 200, reviewed.text

    correlated = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert correlated.status_code == 200, correlated.text
    result = correlated.json()
    assert result["findings_created"] == 1
    assert result["threats_created"] == 1
    assert result["risks_created"] >= 1

    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview")
    assert overview.status_code == 200
    payload = overview.json()
    assert payload["assets"][0]["primary_ip"] == "100.64.42.10"
    assert payload["services"][0]["product"] == "Example Gateway"
    assert payload["findings"][0]["cve_id"] == "CVE-2099-4242"
    assert payload["findings"][0]["epss_score"] == 0.91
    assert payload["threats"][0]["attack_patterns"] == ["T1190"]
    assert payload["risks"]

    report = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "pdf", "report_type": "management"},
    )
    assert report.status_code == 201, report.text
    downloaded = client.get(
        f"/api/v1/operational/reports/{report.json()['id']}/download"
    )
    assert downloaded.status_code == 200
    assert downloaded.content.startswith(b"%PDF-")
    assert downloaded.headers["x-content-sha256"] == report.json()["sha256"]
