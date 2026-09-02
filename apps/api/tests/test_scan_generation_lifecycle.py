from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from traceless_api.db.models import (
    AssetAliasRow,
    AssetObservationRow,
    AssetRow,
    FindingRow,
    ScanJobRow,
)

BASE_SOURCE_TIME = int(datetime.now(UTC).timestamp()) - 300


def _create_system(client: TestClient) -> str:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Generation project", "description": "Lifecycle regression"},
    ).json()
    response = client.post(
        f"/api/v1/operational/projects/{project['id']}/systems",
        json={
            "name": "Generation target",
            "description": "Authoritative inventory target",
            "owner": "Security",
            "criticality": "high",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _authorize(
    client: TestClient,
    system_id: str,
    *,
    targets: list[str] | None = None,
    profile: str = "service_inventory",
) -> str:
    response = client.post(
        f"/api/v1/operational/systems/{system_id}/scan-authorizations",
        json={
            "targets": targets or ["100.64.0.10"],
            "profile": profile,
            "approved_by": "System owner",
            "purpose": "Generation lifecycle regression",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "confirmation": "Jag bekräftar att jag har tillstånd att skanna angivna mål.",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _nmap_xml(
    *,
    completed_at: int,
    hosts: list[dict[str, object]],
    complete: bool = True,
) -> bytes:
    host_xml: list[str] = []
    for host in hosts:
        mac = (
            f'<address addr="{host["mac"]}" addrtype="mac"/>'
            if host.get("mac")
            else ""
        )
        hostname = (
            f'<hostnames><hostname name="{host["hostname"]}" type="PTR"/></hostnames>'
            if host.get("hostname")
            else ""
        )
        ports = "".join(
            f"""<port protocol="{service.get('protocol', 'tcp')}" portid="{service['port']}">
              <state state="{service.get('state', 'open')}"/>
              <service name="https" product="{service.get('product', 'service')}"/>
            </port>"""
            for service in host.get("services", [])
        )
        host_xml.append(
            f"""<host><status state="up"/>
              <address addr="{host['ip']}" addrtype="ipv4"/>{mac}{hostname}
              <ports>{ports}</ports>
            </host>"""
        )
    finished = (
        f'<runstats><finished time="{completed_at}" exit="success"/></runstats>'
        if complete
        else ""
    )
    return (
        f"""<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.99" start="{completed_at - 10}">
          {''.join(host_xml)}{finished}
        </nmaprun>"""
    ).encode()


def _import_nmap(
    client: TestClient,
    system_id: str,
    authorization_id: str,
    payload: bytes,
) -> dict[str, object]:
    response = client.post(
        f"/api/v1/operational/systems/{system_id}/scans/import/nmap",
        params={"authorization_id": authorization_id},
        content=payload,
        headers={"Content-Type": "application/xml"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _vendor_cve(client: TestClient, system_id: str) -> dict[str, object]:
    observed_at = datetime.fromtimestamp(BASE_SOURCE_TIME + 60, UTC).isoformat()
    response = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import",
        json={
            "provider": "qualys",
            "source_name": "endpoint.json",
            "scan_completed_at": observed_at,
            "observations": [
                {
                    "provider_finding_id": "QID-443",
                    "asset_identifier": "api.example.test",
                    "ip_address": "100.64.0.10",
                    "hostname": "api.example.test",
                    "port": 443,
                    "protocol": "tcp",
                    "title": "Endpoint vulnerability",
                    "severity": "high",
                    "state": "open",
                    "cve_ids": ["CVE-2099-44300"],
                    "cvss_score": 8.8,
                    "evidence": {"authenticated": True},
                    "observed_at": observed_at,
                }
            ],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_older_complete_scan_is_historical_and_cannot_replace_inventory(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    current = _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME + 120,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "current.example.test",
                    "services": [{"port": 443, "product": "current-service"}],
                }
            ],
        ),
    )
    assert current["result_summary"]["is_current_inventory"] is True

    historical = _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "old.example.test",
                    "services": [{"port": 80, "product": "old-service"}],
                }
            ],
        ),
    )
    assert historical["result_summary"]["inventory_role"] == "historical"
    assert historical["result_summary"]["is_current_inventory"] is False
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["assets"][0]["hostname"] == "current.example.test"
    assert [service["port"] for service in overview["services"]] == [443]


def test_stale_first_scan_is_retained_but_never_becomes_current(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    stale = _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=1_700_000_000,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "archive.example.test",
                    "services": [{"port": 443}],
                }
            ],
        ),
    )
    assert stale["result_summary"]["source_time_status"] == "stale"
    assert stale["result_summary"]["inventory_role"] == "historical"
    assert stale["result_summary"]["is_current_inventory"] is False
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["assets"] == []
    assert overview["services"] == []


def test_partial_and_discovery_scans_do_not_close_findings_or_replace_inventory(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    inventory_authorization = _authorize(client, system_id)
    _import_nmap(
        client,
        system_id,
        inventory_authorization,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "api.example.test",
                    "services": [{"port": 443, "product": "api-service"}],
                }
            ],
        ),
    )
    assert _vendor_cve(client, system_id)["promoted_findings"] == 1

    partial = _import_nmap(
        client,
        system_id,
        inventory_authorization,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME + 60,
            hosts=[{"ip": "100.64.0.10", "hostname": "api.example.test", "services": []}],
            complete=False,
        ),
    )
    assert partial["result_summary"]["completeness"] == "partial"
    assert partial["result_summary"]["is_current_inventory"] is False

    discovery_authorization = _authorize(
        client, system_id, profile="discovery"
    )
    discovery = _import_nmap(
        client,
        system_id,
        discovery_authorization,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME + 120,
            hosts=[{"ip": "100.64.0.10", "hostname": "api.example.test", "services": []}],
        ),
    )
    assert discovery["result_summary"]["completeness"] == "discovery"
    assert discovery["result_summary"]["is_current_inventory"] is False

    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert [service["port"] for service in overview["services"]] == [443]
    assert overview["findings"][0]["lifecycle_status"] == "open"


def test_later_mac_address_merges_with_ip_identity_and_keeps_observations(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    first = _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME,
            hosts=[{"ip": "100.64.0.10", "hostname": "api.example.test", "services": []}],
        ),
    )
    first_asset_id = client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    ).json()["assets"][0]["id"]
    second = _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME + 60,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "api.example.test",
                    "mac": "02:42:AC:11:00:02",
                    "services": [],
                }
            ],
        ),
    )
    assert first["id"] != second["id"]
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["assets"][0]["id"] == first_asset_id
    assert overview["assets"][0]["mac_address"] == "02:42:ac:11:00:02"
    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count(AssetRow.id))) == 1
        assert session.scalar(select(func.count(AssetObservationRow.id))) == 2
        aliases = set(
            session.execute(
                select(AssetAliasRow.kind, AssetAliasRow.value_normalized)
            ).all()
        )
        assert ("ip", "100.64.0.10") in aliases
        assert ("mac", "02:42:ac:11:00:02") in aliases


def test_ip_reuse_between_distinct_mac_identities_does_not_merge_assets(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    authorization_id = _authorize(
        client,
        system_id,
        targets=["100.64.0.10", "100.64.0.11"],
    )
    _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "old.example.test",
                    "mac": "02:42:AC:11:00:0A",
                    "services": [],
                },
                {
                    "ip": "100.64.0.11",
                    "hostname": "moving.example.test",
                    "mac": "02:42:AC:11:00:0B",
                    "services": [],
                },
            ],
        ),
    )
    with client.app.state.session_factory() as session:
        moving_id = session.scalar(
            select(AssetRow.id).where(
                AssetRow.mac_address == "02:42:ac:11:00:0b"
            )
        )
        assert moving_id is not None

    _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME + 60,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "moving.example.test",
                    "mac": "02:42:AC:11:00:0B",
                    "services": [],
                }
            ],
        ),
    )
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert [asset["id"] for asset in overview["assets"]] == [str(moving_id)]
    with client.app.state.session_factory() as session:
        assets = list(session.scalars(select(AssetRow).order_by(AssetRow.mac_address)))
        assert len(assets) == 2
        assert [asset.inventory_status for asset in assets] == ["unobserved", "current"]
        ip_alias = session.scalar(
            select(AssetAliasRow).where(
                AssetAliasRow.kind == "ip",
                AssetAliasRow.value_normalized == "100.64.0.10",
            )
        )
        assert ip_alias is not None
        assert ip_alias.asset_id == moving_id


def test_historical_scan_cannot_move_a_live_ip_alias_backwards(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME + 120,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "current.example.test",
                    "mac": "02:42:AC:11:00:0A",
                    "services": [],
                }
            ],
        ),
    )
    with client.app.state.session_factory() as session:
        current_id = session.scalar(
            select(AssetRow.id).where(
                AssetRow.mac_address == "02:42:ac:11:00:0a"
            )
        )
        assert current_id is not None

    historical = _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "historical.example.test",
                    "mac": "02:42:AC:11:00:0B",
                    "services": [],
                }
            ],
        ),
    )
    assert historical["result_summary"]["inventory_role"] == "historical"
    with client.app.state.session_factory() as session:
        ip_alias = session.scalar(
            select(AssetAliasRow).where(
                AssetAliasRow.kind == "ip",
                AssetAliasRow.value_normalized == "100.64.0.10",
            )
        )
        assert ip_alias is not None
        assert ip_alias.asset_id == current_id
        assert session.scalar(select(func.count(AssetRow.id))) == 2


def test_complete_generation_marks_covered_missing_asset_unobserved(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    authorization_id = _authorize(
        client,
        system_id,
        targets=["100.64.0.10", "100.64.0.11"],
    )
    _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME,
            hosts=[
                {"ip": "100.64.0.10", "hostname": "one.example.test", "services": []},
                {"ip": "100.64.0.11", "hostname": "two.example.test", "services": []},
            ],
        ),
    )
    _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME + 60,
            hosts=[{"ip": "100.64.0.10", "hostname": "one.example.test", "services": []}],
        ),
    )
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert [asset["primary_ip"] for asset in overview["assets"]] == ["100.64.0.10"]
    with client.app.state.session_factory() as session:
        statuses = dict(
            session.execute(select(AssetRow.primary_ip, AssetRow.inventory_status)).all()
        )
        assert statuses == {
            "100.64.0.10": "current",
            "100.64.0.11": "unobserved",
        }
        assert session.scalar(select(func.count(AssetObservationRow.id))) == 3


def test_closed_port_is_immutable_evidence_but_not_a_matchable_endpoint(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    scan = _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "api.example.test",
                    "services": [{"port": 443, "state": "closed"}],
                }
            ],
        ),
    )
    assert scan["result_summary"]["services_observed"] == 1
    overview = client.get(f"/api/v1/operational/systems/{system_id}/overview").json()
    assert overview["services"] == []
    assert _vendor_cve(client, system_id)["promoted_findings"] == 0


def test_nessus_presence_does_not_become_absence_when_correlation_temporarily_fails(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    authorization_id = _authorize(client, system_id)
    _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "api.example.test",
                    "services": [{"port": 443}],
                }
            ],
        ),
    )
    endpoint = f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import"
    first_completed_at = datetime.fromtimestamp(
        BASE_SOURCE_TIME + 60, UTC
    ).isoformat()
    second_completed_at = datetime.fromtimestamp(
        BASE_SOURCE_TIME + 180, UTC
    ).isoformat()

    def payload(
        completed_at: str,
        source_name: str,
        *,
        ip_address: str = "100.64.0.10",
        hostname: str = "api.example.test",
    ) -> dict[str, object]:
        return {
            "provider": "nessus",
            "source_name": source_name,
            "scan_completed_at": completed_at,
            "report_metadata": {
                "snapshot_complete": True,
                "snapshot_series_id": "stable-api-scan",
            },
            "observations": [
                {
                    "provider_finding_id": "19506",
                    "asset_identifier": hostname,
                    "ip_address": ip_address,
                    "hostname": hostname,
                    "port": 443,
                    "protocol": "tcp",
                    "title": "Still reported by Nessus",
                    "severity": "high",
                    "state": "open",
                    "cve_ids": ["CVE-2099-19506"],
                    "cvss_score": 8.0,
                    "observed_at": completed_at,
                }
            ],
        }

    opened = client.post(endpoint, json=payload(first_completed_at, "first.json"))
    assert opened.status_code == 201, opened.text
    assert opened.json()["promoted_findings"] == 1

    # The vendor still reports the same source identity, but the current
    # inventory temporarily lacks an open endpoint to correlate it to.
    _import_nmap(
        client,
        system_id,
        authorization_id,
        _nmap_xml(
            completed_at=BASE_SOURCE_TIME + 120,
            hosts=[
                {
                    "ip": "100.64.0.10",
                    "hostname": "api.example.test",
                    "services": [{"port": 443, "state": "closed"}],
                }
            ],
        ),
    )

    present = client.post(
        endpoint,
        json=payload(second_completed_at, "second.json"),
    )
    assert present.status_code == 201, present.text
    assert present.json()["promoted_findings"] == 0
    with client.app.state.session_factory() as session:
        finding = session.scalar(select(FindingRow))
        assert finding is not None
        assert finding.lifecycle_status == "open"
        scans = list(
            session.scalars(
                select(ScanJobRow).where(ScanJobRow.is_current_inventory.is_(True))
            )
        )
        assert len(scans) == 1
