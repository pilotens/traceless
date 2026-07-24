import subprocess
import sys
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from traceless_api.db.models import (
    ArchitectureSnapshotRow,
    AssetRow,
    AuditEventRow,
    ScanJobRow,
    ServiceRow,
)
from traceless_api.worker import (
    ScanCancelledError,
    ScanLeaseLostError,
    _cancel_owned_scan,
    _record_owned_scan_failure,
    _run_process,
    _ScanLeaseMonitor,
    process_next_scan,
)

NMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.99">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="100.64.0.10" addrtype="ipv4"/>
    <ports/>
  </host>
  <runstats><finished time="1784325600" exit="success"/></runstats>
</nmaprun>
"""


def _nmap_xml(*, hostname: str, port: int) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.99">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="100.64.0.10" addrtype="ipv4"/>
    <hostnames><hostname name="{hostname}" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="{port}">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="fenced-service" version="1.0" conf="10"/>
      </port>
    </ports>
  </host>
  <runstats><finished time="1784325600" exit="success"/></runstats>
</nmaprun>
""".encode()


def _queued_scan(client: TestClient) -> dict[str, object]:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Worker leases", "description": "Recovery tests"},
    ).json()
    system = client.post(
        f"/api/v1/operational/projects/{project['id']}/systems",
        json={
            "name": "Lease target",
            "description": "Authorized test target",
            "owner": "Security",
            "criticality": "medium",
        },
    ).json()
    authorization = client.post(
        f"/api/v1/operational/systems/{system['id']}/scan-authorizations",
        json={
            "targets": ["100.64.0.10"],
            "profile": "discovery",
            "approved_by": "System owner",
            "purpose": "Authorized worker lease and cancellation test",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "confirmation": "Jag bekräftar att jag har tillstånd att skanna angivna mål.",
        },
    ).json()
    response = client.post(
        f"/api/v1/operational/systems/{system['id']}/scans",
        json={"authorization_id": authorization["id"], "scanner": "nmap"},
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_queued_scan_can_be_cancelled_before_execution(client: TestClient) -> None:
    queued = _queued_scan(client)

    cancelled = client.post(f"/api/v1/operational/scans/{queued['id']}/cancel")

    assert cancelled.status_code == 202
    assert cancelled.json()["status"] == "cancelled"
    enabled = client.app.state.settings.model_copy(update={"nmap_enabled": True})
    assert not process_next_scan(
        settings=enabled, session_factory=client.app.state.session_factory
    )


def test_expired_worker_lease_is_recovered_with_bounded_attempts(client: TestClient) -> None:
    queued = _queued_scan(client)
    with client.app.state.session_factory() as session:
        row = session.get(ScanJobRow, UUID(str(queued["id"])))
        assert row is not None
        row.status = "running"
        row.claimed_by = "crashed-worker"
        row.attempt_count = 1
        row.started_at = datetime.now(UTC) - timedelta(minutes=10)
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    def successful_runner(
        argv: list[str] | tuple[str, ...], _: int, __: int
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 0, stdout=NMAP_XML, stderr=b"")

    enabled = client.app.state.settings.model_copy(update={"nmap_enabled": True})
    assert process_next_scan(
        settings=enabled,
        session_factory=client.app.state.session_factory,
        runner=successful_runner,
    )

    completed = client.get(f"/api/v1/operational/scans/{queued['id']}").json()
    assert completed["status"] == "completed"
    assert completed["attempt_count"] == 2
    assert completed["claimed_by"] is None
    assert completed["lease_expires_at"] is None
    assert "lease_token" not in completed
    with client.app.state.session_factory() as session:
        row = session.get(ScanJobRow, UUID(str(queued["id"])))
        assert row is not None
        assert row.lease_token is None
    with client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEventRow).where(
                AuditEventRow.action == "scan.completed",
                AuditEventRow.resource_id == str(queued["id"]),
            )
        )
        assert event is not None
        assert event.organization_id is not None


def test_cancelled_running_scan_is_terminalized_after_worker_lease_expires(
    client: TestClient,
) -> None:
    queued = _queued_scan(client)
    scan_id = UUID(str(queued["id"]))
    with client.app.state.session_factory() as session:
        row = session.get(ScanJobRow, scan_id)
        assert row is not None
        row.status = "running"
        row.claimed_by = "crashed-worker"
        row.lease_token = "a" * 64
        row.started_at = datetime.now(UTC) - timedelta(minutes=10)
        row.heartbeat_at = datetime.now(UTC) - timedelta(minutes=5)
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        row.cancel_requested_at = datetime.now(UTC)
        session.commit()

    enabled = client.app.state.settings.model_copy(update={"nmap_enabled": True})
    assert not process_next_scan(
        settings=enabled,
        session_factory=client.app.state.session_factory,
    )

    cancelled = client.get(f"/api/v1/operational/scans/{scan_id}").json()
    assert cancelled["status"] == "cancelled"
    assert cancelled["claimed_by"] is None
    assert cancelled["lease_expires_at"] is None
    with client.app.state.session_factory() as session:
        row = session.get(ScanJobRow, scan_id)
        assert row is not None
        assert row.lease_token is None
        event = session.scalar(
            select(AuditEventRow).where(
                AuditEventRow.action == "scan.cancelled",
                AuditEventRow.resource_id == str(scan_id),
            )
        )
        assert event is not None
        assert event.details["reason"] == "cancelled_after_worker_lease_expired"


def test_exhausted_expired_lease_fails_without_reexecution(client: TestClient) -> None:
    queued = _queued_scan(client)
    with client.app.state.session_factory() as session:
        row = session.get(ScanJobRow, UUID(str(queued["id"])))
        assert row is not None
        row.status = "running"
        row.claimed_by = "crashed-worker"
        row.attempt_count = row.max_attempts
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    enabled = client.app.state.settings.model_copy(update={"nmap_enabled": True})
    assert not process_next_scan(
        settings=enabled, session_factory=client.app.state.session_factory
    )
    failed = client.get(f"/api/v1/operational/scans/{queued['id']}").json()
    assert failed["status"] == "failed"
    assert failed["error_code"] == "worker_lease_exhausted"
    with client.app.state.session_factory() as session:
        row = session.get(ScanJobRow, UUID(str(queued["id"])))
        assert row is not None
        assert row.claimed_by is None
        assert row.lease_token is None
        assert row.lease_expires_at is None


def test_same_worker_reclaim_token_fences_stale_attempt_and_all_terminal_writes(
    client: TestClient,
) -> None:
    queued = _queued_scan(client)
    scan_id = UUID(str(queued["id"]))
    with client.app.state.session_factory() as session:
        queued_row = session.get(ScanJobRow, scan_id)
        assert queued_row is not None
        organization_id = queued_row.organization_id
    settings = client.app.state.settings.model_copy(
        update={"nmap_enabled": True, "scan_worker_id": "collision-worker"}
    )
    session_factory = client.app.state.session_factory
    attempt_tokens: list[str] = []
    claimed_by: list[str] = []

    def outer_runner(
        argv: list[str] | tuple[str, ...], _: int, __: int
    ) -> subprocess.CompletedProcess[bytes]:
        with session_factory() as session:
            row = session.get(ScanJobRow, scan_id)
            assert row is not None
            assert row.lease_token is not None
            assert row.claimed_by is not None
            attempt_tokens.append(row.lease_token)
            claimed_by.append(row.claimed_by)
            row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            session.commit()

        def reclaimed_runner(
            reclaimed_argv: list[str] | tuple[str, ...], ___: int, ____: int
        ) -> subprocess.CompletedProcess[bytes]:
            with session_factory() as session:
                row = session.get(ScanJobRow, scan_id)
                assert row is not None
                assert row.lease_token is not None
                assert row.claimed_by is not None
                attempt_tokens.append(row.lease_token)
                claimed_by.append(row.claimed_by)

            stale_monitor = _ScanLeaseMonitor(
                session_factory=session_factory,
                scan_id=scan_id,
                organization_id=organization_id,
                worker_id=claimed_by[0],
                lease_token=attempt_tokens[0],
                lease_seconds=60,
                heartbeat_seconds=15,
            )
            with pytest.raises(ScanLeaseLostError):
                stale_monitor()
            assert not _cancel_owned_scan(
                session_factory,
                scan_id=scan_id,
                organization_id=organization_id,
                lease_token=attempt_tokens[0],
                actor="scanner-worker:stale",
            )
            assert not _record_owned_scan_failure(
                session_factory,
                scan_id=scan_id,
                organization_id=organization_id,
                lease_token=attempt_tokens[0],
                actor="scanner-worker:stale",
                error_code="stale_failure",
                error_message="A stale attempt must not fail the reclaimed scan",
            )
            with session_factory() as session:
                row = session.get(ScanJobRow, scan_id)
                assert row is not None
                assert row.status == "running"
                assert row.lease_token == attempt_tokens[1]
                assert row.error_code is None
            return subprocess.CompletedProcess(
                reclaimed_argv,
                0,
                stdout=_nmap_xml(hostname="current.example.test", port=443),
                stderr=b"",
            )

        assert process_next_scan(
            settings=settings,
            session_factory=session_factory,
            runner=reclaimed_runner,
        )
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=_nmap_xml(hostname="stale.example.test", port=80),
            stderr=b"",
        )

    assert process_next_scan(
        settings=settings,
        session_factory=session_factory,
        runner=outer_runner,
    )

    assert len(attempt_tokens) == 2
    assert attempt_tokens[0] != attempt_tokens[1]
    assert all(
        len(token) == 64 and all(character in "0123456789abcdef" for character in token)
        for token in attempt_tokens
    )
    assert claimed_by[0] == claimed_by[1]
    response = client.get(f"/api/v1/operational/scans/{scan_id}")
    assert response.status_code == 200
    completed = response.json()
    assert completed["status"] == "completed"
    assert completed["attempt_count"] == 2
    assert completed["claimed_by"] is None
    assert completed["lease_expires_at"] is None
    assert "lease_token" not in completed

    with session_factory() as session:
        row = session.get(ScanJobRow, scan_id)
        assert row is not None
        assert row.lease_token is None
        assert row.claimed_by is None
        assets = list(session.scalars(select(AssetRow)))
        services = list(session.scalars(select(ServiceRow)))
        snapshots = list(session.scalars(select(ArchitectureSnapshotRow)))
        completion_events = list(
            session.scalars(
                select(AuditEventRow).where(
                    AuditEventRow.action == "scan.completed",
                    AuditEventRow.resource_id == str(scan_id),
                )
            )
        )
        assert [(asset.hostname, asset.observation_count) for asset in assets] == [
            ("current.example.test", 1)
        ]
        assert [service.port for service in services] == [443]
        # Discovery generations retain immutable evidence but never replace a
        # complete service inventory or create an authoritative topology.
        assert snapshots == []
        assert len(completion_events) == 1


def test_scan_lease_monitor_renews_and_reports_owned_cancellation(
    client: TestClient,
) -> None:
    queued = _queued_scan(client)
    scan_id = UUID(str(queued["id"]))
    token = "d" * 64
    with client.app.state.session_factory() as session:
        row = session.get(ScanJobRow, scan_id)
        assert row is not None
        organization_id = row.organization_id
        row.status = "running"
        row.claimed_by = "heartbeat-worker"
        row.lease_token = token
        row.started_at = datetime.now(UTC)
        row.heartbeat_at = datetime.now(UTC) - timedelta(minutes=1)
        row.lease_expires_at = datetime.now(UTC) + timedelta(seconds=5)
        row.attempt_count = 1
        session.commit()

    monitor = _ScanLeaseMonitor(
        session_factory=client.app.state.session_factory,
        scan_id=scan_id,
        organization_id=organization_id,
        worker_id="heartbeat-worker",
        lease_token=token,
        lease_seconds=120,
        heartbeat_seconds=30,
    )
    assert monitor() is False
    with client.app.state.session_factory() as session:
        renewed = session.get(ScanJobRow, scan_id)
        assert renewed is not None
        assert renewed.heartbeat_at is not None
        assert renewed.lease_expires_at is not None
        assert renewed.lease_expires_at > datetime.now(UTC) + timedelta(seconds=100)

    # Calling again before the next heartbeat performs no database mutation.
    assert monitor() is False
    with client.app.state.session_factory() as session:
        row = session.get(ScanJobRow, scan_id)
        assert row is not None
        row.cancel_requested_at = datetime.now(UTC)
        session.commit()
    monitor.next_heartbeat = 0
    assert monitor() is True


def test_cancellation_requested_during_successful_scan_fences_ingestion(
    client: TestClient,
) -> None:
    queued = _queued_scan(client)
    scan_id = UUID(str(queued["id"]))

    def cancellation_runner(
        argv: list[str] | tuple[str, ...], _: int, __: int
    ) -> subprocess.CompletedProcess[bytes]:
        with client.app.state.session_factory() as session:
            row = session.get(ScanJobRow, scan_id)
            assert row is not None
            assert row.status == "running"
            row.cancel_requested_at = datetime.now(UTC)
            session.commit()
        return subprocess.CompletedProcess(argv, 0, stdout=NMAP_XML, stderr=b"")

    enabled = client.app.state.settings.model_copy(update={"nmap_enabled": True})
    assert process_next_scan(
        settings=enabled,
        session_factory=client.app.state.session_factory,
        runner=cancellation_runner,
    )
    cancelled = client.get(f"/api/v1/operational/scans/{scan_id}").json()
    assert cancelled["status"] == "cancelled"
    with client.app.state.session_factory() as session:
        assert session.scalar(select(AssetRow)) is None
        event = session.scalar(
            select(AuditEventRow).where(
                AuditEventRow.action == "scan.cancelled",
                AuditEventRow.resource_id == str(scan_id),
            )
        )
        assert event is not None


def test_cancellation_wins_when_scanner_process_also_fails(client: TestClient) -> None:
    queued = _queued_scan(client)
    scan_id = UUID(str(queued["id"]))

    def failed_after_cancellation(
        argv: list[str] | tuple[str, ...], _: int, __: int
    ) -> subprocess.CompletedProcess[bytes]:
        with client.app.state.session_factory() as session:
            row = session.get(ScanJobRow, scan_id)
            assert row is not None
            row.cancel_requested_at = datetime.now(UTC)
            session.commit()
        return subprocess.CompletedProcess(argv, 2, stdout=b"", stderr=b"cancelled")

    enabled = client.app.state.settings.model_copy(update={"nmap_enabled": True})
    assert process_next_scan(
        settings=enabled,
        session_factory=client.app.state.session_factory,
        runner=failed_after_cancellation,
    )
    cancelled = client.get(f"/api/v1/operational/scans/{scan_id}").json()
    assert cancelled["status"] == "cancelled"
    assert cancelled["error_code"] is None


def test_process_runner_honors_cancellation_callback() -> None:
    with pytest.raises(ScanCancelledError):
        _run_process(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout_seconds=5,
            max_stdout_bytes=128,
            should_cancel=lambda: True,
        )
