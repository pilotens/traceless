from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from traceless_api import job_worker
from traceless_api.db.models import AuditEventRow, BackgroundJobRow, ReportRow
from traceless_api.job_worker import (
    BackgroundJobCancelledError,
    BackgroundJobLeaseLostError,
    JobExecutionResult,
    process_next_background_job,
)

NESSUS_XML = b"""<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Async Nessus">
    <ReportHost name="unmatched.example.test">
      <HostProperties><tag name="host-ip">100.64.0.25</tag></HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="3"
        pluginID="async-9001" pluginName="Async Nessus observation"
        pluginFamily="Web Servers">
        <cve>CVE-2099-19001</cve>
        <description>Bounded XML parsing before durable correlation.</description>
        <solution>Apply the vendor update.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""


def _create_system(client: TestClient, name: str = "Async processing") -> str:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": name, "description": "Durable background work"},
    )
    assert project.status_code == 201, project.text
    system = client.post(
        f"/api/v1/operational/projects/{project.json()['id']}/systems",
        json={
            "name": f"{name} system",
            "description": "Background job target",
            "owner": "Security",
            "criticality": "high",
        },
    )
    assert system.status_code == 201, system.text
    return str(system.json()["id"])


def _normalized_report() -> dict[str, object]:
    observed_at = datetime.now(UTC).isoformat()
    return {
        "provider": "qualys",
        "source_name": "qualys-normalized.json",
        "report_metadata": {"adapter_version": "1.0"},
        "observations": [
            {
                "provider_finding_id": "QID-async-1",
                "asset_identifier": "unmatched.example.test",
                "hostname": "unmatched.example.test",
                "port": 443,
                "protocol": "tcp",
                "title": "Async scanner observation",
                "severity": "high",
                "state": "open",
                "observed_at": observed_at,
            }
        ],
    }


def test_normalized_import_enqueue_is_idempotent_and_worker_completes(
    client: TestClient,
) -> None:
    system_id = _create_system(client)
    endpoint = (
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/async"
    )
    report = _normalized_report()
    first = client.post(endpoint, json=report)
    replay = client.post(endpoint, json=report)

    assert first.status_code == 202, first.text
    assert replay.status_code == 202, replay.text
    assert replay.json()["idempotent_replay"] is True
    assert replay.json()["job"]["id"] == first.json()["job"]["id"]
    assert "payload" not in first.json()["job"]

    assert process_next_background_job(
        settings=client.app.state.settings,
        session_factory=client.app.state.session_factory,
    )
    completed = client.get(
        f"/api/v1/operational/jobs/{first.json()['job']['id']}"
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "completed"
    assert completed.json()["result"]["imported"] == 1
    assert completed.json()["result_resource_type"] == "vulnerability_scan_import"
    imports = client.get(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans"
    )
    assert len(imports.json()) == 1


def test_report_job_requires_idempotency_key_and_creates_downloadable_report(
    client: TestClient,
) -> None:
    system_id = _create_system(client, "Async report")
    endpoint = f"/api/v1/operational/systems/{system_id}/reports/async"
    missing_key = client.post(
        endpoint, json={"format": "json", "report_type": "technical"}
    )
    assert missing_key.status_code == 422

    headers = {"Idempotency-Key": "report-request-2026-07-21"}
    queued = client.post(
        endpoint,
        json={"format": "json", "report_type": "technical"},
        headers=headers,
    )
    replay = client.post(
        endpoint,
        json={"format": "json", "report_type": "technical"},
        headers=headers,
    )
    assert queued.status_code == 202, queued.text
    assert replay.json()["idempotent_replay"] is True
    conflict = client.post(
        endpoint,
        json={"format": "csv", "report_type": "risk_register"},
        headers=headers,
    )
    assert conflict.status_code == 409

    assert process_next_background_job(
        settings=client.app.state.settings,
        session_factory=client.app.state.session_factory,
    )
    job = client.get(f"/api/v1/operational/jobs/{queued.json()['job']['id']}").json()
    assert job["status"] == "completed"
    report_id = job["result_resource_id"]
    downloaded = client.get(f"/api/v1/operational/reports/{report_id}/download")
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.headers["x-content-sha256"] == job["result"]["sha256"]


def test_nessus_can_be_normalized_then_processed_asynchronously(
    client: TestClient,
) -> None:
    system_id = _create_system(client, "Async Nessus")
    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/nessus/async",
        params={"source_name": "async-scan.nessus"},
        content=NESSUS_XML,
        headers={"Content-Type": "application/xml"},
    )
    assert queued.status_code == 202, queued.text
    assert process_next_background_job(
        settings=client.app.state.settings,
        session_factory=client.app.state.session_factory,
    )
    job = client.get(
        f"/api/v1/operational/jobs/{queued.json()['job']['id']}"
    ).json()
    assert job["status"] == "completed"
    assert job["result"]["imported"] == 1
    imported = client.get(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans"
    ).json()
    assert imported[0]["source_format"] == "nessus-xml"
    assert imported[0]["source_name"] == "async-scan.nessus"


def test_cors_preflight_allows_browser_idempotency_header(client: TestClient) -> None:
    response = client.options(
        "/api/v1/operational/jobs",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "idempotency-key,content-type",
        },
    )
    assert response.status_code == 200, response.text
    allowed = response.headers["access-control-allow-headers"].casefold()
    assert "idempotency-key" in allowed


def test_queued_job_can_be_cancelled_and_manually_retried(client: TestClient) -> None:
    system_id = _create_system(client, "Cancellation")
    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/async",
        json=_normalized_report(),
    ).json()["job"]

    cancelled = client.post(f"/api/v1/operational/jobs/{queued['id']}/cancel")
    assert cancelled.status_code == 202
    assert cancelled.json()["status"] == "cancelled"
    assert not process_next_background_job(
        settings=client.app.state.settings,
        session_factory=client.app.state.session_factory,
    )

    retried = client.post(
        f"/api/v1/operational/jobs/{queued['id']}/retry",
        json={"reason": "Cancellation was accidental"},
    )
    assert retried.status_code == 202, retried.text
    assert retried.json()["status"] == "queued"
    assert retried.json()["attempt_count"] == 0


def test_running_job_cancellation_is_immediately_terminal_and_fences_worker(
    client: TestClient,
) -> None:
    system_id = _create_system(client, "Running cancellation")
    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/async",
        json=_normalized_report(),
    ).json()["job"]
    job_id = UUID(queued["id"])
    lease_token = "c" * 64
    with client.app.state.session_factory() as session:
        row = session.get(BackgroundJobRow, job_id)
        assert row is not None
        row.status = "running"
        row.claimed_by = "in-flight-worker"
        row.lease_token = lease_token
        row.started_at = datetime.now(UTC)
        row.heartbeat_at = datetime.now(UTC)
        row.lease_expires_at = datetime.now(UTC) + timedelta(minutes=5)
        row.attempt_count = 1
        organization_id = row.organization_id
        session.commit()

    cancelled = client.post(f"/api/v1/operational/jobs/{job_id}/cancel")
    assert cancelled.status_code == 202, cancelled.text
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["completed_at"] is not None
    with client.app.state.session_factory() as session:
        row = session.get(BackgroundJobRow, job_id)
        assert row is not None
        assert row.status == "cancelled"
        assert row.claimed_by is None
        assert row.lease_token is None
        assert row.lease_expires_at is None
    assert (
        job_worker._renew_background_job_lease(
            client.app.state.session_factory,
            job_id=job_id,
            organization_id=organization_id,
            lease_token=lease_token,
            lease_seconds=120,
        )
        == "lease_lost"
    )


def test_failures_retry_with_a_bounded_budget(client: TestClient) -> None:
    system_id = _create_system(client, "Retries")
    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/async",
        json=_normalized_report(),
    ).json()["job"]
    settings = client.app.state.settings.model_copy(
        update={"background_job_retry_delay_seconds": 0}
    )

    def fail_executor(*_: object) -> JobExecutionResult:
        raise RuntimeError("temporary worker failure")

    for expected_attempt in (1, 2):
        assert process_next_background_job(
            settings=settings,
            session_factory=client.app.state.session_factory,
            executor=fail_executor,
        )
        state = client.get(f"/api/v1/operational/jobs/{queued['id']}").json()
        assert state["status"] == "queued"
        assert state["attempt_count"] == expected_attempt
        assert state["error_code"] == "job_execution_failed"

    assert process_next_background_job(
        settings=settings,
        session_factory=client.app.state.session_factory,
        executor=fail_executor,
    )
    failed = client.get(f"/api/v1/operational/jobs/{queued['id']}").json()
    assert failed["status"] == "failed"
    assert failed["attempt_count"] == 3
    assert failed["error_message"] == "The background job failed during execution"
    assert "temporary worker failure" not in failed["error_message"]


def test_cancellation_detected_during_execution_rolls_back_partial_writes(
    client: TestClient,
) -> None:
    system_id = _create_system(client, "Cancel rollback")
    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/async",
        json=_normalized_report(),
    ).json()["job"]

    def cancel_after_partial_write(session: Session, *_: object) -> JobExecutionResult:
        session.add(
            ReportRow(
                system_id=UUID(system_id),
                format="json",
                report_type="technical",
                snapshot={},
                content=b"partial",
                sha256="0" * 64,
            )
        )
        raise BackgroundJobCancelledError("Cancellation observed by the worker")

    assert process_next_background_job(
        settings=client.app.state.settings,
        session_factory=client.app.state.session_factory,
        executor=cancel_after_partial_write,
    )
    state = client.get(f"/api/v1/operational/jobs/{queued['id']}").json()
    assert state["status"] == "cancelled"
    assert client.get(
        f"/api/v1/operational/systems/{system_id}/reports"
    ).json() == []


def test_expired_lease_is_recovered_and_payload_tampering_fails_closed(
    client: TestClient,
) -> None:
    system_id = _create_system(client, "Lease recovery")
    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/async",
        json=_normalized_report(),
    ).json()["job"]
    with client.app.state.session_factory() as session:
        row = session.get(BackgroundJobRow, UUID(queued["id"]))
        assert row is not None
        row.status = "running"
        row.claimed_by = "crashed-worker"
        row.started_at = datetime.now(UTC) - timedelta(minutes=10)
        row.heartbeat_at = datetime.now(UTC) - timedelta(minutes=10)
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        row.attempt_count = 1
        row.payload = {**row.payload, "source_format": "tampered"}
        session.commit()

    assert process_next_background_job(
        settings=client.app.state.settings,
        session_factory=client.app.state.session_factory,
    )
    failed = client.get(f"/api/v1/operational/jobs/{queued['id']}").json()
    assert failed["status"] == "failed"
    assert failed["attempt_count"] == 2
    assert failed["error_code"] == "payload_integrity_failed"
    with client.app.state.session_factory() as session:
        imports = list(session.scalars(select(BackgroundJobRow)))
    assert len(imports) == 1


def test_expired_lease_with_exhausted_budget_fails_without_reexecution(
    client: TestClient,
) -> None:
    system_id = _create_system(client, "Exhausted lease")
    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/async",
        json=_normalized_report(),
    ).json()["job"]
    with client.app.state.session_factory() as session:
        row = session.get(BackgroundJobRow, UUID(queued["id"]))
        assert row is not None
        row.status = "running"
        row.claimed_by = "lost-worker"
        row.attempt_count = row.max_attempts
        row.started_at = datetime.now(UTC) - timedelta(minutes=20)
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    assert not process_next_background_job(
        settings=client.app.state.settings,
        session_factory=client.app.state.session_factory,
    )
    failed = client.get(f"/api/v1/operational/jobs/{queued['id']}").json()
    assert failed["status"] == "failed"
    assert failed["error_code"] == "worker_lease_exhausted"


def test_random_attempt_token_fences_same_worker_reclaim_and_all_terminal_writes(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system_id = _create_system(client, "Attempt fencing")
    queued = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/async",
        json=_normalized_report(),
    ).json()["job"]
    job_id = UUID(queued["id"])
    worker_id = "collision-worker:4242"
    actor = f"job-worker:{worker_id}"
    issued_tokens = iter(["a" * 64, "b" * 64])
    monkeypatch.setattr(job_worker.secrets, "token_hex", lambda _: next(issued_tokens))

    first_lease = job_worker._claim_next_job(
        client.app.state.session_factory,
        worker_id=worker_id,
        lease_seconds=60,
        actor=actor,
    )
    assert first_lease is not None and first_lease.token == "a" * 64
    with client.app.state.session_factory() as session:
        stale_job = session.get(BackgroundJobRow, job_id)
        assert stale_job is not None
        session.expunge(stale_job)

    with client.app.state.session_factory() as session:
        row = session.get(BackgroundJobRow, job_id)
        assert row is not None
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    second_lease = job_worker._claim_next_job(
        client.app.state.session_factory,
        worker_id=worker_id,
        lease_seconds=60,
        actor=actor,
    )
    assert second_lease is not None and second_lease.token == "b" * 64
    assert second_lease.job_id == first_lease.job_id

    with client.app.state.session_factory() as session:
        repository = job_worker._repository_for_job(session, stale_job)
        session.add(
            ReportRow(
                system_id=UUID(system_id),
                format="json",
                report_type="technical",
                snapshot={},
                content=b"stale-attempt",
                sha256="0" * 64,
            )
        )
        with pytest.raises(BackgroundJobLeaseLostError):
            job_worker._complete_background_job(
                session,
                job=stale_job,
                lease_token=first_lease.token,
                execution=JobExecutionResult(
                    summary={"stale": True},
                    resource_type="report",
                    resource_id="stale-report",
                ),
                repository=repository,
                actor=actor,
            )
        session.rollback()

    with client.app.state.session_factory() as session:
        current = session.get(BackgroundJobRow, job_id)
        assert current is not None
        second_expiry = current.lease_expires_at
        assert current.status == "running"
        assert current.claimed_by == worker_id
        assert current.lease_token == second_lease.token
        assert current.attempt_count == 2
        partial_report = session.scalar(
            select(ReportRow).where(ReportRow.system_id == UUID(system_id))
        )
        assert partial_report is None

    assert (
        job_worker._renew_background_job_lease(
            client.app.state.session_factory,
            job_id=job_id,
            organization_id=first_lease.organization_id,
            lease_token=first_lease.token,
            lease_seconds=120,
        )
        == "lease_lost"
    )
    job_worker._record_failure(
        client.app.state.session_factory,
        job_id,
        first_lease.organization_id,
        first_lease.token,
        actor,
        error_code="stale_failure",
        error_message="A stale attempt must not win",
        retry_delay_seconds=0,
        retryable=False,
    )
    job_worker._mark_cancelled(
        client.app.state.session_factory,
        job_id,
        first_lease.organization_id,
        first_lease.token,
        actor,
    )
    with client.app.state.session_factory() as session:
        current = session.get(BackgroundJobRow, job_id)
        assert current is not None
        assert current.status == "running"
        assert current.lease_token == second_lease.token
        assert current.lease_expires_at == second_expiry

    assert (
        job_worker._renew_background_job_lease(
            client.app.state.session_factory,
            job_id=job_id,
            organization_id=second_lease.organization_id,
            lease_token=second_lease.token,
            lease_seconds=120,
        )
        == "renewed"
    )
    job_worker._record_failure(
        client.app.state.session_factory,
        job_id,
        second_lease.organization_id,
        second_lease.token,
        actor,
        error_code="current_failure",
        error_message="The current attempt may schedule its retry",
        retry_delay_seconds=0,
        retryable=True,
    )
    response = client.get(f"/api/v1/operational/jobs/{job_id}")
    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    assert "lease_token" not in response.json()
    with client.app.state.session_factory() as session:
        current = session.get(BackgroundJobRow, job_id)
        assert current is not None
        assert current.lease_token is None
        audits = list(
            session.scalars(
                select(AuditEventRow).where(AuditEventRow.resource_id == str(job_id))
            )
        )
        assert all("lease_token" not in event.details for event in audits)
        assert all(first_lease.token not in str(event.details) for event in audits)
        assert all(second_lease.token not in str(event.details) for event in audits)
