"""Separate worker process for durable imports and report generation."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import or_, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from traceless_api.core.config import Settings
from traceless_api.db.models import (
    AuditEventRow,
    BackgroundJobRow,
    OrganizationRow,
    ProjectRow,
    SystemRow,
)
from traceless_api.db.session import (
    apply_tenant_rls_scope,
    create_database_engine,
    create_schema,
    create_session_factory,
)
from traceless_api.models.operational import ReportCreate, VulnerabilityScanImportCreate
from traceless_api.services.background_jobs import job_payload_sha256
from traceless_api.services.intelligence_hub import IntelligenceHubService
from traceless_api.services.operational_repository import OperationalRepository
from traceless_api.services.reporting import (
    build_report_snapshot,
    freeze_report_configuration,
    render_report,
)


class BackgroundJobCancelledError(RuntimeError):
    pass


class BackgroundJobLeaseLostError(RuntimeError):
    pass


class FatalBackgroundJobError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class JobExecutionResult:
    summary: dict[str, Any]
    resource_type: str
    resource_id: str


@dataclass(frozen=True, slots=True)
class BackgroundJobLease:
    """Unforgeable ownership fence for one specific execution attempt."""

    job_id: UUID
    organization_id: UUID
    token: str


JobExecutor = Callable[[Session, BackgroundJobRow, OperationalRepository, str], JobExecutionResult]

logger = logging.getLogger(__name__)


def process_next_background_job(
    *,
    settings: Settings,
    session_factory: sessionmaker[Session],
    executor: JobExecutor | None = None,
) -> bool:
    """Claim and execute one job; return False when no runnable work exists."""

    worker_id = f"{settings.background_job_worker_id}:{os.getpid()}"[:160]
    actor = f"job-worker:{worker_id}"[:160]
    lease = _claim_next_job(
        session_factory,
        worker_id=worker_id,
        lease_seconds=settings.background_job_lease_seconds,
        actor=actor,
    )
    if lease is None:
        return False
    job_id = lease.job_id

    heartbeat = _JobHeartbeat(
        session_factory=session_factory,
        job_id=job_id,
        organization_id=lease.organization_id,
        lease_token=lease.token,
        lease_seconds=settings.background_job_lease_seconds,
        heartbeat_seconds=settings.background_job_heartbeat_seconds,
    )
    heartbeat.start()
    try:
        with session_factory() as session:
            apply_tenant_rls_scope(session, lease.organization_id)
            job = session.get(BackgroundJobRow, job_id)
            if job is None or job.status != "running" or not _lease_matches(job, lease.token):
                raise BackgroundJobLeaseLostError("Background job lease ownership changed")
            if job.cancel_requested_at is not None:
                raise BackgroundJobCancelledError("Background job cancellation was requested")
            if not hmac.compare_digest(job.payload_sha256, job_payload_sha256(job.payload)):
                raise FatalBackgroundJobError(
                    "payload_integrity_failed",
                    "The persisted background job payload does not match its immutable digest",
                )
            repository = _repository_for_job(session, job)
            execution = (executor or _execute_job)(session, job, repository, actor)

            heartbeat.stop()
            if heartbeat.lease_lost:
                raise BackgroundJobLeaseLostError("Background job lease ownership changed")
            if heartbeat.cancel_requested:
                raise BackgroundJobCancelledError("Background job cancellation was requested")

            _complete_background_job(
                session,
                job=job,
                lease_token=lease.token,
                execution=execution,
                repository=repository,
                actor=actor,
            )
            session.commit()
    except BackgroundJobCancelledError:
        heartbeat.stop()
        _mark_cancelled(
            session_factory,
            job_id,
            lease.organization_id,
            lease.token,
            actor,
        )
    except BackgroundJobLeaseLostError:
        heartbeat.stop()
        # The new lease owner is authoritative; the old process must not mutate the row.
    except FatalBackgroundJobError as error:
        heartbeat.stop()
        _record_failure(
            session_factory,
            job_id,
            lease.organization_id,
            lease.token,
            actor,
            error_code=error.code,
            error_message=str(error),
            retry_delay_seconds=settings.background_job_retry_delay_seconds,
            retryable=False,
        )
    except Exception:
        heartbeat.stop()
        logger.exception("Background job %s execution failed", job_id)
        _record_failure(
            session_factory,
            job_id,
            lease.organization_id,
            lease.token,
            actor,
            error_code="job_execution_failed",
            error_message="The background job failed during execution",
            retry_delay_seconds=settings.background_job_retry_delay_seconds,
            retryable=True,
        )
    finally:
        heartbeat.stop()
    return True


def _claim_next_job(
    session_factory: sessionmaker[Session],
    *,
    worker_id: str,
    lease_seconds: int,
    actor: str,
) -> BackgroundJobLease | None:
    while _terminalize_one_expired_job(session_factory, actor=actor):
        pass

    now = datetime.now(UTC)
    with session_factory() as session:
        dispatch = _dispatch_background_job(session, now=now, expired=False)
        if dispatch is None:
            return None
        job_id, organization_id = dispatch
        apply_tenant_rls_scope(session, organization_id)
        job = session.get(BackgroundJobRow, job_id)
        if job is None:  # pragma: no cover - the dispatcher row is locked
            raise RuntimeError("Claimed background job no longer exists")
        job.status = "running"
        job.started_at = job.started_at or now
        job.claimed_by = worker_id
        lease_token = secrets.token_hex(32)
        job.lease_token = lease_token
        job.heartbeat_at = now
        job.lease_expires_at = now + timedelta(seconds=lease_seconds)
        job.attempt_count += 1
        _audit(
            session,
            job,
            actor,
            "background_job.claimed",
            {"attempt_count": job.attempt_count},
        )
        session.commit()
        return BackgroundJobLease(
            job_id=job.id,
            organization_id=job.organization_id,
            token=lease_token,
        )


def _terminalize_one_expired_job(
    session_factory: sessionmaker[Session],
    *,
    actor: str,
) -> bool:
    """Finish one abandoned row while keeping each session tenant-immutable."""

    now = datetime.now(UTC)
    with session_factory() as session:
        dispatch = _dispatch_background_job(session, now=now, expired=True)
        if dispatch is None:
            return False
        job_id, organization_id = dispatch
        apply_tenant_rls_scope(session, organization_id)
        row = session.get(BackgroundJobRow, job_id)
        if row is None:  # pragma: no cover - the dispatcher row is locked
            raise RuntimeError("Expired background job no longer exists")
        row.completed_at = now
        row.claimed_by = None
        row.lease_token = None
        row.lease_expires_at = None
        if row.cancel_requested_at is not None:
            row.status = "cancelled"
            action = "background_job.cancelled"
        else:
            row.status = "failed"
            row.error_code = "worker_lease_exhausted"
            row.error_message = "The worker lease expired and the retry budget is exhausted"
            action = "background_job.failed"
        _audit(session, row, actor, action)
        session.commit()
        return True


def _dispatch_background_job(
    session: Session,
    *,
    now: datetime,
    expired: bool,
) -> tuple[UUID, UUID] | None:
    """Lock one queue header through the privileged PostgreSQL dispatcher."""

    if session.get_bind().dialect.name == "postgresql":
        statement = (
            text(
                "SELECT job_id, organization_id "
                "FROM public.traceless_dispatch_expired_background_job()"
            )
            if expired
            else text(
                "SELECT job_id, organization_id "
                "FROM public.traceless_dispatch_runnable_background_job()"
            )
        )
        row = session.execute(statement).one_or_none()
        return None if row is None else (row.job_id, row.organization_id)

    statement = select(BackgroundJobRow.id, BackgroundJobRow.organization_id)
    if expired:
        statement = statement.where(
            BackgroundJobRow.status == "running",
            BackgroundJobRow.lease_expires_at.is_not(None),
            BackgroundJobRow.lease_expires_at <= now,
            or_(
                BackgroundJobRow.cancel_requested_at.is_not(None),
                BackgroundJobRow.attempt_count >= BackgroundJobRow.max_attempts,
            ),
        ).order_by(BackgroundJobRow.requested_at, BackgroundJobRow.id)
    else:
        statement = statement.where(
            BackgroundJobRow.cancel_requested_at.is_(None),
            or_(
                ((BackgroundJobRow.status == "queued") & (BackgroundJobRow.available_at <= now)),
                (
                    (BackgroundJobRow.status == "running")
                    & BackgroundJobRow.lease_expires_at.is_not(None)
                    & (BackgroundJobRow.lease_expires_at <= now)
                    & (BackgroundJobRow.attempt_count < BackgroundJobRow.max_attempts)
                ),
            ),
        ).order_by(
            BackgroundJobRow.available_at,
            BackgroundJobRow.requested_at,
            BackgroundJobRow.id,
        )
    row = session.execute(statement.with_for_update(skip_locked=True).limit(1)).one_or_none()
    return None if row is None else (row.id, row.organization_id)


def _execute_job(
    session: Session,
    job: BackgroundJobRow,
    repository: OperationalRepository,
    actor: str,
) -> JobExecutionResult:
    if job.payload_schema_version != 1:
        raise FatalBackgroundJobError(
            "unsupported_payload_schema", "The background job payload schema is unsupported"
        )
    if job.job_type == "normalized_vulnerability_import":
        return _execute_vulnerability_import(job, repository, actor)
    if job.job_type == "intelligence_correlation":
        return _execute_intelligence_correlation(job, repository, actor)
    if job.job_type == "report_generation":
        return _execute_report(job, repository, actor)
    raise FatalBackgroundJobError("unsupported_job_type", "The background job type is unsupported")


def _execute_intelligence_correlation(
    job: BackgroundJobRow,
    repository: OperationalRepository,
    actor: str,
) -> JobExecutionResult:
    trigger_type = job.payload.get("trigger_type")
    trigger_id = job.payload.get("trigger_id")
    manifest_sha256 = job.payload.get("manifest_sha256")
    try:
        parsed_trigger_id = UUID(trigger_id)
    except (TypeError, ValueError) as error:
        raise FatalBackgroundJobError(
            "invalid_job_payload", "The intelligence correlation job payload is invalid"
        ) from error
    if trigger_type not in {
        "external_sync",
        "intel_review",
        "intel_superseded",
        "intel_temporal_boundary",
        "inventory_generation",
    } or (
        not isinstance(manifest_sha256, str)
        or len(manifest_sha256) != 64
        or any(character not in "0123456789abcdef" for character in manifest_sha256)
    ):
        raise FatalBackgroundJobError(
            "invalid_job_payload", "The intelligence correlation job payload is invalid"
        )
    outcome = IntelligenceHubService(repository).correlate(job.system_id, actor)
    return JobExecutionResult(
        summary={
            **outcome.model_dump(mode="json"),
            "trigger_type": trigger_type,
            "trigger_id": str(parsed_trigger_id),
            "manifest_sha256": manifest_sha256,
        },
        resource_type="system_intelligence_correlation",
        resource_id=str(job.system_id),
    )


def _execute_vulnerability_import(
    job: BackgroundJobRow,
    repository: OperationalRepository,
    actor: str,
) -> JobExecutionResult:
    report_payload = job.payload.get("report")
    raw_sha256 = job.payload.get("raw_sha256")
    source_format = job.payload.get("source_format")
    if (
        not isinstance(report_payload, dict)
        or not isinstance(raw_sha256, str)
        or len(raw_sha256) != 64
        or any(character not in "0123456789abcdef" for character in raw_sha256)
        or source_format not in {"normalized-json", "nessus-xml"}
    ):
        raise FatalBackgroundJobError(
            "invalid_job_payload", "The normalized vulnerability job payload is invalid"
        )
    try:
        report = VulnerabilityScanImportCreate.model_validate(report_payload)
    except ValidationError as error:
        raise FatalBackgroundJobError(
            "invalid_job_payload", "The normalized vulnerability job payload is invalid"
        ) from error
    row, replay, matched_assets, matched_services, promoted, warnings = (
        repository.import_vulnerability_scan(
            job.system_id,
            report,
            actor,
            raw_sha256=raw_sha256,
            source_format=source_format,
        )
    )
    return JobExecutionResult(
        summary={
            "imported": row.observation_count,
            "matched_assets": matched_assets,
            "matched_services": matched_services,
            "promoted_findings": promoted,
            "idempotent_replay": replay,
            "warnings": warnings,
        },
        resource_type="vulnerability_scan_import",
        resource_id=str(row.id),
    )


def _execute_report(
    job: BackgroundJobRow,
    repository: OperationalRepository,
    actor: str,
) -> JobExecutionResult:
    try:
        request = ReportCreate.model_validate(job.payload)
    except ValidationError as error:
        raise FatalBackgroundJobError(
            "invalid_job_payload", "The report generation job payload is invalid"
        ) from error
    snapshot = build_report_snapshot(repository, job.system_id)
    selected_sections = freeze_report_configuration(
        snapshot, report_type=request.report_type, sections=request.sections
    )
    content = render_report(
        snapshot,
        format=request.format,
        report_type=request.report_type,
        sections=selected_sections,
    )
    digest = hashlib.sha256(content).hexdigest()
    report = repository.save_report(
        system_id=job.system_id,
        report_type=request.report_type,
        format=request.format,
        snapshot=snapshot,
        content=content,
        sha256=digest,
        actor=actor,
    )
    return JobExecutionResult(
        summary={
            "format": report.format,
            "report_type": report.report_type,
            "sha256": report.sha256,
        },
        resource_type="report",
        resource_id=str(report.id),
    )


def _complete_background_job(
    session: Session,
    *,
    job: BackgroundJobRow,
    lease_token: str,
    execution: JobExecutionResult,
    repository: OperationalRepository,
    actor: str,
) -> None:
    """Atomically fence completion against reclaim of the execution attempt."""

    now = datetime.now(UTC)
    completed = session.execute(
        update(BackgroundJobRow)
        .where(
            BackgroundJobRow.id == job.id,
            BackgroundJobRow.status == "running",
            BackgroundJobRow.lease_token == lease_token,
            BackgroundJobRow.cancel_requested_at.is_(None),
        )
        .values(
            status="completed",
            completed_at=now,
            heartbeat_at=now,
            lease_expires_at=None,
            claimed_by=None,
            lease_token=None,
            result=execution.summary,
            result_resource_type=execution.resource_type,
            result_resource_id=execution.resource_id,
            error_code=None,
            error_message=None,
        )
        .execution_options(synchronize_session=False)
    )
    if completed.rowcount != 1:
        cancellation_requested = session.scalar(
            select(BackgroundJobRow.id).where(
                BackgroundJobRow.id == job.id,
                BackgroundJobRow.status == "running",
                BackgroundJobRow.lease_token == lease_token,
                BackgroundJobRow.cancel_requested_at.is_not(None),
            )
        )
        if cancellation_requested is not None:
            raise BackgroundJobCancelledError("Background job cancellation was requested")
        raise BackgroundJobLeaseLostError("Background job lease ownership changed")

    repository.audit(
        actor,
        "background_job.completed",
        "background_job",
        job.id,
        {
            "job_type": job.job_type,
            "result_resource_type": execution.resource_type,
            "result_resource_id": execution.resource_id,
        },
    )


class _JobHeartbeat:
    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        job_id: UUID,
        organization_id: UUID,
        lease_token: str,
        lease_seconds: int,
        heartbeat_seconds: int,
    ) -> None:
        self.session_factory = session_factory
        self.job_id = job_id
        self.organization_id = organization_id
        self.lease_token = lease_token
        self.lease_seconds = lease_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.lease_lost = False
        self.cancel_requested = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._started = False
        bind = session_factory.kw.get("bind")
        # SQLite is a local/test backend with database-wide writer locking. A
        # second heartbeat writer can deadlock the active work transaction;
        # production PostgreSQL receives periodic renewals.
        self._periodic_enabled = bind is not None and bind.dialect.name != "sqlite"

    def start(self) -> None:
        if not self._periodic_enabled:
            return
        self._started = True
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._started and self._thread.is_alive():
            self._thread.join(timeout=max(1.0, self.heartbeat_seconds + 1.0))
            if self._thread.is_alive():
                self.lease_lost = True

    def _run(self) -> None:
        while not self._stop.wait(self.heartbeat_seconds):
            try:
                renewal = _renew_background_job_lease(
                    self.session_factory,
                    job_id=self.job_id,
                    organization_id=self.organization_id,
                    lease_token=self.lease_token,
                    lease_seconds=self.lease_seconds,
                )
                if renewal == "cancel_requested":
                    self.cancel_requested = True
                    return
                if renewal == "lease_lost":
                    self.lease_lost = True
                    return
            except Exception:
                # A missed renewal is not silently treated as ownership. The main
                # transaction will only commit if the persisted lease still belongs
                # to this worker.
                self.lease_lost = True
                return


LeaseRenewalResult = Literal["renewed", "cancel_requested", "lease_lost"]


def _renew_background_job_lease(
    session_factory: sessionmaker[Session],
    *,
    job_id: UUID,
    organization_id: UUID,
    lease_token: str,
    lease_seconds: int,
) -> LeaseRenewalResult:
    """Renew only the exact attempt token; never extend a reclaimed attempt."""

    now = datetime.now(UTC)
    with session_factory() as session:
        apply_tenant_rls_scope(session, organization_id)
        renewed = session.execute(
            update(BackgroundJobRow)
            .where(
                BackgroundJobRow.id == job_id,
                BackgroundJobRow.organization_id == organization_id,
                BackgroundJobRow.status == "running",
                BackgroundJobRow.lease_token == lease_token,
                BackgroundJobRow.cancel_requested_at.is_(None),
            )
            .values(
                heartbeat_at=now,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
            )
            .execution_options(synchronize_session=False)
        )
        if renewed.rowcount == 1:
            session.commit()
            return "renewed"
        cancellation_requested = session.scalar(
            select(BackgroundJobRow.id).where(
                BackgroundJobRow.id == job_id,
                BackgroundJobRow.organization_id == organization_id,
                BackgroundJobRow.status == "running",
                BackgroundJobRow.lease_token == lease_token,
                BackgroundJobRow.cancel_requested_at.is_not(None),
            )
        )
        if cancellation_requested is not None:
            return "cancel_requested"
        return "lease_lost"


def _repository_for_job(
    session: Session,
    job: BackgroundJobRow,
) -> OperationalRepository:
    organization = session.get(OrganizationRow, job.organization_id)
    system_organization_id = session.scalar(
        select(ProjectRow.organization_id)
        .join(SystemRow, SystemRow.project_id == ProjectRow.id)
        .where(SystemRow.id == job.system_id)
    )
    if organization is None or system_organization_id != job.organization_id:
        raise FatalBackgroundJobError(
            "tenant_boundary_invalid",
            "The background job system does not belong to its organization",
        )
    return OperationalRepository(
        session,
        organization_id=organization.id,
        organization_key=organization.external_key,
        organization_name=organization.name,
    )


def _mark_cancelled(
    session_factory: sessionmaker[Session],
    job_id: UUID,
    organization_id: UUID,
    lease_token: str,
    actor: str,
) -> None:
    with session_factory() as session:
        apply_tenant_rls_scope(session, organization_id)
        now = datetime.now(UTC)
        cancelled = session.execute(
            update(BackgroundJobRow)
            .where(
                BackgroundJobRow.id == job_id,
                BackgroundJobRow.organization_id == organization_id,
                BackgroundJobRow.status == "running",
                BackgroundJobRow.lease_token == lease_token,
            )
            .values(
                status="cancelled",
                completed_at=now,
                heartbeat_at=now,
                claimed_by=None,
                lease_token=None,
                lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )
        if cancelled.rowcount != 1:
            return
        row = session.get(BackgroundJobRow, job_id)
        if row is None:  # pragma: no cover - protected by the successful update
            session.rollback()
            return
        _audit(session, row, actor, "background_job.cancelled")
        session.commit()


def _record_failure(
    session_factory: sessionmaker[Session],
    job_id: UUID,
    organization_id: UUID,
    lease_token: str,
    actor: str,
    *,
    error_code: str,
    error_message: str,
    retry_delay_seconds: int,
    retryable: bool,
) -> None:
    with session_factory() as session:
        apply_tenant_rls_scope(session, organization_id)
        now = datetime.now(UTC)
        common_values = {
            "error_code": error_code[:100],
            "error_message": (error_message or error_code)[:4_000],
            "claimed_by": None,
            "lease_token": None,
            "lease_expires_at": None,
            "heartbeat_at": now,
        }
        cancelled = session.execute(
            update(BackgroundJobRow)
            .where(
                BackgroundJobRow.id == job_id,
                BackgroundJobRow.organization_id == organization_id,
                BackgroundJobRow.status == "running",
                BackgroundJobRow.lease_token == lease_token,
                BackgroundJobRow.cancel_requested_at.is_not(None),
            )
            .values(status="cancelled", completed_at=now, **common_values)
            .execution_options(synchronize_session=False)
        )
        action: str | None = None
        if cancelled.rowcount == 1:
            action = "background_job.cancelled"

        if action is None and retryable:
            retry = session.execute(
                update(BackgroundJobRow)
                .where(
                    BackgroundJobRow.id == job_id,
                    BackgroundJobRow.organization_id == organization_id,
                    BackgroundJobRow.status == "running",
                    BackgroundJobRow.lease_token == lease_token,
                    BackgroundJobRow.cancel_requested_at.is_(None),
                    BackgroundJobRow.attempt_count < BackgroundJobRow.max_attempts,
                )
                .values(
                    status="queued",
                    available_at=now + timedelta(seconds=retry_delay_seconds),
                    **common_values,
                )
                .execution_options(synchronize_session=False)
            )
            if retry.rowcount == 1:
                action = "background_job.retry_scheduled"

        if action is None:
            failed = session.execute(
                update(BackgroundJobRow)
                .where(
                    BackgroundJobRow.id == job_id,
                    BackgroundJobRow.organization_id == organization_id,
                    BackgroundJobRow.status == "running",
                    BackgroundJobRow.lease_token == lease_token,
                    BackgroundJobRow.cancel_requested_at.is_(None),
                )
                .values(status="failed", completed_at=now, **common_values)
                .execution_options(synchronize_session=False)
            )
            if failed.rowcount == 1:
                action = "background_job.failed"

        if action is None:
            return
        row = session.get(BackgroundJobRow, job_id)
        if row is None:  # pragma: no cover - protected by the successful update
            session.rollback()
            return
        _audit(
            session,
            row,
            actor,
            action,
            {"error_code": row.error_code, "attempt_count": row.attempt_count},
        )
        session.commit()


def _lease_matches(row: BackgroundJobRow, lease_token: str) -> bool:
    return row.lease_token is not None and hmac.compare_digest(row.lease_token, lease_token)


def _audit(
    session: Session,
    row: BackgroundJobRow,
    actor: str,
    action: str,
    details: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuditEventRow(
            organization_id=row.organization_id,
            actor=actor,
            action=action,
            resource_type="background_job",
            resource_id=str(row.id),
            details={"system_id": str(row.system_id), **(details or {})},
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Process durable Traceless background jobs")
    parser.add_argument("--once", action="store_true", help="Process at most one job and exit")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    args = parser.parse_args()

    settings = Settings()
    engine = create_database_engine(settings.database_url)
    if settings.auto_create_schema:
        create_schema(engine)
    session_factory = create_session_factory(engine)
    try:
        while True:
            processed = process_next_background_job(
                settings=settings,
                session_factory=session_factory,
            )
            if args.once:
                break
            if not processed:
                time.sleep(max(0.2, args.poll_seconds))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
