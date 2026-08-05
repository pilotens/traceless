"""Isolated scanner worker entry point.

The worker is the only process allowed to execute a scanner binary. Nmap is not
bundled with Traceless and must be installed/licensed separately by the operator.
"""

import argparse
import hmac
import os
import secrets
import selectors
import subprocess
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import or_, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from traceless_api.core.config import Settings
from traceless_api.core.scan_authorization import scope_sha256
from traceless_api.db.models import (
    OrganizationRow,
    ProjectRow,
    ScanAuthorizationRow,
    ScanJobRow,
    SystemRow,
)
from traceless_api.db.session import (
    apply_tenant_rls_scope,
    create_database_engine,
    create_schema,
    create_session_factory,
)
from traceless_api.integrations.scanners import (
    NmapCommandBuilder,
    NmapXmlParser,
    ScannerScope,
    ScanProfile,
)
from traceless_api.services.operational_repository import OperationalRepository
from traceless_api.services.scan_ingestion import ingest_scanner_result

Runner = Callable[[Sequence[str], int, int], subprocess.CompletedProcess[bytes]]


class ScanCancelledError(RuntimeError):
    pass


class ScanLeaseLostError(RuntimeError):
    pass


def _run_process(
    argv: Sequence[str],
    timeout_seconds: int,
    max_stdout_bytes: int,
    should_cancel: Callable[[], bool] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run fixed scanner argv while bounding stdout and stderr during execution."""

    max_stderr_bytes = 64 * 1024
    process = subprocess.Popen(  # noqa: S603 - argv is produced by a fixed reviewed profile
        list(argv),
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, ("stdout", max_stdout_bytes))
    selector.register(process.stderr, selectors.EVENT_READ, ("stderr", max_stderr_bytes))
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            if should_cancel is not None and should_cancel():
                _terminate_process(process)
                raise ScanCancelledError("Scan cancellation was requested")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process(process)
                raise subprocess.TimeoutExpired(list(argv), timeout_seconds)
            for key, _ in selector.select(timeout=min(remaining, 0.25)):
                stream_name, limit = key.data
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffers[stream_name].extend(chunk)
                if len(buffers[stream_name]) > limit:
                    _terminate_process(process)
                    raise RuntimeError(f"Scanner {stream_name} exceeds the configured limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process(process)
            raise subprocess.TimeoutExpired(list(argv), timeout_seconds)
        return_code = process.wait(timeout=remaining)
    except BaseException:
        _terminate_process(process)
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    return subprocess.CompletedProcess(
        list(argv),
        return_code,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
    )


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _configured_binary(value: str) -> str:
    if not value or "\x00" in value or len(value) > 500:
        raise ValueError("TRACELESS_NMAP_BINARY is invalid")
    path = Path(value)
    if not path.is_absolute() and path.name != value:
        raise ValueError("Nmap binary must be an absolute path or a plain executable name")
    return value


def process_next_scan(
    *,
    settings: Settings,
    session_factory: sessionmaker[Session],
    runner: Runner = _run_process,
) -> bool:
    """Claim and process one queued job; return False when the queue is empty."""

    if not settings.nmap_enabled:
        raise RuntimeError(
            "Active scanning is disabled; set TRACELESS_NMAP_ENABLED=true explicitly"
        )

    worker_id = f"{settings.scan_worker_id}:{os.getpid()}"[:160]
    worker_actor = f"scanner-worker:{worker_id}"[:160]
    while _terminalize_one_expired_scan(
        session_factory=session_factory,
        actor=worker_actor,
    ):
        pass
    now = datetime.now(UTC)
    with session_factory() as session:
        dispatch = _dispatch_scan_job(session, now=now, expired=False)
        if dispatch is None:
            return False
        scan_id, organization_id = dispatch
        apply_tenant_rls_scope(session, organization_id)
        scan = session.get(ScanJobRow, scan_id)
        if scan is None:  # pragma: no cover - the dispatcher row is locked
            raise RuntimeError("Claimed scan job no longer exists")
        authorization = session.get(ScanAuthorizationRow, scan.authorization_id)
        authorization_expires = (
            authorization.expires_at.replace(tzinfo=authorization.expires_at.tzinfo or UTC)
            if authorization is not None
            else None
        )
        authorization_expired = (
            authorization_expires is not None and authorization_expires <= datetime.now(UTC)
        )
        if (
            authorization is None
            or authorization.system_id != scan.system_id
            or authorization.status != "active"
            or authorization_expired
        ):
            repository = _repository_for_scan(session, scan)
            repository.fail_scan(
                scan,
                "authorization_inactive",
                "The scan authorization is missing, expired or revoked",
                worker_actor,
            )
            session.commit()
            return True
        assert authorization_expires is not None
        expected_scope_sha256 = scope_sha256(
            list(authorization.targets),
            authorization.profile,
            authorization_expires,
        )
        if not hmac.compare_digest(authorization.scope_sha256, expected_scope_sha256):
            repository = _repository_for_scan(session, scan)
            repository.fail_scan(
                scan,
                "authorization_integrity_failed",
                "The persisted scan authorization no longer matches its signed scope digest",
                worker_actor,
            )
            session.commit()
            return True
        scan.status = "running"
        scan.started_at = scan.started_at or now
        scan.claimed_by = worker_id
        lease_token = secrets.token_hex(32)
        scan.lease_token = lease_token
        scan.heartbeat_at = now
        scan.lease_expires_at = now + timedelta(
            seconds=settings.scan_timeout_seconds + settings.scan_lease_grace_seconds
        )
        scan.attempt_count += 1
        session.commit()
        scan_id = scan.id
        scan_organization_id = scan.organization_id
        targets = list(authorization.targets)
        profile = authorization.profile

    try:
        scope = ScannerScope.from_strings(
            targets,
            allow_public_targets=settings.allow_public_scan_targets,
            max_hosts=settings.scan_max_hosts,
        )
        command = NmapCommandBuilder().build(
            profile=ScanProfile(profile), targets=targets, scope=scope
        )
        argv = (_configured_binary(settings.nmap_binary), *command.argv[1:])
        if runner is _run_process:
            monitor = _ScanLeaseMonitor(
                session_factory=session_factory,
                scan_id=scan_id,
                organization_id=scan_organization_id,
                worker_id=worker_id,
                lease_token=lease_token,
                lease_seconds=settings.scan_timeout_seconds
                + settings.scan_lease_grace_seconds,
                heartbeat_seconds=settings.scan_heartbeat_seconds,
            )
            completed = _run_process(
                argv,
                settings.scan_timeout_seconds,
                settings.max_nmap_xml_bytes,
                should_cancel=monitor,
            )
        else:
            completed = runner(argv, settings.scan_timeout_seconds, settings.max_nmap_xml_bytes)
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace")[:2_000]
            raise RuntimeError(f"Nmap exited with status {completed.returncode}: {stderr}")
        if len(completed.stdout) > settings.max_nmap_xml_bytes:
            raise RuntimeError("Nmap XML exceeds the configured evidence limit")
        result = NmapXmlParser().parse(completed.stdout, targets=command.targets)
        with session_factory() as session:
            apply_tenant_rls_scope(session, scan_organization_id)
            scan = session.get(ScanJobRow, scan_id)
            if scan is None:
                raise RuntimeError("Claimed scan job no longer exists")
            if (
                scan.status != "running"
                or scan.claimed_by != worker_id
                or scan.lease_token != lease_token
            ):
                raise ScanLeaseLostError("Scan lease ownership changed before ingestion")
            if scan.cancel_requested_at is not None:
                raise ScanCancelledError("Scan cancellation was requested")
            repository = _repository_for_scan(session, scan)
            ingest_scanner_result(
                repository=repository,
                scan=scan,
                result=result,
                raw_payload=completed.stdout,
                retain_raw_evidence=settings.retain_raw_scan_evidence,
                actor=worker_actor,
                lease_token=lease_token,
            )
            session.commit()
    except ScanCancelledError:
        _cancel_owned_scan(
            session_factory,
            scan_id=scan_id,
            organization_id=scan_organization_id,
            lease_token=lease_token,
            actor=worker_actor,
        )
    except ScanLeaseLostError:
        # Another worker recovered the expired lease. This process must not
        # mutate or ingest the new owner's job.
        pass
    except Exception as error:
        _record_owned_scan_failure(
            session_factory,
            scan_id=scan_id,
            organization_id=scan_organization_id,
            lease_token=lease_token,
            actor=worker_actor,
            error_code="scanner_execution_failed",
            error_message=str(error),
        )
    return True


def _terminalize_one_expired_scan(
    *,
    session_factory: sessionmaker[Session],
    actor: str,
) -> bool:
    """Finish one abandoned tenant job without rebinding a session across tenants."""

    now = datetime.now(UTC)
    with session_factory() as session:
        dispatch = _dispatch_scan_job(session, now=now, expired=True)
        if dispatch is None:
            return False
        scan_id, organization_id = dispatch
        apply_tenant_rls_scope(session, organization_id)
        item = session.get(ScanJobRow, scan_id)
        if item is None:  # pragma: no cover - the dispatcher row is locked
            raise RuntimeError("Expired scan job no longer exists")
        if item.cancel_requested_at is not None:
            item.status = "cancelled"
            item.completed_at = now
            item.heartbeat_at = now
            item.claimed_by = None
            item.lease_token = None
            item.lease_expires_at = None
            _repository_for_scan(session, item).audit(
                actor,
                "scan.cancelled",
                "scan",
                item.id,
                {"reason": "cancelled_after_worker_lease_expired"},
            )
        else:
            _repository_for_scan(session, item).fail_scan(
                item,
                "worker_lease_exhausted",
                "The scanner worker lease expired and the retry budget is exhausted",
                actor,
            )
        session.commit()
        return True


def _dispatch_scan_job(
    session: Session,
    *,
    now: datetime,
    expired: bool,
) -> tuple[UUID, UUID] | None:
    """Lock one cross-tenant queue header without exposing queue payload columns."""

    if session.get_bind().dialect.name == "postgresql":
        statement = (
            text(
                "SELECT job_id, organization_id "
                "FROM public.traceless_dispatch_expired_scan_job()"
            )
            if expired
            else text(
                "SELECT job_id, organization_id "
                "FROM public.traceless_dispatch_runnable_scan_job()"
            )
        )
        row = session.execute(statement).one_or_none()
        return None if row is None else (row.job_id, row.organization_id)

    statement = select(ScanJobRow.id, ScanJobRow.organization_id)
    if expired:
        statement = statement.where(
            ScanJobRow.status == "running",
            or_(
                (
                    ScanJobRow.cancel_requested_at.is_not(None)
                    & or_(
                        ScanJobRow.lease_expires_at.is_(None),
                        ScanJobRow.lease_expires_at <= now,
                    )
                ),
                (
                    ScanJobRow.cancel_requested_at.is_(None)
                    & ScanJobRow.lease_expires_at.is_not(None)
                    & (ScanJobRow.lease_expires_at <= now)
                    & (ScanJobRow.attempt_count >= ScanJobRow.max_attempts)
                ),
            ),
        ).order_by(ScanJobRow.requested_at, ScanJobRow.id)
    else:
        statement = statement.where(
            ScanJobRow.scanner == "nmap",
            ScanJobRow.cancel_requested_at.is_(None),
            or_(
                ScanJobRow.status == "queued",
                (
                    (ScanJobRow.status == "running")
                    & ScanJobRow.lease_expires_at.is_not(None)
                    & (ScanJobRow.lease_expires_at <= now)
                    & (ScanJobRow.attempt_count < ScanJobRow.max_attempts)
                ),
            ),
        ).order_by(ScanJobRow.requested_at, ScanJobRow.id)
    row = session.execute(
        statement.with_for_update(skip_locked=True).limit(1)
    ).one_or_none()
    return None if row is None else (row.id, row.organization_id)


class _ScanLeaseMonitor:
    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        scan_id: UUID,
        organization_id: UUID,
        worker_id: str,
        lease_token: str,
        lease_seconds: int,
        heartbeat_seconds: int,
    ) -> None:
        self.session_factory = session_factory
        self.scan_id = scan_id
        self.organization_id = organization_id
        self.worker_id = worker_id
        self.lease_token = lease_token
        self.lease_seconds = lease_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.next_heartbeat = time.monotonic()

    def __call__(self) -> bool:
        if time.monotonic() < self.next_heartbeat:
            return False
        now = datetime.now(UTC)
        with self.session_factory() as session:
            apply_tenant_rls_scope(session, self.organization_id)
            renewed = session.execute(
                update(ScanJobRow)
                .where(
                    ScanJobRow.id == self.scan_id,
                    ScanJobRow.organization_id == self.organization_id,
                    ScanJobRow.status == "running",
                    ScanJobRow.claimed_by == self.worker_id,
                    ScanJobRow.lease_token == self.lease_token,
                    ScanJobRow.cancel_requested_at.is_(None),
                )
                .values(
                    heartbeat_at=now,
                    lease_expires_at=now + timedelta(seconds=self.lease_seconds),
                )
                .execution_options(synchronize_session=False)
            )
            if renewed.rowcount == 1:
                session.commit()
                self.next_heartbeat = time.monotonic() + self.heartbeat_seconds
                return False
            cancellation_requested = session.scalar(
                select(ScanJobRow.id).where(
                    ScanJobRow.id == self.scan_id,
                    ScanJobRow.organization_id == self.organization_id,
                    ScanJobRow.status == "running",
                    ScanJobRow.claimed_by == self.worker_id,
                    ScanJobRow.lease_token == self.lease_token,
                    ScanJobRow.cancel_requested_at.is_not(None),
                )
            )
            if cancellation_requested is not None:
                return True
            raise ScanLeaseLostError("Scan worker no longer owns the lease")


def _owned_scan_for_update(
    session: Session, *, scan_id: UUID, organization_id: UUID, lease_token: str
) -> ScanJobRow | None:
    return session.scalar(
        select(ScanJobRow)
        .where(
            ScanJobRow.id == scan_id,
            ScanJobRow.organization_id == organization_id,
            ScanJobRow.status == "running",
            ScanJobRow.lease_token == lease_token,
        )
        .with_for_update()
    )


def _cancel_owned_scan(
    session_factory: sessionmaker[Session],
    *,
    scan_id: UUID,
    organization_id: UUID,
    lease_token: str,
    actor: str,
) -> bool:
    """Cancel only the exact claimed execution attempt."""

    with session_factory() as session:
        apply_tenant_rls_scope(session, organization_id)
        scan = _owned_scan_for_update(
            session,
            scan_id=scan_id,
            organization_id=organization_id,
            lease_token=lease_token,
        )
        if scan is None:
            return False
        now = datetime.now(UTC)
        scan.status = "cancelled"
        scan.completed_at = now
        scan.heartbeat_at = now
        scan.claimed_by = None
        scan.lease_token = None
        scan.lease_expires_at = None
        _repository_for_scan(session, scan).audit(actor, "scan.cancelled", "scan", scan.id)
        session.commit()
        return True


def _record_owned_scan_failure(
    session_factory: sessionmaker[Session],
    *,
    scan_id: UUID,
    organization_id: UUID,
    lease_token: str,
    actor: str,
    error_code: str,
    error_message: str,
) -> bool:
    """Fail only the exact claimed execution attempt, honoring cancellation."""

    with session_factory() as session:
        apply_tenant_rls_scope(session, organization_id)
        scan = _owned_scan_for_update(
            session,
            scan_id=scan_id,
            organization_id=organization_id,
            lease_token=lease_token,
        )
        if scan is None:
            return False
        if scan.cancel_requested_at is not None:
            now = datetime.now(UTC)
            scan.status = "cancelled"
            scan.completed_at = now
            scan.heartbeat_at = now
            scan.claimed_by = None
            scan.lease_token = None
            scan.lease_expires_at = None
            _repository_for_scan(session, scan).audit(
                actor, "scan.cancelled", "scan", scan.id
            )
        else:
            _repository_for_scan(session, scan).fail_scan(
                scan,
                error_code,
                error_message,
                actor,
            )
        session.commit()
        return True


def _repository_for_scan(
    session: Session, scan: ScanJobRow
) -> OperationalRepository:
    organization = session.scalar(
        select(OrganizationRow)
        .join(ProjectRow, ProjectRow.organization_id == OrganizationRow.id)
        .join(SystemRow, SystemRow.project_id == ProjectRow.id)
        .where(
            SystemRow.id == scan.system_id,
            OrganizationRow.id == scan.organization_id,
        )
    )
    if organization is None:
        raise RuntimeError("Scanner job has no organization boundary")
    return OperationalRepository(
        session,
        organization_id=organization.id,
        organization_key=organization.external_key,
        organization_name=organization.name,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Process isolated Traceless scanner jobs")
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
            processed = process_next_scan(settings=settings, session_factory=session_factory)
            if args.once:
                break
            if not processed:
                time.sleep(max(0.2, args.poll_seconds))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
