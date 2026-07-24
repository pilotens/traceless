"""Tenant-scoped enqueue, inspection and control of durable background jobs."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import false, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from traceless_api.db.models import AuditEventRow, BackgroundJobRow, SystemRow
from traceless_api.models.jobs import BackgroundJobStatus, BackgroundJobType
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalNotFoundError,
    OperationalRepository,
)


def canonical_job_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def job_payload_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_job_payload(payload)).hexdigest()


class BackgroundJobService:
    """Request-scoped facade that always applies the authenticated tenant boundary."""

    def __init__(
        self,
        session: Session,
        *,
        organization_id: UUID,
        organization_key: str,
        organization_name: str,
        allowed_project_ids: frozenset[UUID] | None = None,
        allowed_system_ids: frozenset[UUID] | None = None,
    ) -> None:
        self.session = session
        self.organization_id = organization_id
        self.allowed_project_ids = allowed_project_ids
        self.allowed_system_ids = allowed_system_ids
        self.operational = OperationalRepository(
            session,
            organization_id=organization_id,
            organization_key=organization_key,
            organization_name=organization_name,
            allowed_project_ids=allowed_project_ids,
            allowed_system_ids=allowed_system_ids,
        )

    def enqueue(
        self,
        *,
        system_id: UUID,
        job_type: BackgroundJobType,
        payload: dict[str, Any],
        actor: str,
        max_attempts: int,
        idempotency_key: str | None = None,
        available_at: datetime | None = None,
    ) -> tuple[BackgroundJobRow, bool]:
        self.operational.get_system(system_id)
        digest = job_payload_sha256(payload)
        key_material = idempotency_key if idempotency_key is not None else digest
        key_digest = hashlib.sha256(
            f"v1\0{job_type}\0{system_id}\0{key_material}".encode()
        ).hexdigest()
        existing = self._by_idempotency_key(key_digest)
        if existing is not None:
            self._validate_replay(existing, system_id, job_type, digest)
            return existing, True

        row = BackgroundJobRow(
            organization_id=self.organization_id,
            system_id=system_id,
            job_type=job_type,
            payload_schema_version=1,
            payload=payload,
            payload_sha256=digest,
            idempotency_key_sha256=key_digest,
            requested_by=actor,
            max_attempts=max_attempts,
            available_at=available_at or datetime.now(UTC),
        )
        try:
            with self.session.begin_nested():
                self.session.add(row)
                self.session.flush()
        except IntegrityError:
            existing = self._by_idempotency_key(key_digest)
            if existing is None:
                raise
            self._validate_replay(existing, system_id, job_type, digest)
            return existing, True
        self._audit(
            actor,
            "background_job.queued",
            row,
            {"job_type": job_type, "payload_sha256": digest},
        )
        return row, False

    def get(self, job_id: UUID) -> BackgroundJobRow:
        row = self.session.scalar(
            select(BackgroundJobRow).where(
                BackgroundJobRow.id == job_id,
                BackgroundJobRow.organization_id == self.organization_id,
            )
        )
        if row is None:
            raise OperationalNotFoundError("Background job was not found")
        # Apply the same project/system assignment boundary as every other
        # operational resource. A cross-scope identifier remains indistinguishable
        # from a missing job.
        self.operational.get_system(row.system_id)
        return row

    def list(
        self,
        *,
        status: BackgroundJobStatus | None,
        job_type: BackgroundJobType | None,
        system_id: UUID | None,
        limit: int,
        offset: int,
    ) -> tuple[list[BackgroundJobRow], int]:
        predicates = [BackgroundJobRow.organization_id == self.organization_id]
        if status is not None:
            predicates.append(BackgroundJobRow.status == status)
        if job_type is not None:
            predicates.append(BackgroundJobRow.job_type == job_type)
        if system_id is not None:
            self.operational.get_system(system_id)
            predicates.append(BackgroundJobRow.system_id == system_id)
        scope_predicate = self._scope_predicate()
        if scope_predicate is not None:
            predicates.append(scope_predicate)
        total = int(
            self.session.scalar(
                select(func.count())
                .select_from(BackgroundJobRow)
                .join(SystemRow, SystemRow.id == BackgroundJobRow.system_id)
                .where(*predicates)
            )
            or 0
        )
        rows = list(
            self.session.scalars(
                select(BackgroundJobRow)
                .join(SystemRow, SystemRow.id == BackgroundJobRow.system_id)
                .where(*predicates)
                .order_by(BackgroundJobRow.requested_at.desc(), BackgroundJobRow.id.desc())
                .offset(offset)
                .limit(limit)
            )
        )
        return rows, total

    def _scope_predicate(self) -> object | None:
        if self.allowed_project_ids is None and self.allowed_system_ids is None:
            return None
        clauses = []
        if self.allowed_project_ids:
            clauses.append(SystemRow.project_id.in_(self.allowed_project_ids))
        if self.allowed_system_ids:
            clauses.append(SystemRow.id.in_(self.allowed_system_ids))
        return or_(*clauses) if clauses else false()

    def request_cancellation(self, job_id: UUID, actor: str) -> BackgroundJobRow:
        row = self.get(job_id)
        if row.status in {"completed", "failed", "cancelled"}:
            return row
        now = datetime.now(UTC)
        row.cancel_requested_at = row.cancel_requested_at or now
        # All current job executors are transactionally fenced database work.
        # Revoking the attempt token immediately makes cancellation terminal;
        # an in-flight worker can no longer commit partial results.
        row.status = "cancelled"
        row.completed_at = now
        row.heartbeat_at = now
        row.claimed_by = None
        row.lease_token = None
        row.lease_expires_at = None
        self._audit(actor, "background_job.cancellation_requested", row)
        self.session.flush()
        return row

    def retry(self, job_id: UUID, actor: str, reason: str) -> BackgroundJobRow:
        row = self.get(job_id)
        if row.status not in {"failed", "cancelled"}:
            raise OperationalConflictError(
                "Only failed or cancelled background jobs can be retried"
            )
        row.status = "queued"
        row.available_at = datetime.now(UTC)
        row.started_at = None
        row.completed_at = None
        row.claimed_by = None
        row.lease_token = None
        row.lease_expires_at = None
        row.heartbeat_at = None
        row.attempt_count = 0
        row.cancel_requested_at = None
        row.result = {}
        row.result_resource_type = None
        row.result_resource_id = None
        row.error_code = None
        row.error_message = None
        self._audit(actor, "background_job.retried", row, {"reason": reason})
        self.session.flush()
        return row

    def _by_idempotency_key(self, key_digest: str) -> BackgroundJobRow | None:
        return self.session.scalar(
            select(BackgroundJobRow).where(
                BackgroundJobRow.organization_id == self.organization_id,
                BackgroundJobRow.idempotency_key_sha256 == key_digest,
            )
        )

    @staticmethod
    def _validate_replay(
        row: BackgroundJobRow,
        system_id: UUID,
        job_type: BackgroundJobType,
        payload_digest: str,
    ) -> None:
        if (
            row.system_id != system_id
            or row.job_type != job_type
            or not hmac.compare_digest(row.payload_sha256, payload_digest)
        ):
            raise OperationalConflictError(
                "The idempotency key was already used with a different job payload"
            )

    def _audit(
        self,
        actor: str,
        action: str,
        row: BackgroundJobRow,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.session.add(
            AuditEventRow(
                organization_id=self.organization_id,
                actor=actor,
                action=action,
                resource_type="background_job",
                resource_id=str(row.id),
                details={"system_id": str(row.system_id), **(details or {})},
            )
        )
