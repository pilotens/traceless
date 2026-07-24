"""Analyst review gate between intelligence ingestion and system correlation."""

import hashlib
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from traceless_api.core.config import Settings
from traceless_api.db.models import GlobalIntelRecordRow
from traceless_api.models.intelligence_hub import (
    GlobalIntelRecordView,
    IntelReviewRequest,
    IntelReviewResult,
)
from traceless_api.services.intelligence_correlation_jobs import (
    enqueue_tenant_correlation_jobs,
)
from traceless_api.services.intelligence_hub import IntelligenceHubService
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalNotFoundError,
    OperationalRepository,
)


def review_intelligence_record(
    *,
    settings: Settings,
    repository: OperationalRepository,
    record_id: UUID,
    payload: IntelReviewRequest,
    actor: str,
) -> IntelReviewResult:
    row = repository.session.scalar(
        select(GlobalIntelRecordRow)
        .where(
            GlobalIntelRecordRow.id == record_id,
            GlobalIntelRecordRow.organization_id == repository.organization_id,
        )
        .with_for_update()
    )
    if row is None:
        raise OperationalNotFoundError("Global intelligence record was not found")
    if row.distribution_tlp == "TLP:RED":
        raise OperationalConflictError(
            "TLP:RED intelligence cannot enter the tenant-wide review workflow"
        )

    normalized_note = payload.note.strip() if payload.note is not None else None
    if row.review_status == payload.decision and row.review_note == normalized_note:
        return IntelReviewResult(
            record=GlobalIntelRecordView.model_validate(row),
            correlation_job_ids=[],
        )

    reviewed_at = datetime.now(UTC)
    row.review_status = payload.decision
    row.reviewed_by = actor
    row.reviewed_at = reviewed_at
    row.review_note = normalized_note
    repository.session.flush()

    if (
        payload.decision != "approved"
        or row.revoked
        or (row.valid_from is not None and row.valid_from > reviewed_at)
        or (row.valid_until is not None and row.valid_until <= reviewed_at)
    ):
        IntelligenceHubService(repository).retire_record_effects(
            {row.id},
            reason="The originating intelligence record is not approved and active.",
            actor=actor,
        )

    job_ids: list[UUID] = []
    # Approval materializes the new evidence; rejection must also run the
    # correlation worker so a previously approved version cannot leave a stale
    # threat or risk open. The review timestamp makes each genuine state
    # transition distinct, while an identical retry is short-circuited above.
    revision_manifest = hashlib.sha256(
        "\0".join(
            [
                row.raw_sha256,
                row.analysis_sha256 or "",
                row.modified_at.isoformat(),
                payload.decision,
                reviewed_at.isoformat(),
            ]
        ).encode("utf-8")
    ).hexdigest()
    job_ids = enqueue_tenant_correlation_jobs(
        settings=settings,
        repository=repository,
        trigger_type="intel_review",
        trigger_id=row.id,
        manifest_sha256=revision_manifest,
        actor=actor,
    )
    if payload.decision == "approved":
        for boundary_name, boundary in (
            ("valid_from", row.valid_from),
            ("valid_until", row.valid_until),
        ):
            if boundary is None or boundary <= reviewed_at:
                continue
            boundary_manifest = hashlib.sha256(
                "\0".join(
                    [
                        row.raw_sha256,
                        row.analysis_sha256 or "",
                        boundary_name,
                        boundary.isoformat(),
                    ]
                ).encode("utf-8")
            ).hexdigest()
            job_ids.extend(
                enqueue_tenant_correlation_jobs(
                    settings=settings,
                    repository=repository,
                    trigger_type="intel_temporal_boundary",
                    trigger_id=row.id,
                    manifest_sha256=boundary_manifest,
                    actor=actor,
                    available_at=boundary,
                )
            )
    repository.audit(
        actor,
        "intelligence.global_record_reviewed",
        "global_intelligence_record",
        row.id,
        {
            "decision": payload.decision,
            "correlation_jobs": len(job_ids),
            "distribution_tlp": row.distribution_tlp,
        },
    )
    repository.session.flush()
    return IntelReviewResult(
        record=GlobalIntelRecordView.model_validate(row),
        correlation_job_ids=job_ids,
    )
