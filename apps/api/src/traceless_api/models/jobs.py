"""Public contracts for durable tenant background jobs."""

from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from traceless_api.models.common import StrictModel

BackgroundJobType = Literal[
    "intelligence_correlation",
    "normalized_vulnerability_import",
    "report_generation",
]
BackgroundJobStatus = Literal[
    "queued",
    "running",
    "completed",
    "failed",
    "cancelled",
]


class BackgroundJobView(StrictModel):
    id: UUID
    organization_id: UUID
    system_id: UUID
    job_type: BackgroundJobType
    status: BackgroundJobStatus
    payload_schema_version: int = Field(ge=1)
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    requested_by: str
    requested_at: AwareDatetime
    available_at: AwareDatetime
    started_at: AwareDatetime | None
    completed_at: AwareDatetime | None
    lease_expires_at: AwareDatetime | None
    heartbeat_at: AwareDatetime | None
    attempt_count: int = Field(ge=0)
    max_attempts: int = Field(ge=1, le=10)
    cancel_requested_at: AwareDatetime | None
    result: dict[str, Any]
    result_resource_type: str | None
    result_resource_id: str | None
    error_code: str | None
    error_message: str | None


class BackgroundJobEnqueueResult(StrictModel):
    job: BackgroundJobView
    idempotent_replay: bool


class BackgroundJobList(StrictModel):
    items: list[BackgroundJobView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class BackgroundJobRetryRequest(StrictModel):
    reason: str = Field(min_length=3, max_length=2_000)
