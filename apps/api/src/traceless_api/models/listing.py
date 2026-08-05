"""Compact contracts for high-cardinality operational collections."""

from datetime import date
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from traceless_api.models.common import StrictModel
from traceless_api.models.operational import Criticality, VulnerabilitySeverity


class ThreatSummaryView(StrictModel):
    id: UUID
    system_id: UUID
    source: str
    external_id: str
    title: str
    severity: Criticality
    confidence: float = Field(ge=0, le=1)
    attack_patterns: list[str]
    affected_products: list[str]
    matched_asset_ids: list[str]
    modified_at: AwareDatetime
    ingested_at: AwareDatetime


class FindingSummaryView(StrictModel):
    id: UUID
    system_id: UUID
    asset_id: UUID | None
    service_id: UUID | None
    finding_type: Literal["vulnerability", "misconfiguration", "informational"]
    cve_id: str | None
    title: str
    status: Literal["candidate", "likely", "confirmed", "false_positive"]
    lifecycle_status: Literal[
        "open", "fixed", "accepted", "false_positive", "out_of_scope", "reopened"
    ]
    cvss_score: float | None = Field(ge=0, le=10)
    epss_score: float | None = Field(ge=0, le=1)
    is_kev: bool
    kev_due_date: date | None
    primary_evidence_strength: int = Field(ge=0, le=100)
    first_seen_at: AwareDatetime
    last_seen_at: AwareDatetime
    resolved_at: AwareDatetime | None
    occurrence_count: int = Field(ge=1)
    inventory_status: Literal["current", "unobserved", "stale", "unknown"]


class RiskSummaryView(StrictModel):
    id: UUID
    system_id: UUID
    finding_id: UUID | None
    threat_id: UUID | None
    title: str
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    score: int = Field(ge=1, le=25)
    level: Criticality
    status: Literal["open", "closed"]
    created_at: AwareDatetime
    evidence_status: Literal["current", "unobserved", "stale", "unknown"]


class VulnerabilityObservationSummaryView(StrictModel):
    id: UUID
    import_id: UUID
    system_id: UUID
    provider_finding_id: str
    asset_identifier: str
    ip_address: str | None
    hostname: str | None
    port: int | None = Field(ge=0, le=65_535)
    protocol: str | None
    cve_ids: list[str]
    title: str
    severity: VulnerabilitySeverity
    cvss_score: float | None = Field(ge=0, le=10)
    state: str
    observed_at: AwareDatetime | None
    matched_asset_id: UUID | None
    matched_service_id: UUID | None
    match_confidence: float | None = Field(ge=0, le=1)
    created_at: AwareDatetime
