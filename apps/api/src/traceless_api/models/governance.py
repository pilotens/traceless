"""Typed contracts for business context, controls and closed-loop risk treatment."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from traceless_api.models.common import StrictModel

RiskLevel = Literal["low", "medium", "high", "critical"]


class BusinessImpactProfile(StrictModel):
    confidentiality: int = Field(default=3, ge=1, le=5)
    integrity: int = Field(default=3, ge=1, le=5)
    availability: int = Field(default=3, ge=1, le=5)
    financial: int = Field(default=3, ge=1, le=5)
    regulatory: int = Field(default=3, ge=1, le=5)
    reputation: int = Field(default=3, ge=1, le=5)
    safety: int = Field(default=1, ge=1, le=5)


class SystemContextCreate(StrictModel):
    business_owner: str = Field(default="", max_length=160)
    capabilities: list[str] = Field(default_factory=list, max_length=50)
    processes: list[str] = Field(default_factory=list, max_length=50)
    data_categories: list[str] = Field(default_factory=list, max_length=50)
    regulations: list[str] = Field(default_factory=list, max_length=50)
    recovery_time_objective_hours: float | None = Field(default=None, ge=0, le=8_760)
    recovery_point_objective_hours: float | None = Field(default=None, ge=0, le=8_760)
    impact_profile: BusinessImpactProfile = Field(default_factory=BusinessImpactProfile)

    @field_validator("capabilities", "processes", "data_categories", "regulations")
    @classmethod
    def normalized_unique_values(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value.strip()]
        if any(len(value) > 160 for value in normalized):
            raise ValueError("context values may not exceed 160 characters")
        if len(normalized) != len(set(normalized)):
            raise ValueError("context values must be unique")
        return normalized


class SystemContextView(SystemContextCreate):
    id: UUID
    system_id: UUID
    version: int
    status: Literal["draft", "published", "superseded"]
    created_by: str
    created_at: AwareDatetime
    published_by: str | None
    published_at: AwareDatetime | None


class RiskEvidenceLinkCreate(StrictModel):
    evidence_type: Literal["finding", "threat", "architecture", "control", "attack_chain", "manual"]
    evidence_id: str = Field(min_length=1, max_length=240)
    label: str = Field(min_length=2, max_length=500)
    source_version: str | None = Field(default=None, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskEvidenceLinkView(RiskEvidenceLinkCreate):
    id: UUID
    risk_id: UUID
    created_by: str
    created_at: AwareDatetime


class RiskTreatmentCreate(StrictModel):
    strategy: Literal["mitigate", "avoid", "transfer", "accept"] = "mitigate"
    title: str = Field(min_length=2, max_length=300)
    description: str = Field(default="", max_length=20_000)
    owner: str = Field(min_length=2, max_length=160)
    approver: str | None = Field(default=None, max_length=160)
    priority: RiskLevel
    due_at: datetime | None = None
    sla_days: int | None = Field(default=None, ge=0, le=3_650)
    verification_criteria: str = Field(default="", max_length=10_000)
    external_system: str | None = Field(default=None, max_length=80)
    external_key: str | None = Field(default=None, max_length=160)
    external_url: str | None = Field(default=None, max_length=2_000)

    @model_validator(mode="after")
    def due_date_or_sla_is_present(self) -> "RiskTreatmentCreate":
        if self.due_at is None and self.sla_days is None:
            raise ValueError("a due date or SLA must be provided")
        return self


class RiskTreatmentUpdate(StrictModel):
    status: (
        Literal["proposed", "approved", "in_progress", "verification", "closed", "cancelled"] | None
    ) = None
    owner: str | None = Field(default=None, min_length=2, max_length=160)
    approver: str | None = Field(default=None, max_length=160)
    due_at: datetime | None = None
    verification_criteria: str | None = Field(default=None, max_length=10_000)
    decision_note: str | None = Field(default=None, max_length=20_000)
    external_system: str | None = Field(default=None, max_length=80)
    external_key: str | None = Field(default=None, max_length=160)
    external_url: str | None = Field(default=None, max_length=2_000)
    residual_likelihood: int | None = Field(default=None, ge=1, le=5)
    residual_impact: int | None = Field(default=None, ge=1, le=5)

    @model_validator(mode="after")
    def residual_values_are_paired(self) -> "RiskTreatmentUpdate":
        if (self.residual_likelihood is None) != (self.residual_impact is None):
            raise ValueError("residual likelihood and impact must be provided together")
        return self


class RiskTreatmentView(StrictModel):
    id: UUID
    system_id: UUID
    risk_id: UUID
    strategy: Literal["mitigate", "avoid", "transfer", "accept"]
    title: str
    description: str
    owner: str
    approver: str | None
    status: Literal["proposed", "approved", "in_progress", "verification", "closed", "cancelled"]
    priority: RiskLevel
    due_at: AwareDatetime | None
    sla_days: int | None
    verification_criteria: str
    decision_note: str
    external_system: str | None
    external_key: str | None
    external_url: str | None
    residual_likelihood: int | None
    residual_impact: int | None
    residual_score: int | None
    residual_level: RiskLevel | None
    created_by: str
    created_at: AwareDatetime
    updated_at: AwareDatetime
    approved_by: str | None
    approved_at: AwareDatetime | None
    verified_by: str | None
    verified_at: AwareDatetime | None
    overdue: bool


class ControlCreate(StrictModel):
    control_key: str = Field(min_length=2, max_length=160)
    name: str = Field(min_length=2, max_length=300)
    description: str = Field(default="", max_length=20_000)
    framework: str = Field(default="", max_length=160)
    owner: str = Field(min_length=2, max_length=160)
    status: Literal["planned", "implemented", "retired"] = "planned"


class ControlView(ControlCreate):
    id: UUID
    system_id: UUID
    created_by: str
    created_at: AwareDatetime
    updated_at: AwareDatetime


class ControlAssessmentCreate(StrictModel):
    design_effectiveness: float = Field(ge=0, le=1)
    operating_effectiveness: float = Field(ge=0, le=1)
    result: Literal["effective", "partial", "ineffective", "not_tested"]
    evidence_reference: str = Field(min_length=2, max_length=10_000)
    valid_until: datetime | None = None


class ControlAssessmentView(ControlAssessmentCreate):
    id: UUID
    control_id: UUID
    assessed_by: str
    assessed_at: AwareDatetime


class AnalysisManifestCreate(StrictModel):
    purpose: str = Field(default="risk_governance", min_length=2, max_length=80)


class AnalysisManifestView(StrictModel):
    id: UUID
    system_id: UUID
    purpose: str
    architecture_snapshot_id: UUID | None
    system_context_version_id: UUID | None
    scan_job_id: UUID | None
    risk_policy_version: str
    source_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    components: dict[str, Any]
    created_by: str
    created_at: AwareDatetime


class GovernanceOverview(StrictModel):
    system_id: UUID
    published_context: SystemContextView | None
    draft_context: SystemContextView | None
    open_risks: int = Field(ge=0)
    risks_with_active_treatment: int = Field(ge=0)
    risks_without_owner: int = Field(ge=0)
    overdue_treatments: int = Field(ge=0)
    controls: int = Field(ge=0)
    controls_with_current_assessment: int = Field(ge=0)
    coverage_percent: int = Field(ge=0, le=100)
    latest_manifest: AnalysisManifestView | None


class PortfolioGovernanceItem(StrictModel):
    system_id: UUID
    system_name: str
    project_id: UUID
    criticality: RiskLevel
    business_owner: str
    open_risks: int
    overdue_treatments: int
    risks_without_owner: int
    coverage_percent: int


class PortfolioGovernanceView(StrictModel):
    systems: list[PortfolioGovernanceItem]
    open_risks: int
    overdue_treatments: int
    risks_without_owner: int
    average_coverage_percent: int = Field(ge=0, le=100)
