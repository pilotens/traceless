"""Contracts for business-context-aware risk reassessment."""

from uuid import UUID

from pydantic import Field

from traceless_api.models.common import StrictModel


class ContextualRiskReassessmentView(StrictModel):
    system_id: UUID
    context_version_id: UUID
    context_version: int = Field(ge=1)
    risks_considered: int = Field(ge=0)
    risks_updated: int = Field(ge=0)
    vulnerability_risks: int = Field(ge=0)
    threat_risks: int = Field(ge=0)
    selected_business_impact: int = Field(ge=1, le=5)
    selected_impact_dimensions: list[str]
    warnings: list[str] = Field(default_factory=list)
