"""Reassess current risks from a published business context version."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select

from traceless_api.db.governance_models import SystemContextVersionRow
from traceless_api.db.models import FindingRow, RiskRow, ThreatRow
from traceless_api.models.contextual_risk import ContextualRiskReassessmentView
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalRepository,
)
from traceless_api.services.risk_engine import assess_threat, assess_vulnerability

_IMPACT_KEYS = (
    "confidentiality",
    "integrity",
    "availability",
    "financial",
    "regulatory",
    "reputation",
    "safety",
)


def _criticality_for_impact(value: int) -> str:
    return {1: "low", 2: "low", 3: "medium", 4: "high", 5: "critical"}[value]


def _architecture_contexts(repository: OperationalRepository, system_id: UUID) -> dict[tuple[str, str | None], dict[str, Any]]:
    architecture = repository.latest_architecture(system_id)
    if architecture is None or not isinstance(architecture.graph, dict):
        return {}
    raw_contexts = architecture.graph.get("risk_contexts")
    if not isinstance(raw_contexts, list):
        return {}
    contexts: dict[tuple[str, str | None], dict[str, Any]] = {}
    for raw in raw_contexts:
        if not isinstance(raw, dict):
            continue
        asset_id = raw.get("asset_id")
        service_id = raw.get("service_id")
        if isinstance(asset_id, str):
            contexts[(asset_id, service_id if isinstance(service_id, str) else None)] = raw
    return contexts


def reassess_current_risks(
    repository: OperationalRepository,
    system_id: UUID,
    actor: str,
) -> ContextualRiskReassessmentView:
    repository.get_system(system_id)
    context = repository.session.scalar(
        select(SystemContextVersionRow)
        .where(
            SystemContextVersionRow.system_id == system_id,
            SystemContextVersionRow.status == "published",
        )
        .order_by(SystemContextVersionRow.version.desc())
    )
    if context is None:
        raise OperationalConflictError(
            "Risk reassessment requires a published business context version"
        )

    profile = {key: int(context.impact_profile.get(key, 1)) for key in _IMPACT_KEYS}
    selected_business_impact = max(profile.values())
    selected_dimensions = [
        key for key, value in profile.items() if value == selected_business_impact
    ]
    criticality = _criticality_for_impact(selected_business_impact)
    architecture_contexts = _architecture_contexts(repository, system_id)
    risks = list(
        repository.session.scalars(
            select(RiskRow)
            .where(RiskRow.system_id == system_id, RiskRow.status == "open")
            .order_by(RiskRow.created_at, RiskRow.id)
        )
    )

    updated = 0
    vulnerability_risks = 0
    threat_risks = 0
    warnings: list[str] = []
    for risk in risks:
        if risk.finding_id is not None:
            finding = repository.session.get(FindingRow, risk.finding_id)
            if finding is None:
                warnings.append(f"Risk {risk.id} references a missing finding")
                continue
            raw_context = architecture_contexts.get(
                (
                    str(finding.asset_id) if finding.asset_id is not None else "",
                    str(finding.service_id) if finding.service_id is not None else None,
                ),
                {},
            )
            assessment = assess_vulnerability(
                criticality=criticality,
                cvss_score=finding.cvss_score,
                epss_score=finding.epss_score,
                is_kev=finding.is_kev,
                match_confidence=finding.match_confidence,
                exposure=str(raw_context.get("exposure") or "unknown"),
                reachable=(
                    raw_context.get("reachable")
                    if isinstance(raw_context.get("reachable"), bool)
                    else None
                ),
                control_effectiveness=(
                    float(raw_context["control_effectiveness"])
                    if isinstance(raw_context.get("control_effectiveness"), (int, float))
                    else None
                ),
            )
            vulnerability_risks += 1
        elif risk.threat_id is not None:
            threat = repository.session.get(ThreatRow, risk.threat_id)
            if threat is None:
                warnings.append(f"Risk {risk.id} references a missing threat")
                continue
            provenance = threat.provenance if isinstance(threat.provenance, dict) else {}
            assessment = assess_threat(
                criticality=criticality,
                confidence=threat.confidence,
                severity=threat.severity,
                targeting=True,
                observed_activity=bool(provenance.get("observed_activity", False)),
            )
            threat_risks += 1
        else:
            warnings.append(f"Risk {risk.id} has no supported primary evidence")
            continue

        risk.likelihood = assessment.likelihood
        risk.impact = assessment.impact
        risk.score = assessment.score
        risk.level = assessment.level
        risk.rationale = {
            **assessment.rationale,
            "business_context": {
                "context_version_id": str(context.id),
                "context_version": context.version,
                "business_owner": context.business_owner,
                "impact_profile": profile,
                "selected_business_impact": selected_business_impact,
                "selected_impact_dimensions": selected_dimensions,
                "recovery_time_objective_hours": context.recovery_time_objective_hours,
                "recovery_point_objective_hours": context.recovery_point_objective_hours,
                "regulations": context.regulations,
            },
        }
        updated += 1

    repository.session.flush()
    repository.audit(
        actor,
        "risks.contextually_reassessed",
        "system",
        system_id,
        {
            "context_version_id": str(context.id),
            "risks_considered": len(risks),
            "risks_updated": updated,
        },
    )
    return ContextualRiskReassessmentView(
        system_id=system_id,
        context_version_id=context.id,
        context_version=context.version,
        risks_considered=len(risks),
        risks_updated=updated,
        vulnerability_risks=vulnerability_risks,
        threat_risks=threat_risks,
        selected_business_impact=selected_business_impact,
        selected_impact_dimensions=selected_dimensions,
        warnings=warnings,
    )
