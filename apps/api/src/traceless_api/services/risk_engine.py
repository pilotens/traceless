"""Deterministic risk policy that keeps source signals semantically separate."""

from dataclasses import dataclass
from typing import Any, Literal

POLICY_VERSION = "traceless-risk-policy/2.1"


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    likelihood: int
    impact: int
    score: int
    level: str
    rationale: dict[str, Any]


def risk_level(score: int) -> str:
    if score >= 17:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


def impact_for_criticality(criticality: str) -> int:
    return {"low": 2, "medium": 3, "high": 4, "critical": 5}[criticality]


def technical_impact_for_cvss(cvss_score: float | None) -> int | None:
    """Map CVSS technical severity to the same bounded impact scale."""

    if cvss_score is None:
        return None
    if not 0 <= cvss_score <= 10:
        raise ValueError("cvss_score must be between 0 and 10")
    if cvss_score >= 9:
        return 5
    if cvss_score >= 7:
        return 4
    if cvss_score >= 4:
        return 3
    if cvss_score > 0:
        return 2
    return 1


def _epss_likelihood(epss_score: float | None, is_kev: bool) -> tuple[int, str]:
    if is_kev:
        # KEV proves exploitation exists in the wild, but it does not prove
        # that this particular deployment is exposed or reachable.
        return 4, "CISA KEV establishes known exploitation in the wild"
    if epss_score is None:
        return 1, "No exploitation-probability signal is available"
    if epss_score >= 0.50:
        return 4, "EPSS is at least 0.50"
    if epss_score >= 0.10:
        return 3, "EPSS is between 0.10 and 0.50"
    if epss_score >= 0.01:
        return 2, "EPSS is between 0.01 and 0.10"
    return 1, "EPSS is below 0.01"


def assess_vulnerability(
    *,
    criticality: str,
    cvss_score: float | None,
    epss_score: float | None,
    is_kev: bool,
    match_confidence: float,
    exposure: Literal["external", "internal", "isolated", "unknown"] = "unknown",
    reachable: bool | None = None,
    control_effectiveness: float | None = None,
) -> RiskAssessment:
    """Assess contextual risk without treating CVSS or confidence as probability."""

    inherent_likelihood, likelihood_reason = _epss_likelihood(epss_score, is_kev)
    current_likelihood = inherent_likelihood
    modifiers: list[str] = []
    if reachable is False:
        current_likelihood = max(1, current_likelihood - 2)
        modifiers.append("verified non-reachability reduces current likelihood by two")
    elif exposure == "isolated":
        current_likelihood = max(1, current_likelihood - 2)
        modifiers.append("isolated exposure reduces current likelihood by two")
    elif exposure == "internal":
        current_likelihood = max(1, current_likelihood - 1)
        modifiers.append("internal-only exposure reduces current likelihood by one")
    elif exposure == "external" and reachable is True:
        current_likelihood = min(5, current_likelihood + 1)
        modifiers.append("verified external reachability raises current likelihood by one")

    if control_effectiveness is not None:
        if not 0 <= control_effectiveness <= 1:
            raise ValueError("control_effectiveness must be between 0 and 1")
        reduction = 2 if control_effectiveness >= 0.8 else 1 if control_effectiveness >= 0.5 else 0
        if reduction:
            current_likelihood = max(1, current_likelihood - reduction)
            modifiers.append(
                f"verified control effectiveness reduces current likelihood by {reduction}"
            )

    business_impact = impact_for_criticality(criticality)
    technical_impact = technical_impact_for_cvss(cvss_score)
    # CVSS remains technical severity rather than likelihood. It can raise the
    # impact dimension above business criticality, while a critical business
    # service cannot be made low-impact by a low vendor score.
    impact = max(
        business_impact,
        technical_impact if technical_impact is not None else business_impact,
    )
    score = current_likelihood * impact
    uncertainty = []
    if match_confidence < 0.75:
        uncertainty.append("finding applicability has low or moderate confidence")
    if exposure == "unknown":
        uncertainty.append("exposure is unknown")
    if reachable is None:
        uncertainty.append("reachability is unknown")
    if control_effectiveness is None:
        uncertainty.append("control effectiveness is unverified")

    return RiskAssessment(
        likelihood=current_likelihood,
        impact=impact,
        score=score,
        level=risk_level(score),
        rationale={
            "policy_version": POLICY_VERSION,
            "likelihood_reason": likelihood_reason,
            "business_criticality": criticality,
            "impact_reason": (
                "Maximum of business criticality and CVSS technical-impact band"
                if technical_impact is not None
                else "Business criticality; CVSS technical severity is unavailable"
            ),
            "risk_stages": {
                "inherent": {
                    "likelihood": inherent_likelihood,
                    "impact": impact,
                    "score": inherent_likelihood * impact,
                },
                "current": {
                    "likelihood": current_likelihood,
                    "impact": impact,
                    "score": score,
                },
            },
            "impact_components": {
                "business_impact": business_impact,
                "technical_impact_cvss": technical_impact,
                "selected_impact": impact,
            },
            "signals": {
                "technical_severity_cvss": cvss_score,
                "exploit_probability_epss": epss_score,
                "known_exploitation_kev": is_kev,
                "applicability_confidence": match_confidence,
                # Compatibility keys remain during the API transition.
                "cvss": cvss_score,
                "epss": epss_score,
                "kev": is_kev,
                "match_confidence": match_confidence,
            },
            "context": {
                "exposure": exposure,
                "reachable": reachable,
                "control_effectiveness": control_effectiveness,
                "modifiers": modifiers,
            },
            "uncertainty": uncertainty,
            "warning": (
                "CVSS is technical severity, EPSS is a dated probability estimate, KEV is "
                "catalogue membership, and evidence confidence is not likelihood."
            ),
        },
    )


def assess_threat(
    *,
    criticality: str,
    confidence: float,
    severity: str,
    targeting: bool = True,
    observed_activity: bool = False,
) -> RiskAssessment:
    """Assess a contextual threat without converting CTI confidence to probability."""

    likelihood = 4 if observed_activity else 2 if targeting else 1
    reason = (
        "Activity against this system is observed"
        if observed_activity
        else "Threat intelligence explicitly matches system technology"
        if targeting
        else "No system-specific targeting signal is available"
    )
    impact = impact_for_criticality(criticality)
    score = likelihood * impact
    return RiskAssessment(
        likelihood=likelihood,
        impact=impact,
        score=score,
        level=risk_level(score),
        rationale={
            "policy_version": POLICY_VERSION,
            "likelihood_reason": reason,
            "threat_confidence": confidence,
            "threat_severity": severity,
            "business_criticality": criticality,
            "signals": {
                "targeting": targeting,
                "observed_activity": observed_activity,
                "evidence_confidence": confidence,
            },
            "uncertainty": (
                [] if confidence >= 0.75 else ["threat evidence has low or moderate confidence"]
            ),
            "warning": (
                "Threat-intelligence confidence describes evidence certainty; it is not "
                "exploitation likelihood or proof of compromise."
            ),
        },
    )
