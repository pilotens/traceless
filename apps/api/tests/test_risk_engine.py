import pytest

from traceless_api.services.risk_engine import assess_threat, assess_vulnerability


def test_cvss_and_match_confidence_are_not_used_as_exploitation_probability() -> None:
    assessment = assess_vulnerability(
        criticality="high",
        cvss_score=10.0,
        epss_score=None,
        is_kev=False,
        match_confidence=0.99,
    )

    assert assessment.likelihood == 1
    assert assessment.rationale["signals"]["technical_severity_cvss"] == 10.0
    assert "reachability is unknown" in assessment.rationale["uncertainty"]


def test_cvss_can_raise_technical_impact_without_changing_likelihood() -> None:
    low_severity = assess_vulnerability(
        criticality="low",
        cvss_score=2.0,
        epss_score=0.2,
        is_kev=False,
        match_confidence=0.95,
    )
    critical_severity = assess_vulnerability(
        criticality="low",
        cvss_score=9.8,
        epss_score=0.2,
        is_kev=False,
        match_confidence=0.95,
    )

    assert low_severity.likelihood == critical_severity.likelihood == 3
    assert low_severity.impact == 2
    assert critical_severity.impact == 5
    assert critical_severity.score > low_severity.score
    assert critical_severity.rationale["impact_components"] == {
        "business_impact": 2,
        "technical_impact_cvss": 5,
        "selected_impact": 5,
    }


def test_kev_requires_context_before_reaching_maximum_likelihood() -> None:
    unknown_context = assess_vulnerability(
        criticality="critical",
        cvss_score=9.8,
        epss_score=0.9,
        is_kev=True,
        match_confidence=0.9,
    )
    exposed = assess_vulnerability(
        criticality="critical",
        cvss_score=9.8,
        epss_score=0.9,
        is_kev=True,
        match_confidence=0.9,
        exposure="external",
        reachable=True,
    )

    assert unknown_context.likelihood == 4
    assert exposed.likelihood == 5


def test_verified_controls_reduce_current_but_not_inherent_risk() -> None:
    assessment = assess_vulnerability(
        criticality="high",
        cvss_score=8.8,
        epss_score=0.7,
        is_kev=False,
        match_confidence=0.95,
        exposure="external",
        reachable=True,
        control_effectiveness=0.9,
    )

    assert assessment.rationale["risk_stages"]["inherent"]["likelihood"] == 4
    assert assessment.likelihood == 3


def test_invalid_control_effectiveness_is_rejected() -> None:
    with pytest.raises(ValueError, match="control_effectiveness"):
        assess_vulnerability(
            criticality="medium",
            cvss_score=5.0,
            epss_score=0.1,
            is_kev=False,
            match_confidence=0.8,
            control_effectiveness=1.1,
        )


def test_threat_confidence_remains_uncertainty_not_likelihood() -> None:
    low_confidence = assess_threat(
        criticality="high", confidence=0.2, severity="critical", targeting=True
    )
    high_confidence = assess_threat(
        criticality="high", confidence=0.99, severity="critical", targeting=True
    )

    assert low_confidence.likelihood == high_confidence.likelihood == 2
    assert low_confidence.rationale["uncertainty"]
    assert high_confidence.rationale["uncertainty"] == []
