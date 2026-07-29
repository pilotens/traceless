from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient

from traceless_api.db.models import RiskRow, ThreatRow


def _system_with_risk(client: TestClient) -> tuple[str, str]:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Governance project", "description": ""},
    )
    assert project.status_code == 201, project.text
    system = client.post(
        f"/api/v1/operational/projects/{project.json()['id']}/systems",
        json={
            "name": "Governed API",
            "description": "",
            "owner": "Platform",
            "criticality": "critical",
        },
    )
    assert system.status_code == 201, system.text
    system_id = system.json()["id"]
    system_uuid = UUID(system_id)

    with client.app.state.session_factory() as session:
        threat = ThreatRow(
            system_id=system_uuid,
            source="governance-test",
            external_id="threat-1",
            title="Targeted campaign",
            description="System-specific threat",
            severity="high",
            confidence=0.9,
            attack_patterns=["T1190"],
            affected_products=[],
            matched_asset_ids=[],
            provenance={"source": "test"},
            modified_at=datetime.now(UTC),
        )
        session.add(threat)
        session.flush()
        risk = RiskRow(
            system_id=system_uuid,
            finding_id=None,
            threat_id=threat.id,
            title="Compromise through targeted campaign",
            likelihood=2,
            impact=5,
            score=10,
            level="high",
            status="open",
            rationale={"policy_version": "test"},
            evidence_status="current",
        )
        session.add(risk)
        session.commit()
        risk_id = str(risk.id)
    return system_id, risk_id


def test_closed_loop_context_treatment_control_and_manifest(client: TestClient) -> None:
    system_id, risk_id = _system_with_risk(client)

    context = client.post(
        f"/api/v1/operational/systems/{system_id}/context/versions",
        json={
            "business_owner": "Head of Payments",
            "capabilities": ["Accept payments"],
            "processes": ["Authorization"],
            "data_categories": ["Payment data"],
            "regulations": ["DORA"],
            "recovery_time_objective_hours": 2,
            "recovery_point_objective_hours": 0.5,
            "impact_profile": {
                "confidentiality": 5,
                "integrity": 5,
                "availability": 5,
                "financial": 5,
                "regulatory": 5,
                "reputation": 4,
                "safety": 1,
            },
        },
    )
    assert context.status_code == 201, context.text
    published = client.post(
        f"/api/v1/operational/systems/{system_id}/context/versions/{context.json()['id']}/publish"
    )
    assert published.status_code == 200, published.text
    assert published.json()["status"] == "published"

    reassessed = client.post(
        f"/api/v1/operational/systems/{system_id}/risks/reassess"
    )
    assert reassessed.status_code == 200, reassessed.text
    assert reassessed.json()["risks_updated"] == 1
    assert reassessed.json()["selected_business_impact"] == 5
    risk_detail = client.get(
        f"/api/v1/operational/systems/{system_id}/risks/{risk_id}"
    )
    assert risk_detail.status_code == 200, risk_detail.text
    assert risk_detail.json()["rationale"]["business_context"]["context_version"] == 1
    assert "regulatory" in risk_detail.json()["rationale"]["business_context"][
        "selected_impact_dimensions"
    ]

    evidence = client.post(
        f"/api/v1/operational/systems/{system_id}/risks/{risk_id}/evidence",
        json={
            "evidence_type": "manual",
            "evidence_id": "review-2026-07",
            "label": "Analyst review",
            "source_version": "1",
            "metadata": {"reviewed": True},
        },
    )
    assert evidence.status_code == 201, evidence.text

    treatment = client.post(
        f"/api/v1/operational/systems/{system_id}/risks/{risk_id}/treatments",
        json={
            "strategy": "mitigate",
            "title": "Restrict exposure",
            "description": "",
            "owner": "Platform Team",
            "priority": "critical",
            "sla_days": 7,
            "verification_criteria": "External reachability is removed.",
        },
    )
    assert treatment.status_code == 201, treatment.text
    approved = client.patch(
        f"/api/v1/operational/systems/{system_id}/treatments/{treatment.json()['id']}",
        json={
            "status": "approved",
            "decision_note": "Approved by risk owner.",
        },
    )
    assert approved.status_code == 200, approved.text

    control = client.post(
        f"/api/v1/operational/systems/{system_id}/controls",
        json={
            "control_key": "ISO27001-A.8.8",
            "name": "Technical vulnerability management",
            "description": "",
            "framework": "ISO 27001",
            "owner": "Security",
            "status": "implemented",
        },
    )
    assert control.status_code == 201, control.text
    assessment = client.post(
        f"/api/v1/operational/systems/{system_id}/controls/{control.json()['id']}/assessments",
        json={
            "design_effectiveness": 0.8,
            "operating_effectiveness": 0.7,
            "result": "partial",
            "evidence_reference": "Internal control test 2026-07",
            "valid_until": (datetime.now(UTC) + timedelta(days=90)).isoformat(),
        },
    )
    assert assessment.status_code == 201, assessment.text

    manifest = client.post(
        f"/api/v1/operational/systems/{system_id}/analysis-manifests",
        json={"purpose": "risk_governance"},
    )
    assert manifest.status_code == 201, manifest.text
    assert len(manifest.json()["source_fingerprint"]) == 64

    overview = client.get(f"/api/v1/operational/systems/{system_id}/governance/overview")
    assert overview.status_code == 200, overview.text
    assert overview.json()["published_context"]["business_owner"] == "Head of Payments"
    assert overview.json()["risks_with_active_treatment"] == 1
    assert overview.json()["controls"] == 1


def test_treatment_cannot_close_without_residual_risk(client: TestClient) -> None:
    system_id, risk_id = _system_with_risk(client)
    treatment = client.post(
        f"/api/v1/operational/systems/{system_id}/risks/{risk_id}/treatments",
        json={
            "strategy": "mitigate",
            "title": "Patch",
            "description": "",
            "owner": "Platform Team",
            "priority": "high",
            "due_at": (datetime.now(UTC) + timedelta(days=14)).isoformat(),
            "verification_criteria": "Patch is verified.",
        },
    )
    assert treatment.status_code == 201
    closed = client.patch(
        f"/api/v1/operational/systems/{system_id}/treatments/{treatment.json()['id']}",
        json={"status": "closed", "decision_note": "Done"},
    )
    assert closed.status_code == 409
