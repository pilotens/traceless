def test_risk_graph_exposes_business_context_and_ciso_summary(client):
    project_response = client.post(
        "/api/v1/operational/projects",
        json={"name": "Payments", "description": "Business critical payments"},
    )
    assert project_response.status_code == 201, project_response.text
    project_id = project_response.json()["id"]

    system_response = client.post(
        f"/api/v1/operational/projects/{project_id}/systems",
        json={
            "name": "Payment API",
            "description": "Processes customer payments",
            "owner": "Payments Platform",
            "criticality": "critical",
        },
    )
    assert system_response.status_code == 201, system_response.text
    system_id = system_response.json()["id"]

    architecture_response = client.post(
        f"/api/v1/operational/systems/{system_id}/architecture/versions",
        json={
            "title": "Business-linked architecture",
            "change_note": "Add business impact context",
            "base_snapshot_id": None,
            "graph": {
                "schema_version": "1.0",
                "publication_state": "draft",
                "warning": "Analyst-reviewed business context.",
                "business_context": {
                    "business_owner": "Head of Payments",
                    "capabilities": ["Accept payments"],
                    "processes": ["Card authorization"],
                    "data_categories": ["Payment data"],
                    "regulations": ["DORA", "PCI DSS"],
                    "recovery_time_objective_hours": 2,
                    "recovery_point_objective_hours": 0.5,
                    "impact": {
                        "confidentiality": 5,
                        "integrity": 5,
                        "availability": 5,
                        "financial": 5,
                        "regulatory": 5,
                        "reputation": 4,
                        "safety": 1,
                    },
                },
                "zones": [],
                "nodes": [],
                "edges": [],
                "risk_contexts": [],
            },
        },
    )
    assert architecture_response.status_code == 201, architecture_response.text

    response = client.get(f"/api/v1/operational/systems/{system_id}/risk-graph")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["business_context"]["business_owner"] == "Head of Payments"
    assert payload["business_context"]["capabilities"] == ["Accept payments"]
    assert payload["summary"]["security_score"] == 100
    assert payload["summary"]["critical_risks"] == 0
    assert any(node["kind"] == "business_capability" for node in payload["nodes"])
    assert any(node["kind"] == "regulation" for node in payload["nodes"])
    assert any(edge["relationship"] == "enabled_by" for edge in payload["edges"])


def test_architecture_business_context_rejects_duplicates(client):
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Context validation", "description": ""},
    ).json()
    system = client.post(
        f"/api/v1/operational/projects/{project['id']}/systems",
        json={
            "name": "Context system",
            "description": "",
            "owner": "Owner",
            "criticality": "medium",
        },
    ).json()
    response = client.post(
        f"/api/v1/operational/systems/{system['id']}/architecture/versions",
        json={
            "title": "Invalid context",
            "change_note": "",
            "base_snapshot_id": None,
            "graph": {
                "schema_version": "1.0",
                "publication_state": "draft",
                "warning": "Validation test",
                "business_context": {"capabilities": ["Payments", "Payments"]},
                "zones": [],
                "nodes": [],
                "edges": [],
                "risk_contexts": [],
            },
        },
    )
    assert response.status_code == 422
