from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import select

from traceless_api.db.attack_chain_models import AttackChainAnalysisRow
from traceless_api.db.models import AuditEventRow


def _predicate(category: str, name: str, *arguments: str) -> dict[str, object]:
    return {"category": category, "name": name, "arguments": list(arguments)}


def _unit(
    unit_id: str,
    sequence: int,
    behavior_class: str,
    summary: str,
    preconditions: list[dict[str, object]],
    postconditions: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "unit_id": unit_id,
        "behavior": {
            "behavior_class": behavior_class,
            "summary": summary,
            "sequence": sequence,
            "confidence": 0.9,
        },
        "preconditions": preconditions,
        "postconditions": postconditions,
    }


def test_attack_chain_preview_is_persistent_deduplicated_and_hidden(
    client: TestClient,
) -> None:
    delivered = _predicate("file", "delivered", "victim_host", "invoice.pdf")
    opened = _predicate("user", "opened", "victim_host", "invoice.pdf")
    execution = _predicate(
        "privilege",
        "code_execution",
        "victim_host",
        "attacker",
    )
    payload = {
        "source_text": (
            "The victim opened invoice.pdf. The malicious document then enabled "
            "attacker code execution."
        ),
        "title": "Reachable-chain fixture",
        "markings": ["TLP:CLEAR"],
        "initial_facts": [delivered],
        "goal": execution,
        "candidate_units": [
            _unit(
                "open-document",
                0,
                "user_action",
                "The victim opened invoice.pdf.",
                [delivered],
                [opened],
            ),
            _unit(
                "exploit-document",
                1,
                "exploitation",
                "The malicious document enabled attacker code execution.",
                [opened],
                [execution],
            ),
        ],
    }

    created = client.post(
        "/api/v1/operational/intelligence/attack-chains/analyze",
        json=payload,
        headers={"X-Actor": "chain-analyst"},
    )
    assert created.status_code == 201, created.text
    assert created.headers["X-TLP"] == "TLP:CLEAR"
    created_body = created.json()
    assert created_body["reused"] is False
    analysis = created_body["analysis"]
    assert analysis["reachable"] is True
    assert analysis["unit_count"] == 2
    assert analysis["path_count"] == 1
    assert analysis["analysis"]["reasoning"]["paths"][0]["unit_ids"] == [
        "open-document",
        "exploit-document",
    ]

    repeated = client.post(
        "/api/v1/operational/intelligence/attack-chains/analyze",
        json=payload,
    )
    assert repeated.status_code == 200
    assert repeated.json()["reused"] is True
    assert repeated.json()["analysis"]["id"] == analysis["id"]

    listed = client.get("/api/v1/operational/intelligence/attack-chains")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert "analysis" not in listed.json()["items"][0]

    detail = client.get(
        f"/api/v1/operational/intelligence/attack-chains/{analysis['id']}"
    )
    assert detail.status_code == 200
    assert detail.json()["analysis"]["goal"] == execution

    rerun = client.post(
        f"/api/v1/operational/intelligence/attack-chains/{analysis['id']}/reason",
        json={"initial_facts": [delivered], "goal": execution},
    )
    assert rerun.status_code == 200
    assert rerun.headers["X-TLP"] == "TLP:CLEAR"
    assert rerun.json()["reachable"] is True

    invalid_reasoning = client.post(
        f"/api/v1/operational/intelligence/attack-chains/{analysis['id']}/reason",
        json={
            "initial_facts": [delivered],
            "goal": _predicate("custom", "invented_state", "victim_host"),
        },
    )
    assert invalid_reasoning.status_code == 409

    public_paths = client.get("/openapi.json").json()["paths"]
    assert not any("attack-chains" in path for path in public_paths)

    with client.app.state.session_factory() as session:
        row = session.scalar(select(AttackChainAnalysisRow))
        assert row is not None
        assert row.source_text is None
        assert row.source_text_retained is False
        audit = session.scalar(
            select(AuditEventRow).where(
                AuditEventRow.action == "attack_chain.analysis_created"
            )
        )
        assert audit is not None


def test_attack_chain_preview_rejects_tlp_red(client: TestClient) -> None:
    response = client.post(
        "/api/v1/operational/intelligence/attack-chains/analyze",
        json={
            "source_text": "The attacker executed a payload.",
            "markings": ["TLP:RED"],
        },
    )
    assert response.status_code == 409


def test_attack_chain_preview_requires_one_unambiguous_source(client: TestClient) -> None:
    missing = client.post(
        "/api/v1/operational/intelligence/attack-chains/analyze",
        json={},
    )
    assert missing.status_code == 422

    ambiguous = client.post(
        "/api/v1/operational/intelligence/attack-chains/analyze",
        json={
            "source_text": "The attacker executed payload.exe.",
            "source_record_id": "00000000-0000-0000-0000-000000000001",
        },
    )
    assert ambiguous.status_code == 422


def test_attack_chain_source_record_must_be_approved(client: TestClient) -> None:
    now = datetime.now(UTC).isoformat()
    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json={
            "schema_version": "1.0",
            "feed_id": "attack-chain-test",
            "feed_version": "1",
            "generated_at": now,
            "items": [
                {
                    "source_kind": "news",
                    "provider": "attack-chain-test",
                    "external_id": "report-1",
                    "record_type": "report",
                    "title": "Payload execution report",
                    "summary": "The attacker executed payload.exe.",
                    "modified_at": now,
                    "retrieved_at": now,
                    "markings": ["TLP:CLEAR"],
                    "raw_evidence": {"sentence": "The attacker executed payload.exe."},
                }
            ],
        },
    )
    assert imported.status_code == 200, imported.text
    record = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending"},
    ).json()["items"][0]

    blocked = client.post(
        "/api/v1/operational/intelligence/attack-chains/analyze",
        json={"source_record_id": record["id"]},
    )
    assert blocked.status_code == 409

    reviewed = client.patch(
        f"/api/v1/operational/intelligence/records/{record['id']}/review",
        json={"decision": "approved", "note": "Verified for chain extraction."},
        headers={"X-Actor": "chain-reviewer"},
    )
    assert reviewed.status_code == 200, reviewed.text

    analyzed = client.post(
        "/api/v1/operational/intelligence/attack-chains/analyze",
        json={"source_record_id": record["id"]},
    )
    assert analyzed.status_code == 201, analyzed.text
    assert analyzed.json()["analysis"]["source_record_id"] == record["id"]
