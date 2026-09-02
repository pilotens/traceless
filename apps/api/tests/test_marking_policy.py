from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select

from traceless_api.core.markings import (
    TLP_AMBER,
    TLP_AMBER_STRICT,
    TLP_CLEAR,
    TLP_RED,
    most_restrictive_tlp,
    normalize_markings,
    permits_automated_processing,
    permits_org_export,
    tlp_marking,
)
from traceless_api.db.models import GlobalIntelRecordRow, GlobalIntelRevisionRow, ReportRow
from traceless_api.models.intelligence_hub import CanonicalIntelRecord


def _record(**overrides: object) -> CanonicalIntelRecord:
    values: dict[str, object] = {
        "source_kind": "news",
        "provider": "separate-scraper",
        "external_id": "article-42",
        "record_type": "report",
        "title": "Source-grounded threat report",
        "summary": "Normalized source evidence for analyst review.",
        "modified_at": "2026-07-21T08:00:00Z",
        "retrieved_at": "2026-07-21T08:01:00Z",
        "raw_evidence": {"source_id": "article-42"},
    }
    values.update(overrides)
    return CanonicalIntelRecord.model_validate(values)


def _system_with_inventory(client: TestClient) -> str:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Marking project", "description": "Report policy regression"},
    ).json()
    system = client.post(
        f"/api/v1/operational/projects/{project['id']}/systems",
        json={
            "name": "Marked system",
            "description": "Organization-confidential inventory",
            "owner": "Security",
            "criticality": "high",
        },
    ).json()
    authorization = client.post(
        f"/api/v1/operational/systems/{system['id']}/scan-authorizations",
        json={
            "targets": ["100.64.0.10"],
            "profile": "service_inventory",
            "approved_by": "System owner",
            "purpose": "Marking policy verification",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "confirmation": "Jag bekräftar att jag har tillstånd att skanna angivna mål.",
        },
    ).json()
    source_completed_at = int(datetime.now(UTC).timestamp()) - 300
    scanned = client.post(
        f"/api/v1/operational/systems/{system['id']}/scans/import/nmap",
        params={"authorization_id": authorization["id"]},
        content=f"""<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.99" start="{source_completed_at - 10}">
          <host><status state="up"/><address addr="100.64.0.10" addrtype="ipv4"/>
            <hostnames><hostname name="gateway.example.invalid" type="PTR"/></hostnames>
            <ports><port protocol="tcp" portid="443"><state state="open"/>
              <service name="https" product="Example Gateway" version="1.0"/>
            </port></ports>
          </host><runstats><finished time="{source_completed_at}" exit="success"/></runstats>
        </nmaprun>""".encode(),
        headers={"Content-Type": "application/xml"},
    )
    assert scanned.status_code == 201, scanned.text
    return system["id"]


def _import_review_and_correlate_marked_threat(
    client: TestClient,
    system_id: str,
    *,
    modified_at: datetime,
    marking: str,
) -> str:
    record = _record(
        record_type="threat",
        title="Gateway exploitation campaign",
        summary="A reviewed campaign targeting the exact observed product.",
        affected_products=["Example Gateway"],
        modified_at=modified_at,
        retrieved_at=modified_at,
        markings=[marking],
    )
    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json={
            "schema_version": "1.0",
            "feed_id": "marked-report-source",
            "feed_version": modified_at.isoformat(),
            "generated_at": modified_at.isoformat(),
            "items": [record.model_dump(mode="json")],
        },
    )
    assert imported.status_code == 200, imported.text
    pending = client.get(
        "/api/v1/operational/intelligence/records",
        params={"review_status": "pending"},
    ).json()["items"]
    record_id = pending[0]["id"]
    approved = client.patch(
        f"/api/v1/operational/intelligence/records/{record_id}/review",
        json={"decision": "approved", "note": "Verified report source."},
    )
    assert approved.status_code == 200, approved.text
    correlated = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/correlate"
    )
    assert correlated.status_code == 200, correlated.text
    return record_id


def test_unmarked_intelligence_defaults_to_tlp_amber() -> None:
    assert _record().markings == [TLP_AMBER]
    assert normalize_markings([]) == [TLP_AMBER]
    assert tlp_marking([]) == TLP_AMBER


def test_tlp_white_is_normalized_to_tlp_clear_without_losing_other_markings() -> None:
    record = _record(markings=["TLP:WHITE", "PAP:GREEN"])

    assert record.markings == [TLP_CLEAR, "PAP:GREEN"]


@pytest.mark.parametrize(
    "markings",
    [
        ["TLP:GREEN", "TLP:AMBER"],
        ["TLP:BLUE"],
        ["TLP:RED", "tlp:red"],
    ],
)
def test_ambiguous_or_unknown_tlp_markings_are_rejected(markings: list[str]) -> None:
    with pytest.raises(ValidationError):
        _record(markings=markings)


def test_tlp_red_is_fail_closed_for_automation_and_org_exports() -> None:
    assert not permits_automated_processing([TLP_RED])
    assert not permits_org_export([TLP_RED])
    assert permits_automated_processing([TLP_AMBER_STRICT])
    assert permits_org_export([TLP_AMBER_STRICT])
    assert most_restrictive_tlp([[TLP_CLEAR], [TLP_AMBER_STRICT]]) == TLP_AMBER_STRICT


def test_tlp_red_feed_is_quarantined_without_a_queryable_record(
    client: TestClient,
) -> None:
    record = _record(markings=[TLP_RED])
    response = client.post(
        "/api/v1/operational/intelligence/records/import",
        json={
            "schema_version": "1.0",
            "feed_id": "named-recipient-feed",
            "feed_version": "1",
            "generated_at": "2026-07-21T08:01:00Z",
            "items": [record.model_dump(mode="json")],
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["quarantined"] == 1
    assert "TLP:RED" in response.json()["warnings"][0]
    assert client.get("/api/v1/operational/intelligence/records").json()["total"] == 0
    with client.app.state.session_factory() as session:
        assert session.scalar(select(GlobalIntelRecordRow.id)) is None
        revision = session.scalar(select(GlobalIntelRevisionRow))
        assert revision is not None
        assert revision.outcome == "quarantined"
        assert revision.quarantine_reason == "tlp_red_requires_named_recipient_controls"
        assert revision.raw_evidence == {
            "restricted_payload_sha256": revision.raw_sha256
        }


def test_red_reclassification_hides_current_record_but_stale_or_future_red_cannot_poison_it(
    client: TestClient,
) -> None:
    base = datetime.now(UTC) - timedelta(minutes=10)

    def import_record(*, modified_at: datetime, markings: list[str]) -> object:
        record = _record(
            modified_at=modified_at,
            retrieved_at=modified_at,
            markings=markings,
        )
        return client.post(
            "/api/v1/operational/intelligence/records/import",
            json={
                "schema_version": "1.0",
                "feed_id": "reclassification-feed",
                "feed_version": modified_at.isoformat(),
                "generated_at": modified_at.isoformat(),
                "items": [record.model_dump(mode="json")],
            },
        )

    created = import_record(modified_at=base, markings=[TLP_CLEAR])
    record_id = client.get("/api/v1/operational/intelligence/records").json()["items"][0][
        "id"
    ]
    approved = client.patch(
        f"/api/v1/operational/intelligence/records/{record_id}/review",
        json={"decision": "approved", "note": "Reviewed source."},
    )
    assert created.status_code == approved.status_code == 200

    stale_red = import_record(
        modified_at=base - timedelta(minutes=1), markings=[TLP_RED]
    )
    assert stale_red.json()["unchanged"] == 1
    visible = client.get("/api/v1/operational/intelligence/records").json()
    assert visible["total"] == 1
    assert visible["items"][0]["review_status"] == "approved"

    future_red = import_record(
        modified_at=datetime.now(UTC) + timedelta(hours=2), markings=[TLP_RED]
    )
    assert future_red.json()["quarantined"] == 1
    assert client.get("/api/v1/operational/intelligence/records").json()["total"] == 1

    legitimate = import_record(
        modified_at=base + timedelta(minutes=1), markings=[TLP_CLEAR]
    )
    assert legitimate.json()["updated"] == 1

    restricted = import_record(
        modified_at=base + timedelta(minutes=2), markings=[TLP_RED]
    )
    assert restricted.json()["quarantined"] == 1
    assert client.get("/api/v1/operational/intelligence/records").json()["total"] == 0
    assert client.get(
        f"/api/v1/operational/intelligence/records/{record_id}"
    ).status_code == 404
    with client.app.state.session_factory() as session:
        row = session.get(GlobalIntelRecordRow, UUID(record_id))
        assert row is not None
        assert row.distribution_tlp == TLP_RED
        assert row.review_status == "pending"
        assert row.revoked is True


def test_operational_report_has_amber_floor_and_withdraws_after_stricter_marking(
    client: TestClient,
) -> None:
    system_id = _system_with_inventory(client)
    base = datetime.now(UTC) - timedelta(minutes=5)
    record_id = _import_review_and_correlate_marked_threat(
        client,
        system_id,
        modified_at=base,
        marking=TLP_CLEAR,
    )
    created = client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "json", "report_type": "management"},
    )
    assert created.status_code == 201, created.text
    report_id = created.json()["id"]
    assert created.json()["distribution_tlp"] == TLP_AMBER
    assert created.json()["export_status"] == "available"

    revised = _record(
        record_type="threat",
        title="Gateway exploitation campaign",
        summary="A reviewed campaign targeting the exact observed product.",
        affected_products=["Example Gateway"],
        modified_at=base + timedelta(seconds=1),
        retrieved_at=base + timedelta(seconds=1),
        markings=[TLP_AMBER_STRICT],
    )
    imported = client.post(
        "/api/v1/operational/intelligence/records/import",
        json={
            "schema_version": "1.0",
            "feed_id": "marked-report-source",
            "feed_version": "strict-2",
            "generated_at": (base + timedelta(seconds=1)).isoformat(),
            "items": [revised.model_dump(mode="json")],
        },
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["updated"] == 1

    listed = client.get(f"/api/v1/operational/systems/{system_id}/reports").json()
    assert listed[0]["id"] == report_id
    assert listed[0]["export_status"] == "withdrawn"
    assert listed[0]["withdrawal_reason"]
    assert client.get(
        f"/api/v1/operational/reports/{report_id}/download"
    ).status_code == 409

    # A later RED reclassification also blocks generation while historical
    # correlated provenance still references the now-restricted source.
    red = revised.model_copy(
        update={
            "modified_at": base + timedelta(seconds=2),
            "retrieved_at": base + timedelta(seconds=2),
            "markings": [TLP_RED],
        }
    )
    restricted = client.post(
        "/api/v1/operational/intelligence/records/import",
        json={
            "schema_version": "1.0",
            "feed_id": "marked-report-source",
            "feed_version": "red-3",
            "generated_at": (base + timedelta(seconds=2)).isoformat(),
            "items": [red.model_dump(mode="json")],
        },
    )
    assert restricted.status_code == 200, restricted.text
    assert restricted.json()["quarantined"] == 1
    assert client.post(
        f"/api/v1/operational/systems/{system_id}/reports",
        json={"format": "json", "report_type": "management"},
    ).status_code == 409
    with client.app.state.session_factory() as session:
        assert session.get(GlobalIntelRecordRow, UUID(record_id)).distribution_tlp == TLP_RED


@pytest.mark.parametrize("legacy_tlp", [TLP_CLEAR, "TLP:GREEN"])
def test_legacy_underclassified_report_is_withdrawn_without_source_manifest(
    client: TestClient,
    legacy_tlp: str,
) -> None:
    system_id = _system_with_inventory(client)
    content = b"legacy report bytes"
    with client.app.state.session_factory() as session:
        report = ReportRow(
            system_id=UUID(system_id),
            format="json",
            report_type="management",
            snapshot={"schema_version": "traceless-report/1.1", "distribution_tlp": legacy_tlp},
            content=content,
            sha256=sha256(content).hexdigest(),
        )
        session.add(report)
        session.commit()
        report_id = report.id

    response = client.get(f"/api/v1/operational/reports/{report_id}/download")
    assert response.status_code == 409
    assert "baseline" in response.json()["detail"]


def test_legacy_nested_risk_provenance_is_subject_to_current_marking(
    client: TestClient,
) -> None:
    system_id = _system_with_inventory(client)
    base = datetime.now(UTC) - timedelta(minutes=5)
    record_id = _import_review_and_correlate_marked_threat(
        client,
        system_id,
        modified_at=base,
        marking=TLP_CLEAR,
    )
    content = b"legacy nested provenance"
    with client.app.state.session_factory() as session:
        record = session.get(GlobalIntelRecordRow, UUID(record_id))
        assert record is not None
        record.distribution_tlp = TLP_AMBER_STRICT
        record.markings = [TLP_AMBER_STRICT]
        report = ReportRow(
            system_id=UUID(system_id),
            format="json",
            report_type="risk_register",
            snapshot={
                "schema_version": "traceless-report/1.1",
                "distribution_tlp": TLP_AMBER,
                "risks": [
                    {
                        "rationale": {
                            "retired_threat_provenance": {
                                "global_intel_record_id": record_id
                            }
                        }
                    }
                ],
            },
            content=content,
            sha256=sha256(content).hexdigest(),
        )
        session.add(report)
        session.commit()
        report_id = report.id

    response = client.get(f"/api/v1/operational/reports/{report_id}/download")
    assert response.status_code == 409
    assert "stricter" in response.json()["detail"]
