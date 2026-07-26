"""Purpose-specific reporting regression tests."""

import csv
import io
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from sqlalchemy.orm import Session

from traceless_api.services import reporting
from traceless_api.services.reporting import (
    ReportSnapshotConsistencyError,
    build_report_snapshot,
    prepare_report_transaction,
    render_report,
)


def _snapshot() -> dict[str, object]:
    base_risk = {
        "id": "risk-open",
        "title": "Open high risk",
        "likelihood": 4,
        "impact": 5,
        "score": 20,
        "level": "critical",
        "status": "open",
        "finding_id": "finding-open",
        "threat_id": None,
        "created_at": "2026-07-21T10:00:00Z",
    }
    return {
        "schema_version": "traceless-report/1.1",
        "system": {"id": "system-1", "name": "Payments", "criticality": "critical"},
        "latest_scan": {"id": "scan-1"},
        "latest_architecture": {"id": "architecture-1"},
        "assets": [{"id": "asset-1"}],
        "services": [{"id": "service-1"}],
        "findings": [
            {
                "id": "finding-open",
                "finding_type": "misconfiguration",
                "cve_id": None,
                "title": "=unsafe title",
                "lifecycle_status": "open",
                "inventory_status": "current",
                "status": "confirmed",
                "cvss_score": None,
                "epss_score": None,
                "is_kev": False,
                "asset_id": "asset-1",
                "service_id": None,
            },
            {
                "id": "finding-fixed",
                "finding_type": "vulnerability",
                "cve_id": "CVE-2099-12345",
                "title": "Fixed issue",
                "lifecycle_status": "fixed",
                "inventory_status": "current",
                "status": "likely",
                "cvss_score": 7.5,
                "epss_score": 0.2,
                "is_kev": False,
                "asset_id": "asset-1",
                "service_id": "service-1",
            },
        ],
        "threats": [{"id": "threat-1"}],
        "risks": [
            base_risk,
            {
                **base_risk,
                "id": "risk-closed",
                "title": "Closed higher-scored risk",
                "score": 25,
                "likelihood": 5,
                "status": "closed",
                "finding_id": "finding-fixed",
                "created_at": "2026-07-20T10:00:00Z",
            },
        ],
        "vulnerability_scan_imports": [{"id": "import-1"}],
        "vulnerability_observations": [{"id": "observation-1"}],
        "vulnerability_observations_truncated": True,
        "methodology": {"risk_scale": "likelihood 1-5 × impact 1-5"},
    }


def test_management_json_contains_only_decision_data_and_open_priorities() -> None:
    payload = json.loads(render_report(_snapshot(), format="json", report_type="management"))

    assert payload["report_type"] == "management"
    assert payload["summary"]["open_risks"] == 1
    assert payload["summary"]["closed_risks"] == 1
    assert payload["summary"]["active_findings"] == 1
    assert [risk["id"] for risk in payload["prioritized_open_risks"]] == ["risk-open"]
    assert "vulnerability_observations" not in payload
    assert "assets" not in payload


def test_technical_json_preserves_evidence_and_risk_register_preserves_status() -> None:
    snapshot = _snapshot()
    technical = json.loads(render_report(snapshot, format="json", report_type="technical"))
    register = json.loads(render_report(snapshot, format="json", report_type="risk_register"))

    assert technical["vulnerability_observations"] == [{"id": "observation-1"}]
    assert technical["vulnerability_observations_truncated"] is True
    assert "prioritized_open_risks" not in technical
    assert register["summary"] == {"closed": 1, "open": 1, "retired": 0, "total": 2}
    assert [risk["status"] for risk in register["risks"]] == ["open", "closed"]
    assert "findings" not in register


def test_retired_open_risk_is_not_presented_as_currently_open() -> None:
    snapshot = _snapshot()
    snapshot["current_risk_ids"] = []

    register = json.loads(render_report(snapshot, format="json", report_type="risk_register"))
    management = json.loads(render_report(snapshot, format="json", report_type="management"))

    assert register["summary"] == {"closed": 1, "open": 0, "retired": 1, "total": 2}
    retired = next(risk for risk in register["risks"] if risk["id"] == "risk-open")
    assert retired["status"] == "retired"
    assert retired["recorded_status"] == "open"
    assert retired["scope_status"] == "retired"
    assert management["prioritized_open_risks"] == []
    assert management["summary"]["retired_risks"] == 1


def test_each_csv_report_has_a_distinct_schema_and_neutralizes_formulas() -> None:
    snapshot = _snapshot()
    management = render_report(snapshot, format="csv", report_type="management").decode("utf-8-sig")
    technical = render_report(snapshot, format="csv", report_type="technical").decode("utf-8-sig")
    register = render_report(snapshot, format="csv", report_type="risk_register").decode(
        "utf-8-sig"
    )

    assert next(csv.reader(io.StringIO(management))) == ["metric", "value"]
    assert next(csv.reader(io.StringIO(technical)))[:4] == [
        "finding_id",
        "type",
        "cve_id",
        "title",
    ]
    assert next(csv.reader(io.StringIO(register)))[:2] == ["risk_id", "title"]
    assert "'=unsafe title" in technical


@pytest.mark.parametrize("report_type", ["management", "technical", "risk_register"])
def test_each_pdf_report_renders(report_type: str) -> None:
    content = render_report(_snapshot(), format="pdf", report_type=report_type)
    assert content.startswith(b"%PDF-")


def test_pdf_tables_do_not_silently_truncate_findings_or_risks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot()
    finding_template = snapshot["findings"][0]  # type: ignore[index]
    risk_template = snapshot["risks"][0]  # type: ignore[index]
    snapshot["findings"] = [
        {**finding_template, "id": f"finding-{index}", "title": f"Finding {index}"}
        for index in range(75)
    ]
    snapshot["risks"] = [
        {**risk_template, "id": f"risk-{index}", "title": f"Risk {index}"} for index in range(150)
    ]
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TracelessSmall", parent=styles["BodyText"], fontSize=7))
    captured: list[list[list[object]]] = []

    def capture(
        rows: list[list[object]],
        _: list[object] | None = None,
        **__: object,
    ) -> object:
        captured.append(rows)
        return object()

    monkeypatch.setattr(reporting, "_styled_table", capture)
    reporting._append_technical_pdf(
        [],
        styles,
        reporting._report_payload(snapshot, "technical"),
    )
    finding_rows = next(rows for rows in captured if rows[0][0] == "Fynd")
    assert len(finding_rows) == 76  # header + all 75 findings

    captured.clear()
    reporting._append_risk_register_pdf(
        [],
        styles,
        reporting._report_payload(snapshot, "risk_register"),
    )
    risk_rows = next(rows for rows in captured if rows[0][0] == "Risk")
    assert len(risk_rows) == 151  # header + all 150 risks


def test_invalid_report_type_and_format_are_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported report type"):
        render_report(_snapshot(), format="json", report_type="combined")
    with pytest.raises(ValueError, match="Unsupported report format"):
        render_report(_snapshot(), format="xml", report_type="management")


class _FingerprintSession:
    def __init__(self) -> None:
        self.expire_count = 0

    def get_bind(self) -> object:
        return SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

    def expire_all(self) -> None:
        self.expire_count += 1


def test_snapshot_builder_retries_until_consecutive_fingerprints_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states = [
        {"generation": "scan-a", "assets": ["asset-a"]},
        {"generation": "scan-b", "assets": ["asset-b"]},
        {"generation": "scan-b", "assets": ["asset-b"]},
    ]
    session = _FingerprintSession()
    repository = SimpleNamespace(session=session)

    def read_once(*_: object) -> dict[str, object]:
        return states.pop(0)

    monkeypatch.setattr(reporting, "_build_report_snapshot_once", read_once)
    snapshot = build_report_snapshot(repository, "system", max_consistency_reads=3)

    assert snapshot["generation"] == "scan-b"
    assert snapshot["consistency"] == "verified-consecutive-fingerprints"
    assert len(snapshot["source_fingerprint"]) == 64
    assert session.expire_count == 2


def test_snapshot_builder_fails_closed_when_fingerprint_never_stabilizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation = iter(range(3))
    session = _FingerprintSession()
    repository = SimpleNamespace(session=session)
    monkeypatch.setattr(
        reporting,
        "_build_report_snapshot_once",
        lambda *_: {"generation": next(generation)},
    )

    with pytest.raises(ReportSnapshotConsistencyError, match="changed"):
        build_report_snapshot(repository, "system", max_consistency_reads=3)


def test_postgres_report_transaction_requests_repeatable_read_before_queries() -> None:
    session = MagicMock(spec=Session)
    session.info = {}
    session.get_bind.return_value.dialect.name = "postgresql"
    session.in_transaction.return_value = False

    assert prepare_report_transaction(session) is True
    session.connection.assert_called_once_with(
        execution_options={"isolation_level": "REPEATABLE READ"}
    )
    assert prepare_report_transaction(session) is True
    session.connection.assert_called_once()


def test_started_postgres_worker_transaction_uses_fingerprints_without_isolation_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock(spec=Session)
    session.info = {}
    session.get_bind.return_value.dialect.name = "postgresql"
    session.in_transaction.return_value = True
    repository = SimpleNamespace(session=session)
    states = iter(
        [
            {"generation": "before-heartbeat"},
            {"generation": "after-heartbeat"},
            {"generation": "after-heartbeat"},
        ]
    )
    monkeypatch.setattr(
        reporting,
        "_build_report_snapshot_once",
        lambda *_: next(states),
    )

    snapshot = build_report_snapshot(repository, "system", max_consistency_reads=3)

    assert snapshot["generation"] == "after-heartbeat"
    assert snapshot["consistency"] == "verified-consecutive-fingerprints"
    session.connection.assert_not_called()


def test_custom_report_sections_control_payload_and_are_frozen():
    from traceless_api.services.reporting import freeze_report_configuration, render_report

    snapshot = _snapshot()
    selected = freeze_report_configuration(
        snapshot,
        report_type="technical",
        sections=["executive_summary", "risks", "limitations"],
    )
    payload = json.loads(
        render_report(
            snapshot,
            format="json",
            report_type="technical",
            sections=selected,
        )
    )
    assert payload["selected_sections"] == ["executive_summary", "risks", "limitations"]
    assert "summary" in payload
    assert "risks" in payload
    assert "limitations" in payload
    assert "assets" not in payload
    assert "findings" not in payload
    assert snapshot["report_configuration"]["sections"] == selected


def test_report_create_rejects_duplicate_sections():
    from pydantic import ValidationError

    from traceless_api.models.operational import ReportCreate

    with pytest.raises(ValidationError):
        ReportCreate(
            format="pdf",
            report_type="management",
            sections=["risks", "risks"],
        )
