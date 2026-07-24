"""Deterministic, purpose-specific security report renderers."""

import csv
import hashlib
import io
import json
from collections.abc import Iterable
from typing import Any
from uuid import UUID
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from traceless_api.core.markings import (
    TLP_AMBER,
    TLP_RED,
    is_more_restrictive_tlp,
    most_restrictive_tlp,
)
from traceless_api.db.models import FindingEvidenceRow, GlobalIntelRecordRow, ThreatRow
from traceless_api.models.operational import (
    ArchitectureSnapshotView,
    AssetView,
    FindingView,
    OperationalSystemView,
    RiskView,
    ScanJobView,
    ServiceView,
    ThreatView,
    VulnerabilityObservationView,
    VulnerabilityScanImportView,
)
from traceless_api.services.intelligence_hub import IntelligenceHubService
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalRepository,
)

REPORT_TYPES = {"management", "technical", "risk_register"}
_REPORT_ISOLATION_MARKER = "traceless_report_repeatable_read"


class ReportSnapshotConsistencyError(RuntimeError):
    """Raised when a non-repeatable database never yields a stable report view."""


def prepare_report_transaction(session: Session) -> bool:
    """Start PostgreSQL report work at REPEATABLE READ before the first statement.

    The synchronous report route calls this through :func:`build_report_snapshot`.
    A background worker has already loaded and fenced its job row, so it deliberately
    falls back to consecutive fingerprints instead of sharing a repeatable-read
    transaction with its concurrent heartbeat. PostgreSQL cannot change isolation
    after a statement has executed.
    """

    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return False
    if session.info.get(_REPORT_ISOLATION_MARKER) is True:
        return True
    if session.in_transaction():
        return False
    session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
    session.info[_REPORT_ISOLATION_MARKER] = True
    return True


def build_report_snapshot(
    repository: OperationalRepository,
    system_id: Any,
    *,
    max_consistency_reads: int = 4,
) -> dict[str, Any]:
    """Freeze one coherent evidence view before deriving a purpose-specific report.

    PostgreSQL reads run in a single repeatable-read transaction. SQLite and any
    already-started transaction are accepted only after two consecutive canonical
    snapshots have the same source fingerprint. This fails closed instead of storing
    a report assembled across two changing inventory generations.
    """

    if max_consistency_reads < 2:
        raise ValueError("max_consistency_reads must be at least 2")
    if prepare_report_transaction(repository.session):
        snapshot = _build_report_snapshot_once(repository, system_id)
        snapshot["source_fingerprint"] = _snapshot_fingerprint(snapshot)
        snapshot["consistency"] = "postgresql-repeatable-read"
        return snapshot

    previous: dict[str, Any] | None = None
    previous_fingerprint: str | None = None
    for _ in range(max_consistency_reads):
        candidate = _build_report_snapshot_once(repository, system_id)
        fingerprint = _snapshot_fingerprint(candidate)
        if previous_fingerprint == fingerprint:
            candidate["source_fingerprint"] = fingerprint
            candidate["consistency"] = "verified-consecutive-fingerprints"
            return candidate
        previous = candidate
        previous_fingerprint = fingerprint
        repository.session.expire_all()
    del previous
    raise ReportSnapshotConsistencyError(
        "Operational data changed while the report snapshot was being frozen"
    )


def _build_report_snapshot_once(
    repository: OperationalRepository, system_id: Any
) -> dict[str, Any]:
    repository.get_system(system_id)
    IntelligenceHubService(repository).retire_nonprocessable_effects(
        system_ids={system_id}
    )
    system = OperationalSystemView.model_validate(repository.get_system(system_id))
    scan = repository.latest_completed_scan(system_id)
    assets = repository.list_assets_for_scan(system_id, scan.id) if scan is not None else []
    services = repository.list_services_for_scan(system_id, scan.id) if scan is not None else []
    findings = repository.list_findings(system_id)
    threats = (
        repository.list_threats_for_inventory(
            system_id,
            scan_id=scan.id,
            asset_ids={str(asset.id) for asset in assets},
        )
        if scan is not None
        else []
    )
    current_risks = repository.list_current_risks(
        system_id,
        finding_ids={
            finding.id for finding in findings if finding.inventory_status == "current"
        },
        threat_ids={threat.id for threat in threats},
    )
    all_risks = repository.list_all_risks(system_id)
    reported_threat_ids = {
        risk.threat_id for risk in all_risks if risk.threat_id is not None
    }
    reported_threats = (
        list(
            repository.session.scalars(
                select(ThreatRow).where(
                    ThreatRow.system_id == system_id,
                    ThreatRow.id.in_(reported_threat_ids),
                )
            )
        )
        if reported_threat_ids
        else []
    )
    architecture = repository.latest_architecture(system_id)
    vulnerability_imports = repository.list_vulnerability_scan_imports(system_id)
    vulnerability_observations = repository.list_vulnerability_observations(
        system_id, limit=2_000
    )
    vulnerability_observation_total = sum(
        item.observation_count for item in vulnerability_imports
    )
    # Operational inventory is organization-confidential even when every CTI
    # input is CLEAR/GREEN. Imported markings may only make this stricter.
    source_markings: list[list[str]] = [[TLP_AMBER]]
    global_intel_record_ids: set[str] = set()
    for finding in findings:
        for source in finding.sources:
            global_record_id = source.get("global_intel_record_id")
            if isinstance(global_record_id, str):
                global_intel_record_ids.add(global_record_id)
            markings = source.get("markings")
            if isinstance(markings, list) and all(
                isinstance(marking, str) for marking in markings
            ):
                source_markings.append(markings)
    reported_finding_ids = {finding.id for finding in findings}
    historical_evidence = (
        repository.session.scalars(
            select(FindingEvidenceRow).where(
                FindingEvidenceRow.finding_id.in_(reported_finding_ids)
            )
        )
        if reported_finding_ids
        else []
    )
    for evidence in historical_evidence:
        global_record_id = evidence.payload.get("global_intel_record_id")
        if isinstance(global_record_id, str):
            global_intel_record_ids.add(global_record_id)
        markings = evidence.payload.get("markings")
        if isinstance(markings, list) and all(
            isinstance(marking, str) for marking in markings
        ):
            source_markings.append(markings)
    for threat in reported_threats:
        global_record_id = threat.provenance.get("global_intel_record_id")
        if isinstance(global_record_id, str):
            global_intel_record_ids.add(global_record_id)
        markings = threat.provenance.get("markings")
        if isinstance(markings, list) and all(
            isinstance(marking, str) for marking in markings
        ):
            source_markings.append(markings)
    current_global_rows = _current_global_intel_rows(
        repository.session, global_intel_record_ids
    )
    source_markings.extend(
        [row.distribution_tlp, *row.markings] for row in current_global_rows
    )
    distribution_tlp = most_restrictive_tlp(source_markings)
    if distribution_tlp == TLP_RED:
        raise OperationalConflictError(
            "A report cannot include TLP:RED evidence without named-recipient enforcement"
        )
    return {
        "schema_version": "traceless-report/1.2",
        "distribution_tlp": distribution_tlp,
        "global_intel_record_ids": sorted(global_intel_record_ids),
        "system": system.model_dump(mode="json"),
        "latest_scan": (ScanJobView.model_validate(scan).model_dump(mode="json") if scan else None),
        "latest_architecture": (
            ArchitectureSnapshotView.model_validate(architecture).model_dump(mode="json")
            if architecture
            else None
        ),
        "assets": [
            AssetView.model_validate(row).model_dump(mode="json")
            for row in assets
        ],
        "services": [
            ServiceView.model_validate(row).model_dump(mode="json")
            for row in services
        ],
        "findings": [
            FindingView.model_validate(row).model_dump(mode="json")
            for row in findings
        ],
        "vulnerability_scan_imports": [
            VulnerabilityScanImportView.model_validate(row).model_dump(mode="json")
            for row in vulnerability_imports
        ],
        "vulnerability_observations": [
            VulnerabilityObservationView.model_validate(row).model_dump(mode="json")
            for row in vulnerability_observations
        ],
        "vulnerability_observations_truncated": (
            vulnerability_observation_total > len(vulnerability_observations)
        ),
        "threats": [
            ThreatView.model_validate(row).model_dump(mode="json")
            for row in threats
        ],
        "risks": [
            RiskView.model_validate(row).model_dump(mode="json")
            for row in all_risks
        ],
        "current_risk_ids": sorted(str(row.id) for row in current_risks),
        "methodology": {
            "risk_scale": "likelihood 1-5 × impact 1-5",
            "signal_separation": "CVSS, EPSS, KEV and contextual risk are separate fields",
            "architecture_state": (
                "scanner-derived and manually edited graphs remain versioned drafts "
                "until analyst review"
            ),
            "vulnerability_evidence": (
                "vendor observations remain separate from correlated operational findings"
            ),
        },
    }


def ensure_report_remains_exportable(
    repository: OperationalRepository, snapshot: dict[str, Any]
) -> None:
    """Withdraw stored bytes after a referenced source becomes more restricted.

    Schema 1.1 reports predate the explicit source-id manifest, so ids are also
    recovered from their frozen finding and threat provenance. This keeps old
    report bytes subject to later dissemination decisions.
    """

    raw_ids = snapshot.get("global_intel_record_ids", [])
    record_ids = {
        value for value in raw_ids if isinstance(value, str)
    } if isinstance(raw_ids, list) else set()
    record_ids.update(_legacy_snapshot_global_intel_ids(snapshot))
    current_rows = _current_global_intel_rows(repository.session, record_ids)
    snapshot_tlp = snapshot.get("distribution_tlp", TLP_AMBER)
    if not isinstance(snapshot_tlp, str):
        snapshot_tlp = TLP_AMBER
    if is_more_restrictive_tlp(TLP_AMBER, snapshot_tlp):
        raise OperationalConflictError(
            "This legacy report is less restrictive than the operational inventory "
            "baseline and must be regenerated"
        )
    current_tlp = most_restrictive_tlp(
        [row.distribution_tlp, *row.markings] for row in current_rows
    )
    if current_tlp == TLP_RED:
        raise OperationalConflictError(
            "This report was withdrawn after source intelligence was reclassified TLP:RED"
        )
    if current_rows and is_more_restrictive_tlp(current_tlp, snapshot_tlp):
        raise OperationalConflictError(
            "This report was withdrawn after source intelligence received a stricter "
            "distribution marking"
        )


def _legacy_snapshot_global_intel_ids(snapshot: dict[str, Any]) -> set[str]:
    """Recover source ids from old finding, threat, and risk provenance."""

    record_ids: set[str] = set()
    stack: list[Any] = [
        snapshot.get("findings", []),
        snapshot.get("threats", []),
        snapshot.get("risks", []),
    ]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            source_id = value.get("global_intel_record_id")
            if isinstance(source_id, str):
                record_ids.add(source_id)
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return record_ids


def _current_global_intel_rows(
    session: Session, record_ids: set[str]
) -> list[GlobalIntelRecordRow]:
    parsed_ids = []
    for value in record_ids:
        try:
            parsed_ids.append(UUID(value))
        except ValueError:
            continue
    if not parsed_ids:
        return []
    return list(
        session.scalars(
            select(GlobalIntelRecordRow).where(GlobalIntelRecordRow.id.in_(parsed_ids))
        )
    )


def _snapshot_fingerprint(snapshot: dict[str, Any]) -> str:
    canonical = dict(snapshot)
    for key in (
        "assets",
        "services",
        "findings",
        "vulnerability_scan_imports",
        "vulnerability_observations",
        "threats",
        "risks",
        "current_risk_ids",
    ):
        value = canonical.get(key)
        if isinstance(value, list):
            canonical[key] = sorted(
                value,
                key=lambda item: json.dumps(
                    item,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
    material = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def render_report(snapshot: dict[str, Any], *, format: str, report_type: str) -> bytes:
    """Render a report whose content genuinely follows the requested audience."""

    if report_type not in REPORT_TYPES:
        raise ValueError(f"Unsupported report type: {report_type}")
    payload = _report_payload(snapshot, report_type)
    if format == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    if format == "csv":
        return _render_csv(payload, report_type)
    if format == "pdf":
        return _render_pdf(payload, report_type=report_type)
    raise ValueError(f"Unsupported report format: {format}")


def _report_payload(snapshot: dict[str, Any], report_type: str) -> dict[str, Any]:
    current_risk_ids = set(
        snapshot.get("current_risk_ids", [risk["id"] for risk in snapshot["risks"]])
    )
    open_risks = [
        risk
        for risk in snapshot["risks"]
        if risk["status"] == "open" and risk["id"] in current_risk_ids
    ]
    closed_risks = [risk for risk in snapshot["risks"] if risk["status"] != "open"]
    retired_open_risks = [
        risk
        for risk in snapshot["risks"]
        if risk["status"] == "open" and risk["id"] not in current_risk_ids
    ]
    presented_risks = [
        _present_risk(risk, current_risk_ids=current_risk_ids)
        for risk in snapshot["risks"]
    ]
    active_findings = [
        finding
        for finding in snapshot["findings"]
        if finding["lifecycle_status"] in {"open", "reopened"}
        and finding.get("inventory_status", "unknown") == "current"
    ]
    common = {
        "schema_version": snapshot["schema_version"],
        "report_type": report_type,
        "distribution_tlp": snapshot.get("distribution_tlp", "TLP:AMBER"),
        "system": snapshot["system"],
        "methodology": snapshot["methodology"],
    }
    if report_type == "management":
        return {
            **common,
            "summary": {
                "assets": len(snapshot["assets"]),
                "services": len(snapshot["services"]),
                "active_findings": len(active_findings),
                "active_threats": len(snapshot["threats"]),
                "open_risks": len(open_risks),
                "closed_risks": len(closed_risks),
                "retired_risks": len(retired_open_risks),
                "critical_open_risks": sum(
                    risk["level"] == "critical" for risk in open_risks
                ),
            },
            "prioritized_open_risks": _sort_risks(open_risks)[:25],
            "limitations": [
                "Only current open risks are included in management priorities.",
                "Scanner observations and correlation candidates require analyst review.",
            ],
        }
    if report_type == "risk_register":
        return {
            **common,
            "summary": {
                "open": len(open_risks),
                "closed": len(closed_risks),
                "retired": len(retired_open_risks),
                "total": len(snapshot["risks"]),
            },
            "risks": _sort_risks(presented_risks),
        }
    return {
        **common,
        "latest_scan": snapshot["latest_scan"],
        "latest_architecture": snapshot["latest_architecture"],
        "assets": snapshot["assets"],
        "services": snapshot["services"],
        "findings": snapshot["findings"],
        "threats": snapshot["threats"],
        "risks": _sort_risks(presented_risks),
        "vulnerability_scan_imports": snapshot["vulnerability_scan_imports"],
        "vulnerability_observations": snapshot["vulnerability_observations"],
        "vulnerability_observations_truncated": snapshot[
            "vulnerability_observations_truncated"
        ],
    }


def _present_risk(
    risk: dict[str, Any],
    *,
    current_risk_ids: set[str],
) -> dict[str, Any]:
    presented = dict(risk)
    is_current = risk["id"] in current_risk_ids
    presented["scope_status"] = "current" if is_current else "retired"
    presented["recorded_status"] = risk["status"]
    if risk["status"] == "open" and not is_current:
        presented["status"] = "retired"
    return presented


def _sort_risks(risks: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        risks,
        key=lambda item: (item["status"] == "open", item["score"], item["created_at"]),
        reverse=True,
    )


def _render_csv(payload: dict[str, Any], report_type: str) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    if report_type == "management":
        writer.writerow(["metric", "value"])
        writer.writerow(["distribution_tlp", payload["distribution_tlp"]])
        for key, value in payload["summary"].items():
            writer.writerow([key, value])
    elif report_type == "technical":
        writer.writerow(
            [
                "finding_id",
                "type",
                "cve_id",
                "title",
                "lifecycle_status",
                "verification_status",
                "cvss",
                "epss",
                "kev",
                "asset_id",
                "service_id",
                "distribution_tlp",
            ]
        )
        for finding in payload["findings"]:
            writer.writerow(
                [
                    finding["id"],
                    finding["finding_type"],
                    finding["cve_id"] or "",
                    _spreadsheet_safe(finding["title"]),
                    finding["lifecycle_status"],
                    finding["status"],
                    finding["cvss_score"] if finding["cvss_score"] is not None else "",
                    finding["epss_score"] if finding["epss_score"] is not None else "",
                    finding["is_kev"],
                    finding["asset_id"] or "",
                    finding["service_id"] or "",
                    payload["distribution_tlp"],
                ]
            )
    else:
        _write_risk_rows(
            writer,
            payload["risks"],
            distribution_tlp=payload["distribution_tlp"],
        )
    return ("\ufeff" + stream.getvalue()).encode("utf-8")


def _write_risk_rows(
    writer: Any,
    risks: Iterable[dict[str, Any]],
    *,
    distribution_tlp: str,
) -> None:
    writer.writerow(
        [
            "risk_id",
            "title",
            "likelihood",
            "impact",
            "score",
            "level",
            "status",
            "recorded_status",
            "scope_status",
            "updated_at",
            "closed_at",
            "finding_id",
            "threat_id",
            "distribution_tlp",
        ]
    )
    for risk in risks:
        writer.writerow(
            [
                risk["id"],
                _spreadsheet_safe(risk["title"]),
                risk["likelihood"],
                risk["impact"],
                risk["score"],
                risk["level"],
                risk["status"],
                risk.get("recorded_status", risk["status"]),
                risk.get("scope_status", "current"),
                risk.get("updated_at", ""),
                risk.get("closed_at") or "",
                risk["finding_id"],
                risk["threat_id"],
                distribution_tlp,
            ]
        )


def _spreadsheet_safe(value: str) -> str:
    """Prevent imported text from becoming a spreadsheet formula on CSV open."""

    stripped = value.lstrip()
    if value.startswith(("\t", "\r", "\n")) or stripped.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def _render_pdf(payload: dict[str, Any], *, report_type: str) -> bytes:
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"Traceless – {payload['system']['name']}",
        author="Traceless",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="TracelessSmall",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
            alignment=TA_LEFT,
        )
    )
    titles = {
        "management": "Traceless ledningsrapport",
        "technical": "Traceless teknisk rapport",
        "risk_register": "Traceless riskregister",
    }
    story: list[Any] = [
        Paragraph(titles[report_type], styles["Title"]),
        Paragraph(escape(payload["distribution_tlp"]), styles["Heading3"]),
        Paragraph(escape(payload["system"]["name"]), styles["Heading2"]),
        Paragraph(
            escape(f"Kritikalitet: {payload['system']['criticality']}"), styles["BodyText"]
        ),
        Spacer(1, 6 * mm),
    ]
    if report_type == "management":
        _append_management_pdf(story, styles, payload)
    elif report_type == "technical":
        _append_technical_pdf(story, styles, payload)
    else:
        _append_risk_register_pdf(story, styles, payload)
    document.build(story)
    return output.getvalue()


def _append_management_pdf(story: list[Any], styles: Any, payload: dict[str, Any]) -> None:
    labels = {
        "assets": "Tillgångar",
        "services": "Tjänster",
        "active_findings": "Aktiva fynd",
        "active_threats": "Aktiva hot",
        "open_risks": "Öppna risker",
        "closed_risks": "Stängda risker",
        "retired_risks": "Inaktiva historiska risker",
        "critical_open_risks": "Kritiska öppna risker",
    }
    summary = [[labels[key], value] for key, value in payload["summary"].items()]
    story.extend([Paragraph("Sammanfattning", styles["Heading2"]), _styled_table(summary)])
    story.extend([Spacer(1, 5 * mm), Paragraph("Prioriterade öppna risker", styles["Heading2"])])
    _append_risk_table(story, styles, payload["prioritized_open_risks"])
    story.extend(
        [
            Spacer(1, 5 * mm),
            Paragraph("Beslutsunderlagets begränsningar", styles["Heading2"]),
            Paragraph(escape(" ".join(payload["limitations"])), styles["BodyText"]),
        ]
    )


def _append_technical_pdf(story: list[Any], styles: Any, payload: dict[str, Any]) -> None:
    summary = [
        ["Tillgångar", len(payload["assets"])],
        ["Tjänster", len(payload["services"])],
        ["Fynd", len(payload["findings"])],
        ["Hot", len(payload["threats"])],
        ["Risker", len(payload["risks"])],
        ["Leverantörsobservationer", len(payload["vulnerability_observations"])],
    ]
    story.extend([Paragraph("Teknisk omfattning", styles["Heading2"]), _styled_table(summary)])
    story.extend([Spacer(1, 5 * mm), Paragraph("Fynd", styles["Heading2"])])
    findings = payload["findings"]
    if findings:
        rows: list[list[Any]] = [["Fynd", "Typ", "CVE", "Status", "CVSS"]]
        for finding in findings:
            rows.append(
                [
                    Paragraph(escape(finding["title"]), styles["TracelessSmall"]),
                    finding["finding_type"],
                    finding["cve_id"] or "–",
                    finding["lifecycle_status"],
                    finding["cvss_score"] if finding["cvss_score"] is not None else "–",
                ]
            )
        story.append(
            _styled_table(
                rows,
                header=True,
                widths=[75 * mm, 25 * mm, 29 * mm, 24 * mm, 14 * mm],
            )
        )
    else:
        story.append(Paragraph("Inga fynd finns i rapportens frysta underlag.", styles["BodyText"]))
    if payload["vulnerability_observations_truncated"]:
        story.append(
            Paragraph(
                "Råobservationslistan är avsiktligt begränsad; totalsiffror kommer från "
                "importmanifesten.",
                styles["BodyText"],
            )
        )


def _append_risk_register_pdf(story: list[Any], styles: Any, payload: dict[str, Any]) -> None:
    summary = [
        ["Öppna", payload["summary"]["open"]],
        ["Stängda", payload["summary"]["closed"]],
        ["Totalt", payload["summary"]["total"]],
    ]
    story.extend([Paragraph("Status", styles["Heading2"]), _styled_table(summary)])
    story.extend([Spacer(1, 5 * mm), Paragraph("Risker", styles["Heading2"])])
    _append_risk_table(story, styles, payload["risks"], include_status=True)


def _append_risk_table(
    story: list[Any],
    styles: Any,
    risks: list[dict[str, Any]],
    *,
    include_status: bool = False,
) -> None:
    if not risks:
        story.append(
            Paragraph("Inga risker finns i rapportens frysta underlag.", styles["BodyText"])
        )
        return
    headers = ["Risk", "L", "I", "Poäng", "Nivå"]
    widths = [104 * mm, 10 * mm, 10 * mm, 15 * mm, 22 * mm]
    if include_status:
        headers.append("Status")
        widths = [82 * mm, 9 * mm, 9 * mm, 14 * mm, 20 * mm, 27 * mm]
    rows: list[list[Any]] = [headers]
    for risk in risks:
        row: list[Any] = [
            Paragraph(escape(risk["title"]), styles["TracelessSmall"]),
            risk["likelihood"],
            risk["impact"],
            risk["score"],
            risk["level"],
        ]
        if include_status:
            row.append(risk["status"])
        rows.append(row)
    story.append(_styled_table(rows, header=True, widths=widths))


def _styled_table(
    rows: list[list[Any]],
    *,
    header: bool = False,
    widths: list[float] | None = None,
) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands: list[tuple[Any, ...]] = [
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D6DFEA")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F6F8FB")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        commands.extend(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    table.setStyle(TableStyle(commands))
    return table
