"""Build a bounded, explainable cyber-risk graph for one operational system."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import func, select

from traceless_api.db.models import (
    AssetRow,
    FindingRow,
    RiskRow,
    ServiceRow,
    ThreatRow,
)
from traceless_api.models.operational import (
    ArchitectureBusinessContextInput,
    CisoRiskSummary,
    CyberRiskGraphView,
    RiskGraphEdge,
    RiskGraphNode,
)
from traceless_api.services.operational_repository import OperationalRepository

_MAX_ASSETS = 150
_MAX_SERVICES = 200
_MAX_FINDINGS = 150
_MAX_THREATS = 100
_MAX_RISKS = 100
_MAX_ARCHITECTURE_COMPONENTS = 100


def _stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _severity_for_finding(finding: FindingRow) -> str:
    if finding.is_kev or (finding.cvss_score is not None and finding.cvss_score >= 9):
        return "critical"
    if finding.cvss_score is not None and finding.cvss_score >= 7:
        return "high"
    if finding.cvss_score is not None and finding.cvss_score >= 4:
        return "medium"
    return "low"


def _action_for_risk(
    risk: RiskRow,
    finding: FindingRow | None,
    threat: ThreatRow | None,
) -> str:
    if finding is not None and finding.is_kev:
        return f"Patcha eller isolera {finding.cve_id or finding.title} omedelbart."
    if finding is not None and finding.cvss_score is not None and finding.cvss_score >= 9:
        return f"Verifiera patchläge och begränsa exponeringen för {finding.title}."
    if finding is not None:
        return f"Tilldela ägare, verifiera fyndet och planera åtgärd för {finding.title}."
    if threat is not None:
        return f"Validera detektion, beredskap och skydd mot {threat.title}."
    return f"Tilldela riskägare och dokumentera åtgärdsplan för {risk.title}."


def _business_context(
    architecture_graph: dict[str, Any],
    *,
    fallback_owner: str,
) -> ArchitectureBusinessContextInput:
    raw = architecture_graph.get("business_context")
    try:
        context = ArchitectureBusinessContextInput.model_validate(
            raw if isinstance(raw, dict) else {}
        )
    except ValidationError:
        context = ArchitectureBusinessContextInput()
    if not context.business_owner:
        context = context.model_copy(update={"business_owner": fallback_owner})
    return context


def build_cyber_risk_graph(
    repository: OperationalRepository,
    system_id: UUID,
) -> CyberRiskGraphView:
    """Return current operational relationships without claiming an attack path is proven."""

    system = repository.get_system(system_id)
    architecture = repository.latest_architecture(system_id)
    architecture_graph = architecture.graph if architecture is not None else {}
    if not isinstance(architecture_graph, dict):
        architecture_graph = {}
    business_context = _business_context(
        architecture_graph,
        fallback_owner=system.owner,
    )

    session = repository.session
    assets = list(
        session.scalars(
            select(AssetRow)
            .where(
                AssetRow.system_id == system_id,
                AssetRow.inventory_status == "current",
            )
            .order_by(AssetRow.last_seen_at.desc(), AssetRow.id)
            .limit(_MAX_ASSETS)
        )
    )
    services = list(
        session.scalars(
            select(ServiceRow)
            .join(AssetRow, AssetRow.id == ServiceRow.asset_id)
            .where(
                AssetRow.system_id == system_id,
                AssetRow.inventory_status == "current",
                ServiceRow.scan_job_id == AssetRow.source_scan_id,
            )
            .order_by(ServiceRow.asset_id, ServiceRow.port, ServiceRow.protocol)
            .limit(_MAX_SERVICES)
        )
    )
    findings = list(
        session.scalars(
            select(FindingRow)
            .where(
                FindingRow.system_id == system_id,
                FindingRow.lifecycle_status.in_(("open", "reopened")),
                FindingRow.inventory_status.in_(("current", "unknown")),
            )
            .order_by(FindingRow.is_kev.desc(), FindingRow.cvss_score.desc(), FindingRow.id)
            .limit(_MAX_FINDINGS)
        )
    )
    threats = list(
        session.scalars(
            select(ThreatRow)
            .where(ThreatRow.system_id == system_id)
            .order_by(ThreatRow.modified_at.desc(), ThreatRow.id)
            .limit(_MAX_THREATS)
        )
    )
    risks = list(
        session.scalars(
            select(RiskRow)
            .where(RiskRow.system_id == system_id, RiskRow.status == "open")
            .order_by(RiskRow.score.desc(), RiskRow.created_at.desc(), RiskRow.id)
            .limit(_MAX_RISKS)
        )
    )

    open_findings_total = int(
        session.scalar(
            select(func.count(FindingRow.id)).where(
                FindingRow.system_id == system_id,
                FindingRow.lifecycle_status.in_(("open", "reopened")),
            )
        )
        or 0
    )
    kev_findings_total = int(
        session.scalar(
            select(func.count(FindingRow.id)).where(
                FindingRow.system_id == system_id,
                FindingRow.lifecycle_status.in_(("open", "reopened")),
                FindingRow.is_kev.is_(True),
            )
        )
        or 0
    )
    active_threats_total = int(
        session.scalar(select(func.count(ThreatRow.id)).where(ThreatRow.system_id == system_id))
        or 0
    )
    critical_risks_total = int(
        session.scalar(
            select(func.count(RiskRow.id)).where(
                RiskRow.system_id == system_id,
                RiskRow.status == "open",
                RiskRow.level == "critical",
            )
        )
        or 0
    )
    high_risks_total = int(
        session.scalar(
            select(func.count(RiskRow.id)).where(
                RiskRow.system_id == system_id,
                RiskRow.status == "open",
                RiskRow.level == "high",
            )
        )
        or 0
    )
    asset_total = int(
        session.scalar(
            select(func.count(AssetRow.id)).where(
                AssetRow.system_id == system_id,
                AssetRow.inventory_status == "current",
            )
        )
        or 0
    )
    service_total = int(
        session.scalar(
            select(func.count(ServiceRow.id))
            .join(AssetRow, AssetRow.id == ServiceRow.asset_id)
            .where(
                AssetRow.system_id == system_id,
                AssetRow.inventory_status == "current",
                ServiceRow.scan_job_id == AssetRow.source_scan_id,
            )
        )
        or 0
    )
    risk_total = int(
        session.scalar(
            select(func.count(RiskRow.id)).where(
                RiskRow.system_id == system_id,
                RiskRow.status == "open",
            )
        )
        or 0
    )

    external_asset_ids: set[str] = set()
    risk_contexts = architecture_graph.get("risk_contexts")
    if isinstance(risk_contexts, list):
        for context in risk_contexts:
            if not isinstance(context, dict) or context.get("exposure") != "external":
                continue
            asset_id = context.get("asset_id")
            if isinstance(asset_id, str):
                external_asset_ids.add(asset_id)

    nodes: list[RiskGraphNode] = []
    node_ids: set[str] = set()
    edges: list[RiskGraphEdge] = []
    edge_ids: set[str] = set()

    def add_node(node: RiskGraphNode) -> None:
        if node.id in node_ids:
            return
        nodes.append(node)
        node_ids.add(node.id)

    def add_edge(
        source: str,
        target: str,
        relationship: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if source not in node_ids or target not in node_ids:
            return
        edge_id = _stable_id("edge", f"{source}|{relationship}|{target}")
        if edge_id in edge_ids:
            return
        edges.append(
            RiskGraphEdge(
                id=edge_id,
                source=source,
                target=target,
                relationship=relationship,
                metadata=metadata or {},
            )
        )
        edge_ids.add(edge_id)

    system_node_id = f"system:{system.id}"
    add_node(
        RiskGraphNode(
            id=system_node_id,
            kind="system",
            label=system.name,
            severity=system.criticality,
            status="operational",
            metadata={
                "owner": system.owner,
                "description": system.description,
            },
        )
    )

    capability_node_ids: list[str] = []
    for capability in business_context.capabilities:
        node_id = _stable_id("capability", capability.casefold())
        capability_node_ids.append(node_id)
        add_node(
            RiskGraphNode(
                id=node_id,
                kind="business_capability",
                label=capability,
                status="business_context",
            )
        )
    regulation_node_ids: list[str] = []
    for regulation in business_context.regulations:
        node_id = _stable_id("regulation", regulation.casefold())
        regulation_node_ids.append(node_id)
        add_node(
            RiskGraphNode(
                id=node_id,
                kind="regulation",
                label=regulation,
                status="applicable",
            )
        )

    asset_nodes: dict[UUID, str] = {}
    for asset in assets:
        node_id = f"asset:{asset.id}"
        asset_nodes[asset.id] = node_id
        add_node(
            RiskGraphNode(
                id=node_id,
                kind="asset",
                label=asset.hostname or asset.primary_ip,
                status=asset.inventory_status,
                metadata={
                    "ip": asset.primary_ip,
                    "os_family": asset.os_family,
                    "last_seen_at": asset.last_seen_at.isoformat(),
                    "external": str(asset.id) in external_asset_ids,
                },
            )
        )

    service_nodes: dict[UUID, str] = {}
    for service in services:
        node_id = f"service:{service.id}"
        service_nodes[service.id] = node_id
        label = service.product or service.service_name or "Tjänst"
        add_node(
            RiskGraphNode(
                id=node_id,
                kind="service",
                label=f"{label} · {service.port}/{service.protocol}",
                status=service.state,
                metadata={
                    "product": service.product,
                    "version": service.version,
                    "cpes": service.cpes,
                },
            )
        )

    finding_nodes: dict[UUID, str] = {}
    finding_by_id = {finding.id: finding for finding in findings}
    for finding in findings:
        node_id = f"finding:{finding.id}"
        finding_nodes[finding.id] = node_id
        add_node(
            RiskGraphNode(
                id=node_id,
                kind="finding",
                label=finding.cve_id or finding.title,
                severity=_severity_for_finding(finding),
                status=finding.lifecycle_status,
                metadata={
                    "title": finding.title,
                    "finding_type": finding.finding_type,
                    "cvss_score": finding.cvss_score,
                    "epss_score": finding.epss_score,
                    "is_kev": finding.is_kev,
                    "evidence_strength": finding.primary_evidence_strength,
                },
            )
        )

    threat_nodes: dict[UUID, str] = {}
    threat_by_id = {threat.id: threat for threat in threats}
    for threat in threats:
        node_id = f"threat:{threat.id}"
        threat_nodes[threat.id] = node_id
        severity = (
            threat.severity if threat.severity in {"low", "medium", "high", "critical"} else None
        )
        add_node(
            RiskGraphNode(
                id=node_id,
                kind="threat",
                label=threat.title,
                severity=severity,
                status="active_match",
                metadata={
                    "source": threat.source,
                    "confidence": threat.confidence,
                    "attack_patterns": threat.attack_patterns,
                },
            )
        )

    risk_nodes: dict[UUID, str] = {}
    action_by_risk: dict[UUID, tuple[str, str]] = {}
    recommended_actions: list[str] = []
    for risk in risks:
        node_id = f"risk:{risk.id}"
        risk_nodes[risk.id] = node_id
        add_node(
            RiskGraphNode(
                id=node_id,
                kind="risk",
                label=risk.title,
                severity=risk.level,
                status=risk.status,
                metadata={
                    "score": risk.score,
                    "likelihood": risk.likelihood,
                    "impact": risk.impact,
                    "evidence_status": risk.evidence_status,
                },
            )
        )
        finding = finding_by_id.get(risk.finding_id) if risk.finding_id is not None else None
        threat = threat_by_id.get(risk.threat_id) if risk.threat_id is not None else None
        action = _action_for_risk(risk, finding, threat)
        action_node_id = f"action:{risk.id}"
        action_by_risk[risk.id] = (action_node_id, action)
        add_node(
            RiskGraphNode(
                id=action_node_id,
                kind="action",
                label=action,
                severity=risk.level,
                status="recommended",
                metadata={"risk_id": str(risk.id)},
            )
        )
        if action not in recommended_actions and len(recommended_actions) < 6:
            recommended_actions.append(action)

    architecture_component_ids: dict[str, str] = {}
    raw_architecture_nodes = architecture_graph.get("nodes")
    if isinstance(raw_architecture_nodes, list):
        for raw in raw_architecture_nodes[:_MAX_ARCHITECTURE_COMPONENTS]:
            if not isinstance(raw, dict):
                continue
            raw_id = raw.get("id")
            label = raw.get("name")
            if not isinstance(raw_id, str) or not isinstance(label, str):
                continue
            properties = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
            bound_asset = properties.get("asset_id") or raw.get("asset_id")
            bound_service = properties.get("service_id") or raw.get("service_id")
            if isinstance(bound_asset, str) and f"asset:{bound_asset}" in node_ids:
                architecture_component_ids[raw_id] = f"asset:{bound_asset}"
                continue
            if isinstance(bound_service, str) and f"service:{bound_service}" in node_ids:
                architecture_component_ids[raw_id] = f"service:{bound_service}"
                continue
            node_id = _stable_id("architecture", raw_id)
            architecture_component_ids[raw_id] = node_id
            add_node(
                RiskGraphNode(
                    id=node_id,
                    kind="architecture_component",
                    label=label,
                    status=str(raw.get("provenance") or "modeled"),
                    metadata={
                        "component_kind": raw.get("kind"),
                        "zone_id": raw.get("zone_id"),
                    },
                )
            )

    for capability_node_id in capability_node_ids:
        add_edge(capability_node_id, system_node_id, "enabled_by")
    for regulation_node_id in regulation_node_ids:
        add_edge(regulation_node_id, system_node_id, "governs")
    for _asset_id, asset_node_id in asset_nodes.items():
        add_edge(system_node_id, asset_node_id, "contains")
    for service in services:
        add_edge(asset_nodes.get(service.asset_id, ""), service_nodes[service.id], "exposes")
    for finding in findings:
        source_node = (
            (service_nodes.get(finding.service_id) if finding.service_id is not None else None)
            or (asset_nodes.get(finding.asset_id) if finding.asset_id is not None else None)
            or system_node_id
        )
        add_edge(source_node, finding_nodes[finding.id], "has_finding")
    for threat in threats:
        threat_node_id = threat_nodes[threat.id]
        for matched_asset_id in threat.matched_asset_ids[:50]:
            add_edge(threat_node_id, f"asset:{matched_asset_id}", "targets")
    for risk in risks:
        risk_node_id = risk_nodes[risk.id]
        if risk.finding_id is not None:
            add_edge(finding_nodes.get(risk.finding_id, ""), risk_node_id, "creates_risk")
        if risk.threat_id is not None:
            add_edge(threat_nodes.get(risk.threat_id, ""), risk_node_id, "creates_risk")
        add_edge(risk_node_id, system_node_id, "affects")
        action_node_id, _ = action_by_risk[risk.id]
        add_edge(risk_node_id, action_node_id, "mitigated_by")
        for capability_node_id in capability_node_ids[:3]:
            add_edge(risk_node_id, capability_node_id, "impacts")
    for _raw_id, node_id in architecture_component_ids.items():
        if node_id.startswith("architecture:"):
            add_edge(system_node_id, node_id, "contains_modeled_component")
    raw_architecture_edges = architecture_graph.get("edges")
    if isinstance(raw_architecture_edges, list):
        for raw in raw_architecture_edges[:500]:
            if not isinstance(raw, dict):
                continue
            source = architecture_component_ids.get(str(raw.get("source")))
            target = architecture_component_ids.get(str(raw.get("target")))
            if source and target:
                add_edge(source, target, "data_flow", {"label": raw.get("label")})

    external_assets_total = len(external_asset_ids)
    penalty = (
        critical_risks_total * 14
        + high_risks_total * 7
        + kev_findings_total * 5
        + external_assets_total * 2
        + min(open_findings_total, 20)
    )
    security_score = max(0, 100 - min(100, penalty))
    truncated = any(
        (
            asset_total > len(assets),
            service_total > len(services),
            open_findings_total > len(findings),
            active_threats_total > len(threats),
            risk_total > len(risks),
        )
    )

    return CyberRiskGraphView(
        system_id=system.id,
        business_context=business_context,
        summary=CisoRiskSummary(
            security_score=security_score,
            critical_risks=critical_risks_total,
            high_risks=high_risks_total,
            open_findings=open_findings_total,
            kev_findings=kev_findings_total,
            active_threats=active_threats_total,
            external_assets=external_assets_total,
            recommended_actions=recommended_actions,
        ),
        nodes=nodes,
        edges=edges,
        truncated=truncated,
    )
