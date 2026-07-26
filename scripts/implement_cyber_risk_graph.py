from __future__ import annotations

from pathlib import Path
import re
import textwrap


def read(path: str) -> str:
    return Path(path).read_text()


def write(path: str, content: str) -> None:
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(content)


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    if old not in text:
        raise SystemExit(f"Pattern not found in {path}: {old[:180]!r}")
    write(path, text.replace(old, new, 1))


def regex_once(path: str, pattern: str, replacement: str, *, flags: int = 0) -> None:
    text = read(path)
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise SystemExit(f"Regex did not match exactly once in {path}: {pattern[:180]!r}; count={count}")
    write(path, updated)


# ---------------------------------------------------------------------------
# Backend contracts: business context, CISO summary and graph response.
# ---------------------------------------------------------------------------
models_path = "apps/api/src/traceless_api/models/operational.py"
business_models = textwrap.dedent(
    '''

    class ArchitectureBusinessImpactInput(StrictModel):
        confidentiality: int = Field(default=3, ge=1, le=5)
        integrity: int = Field(default=3, ge=1, le=5)
        availability: int = Field(default=3, ge=1, le=5)
        financial: int = Field(default=3, ge=1, le=5)
        regulatory: int = Field(default=3, ge=1, le=5)
        reputation: int = Field(default=3, ge=1, le=5)
        safety: int = Field(default=1, ge=1, le=5)


    class ArchitectureBusinessContextInput(StrictModel):
        business_owner: str = Field(default="", max_length=160)
        capabilities: list[str] = Field(default_factory=list, max_length=50)
        processes: list[str] = Field(default_factory=list, max_length=50)
        data_categories: list[str] = Field(default_factory=list, max_length=50)
        regulations: list[str] = Field(default_factory=list, max_length=50)
        recovery_time_objective_hours: float | None = Field(default=None, ge=0, le=8_760)
        recovery_point_objective_hours: float | None = Field(default=None, ge=0, le=8_760)
        impact: ArchitectureBusinessImpactInput = Field(
            default_factory=ArchitectureBusinessImpactInput
        )

        @field_validator(
            "capabilities",
            "processes",
            "data_categories",
            "regulations",
        )
        @classmethod
        def values_are_normalized_and_unique(cls, values: list[str]) -> list[str]:
            normalized = [value.strip() for value in values if value.strip()]
            if any(len(value) > 160 for value in normalized):
                raise ValueError("business context values may not exceed 160 characters")
            if len(normalized) != len(set(normalized)):
                raise ValueError("business context values must be unique")
            return normalized
    '''
)
replace_once(
    models_path,
    "\n\nclass ArchitectureGraphInput(StrictModel):",
    business_models + "\n\nclass ArchitectureGraphInput(StrictModel):",
)
replace_once(
    models_path,
    "    zones: list[ArchitectureZoneInput] = Field(default_factory=list, max_length=100)\n",
    "    business_context: ArchitectureBusinessContextInput = Field(\n"
    "        default_factory=ArchitectureBusinessContextInput\n"
    "    )\n"
    "    zones: list[ArchitectureZoneInput] = Field(default_factory=list, max_length=100)\n",
)

graph_models = textwrap.dedent(
    '''

    RiskGraphNodeKind = Literal[
        "business_capability",
        "regulation",
        "system",
        "architecture_component",
        "asset",
        "service",
        "finding",
        "threat",
        "risk",
        "action",
    ]


    class RiskGraphNode(StrictModel):
        id: str = Field(min_length=1, max_length=240)
        kind: RiskGraphNodeKind
        label: str = Field(min_length=1, max_length=500)
        severity: Criticality | None = None
        status: str | None = Field(default=None, max_length=80)
        metadata: dict[str, Any] = Field(default_factory=dict)


    class RiskGraphEdge(StrictModel):
        id: str = Field(min_length=1, max_length=300)
        source: str = Field(min_length=1, max_length=240)
        target: str = Field(min_length=1, max_length=240)
        relationship: str = Field(min_length=1, max_length=80)
        metadata: dict[str, Any] = Field(default_factory=dict)


    class CisoRiskSummary(StrictModel):
        security_score: int = Field(ge=0, le=100)
        critical_risks: int = Field(ge=0)
        high_risks: int = Field(ge=0)
        open_findings: int = Field(ge=0)
        kev_findings: int = Field(ge=0)
        active_threats: int = Field(ge=0)
        external_assets: int = Field(ge=0)
        recommended_actions: list[str] = Field(default_factory=list, max_length=10)


    class CyberRiskGraphView(StrictModel):
        system_id: UUID
        business_context: ArchitectureBusinessContextInput
        summary: CisoRiskSummary
        nodes: list[RiskGraphNode]
        edges: list[RiskGraphEdge]
        truncated: bool = False
    '''
)
replace_once(
    models_path,
    "\n\nclass PipelineCollectionTotals(StrictModel):",
    graph_models + "\n\nclass PipelineCollectionTotals(StrictModel):",
)


# ---------------------------------------------------------------------------
# Backend graph builder.
# ---------------------------------------------------------------------------
risk_graph_service = textwrap.dedent(
    '''
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
            session.scalar(
                select(func.count(ThreatRow.id)).where(ThreatRow.system_id == system_id)
            )
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
            severity = threat.severity if threat.severity in {"low", "medium", "high", "critical"} else None
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
        for asset_id, asset_node_id in asset_nodes.items():
            add_edge(system_node_id, asset_node_id, "contains")
        for service in services:
            add_edge(asset_nodes.get(service.asset_id, ""), service_nodes[service.id], "exposes")
        for finding in findings:
            source_node = (
                service_nodes.get(finding.service_id)
                if finding.service_id is not None
                else None
            ) or (
                asset_nodes.get(finding.asset_id)
                if finding.asset_id is not None
                else None
            ) or system_node_id
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
        for raw_id, node_id in architecture_component_ids.items():
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
    '''
)
write("apps/api/src/traceless_api/services/risk_graph.py", risk_graph_service)


# ---------------------------------------------------------------------------
# Operational endpoint.
# ---------------------------------------------------------------------------
routes_path = "apps/api/src/traceless_api/api/routes/operational.py"
replace_once(
    routes_path,
    "    ArchitectureVersionCreate,\n    AssetView,\n",
    "    ArchitectureVersionCreate,\n    AssetView,\n    CyberRiskGraphView,\n",
)
replace_once(
    routes_path,
    "from traceless_api.services.scan_ingestion import ingest_scanner_result\n",
    "from traceless_api.services.risk_graph import build_cyber_risk_graph\n"
    "from traceless_api.services.scan_ingestion import ingest_scanner_result\n",
)
risk_graph_route = textwrap.dedent(
    '''

    @router.get(
        "/systems/{system_id}/risk-graph",
        response_model=CyberRiskGraphView,
        dependencies=[Depends(require_read_access)],
    )
    def cyber_risk_graph(
        system_id: UUID,
        repository: OperationalRepositoryDependency,
    ) -> CyberRiskGraphView:
        return build_cyber_risk_graph(repository, system_id)
    '''
)
replace_once(
    routes_path,
    "\n\n@router.get(\n    \"/systems/{system_id}/overview\",",
    risk_graph_route + "\n\n@router.get(\n    \"/systems/{system_id}/overview\",",
)


# ---------------------------------------------------------------------------
# Backend tests.
# ---------------------------------------------------------------------------
risk_graph_test = textwrap.dedent(
    '''
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
                    "business_context": {
                        "capabilities": ["Payments", "Payments"]
                    },
                    "zones": [],
                    "nodes": [],
                    "edges": [],
                    "risk_contexts": [],
                },
            },
        )
        assert response.status_code == 422
    '''
)
write("apps/api/tests/test_risk_graph.py", risk_graph_test)


# ---------------------------------------------------------------------------
# Frontend contracts and API client.
# ---------------------------------------------------------------------------
api_path = "apps/web/src/api.ts"
business_types = textwrap.dedent(
    '''

    export interface ArchitectureBusinessImpactInput {
      confidentiality: number;
      integrity: number;
      availability: number;
      financial: number;
      regulatory: number;
      reputation: number;
      safety: number;
    }

    export interface ArchitectureBusinessContextInput {
      business_owner: string;
      capabilities: string[];
      processes: string[];
      data_categories: string[];
      regulations: string[];
      recovery_time_objective_hours: number | null;
      recovery_point_objective_hours: number | null;
      impact: ArchitectureBusinessImpactInput;
    }
    '''
)
replace_once(
    api_path,
    "\n\nexport interface ArchitectureGraphInput {",
    business_types + "\n\nexport interface ArchitectureGraphInput {",
)
replace_once(
    api_path,
    "  warning: string;\n  zones: ArchitectureZoneInput[];\n",
    "  warning: string;\n  business_context: ArchitectureBusinessContextInput;\n"
    "  zones: ArchitectureZoneInput[];\n",
)

risk_graph_types = textwrap.dedent(
    '''

    export type RiskGraphNodeKind =
      | 'business_capability'
      | 'regulation'
      | 'system'
      | 'architecture_component'
      | 'asset'
      | 'service'
      | 'finding'
      | 'threat'
      | 'risk'
      | 'action';

    export interface RiskGraphNode {
      id: string;
      kind: RiskGraphNodeKind;
      label: string;
      severity: Criticality | null;
      status: string | null;
      metadata: Record<string, unknown>;
    }

    export interface RiskGraphEdge {
      id: string;
      source: string;
      target: string;
      relationship: string;
      metadata: Record<string, unknown>;
    }

    export interface CisoRiskSummary {
      security_score: number;
      critical_risks: number;
      high_risks: number;
      open_findings: number;
      kev_findings: number;
      active_threats: number;
      external_assets: number;
      recommended_actions: string[];
    }

    export interface CyberRiskGraphView {
      system_id: string;
      business_context: ArchitectureBusinessContextInput;
      summary: CisoRiskSummary;
      nodes: RiskGraphNode[];
      edges: RiskGraphEdge[];
      truncated: boolean;
    }
    '''
)
replace_once(
    api_path,
    "\n\nexport interface ArchitectureSnapshot {",
    risk_graph_types + "\n\nexport interface ArchitectureSnapshot {",
)
replace_once(
    api_path,
    "  getOverview(systemId: string): Promise<PipelineOverview>;\n",
    "  getOverview(systemId: string): Promise<PipelineOverview>;\n"
    "  getRiskGraph(systemId: string): Promise<CyberRiskGraphView>;\n",
)
replace_once(
    api_path,
    "    getOverview: (systemId) => json<PipelineOverview>(`${systemPath(systemId)}/overview`),\n",
    "    getOverview: (systemId) => json<PipelineOverview>(`${systemPath(systemId)}/overview`),\n"
    "    getRiskGraph: (systemId) =>\n"
    "      json<CyberRiskGraphView>(`${systemPath(systemId)}/risk-graph`),\n",
)


# ---------------------------------------------------------------------------
# Read-only graph visualization.
# ---------------------------------------------------------------------------
cyber_risk_graph_component = textwrap.dedent(
    '''
    import {
      Background,
      BackgroundVariant,
      Controls,
      MarkerType,
      MiniMap,
      ReactFlow,
      type Edge,
      type Node,
    } from '@xyflow/react';
    import { useMemo } from 'react';
    import '@xyflow/react/dist/style.css';

    import type { CyberRiskGraphView, RiskGraphNodeKind } from '../api';

    const columnOrder: Record<RiskGraphNodeKind, number> = {
      business_capability: 0,
      regulation: 0,
      system: 1,
      architecture_component: 2,
      asset: 2,
      service: 3,
      finding: 4,
      threat: 4,
      risk: 5,
      action: 6,
    };

    const kindLabel: Record<RiskGraphNodeKind, string> = {
      business_capability: 'Förmåga',
      regulation: 'Regelverk',
      system: 'System',
      architecture_component: 'Arkitektur',
      asset: 'Tillgång',
      service: 'Tjänst',
      finding: 'Fynd',
      threat: 'Hot',
      risk: 'Risk',
      action: 'Åtgärd',
    };

    interface CyberRiskGraphProps {
      graph: CyberRiskGraphView;
    }

    export function CyberRiskGraph({ graph }: CyberRiskGraphProps) {
      const layout = useMemo(() => {
        const counters = new Map<number, number>();
        const nodes: Node[] = graph.nodes.map((node) => {
          const column = columnOrder[node.kind];
          const row = counters.get(column) ?? 0;
          counters.set(column, row + 1);
          return {
            id: node.id,
            position: { x: column * 280, y: row * 116 },
            className: `op-risk-graph-node op-risk-graph-node--${node.kind}`,
            data: {
              label: (
                <span className="op-risk-graph-node__content">
                  <small>{kindLabel[node.kind]}</small>
                  <strong>{node.label}</strong>
                  {node.status && <em>{node.status}</em>}
                  {node.severity && <b className={`op-criticality op-criticality--${node.severity}`}>{node.severity}</b>}
                </span>
              ),
            },
          };
        });
        const edges: Edge[] = graph.edges.map((edge) => ({
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.relationship.replaceAll('_', ' '),
          markerEnd: { type: MarkerType.ArrowClosed },
          className: 'op-risk-graph-edge',
        }));
        return { nodes, edges };
      }, [graph.edges, graph.nodes]);

      const context = graph.business_context;
      return (
        <div className="op-risk-graph-workspace">
          <section className="op-risk-graph-summary" aria-label="CISO-sammanfattning">
            {[
              ['Säkerhetspoäng', `${graph.summary.security_score}/100`],
              ['Kritiska risker', graph.summary.critical_risks],
              ['Höga risker', graph.summary.high_risks],
              ['KEV-fynd', graph.summary.kev_findings],
              ['Aktiva hot', graph.summary.active_threats],
              ['Externa tillgångar', graph.summary.external_assets],
            ].map(([label, value]) => (
              <article key={label}><strong>{value}</strong><small>{label}</small></article>
            ))}
          </section>

          <section className="op-risk-graph-context panel">
            <div>
              <span className="section-kicker">VERKSAMHETSKONTEXT</span>
              <h2>{context.business_owner || 'Affärsägare saknas'}</h2>
              <p>{context.capabilities.join(' · ') || 'Koppla verksamhetsförmågor i arkitekturvyn.'}</p>
            </div>
            <dl>
              <div><dt>Processer</dt><dd>{context.processes.join(', ') || 'Saknas'}</dd></div>
              <div><dt>Data</dt><dd>{context.data_categories.join(', ') || 'Saknas'}</dd></div>
              <div><dt>Regelverk</dt><dd>{context.regulations.join(', ') || 'Saknas'}</dd></div>
              <div><dt>RTO / RPO</dt><dd>{context.recovery_time_objective_hours ?? '–'} h / {context.recovery_point_objective_hours ?? '–'} h</dd></div>
            </dl>
          </section>

          {graph.summary.recommended_actions.length > 0 && (
            <section className="op-risk-graph-actions panel">
              <span className="section-kicker">REKOMMENDERADE BESLUT</span>
              <ol>{graph.summary.recommended_actions.map((action) => <li key={action}>{action}</li>)}</ol>
            </section>
          )}

          {graph.truncated && (
            <div className="op-collection-note" role="note">
              Grafen är begränsad för läsbarhet. Sammanfattningens totalsiffror omfattar hela systemet.
            </div>
          )}

          <section className="op-risk-graph-canvas panel" aria-label="Cyber Risk Graph">
            <ReactFlow
              edges={layout.edges}
              fitView
              fitViewOptions={{ padding: 0.18 }}
              nodes={layout.nodes}
              nodesConnectable={false}
              nodesDraggable={false}
              elementsSelectable
              proOptions={{ hideAttribution: true }}
            >
              <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
              <MiniMap pannable zoomable />
              <Controls showInteractive={false} />
            </ReactFlow>
          </section>
        </div>
      );
    }
    '''
)
write("apps/web/src/components/CyberRiskGraph.tsx", cyber_risk_graph_component)

cyber_risk_graph_test = textwrap.dedent(
    '''
    import { render, screen } from '@testing-library/react';
    import { describe, expect, test } from 'vitest';

    import type { CyberRiskGraphView } from '../api';
    import { CyberRiskGraph } from './CyberRiskGraph';

    const graph: CyberRiskGraphView = {
      system_id: 'system-1',
      business_context: {
        business_owner: 'Head of Payments',
        capabilities: ['Accept payments'],
        processes: ['Card authorization'],
        data_categories: ['Payment data'],
        regulations: ['DORA'],
        recovery_time_objective_hours: 2,
        recovery_point_objective_hours: 0.5,
        impact: {
          confidentiality: 5,
          integrity: 5,
          availability: 5,
          financial: 5,
          regulatory: 5,
          reputation: 4,
          safety: 1,
        },
      },
      summary: {
        security_score: 61,
        critical_risks: 2,
        high_risks: 1,
        open_findings: 5,
        kev_findings: 1,
        active_threats: 3,
        external_assets: 2,
        recommended_actions: ['Patcha gateway omedelbart.'],
      },
      nodes: [
        { id: 'system:1', kind: 'system', label: 'Payment API', severity: 'critical', status: 'operational', metadata: {} },
        { id: 'risk:1', kind: 'risk', label: 'Gateway compromise', severity: 'critical', status: 'open', metadata: {} },
      ],
      edges: [{ id: 'edge:1', source: 'risk:1', target: 'system:1', relationship: 'affects', metadata: {} }],
      truncated: false,
    };

    describe('CyberRiskGraph', () => {
      test('renders CISO metrics, business context and recommended actions', () => {
        render(<CyberRiskGraph graph={graph} />);
        expect(screen.getByText('61/100')).toBeInTheDocument();
        expect(screen.getByText('Head of Payments')).toBeInTheDocument();
        expect(screen.getByText('Accept payments')).toBeInTheDocument();
        expect(screen.getByText('Patcha gateway omedelbart.')).toBeInTheDocument();
        expect(screen.getByLabelText('Cyber Risk Graph')).toBeInTheDocument();
      });
    });
    '''
)
write("apps/web/src/components/CyberRiskGraph.test.tsx", cyber_risk_graph_test)


# ---------------------------------------------------------------------------
# Architecture editor: persist business context in each manual version.
# ---------------------------------------------------------------------------
editor_path = "apps/web/src/components/OperationalArchitectureEditor.tsx"
replace_once(
    editor_path,
    "  type ArchitectureEdgeInput,\n  type ArchitectureGraphInput,\n",
    "  type ArchitectureBusinessContextInput,\n  type ArchitectureEdgeInput,\n  type ArchitectureGraphInput,\n",
)
editor_helpers = textwrap.dedent(
    '''

    const DEFAULT_BUSINESS_CONTEXT: ArchitectureBusinessContextInput = {
      business_owner: '',
      capabilities: [],
      processes: [],
      data_categories: [],
      regulations: [],
      recovery_time_objective_hours: null,
      recovery_point_objective_hours: null,
      impact: {
        confidentiality: 3,
        integrity: 3,
        availability: 3,
        financial: 3,
        regulatory: 3,
        reputation: 3,
        safety: 1,
      },
    };

    function stringListValue(value: unknown): string[] {
      return Array.isArray(value)
        ? value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
        : [];
    }

    function numericImpact(value: unknown, fallback: number): number {
      return typeof value === 'number' && value >= 1 && value <= 5 ? value : fallback;
    }

    function normalizeBusinessContext(graph: Record<string, unknown>): ArchitectureBusinessContextInput {
      const raw = objectValue(graph.business_context);
      const impact = objectValue(raw.impact);
      return {
        business_owner: stringValue(raw.business_owner) ?? '',
        capabilities: stringListValue(raw.capabilities),
        processes: stringListValue(raw.processes),
        data_categories: stringListValue(raw.data_categories),
        regulations: stringListValue(raw.regulations),
        recovery_time_objective_hours:
          typeof raw.recovery_time_objective_hours === 'number'
            ? raw.recovery_time_objective_hours
            : null,
        recovery_point_objective_hours:
          typeof raw.recovery_point_objective_hours === 'number'
            ? raw.recovery_point_objective_hours
            : null,
        impact: {
          confidentiality: numericImpact(impact.confidentiality, 3),
          integrity: numericImpact(impact.integrity, 3),
          availability: numericImpact(impact.availability, 3),
          financial: numericImpact(impact.financial, 3),
          regulatory: numericImpact(impact.regulatory, 3),
          reputation: numericImpact(impact.reputation, 3),
          safety: numericImpact(impact.safety, 1),
        },
      };
    }

    function parseCommaSeparated(value: string): string[] {
      return [...new Set(value.split(',').map((item) => item.trim()).filter(Boolean))];
    }
    '''
)
replace_once(editor_path, "\n\nfunction normalizeGraph(", editor_helpers + "\n\nfunction normalizeGraph(")
replace_once(
    editor_path,
    "  riskContexts: EditorRiskContext[];\n} {\n  if (!snapshot) return { nodes: [], edges: [], zones: [], riskContexts: [] };\n  const graph = snapshot.graph;\n",
    "  riskContexts: EditorRiskContext[];\n  businessContext: ArchitectureBusinessContextInput;\n} {\n"
    "  if (!snapshot) {\n"
    "    return { nodes: [], edges: [], zones: [], riskContexts: [], businessContext: DEFAULT_BUSINESS_CONTEXT };\n"
    "  }\n"
    "  const graph = snapshot.graph;\n"
    "  const businessContext = normalizeBusinessContext(graph);\n",
)
replace_once(
    editor_path,
    "  return { nodes, edges, zones, riskContexts };\n}\n",
    "  return { nodes, edges, zones, riskContexts, businessContext };\n}\n",
)
replace_once(
    editor_path,
    "  riskContexts: EditorRiskContext[],\n): ArchitectureGraphInput {\n",
    "  riskContexts: EditorRiskContext[],\n"
    "  businessContext: ArchitectureBusinessContextInput,\n"
    "): ArchitectureGraphInput {\n",
)
replace_once(
    editor_path,
    "    warning:\n      'Manuellt redigerad arkitektur. Komponenter, trust boundaries och dataflöden måste granskas innan publicering.',\n    zones,\n",
    "    warning:\n      'Manuellt redigerad arkitektur. Komponenter, trust boundaries och dataflöden måste granskas innan publicering.',\n"
    "    business_context: businessContext,\n"
    "    zones,\n",
)
replace_once(
    editor_path,
    "  riskContexts: EditorRiskContext[],\n  title: string,\n",
    "  riskContexts: EditorRiskContext[],\n"
    "  businessContext: ArchitectureBusinessContextInput,\n"
    "  title: string,\n",
)
replace_once(
    editor_path,
    "    graph: buildGraph(nodes, edges, zones, riskContexts),\n",
    "    graph: buildGraph(nodes, edges, zones, riskContexts, businessContext),\n",
)
replace_once(
    editor_path,
    "  const [riskContexts, setRiskContexts] = useState<EditorRiskContext[]>(\n    normalized.riskContexts,\n  );\n",
    "  const [riskContexts, setRiskContexts] = useState<EditorRiskContext[]>(\n"
    "    normalized.riskContexts,\n"
    "  );\n"
    "  const [businessContext, setBusinessContext] = useState<ArchitectureBusinessContextInput>(\n"
    "    normalized.businessContext,\n"
    "  );\n",
)
replace_once(
    editor_path,
    "      normalized.riskContexts,\n      selectedVersion?.title ?? `${systemName} – arkitektur`,\n",
    "      normalized.riskContexts,\n"
    "      normalized.businessContext,\n"
    "      selectedVersion?.title ?? `${systemName} – arkitektur`,\n",
)
replace_once(
    editor_path,
    "    () => editorFingerprint(nodes, edges, zones, riskContexts, title, changeNote),\n    [changeNote, edges, nodes, riskContexts, title, zones],\n",
    "    () =>\n"
    "      editorFingerprint(\n"
    "        nodes,\n"
    "        edges,\n"
    "        zones,\n"
    "        riskContexts,\n"
    "        businessContext,\n"
    "        title,\n"
    "        changeNote,\n"
    "      ),\n"
    "    [businessContext, changeNote, edges, nodes, riskContexts, title, zones],\n",
)
replace_once(
    editor_path,
    "    setRiskContexts(normalized.riskContexts);\n",
    "    setRiskContexts(normalized.riskContexts);\n"
    "    setBusinessContext(normalized.businessContext);\n",
)
replace_once(
    editor_path,
    "        normalized.riskContexts,\n        nextTitle,\n",
    "        normalized.riskContexts,\n"
    "        normalized.businessContext,\n"
    "        nextTitle,\n",
)
replace_once(
    editor_path,
    "    const graph = buildGraph(nodes, edges, zones, riskContexts);\n",
    "    const graph = buildGraph(nodes, edges, zones, riskContexts, businessContext);\n",
)
replace_once(
    editor_path,
    "        editorFingerprint(nodes, edges, zones, riskContexts, title, changeNote),\n",
    "        editorFingerprint(\n"
    "          nodes,\n"
    "          edges,\n"
    "          zones,\n"
    "          riskContexts,\n"
    "          businessContext,\n"
    "          title,\n"
    "          changeNote,\n"
    "        ),\n",
)

business_context_ui = textwrap.dedent(
    '''

          <section className="op-business-context panel" aria-label="Verksamhetskontext">
            <header className="op-section-heading">
              <div>
                <span className="section-kicker">CYBER RISK CONTEXT</span>
                <h2>Koppla arkitekturen till verksamheten</h2>
              </div>
              <small>Kontexten versionshanteras med den manuella arkitekturmodellen och används i riskgrafen.</small>
            </header>
            <div className="op-business-context__grid">
              <label><span>Affärsägare</span><input disabled={readOnly} value={businessContext.business_owner} onChange={(event) => setBusinessContext((current) => ({ ...current, business_owner: event.target.value }))} /></label>
              <label><span>Verksamhetsförmågor, kommaseparerade</span><input disabled={readOnly} value={businessContext.capabilities.join(', ')} onChange={(event) => setBusinessContext((current) => ({ ...current, capabilities: parseCommaSeparated(event.target.value) }))} /></label>
              <label><span>Processer, kommaseparerade</span><input disabled={readOnly} value={businessContext.processes.join(', ')} onChange={(event) => setBusinessContext((current) => ({ ...current, processes: parseCommaSeparated(event.target.value) }))} /></label>
              <label><span>Datakategorier, kommaseparerade</span><input disabled={readOnly} value={businessContext.data_categories.join(', ')} onChange={(event) => setBusinessContext((current) => ({ ...current, data_categories: parseCommaSeparated(event.target.value) }))} /></label>
              <label><span>Regelverk, kommaseparerade</span><input disabled={readOnly} value={businessContext.regulations.join(', ')} onChange={(event) => setBusinessContext((current) => ({ ...current, regulations: parseCommaSeparated(event.target.value) }))} /></label>
              <label><span>RTO, timmar</span><input disabled={readOnly} min={0} step="0.5" type="number" value={businessContext.recovery_time_objective_hours ?? ''} onChange={(event) => setBusinessContext((current) => ({ ...current, recovery_time_objective_hours: event.target.value === '' ? null : Number(event.target.value) }))} /></label>
              <label><span>RPO, timmar</span><input disabled={readOnly} min={0} step="0.5" type="number" value={businessContext.recovery_point_objective_hours ?? ''} onChange={(event) => setBusinessContext((current) => ({ ...current, recovery_point_objective_hours: event.target.value === '' ? null : Number(event.target.value) }))} /></label>
            </div>
            <div className="op-business-impact" role="group" aria-label="Konsekvensprofil">
              {([
                ['confidentiality', 'Konfidentialitet'],
                ['integrity', 'Riktighet'],
                ['availability', 'Tillgänglighet'],
                ['financial', 'Finansiell'],
                ['regulatory', 'Regulatorisk'],
                ['reputation', 'Anseende'],
                ['safety', 'Säkerhet för person'],
              ] as const).map(([key, label]) => (
                <label key={key}><span>{label}</span><select disabled={readOnly} value={businessContext.impact[key]} onChange={(event) => setBusinessContext((current) => ({ ...current, impact: { ...current.impact, [key]: Number(event.target.value) } }))}>{[1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}/5</option>)}</select></label>
              ))}
            </div>
          </section>
    '''
)
replace_once(
    editor_path,
    "      <div className=\"op-editor-shell\">\n",
    business_context_ui + "\n      <div className=\"op-editor-shell\">\n",
)


# ---------------------------------------------------------------------------
# Operational workspace: CISO-first summary and graph tab.
# ---------------------------------------------------------------------------
workspace_path = "apps/web/src/components/OperationalWorkspace.tsx"
replace_once(
    workspace_path,
    "  type Criticality,\n  type Finding,\n",
    "  type Criticality,\n  type CyberRiskGraphView,\n  type Finding,\n",
)
replace_once(
    workspace_path,
    "import { ExternalIntelligenceConnectorPanel } from './ExternalIntelligenceConnectorPanel';\n",
    "import { CyberRiskGraph } from './CyberRiskGraph';\n"
    "import { ExternalIntelligenceConnectorPanel } from './ExternalIntelligenceConnectorPanel';\n",
)
replace_once(
    workspace_path,
    "  | 'architecture'\n  | 'reports';\n",
    "  | 'architecture'\n  | 'risk_graph'\n  | 'reports';\n",
)
replace_once(
    workspace_path,
    "  const [overview, setOverview] = useState<PipelineOverview | null>(null);\n",
    "  const [overview, setOverview] = useState<PipelineOverview | null>(null);\n"
    "  const [riskGraph, setRiskGraph] = useState<CyberRiskGraphView | null>(null);\n",
)
replace_once(
    workspace_path,
    "    setOverview(null);\n",
    "    setOverview(null);\n    setRiskGraph(null);\n",
)
replace_once(
    workspace_path,
    "      api.getOverview(selectedSystemId),\n      api.listAssetPage",
    "      api.getOverview(selectedSystemId),\n      api.getRiskGraph(selectedSystemId),\n      api.listAssetPage",
)
replace_once(
    workspace_path,
    "        nextOverview,\n        nextAssetPage,\n",
    "        nextOverview,\n        nextRiskGraph,\n        nextAssetPage,\n",
)
replace_once(
    workspace_path,
    "        setOverview(nextOverview);\n        setAssetPage(nextAssetPage);\n",
    "        setOverview(nextOverview);\n        setRiskGraph(nextRiskGraph);\n        setAssetPage(nextAssetPage);\n",
)
replace_once(
    workspace_path,
    "      api.getOverview(systemId),\n      api.listAssetPage",
    "      api.getOverview(systemId),\n      api.getRiskGraph(systemId),\n      api.listAssetPage",
)
replace_once(
    workspace_path,
    "      nextOverview,\n      nextAssetPage,\n",
    "      nextOverview,\n      nextRiskGraph,\n      nextAssetPage,\n",
)
replace_once(
    workspace_path,
    "    setOverview(nextOverview);\n    setAssetPage(nextAssetPage);\n",
    "    setOverview(nextOverview);\n    setRiskGraph(nextRiskGraph);\n    setAssetPage(nextAssetPage);\n",
)
replace_once(
    workspace_path,
    "    { id: 'architecture', label: 'Arkitektur' },\n    { id: 'reports', label: 'Rapporter', count: reports.length },\n",
    "    { id: 'architecture', label: 'Arkitektur' },\n"
    "    { id: 'risk_graph', label: 'Riskgraf', count: riskGraph?.summary.critical_risks ?? 0 },\n"
    "    { id: 'reports', label: 'Rapporter', count: reports.length },\n",
)

ciso_panel = textwrap.dedent(
    '''

              {riskGraph && (
                <section className="op-ciso-dashboard panel" aria-label="CISO-läge">
                  <header className="op-section-heading">
                    <div><span className="section-kicker">CISO-LÄGE</span><h2>Beslutsorienterad cyberrisk</h2></div>
                    <button className="secondary-button" onClick={() => selectWorkspaceTab('risk_graph')} type="button">Öppna Cyber Risk Graph</button>
                  </header>
                  <div className="op-ciso-dashboard__metrics">
                    <article><strong>{riskGraph.summary.security_score}/100</strong><small>Säkerhetspoäng</small></article>
                    <article><strong>{riskGraph.summary.critical_risks}</strong><small>Kritiska risker</small></article>
                    <article><strong>{riskGraph.summary.kev_findings}</strong><small>KEV-fynd</small></article>
                    <article><strong>{riskGraph.summary.external_assets}</strong><small>Externa tillgångar</small></article>
                    <article><strong>{riskGraph.summary.active_threats}</strong><small>Aktiva hot</small></article>
                  </div>
                  <div className="op-ciso-dashboard__body">
                    <div><strong>{riskGraph.business_context.business_owner || selectedSystem.owner}</strong><span>{riskGraph.business_context.capabilities.join(' · ') || 'Verksamhetsförmågor behöver anges i arkitekturvyn.'}</span></div>
                    <ol>{riskGraph.summary.recommended_actions.slice(0, 3).map((action) => <li key={action}>{action}</li>)}</ol>
                  </div>
                </section>
              )}
    '''
)
replace_once(
    workspace_path,
    "          <section className=\"op-pipeline panel\" aria-label=\"Analyskedja\">\n",
    ciso_panel + "\n          <section className=\"op-pipeline panel\" aria-label=\"Analyskedja\">\n",
)

risk_graph_tab = textwrap.dedent(
    '''

                {activeTab === 'risk_graph' && (
                  riskGraph ? (
                    <CyberRiskGraph graph={riskGraph} />
                  ) : (
                    <EmptyState title="Riskgrafen kunde inte byggas">
                      Skapa eller välj ett system och lägg till verksamhetskontext i arkitekturvyn.
                    </EmptyState>
                  )
                )}
    '''
)
replace_once(
    workspace_path,
    "            {activeTab === 'architecture' && (\n",
    risk_graph_tab + "\n            {activeTab === 'architecture' && (\n",
)


# ---------------------------------------------------------------------------
# Frontend test fixture: expose the new API method.
# ---------------------------------------------------------------------------
workspace_test_path = "apps/web/src/components/OperationalWorkspace.test.tsx"
replace_once(
    workspace_test_path,
    "  BackgroundJobListOptions,\n  ExternalIntelligenceSyncRunList,\n",
    "  BackgroundJobListOptions,\n  CyberRiskGraphView,\n  ExternalIntelligenceSyncRunList,\n",
)
risk_graph_fixture = textwrap.dedent(
    '''

    const riskGraph: CyberRiskGraphView = {
      system_id: system.id,
      business_context: {
        business_owner: 'Head of Payments',
        capabilities: ['Accept payments'],
        processes: ['Card authorization'],
        data_categories: ['Payment data'],
        regulations: ['DORA', 'PCI DSS'],
        recovery_time_objective_hours: 2,
        recovery_point_objective_hours: 0.5,
        impact: {
          confidentiality: 5,
          integrity: 5,
          availability: 5,
          financial: 5,
          regulatory: 5,
          reputation: 4,
          safety: 1,
        },
      },
      summary: {
        security_score: 61,
        critical_risks: 1,
        high_risks: 0,
        open_findings: 1,
        kev_findings: 1,
        active_threats: 1,
        external_assets: 1,
        recommended_actions: ['Patcha eller isolera CVE-2099-12345 omedelbart.'],
      },
      nodes: [
        { id: 'system:system-1', kind: 'system', label: 'Payment API', severity: 'critical', status: 'operational', metadata: {} },
        { id: 'risk:risk-1', kind: 'risk', label: 'Exploitation of CVE-2099-12345', severity: 'critical', status: 'open', metadata: {} },
      ],
      edges: [{ id: 'edge:1', source: 'risk:risk-1', target: 'system:system-1', relationship: 'affects', metadata: {} }],
      truncated: false,
    };
    '''
)
replace_once(
    workspace_test_path,
    "\n\nconst report: Report = {",
    risk_graph_fixture + "\n\nconst report: Report = {",
)
replace_once(
    workspace_test_path,
    "    getOverview: vi.fn(async () => overview),\n",
    "    getOverview: vi.fn(async () => overview),\n"
    "    getRiskGraph: vi.fn(async () => riskGraph),\n",
)
replace_once(
    workspace_test_path,
    "    expect(screen.getByText(/ingen kontinuerlig liveinsamling hävdas/i)).toBeInTheDocument();\n",
    "    expect(screen.getByText(/ingen kontinuerlig liveinsamling hävdas/i)).toBeInTheDocument();\n"
    "    expect(screen.getByRole('region', { name: 'CISO-läge' })).toBeInTheDocument();\n"
    "    expect(screen.getByText('61/100')).toBeInTheDocument();\n",
)


# ---------------------------------------------------------------------------
# Styling.
# ---------------------------------------------------------------------------
styles_path = "apps/web/src/styles.css"
styles = textwrap.dedent(
    '''

    .op-business-context { margin-bottom: 16px; }
    .op-business-context__grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
    .op-business-context__grid label, .op-business-impact label { display: grid; gap: 6px; }
    .op-business-impact { display: grid; grid-template-columns: repeat(auto-fit, minmax(145px, 1fr)); gap: 10px; margin-top: 14px; }
    .op-ciso-dashboard { display: grid; gap: 16px; }
    .op-ciso-dashboard__metrics, .op-risk-graph-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; }
    .op-ciso-dashboard__metrics article, .op-risk-graph-summary article { border: 1px solid var(--line, #d6dfea); border-radius: 12px; padding: 14px; display: grid; gap: 4px; }
    .op-ciso-dashboard__metrics strong, .op-risk-graph-summary strong { font-size: 1.45rem; }
    .op-ciso-dashboard__body { display: grid; grid-template-columns: minmax(220px, 0.8fr) minmax(300px, 1.2fr); gap: 18px; }
    .op-ciso-dashboard__body > div { display: grid; gap: 5px; align-content: start; }
    .op-ciso-dashboard__body ol, .op-risk-graph-actions ol { margin: 0; padding-left: 20px; display: grid; gap: 8px; }
    .op-risk-graph-workspace { display: grid; gap: 14px; }
    .op-risk-graph-context { display: grid; grid-template-columns: minmax(240px, 0.8fr) minmax(320px, 1.2fr); gap: 20px; }
    .op-risk-graph-context dl { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin: 0; }
    .op-risk-graph-context dl div { border-bottom: 1px solid var(--line, #d6dfea); padding-bottom: 8px; }
    .op-risk-graph-context dt { font-size: .78rem; color: var(--muted, #5f6b7a); }
    .op-risk-graph-context dd { margin: 3px 0 0; }
    .op-risk-graph-canvas { height: min(72vh, 760px); min-height: 520px; padding: 0; overflow: hidden; }
    .op-risk-graph-node { width: 220px; border-radius: 12px; border: 1px solid var(--line, #d6dfea); background: var(--surface, #fff); padding: 10px; }
    .op-risk-graph-node__content { display: grid; gap: 3px; text-align: left; }
    .op-risk-graph-node__content small, .op-risk-graph-node__content em { color: var(--muted, #5f6b7a); font-size: .7rem; font-style: normal; }
    .op-risk-graph-node__content b { justify-self: start; margin-top: 4px; }
    .op-risk-graph-node--risk, .op-risk-graph-node--finding, .op-risk-graph-node--threat { box-shadow: 0 0 0 1px rgba(160, 65, 65, .16) inset; }
    .op-risk-graph-node--business_capability, .op-risk-graph-node--regulation { box-shadow: 0 0 0 1px rgba(49, 95, 143, .18) inset; }
    .op-risk-graph-node--action { box-shadow: 0 0 0 1px rgba(42, 120, 82, .18) inset; }
    .op-risk-graph-edge .react-flow__edge-text { font-size: 9px; }
    @media (max-width: 760px) {
      .op-ciso-dashboard__body, .op-risk-graph-context { grid-template-columns: 1fr; }
      .op-risk-graph-canvas { min-height: 460px; }
    }
    '''
)
write(styles_path, read(styles_path) + styles)


# ---------------------------------------------------------------------------
# Architecture tests need the new required graph field in their local type fixtures.
# The backend provides a default, while the TypeScript contract is explicit.
# ---------------------------------------------------------------------------
for path in [
    "apps/web/src/components/OperationalArchitectureEditor.test.tsx",
]:
    text = read(path)
    text = text.replace(
        "      warning: 'Scanner draft',\n      zones:",
        "      warning: 'Scanner draft',\n      business_context: { ...DEFAULT_TEST_BUSINESS_CONTEXT },\n      zones:",
    )
    if "DEFAULT_TEST_BUSINESS_CONTEXT" not in text:
        # The replacement above did not occur; no matching typed inline fixture needs adjustment.
        continue
    write(path, text)


# ---------------------------------------------------------------------------
# Documentation.
# ---------------------------------------------------------------------------
documentation = textwrap.dedent(
    '''
    # Cyber Risk Graph

    Traceless bygger en läsbar, begränsad graf från den senaste lokala kunddatan:

    `verksamhetsförmåga → system → tillgång → tjänst → fynd/hot → risk → rekommenderad åtgärd`

    Verksamhetskontexten lagras i varje manuell arkitekturversion och omfattar affärsägare,
    processer, datakategorier, regelverk, RTO/RPO och en konsekvensprofil. Grafen är ett
    besluts- och navigationsunderlag. En grafkant innebär en spårbar relation i aktuell data,
    inte bevis för genomförd exploatering eller en fullständigt validerad attackväg.

    API: `GET /api/v1/operational/systems/{system_id}/risk-graph`

    Svaret innehåller:

    - CISO-sammanfattning och säkerhetspoäng,
    - verksamhetskontext,
    - typade noder och relationer,
    - prioriterade rekommenderade åtgärder,
    - markering om grafen har begränsats för läsbarhet.
    '''
)
write("docs/cyber-risk-graph.md", documentation)

print("Cyber Risk Graph implementation applied")
