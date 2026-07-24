"""Persistence operations for the operational security-analysis pipeline."""

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import Any
from uuid import UUID

from sqlalchemy import Select, false, func, or_, select, update
from sqlalchemy.orm import Session

from traceless_api.core.tenancy import (
    DEFAULT_ORGANIZATION_ID,
    DEFAULT_ORGANIZATION_KEY,
    DEFAULT_ORGANIZATION_NAME,
)
from traceless_api.db.models import (
    ArchitectureSnapshotRow,
    AssetAliasRow,
    AssetObservationRow,
    AssetRow,
    AssetSourceSnapshotRow,
    AuditEventRow,
    FindingEvidenceRow,
    FindingRow,
    GlobalIntelRecordRow,
    IntelligenceCacheRow,
    IntelligenceSyncStateRow,
    OrganizationRow,
    ProjectRow,
    ReportRow,
    RiskRow,
    ScanAuthorizationRow,
    ScanJobRow,
    ServiceRow,
    SystemRow,
    ThreatRow,
    VulnerabilityObservationRow,
    VulnerabilityScanImportRow,
)
from traceless_api.integrations.asset_sources import AssetSourceSnapshot, NetBoxAssetRecord
from traceless_api.integrations.intelligence import (
    CvssMetric,
    EpssMetric,
    IntelligenceBatch,
    KevCatalogEntry,
    NvdCveBatch,
    ThreatIntelligenceObject,
)
from traceless_api.models.operational import (
    ArchitectureVersionCreate,
    CveEnrichmentImport,
    OperationalSystemCreate,
    ProjectCreate,
    ThreatFeedImport,
    VulnerabilityScanImportCreate,
)
from traceless_api.services.risk_engine import assess_threat, assess_vulnerability


class OperationalNotFoundError(LookupError):
    pass


class OperationalConflictError(RuntimeError):
    pass


def _one_or_not_found(session: Session, statement: Select[Any], resource: str) -> Any:
    item = session.scalar(statement)
    if item is None:
        raise OperationalNotFoundError(f"{resource} was not found")
    return item


class OperationalRepository:
    """Transaction-scoped repository; the FastAPI dependency owns commit/rollback."""

    def __init__(
        self,
        session: Session,
        *,
        organization_id: UUID | None = DEFAULT_ORGANIZATION_ID,
        organization_key: str | None = DEFAULT_ORGANIZATION_KEY,
        organization_name: str | None = DEFAULT_ORGANIZATION_NAME,
        allowed_project_ids: frozenset[UUID] | None = None,
        allowed_system_ids: frozenset[UUID] | None = None,
    ) -> None:
        self.session = session
        self.organization_id = organization_id
        self.organization_key = organization_key
        self.organization_name = organization_name
        self.allowed_project_ids = allowed_project_ids
        self.allowed_system_ids = allowed_system_ids

    @property
    def resource_scope_is_restricted(self) -> bool:
        return not (
            self.allowed_project_ids is None and self.allowed_system_ids is None
        )

    def _project_scope_clause(self) -> Any:
        if not self.resource_scope_is_restricted:
            return None
        clauses = []
        project_ids = self.allowed_project_ids or frozenset()
        system_ids = self.allowed_system_ids or frozenset()
        if project_ids:
            clauses.append(ProjectRow.id.in_(project_ids))
        if system_ids:
            clauses.append(
                ProjectRow.id.in_(
                    select(SystemRow.project_id).where(SystemRow.id.in_(system_ids))
                )
            )
        return or_(*clauses) if clauses else false()

    def _system_scope_clause(self) -> Any:
        if not self.resource_scope_is_restricted:
            return None
        clauses = []
        project_ids = self.allowed_project_ids or frozenset()
        system_ids = self.allowed_system_ids or frozenset()
        if project_ids:
            clauses.append(SystemRow.project_id.in_(project_ids))
        if system_ids:
            clauses.append(SystemRow.id.in_(system_ids))
        return or_(*clauses) if clauses else false()

    @classmethod
    def unscoped(cls, session: Session) -> "OperationalRepository":
        """Create an internal worker repository; never use for request handling."""

        return cls(
            session,
            organization_id=None,
            organization_key=None,
            organization_name=None,
        )

    def ensure_organization(self) -> OrganizationRow:
        if self.organization_id is None:
            raise OperationalConflictError("An organization scope is required")
        row = self.session.get(OrganizationRow, self.organization_id)
        if row is None:
            row = OrganizationRow(
                id=self.organization_id,
                external_key=self.organization_key or str(self.organization_id),
                name=self.organization_name or str(self.organization_id),
            )
            self.session.add(row)
            self.session.flush()
        elif self.organization_key and row.external_key != self.organization_key:
            raise OperationalConflictError("Organization identity does not match persisted scope")
        elif self.organization_name and row.name != self.organization_name:
            row.name = self.organization_name
        return row

    def create_project(self, payload: ProjectCreate, actor: str) -> ProjectRow:
        organization = self.ensure_organization()
        row = ProjectRow(
            organization_id=organization.id,
            name=payload.name,
            description=payload.description,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "project.created", "project", row.id)
        return row

    def list_projects(self) -> list[ProjectRow]:
        statement = select(ProjectRow).order_by(ProjectRow.created_at)
        if self.organization_id is not None:
            statement = statement.where(ProjectRow.organization_id == self.organization_id)
        project_scope = self._project_scope_clause()
        if project_scope is not None:
            statement = statement.where(project_scope)
        return list(self.session.scalars(statement))

    def get_project(self, project_id: UUID) -> ProjectRow:
        statement = select(ProjectRow).where(ProjectRow.id == project_id)
        if self.organization_id is not None:
            statement = statement.where(ProjectRow.organization_id == self.organization_id)
        project_scope = self._project_scope_clause()
        if project_scope is not None:
            statement = statement.where(project_scope)
        return _one_or_not_found(self.session, statement, "Project")

    def create_system(
        self,
        project_id: UUID,
        payload: OperationalSystemCreate,
        actor: str,
    ) -> SystemRow:
        self.get_project(project_id)
        if self.resource_scope_is_restricted and project_id not in (
            self.allowed_project_ids or frozenset()
        ):
            # A system-only assignment may make its parent project readable for
            # navigation, but it never grants authority to create sibling systems.
            raise OperationalNotFoundError("Project was not found")
        row = SystemRow(project_id=project_id, **payload.model_dump())
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "system.created", "system", row.id)
        return row

    def list_systems(self, project_id: UUID) -> list[SystemRow]:
        self.get_project(project_id)
        statement = select(SystemRow).where(SystemRow.project_id == project_id)
        system_scope = self._system_scope_clause()
        if system_scope is not None:
            statement = statement.where(system_scope)
        return list(
            self.session.scalars(
                statement.order_by(SystemRow.created_at)
            )
        )

    def get_system(self, system_id: UUID) -> SystemRow:
        statement = select(SystemRow).where(SystemRow.id == system_id)
        if self.organization_id is not None:
            statement = statement.join(ProjectRow, ProjectRow.id == SystemRow.project_id).where(
                ProjectRow.organization_id == self.organization_id
            )
        system_scope = self._system_scope_clause()
        if system_scope is not None:
            statement = statement.where(system_scope)
        return _one_or_not_found(
            self.session,
            statement,
            "Operational system",
        )

    def _lock_system(self, system_id: UUID) -> SystemRow:
        """Serialize version allocation for one system on databases that support row locks."""

        statement = select(SystemRow).where(SystemRow.id == system_id)
        if self.organization_id is not None:
            statement = statement.join(ProjectRow, ProjectRow.id == SystemRow.project_id).where(
                ProjectRow.organization_id == self.organization_id
            )
        system_scope = self._system_scope_clause()
        if system_scope is not None:
            statement = statement.where(system_scope)
        return _one_or_not_found(self.session, statement.with_for_update(), "Operational system")

    def lock_system_for_scan_ingestion(self, system_id: UUID) -> SystemRow:
        """Serialize all scan-derived writes for one operational system."""

        return self._lock_system(system_id)

    def create_authorization(
        self,
        *,
        system_id: UUID,
        targets: list[str],
        profile: str,
        approved_by: str,
        purpose: str,
        expires_at: datetime,
        scope_sha256: str,
        actor: str,
    ) -> ScanAuthorizationRow:
        self.get_system(system_id)
        row = ScanAuthorizationRow(
            system_id=system_id,
            targets=targets,
            profile=profile,
            approved_by=approved_by,
            purpose=purpose,
            expires_at=expires_at,
            scope_sha256=scope_sha256,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(
            actor,
            "scan_authorization.created",
            "scan_authorization",
            row.id,
            {"scope_sha256": scope_sha256, "expires_at": expires_at.isoformat()},
        )
        return row

    def get_authorization(self, authorization_id: UUID) -> ScanAuthorizationRow:
        statement = select(ScanAuthorizationRow).where(ScanAuthorizationRow.id == authorization_id)
        if self.organization_id is not None:
            statement = (
                statement.join(SystemRow, SystemRow.id == ScanAuthorizationRow.system_id)
                .join(ProjectRow, ProjectRow.id == SystemRow.project_id)
                .where(ProjectRow.organization_id == self.organization_id)
            )
        system_scope = self._system_scope_clause()
        if system_scope is not None:
            statement = statement.where(system_scope)
        row = _one_or_not_found(
            self.session,
            statement,
            "Scan authorization",
        )
        if row.status == "active" and _as_aware(row.expires_at) <= datetime.now(UTC):
            row.status = "expired"
            self.session.flush()
        return row

    def create_scan_job(
        self,
        *,
        system_id: UUID,
        authorization_id: UUID,
        mode: str,
        actor: str,
        scanner: str = "nmap",
        max_attempts: int = 3,
    ) -> ScanJobRow:
        if self.organization_id is None:
            raise OperationalConflictError("Scan jobs require an organization boundary")
        authorization = self.get_authorization(authorization_id)
        if authorization.system_id != system_id:
            raise OperationalConflictError("Authorization belongs to another system")
        if authorization.status != "active":
            raise OperationalConflictError("Authorization is not active")
        row = ScanJobRow(
            organization_id=self.organization_id,
            system_id=system_id,
            authorization_id=authorization_id,
            scanner=scanner,
            mode=mode,
            status="queued" if mode == "live" else "running",
            started_at=datetime.now(UTC) if mode == "import" else None,
            max_attempts=max_attempts,
            scope_targets=list(authorization.targets),
            scope_sha256=authorization.scope_sha256,
            scan_profile=authorization.profile,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "scan.queued" if mode == "live" else "scan.imported", "scan", row.id)
        return row

    def get_scan_job(self, scan_id: UUID) -> ScanJobRow:
        statement = select(ScanJobRow).where(ScanJobRow.id == scan_id)
        if self.organization_id is not None:
            statement = (
                statement.join(SystemRow, SystemRow.id == ScanJobRow.system_id)
                .join(ProjectRow, ProjectRow.id == SystemRow.project_id)
                .where(ProjectRow.organization_id == self.organization_id)
            )
        system_scope = self._system_scope_clause()
        if system_scope is not None:
            statement = statement.where(system_scope)
        return _one_or_not_found(self.session, statement, "Scan job")

    def list_scan_jobs(self, system_id: UUID) -> list[ScanJobRow]:
        self.get_system(system_id)
        return list(
            self.session.scalars(
                select(ScanJobRow)
                .where(ScanJobRow.system_id == system_id)
                .order_by(ScanJobRow.requested_at.desc())
            )
        )

    def upsert_asset(
        self,
        *,
        system_id: UUID,
        scan_id: UUID,
        primary_ip: str,
        hostname: str | None,
        mac_address: str | None,
        state: str,
        os_family: str | None,
        os_accuracy: int | None,
        observed_at: datetime,
        promote_current: bool = True,
    ) -> AssetRow:
        normalized_ip = _normalized_asset_alias("ip", primary_ip)
        normalized_mac = _normalized_asset_alias("mac", mac_address) if mac_address else None
        normalized_hostname = _normalized_asset_alias("hostname", hostname) if hostname else None
        mac_asset = (
            self._asset_for_alias(system_id, "mac", normalized_mac)
            if normalized_mac is not None
            else None
        )
        ip_asset = self._asset_for_alias(system_id, "ip", normalized_ip)
        if mac_asset is None and normalized_mac is not None:
            mac_asset = self.session.scalar(
                select(AssetRow).where(
                    AssetRow.system_id == system_id,
                    AssetRow.stable_key == f"mac:{normalized_mac}",
                )
            )
        if ip_asset is None:
            ip_asset = self.session.scalar(
                select(AssetRow).where(
                    AssetRow.system_id == system_id,
                    AssetRow.stable_key == f"ip:{normalized_ip}",
                )
            )

        row = mac_asset
        if row is not None and ip_asset is not None and row.id != ip_asset.id:
            # MAC is the durable identity. An IP may legitimately move between
            # two already established devices, in which case merging would
            # destroy both finding history and inventory truth. Only merge an
            # IP-only identity into the MAC identity.
            if not _assets_have_distinct_macs(row, ip_asset):
                row = self._merge_assets(row, ip_asset)
        elif row is None and ip_asset is not None:
            # A newly observed MAC on an IP-only asset enriches that identity.
            # A different established MAC means IP reuse and must create/select
            # the new MAC identity instead of mutating the former device.
            if normalized_mac is None or not _asset_has_other_mac(ip_asset, normalized_mac):
                row = ip_asset
        if row is None and normalized_hostname is not None:
            hostname_asset = self._asset_for_alias(
                system_id, "hostname", normalized_hostname
            )
            if hostname_asset is not None and (
                normalized_mac is None
                or not _asset_has_other_mac(hostname_asset, normalized_mac)
            ):
                row = hostname_asset
        stable_key = (
            f"mac:{normalized_mac}" if normalized_mac is not None else f"ip:{normalized_ip}"
        )
        if row is None:
            row = AssetRow(
                system_id=system_id,
                source_scan_id=scan_id,
                stable_key=stable_key,
                primary_ip=primary_ip,
                hostname=hostname,
                mac_address=normalized_mac,
                state=state,
                os_family=os_family,
                os_accuracy=os_accuracy,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                inventory_status="current" if promote_current else "stale",
            )
            self.session.add(row)
        else:
            if normalized_mac is not None and row.stable_key.startswith("ip:"):
                conflicting = self.session.scalar(
                    select(AssetRow).where(
                        AssetRow.system_id == system_id,
                        AssetRow.stable_key == stable_key,
                        AssetRow.id != row.id,
                    )
                )
                if conflicting is not None:
                    row = self._merge_assets(conflicting, row)
                else:
                    row.stable_key = stable_key
            if promote_current:
                row.source_scan_id = scan_id
                row.primary_ip = primary_ip
                row.hostname = hostname or row.hostname
                row.mac_address = normalized_mac or row.mac_address
                row.state = state
                row.os_family = os_family or row.os_family
                row.os_accuracy = os_accuracy if os_accuracy is not None else row.os_accuracy
                row.inventory_status = "current"
            row.first_seen_at = min(_as_aware(row.first_seen_at), observed_at)
            row.last_seen_at = max(_as_aware(row.last_seen_at), observed_at)
            row.observation_count += 1
        self.session.flush()
        self._upsert_asset_alias(
            system_id=system_id,
            asset=row,
            kind="ip",
            normalized=normalized_ip,
            display=primary_ip,
            observed_at=observed_at,
        )
        if normalized_mac is not None and mac_address is not None:
            self._upsert_asset_alias(
                system_id=system_id,
                asset=row,
                kind="mac",
                normalized=normalized_mac,
                display=mac_address,
                observed_at=observed_at,
            )
        if normalized_hostname is not None and hostname is not None:
            self._upsert_asset_alias(
                system_id=system_id,
                asset=row,
                kind="hostname",
                normalized=normalized_hostname,
                display=hostname,
                observed_at=observed_at,
            )
        observation_material = json.dumps(
            [
                str(row.id),
                normalized_ip,
                normalized_hostname,
                normalized_mac,
                state,
                os_family,
                os_accuracy,
            ],
            separators=(",", ":"),
        )
        observation = AssetObservationRow(
            system_id=system_id,
            scan_job_id=scan_id,
            asset_id=row.id,
            observation_key=hashlib.sha256(observation_material.encode()).hexdigest(),
            primary_ip=primary_ip,
            hostname=hostname,
            mac_address=normalized_mac,
            state=state,
            os_family=os_family,
            os_accuracy=os_accuracy,
            observed_at=observed_at,
        )
        self.session.add(observation)
        self.session.flush()
        return row

    def prepare_scan_generation(
        self,
        scan: ScanJobRow,
        *,
        source_started_at: datetime | None,
        source_completed_at: datetime | None,
        completeness: str,
        received_at: datetime,
    ) -> None:
        """Classify a scan before it is allowed to mutate the current inventory."""

        current = self.current_inventory_scan(scan.system_id)
        scan.source_started_at = source_started_at
        scan.source_completed_at = source_completed_at
        reported_at = source_completed_at or source_started_at
        if reported_at is None:
            source_observed_at = received_at
            source_time_status = "missing"
        elif (
            source_started_at is not None
            and source_completed_at is not None
            and _as_aware(source_completed_at) < _as_aware(source_started_at)
        ):
            source_observed_at = received_at
            source_time_status = "quarantined"
        else:
            reported_at = _as_aware(reported_at)
            if reported_at > received_at + timedelta(minutes=5):
                source_observed_at = received_at
                source_time_status = "quarantined"
            elif reported_at < received_at - timedelta(days=30):
                source_observed_at = reported_at
                source_time_status = "stale"
            else:
                source_observed_at = reported_at
                source_time_status = "trusted"
        normalized_completeness = "discovery" if scan.scan_profile == "discovery" else completeness
        if normalized_completeness not in {"complete", "partial", "discovery"}:
            normalized_completeness = "partial"

        scan.source_observed_at = source_observed_at
        scan.source_time_status = source_time_status
        scan.completeness = normalized_completeness
        can_be_authoritative = (
            scan.scanner == "nmap"
            and scan.scan_profile == "service_inventory"
            and normalized_completeness == "complete"
            and source_time_status != "quarantined"
            and (
                source_time_status == "trusted"
                or (
                    source_time_status == "missing"
                    and (current is None or current.source_time_status == "missing")
                )
            )
        )
        is_newer = current is None or source_observed_at > _as_aware(
            current.source_observed_at or current.completed_at or current.requested_at
        )
        # A newly authorized service-inventory scope may deliberately replace
        # an older scope. Assets outside the new scope become stale (not
        # unobserved), so the system never interprets that scope change as proof
        # of absence.
        becomes_current = bool(can_be_authoritative and is_newer)
        if becomes_current:
            # The database enforces one current generation per system. Clear
            # the previous owner in a separate statement/flush so ORM write
            # ordering cannot transiently violate the partial unique index.
            self.session.execute(
                update(ScanJobRow)
                .where(
                    ScanJobRow.system_id == scan.system_id,
                    ScanJobRow.id != scan.id,
                    ScanJobRow.is_current_inventory.is_(True),
                )
                .values(is_current_inventory=False)
                .execution_options(synchronize_session="fetch")
            )
            self.session.flush()
            scan.is_current_inventory = True
            scan.inventory_role = "authoritative"
        elif source_time_status == "stale" or (current is not None and not is_newer):
            scan.is_current_inventory = False
            scan.inventory_role = "historical"
        else:
            scan.is_current_inventory = False
            scan.inventory_role = "supplemental"
        self.session.flush()

    def finalize_current_inventory(
        self, scan: ScanJobRow, *, observed_asset_ids: set[UUID]
    ) -> None:
        if not scan.is_current_inventory:
            return
        assets = self.list_all_assets(scan.system_id)
        for asset in assets:
            if asset.id in observed_asset_ids:
                asset.inventory_status = "current"
                continue
            asset.inventory_status = (
                "unobserved" if _address_in_scope(asset.primary_ip, scan.scope_targets) else "stale"
            )
        asset_status = {asset.id: asset.inventory_status for asset in assets}
        current_open_endpoints = {
            (service.asset_id, service.port, service.protocol.casefold())
            for service in self.session.scalars(
                select(ServiceRow).where(
                    ServiceRow.scan_job_id == scan.id,
                    func.lower(ServiceRow.state) == "open",
                )
            )
        }
        findings = list(
            self.session.scalars(
                select(FindingRow).where(FindingRow.system_id == scan.system_id)
            )
        )
        for finding in findings:
            status = (
                asset_status.get(finding.asset_id, "unknown")
                if finding.asset_id is not None
                else "unknown"
            )
            if finding.service_id is not None and status == "current":
                finding_service = self.session.get(ServiceRow, finding.service_id)
                if finding_service is None:
                    status = "unknown"
                elif (
                    finding_service.asset_id,
                    finding_service.port,
                    finding_service.protocol.casefold(),
                ) not in current_open_endpoints:
                    status = "unobserved"
            finding.inventory_status = status
        finding_status = {finding.id: finding.inventory_status for finding in findings}
        for risk in self.session.scalars(
            select(RiskRow).where(
                RiskRow.system_id == scan.system_id,
                RiskRow.finding_id.is_not(None),
            )
        ):
            risk.evidence_status = finding_status.get(risk.finding_id, "unknown")
        self.session.flush()

    def _asset_for_alias(self, system_id: UUID, kind: str, normalized: str) -> AssetRow | None:
        alias = self.session.scalar(
            select(AssetAliasRow).where(
                AssetAliasRow.system_id == system_id,
                AssetAliasRow.kind == kind,
                AssetAliasRow.value_normalized == normalized,
            )
        )
        return self.session.get(AssetRow, alias.asset_id) if alias is not None else None

    def _upsert_asset_alias(
        self,
        *,
        system_id: UUID,
        asset: AssetRow,
        kind: str,
        normalized: str,
        display: str,
        observed_at: datetime,
    ) -> None:
        alias = self.session.scalar(
            select(AssetAliasRow).where(
                AssetAliasRow.system_id == system_id,
                AssetAliasRow.kind == kind,
                AssetAliasRow.value_normalized == normalized,
            )
        )
        if alias is None:
            self.session.add(
                AssetAliasRow(
                    system_id=system_id,
                    asset_id=asset.id,
                    kind=kind,
                    value_normalized=normalized,
                    value_display=display,
                    first_seen_at=observed_at,
                    last_seen_at=observed_at,
                )
            )
            return
        observed_at = _as_aware(observed_at)
        alias_last_seen_at = _as_aware(alias.last_seen_at)
        alias.first_seen_at = min(_as_aware(alias.first_seen_at), observed_at)
        if observed_at < alias_last_seen_at or (
            observed_at == alias_last_seen_at and alias.asset_id != asset.id
        ):
            # A delayed historical scan must never steal a live IP/hostname
            # alias from a newer identity. Equal-time conflicting claims are
            # also left with their first deterministic owner.
            return
        if alias.asset_id != asset.id:
            former_asset = self.session.get(AssetRow, alias.asset_id)
            if kind != "mac" and _assets_have_distinct_macs(asset, former_asset):
                # IPs and hostnames can be reassigned. Their old association is
                # retained by immutable observations; the live alias follows
                # the presently observed strong MAC identity.
                alias.asset_id = asset.id
                alias.first_seen_at = observed_at
            else:
                asset = self._merge_assets(asset, former_asset)
                alias.asset_id = asset.id
        alias.value_display = display
        alias.last_seen_at = max(_as_aware(alias.last_seen_at), observed_at)

    def _merge_assets(self, canonical: AssetRow, duplicate: AssetRow | None) -> AssetRow:
        """Merge an identity split without discarding immutable scan observations."""

        if duplicate is None or duplicate.id == canonical.id:
            return canonical
        if _assets_have_distinct_macs(canonical, duplicate):
            return canonical
        canonical_is_protected = self._asset_has_persisted_analysis(canonical)
        duplicate_is_protected = self._asset_has_persisted_analysis(duplicate)
        if canonical_is_protected and duplicate_is_protected:
            # Two evidence-bearing identities require an analyst-visible merge.
            # Keeping both is safer than producing duplicate stable-key chains
            # or orphaning architecture risk contexts.
            return canonical
        if duplicate_is_protected:
            # Prefer the identity already referenced by findings or manual
            # architecture so automatic enrichment never changes its UUID.
            canonical, duplicate = duplicate, canonical

        services = list(
            self.session.scalars(select(ServiceRow).where(ServiceRow.asset_id == duplicate.id))
        )
        for service in services:
            existing = self.session.scalar(
                select(ServiceRow).where(
                    ServiceRow.asset_id == canonical.id,
                    ServiceRow.scan_job_id == service.scan_job_id,
                    ServiceRow.protocol == service.protocol,
                    ServiceRow.port == service.port,
                )
            )
            if existing is None:
                service.asset_id = canonical.id
                continue
            self.session.execute(
                update(VulnerabilityObservationRow)
                .where(VulnerabilityObservationRow.matched_service_id == service.id)
                .values(matched_service_id=existing.id)
            )
            self.session.execute(
                update(FindingRow)
                .where(FindingRow.service_id == service.id)
                .values(service_id=existing.id)
            )
            self.session.delete(service)
        self.session.execute(
            update(VulnerabilityObservationRow)
            .where(VulnerabilityObservationRow.matched_asset_id == duplicate.id)
            .values(matched_asset_id=canonical.id)
        )
        self.session.execute(
            update(FindingRow)
            .where(FindingRow.asset_id == duplicate.id)
            .values(asset_id=canonical.id)
        )
        self.session.execute(
            update(AssetObservationRow)
            .where(AssetObservationRow.asset_id == duplicate.id)
            .values(asset_id=canonical.id)
        )
        aliases = list(
            self.session.scalars(
                select(AssetAliasRow).where(AssetAliasRow.asset_id == duplicate.id)
            )
        )
        for alias in aliases:
            conflict = self.session.scalar(
                select(AssetAliasRow).where(
                    AssetAliasRow.system_id == alias.system_id,
                    AssetAliasRow.kind == alias.kind,
                    AssetAliasRow.value_normalized == alias.value_normalized,
                    AssetAliasRow.id != alias.id,
                )
            )
            if conflict is None:
                alias.asset_id = canonical.id
            else:
                conflict.first_seen_at = min(
                    _as_aware(conflict.first_seen_at), _as_aware(alias.first_seen_at)
                )
                conflict.last_seen_at = max(
                    _as_aware(conflict.last_seen_at), _as_aware(alias.last_seen_at)
                )
                self.session.delete(alias)
        canonical.first_seen_at = min(
            _as_aware(canonical.first_seen_at), _as_aware(duplicate.first_seen_at)
        )
        canonical.last_seen_at = max(
            _as_aware(canonical.last_seen_at), _as_aware(duplicate.last_seen_at)
        )
        canonical.observation_count += duplicate.observation_count
        if canonical.hostname is None:
            canonical.hostname = duplicate.hostname
        if canonical.mac_address is None:
            canonical.mac_address = duplicate.mac_address
        self.session.delete(duplicate)
        self.session.flush()
        return canonical

    def _asset_has_persisted_analysis(self, asset: AssetRow) -> bool:
        if self.session.scalar(
            select(FindingRow.id).where(FindingRow.asset_id == asset.id).limit(1)
        ) is not None:
            return True
        architectures = self.session.scalars(
            select(ArchitectureSnapshotRow).where(
                ArchitectureSnapshotRow.system_id == asset.system_id,
                ArchitectureSnapshotRow.layer == "manual",
            )
        )
        asset_id = str(asset.id)
        return any(
            isinstance(context, dict) and context.get("asset_id") == asset_id
            for architecture in architectures
            for context in architecture.graph.get("risk_contexts", [])
        )

    def add_service(
        self,
        *,
        asset_id: UUID,
        scan_id: UUID,
        port: int,
        protocol: str,
        state: str,
        service_name: str | None,
        product: str | None,
        version: str | None,
        cpes: list[str],
        confidence: float,
    ) -> ServiceRow:
        row = ServiceRow(
            asset_id=asset_id,
            scan_job_id=scan_id,
            port=port,
            protocol=protocol,
            state=state,
            service_name=service_name,
            product=product,
            version=version,
            cpes=cpes,
            confidence=confidence,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def complete_scan(
        self,
        scan: ScanJobRow,
        *,
        raw_evidence: str | None,
        raw_sha256: str,
        result_summary: dict[str, Any],
        actor: str,
        lease_token: str | None = None,
    ) -> ArchitectureSnapshotRow | None:
        now = datetime.now(UTC)
        terminal_values = {
            "raw_evidence": raw_evidence,
            "raw_evidence_sha256": raw_sha256,
            "result_summary": result_summary,
            "status": "completed",
            "completed_at": now,
            "heartbeat_at": now,
            "claimed_by": None,
            "lease_token": None,
            "lease_expires_at": None,
            "error_code": None,
            "error_message": None,
        }
        if lease_token is None:
            for field, value in terminal_values.items():
                setattr(scan, field, value)
        else:
            completed = self.session.execute(
                update(ScanJobRow)
                .where(
                    ScanJobRow.id == scan.id,
                    ScanJobRow.status == "running",
                    ScanJobRow.lease_token == lease_token,
                    ScanJobRow.cancel_requested_at.is_(None),
                )
                .values(**terminal_values)
                .execution_options(synchronize_session=False)
            )
            if completed.rowcount != 1:
                raise OperationalConflictError(
                    "Scan lease ownership changed before scanner evidence was committed"
                )
        snapshot = None
        correlation_job_id: str | None = None
        if scan.is_current_inventory:
            snapshot = self.create_architecture_snapshot(scan.system_id, scan.id)
            self.recorrelate_vulnerability_observations(scan.system_id, actor=actor)
            self.recorrelate_threats_for_inventory(scan.system_id, actor=actor)
            correlation_job_id = self._enqueue_inventory_correlation(scan, actor)
        self.audit(
            actor,
            "scan.completed",
            "scan",
            scan.id,
            {
                "evidence_sha256": raw_sha256,
                "correlation_job_id": correlation_job_id,
                **result_summary,
            },
        )
        return snapshot

    def _enqueue_inventory_correlation(
        self, scan: ScanJobRow, actor: str
    ) -> str | None:
        if self.organization_id is None:
            return None
        # Local import avoids a module cycle: background_jobs itself uses this
        # repository as its tenant-scoped authorization boundary.
        from traceless_api.services.background_jobs import BackgroundJobService

        service = BackgroundJobService(
            self.session,
            organization_id=self.organization_id,
            organization_key=self.organization_key or str(self.organization_id),
            organization_name=self.organization_name or str(self.organization_id),
            allowed_project_ids=self.allowed_project_ids,
            allowed_system_ids=self.allowed_system_ids,
        )
        manifest = scan.raw_evidence_sha256 or hashlib.sha256(
            f"inventory:{scan.id}".encode()
        ).hexdigest()
        row, _ = service.enqueue(
            system_id=scan.system_id,
            job_type="intelligence_correlation",
            payload={
                "trigger_type": "inventory_generation",
                "trigger_id": str(scan.id),
                "manifest_sha256": manifest,
            },
            actor=actor,
            max_attempts=3,
            idempotency_key=f"inventory_generation:{scan.id}:{manifest}",
        )
        return str(row.id)

    def fail_scan(self, scan: ScanJobRow, code: str, message: str, actor: str) -> None:
        now = datetime.now(UTC)
        scan.status = "failed"
        scan.error_code = code
        scan.error_message = message[:4_000]
        scan.completed_at = now
        scan.heartbeat_at = now
        scan.claimed_by = None
        scan.lease_token = None
        scan.lease_expires_at = None
        self.audit(actor, "scan.failed", "scan", scan.id, {"code": code})

    def request_scan_cancellation(self, scan_id: UUID, actor: str) -> ScanJobRow:
        scan = self.get_scan_job(scan_id)
        if scan.status in {"completed", "failed", "cancelled"}:
            return scan
        now = datetime.now(UTC)
        scan.cancel_requested_at = now
        # Revoking the per-attempt lease is an immediate terminal fence. The
        # live worker monitor observes ownership loss, terminates Nmap and is
        # unable to ingest any output from the cancelled attempt.
        scan.status = "cancelled"
        scan.completed_at = now
        scan.heartbeat_at = now
        scan.claimed_by = None
        scan.lease_token = None
        scan.lease_expires_at = None
        self.audit(actor, "scan.cancel_requested", "scan", scan.id)
        self.session.flush()
        return scan

    def create_architecture_snapshot(
        self, system_id: UUID, scan_id: UUID
    ) -> ArchitectureSnapshotRow:
        self._lock_system(system_id)
        current_version = self.session.scalar(
            select(func.max(ArchitectureSnapshotRow.version)).where(
                ArchitectureSnapshotRow.system_id == system_id
            )
        )
        assets = list(
            self.session.scalars(
                select(AssetRow)
                .where(
                    AssetRow.system_id == system_id,
                    AssetRow.source_scan_id == scan_id,
                )
                .order_by(AssetRow.primary_ip)
            )
        )
        asset_ids = [item.id for item in assets]
        services = (
            list(
                self.session.scalars(
                    select(ServiceRow)
                    .where(
                        ServiceRow.asset_id.in_(asset_ids),
                        ServiceRow.scan_job_id == scan_id,
                        func.lower(ServiceRow.state) == "open",
                    )
                    .order_by(ServiceRow.port)
                )
            )
            if asset_ids
            else []
        )
        graph = _build_architecture_graph(assets, services, scan_id)
        previous_observed = self.latest_observed_topology(system_id)
        if previous_observed is not None and previous_observed.status == "draft":
            previous_observed.status = "superseded"
        row = ArchitectureSnapshotRow(
            system_id=system_id,
            source_scan_id=scan_id,
            version=(current_version or 0) + 1,
            status="draft",
            source_type="scan",
            layer="observed",
            title="Skanningshärlett arkitekturutkast",
            change_note="Automatiskt utkast från observerade assets och tjänster.",
            created_by="scanner-pipeline",
            graph=graph,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def latest_architecture(self, system_id: UUID) -> ArchitectureSnapshotRow | None:
        self.get_system(system_id)
        manual = self.session.scalar(
            select(ArchitectureSnapshotRow)
            .where(
                ArchitectureSnapshotRow.system_id == system_id,
                ArchitectureSnapshotRow.layer == "manual",
            )
            .order_by(ArchitectureSnapshotRow.version.desc())
            .limit(1)
        )
        return manual or self.latest_observed_topology(system_id)

    def latest_observed_topology(self, system_id: UUID) -> ArchitectureSnapshotRow | None:
        self.get_system(system_id)
        return self.session.scalar(
            select(ArchitectureSnapshotRow)
            .where(
                ArchitectureSnapshotRow.system_id == system_id,
                ArchitectureSnapshotRow.layer == "observed",
            )
            .order_by(ArchitectureSnapshotRow.version.desc())
            .limit(1)
        )

    def list_architecture_versions(self, system_id: UUID) -> list[ArchitectureSnapshotRow]:
        self.get_system(system_id)
        return list(
            self.session.scalars(
                select(ArchitectureSnapshotRow)
                .where(ArchitectureSnapshotRow.system_id == system_id)
                .order_by(ArchitectureSnapshotRow.version.desc())
            )
        )

    def create_manual_architecture_version(
        self,
        system_id: UUID,
        payload: ArchitectureVersionCreate,
        actor: str,
    ) -> ArchitectureSnapshotRow:
        system = self._lock_system(system_id)
        latest_manual = self.session.scalar(
            select(ArchitectureSnapshotRow)
            .where(
                ArchitectureSnapshotRow.system_id == system_id,
                ArchitectureSnapshotRow.layer == "manual",
            )
            .order_by(ArchitectureSnapshotRow.version.desc())
            .limit(1)
        )
        latest_any = self.latest_architecture(system_id)
        base: ArchitectureSnapshotRow | None = None
        if payload.base_snapshot_id is not None:
            base = self.session.scalar(
                select(ArchitectureSnapshotRow).where(
                    ArchitectureSnapshotRow.id == payload.base_snapshot_id,
                    ArchitectureSnapshotRow.system_id == system_id,
                )
            )
            if base is None:
                raise OperationalConflictError(
                    "The selected architecture base version does not belong to this system"
                )
            if latest_manual is not None and base.id != latest_manual.id:
                raise OperationalConflictError(
                    "A newer architecture version exists; reload it before saving"
                )
            if latest_manual is None and base.layer != "observed":
                raise OperationalConflictError(
                    "The first manual architecture must be based on an observed version"
                )
        elif latest_any is not None:
            raise OperationalConflictError(
                "base_snapshot_id is required when the system already has architecture versions"
            )

        context_asset_ids = {context.asset_id for context in payload.graph.risk_contexts}
        context_assets = {
            asset.id: asset
            for asset in self.session.scalars(
                select(AssetRow).where(
                    AssetRow.system_id == system_id,
                    AssetRow.id.in_(context_asset_ids),
                )
            )
        }
        if len(context_assets) != len(context_asset_ids):
            raise OperationalConflictError(
                "Architecture risk context references an asset outside this system"
            )
        context_endpoints: dict[tuple[UUID, UUID], tuple[int, str]] = {}
        for context in payload.graph.risk_contexts:
            if context.service_id is None:
                continue
            service = self.session.scalar(
                select(ServiceRow).where(
                    ServiceRow.id == context.service_id,
                    ServiceRow.asset_id == context.asset_id,
                )
            )
            if service is None:
                raise OperationalConflictError(
                    "Architecture risk context service does not belong to its asset"
                )
            context_endpoints[(context.asset_id, context.service_id)] = (
                service.port,
                service.protocol.casefold(),
            )

        recorded_at = datetime.now(UTC)
        graph = payload.graph.model_dump(mode="json")
        stamped_contexts: list[dict[str, Any]] = []
        for context in graph["risk_contexts"]:
            stamped = {
                **context,
                "verified_by": actor,
                "verified_at": recorded_at.isoformat(),
            }
            service_id = context.get("service_id")
            if service_id is not None:
                endpoint = context_endpoints[(UUID(context["asset_id"]), UUID(service_id))]
                stamped["endpoint_port"] = endpoint[0]
                stamped["endpoint_protocol"] = endpoint[1]
            stamped_contexts.append(stamped)
        graph["risk_contexts"] = stamped_contexts
        normalized_graph = json.dumps(
            graph,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(normalized_graph) > 1_000_000:
            raise OperationalConflictError(
                "Architecture graph exceeds the 1 MB normalized limit after provenance stamping"
            )

        if latest_manual is not None and latest_manual.status == "draft":
            latest_manual.status = "superseded"
        current_version = self.session.scalar(
            select(func.max(ArchitectureSnapshotRow.version)).where(
                ArchitectureSnapshotRow.system_id == system_id
            )
        )
        row = ArchitectureSnapshotRow(
            system_id=system_id,
            source_scan_id=base.source_scan_id if base is not None else None,
            base_snapshot_id=base.id if base is not None else None,
            version=(current_version or 0) + 1,
            status="draft",
            source_type="manual",
            layer="manual",
            title=payload.title,
            change_note=payload.change_note,
            created_by=actor,
            graph=graph,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(
            actor,
            "architecture.version_created",
            "architecture_snapshot",
            row.id,
            {
                "system_id": str(system_id),
                "version": row.version,
                "base_snapshot_id": str(base.id) if base is not None else None,
                "nodes": len(payload.graph.nodes),
                "edges": len(payload.graph.edges),
                "risk_contexts": len(payload.graph.risk_contexts),
            },
        )
        if context_asset_ids:
            findings = list(
                self.session.scalars(
                    select(FindingRow).where(
                        FindingRow.system_id == system_id,
                        FindingRow.asset_id.in_(context_asset_ids),
                    )
                )
            )
            for finding in findings:
                self._reassess_finding(system, finding)
        return row

    def list_assets(self, system_id: UUID) -> list[AssetRow]:
        scan = self.latest_completed_scan(system_id)
        if scan is None:
            return []
        return self.list_assets_for_scan(system_id, scan.id)

    def list_assets_for_scan(self, system_id: UUID, scan_id: UUID) -> list[AssetRow]:
        """Return the inventory frozen to one explicitly selected scan."""

        self.get_system(system_id)
        return list(
            self.session.scalars(
                select(AssetRow)
                .join(
                    AssetObservationRow,
                    AssetObservationRow.asset_id == AssetRow.id,
                )
                .where(
                    AssetRow.system_id == system_id,
                    AssetObservationRow.scan_job_id == scan_id,
                )
                .distinct()
                .order_by(AssetRow.primary_ip)
            )
        )

    def list_all_assets(self, system_id: UUID) -> list[AssetRow]:
        """Return persistent inventory identities, including assets absent from the latest scan."""

        self.get_system(system_id)
        return list(
            self.session.scalars(
                select(AssetRow)
                .where(AssetRow.system_id == system_id)
                .order_by(AssetRow.last_seen_at.desc())
            )
        )

    def list_services(self, system_id: UUID) -> list[ServiceRow]:
        scan = self.latest_completed_scan(system_id)
        if scan is None:
            return []
        return self.list_services_for_scan(system_id, scan.id)

    def list_services_for_scan(self, system_id: UUID, scan_id: UUID) -> list[ServiceRow]:
        """Return services frozen to the same scan as a report inventory."""

        self.get_system(system_id)
        return list(
            self.session.scalars(
                select(ServiceRow)
                .join(AssetRow, ServiceRow.asset_id == AssetRow.id)
                .where(
                    AssetRow.system_id == system_id,
                    ServiceRow.scan_job_id == scan_id,
                    func.lower(ServiceRow.state) == "open",
                )
                .order_by(ServiceRow.port)
            )
        )

    def latest_scan(self, system_id: UUID) -> ScanJobRow | None:
        self.get_system(system_id)
        return self.session.scalar(
            select(ScanJobRow)
            .where(ScanJobRow.system_id == system_id)
            .order_by(ScanJobRow.requested_at.desc())
            .limit(1)
        )

    def latest_completed_scan(self, system_id: UUID) -> ScanJobRow | None:
        return self.current_inventory_scan(system_id)

    def current_inventory_scan(self, system_id: UUID) -> ScanJobRow | None:
        self.get_system(system_id)
        return self.session.scalar(
            select(ScanJobRow)
            .where(
                ScanJobRow.system_id == system_id,
                ScanJobRow.status == "completed",
                ScanJobRow.is_current_inventory.is_(True),
            )
            .order_by(
                ScanJobRow.source_observed_at.desc(),
                ScanJobRow.completed_at.desc(),
            )
            .limit(1)
        )

    def import_vulnerability_scan(
        self,
        system_id: UUID,
        payload: VulnerabilityScanImportCreate,
        actor: str,
        *,
        raw_sha256: str,
        source_format: str,
    ) -> tuple[VulnerabilityScanImportRow, bool, int, int, int, list[str]]:
        system = self._lock_system(system_id)
        existing_import = self.session.scalar(
            select(VulnerabilityScanImportRow).where(
                VulnerabilityScanImportRow.system_id == system_id,
                VulnerabilityScanImportRow.raw_sha256 == raw_sha256,
            )
        )
        if existing_import is not None:
            existing_observations = list(
                self.session.scalars(
                    select(VulnerabilityObservationRow).where(
                        VulnerabilityObservationRow.import_id == existing_import.id
                    )
                )
            )
            return (
                existing_import,
                True,
                sum(item.matched_asset_id is not None for item in existing_observations),
                sum(item.matched_service_id is not None for item in existing_observations),
                existing_import.promoted_finding_count,
                ["Samma rapport har redan importerats; befintligt underlag returnerades."],
            )

        assets, asset_by_ip, hostname_candidates, service_by_endpoint = (
            self._current_inventory_index(system_id)
        )

        row = VulnerabilityScanImportRow(
            system_id=system_id,
            provider=payload.provider,
            source_format=source_format,
            source_name=payload.source_name,
            scanner_version=payload.scanner_version,
            scan_started_at=payload.scan_started_at,
            scan_completed_at=payload.scan_completed_at,
            imported_by=actor,
            raw_sha256=raw_sha256,
            report_metadata=payload.report_metadata,
            observation_count=len(payload.observations),
            asset_count=len({item.asset_identifier.casefold() for item in payload.observations}),
        )
        self.session.add(row)
        self.session.flush()

        matched_asset_ids: set[UUID] = set()
        matched_service_observations = 0
        promoted_finding_ids: set[UUID] = set()
        seen_observation_keys: set[str] = set()
        duplicate_observations = 0
        for item in payload.observations:
            asset, service, match_confidence = self._match_vulnerability_record(
                item,
                asset_by_ip=asset_by_ip,
                hostname_candidates=hostname_candidates,
                service_by_endpoint=service_by_endpoint,
            )
            if asset is not None:
                matched_asset_ids.add(asset.id)
            if service is not None:
                matched_service_observations += 1

            observation_key = hashlib.sha256(
                json.dumps(
                    [
                        item.provider_finding_id,
                        item.asset_identifier.casefold(),
                        item.port,
                        item.protocol.casefold() if item.protocol else None,
                        item.title,
                    ],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            if observation_key in seen_observation_keys:
                duplicate_observations += 1
                if service is not None:
                    matched_service_observations -= 1
                continue
            seen_observation_keys.add(observation_key)
            observation = VulnerabilityObservationRow(
                import_id=row.id,
                system_id=system_id,
                observation_key=observation_key,
                provider_finding_id=item.provider_finding_id,
                asset_identifier=item.asset_identifier,
                ip_address=item.ip_address,
                hostname=item.hostname,
                port=item.port,
                protocol=item.protocol,
                service_name=item.service_name,
                product=item.product,
                version=item.version,
                cpes=item.cpes,
                cve_ids=item.cve_ids,
                title=item.title,
                description=item.description,
                solution=item.solution,
                severity=item.severity,
                cvss_score=item.cvss_score,
                cvss_vector=item.cvss_vector,
                state=item.state,
                exploitable=item.exploitable,
                evidence=item.evidence,
                observed_at=item.observed_at,
                matched_asset_id=asset.id if asset is not None else None,
                matched_service_id=service.id if service is not None else None,
                match_confidence=match_confidence,
            )
            self.session.add(observation)
            self.session.flush()
            if asset is not None:
                for finding in self._promote_vulnerability_observation(
                    system=system,
                    imported=row,
                    observation=observation,
                    raw_sha256=raw_sha256,
                    count_occurrence=True,
                ):
                    promoted_finding_ids.add(finding.id)

        row.observation_count = len(seen_observation_keys)
        row.matched_asset_count = len(matched_asset_ids)
        row.promoted_finding_count = len(promoted_finding_ids)
        resolved_absent = 0
        if _is_complete_vulnerability_snapshot(row):
            resolved_absent = self._resolve_absent_scanner_evidence(
                system=system,
                imported=row,
            )
        self.session.flush()
        warnings = [
            "Importerade observationer är leverantörsevidens, inte automatiskt verifierade fynd."
        ]
        if not assets:
            warnings.append(
                "Ingen slutförd nätverksskanning finns; observationerna sparades "
                "utan assetkoppling."
            )
        unmatched = row.asset_count - row.matched_asset_count
        if unmatched > 0:
            warnings.append(
                f"{unmatched} leverantörsasset kunde inte entydigt matchas mot aktuell inventering."
            )
        if duplicate_observations:
            warnings.append(
                f"{duplicate_observations} identiska observationer deduplicerades inom rapporten."
            )
        if resolved_absent:
            warnings.append(
                f"{resolved_absent} leverantörsevidens markerades som åtgärdade eftersom "
                "de saknades i den kompletta rapporten."
            )
        self.audit(
            actor,
            "vulnerability_scan.imported",
            "vulnerability_scan_import",
            row.id,
            {
                "system_id": str(system_id),
                "provider": payload.provider,
                "observations": row.observation_count,
                "matched_assets": row.matched_asset_count,
                "matched_services": matched_service_observations,
                "promoted_findings": row.promoted_finding_count,
                "resolved_absent_evidence": resolved_absent,
                "raw_sha256": raw_sha256,
            },
        )
        return (
            row,
            False,
            len(matched_asset_ids),
            matched_service_observations,
            len(promoted_finding_ids),
            warnings,
        )

    def recorrelate_vulnerability_observations(self, system_id: UUID, actor: str) -> int:
        """Re-run saved vendor evidence whenever the active inventory changes."""

        system = self.get_system(system_id)
        current_scan = self.current_inventory_scan(system_id)
        if current_scan is None:
            return 0
        _, asset_by_ip, hostname_candidates, service_by_endpoint = self._current_inventory_index(
            system_id
        )
        imported_rows = list(
            self.session.scalars(
                select(VulnerabilityScanImportRow)
                .where(VulnerabilityScanImportRow.system_id == system_id)
                .order_by(
                    VulnerabilityScanImportRow.imported_at,
                    VulnerabilityScanImportRow.id,
                )
            )
        )
        imports = {row.id: row for row in imported_rows}
        rows = list(
            self.session.scalars(
                select(VulnerabilityObservationRow)
                .where(VulnerabilityObservationRow.system_id == system_id)
                .order_by(VulnerabilityObservationRow.created_at)
            )
        )
        promoted_ids: set[UUID] = set()
        matched_by_import: dict[UUID, set[UUID]] = {}
        promoted_by_import: dict[UUID, set[UUID]] = {}
        observations_by_import: dict[UUID, list[VulnerabilityObservationRow]] = {}
        for observation in rows:
            observations_by_import.setdefault(observation.import_id, []).append(observation)
        for imported in imported_rows:
            for observation in observations_by_import.get(imported.id, []):
                previously_matched_asset_id = observation.matched_asset_id
                asset, service, confidence = self._match_vulnerability_record(
                    observation,
                    asset_by_ip=asset_by_ip,
                    hostname_candidates=hostname_candidates,
                    service_by_endpoint=service_by_endpoint,
                )
                observation.matched_asset_id = asset.id if asset is not None else None
                observation.matched_service_id = service.id if service is not None else None
                observation.match_confidence = confidence
                target_is_covered = asset is not None or self._observation_target_is_in_scope(
                    observation,
                    current_scan,
                    previously_matched_asset_id=previously_matched_asset_id,
                )
                if (
                    observation.cve_ids
                    and (asset is None or service is None)
                    and target_is_covered
                ):
                    self._resolve_uncorrelated_cve_evidence(
                        system=system,
                        observation=observation,
                    )
                if asset is None:
                    continue
                matched_by_import.setdefault(observation.import_id, set()).add(asset.id)
                for finding in self._promote_vulnerability_observation(
                    system=system,
                    imported=imported,
                    observation=observation,
                    raw_sha256=imported.raw_sha256,
                    count_occurrence=False,
                ):
                    promoted_ids.add(finding.id)
                    promoted_by_import.setdefault(observation.import_id, set()).add(finding.id)
            if _is_complete_vulnerability_snapshot(imported):
                self._resolve_absent_scanner_evidence(
                    system=system,
                    imported=imported,
                )
        for import_id, imported in imports.items():
            imported.matched_asset_count = len(matched_by_import.get(import_id, set()))
            imported.promoted_finding_count = len(promoted_by_import.get(import_id, set()))
        if rows:
            self.audit(
                actor,
                "vulnerability_observations.recorrelated",
                "system",
                system_id,
                {"observations": len(rows), "findings": len(promoted_ids)},
            )
        self.session.flush()
        return len(promoted_ids)

    def _observation_target_is_in_scope(
        self,
        observation: VulnerabilityObservationRow,
        scan: ScanJobRow,
        *,
        previously_matched_asset_id: UUID | None,
    ) -> bool:
        """Return true only when the new inventory actually covered the target."""

        if observation.ip_address:
            return _address_in_scope(observation.ip_address, scan.scope_targets)
        if previously_matched_asset_id is None:
            return False
        previous_asset = self.session.get(AssetRow, previously_matched_asset_id)
        return bool(
            previous_asset is not None
            and _address_in_scope(previous_asset.primary_ip, scan.scope_targets)
        )

    def _current_inventory_index(
        self, system_id: UUID
    ) -> tuple[
        list[AssetRow],
        dict[str, AssetRow],
        dict[str, list[AssetRow]],
        dict[tuple[UUID, int, str], ServiceRow],
    ]:
        assets = self.list_assets(system_id)
        services = self.list_services(system_id)
        assets_by_id = {asset.id: asset for asset in assets}
        current_scan = self.current_inventory_scan(system_id)
        current_observations = (
            list(
                self.session.scalars(
                    select(AssetObservationRow).where(
                        AssetObservationRow.scan_job_id == current_scan.id,
                        AssetObservationRow.asset_id.in_(assets_by_id),
                    )
                )
            )
            if current_scan is not None and assets_by_id
            else []
        )
        asset_by_ip: dict[str, AssetRow] = {}
        hostname_candidates: dict[str, list[AssetRow]] = {}
        for observation in current_observations:
            asset = assets_by_id.get(observation.asset_id)
            if asset is None:
                continue
            asset_by_ip[observation.primary_ip] = asset
            if observation.hostname:
                hostname_candidates.setdefault(
                    observation.hostname.rstrip(".").casefold(), []
                ).append(asset)
        service_by_endpoint = {
            (service.asset_id, service.port, service.protocol.casefold()): service
            for service in services
        }
        return assets, asset_by_ip, hostname_candidates, service_by_endpoint

    @staticmethod
    def _match_vulnerability_record(
        record: Any,
        *,
        asset_by_ip: dict[str, AssetRow],
        hostname_candidates: dict[str, list[AssetRow]],
        service_by_endpoint: dict[tuple[UUID, int, str], ServiceRow],
    ) -> tuple[AssetRow | None, ServiceRow | None, float | None]:
        asset = asset_by_ip.get(record.ip_address or "")
        confidence: float | None = 0.97 if asset is not None else None
        if asset is None and record.hostname:
            candidates = hostname_candidates.get(record.hostname.rstrip(".").casefold(), [])
            if len(candidates) == 1:
                asset = candidates[0]
                confidence = 0.90
        service = None
        if asset is not None and record.port is not None and record.protocol is not None:
            service = service_by_endpoint.get((asset.id, record.port, record.protocol.casefold()))
            if service is not None:
                confidence = min(0.99, (confidence or 0) + 0.02)
        return asset, service, confidence

    def _promote_vulnerability_observation(
        self,
        *,
        system: SystemRow,
        imported: VulnerabilityScanImportRow,
        observation: VulnerabilityObservationRow,
        raw_sha256: str,
        count_occurrence: bool,
    ) -> list[FindingRow]:
        asset = (
            self.session.get(AssetRow, observation.matched_asset_id)
            if observation.matched_asset_id is not None
            else None
        )
        if asset is None:
            return []
        service = (
            self.session.get(ServiceRow, observation.matched_service_id)
            if observation.matched_service_id is not None
            else None
        )
        scan = self.latest_completed_scan(system.id)
        snapshot_series_id = _vulnerability_snapshot_series_key(imported)
        cve_ids: list[str | None] = list(observation.cve_ids) or [None]
        findings: list[FindingRow] = []
        for cve_id in cve_ids:
            # A CVE is endpoint-specific evidence. Matching only the host is not
            # enough to assert that the vulnerable service is present now.
            if cve_id is not None and service is None:
                continue
            if cve_id is not None:
                stable_key = _cve_asset_endpoint_stable_key(
                    asset.id,
                    observation.port or (service.port if service is not None else 0),
                    observation.protocol or (service.protocol if service is not None else "host"),
                    cve_id,
                )
            else:
                identity = "|".join(
                    [
                        "scanner",
                        f"{imported.provider.casefold()}:{observation.provider_finding_id.casefold()}",
                        str(asset.id),
                        str(observation.port or 0),
                        (observation.protocol or "host").casefold(),
                    ]
                )
                stable_key = hashlib.sha256(identity.encode("utf-8")).hexdigest()
            finding = self.session.scalar(
                select(FindingRow).where(
                    FindingRow.system_id == system.id,
                    FindingRow.stable_key == stable_key,
                )
            )
            reported_observed_at = _as_aware(
                observation.observed_at
                or imported.scan_completed_at
                or imported.imported_at
                or observation.created_at
            )
            ingested_at = _as_aware(imported.imported_at)
            observed_at, timestamp_quarantined = _effective_source_time(
                reported_observed_at,
                received_at=ingested_at,
            )
            lifecycle = _normalized_scanner_lifecycle(observation.state)
            initial_lifecycle = "open" if timestamp_quarantined else lifecycle
            confidence = observation.match_confidence or 0.80
            strength = 95 if service is not None else 85
            source_entry = {
                "provider": imported.provider,
                "import_id": str(imported.id),
                "observation_id": str(observation.id),
                "provider_finding_id": observation.provider_finding_id,
                "raw_sha256": raw_sha256,
                "reported_severity": observation.severity,
                "exploitable": observation.exploitable,
                "reported_observed_at": reported_observed_at.isoformat(),
                "effective_observed_at": observed_at.isoformat(),
                "ingested_at": ingested_at.isoformat(),
                "timestamp_quarantined": timestamp_quarantined,
                "snapshot_series_id": snapshot_series_id,
                "evidence_strength": strength,
                "presence_key": _vulnerability_presence_key(observation, cve_id),
                "primary_fields": {
                    "title": observation.title,
                    "verification_status": (
                        "likely" if confidence >= 0.90 else "candidate"
                    ),
                    "match_confidence": confidence,
                    "match_reason": (
                        "Third-party scanner evidence was correlated to the current asset"
                        + (
                            " and exact service endpoint."
                            if service is not None
                            else "; this is host-scoped non-CVE evidence."
                        )
                    ),
                    "cvss_score": observation.cvss_score,
                    "cvss_vector": observation.cvss_vector,
                },
            }
            created = finding is None
            if finding is None:
                revision_at = datetime.now(UTC)
                finding = FindingRow(
                    system_id=system.id,
                    scan_job_id=scan.id if scan is not None else None,
                    asset_id=asset.id,
                    service_id=service.id if service is not None else None,
                    stable_key=stable_key,
                    finding_type=(
                        "vulnerability"
                        if cve_id is not None
                        else (
                            "informational"
                            if observation.severity == "info"
                            else "misconfiguration"
                        )
                    ),
                    cve_id=cve_id,
                    title=observation.title,
                    status="likely" if confidence >= 0.90 else "candidate",
                    lifecycle_status=initial_lifecycle,
                    match_confidence=confidence,
                    match_reason=(
                        "Third-party scanner evidence was correlated to the current asset"
                        + (
                            " and exact service endpoint."
                            if service is not None
                            else "; no exact service endpoint was required for this host finding."
                        )
                    ),
                    cvss_score=observation.cvss_score,
                    cvss_vector=observation.cvss_vector,
                    is_kev=False,
                    sources=[],
                    primary_evidence_strength=strength,
                    first_seen_at=observed_at,
                    last_seen_at=observed_at,
                    status_updated_at=revision_at,
                    resolved_at=(
                        revision_at if initial_lifecycle not in {"open", "reopened"} else None
                    ),
                    occurrence_count=1,
                )
                self.session.add(finding)
                self.session.flush()
            else:
                finding.scan_job_id = scan.id if scan is not None else finding.scan_job_id
                finding.asset_id = asset.id
                finding.service_id = service.id if service is not None else None
                if not timestamp_quarantined:
                    finding.first_seen_at = min(_as_aware(finding.first_seen_at), observed_at)
                    finding.last_seen_at = max(_as_aware(finding.last_seen_at), observed_at)
                if count_occurrence:
                    finding.occurrence_count += 1
            _, metadata_is_current = self._upsert_finding_evidence(
                finding=finding,
                observation=observation,
                imported=imported,
                lifecycle=lifecycle,
                strength=strength,
                observed_at=observed_at,
                payload=source_entry,
                count_occurrence=count_occurrence,
            )
            if (created or metadata_is_current) and (
                not timestamp_quarantined or not finding.sources
            ):
                if self._apply_primary_finding_evidence(
                    finding,
                    title=observation.title,
                    verification_status=("likely" if confidence >= 0.90 else "candidate"),
                    confidence=confidence,
                    reason=(
                        "Third-party scanner evidence was correlated to the current asset"
                        + (
                            " and exact service endpoint."
                            if service is not None
                            else "; this is host-scoped non-CVE evidence."
                        )
                    ),
                    cvss_score=observation.cvss_score,
                    cvss_vector=observation.cvss_vector,
                    strength=strength,
                    revision_at=observed_at,
                ):
                    finding.sources = _replace_scanner_source(
                        finding.sources,
                        provider=imported.provider,
                        provider_finding_id=observation.provider_finding_id,
                        replacement=source_entry,
                    )
            self.recompute_primary_finding_evidence(finding)
            self._recompute_finding_lifecycle(finding)
            self._reassess_finding(system, finding)
            findings.append(finding)
        return findings

    def _upsert_finding_evidence(
        self,
        *,
        finding: FindingRow,
        observation: VulnerabilityObservationRow,
        imported: VulnerabilityScanImportRow,
        lifecycle: str,
        strength: int,
        observed_at: datetime,
        payload: dict[str, Any],
        count_occurrence: bool,
    ) -> tuple[FindingEvidenceRow, bool]:
        evidence_key = "|".join(
            [
                imported.provider.casefold(),
                _vulnerability_snapshot_series_key(imported) or "default",
                observation.provider_finding_id.casefold(),
                finding.cve_id or "non-cve",
            ]
        )
        evidence = self.session.scalar(
            select(FindingEvidenceRow).where(
                FindingEvidenceRow.finding_id == finding.id,
                FindingEvidenceRow.evidence_key == evidence_key,
            )
        )
        evidence_payload = {**payload, "normalized_evidence": observation.evidence}
        incoming_quarantined = bool(payload.get("timestamp_quarantined"))
        existing_quarantined = bool(
            evidence is not None and evidence.payload.get("timestamp_quarantined")
        )
        metadata_is_current = not incoming_quarantined and (
            evidence is None
            or existing_quarantined
            or observed_at >= _evidence_representative_revision(evidence)
        )
        if evidence is None:
            evidence = FindingEvidenceRow(
                finding_id=finding.id,
                observation_id=observation.id,
                evidence_key=evidence_key,
                source_kind="scanner",
                source_name=imported.provider,
                external_id=observation.provider_finding_id,
                # A future-quarantined vendor clock is retained as an immutable
                # observation, but cannot close the source's representative state.
                lifecycle_status=lifecycle if metadata_is_current else "open",
                strength=strength,
                payload=evidence_payload,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                observation_count=1,
            )
            self.session.add(evidence)
        elif evidence.observation_id != observation.id:
            previous_observation_id = evidence.observation_id
            previous_payload = evidence.payload
            if metadata_is_current:
                evidence.observation_id = observation.id
                evidence.lifecycle_status = lifecycle
                evidence.strength = max(evidence.strength, strength)
                evidence.payload = evidence_payload
                prior_quarantined_revisions = list(
                    previous_payload.get("quarantined_revisions", [])
                )[-20:]
                prior_superseded_revisions = list(previous_payload.get("superseded_revisions", []))[
                    -20:
                ]
                if prior_quarantined_revisions:
                    evidence.payload = {
                        **evidence.payload,
                        "quarantined_revisions": prior_quarantined_revisions,
                    }
                if prior_superseded_revisions:
                    evidence.payload = {
                        **evidence.payload,
                        "superseded_revisions": prior_superseded_revisions,
                    }
                if existing_quarantined:
                    evidence.payload = {
                        **evidence.payload,
                        "quarantined_revisions": [
                            *list(previous_payload.get("quarantined_revisions", []))[-19:],
                            {
                                "observation_id": (
                                    str(previous_observation_id)
                                    if previous_observation_id is not None
                                    else None
                                ),
                                "reported_observed_at": previous_payload.get(
                                    "reported_observed_at"
                                ),
                                "ingested_at": previous_payload.get("ingested_at"),
                                "raw_sha256": previous_payload.get("raw_sha256"),
                                "reason": "implausible_future_timestamp",
                            },
                        ],
                    }
            else:
                history_key = (
                    "quarantined_revisions" if incoming_quarantined else "superseded_revisions"
                )
                historical_revisions = list(evidence.payload.get(history_key, []))[-19:]
                evidence.payload = {
                    **evidence.payload,
                    history_key: [
                        *historical_revisions,
                        {
                            "observation_id": str(observation.id),
                            "reported_observed_at": payload.get("reported_observed_at"),
                            "ingested_at": payload.get("ingested_at"),
                            "raw_sha256": payload.get("raw_sha256"),
                            "lifecycle_status": lifecycle,
                            "reason": (
                                "implausible_future_timestamp"
                                if incoming_quarantined
                                else "older_than_representative_evidence"
                            ),
                        },
                    ],
                }
            if not incoming_quarantined:
                evidence.first_seen_at = min(_as_aware(evidence.first_seen_at), observed_at)
                evidence.last_seen_at = max(_as_aware(evidence.last_seen_at), observed_at)
            if count_occurrence:
                evidence.observation_count += 1
            evidence.updated_at = datetime.now(UTC)
        elif "correlation_resolution" in evidence.payload:
            # Re-correlation can revisit the same immutable observation after
            # inventory changed. Only correlation-derived closure is reversible;
            # a later complete scanner snapshot remains authoritative.
            evidence.lifecycle_status = lifecycle
            evidence.payload = {
                key: value
                for key, value in evidence.payload.items()
                if key != "correlation_resolution"
            }
            evidence.updated_at = datetime.now(UTC)
        self.session.flush()
        return evidence, metadata_is_current

    def _upsert_intelligence_finding_evidence(
        self,
        *,
        finding: FindingRow,
        source_name: str,
        external_id: str,
        source_updated_at: datetime,
        strength: int,
        payload: dict[str, Any],
    ) -> FindingEvidenceRow:
        evidence_key = f"intelligence|{source_name.casefold()}|{external_id.casefold()}"
        evidence = self.session.scalar(
            select(FindingEvidenceRow).where(
                FindingEvidenceRow.finding_id == finding.id,
                FindingEvidenceRow.evidence_key == evidence_key,
            )
        )
        observed_at = _as_aware(source_updated_at)
        if evidence is None:
            evidence = FindingEvidenceRow(
                finding_id=finding.id,
                evidence_key=evidence_key,
                source_kind="intelligence",
                source_name=source_name[:120],
                external_id=external_id[:200],
                lifecycle_status="open",
                strength=strength,
                payload=payload,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
            )
            self.session.add(evidence)
        elif observed_at >= _as_aware(evidence.last_seen_at):
            evidence.last_seen_at = observed_at
            evidence.strength = max(evidence.strength, strength)
            evidence.payload = payload
            evidence.lifecycle_status = "open"
            evidence.observation_count += 1
        return evidence

    def _reactivate_finding_from_intelligence(
        self,
        finding: FindingRow,
        *,
        evidence: FindingEvidenceRow,
        source_updated_at: datetime,
    ) -> None:
        """Reopen only for active intelligence newer than a manual decision."""

        if (
            finding.lifecycle_status != "fixed"
            or evidence.lifecycle_status not in {"open", "reopened"}
        ):
            return
        latest_manual = self.session.scalar(
            select(FindingEvidenceRow)
            .where(
                FindingEvidenceRow.finding_id == finding.id,
                FindingEvidenceRow.source_kind == "manual",
            )
            .order_by(FindingEvidenceRow.last_seen_at.desc())
            .limit(1)
        )
        if latest_manual is not None and _as_aware(
            latest_manual.last_seen_at
        ) >= _as_aware(source_updated_at):
            return
        self._transition_finding_lifecycle(
            finding,
            "open",
            datetime.now(UTC),
            source_kind="intelligence",
        )

    @staticmethod
    def _apply_primary_finding_evidence(
        finding: FindingRow,
        *,
        title: str,
        verification_status: str,
        confidence: float,
        reason: str,
        cvss_score: float | None,
        cvss_vector: str | None,
        strength: int,
        revision_at: datetime | None = None,
    ) -> bool:
        current_revision = _primary_source_revision(
            finding.sources,
            evidence_strength=finding.primary_evidence_strength,
        )
        may_replace = strength > finding.primary_evidence_strength or (
            strength == finding.primary_evidence_strength
            and (
                revision_at is None
                or current_revision is None
                or _as_aware(revision_at) >= current_revision
            )
        )
        if may_replace:
            finding.title = title
            # Scanner/intelligence revisions may improve technical metadata,
            # but they cannot silently downgrade a persisted analyst review.
            if finding.status not in {"confirmed", "false_positive"}:
                finding.status = verification_status
            finding.match_confidence = confidence
            finding.match_reason = reason
            if cvss_score is not None:
                finding.cvss_score = cvss_score
                finding.cvss_vector = cvss_vector
            finding.primary_evidence_strength = strength
            return True
        elif finding.cvss_score is None and cvss_score is not None:
            finding.cvss_score = cvss_score
            finding.cvss_vector = cvss_vector
        return False

    @staticmethod
    def _transition_finding_lifecycle(
        finding: FindingRow,
        requested: str,
        observed_at: datetime,
        *,
        source_kind: str,
    ) -> None:
        protected = {"accepted", "false_positive", "out_of_scope"}
        if source_kind != "manual" and finding.lifecycle_status in protected:
            return
        target = requested
        if requested == "open" and finding.lifecycle_status == "fixed":
            target = "reopened"
        finding.lifecycle_status = target
        # observed_at is an internal revision time for all callers. Vendor
        # timestamps never participate in finding status ordering.
        finding.status_updated_at = observed_at
        finding.resolved_at = None if target in {"open", "reopened"} else observed_at

    def _recompute_finding_lifecycle(self, finding: FindingRow) -> None:
        """Aggregate independent scanner sources without letting one close another."""

        if finding.lifecycle_status in {"accepted", "false_positive", "out_of_scope"}:
            return
        evidence_rows = list(
            self.session.scalars(
                select(FindingEvidenceRow).where(
                    FindingEvidenceRow.finding_id == finding.id,
                )
            )
        )
        scanner_evidence = [item for item in evidence_rows if item.source_kind == "scanner"]
        if not scanner_evidence:
            return
        latest_manual_evidence = max(
            (item for item in evidence_rows if item.source_kind == "manual"),
            key=lambda item: _as_aware(item.last_seen_at),
            default=None,
        )
        if latest_manual_evidence is not None:
            manual_revision = _as_aware(latest_manual_evidence.last_seen_at)
            scanner_evidence = [
                item
                for item in scanner_evidence
                if _scanner_evidence_ingested_at(item) > manual_revision
                and _evidence_representative_revision(item) > manual_revision
            ]
            if not scanner_evidence:
                # Re-correlation of pre-decision observations is not a new scanner
                # decision. Preserve the latest authenticated analyst transition,
                # whether it closed or deliberately reopened the finding.
                return
        active = any(
            _normalized_scanner_lifecycle(item.lifecycle_status) in {"open", "reopened"}
            for item in scanner_evidence
        )
        if active:
            target = (
                "reopened"
                if finding.lifecycle_status == "fixed"
                else (
                    finding.lifecycle_status
                    if finding.lifecycle_status in {"open", "reopened"}
                    else "open"
                )
            )
        else:
            target = "fixed"
        if target == finding.lifecycle_status:
            return
        revision_at = datetime.now(UTC)
        finding.lifecycle_status = target
        finding.status_updated_at = revision_at
        finding.resolved_at = None if active else revision_at

    def _resolve_absent_scanner_evidence(
        self,
        *,
        system: SystemRow,
        imported: VulnerabilityScanImportRow,
    ) -> int:
        """Resolve source evidence absent from a complete scanner snapshot."""

        current_observations = list(
            self.session.scalars(
                select(VulnerabilityObservationRow).where(
                    VulnerabilityObservationRow.import_id == imported.id
                )
            )
        )
        current_observation_ids = {item.id for item in current_observations}
        current_presence_keys = {
            _vulnerability_presence_key(observation, cve_id)
            for observation in current_observations
            for cve_id in (list(observation.cve_ids) or [None])
        }
        snapshot_series_id = _vulnerability_snapshot_series_key(imported)
        if snapshot_series_id is None:
            return 0
        if imported.scan_completed_at is None:
            return 0
        snapshot_completed_at, completion_quarantined = _effective_source_time(
            _as_aware(imported.scan_completed_at),
            received_at=_as_aware(imported.imported_at),
        )
        if completion_quarantined:
            return 0
        evidence_rows = list(
            self.session.scalars(
                select(FindingEvidenceRow)
                .join(FindingRow, FindingEvidenceRow.finding_id == FindingRow.id)
                .where(
                    FindingRow.system_id == system.id,
                    FindingEvidenceRow.source_kind == "scanner",
                    func.lower(FindingEvidenceRow.source_name) == imported.provider.casefold(),
                )
            )
        )
        affected: dict[UUID, FindingRow] = {}
        resolved = 0
        revision_at = datetime.now(UTC)
        for evidence in evidence_rows:
            if evidence.payload.get("snapshot_series_id") != snapshot_series_id:
                continue
            if evidence.observation_id in current_observation_ids:
                continue
            presence_key = evidence.payload.get("presence_key")
            if isinstance(presence_key, str) and presence_key in current_presence_keys:
                # Presence is independent of whether the record could currently
                # be correlated. A still-reported finding must never be closed
                # merely because an asset alias or endpoint mapping changed.
                continue
            if evidence.payload.get("timestamp_quarantined") is True:
                continue
            if snapshot_completed_at <= _evidence_representative_revision(evidence):
                continue
            if evidence.lifecycle_status != "fixed":
                resolved += 1
            evidence.lifecycle_status = "fixed"
            evidence.updated_at = revision_at
            evidence.payload = {
                **evidence.payload,
                "snapshot_resolution": {
                    "reason": "absent_from_complete_snapshot",
                    "import_id": str(imported.id),
                    "raw_sha256": imported.raw_sha256,
                    "scan_completed_at": snapshot_completed_at.isoformat(),
                    "recorded_at": revision_at.isoformat(),
                },
            }
            finding = self.session.get(FindingRow, evidence.finding_id)
            if finding is not None:
                affected[finding.id] = finding
        self.session.flush()
        for finding in affected.values():
            self.recompute_primary_finding_evidence(finding)
            self._recompute_finding_lifecycle(finding)
            self._reassess_finding(system, finding)
        return resolved

    def _resolve_uncorrelated_cve_evidence(
        self,
        *,
        system: SystemRow,
        observation: VulnerabilityObservationRow,
    ) -> None:
        """Annotate CVE evidence when its endpoint leaves current inventory.

        Inventory absence is not a scanner remediation statement. The finding
        remains open with stale/unobserved evidence until a comparable complete
        vendor snapshot explicitly omits it or reports a fixed state.
        """

        evidence_rows = list(
            self.session.scalars(
                select(FindingEvidenceRow).where(
                    FindingEvidenceRow.observation_id == observation.id,
                    FindingEvidenceRow.source_kind == "scanner",
                )
            )
        )
        if not evidence_rows:
            return
        revision_at = datetime.now(UTC)
        affected: dict[UUID, FindingRow] = {}
        for evidence in evidence_rows:
            evidence.updated_at = revision_at
            evidence.payload = {
                **evidence.payload,
                "correlation_resolution": {
                    "reason": "exact_endpoint_absent_from_current_inventory",
                    "observation_id": str(observation.id),
                    "recorded_at": revision_at.isoformat(),
                },
            }
            finding = self.session.get(FindingRow, evidence.finding_id)
            if finding is not None:
                affected[finding.id] = finding
        self.session.flush()
        for finding in affected.values():
            self._reassess_finding(system, finding)

    def list_vulnerability_scan_imports(self, system_id: UUID) -> list[VulnerabilityScanImportRow]:
        self.get_system(system_id)
        return list(
            self.session.scalars(
                select(VulnerabilityScanImportRow)
                .where(VulnerabilityScanImportRow.system_id == system_id)
                .order_by(VulnerabilityScanImportRow.imported_at.desc())
            )
        )

    def list_vulnerability_observations(
        self,
        system_id: UUID,
        *,
        import_id: UUID | None = None,
        limit: int = 500,
    ) -> list[VulnerabilityObservationRow]:
        self.get_system(system_id)
        statement = select(VulnerabilityObservationRow).where(
            VulnerabilityObservationRow.system_id == system_id
        )
        if import_id is not None:
            imported = self.session.scalar(
                select(VulnerabilityScanImportRow).where(
                    VulnerabilityScanImportRow.id == import_id,
                    VulnerabilityScanImportRow.system_id == system_id,
                )
            )
            if imported is None:
                raise OperationalNotFoundError("Vulnerability scan import was not found")
            statement = statement.where(VulnerabilityObservationRow.import_id == import_id)
        return list(
            self.session.scalars(
                statement.order_by(
                    VulnerabilityObservationRow.created_at.desc(),
                    VulnerabilityObservationRow.severity.desc(),
                ).limit(limit)
            )
        )

    def save_asset_source_snapshot(
        self,
        *,
        system_id: UUID,
        snapshot: AssetSourceSnapshot[NetBoxAssetRecord],
        actor: str,
    ) -> AssetSourceSnapshotRow:
        """Persist source evidence without promoting it into the architecture graph."""

        self.get_system(system_id)
        existing = self.session.scalar(
            select(AssetSourceSnapshotRow).where(
                AssetSourceSnapshotRow.system_id == system_id,
                AssetSourceSnapshotRow.provider == snapshot.provider,
                AssetSourceSnapshotRow.manifest_sha256 == snapshot.manifest_sha256,
            )
        )
        if existing is not None:
            self.audit(
                actor,
                "asset_source.snapshot_reused",
                "asset_source_snapshot",
                existing.id,
                {"provider": snapshot.provider},
            )
            return existing

        serialized = snapshot.model_dump(mode="json")
        record_counts: dict[str, int] = {}
        for record in snapshot.records:
            kind = record.kind.value
            record_counts[kind] = record_counts.get(kind, 0) + 1
        row = AssetSourceSnapshotRow(
            system_id=system_id,
            provider=snapshot.provider,
            source_base_url=str(snapshot.source_base_url),
            approval_state=snapshot.approval_state,
            manifest_sha256=snapshot.manifest_sha256,
            record_count=len(snapshot.records),
            page_count=len(snapshot.pages),
            record_counts=record_counts,
            snapshot=serialized,
            started_at=snapshot.started_at,
            completed_at=snapshot.completed_at,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(
            actor,
            "asset_source.snapshot_created",
            "asset_source_snapshot",
            row.id,
            {
                "provider": snapshot.provider,
                "manifest_sha256": snapshot.manifest_sha256,
                "record_count": len(snapshot.records),
            },
        )
        return row

    def list_asset_source_snapshots(self, system_id: UUID) -> list[AssetSourceSnapshotRow]:
        self.get_system(system_id)
        return list(
            self.session.scalars(
                select(AssetSourceSnapshotRow)
                .where(AssetSourceSnapshotRow.system_id == system_id)
                .order_by(AssetSourceSnapshotRow.created_at.desc())
            )
        )

    def get_asset_source_snapshot(self, snapshot_id: UUID) -> AssetSourceSnapshotRow:
        statement = select(AssetSourceSnapshotRow).where(AssetSourceSnapshotRow.id == snapshot_id)
        if self.organization_id is not None:
            statement = (
                statement.join(SystemRow, SystemRow.id == AssetSourceSnapshotRow.system_id)
                .join(ProjectRow, ProjectRow.id == SystemRow.project_id)
                .where(ProjectRow.organization_id == self.organization_id)
            )
        system_scope = self._system_scope_clause()
        if system_scope is not None:
            statement = statement.where(system_scope)
        return _one_or_not_found(
            self.session,
            statement,
            "Asset-source snapshot",
        )

    def import_cve_enrichment(
        self, system_id: UUID, payload: CveEnrichmentImport, actor: str
    ) -> tuple[int, int]:
        system = self.get_system(system_id)
        scan = self.current_inventory_scan(system_id)
        if scan is None:
            raise OperationalConflictError(
                "A current authoritative inventory is required before CVE enrichment"
            )
        services = list(
            self.session.scalars(
                select(ServiceRow).where(
                    ServiceRow.scan_job_id == scan.id,
                    func.lower(ServiceRow.state) == "open",
                )
            )
        )
        matched = 0
        created = 0
        for item in payload.items:
            for service in services:
                confidence = _best_cpe_match(service.cpes, item.affected_cpes)
                if confidence is None:
                    continue
                matched += 1
                stable_key = _cve_finding_stable_key(service, item.cve_id)
                existing = self.session.scalar(
                    select(FindingRow).where(
                        FindingRow.system_id == system_id,
                        FindingRow.stable_key == stable_key,
                    )
                )
                source_entry = {
                    "provider": "cve-enrichment",
                    "feed": payload.feed_name,
                    "feed_version": payload.feed_version,
                    "generated_at": payload.generated_at.isoformat(),
                    "source": item.source,
                    "record_url": item.source_record_url,
                    "source_updated_at": item.source_updated_at.isoformat(),
                    "evidence_strength": 65,
                    "primary_fields": {
                        "title": item.title,
                        "verification_status": (
                            "likely" if confidence >= 0.75 else "candidate"
                        ),
                        "match_confidence": confidence,
                        "match_reason": (
                            "CPE correlation against observed scanner evidence; analyst or "
                            "authenticated verification is still required."
                        ),
                        "cvss_score": item.cvss_score,
                        "cvss_vector": item.cvss_vector,
                    },
                }
                if existing is not None:
                    if not _source_update_is_current(
                        existing.sources,
                        source=item.source,
                        source_updated_at=item.source_updated_at,
                    ):
                        continue
                    existing.scan_job_id = scan.id
                    existing.asset_id = service.asset_id
                    existing.service_id = service.id
                    self._apply_primary_finding_evidence(
                        existing,
                        title=item.title,
                        verification_status=("likely" if confidence >= 0.75 else "candidate"),
                        confidence=confidence,
                        reason=(
                            "CPE correlation against observed scanner evidence; analyst or "
                            "authenticated verification is still required."
                        ),
                        cvss_score=item.cvss_score,
                        cvss_vector=item.cvss_vector,
                        strength=65,
                    )
                    # EPSS is an independently attributed signal. A different
                    # enrichment source omitting it cannot erase a newer FIRST
                    # estimate already attached to the finding.
                    if item.epss_score is not None:
                        existing.epss_score = item.epss_score
                    if item.epss_percentile is not None:
                        existing.epss_percentile = item.epss_percentile
                    existing.sources = [
                        source for source in existing.sources if source.get("source") != item.source
                    ] + [source_entry]
                    existing.last_seen_at = max(
                        _as_aware(existing.last_seen_at), item.source_updated_at
                    )
                    evidence = self._upsert_intelligence_finding_evidence(
                        finding=existing,
                        source_name=item.source,
                        external_id=item.cve_id,
                        source_updated_at=item.source_updated_at,
                        strength=65,
                        payload=source_entry,
                    )
                    self._reactivate_finding_from_intelligence(
                        existing,
                        evidence=evidence,
                        source_updated_at=item.source_updated_at,
                    )
                    self._reassess_finding(system, existing)
                    continue
                finding = FindingRow(
                    system_id=system_id,
                    scan_job_id=scan.id,
                    asset_id=service.asset_id,
                    service_id=service.id,
                    stable_key=stable_key,
                    finding_type="vulnerability",
                    cve_id=item.cve_id,
                    title=item.title,
                    status="likely" if confidence >= 0.75 else "candidate",
                    lifecycle_status="open",
                    match_confidence=confidence,
                    match_reason=(
                        "CPE correlation against observed scanner evidence; analyst or "
                        "authenticated verification is still required."
                    ),
                    cvss_score=item.cvss_score,
                    cvss_vector=item.cvss_vector,
                    epss_score=item.epss_score,
                    epss_percentile=item.epss_percentile,
                    is_kev=item.is_kev,
                    kev_due_date=item.kev_due_date,
                    sources=[source_entry],
                    primary_evidence_strength=65,
                    first_seen_at=item.source_updated_at,
                    last_seen_at=item.source_updated_at,
                    status_updated_at=item.source_updated_at,
                )
                self.session.add(finding)
                self.session.flush()
                self._upsert_intelligence_finding_evidence(
                    finding=finding,
                    source_name=item.source,
                    external_id=item.cve_id,
                    source_updated_at=item.source_updated_at,
                    strength=65,
                    payload=source_entry,
                )
                self._reassess_finding(system, finding)
                created += 1
        self.session.flush()
        self.audit(
            actor,
            "intelligence.cve_imported",
            "system",
            system_id,
            {"feed": payload.feed_name, "items": len(payload.items), "matches": matched},
        )
        return matched, created

    def import_threat_feed(
        self, system_id: UUID, payload: ThreatFeedImport, actor: str
    ) -> tuple[int, int]:
        system = self.get_system(system_id)
        current_scan = self.latest_completed_scan(system_id)
        services = self.list_services(system_id)
        matched = 0
        created = 0
        for item in payload.items:
            existing = self.session.scalar(
                select(ThreatRow).where(
                    ThreatRow.system_id == system_id,
                    ThreatRow.source == payload.source,
                    ThreatRow.external_id == item.external_id,
                )
            )
            if existing is not None and _as_aware(existing.modified_at) > item.modified_at:
                # Never roll a source record back to an older revision.
                continue
            service_matches = [
                service for service in services if _product_matches(service, item.affected_products)
            ]
            asset_ids = sorted({str(service.asset_id) for service in service_matches})
            matched += len(service_matches)
            if existing is None:
                threat = ThreatRow(
                    system_id=system_id,
                    source=payload.source,
                    external_id=item.external_id,
                    title=item.title,
                    description=item.description,
                    severity=item.severity,
                    confidence=item.confidence,
                    attack_patterns=item.attack_patterns,
                    affected_products=item.affected_products,
                    matched_asset_ids=asset_ids,
                    provenance={
                        "source_url": payload.source_url,
                        "feed_version": payload.feed_version,
                        "generated_at": payload.generated_at.isoformat(),
                        "matched_scan_id": str(current_scan.id) if current_scan else None,
                    },
                    modified_at=item.modified_at,
                )
                self.session.add(threat)
                self.session.flush()
                created += 1
            else:
                threat = existing
                threat.title = item.title
                threat.description = item.description
                threat.confidence = item.confidence
                threat.severity = item.severity
                threat.attack_patterns = item.attack_patterns
                threat.affected_products = item.affected_products
                threat.matched_asset_ids = asset_ids
                threat.provenance = {
                    "source_url": payload.source_url,
                    "feed_version": payload.feed_version,
                    "generated_at": payload.generated_at.isoformat(),
                    "matched_scan_id": str(current_scan.id) if current_scan else None,
                }
                threat.modified_at = item.modified_at
            risk = self.session.scalar(select(RiskRow).where(RiskRow.threat_id == threat.id))
            if asset_ids:
                assessment = assess_threat(
                    criticality=system.criticality,
                    confidence=item.confidence,
                    severity=item.severity,
                )
                if risk is None:
                    risk = RiskRow(
                        system_id=system_id,
                        threat_id=threat.id,
                        title=f"{item.title} affects observed technology",
                        likelihood=assessment.likelihood,
                        impact=assessment.impact,
                        score=assessment.score,
                        level=assessment.level,
                        rationale=assessment.rationale,
                    )
                    self.session.add(risk)
                else:
                    risk.title = f"{item.title} affects observed technology"
                    risk.likelihood = assessment.likelihood
                    risk.impact = assessment.impact
                    risk.score = assessment.score
                    risk.level = assessment.level
                    risk.status = "open"
                    risk.rationale = assessment.rationale
            elif risk is not None:
                risk.status = "closed"
                risk.rationale = {
                    **risk.rationale,
                    "closed_reason": "No current observed technology matches this threat record.",
                }
        self.session.flush()
        self.audit(
            actor,
            "intelligence.threats_imported",
            "system",
            system_id,
            {"source": payload.source, "items": len(payload.items), "matches": matched},
        )
        return matched, created

    def list_findings(self, system_id: UUID) -> list[FindingRow]:
        self.get_system(system_id)
        return list(
            self.session.scalars(
                select(FindingRow)
                .where(FindingRow.system_id == system_id)
                .order_by(FindingRow.last_seen_at.desc(), FindingRow.created_at.desc())
            )
        )

    def update_finding_lifecycle(
        self,
        system_id: UUID,
        finding_id: UUID,
        lifecycle_status: str,
        reason: str,
        actor: str,
    ) -> FindingRow:
        # Scanner imports and scan re-correlation lock the same system row. Taking
        # that lock before reading the finding prevents a transaction which loaded
        # stale scanner state from committing over an analyst decision.
        system = self._lock_system(system_id)
        finding = _one_or_not_found(
            self.session,
            select(FindingRow).where(
                FindingRow.id == finding_id,
                FindingRow.system_id == system_id,
            ),
            "Finding",
        )
        now = datetime.now(UTC)
        self._transition_finding_lifecycle(
            finding,
            lifecycle_status,
            now,
            source_kind="manual",
        )
        finding.status = "false_positive" if lifecycle_status == "false_positive" else "confirmed"
        evidence_key = f"manual:{actor.casefold()}"
        evidence = self.session.scalar(
            select(FindingEvidenceRow).where(
                FindingEvidenceRow.finding_id == finding.id,
                FindingEvidenceRow.evidence_key == evidence_key,
            )
        )
        payload = {"reason": reason, "actor": actor, "recorded_at": now.isoformat()}
        if evidence is None:
            evidence = FindingEvidenceRow(
                finding_id=finding.id,
                evidence_key=evidence_key,
                source_kind="manual",
                source_name="analyst",
                external_id=actor,
                lifecycle_status=lifecycle_status,
                strength=100,
                payload=payload,
                first_seen_at=now,
                last_seen_at=now,
            )
            self.session.add(evidence)
        else:
            evidence.lifecycle_status = lifecycle_status
            evidence.payload = payload
            evidence.last_seen_at = now
            evidence.observation_count += 1
        self._reassess_finding(system, finding)
        self.audit(
            actor,
            "finding.lifecycle_updated",
            "finding",
            finding.id,
            {
                "lifecycle_status": lifecycle_status,
                "verification_status": finding.status,
                "reason": reason,
            },
        )
        self.session.flush()
        return finding

    def list_finding_evidence(self, system_id: UUID, finding_id: UUID) -> list[FindingEvidenceRow]:
        self.get_system(system_id)
        finding = self.session.scalar(
            select(FindingRow).where(
                FindingRow.id == finding_id,
                FindingRow.system_id == system_id,
            )
        )
        if finding is None:
            raise OperationalNotFoundError("Finding was not found")
        return list(
            self.session.scalars(
                select(FindingEvidenceRow)
                .where(FindingEvidenceRow.finding_id == finding_id)
                .order_by(
                    FindingEvidenceRow.strength.desc(),
                    FindingEvidenceRow.last_seen_at.desc(),
                )
            )
        )

    def recorrelate_threats_for_inventory(self, system_id: UUID, actor: str) -> int:
        """Move still-relevant threat matches onto the new authoritative generation."""

        system = self.get_system(system_id)
        current_scan = self.current_inventory_scan(system_id)
        if current_scan is None:
            return 0
        current_asset_ids = {
            str(asset.id) for asset in self.list_assets_for_scan(system_id, current_scan.id)
        }
        current_services = [
            service
            for service in self.list_services_for_scan(system_id, current_scan.id)
            if service.state.casefold() == "open"
        ]
        findings = [
            finding
            for finding in self.list_findings(system_id)
            if finding.asset_id is not None
            and str(finding.asset_id) in current_asset_ids
            and finding.lifecycle_status in {"open", "reopened"}
        ]
        updated = 0
        now = datetime.now(UTC)
        for threat in self.session.scalars(
            select(ThreatRow).where(ThreatRow.system_id == system_id)
        ):
            cves = {
                value.upper()
                for value in threat.affected_products
                if isinstance(value, str) and value.upper().startswith("CVE-")
            }
            source_is_processable = self._threat_source_is_processable(threat, now)
            matched_assets: set[str] = set()
            if source_is_processable:
                matched_assets.update(
                    {
                        str(finding.asset_id)
                        for finding in findings
                        if finding.cve_id is not None and finding.cve_id.upper() in cves
                    }
                )
                affected_cpes = [
                    value
                    for value in threat.affected_products
                    if isinstance(value, str) and value.casefold().startswith("cpe:2.3:")
                ]
                matched_assets.update(
                    {
                        str(service.asset_id)
                        for service in current_services
                        if _product_matches(service, threat.affected_products)
                        or _best_cpe_match(service.cpes, affected_cpes) is not None
                    }
                )
                prior_methods = threat.provenance.get("match_methods_by_asset", {})
                if isinstance(prior_methods, dict):
                    matched_assets.update(
                        asset_id
                        for asset_id, methods in prior_methods.items()
                        if asset_id in current_asset_ids
                        and isinstance(methods, list)
                        and any(
                            isinstance(method, dict)
                            and str(method.get("method", "")).startswith("indicator:")
                            for method in methods
                        )
                    )
            matched_asset_ids = sorted(matched_assets)
            threat.matched_asset_ids = matched_asset_ids
            threat.provenance = {
                **threat.provenance,
                "matched_scan_id": str(current_scan.id),
                "inventory_recorrelated_at": now.isoformat(),
            }
            risk = self.session.scalar(select(RiskRow).where(RiskRow.threat_id == threat.id))
            if risk is not None and matched_asset_ids:
                assessment = assess_threat(
                    criticality=system.criticality,
                    confidence=threat.confidence,
                    severity=threat.severity,
                )
                risk.likelihood = assessment.likelihood
                risk.impact = assessment.impact
                risk.score = assessment.score
                risk.level = assessment.level
                risk.status = "open"
                risk.evidence_status = "current"
                risk.closed_at = None
                risk.rationale = assessment.rationale
            elif risk is not None:
                risk.status = "closed"
                risk.evidence_status = "stale"
                risk.closed_at = now
                risk.rationale = {
                    **risk.rationale,
                    "closed_reason": (
                        "The originating intelligence record is not approved and active."
                        if not source_is_processable
                        else "No current finding links this threat to the current inventory."
                    ),
                }
            updated += 1
        if updated:
            self.audit(
                actor,
                "threats.inventory_recorrelated",
                "system",
                system_id,
                {"threats": updated, "scan_id": str(current_scan.id)},
            )
        self.session.flush()
        return updated

    def _threat_source_is_processable(self, threat: ThreatRow, now: datetime) -> bool:
        """Fail closed when a global source was rejected, revoked or expired."""

        raw_record_id = threat.provenance.get("global_intel_record_id")
        if raw_record_id is not None:
            try:
                record_id = UUID(str(raw_record_id))
            except ValueError:
                return False
            statement = select(GlobalIntelRecordRow).where(GlobalIntelRecordRow.id == record_id)
            if self.organization_id is not None:
                statement = statement.where(
                    GlobalIntelRecordRow.organization_id == self.organization_id
                )
            record = self.session.scalar(statement)
            return bool(
                record is not None
                and record.review_status == "approved"
                and not record.revoked
                and record.distribution_tlp != "TLP:RED"
                and (record.valid_from is None or _as_aware(record.valid_from) <= now)
                and (record.valid_until is None or _as_aware(record.valid_until) > now)
            )

        if threat.provenance.get("revoked") is True:
            return False
        for field, is_start in (("valid_from", True), ("valid_until", False)):
            raw_value = threat.provenance.get(field)
            if raw_value is None:
                continue
            if not isinstance(raw_value, str):
                return False
            try:
                boundary = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
            except ValueError:
                return False
            if boundary.tzinfo is None:
                return False
            boundary = boundary.astimezone(UTC)
            if (is_start and boundary > now) or (not is_start and boundary <= now):
                return False
        return True

    def list_threats(self, system_id: UUID) -> list[ThreatRow]:
        current_scan = self.latest_completed_scan(system_id)
        if current_scan is None:
            return []
        current_asset_ids = {
            str(asset.id) for asset in self.list_assets_for_scan(system_id, current_scan.id)
        }
        return self.list_threats_for_inventory(
            system_id,
            scan_id=current_scan.id,
            asset_ids=current_asset_ids,
        )

    def list_threats_for_inventory(
        self,
        system_id: UUID,
        *,
        scan_id: UUID,
        asset_ids: set[str],
    ) -> list[ThreatRow]:
        """Return current threats for one explicitly anchored inventory snapshot."""

        self.get_system(system_id)
        now = datetime.now(UTC)
        return [
            row
            for row in self.session.scalars(
                select(ThreatRow)
                .where(ThreatRow.system_id == system_id)
                .order_by(ThreatRow.ingested_at.desc())
            )
            if row.provenance.get("matched_scan_id") == str(scan_id)
            and asset_ids.intersection(row.matched_asset_ids)
            and self._threat_source_is_processable(row, now)
        ]

    def list_risks(self, system_id: UUID) -> list[RiskRow]:
        finding_ids = {finding.id for finding in self.list_findings(system_id)}
        threat_ids = {threat.id for threat in self.list_threats(system_id)}
        return self.list_current_risks(
            system_id,
            finding_ids=finding_ids,
            threat_ids=threat_ids,
        )

    def list_current_risks(
        self,
        system_id: UUID,
        *,
        finding_ids: set[UUID],
        threat_ids: set[UUID],
    ) -> list[RiskRow]:
        """Return risks attached to an explicitly selected current evidence set."""

        self.get_system(system_id)
        return [
            row
            for row in self.session.scalars(
                select(RiskRow).where(RiskRow.system_id == system_id).order_by(RiskRow.score.desc())
            )
            if row.finding_id in finding_ids or row.threat_id in threat_ids
        ]

    def list_all_risks(self, system_id: UUID) -> list[RiskRow]:
        """Return the full risk register, including risks whose threat is retired."""

        self.get_system(system_id)
        return list(
            self.session.scalars(
                select(RiskRow)
                .where(RiskRow.system_id == system_id)
                .order_by(RiskRow.score.desc(), RiskRow.created_at.desc())
            )
        )

    def apply_kev_batch(
        self,
        system_id: UUID,
        batch: IntelligenceBatch[KevCatalogEntry],
        actor: str,
    ) -> tuple[int, int]:
        system = self.get_system(system_id)
        if not batch.records:
            raise OperationalConflictError(
                "An empty KEV catalogue cannot replace the authoritative snapshot"
            )
        revision_at = (
            batch.provenance.source_updated_at or batch.provenance.retrieved_at
        )
        if not self._advance_intelligence_sync_state(
            system_id=system_id,
            provider="cisa-kev",
            scope_key="complete-catalog",
            source_updated_at=revision_at,
            source_version=batch.provenance.source_version,
            payload_sha256=batch.provenance.payload_sha256,
        ):
            return 0, 0
        records = {record.cve_id: record for record in batch.records}
        for record in batch.records:
            self._cache_intelligence("cisa-kev", record.cve_id, record.model_dump(mode="json"))
        findings = self.list_findings(system_id)
        matched = 0
        updated = 0
        for finding in findings:
            record = records.get(finding.cve_id)
            non_kev_sources = [
                source for source in finding.sources if source.get("provider") != "cisa-kev"
            ]
            if record is None:
                if finding.is_kev or finding.kev_due_date is not None:
                    finding.is_kev = False
                    finding.kev_due_date = None
                    finding.sources = non_kev_sources
                    self._reassess_finding(system, finding)
                    updated += 1
                continue
            matched += 1
            finding.is_kev = True
            finding.kev_due_date = record.due_date
            finding.sources = [
                *non_kev_sources,
                {
                    "provider": "cisa-kev",
                    "source_record_id": record.provenance.source_record_id,
                    "source_version": record.provenance.source_version,
                    "source_updated_at": (
                        record.provenance.source_updated_at.isoformat()
                        if record.provenance.source_updated_at
                        else None
                    ),
                    "retrieved_at": record.provenance.retrieved_at.isoformat(),
                    "payload_sha256": record.provenance.payload_sha256,
                    "required_action": record.required_action,
                    "due_date": record.due_date.isoformat(),
                    "due_date_warning": (
                        "CISA BOD 22-01 deadline for US federal civilian agencies; "
                        "not a customer SLA"
                    ),
                },
            ]
            self._reassess_finding(system, finding)
            updated += 1
        self.audit(
            actor,
            "intelligence.kev_synced",
            "system",
            system_id,
            {"records": len(batch.records), "matched": matched},
        )
        self.session.flush()
        return matched, updated

    def accept_nvd_snapshot(
        self,
        system_id: UUID,
        *,
        queried_cpe: str,
        source_updated_at: datetime,
        source_version: str,
        payload_sha256: str,
    ) -> bool:
        """Fence a complete CPE result before any NVD finding mutation."""

        self.get_system(system_id)
        return self._advance_intelligence_sync_state(
            system_id=system_id,
            provider="nvd",
            scope_key=f"cpe:{queried_cpe}",
            source_updated_at=source_updated_at,
            source_version=source_version,
            payload_sha256=payload_sha256,
        )

    def _advance_intelligence_sync_state(
        self,
        *,
        system_id: UUID,
        provider: str,
        scope_key: str,
        source_updated_at: datetime,
        source_version: str,
        payload_sha256: str,
    ) -> bool:
        """Accept only a strictly newer authoritative provider snapshot."""

        incoming = _as_aware(source_updated_at)
        # Serialize first creation as well as updates of a scope watermark.
        self.session.scalar(
            select(SystemRow.id)
            .where(SystemRow.id == system_id)
            .with_for_update()
        )
        state = self.session.scalar(
            select(IntelligenceSyncStateRow)
            .where(
                IntelligenceSyncStateRow.system_id == system_id,
                IntelligenceSyncStateRow.provider == provider,
                IntelligenceSyncStateRow.scope_key == scope_key,
            )
            .with_for_update()
        )
        if state is None:
            self.session.add(
                IntelligenceSyncStateRow(
                    system_id=system_id,
                    provider=provider,
                    scope_key=scope_key,
                    source_updated_at=incoming,
                    source_version=source_version,
                    payload_sha256=payload_sha256,
                )
            )
            self.session.flush()
            return True
        current = _as_aware(state.source_updated_at)
        if incoming < current:
            return False
        if incoming == current:
            if state.payload_sha256 == payload_sha256:
                return False
            raise OperationalConflictError(
                f"{provider} reused a source timestamp with different content"
            )
        state.source_updated_at = incoming
        state.source_version = source_version
        state.payload_sha256 = payload_sha256
        state.updated_at = datetime.now(UTC)
        return True

    def apply_nvd_batch(
        self,
        system_id: UUID,
        batch: NvdCveBatch,
        queried_cpe: str,
        actor: str,
    ) -> tuple[int, int]:
        system = self.get_system(system_id)
        scan = self.current_inventory_scan(system_id)
        if scan is None:
            raise OperationalConflictError(
                "A current authoritative inventory is required before NVD sync"
            )
        services = [
            service
            for service in self.session.scalars(
                select(ServiceRow).where(
                    ServiceRow.scan_job_id == scan.id,
                    func.lower(ServiceRow.state) == "open",
                )
            )
            if queried_cpe in service.cpes
        ]
        matched = 0
        updated = 0
        for record in batch.records:
            self._cache_intelligence("nvd", record.cve_id, record.model_dump(mode="json"))
            if record.vulnerability_status.casefold() == "rejected":
                # A rejected NVD CVE is a provider revocation, never positive
                # applicability evidence. Complete-snapshot reconciliation
                # below retires any prior evidence for this CPE/CVE.
                continue
            metric = _preferred_cvss_metric(record.cvss_metrics)
            description = next(
                (
                    item.value
                    for item in record.descriptions
                    if item.language.casefold().startswith("en")
                ),
                record.descriptions[0].value,
            )
            source_entry = {
                "provider": "nvd",
                "evidence_strength": 45,
                "effective_observed_at": record.last_modified_at.isoformat(),
                "primary_fields": {
                    "title": description[:500],
                    "verification_status": "candidate",
                    "match_confidence": 0.70,
                    "match_reason": (
                        "NVD returned this CVE for the observed CPE through cpeName. "
                        "The preserved NVD applicability tree and environmental conditions "
                        "have not yet been fully evaluated."
                    ),
                    "cvss_score": float(metric.score) if metric else None,
                    "cvss_vector": metric.vector if metric else None,
                },
                "source_record_id": record.provenance.source_record_id,
                "source_updated_at": record.last_modified_at.isoformat(),
                "retrieved_at": record.provenance.retrieved_at.isoformat(),
                "payload_sha256": record.provenance.payload_sha256,
                "queried_cpe": queried_cpe,
                "cvss_metrics": [item.model_dump(mode="json") for item in record.cvss_metrics],
                "weaknesses": [item.model_dump(mode="json") for item in record.weaknesses],
                "applicability_configurations": [
                    item.model_dump(mode="json") for item in record.applicability_configurations
                ],
                "disclaimer": batch.disclaimer,
            }
            for service in services:
                matched += 1
                stable_key = _cve_finding_stable_key(service, record.cve_id)
                existing = self.session.scalar(
                    select(FindingRow).where(
                        FindingRow.system_id == system_id,
                        FindingRow.stable_key == stable_key,
                    )
                )
                if existing is not None:
                    current_nvd_revisions = [
                        _parse_source_revision(source.get("source_updated_at"))
                        for source in existing.sources
                        if source.get("provider") == "nvd"
                        and source.get("queried_cpe") == queried_cpe
                    ]
                    if any(
                        revision is not None and revision > record.last_modified_at
                        for revision in current_nvd_revisions
                    ):
                        continue
                    existing.scan_job_id = scan.id
                    existing.asset_id = service.asset_id
                    existing.service_id = service.id
                    self._apply_primary_finding_evidence(
                        existing,
                        title=description[:500],
                        verification_status="candidate",
                        confidence=0.70,
                        reason=(
                            "NVD returned this CVE for the observed CPE through cpeName. "
                            "The preserved NVD applicability tree and environmental conditions "
                            "have not yet been fully evaluated."
                        ),
                        cvss_score=float(metric.score) if metric else None,
                        cvss_vector=metric.vector if metric else None,
                        strength=45,
                        revision_at=record.last_modified_at,
                    )
                    existing.sources = [
                        source
                        for source in existing.sources
                        if not (
                            source.get("provider") == "nvd"
                            and source.get("queried_cpe") == queried_cpe
                        )
                    ] + [source_entry]
                    existing.last_seen_at = max(
                        _as_aware(existing.last_seen_at), record.last_modified_at
                    )
                    evidence = self._upsert_intelligence_finding_evidence(
                        finding=existing,
                        source_name=_nvd_evidence_source(queried_cpe),
                        external_id=record.cve_id,
                        source_updated_at=record.last_modified_at,
                        strength=45,
                        payload=source_entry,
                    )
                    self._reactivate_finding_from_intelligence(
                        existing,
                        evidence=evidence,
                        source_updated_at=record.last_modified_at,
                    )
                    self._reassess_finding(system, existing)
                    updated += 1
                    continue
                finding = FindingRow(
                    system_id=system_id,
                    scan_job_id=scan.id,
                    asset_id=service.asset_id,
                    service_id=service.id,
                    stable_key=stable_key,
                    finding_type="vulnerability",
                    cve_id=record.cve_id,
                    title=description[:500],
                    status="candidate",
                    lifecycle_status="open",
                    match_confidence=0.70,
                    match_reason=(
                        "NVD returned this CVE for the observed CPE through cpeName. "
                        "The preserved NVD applicability tree and environmental conditions "
                        "have not yet been fully evaluated."
                    ),
                    cvss_score=float(metric.score) if metric else None,
                    cvss_vector=metric.vector if metric else None,
                    is_kev=False,
                    sources=[source_entry],
                    primary_evidence_strength=45,
                    first_seen_at=record.last_modified_at,
                    last_seen_at=record.last_modified_at,
                    status_updated_at=record.last_modified_at,
                )
                self.session.add(finding)
                self.session.flush()
                self._upsert_intelligence_finding_evidence(
                    finding=finding,
                    source_name=_nvd_evidence_source(queried_cpe),
                    external_id=record.cve_id,
                    source_updated_at=record.last_modified_at,
                    strength=45,
                    payload=source_entry,
                )
                self._reassess_finding(system, finding)
                updated += 1
        self.audit(
            actor,
            "intelligence.nvd_synced",
            "system",
            system_id,
            {
                "queried_cpe": queried_cpe,
                "records": len(batch.records),
                "matches": matched,
            },
        )
        self.session.flush()
        return matched, updated

    def retire_nvd_snapshot(
        self,
        system_id: UUID,
        *,
        queried_cpe: str,
        active_cve_ids: set[str],
        actor: str,
    ) -> int:
        """Retire NVD-only evidence absent from a newer complete CPE result."""

        system = self.get_system(system_id)
        findings = list(
            self.session.scalars(
                select(FindingRow).where(FindingRow.system_id == system_id)
            )
        )
        finding_by_id = {finding.id: finding for finding in findings}
        evidence_rows = list(
            self.session.scalars(
                select(FindingEvidenceRow).where(
                    FindingEvidenceRow.finding_id.in_(finding_by_id),
                    FindingEvidenceRow.source_kind == "intelligence",
                )
            )
        ) if finding_by_id else []
        affected: set[UUID] = set()
        for evidence in evidence_rows:
            if evidence.payload.get("provider") != "nvd" or (
                evidence.payload.get("queried_cpe") != queried_cpe
            ):
                continue
            if evidence.external_id in active_cve_ids:
                continue
            evidence.lifecycle_status = "fixed"
            affected.add(evidence.finding_id)

        now = datetime.now(UTC)
        retired = 0
        self.session.flush()
        for finding_id in affected:
            finding = finding_by_id[finding_id]
            finding.sources = [
                source
                for source in finding.sources
                if not (
                    source.get("provider") == "nvd"
                    and source.get("queried_cpe") == queried_cpe
                    and source.get("source_record_id") not in active_cve_ids
                )
            ]
            active_evidence = self.session.scalar(
                select(func.count(FindingEvidenceRow.id)).where(
                    FindingEvidenceRow.finding_id == finding.id,
                    FindingEvidenceRow.lifecycle_status.in_(("open", "reopened")),
                )
            )
            self.recompute_primary_finding_evidence(finding)
            if not active_evidence and finding.lifecycle_status not in {
                "accepted",
                "false_positive",
                "out_of_scope",
            }:
                finding.lifecycle_status = "fixed"
                finding.resolved_at = now
                finding.status_updated_at = now
            risk = self._reassess_finding(system, finding)
            if not active_evidence:
                risk.rationale = {
                    **risk.rationale,
                    "closed_reason": (
                        "The newer complete NVD CPE snapshot no longer contains "
                        "this CVE as active applicability evidence."
                    ),
                }
            retired += 1
        self.audit(
            actor,
            "intelligence.nvd_snapshot_reconciled",
            "system",
            system_id,
            {"queried_cpe": queried_cpe, "retired": retired},
        )
        self.session.flush()
        return retired

    def apply_epss_batch(
        self,
        system_id: UUID,
        batch: IntelligenceBatch[EpssMetric],
        actor: str,
    ) -> tuple[int, int]:
        system = self.get_system(system_id)
        records: dict[str, EpssMetric] = {}
        for record in batch.records:
            record_payload = record.model_dump(mode="json")
            record_sha256 = hashlib.sha256(
                json.dumps(
                    {
                        "cve_id": record.cve_id,
                        "model_date": record.model_date.isoformat(),
                        "probability": str(record.probability),
                        "percentile": str(record.percentile),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            model_revision = datetime.combine(
                record.model_date, datetime.min.time(), tzinfo=UTC
            )
            if not self._advance_intelligence_sync_state(
                system_id=system_id,
                provider="first-epss",
                scope_key=f"cve:{record.cve_id}",
                source_updated_at=model_revision,
                source_version=record.provenance.source_version,
                payload_sha256=record_sha256,
            ):
                continue
            records[record.cve_id] = record
            self._cache_intelligence(
                "first-epss",
                f"{record.cve_id}@{record.model_date.isoformat()}",
                record_payload,
            )
        findings = [
            finding for finding in self.list_findings(system_id) if finding.cve_id in records
        ]
        updated = 0
        for finding in findings:
            record = records[finding.cve_id]
            finding.epss_score = float(record.probability)
            finding.epss_percentile = float(record.percentile)
            finding.sources = [
                *[source for source in finding.sources if source.get("provider") != "first-epss"],
                {
                    "provider": "first-epss",
                    "source_record_id": record.provenance.source_record_id,
                    "source_version": record.provenance.source_version,
                    "model_date": record.model_date.isoformat(),
                    "epss_score": float(record.probability),
                    "epss_percentile": float(record.percentile),
                    "retrieved_at": record.provenance.retrieved_at.isoformat(),
                    "payload_sha256": record.provenance.payload_sha256,
                },
            ]
            self._reassess_finding(system, finding)
            updated += 1
        self.audit(
            actor,
            "intelligence.epss_synced",
            "system",
            system_id,
            {"records": len(batch.records), "matched": len(findings)},
        )
        self.session.flush()
        return len(findings), updated

    def apply_internal_threat_batch(
        self,
        system_id: UUID,
        batch: IntelligenceBatch[ThreatIntelligenceObject],
        actor: str,
    ) -> tuple[int, int]:
        system = self.get_system(system_id)
        current_scan = self.latest_completed_scan(system_id)
        findings = self.list_findings(system_id)
        current_service_ids = {service.id for service in self.list_services(system_id)}
        findings_by_cve: dict[str, list[FindingRow]] = {}
        for finding in findings:
            if (
                finding.cve_id
                and finding.lifecycle_status in {"open", "reopened"}
                and finding.service_id in current_service_ids
            ):
                findings_by_cve.setdefault(finding.cve_id, []).append(finding)
        matched = 0
        updated = 0
        now = datetime.now(UTC)
        for record in batch.records:
            active_record = (
                not record.revoked
                and (record.valid_from is None or record.valid_from <= now)
                and (record.valid_until is None or record.valid_until > now)
            )
            linked_findings = (
                [
                    finding
                    for cve_id in record.cve_ids
                    for finding in findings_by_cve.get(cve_id, [])
                ]
                if active_record
                else []
            )
            matched_asset_ids = sorted(
                {
                    str(service.asset_id)
                    for finding in linked_findings
                    if finding.service_id is not None
                    and (service := self.session.get(ServiceRow, finding.service_id)) is not None
                }
            )
            matched += len(matched_asset_ids)
            threat = self.session.scalar(
                select(ThreatRow).where(
                    ThreatRow.system_id == system_id,
                    ThreatRow.source == batch.provenance.provider,
                    ThreatRow.external_id == record.id,
                )
            )
            if threat is not None and _as_aware(threat.modified_at) > record.modified:
                continue
            severity = _severity_from_labels(record.labels)
            confidence = (record.confidence if record.confidence is not None else 50) / 100
            threat_provenance = {
                **record.provenance.model_dump(mode="json"),
                "object_marking_refs": list(record.object_marking_refs),
                "markings": ["TLP:AMBER"],
                "revoked": record.revoked,
                "valid_from": record.valid_from.isoformat() if record.valid_from else None,
                "valid_until": record.valid_until.isoformat() if record.valid_until else None,
                "matched_scan_id": str(current_scan.id) if current_scan else None,
            }
            if threat is None:
                threat = ThreatRow(
                    system_id=system_id,
                    source=batch.provenance.provider,
                    external_id=record.id,
                    title=record.name or record.id,
                    description=record.description or "No source description supplied.",
                    severity=severity,
                    confidence=confidence,
                    attack_patterns=list(record.mitre_attack_ids),
                    affected_products=list(record.cve_ids),
                    matched_asset_ids=matched_asset_ids,
                    provenance=threat_provenance,
                    modified_at=record.modified,
                )
                self.session.add(threat)
                self.session.flush()
                updated += 1
            else:
                threat.title = record.name or record.id
                threat.description = record.description or "No source description supplied."
                threat.severity = severity
                threat.confidence = confidence
                threat.attack_patterns = list(record.mitre_attack_ids)
                threat.affected_products = list(record.cve_ids)
                threat.matched_asset_ids = matched_asset_ids
                threat.provenance = threat_provenance
                threat.modified_at = record.modified
                updated += 1
            risk = self.session.scalar(select(RiskRow).where(RiskRow.threat_id == threat.id))
            if matched_asset_ids:
                assessment = assess_threat(
                    criticality=system.criticality,
                    confidence=confidence,
                    severity=severity,
                )
                if risk is None:
                    risk = RiskRow(
                        system_id=system_id,
                        threat_id=threat.id,
                        title=f"{threat.title} is relevant to observed findings",
                        likelihood=assessment.likelihood,
                        impact=assessment.impact,
                        score=assessment.score,
                        level=assessment.level,
                        rationale=assessment.rationale,
                    )
                    self.session.add(risk)
                else:
                    risk.likelihood = assessment.likelihood
                    risk.impact = assessment.impact
                    risk.score = assessment.score
                    risk.level = assessment.level
                    risk.status = "open"
                    risk.rationale = assessment.rationale
            elif risk is not None:
                risk.status = "closed"
                risk.rationale = {
                    **risk.rationale,
                    "closed_reason": (
                        "Threat object is revoked or expired."
                        if not active_record
                        else "No current finding links this threat to an observed asset."
                    ),
                }
        self.audit(
            actor,
            "intelligence.internal_feed_synced",
            "system",
            system_id,
            {"records": len(batch.records), "matched_assets": matched},
        )
        self.session.flush()
        return matched, updated

    def _cache_intelligence(
        self, provider: str, external_id: str, payload: dict[str, Any]
    ) -> IntelligenceCacheRow:
        if provider not in {"cisa-kev", "nvd", "first-epss"}:
            raise OperationalConflictError(
                "The shared enrichment cache accepts verified public providers only"
            )
        row = self.session.scalar(
            select(IntelligenceCacheRow).where(
                IntelligenceCacheRow.provider == provider,
                IntelligenceCacheRow.external_id == external_id,
            )
        )
        if row is None:
            row = IntelligenceCacheRow(
                provider=provider,
                external_id=external_id,
                payload=payload,
            )
            self.session.add(row)
        else:
            row.payload = payload
            row.fetched_at = datetime.now(UTC)
        return row

    def _reassess_finding(self, system: SystemRow, finding: FindingRow) -> RiskRow:
        if finding.asset_id is not None:
            asset = self.session.get(AssetRow, finding.asset_id)
            finding.inventory_status = (
                asset.inventory_status if asset is not None else "unknown"
            )
            if finding.service_id is not None and finding.inventory_status == "current":
                finding_service = self.session.get(ServiceRow, finding.service_id)
                current_scan_id = self.session.scalar(
                    select(ScanJobRow.id).where(
                        ScanJobRow.system_id == system.id,
                        ScanJobRow.is_current_inventory.is_(True),
                    )
                )
                endpoint_is_current = bool(
                    finding_service is not None
                    and current_scan_id is not None
                    and self.session.scalar(
                        select(ServiceRow.id).where(
                            ServiceRow.scan_job_id == current_scan_id,
                            ServiceRow.asset_id == finding_service.asset_id,
                            ServiceRow.port == finding_service.port,
                            func.lower(ServiceRow.protocol)
                            == finding_service.protocol.casefold(),
                            func.lower(ServiceRow.state) == "open",
                        )
                    )
                )
                if not endpoint_is_current:
                    finding.inventory_status = "unobserved"
        else:
            finding.inventory_status = "unknown"
        exposure, reachable, control_effectiveness, context_provenance = self._finding_risk_context(
            system.id, finding
        )
        assessment = assess_vulnerability(
            criticality=system.criticality,
            cvss_score=finding.cvss_score,
            epss_score=finding.epss_score,
            is_kev=finding.is_kev,
            match_confidence=finding.match_confidence,
            exposure=exposure,
            reachable=reachable,
            control_effectiveness=control_effectiveness,
        )
        rationale = {
            **assessment.rationale,
            "context": {
                **assessment.rationale["context"],
                "provenance": context_provenance,
            },
        }
        risk = self.session.scalar(select(RiskRow).where(RiskRow.finding_id == finding.id))
        active = finding.lifecycle_status in {"open", "reopened"}
        if risk is None:
            risk = RiskRow(
                system_id=system.id,
                finding_id=finding.id,
                title=(f"Exploitation of {finding.cve_id}" if finding.cve_id else finding.title),
                likelihood=assessment.likelihood,
                impact=assessment.impact,
                score=assessment.score,
                level=assessment.level,
                status="open" if active else "closed",
                rationale=(
                    rationale
                    if active
                    else {
                        **rationale,
                        "closed_reason": (
                            f"Finding lifecycle changed to {finding.lifecycle_status}."
                        ),
                    }
                ),
                closed_at=None if active else finding.resolved_at or datetime.now(UTC),
                evidence_status=finding.inventory_status,
            )
            self.session.add(risk)
        else:
            risk.evidence_status = finding.inventory_status
            risk.likelihood = assessment.likelihood
            risk.impact = assessment.impact
            risk.score = assessment.score
            risk.level = assessment.level
            risk.updated_at = datetime.now(UTC)
            if active:
                risk.status = "open"
                risk.closed_at = None
                risk.rationale = {
                    **rationale,
                    **(
                        {"reopened_from_finding": True}
                        if finding.lifecycle_status == "reopened"
                        else {}
                    ),
                }
            else:
                risk.status = "closed"
                risk.closed_at = finding.resolved_at or datetime.now(UTC)
                risk.rationale = {
                    **rationale,
                    "closed_reason": (f"Finding lifecycle changed to {finding.lifecycle_status}."),
                }
        return risk

    def recompute_primary_finding_evidence(self, finding: FindingRow) -> None:
        """Re-select technical fields after a source is withdrawn.

        Source withdrawal must also withdraw the title/severity/confidence it
        contributed. Scanner observations are recoverable from immutable rows;
        normalized intelligence sources carry the same bounded primary fields.
        """

        candidates: list[tuple[int, datetime, dict[str, Any]]] = []
        historical_scanner_candidates: list[
            tuple[int, datetime, dict[str, Any]]
        ] = []
        evidence_rows = list(
            self.session.scalars(
                select(FindingEvidenceRow).where(
                    FindingEvidenceRow.finding_id == finding.id,
                )
            )
        )
        for evidence in evidence_rows:
            primary_fields = evidence.payload.get("primary_fields")
            is_active = evidence.lifecycle_status in {"open", "reopened"}
            if not is_active:
                if (
                    evidence.source_kind == "scanner"
                    and evidence.lifecycle_status == "fixed"
                    and evidence.payload.get("timestamp_quarantined") is not True
                    and isinstance(primary_fields, dict)
                ):
                    historical_scanner_candidates.append(
                        (
                            evidence.strength,
                            _evidence_representative_revision(evidence),
                            primary_fields,
                        )
                    )
                continue
            if isinstance(primary_fields, dict):
                candidates.append(
                    (
                        evidence.strength,
                        _evidence_representative_revision(evidence),
                        primary_fields,
                    )
                )
                continue
            if evidence.source_kind != "scanner" or evidence.observation_id is None:
                continue
            observation = self.session.get(
                VulnerabilityObservationRow, evidence.observation_id
            )
            if observation is None:
                continue
            confidence = observation.match_confidence or 0.80
            candidates.append(
                (
                    evidence.strength,
                    _evidence_representative_revision(evidence),
                    {
                        "title": observation.title,
                        "verification_status": (
                            "likely" if confidence >= 0.90 else "candidate"
                        ),
                        "match_confidence": confidence,
                        "match_reason": (
                            "Third-party scanner evidence remains active after another "
                            "intelligence source was withdrawn."
                        ),
                        "cvss_score": observation.cvss_score,
                        "cvss_vector": observation.cvss_vector,
                    },
                )
            )
        if not candidates and historical_scanner_candidates:
            # A resolved scanner finding keeps its last legitimate technical
            # description for audit/history. Withdrawn intelligence is never
            # eligible for this fallback and cannot keep an active risk open.
            candidates = historical_scanner_candidates
        if not candidates:
            finding.title = finding.cve_id or "Unverified finding"
            if finding.status not in {"confirmed", "false_positive"}:
                finding.status = "candidate"
            finding.match_confidence = 0.0
            finding.match_reason = (
                "The selected technical source was withdrawn; remaining evidence does not "
                "contain enough normalized metadata for automatic selection."
            )
            finding.cvss_score = None
            finding.cvss_vector = None
            finding.primary_evidence_strength = 0
            return
        strength, _, selected = max(candidates, key=lambda item: (item[0], item[1]))
        title = selected.get("title")
        status = selected.get("verification_status")
        confidence = selected.get("match_confidence")
        reason = selected.get("match_reason")
        cvss_score = selected.get("cvss_score")
        cvss_vector = selected.get("cvss_vector")
        if isinstance(title, str) and title:
            finding.title = title[:500]
        if (
            finding.status not in {"confirmed", "false_positive"}
            and status in {"candidate", "likely"}
        ):
            finding.status = status
        finding.match_confidence = (
            float(confidence)
            if isinstance(confidence, (int, float)) and 0 <= confidence <= 1
            else 0.0
        )
        finding.match_reason = (
            reason[:4_000]
            if isinstance(reason, str) and reason
            else "Remaining active evidence selected after source withdrawal."
        )
        finding.cvss_score = (
            float(cvss_score)
            if isinstance(cvss_score, (int, float)) and 0 <= cvss_score <= 10
            else None
        )
        finding.cvss_vector = (
            cvss_vector[:160] if isinstance(cvss_vector, str) else None
        )
        finding.primary_evidence_strength = max(0, min(100, strength))

    def _finding_risk_context(
        self,
        system_id: UUID,
        finding: FindingRow,
    ) -> tuple[str, bool | None, float | None, dict[str, Any]]:
        """Resolve measured context and an optional analyst-verified override."""

        exposure = "unknown"
        reachable: bool | None = None
        provenance: dict[str, Any] = {"source": "unavailable"}
        asset = self.session.get(AssetRow, finding.asset_id) if finding.asset_id else None
        historical_service = (
            self.session.get(ServiceRow, finding.service_id) if finding.service_id else None
        )
        if asset is not None and asset.system_id == system_id:
            address = ip_address(asset.primary_ip)
            if address.is_loopback:
                address_classification = "loopback"
            elif address.is_link_local:
                address_classification = "link_local"
            elif address.is_global:
                address_classification = "global"
            elif address.is_private:
                address_classification = "private"
            else:
                address_classification = "other"
            provenance = {
                "source": "observed_inventory",
                "asset_id": str(asset.id),
                "address_classification": address_classification,
                "exposure": "unknown_without_analyst_attestation",
            }
        current_service = None
        if historical_service is not None and (
            asset is None or historical_service.asset_id == asset.id
        ):
            current_scan_id = self.session.scalar(
                select(ScanJobRow.id).where(
                    ScanJobRow.system_id == system_id,
                    ScanJobRow.is_current_inventory.is_(True),
                )
            )
            if current_scan_id is not None:
                current_service = self.session.scalar(
                    select(ServiceRow).where(
                        ServiceRow.scan_job_id == current_scan_id,
                        ServiceRow.asset_id == historical_service.asset_id,
                        ServiceRow.port == historical_service.port,
                        func.lower(ServiceRow.protocol)
                        == historical_service.protocol.casefold(),
                    )
                )
        if current_service is not None:
            normalized_state = current_service.state.casefold()
            if normalized_state == "open":
                reachable = True
            elif normalized_state == "closed":
                reachable = False
            provenance = {
                **provenance,
                "service_id": str(current_service.id),
                "observed_service_state": current_service.state,
                "current_endpoint_observed": True,
            }
        elif historical_service is not None:
            provenance = {
                **provenance,
                "historical_service_id": str(historical_service.id),
                "current_endpoint_observed": False,
            }

        architecture = self.session.scalar(
            select(ArchitectureSnapshotRow)
            .where(
                ArchitectureSnapshotRow.system_id == system_id,
                ArchitectureSnapshotRow.layer == "manual",
            )
            .order_by(ArchitectureSnapshotRow.version.desc())
            .limit(1)
        )
        if architecture is None or finding.asset_id is None:
            return exposure, reachable, None, provenance
        contexts = architecture.graph.get("risk_contexts", [])
        if not isinstance(contexts, list):
            return exposure, reachable, None, provenance
        exact: dict[str, Any] | None = None
        asset_level: dict[str, Any] | None = None
        endpoint_service = current_service or historical_service
        for candidate in contexts:
            if not isinstance(candidate, dict) or candidate.get("asset_id") != str(
                finding.asset_id
            ):
                continue
            candidate_service = candidate.get("service_id")
            if candidate_service is None:
                asset_level = candidate
            elif finding.service_id is not None and candidate_service == str(finding.service_id):
                exact = candidate
            elif (
                endpoint_service is not None
                and candidate.get("endpoint_port") == endpoint_service.port
                and candidate.get("endpoint_protocol")
                == endpoint_service.protocol.casefold()
            ):
                exact = candidate
        selected = exact or asset_level
        if selected is None:
            return exposure, reachable, None, provenance
        selected_exposure = selected.get("exposure")
        if selected_exposure in {"external", "internal", "isolated"}:
            exposure = selected_exposure
        if isinstance(selected.get("reachable"), bool):
            reachable = selected["reachable"]
        effectiveness = selected.get("control_effectiveness")
        control_effectiveness = (
            float(effectiveness) if isinstance(effectiveness, (int, float)) else None
        )
        return (
            exposure,
            reachable,
            control_effectiveness,
            {
                "source": "analyst_verified_architecture",
                "architecture_snapshot_id": str(architecture.id),
                "architecture_version": architecture.version,
                "verified_by": selected.get("verified_by"),
                "verified_at": selected.get("verified_at"),
                "evidence_reference": selected.get("evidence_reference"),
                "bound_endpoint": {
                    "port": selected.get("endpoint_port"),
                    "protocol": selected.get("endpoint_protocol"),
                },
                "current_service_id": (
                    str(current_service.id) if current_service is not None else None
                ),
                "inventory_fallback": provenance,
            },
        )

    def save_report(
        self,
        *,
        system_id: UUID,
        report_type: str,
        format: str,
        snapshot: dict[str, Any],
        content: bytes,
        sha256: str,
        actor: str,
    ) -> ReportRow:
        self.get_system(system_id)
        row = ReportRow(
            system_id=system_id,
            report_type=report_type,
            format=format,
            snapshot=snapshot,
            content=content,
            sha256=sha256,
        )
        self.session.add(row)
        self.session.flush()
        self.audit(actor, "report.created", "report", row.id, {"sha256": sha256})
        return row

    def get_report(self, report_id: UUID) -> ReportRow:
        statement = select(ReportRow).where(ReportRow.id == report_id)
        if self.organization_id is not None:
            statement = (
                statement.join(SystemRow, SystemRow.id == ReportRow.system_id)
                .join(ProjectRow, ProjectRow.id == SystemRow.project_id)
                .where(ProjectRow.organization_id == self.organization_id)
            )
        system_scope = self._system_scope_clause()
        if system_scope is not None:
            statement = statement.where(system_scope)
        return _one_or_not_found(self.session, statement, "Report")

    def list_reports(self, system_id: UUID) -> list[ReportRow]:
        self.get_system(system_id)
        return list(
            self.session.scalars(
                select(ReportRow)
                .where(ReportRow.system_id == system_id)
                .order_by(ReportRow.created_at.desc())
            )
        )

    def audit(
        self,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: UUID | str,
        details: dict[str, Any] | None = None,
    ) -> None:
        if self.organization_id is None:
            raise OperationalConflictError("Audit events require an explicit organization boundary")
        self.session.add(
            AuditEventRow(
                organization_id=self.organization_id,
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=str(resource_id),
                details=details or {},
            )
        )


def _as_aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _normalized_scanner_lifecycle(state: str) -> str:
    """Map vendor state without accepting analyst-only decisions from a feed."""

    if state == "fixed":
        return "fixed"
    if state == "reopened":
        return "reopened"
    # accepted, false_positive and out_of_scope require an authenticated
    # analyst action in Traceless. Unknown vendor state remains active evidence.
    return "open"


def _effective_source_time(
    reported_at: datetime,
    *,
    received_at: datetime,
) -> tuple[datetime, bool]:
    """Bound untrusted future clocks while retaining legitimate historical evidence."""

    reported = _as_aware(reported_at)
    received = _as_aware(received_at)
    if reported > received + timedelta(hours=24):
        return received, True
    return reported, False


def _evidence_representative_revision(evidence: FindingEvidenceRow) -> datetime:
    resolution = evidence.payload.get("snapshot_resolution")
    if isinstance(resolution, dict):
        completed_at = resolution.get("scan_completed_at")
        if isinstance(completed_at, str):
            try:
                return _as_aware(datetime.fromisoformat(completed_at.replace("Z", "+00:00")))
            except ValueError:
                pass
    return _as_aware(evidence.last_seen_at)


def _scanner_evidence_ingested_at(evidence: FindingEvidenceRow) -> datetime:
    """Return the trusted ingestion revision represented by scanner evidence.

    Legacy evidence without an internal ingestion timestamp is deliberately treated
    as older than an analyst decision. Re-correlation of that same immutable row must
    not manufacture a newer scanner decision merely by touching ``updated_at``.
    """

    ingested_at = evidence.payload.get("ingested_at")
    if isinstance(ingested_at, str):
        try:
            return _as_aware(datetime.fromisoformat(ingested_at.replace("Z", "+00:00")))
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=UTC)


def _is_complete_vulnerability_snapshot(imported: VulnerabilityScanImportRow) -> bool:
    return bool(
        imported.provider == "nessus"
        and imported.report_metadata.get("snapshot_complete") is True
        and _vulnerability_snapshot_series_key(imported) is not None
    )


def _vulnerability_snapshot_series_key(
    imported: VulnerabilityScanImportRow,
) -> str | None:
    value = imported.report_metadata.get("snapshot_series_id")
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold()
    if not normalized:
        return None
    material = f"{imported.provider.casefold()}|{normalized}".encode()
    return hashlib.sha256(material).hexdigest()


def _vulnerability_presence_key(
    observation: VulnerabilityObservationRow, cve_id: str | None
) -> str:
    asset_identity = (
        observation.hostname.casefold().rstrip(".")
        if observation.hostname
        else (
            str(ip_address(observation.ip_address))
            if observation.ip_address
            else observation.asset_identifier.casefold()
        )
    )
    material = json.dumps(
        [
            observation.provider_finding_id.casefold(),
            asset_identity,
            observation.port or 0,
            (observation.protocol or "host").casefold(),
            cve_id.upper() if cve_id else "non-cve",
        ],
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode()).hexdigest()


def _normalized_asset_alias(kind: str, value: str) -> str:
    if kind == "ip":
        return str(ip_address(value))
    if kind == "mac":
        return value.strip().replace("-", ":").casefold()
    return value.strip().casefold().rstrip(".")


def _asset_has_other_mac(asset: AssetRow, normalized_mac: str) -> bool:
    return bool(
        asset.mac_address
        and _normalized_asset_alias("mac", asset.mac_address) != normalized_mac
    )


def _assets_have_distinct_macs(first: AssetRow, second: AssetRow | None) -> bool:
    if second is None or not first.mac_address or not second.mac_address:
        return False
    return _normalized_asset_alias(
        "mac", first.mac_address
    ) != _normalized_asset_alias("mac", second.mac_address)


def _address_in_scope(value: str, targets: list[str]) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return False
    for target in targets:
        try:
            network = ip_network(target, strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return True
    return False


def _primary_source_revision(
    sources: list[dict[str, Any]],
    *,
    evidence_strength: int,
) -> datetime | None:
    revisions: list[datetime] = []
    for source in sources:
        if source.get("evidence_strength") != evidence_strength:
            continue
        if source.get("timestamp_quarantined") is True:
            continue
        timestamp = source.get("effective_observed_at")
        if not isinstance(timestamp, str):
            continue
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        revisions.append(_as_aware(parsed))
    return max(revisions) if revisions else None


def _replace_scanner_source(
    sources: list[dict[str, Any]],
    *,
    provider: str,
    provider_finding_id: str,
    replacement: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        source
        for source in sources
        if not (
            source.get("provider") == provider
            and source.get("provider_finding_id") == provider_finding_id
            and source.get("snapshot_series_id") == replacement.get("snapshot_series_id")
        )
    ] + [replacement]


def _cve_finding_stable_key(service: ServiceRow, cve_id: str) -> str:
    return _cve_asset_endpoint_stable_key(service.asset_id, service.port, service.protocol, cve_id)


def _nvd_evidence_source(queried_cpe: str) -> str:
    return f"nvd:{hashlib.sha256(queried_cpe.encode('utf-8')).hexdigest()[:16]}"


def _parse_source_revision(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return _as_aware(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def _cve_asset_endpoint_stable_key(asset_id: UUID, port: int, protocol: str, cve_id: str) -> str:
    identity = "|".join(
        [
            "cve",
            str(asset_id),
            str(port),
            protocol.casefold(),
            cve_id.upper(),
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _source_update_is_current(
    sources: list[dict[str, Any]],
    *,
    source: str,
    source_updated_at: datetime,
) -> bool:
    for evidence in sources:
        if evidence.get("source") != source:
            continue
        timestamp = evidence.get("source_updated_at")
        if not isinstance(timestamp, str):
            continue
        try:
            existing = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if _as_aware(existing) > source_updated_at:
            return False
    return True


def _best_cpe_match(observed: Iterable[str], affected: Iterable[str]) -> float | None:
    best: float | None = None
    for candidate in observed:
        for pattern in affected:
            score = _cpe_match_confidence(candidate, pattern)
            if score is not None and (best is None or score > best):
                best = score
    return best


def _cpe_match_confidence(observed: str, affected: str) -> float | None:
    if observed == affected:
        return 0.95
    if affected.endswith("*") and observed.startswith(affected[:-1]):
        return 0.80
    observed_parts = observed.split(":")
    affected_parts = affected.split(":")
    if len(observed_parts) >= 6 and len(affected_parts) >= 6:
        # cpe:2.3:part:vendor:product:version; a wildcard version is a
        # candidate only because ranges and update fields require NVD logic.
        if observed_parts[2:5] == affected_parts[2:5] and affected_parts[5] in {"*", "-"}:
            return 0.65
    return None


def _product_matches(service: ServiceRow, affected_products: list[str]) -> bool:
    """Require an exact normalized product identity, never a substring hit."""

    observed = {
        " ".join(value.casefold().split())
        for value in (service.product, service.service_name)
        if value and value.strip()
    }
    affected = {
        " ".join(value.casefold().split())
        for value in affected_products
        if value.strip() and not value.casefold().startswith("cpe:2.3:")
    }
    return bool(observed.intersection(affected))


def _severity_from_labels(labels: Iterable[str]) -> str:
    normalized = {label.casefold() for label in labels}
    for level in ("critical", "high", "medium", "low"):
        if level in normalized or f"severity:{level}" in normalized:
            return level
    return "medium"


def _preferred_cvss_metric(metrics: Iterable[CvssMetric]) -> CvssMetric | None:
    """Select a display metric while preserving every provider metric in evidence."""

    rank = {"3.0": 1, "3.1": 2, "4.0": 3}
    return max(
        metrics,
        key=lambda metric: (
            metric.metric_type == "Primary",
            rank[metric.version],
            metric.score,
        ),
        default=None,
    )


def _build_architecture_graph(
    assets: list[AssetRow], services: list[ServiceRow], scan_id: UUID
) -> dict[str, Any]:
    zones: dict[str, dict[str, Any]] = {}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for asset in assets:
        address = ip_address(asset.primary_ip)
        prefix = 24 if address.version == 4 else 64
        subnet = str(ip_network(f"{address}/{prefix}", strict=False))
        zone_id = f"subnet:{subnet}"
        zones.setdefault(
            zone_id,
            {
                "id": zone_id,
                "name": subnet,
                "kind": "observed_network",
                "trust_boundary": "unconfirmed",
                "provenance": "derived_from_observed_address",
            },
        )
        nodes.append(
            {
                "id": str(asset.id),
                "kind": "asset",
                "name": asset.hostname or asset.primary_ip,
                "zone_id": zone_id,
                "asset_id": str(asset.id),
                "properties": {
                    "ip": asset.primary_ip,
                    "os": asset.os_family,
                    "state": asset.state,
                },
                "provenance": "observed",
                "source_scan_id": str(scan_id),
            }
        )
    for service in services:
        if service.state.casefold() != "open":
            continue
        node_id = f"service:{service.id}"
        nodes.append(
            {
                "id": node_id,
                "kind": "service",
                "name": service.product
                or service.service_name
                or f"{service.protocol}/{service.port}",
                "asset_id": str(service.asset_id),
                "service_id": str(service.id),
                "properties": {
                    "port": service.port,
                    "protocol": service.protocol,
                    "version": service.version,
                    "cpes": service.cpes,
                },
                "provenance": "observed",
                "source_scan_id": str(scan_id),
            }
        )
        edges.append(
            {
                "id": f"hosts:{service.asset_id}:{service.id}",
                "source": str(service.asset_id),
                "target": node_id,
                "kind": "hosts",
                "provenance": "derived",
                "warning": "Hosting relation only; this is not an inferred business data flow.",
            }
        )
    return {
        "schema_version": "1.0",
        "source_scan_id": str(scan_id),
        "zones": list(zones.values()),
        "nodes": nodes,
        "edges": edges,
        "publication_state": "draft",
        "warning": (
            "Scanner observations create a reviewable draft. Trust boundaries and data flows "
            "require analyst confirmation."
        ),
    }
