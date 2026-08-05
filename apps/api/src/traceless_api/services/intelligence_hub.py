"""Global intelligence ingestion, search and system-specific correlation."""

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select, tuple_

from traceless_api.core.markings import TLP_RED, permits_automated_processing, tlp_marking
from traceless_api.db.models import (
    AssetRow,
    FindingEvidenceRow,
    FindingRow,
    GlobalIntelObservableRow,
    GlobalIntelRecordRow,
    GlobalIntelRevisionRow,
    OrganizationRow,
    ProjectRow,
    RiskRow,
    ServiceRow,
    SystemRow,
    ThreatRow,
)
from traceless_api.models.intelligence_hub import (
    CanonicalIntelFeed,
    CanonicalIntelRecord,
    GlobalIntelPage,
    GlobalIntelRecordView,
    IntelCorrelationResult,
    IntelImportResult,
)
from traceless_api.models.operational import CveEnrichmentImport, CveEnrichmentItem
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalNotFoundError,
    OperationalRepository,
    _best_cpe_match,
    _product_matches,
)
from traceless_api.services.risk_engine import assess_threat


def _hash_json(value: Any) -> str:
    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(serialized.encode()).hexdigest()


def _as_aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _analysis_payload(item: CanonicalIntelRecord) -> dict[str, Any]:
    return {
        "record_type": item.record_type,
        "title": item.title,
        "summary": item.summary,
        "severity": item.severity,
        "confidence": item.confidence,
        "ai_analysis": item.ai_analysis.model_dump(mode="json") if item.ai_analysis else None,
        "normalized_links": {
            "cve_ids": item.cve_ids,
            "cpes": item.cpes,
            "affected_products": item.affected_products,
            "mitre_attack_ids": item.mitre_attack_ids,
            "indicators": [indicator.model_dump() for indicator in item.indicators],
            "tags": item.tags,
            "sectors": item.sectors,
            "regions": item.regions,
            "markings": item.markings,
            "valid_from": item.valid_from.isoformat() if item.valid_from else None,
            "valid_until": item.valid_until.isoformat() if item.valid_until else None,
            "revoked": item.revoked,
            "vulnerability": (
                item.vulnerability.model_dump(mode="json") if item.vulnerability else None
            ),
        },
    }


def _is_active(row: GlobalIntelRecordRow, now: datetime) -> bool:
    return (
        not row.revoked
        and (row.valid_from is None or _as_aware(row.valid_from) <= now)
        and (
        row.valid_until is None or _as_aware(row.valid_until) > now
        )
    )


def _is_processable(row: GlobalIntelRecordRow, now: datetime) -> bool:
    return row.review_status == "approved" and _is_active(row, now)


class IntelligenceHubService:
    def __init__(self, repository: OperationalRepository) -> None:
        self.repository = repository
        self.session = repository.session
        if repository.organization_id is None:
            raise OperationalConflictError(
                "Global intelligence operations require an organization scope"
            )
        self.organization_id = repository.organization_id

    def import_feed(
        self,
        payload: CanonicalIntelFeed,
        actor: str,
        *,
        sync_run_id: UUID | None = None,
        max_future_skew_seconds: int = 300,
    ) -> IntelImportResult:
        self.repository.ensure_organization()
        # Serialize provider-identity upserts per tenant. Without this lock, two
        # concurrent direct imports can both observe a missing provider/external_id
        # row and race into the unique constraint instead of producing one ordered
        # append-only revision history.
        organization = self.session.scalar(
            select(OrganizationRow)
            .where(OrganizationRow.id == self.organization_id)
            .with_for_update()
        )
        if organization is None:  # pragma: no cover - ensure_organization just created it
            raise OperationalConflictError("The intelligence organization is unavailable")
        created = 0
        updated = 0
        unchanged = 0
        quarantined = 0
        warnings: list[str] = []
        now = datetime.now(UTC)
        future_cutoff = now + timedelta(seconds=max_future_skew_seconds)
        identities = {(item.provider.casefold(), item.external_id) for item in payload.items}
        existing_rows = list(
            self.session.scalars(
                select(GlobalIntelRecordRow).where(
                    GlobalIntelRecordRow.organization_id == self.organization_id,
                    tuple_(
                        GlobalIntelRecordRow.provider_key,
                        GlobalIntelRecordRow.external_id,
                    ).in_(identities)
                )
            )
        )
        rows_by_identity = {
            (row.provider_key, row.external_id): row for row in existing_rows
        }
        rows_to_reindex: list[GlobalIntelRecordRow] = []
        recorrelation_rows: dict[UUID, str] = {}

        for item in payload.items:
            identity = (item.provider.casefold(), item.external_id)
            row = rows_by_identity.get(identity)
            raw_sha256 = _hash_json(item.raw_evidence)
            analysis_payload = _analysis_payload(item)
            analysis_sha256 = _hash_json(analysis_payload)
            if row is not None and _as_aware(row.modified_at) > item.modified_at:
                unchanged += 1
                warnings.append(
                    f"Ignored older revision for {item.provider}/{item.external_id}."
                )
                red_restriction = (
                    "tlp_red_requires_named_recipient_controls"
                    if not permits_automated_processing(item.markings)
                    else None
                )
                self._append_revision(
                    payload=payload,
                    item=item,
                    row=row,
                    sync_run_id=sync_run_id,
                    raw_sha256=raw_sha256,
                    analysis_sha256=analysis_sha256,
                    outcome="superseded",
                    quarantine_reason=red_restriction,
                    received_at=now,
                )
                continue
            quarantine_reason = self._clock_quarantine_reason(
                payload, item, future_cutoff
            )
            if quarantine_reason is not None:
                quarantined += 1
                warning_reason = (
                    "future-dated revision"
                    if quarantine_reason.startswith("future_clock_skew:")
                    else "TLP:RED revision requiring named-recipient controls"
                )
                warnings.append(
                    f"Quarantined {warning_reason} for {item.provider}/{item.external_id}."
                )
                self._append_revision(
                    payload=payload,
                    item=item,
                    row=row,
                    sync_run_id=sync_run_id,
                    raw_sha256=raw_sha256,
                    analysis_sha256=analysis_sha256,
                    outcome="quarantined",
                    quarantine_reason=quarantine_reason,
                    received_at=now,
                )
                if (
                    row is not None
                    and quarantine_reason == "tlp_red_requires_named_recipient_controls"
                ):
                    # A RED reclassification must immediately fail closed. Do
                    # not copy the restricted payload into the tenant-wide
                    # current-record table, but advance its source watermark,
                    # hide it from readers and make prior materializations
                    # eligible for durable de-correlation.
                    row.modified_at = item.modified_at
                    row.retrieved_at = item.retrieved_at
                    row.feed_id = payload.feed_id
                    row.feed_version = payload.feed_version
                    row.feed_generated_at = payload.generated_at
                    row.markings = [TLP_RED]
                    row.distribution_tlp = TLP_RED
                    row.review_status = "pending"
                    row.reviewed_by = None
                    row.reviewed_at = None
                    row.review_note = None
                    row.revoked = True
                    row.last_ingested_at = now
                    recorrelation_rows[row.id] = raw_sha256
                continue
            if (
                row is not None
                and _as_aware(row.modified_at) == item.modified_at
                and row.raw_sha256 == raw_sha256
                and row.analysis_sha256 == analysis_sha256
            ):
                row.last_ingested_at = now
                row.retrieved_at = item.retrieved_at
                unchanged += 1
                self._append_revision(
                    payload=payload,
                    item=item,
                    row=row,
                    sync_run_id=sync_run_id,
                    raw_sha256=raw_sha256,
                    analysis_sha256=analysis_sha256,
                    outcome="unchanged",
                    quarantine_reason=None,
                    received_at=now,
                )
                continue

            values = self._row_values(
                organization_id=self.organization_id,
                payload=payload,
                item=item,
                raw_sha256=raw_sha256,
                analysis_sha256=analysis_sha256,
                now=now,
            )
            if row is None:
                row = GlobalIntelRecordRow(**values)
                self.session.add(row)
                rows_by_identity[identity] = row
                created += 1
            else:
                recorrelation_rows[row.id] = raw_sha256
                for field, value in values.items():
                    setattr(row, field, value)
                updated += 1
            self.session.flush()
            self._append_revision(
                payload=payload,
                item=item,
                row=row,
                sync_run_id=sync_run_id,
                raw_sha256=raw_sha256,
                analysis_sha256=analysis_sha256,
                outcome="applied",
                quarantine_reason=None,
                received_at=now,
            )
            rows_to_reindex.append(row)

        self.session.flush()
        self._replace_observables(rows_to_reindex)
        self.session.flush()
        if recorrelation_rows:
            # Updated records return to pending review (and RED/revoked records
            # are explicitly inactive). Retire their previously materialized
            # effects synchronously; the durable jobs then rebuild approved
            # effects instead of being the fail-closed boundary.
            self.retire_record_effects(
                set(recorrelation_rows),
                reason="The originating intelligence revision is no longer approved and active.",
                actor=actor,
            )
        self.repository.audit(
            actor,
            "intelligence.global_feed_imported",
            "intelligence_feed",
            payload.feed_id,
            {
                "feed_version": payload.feed_version,
                "items": len(payload.items),
                "created": created,
                "updated": updated,
                "unchanged": unchanged,
                "quarantined": quarantined,
                "sync_run_id": str(sync_run_id) if sync_run_id else None,
            },
        )
        result = IntelImportResult(
            imported=len(payload.items),
            created=created,
            updated=updated,
            unchanged=unchanged,
            quarantined=quarantined,
            warnings=warnings[:100],
        )
        if recorrelation_rows:
            ordered = tuple(sorted(recorrelation_rows, key=str))
            result._records_requiring_recorrelation = ordered
            result._recorrelation_manifest_sha256 = hashlib.sha256(
                "\0".join(
                    f"{record_id}:{recorrelation_rows[record_id]}"
                    for record_id in ordered
                ).encode("utf-8")
            ).hexdigest()
        return result

    def reconcile_full_snapshot(
        self,
        *,
        feed_id: str,
        feed_version: str,
        feed_generated_at: datetime,
        present_identities: set[tuple[str, str]],
        sync_run_id: UUID,
        actor: str,
    ) -> tuple[set[UUID], str | None]:
        """Withdraw records absent from a completed authoritative snapshot.

        Stable record identifiers are preserved so local references and review history
        remain attributable. Current payload fields and observables are replaced by a
        minimal tombstone, and materialized findings/risks are withdrawn synchronously.
        """

        rows = list(
            self.session.scalars(
                select(GlobalIntelRecordRow).where(
                    GlobalIntelRecordRow.organization_id == self.organization_id,
                    GlobalIntelRecordRow.feed_id == feed_id,
                )
            )
        )
        missing = [
            row
            for row in rows
            if (row.provider_key, row.external_id) not in present_identities
        ]
        if not missing:
            return set(), None

        now = datetime.now(UTC)
        withdrawn_at = max(_as_aware(feed_generated_at), now)
        manifest_material: list[str] = []
        for row in missing:
            previous_raw_sha256 = row.raw_sha256
            previous_analysis_sha256 = row.analysis_sha256 or ""
            previous_review = {
                "status": row.review_status,
                "reviewed_by": row.reviewed_by,
                "reviewed_at": (
                    _as_aware(row.reviewed_at).isoformat()
                    if row.reviewed_at is not None
                    else None
                ),
                "note_sha256": (
                    hashlib.sha256(row.review_note.encode("utf-8")).hexdigest()
                    if row.review_note
                    else None
                ),
            }
            tombstone_evidence = {
                "publisher_withdrawal": {
                    "feed_id": feed_id,
                    "feed_version": feed_version,
                    "withdrawn_at": withdrawn_at.isoformat(),
                    "previous_raw_sha256": previous_raw_sha256,
                    "previous_analysis_sha256": previous_analysis_sha256 or None,
                    "previous_review": previous_review,
                }
            }
            tombstone_analysis = {
                "record_type": row.record_type,
                "title": "Withdrawn publisher record",
                "summary": "The record is absent from the current authorized publisher snapshot.",
                "normalized_links": {
                    "revoked": True,
                    "markings": ["TLP:CLEAR"],
                    "tags": [
                        "traceless:source-status:deleted",
                        "traceless:publisher-reconciliation",
                    ],
                },
            }
            raw_sha256 = _hash_json(tombstone_evidence)
            analysis_sha256 = _hash_json(tombstone_analysis)
            canonical_payload = {
                "source_kind": row.source_kind,
                "provider": row.provider,
                "external_id": row.external_id,
                "record_type": row.record_type,
                "title": "Withdrawn publisher record",
                "summary": tombstone_analysis["summary"],
                "modified_at": withdrawn_at.isoformat(),
                "retrieved_at": now.isoformat(),
                "markings": ["TLP:CLEAR"],
                "tags": tombstone_analysis["normalized_links"]["tags"],
                "revoked": True,
                "valid_until": withdrawn_at.isoformat(),
                "raw_evidence": tombstone_evidence,
            }
            self.session.add(
                GlobalIntelRevisionRow(
                    organization_id=self.organization_id,
                    record_id=row.id,
                    sync_run_id=sync_run_id,
                    provider=row.provider,
                    provider_key=row.provider_key,
                    external_id=row.external_id,
                    feed_id=feed_id,
                    feed_version=feed_version,
                    feed_generated_at=feed_generated_at,
                    source_modified_at=withdrawn_at,
                    source_retrieved_at=now,
                    outcome="applied",
                    quarantine_reason="publisher_snapshot_withdrawal",
                    canonical_payload=canonical_payload,
                    raw_evidence=tombstone_evidence,
                    raw_sha256=raw_sha256,
                    analysis_sha256=analysis_sha256,
                    received_at=now,
                )
            )
            row.title = "Withdrawn publisher record"
            row.summary = str(tombstone_analysis["summary"])
            row.source_url = None
            row.published_at = None
            row.modified_at = withdrawn_at
            row.retrieved_at = now
            row.severity = None
            row.confidence = None
            row.cve_ids = []
            row.cpes = []
            row.affected_products = []
            row.mitre_attack_ids = []
            row.indicators = []
            row.tags = list(tombstone_analysis["normalized_links"]["tags"])
            row.sectors = []
            row.regions = []
            row.markings = ["TLP:CLEAR"]
            row.distribution_tlp = "TLP:CLEAR"
            row.review_status = "pending"
            row.reviewed_by = None
            row.reviewed_at = None
            row.review_note = None
            row.valid_from = None
            row.valid_until = withdrawn_at
            row.revoked = True
            row.raw_evidence = tombstone_evidence
            row.raw_sha256 = raw_sha256
            row.ai_analysis = None
            row.analysis_sha256 = analysis_sha256
            row.vulnerability = None
            row.feed_version = feed_version
            row.feed_generated_at = feed_generated_at
            row.last_ingested_at = now
            manifest_material.append(
                f"{row.id}:{previous_raw_sha256}:{previous_analysis_sha256}"
            )

        self._replace_observables(missing)
        record_ids = {row.id for row in missing}
        self.retire_record_effects(
            record_ids,
            reason="The record is absent from the completed authorized publisher snapshot.",
            actor=actor,
        )
        manifest = hashlib.sha256(
            "\0".join(sorted(manifest_material)).encode("utf-8")
        ).hexdigest()
        self.repository.audit(
            actor,
            "intelligence.publisher_snapshot_reconciled",
            "intelligence_feed",
            feed_id,
            {
                "feed_version": feed_version,
                "withdrawn_records": len(record_ids),
                "manifest_sha256": manifest,
                "sync_run_id": str(sync_run_id),
            },
        )
        self.session.flush()
        return record_ids, manifest

    def retire_record_effects(
        self,
        record_ids: set[UUID],
        *,
        reason: str,
        system_ids: set[UUID] | None = None,
        actor: str | None = None,
    ) -> None:
        """Synchronously withdraw materialized effects for global records."""

        if not record_ids:
            return
        source_record_ids = {
            f"intel-hub:{record_id}": record_id for record_id in record_ids
        }
        source_names = set(source_record_ids)
        now = datetime.now(UTC)
        organization_filter = (
            ProjectRow.organization_id == self.organization_id
        )
        threat_statement = (
            select(ThreatRow)
            .join(SystemRow, SystemRow.id == ThreatRow.system_id)
            .join(ProjectRow, ProjectRow.id == SystemRow.project_id)
            .where(organization_filter)
        )
        if system_ids is not None:
            threat_statement = threat_statement.where(ThreatRow.system_id.in_(system_ids))
        threats = list(self.session.scalars(threat_statement))
        changed_records_by_system: dict[UUID, set[UUID]] = {}
        for threat in threats:
            raw_record_id = threat.provenance.get("global_intel_record_id")
            if not isinstance(raw_record_id, str):
                continue
            try:
                record_id = UUID(raw_record_id)
            except ValueError:
                continue
            if record_id not in record_ids:
                continue
            if (
                not threat.matched_asset_ids
                and threat.provenance.get("source_processability") == "withdrawn"
            ):
                continue
            threat.matched_asset_ids = []
            changed_records_by_system.setdefault(threat.system_id, set()).add(record_id)
            threat.provenance = {
                **threat.provenance,
                "source_processability": "withdrawn",
                "source_withdrawn_at": now.isoformat(),
            }
            risk = self.session.scalar(
                select(RiskRow).where(RiskRow.threat_id == threat.id)
            )
            if risk is not None:
                risk.status = "closed"
                risk.evidence_status = "stale"
                risk.closed_at = now
                risk.rationale = {**risk.rationale, "closed_reason": reason}

        finding_statement = (
            select(FindingRow)
            .join(SystemRow, SystemRow.id == FindingRow.system_id)
            .join(ProjectRow, ProjectRow.id == SystemRow.project_id)
            .where(organization_filter)
        )
        if system_ids is not None:
            finding_statement = finding_statement.where(FindingRow.system_id.in_(system_ids))
        findings = list(self.session.scalars(finding_statement))
        for finding in findings:
            affected_sources = {
                str(source.get("source"))
                for source in finding.sources
                if source.get("source") in source_names
            }
            if not affected_sources:
                continue
            changed_records_by_system.setdefault(finding.system_id, set()).update(
                source_record_ids[source_name] for source_name in affected_sources
            )
            finding.sources = [
                source
                for source in finding.sources
                if source.get("source") not in affected_sources
            ]
            for evidence in self.session.scalars(
                select(FindingEvidenceRow).where(
                    FindingEvidenceRow.finding_id == finding.id,
                    FindingEvidenceRow.source_kind == "intelligence",
                    FindingEvidenceRow.source_name.in_(affected_sources),
                )
            ):
                evidence.lifecycle_status = "fixed"
                evidence.updated_at = now
                evidence.payload = {
                    **evidence.payload,
                    "source_processability": "withdrawn",
                    "source_withdrawn_at": now.isoformat(),
                }
            self.session.flush()
            self.repository.recompute_primary_finding_evidence(finding)
            has_active_evidence = self.session.scalar(
                select(func.count(FindingEvidenceRow.id)).where(
                    FindingEvidenceRow.finding_id == finding.id,
                    FindingEvidenceRow.lifecycle_status.in_(("open", "reopened")),
                )
            )
            if not has_active_evidence and finding.lifecycle_status not in {
                "accepted",
                "false_positive",
                "out_of_scope",
            }:
                finding.lifecycle_status = "fixed"
                finding.resolved_at = now
                finding.status_updated_at = now
            system = self.session.get(SystemRow, finding.system_id)
            if system is not None:
                self.repository._reassess_finding(system, finding)
        self.session.flush()
        for system_id in sorted(changed_records_by_system, key=str):
            self.repository.audit(
                actor or "system:temporal-policy",
                "intelligence.effects_withdrawn",
                "system",
                system_id,
                {
                    "record_ids": sorted(
                        str(record_id)
                        for record_id in changed_records_by_system[system_id]
                    ),
                    "reason": reason,
                },
            )
        self.session.flush()

    def retire_nonprocessable_effects(
        self,
        *,
        now: datetime | None = None,
        system_ids: set[UUID] | None = None,
    ) -> int:
        """Materialize fail-closed review/revocation/time state before a current view."""

        evaluated_at = now or datetime.now(UTC)
        if system_ids is not None:
            for system_id in system_ids:
                self.repository.get_system(system_id)
        record_ids = set(
            self.session.scalars(
                select(GlobalIntelRecordRow.id).where(
                    GlobalIntelRecordRow.organization_id == self.organization_id,
                    or_(
                        GlobalIntelRecordRow.review_status != "approved",
                        GlobalIntelRecordRow.revoked.is_(True),
                        GlobalIntelRecordRow.distribution_tlp == TLP_RED,
                        GlobalIntelRecordRow.valid_from > evaluated_at,
                        GlobalIntelRecordRow.valid_until <= evaluated_at,
                    ),
                )
            )
        )
        self.retire_record_effects(
            record_ids,
            reason="The originating intelligence record is not currently processable.",
            system_ids=system_ids,
        )
        return len(record_ids)

    @staticmethod
    def _clock_quarantine_reason(
        payload: CanonicalIntelFeed,
        item: CanonicalIntelRecord,
        future_cutoff: datetime,
    ) -> str | None:
        timestamps: dict[str, datetime | None] = {
            "feed_generated_at": payload.generated_at,
            "modified_at": item.modified_at,
            "retrieved_at": item.retrieved_at,
            "published_at": item.published_at,
            "analysis_at": item.ai_analysis.analyzed_at if item.ai_analysis else None,
        }
        future_fields = sorted(
            name
            for name, value in timestamps.items()
            if value is not None and _as_aware(value) > future_cutoff
        )
        if future_fields:
            return "future_clock_skew:" + ",".join(future_fields)
        if not permits_automated_processing(item.markings):
            return "tlp_red_requires_named_recipient_controls"
        return None

    def _append_revision(
        self,
        *,
        payload: CanonicalIntelFeed,
        item: CanonicalIntelRecord,
        row: GlobalIntelRecordRow | None,
        sync_run_id: UUID | None,
        raw_sha256: str,
        analysis_sha256: str,
        outcome: str,
        quarantine_reason: str | None,
        received_at: datetime,
    ) -> None:
        restricted = quarantine_reason == "tlp_red_requires_named_recipient_controls"
        canonical_payload = (
            {
                "provider": item.provider,
                "external_id": item.external_id,
                "record_type": item.record_type,
                "modified_at": item.modified_at.isoformat(),
                "markings": [TLP_RED],
                "restricted_payload_sha256": raw_sha256,
            }
            if restricted
            else item.model_dump(mode="json")
        )
        raw_evidence = (
            {"restricted_payload_sha256": raw_sha256}
            if restricted
            else item.raw_evidence
        )
        self.session.add(
            GlobalIntelRevisionRow(
                organization_id=self.organization_id,
                record_id=row.id if row is not None else None,
                sync_run_id=sync_run_id,
                provider=item.provider,
                provider_key=item.provider.casefold(),
                external_id=item.external_id,
                feed_id=payload.feed_id,
                feed_version=payload.feed_version,
                feed_generated_at=payload.generated_at,
                source_modified_at=item.modified_at,
                source_retrieved_at=item.retrieved_at,
                outcome=outcome,
                quarantine_reason=quarantine_reason,
                canonical_payload=canonical_payload,
                raw_evidence=raw_evidence,
                raw_sha256=raw_sha256,
                analysis_sha256=analysis_sha256,
                received_at=received_at,
            )
        )

    def list_records(
        self,
        *,
        source_kind: str | None = None,
        record_type: str | None = None,
        query: str | None = None,
        review_status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> GlobalIntelPage:
        filters = [
            GlobalIntelRecordRow.organization_id == self.organization_id,
            GlobalIntelRecordRow.distribution_tlp != TLP_RED,
        ]
        if source_kind:
            filters.append(GlobalIntelRecordRow.source_kind == source_kind)
        if record_type:
            filters.append(GlobalIntelRecordRow.record_type == record_type)
        if review_status:
            filters.append(GlobalIntelRecordRow.review_status == review_status)
        if query:
            escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
            filters.append(
                or_(
                    GlobalIntelRecordRow.title.ilike(pattern, escape="\\"),
                    GlobalIntelRecordRow.summary.ilike(pattern, escape="\\"),
                    GlobalIntelRecordRow.provider.ilike(pattern, escape="\\"),
                    GlobalIntelRecordRow.external_id.ilike(pattern, escape="\\"),
                )
            )
        total = self.session.scalar(
            select(func.count()).select_from(GlobalIntelRecordRow).where(*filters)
        )
        rows = list(
            self.session.scalars(
                select(GlobalIntelRecordRow)
                .where(*filters)
                .order_by(GlobalIntelRecordRow.modified_at.desc())
                .offset(offset)
                .limit(limit)
            )
        )
        return GlobalIntelPage(
            items=[GlobalIntelRecordView.model_validate(row) for row in rows],
            total=total or 0,
            limit=limit,
            offset=offset,
        )

    def get_record(self, record_id: UUID) -> GlobalIntelRecordView:
        row = self.session.scalar(
            select(GlobalIntelRecordRow).where(
                GlobalIntelRecordRow.id == record_id,
                GlobalIntelRecordRow.organization_id == self.organization_id,
                GlobalIntelRecordRow.distribution_tlp != TLP_RED,
            )
        )
        if row is None:
            raise OperationalNotFoundError("Global intelligence record was not found")
        return GlobalIntelRecordView.model_validate(row)

    def correlate(self, system_id: UUID, actor: str) -> IntelCorrelationResult:
        system = self.repository.get_system(system_id)
        scan = self.repository.latest_completed_scan(system_id)
        if scan is None:
            raise OperationalConflictError(
                "A completed scan is required before intelligence correlation"
            )
        now = datetime.now(UTC)
        assets = self.repository.list_assets(system_id)
        services = self.repository.list_services(system_id)
        findings = self.repository.list_findings(system_id)
        initial_rows = self._candidate_rows(system_id, assets, services, findings)
        active_rows = [row for row in initial_rows if _is_processable(row, now)]
        vulnerability_rows = sorted(
            (
                row
                for row in active_rows
                if row.record_type == "vulnerability" and row.vulnerability and row.cve_ids
            ),
            key=lambda row: _as_aware(row.modified_at),
        )
        risk_count_before = self.session.scalar(
            select(func.count(RiskRow.id)).where(RiskRow.system_id == system_id)
        ) or 0
        cve_items: list[CveEnrichmentItem] = []
        for row in vulnerability_rows:
            signals = row.vulnerability or {}
            affected_cpes = signals.get("affected_cpes") or row.cpes
            for cve_id in row.cve_ids:
                cve_items.append(
                    CveEnrichmentItem(
                        cve_id=cve_id,
                        title=row.title,
                        affected_cpes=affected_cpes,
                        cvss_score=signals.get("cvss_score"),
                        cvss_vector=signals.get("cvss_vector"),
                        epss_score=signals.get("epss_score"),
                        epss_percentile=signals.get("epss_percentile"),
                        is_kev=False,
                        kev_due_date=None,
                        source=f"intel-hub:{row.id}",
                        source_record_url=row.source_url,
                        source_updated_at=row.modified_at,
                    )
                )
        finding_matches = 0
        findings_created = 0
        warnings: list[str] = []
        if cve_items:
            finding_matches, findings_created = self.repository.import_cve_enrichment(
                system_id,
                CveEnrichmentImport(
                    feed_name="global-intelligence-hub",
                    feed_version=max(row.feed_version for row in vulnerability_rows),
                    generated_at=max(row.feed_generated_at for row in vulnerability_rows),
                    items=cve_items,
                ),
                actor,
            )

        findings = self.repository.list_findings(system_id)
        self._annotate_and_retire_vulnerability_sources(
            initial_rows,
            findings,
            system,
            now,
            warnings,
        )
        findings_by_cve: dict[str, list[FindingRow]] = {}
        for finding in findings:
            if finding.cve_id and finding.lifecycle_status in {"open", "reopened"}:
                findings_by_cve.setdefault(finding.cve_id, []).append(finding)

        threat_records_matched = 0
        threats_created = 0
        rows = self._candidate_rows(system_id, assets, services, findings)
        considered_ids = {row.id for row in initial_rows} | {row.id for row in rows}
        for row in rows:
            if row.record_type == "vulnerability":
                continue
            matches = (
                self._match_assets(row, assets, services, findings_by_cve)
                if _is_processable(row, now)
                else {}
            )
            asset_ids = sorted(matches)
            if asset_ids:
                threat_records_matched += 1
            source = f"intel-hub:{row.provider}"
            threat = self.session.scalar(
                select(ThreatRow).where(
                    ThreatRow.system_id == system_id,
                    ThreatRow.source == source,
                    ThreatRow.external_id == row.external_id,
                )
            )
            if threat is not None and _as_aware(threat.modified_at) > _as_aware(row.modified_at):
                continue
            confidence = self._confidence(row)
            severity = row.severity or "medium"
            provenance = {
                "global_intel_record_id": str(row.id),
                "source_url": row.source_url,
                "feed_id": row.feed_id,
                "feed_version": row.feed_version,
                "raw_sha256": row.raw_sha256,
                "analysis_sha256": row.analysis_sha256,
                "markings": row.markings,
                "revoked": row.revoked,
                "valid_from": row.valid_from.isoformat() if row.valid_from else None,
                "valid_until": row.valid_until.isoformat() if row.valid_until else None,
                "matched_scan_id": str(scan.id),
                "match_methods_by_asset": matches,
            }
            if threat is None and not asset_ids:
                continue
            if threat is None:
                threat = ThreatRow(
                    system_id=system_id,
                    source=source,
                    external_id=row.external_id,
                    title=row.title[:300],
                    description=row.summary,
                    severity=severity,
                    confidence=confidence,
                    attack_patterns=row.mitre_attack_ids,
                    affected_products=[*row.cve_ids, *row.affected_products, *row.cpes],
                    matched_asset_ids=asset_ids,
                    provenance=provenance,
                    modified_at=row.modified_at,
                )
                self.session.add(threat)
                self.session.flush()
                threats_created += 1
            else:
                threat.title = row.title[:300]
                threat.description = row.summary
                threat.severity = severity
                threat.confidence = confidence
                threat.attack_patterns = row.mitre_attack_ids
                threat.affected_products = [*row.cve_ids, *row.affected_products, *row.cpes]
                threat.matched_asset_ids = asset_ids
                threat.provenance = provenance
                threat.modified_at = row.modified_at
            risk = self.session.scalar(select(RiskRow).where(RiskRow.threat_id == threat.id))
            if asset_ids:
                match_confidence = max(
                    method["confidence"] for methods in matches.values() for method in methods
                )
                assessment = assess_threat(
                    criticality=system.criticality,
                    confidence=min(confidence, match_confidence),
                    severity=severity,
                )
                rationale = {
                    **assessment.rationale,
                    "correlation_confidence": match_confidence,
                    "global_intel_record_id": str(row.id),
                }
                if risk is None:
                    risk = RiskRow(
                        system_id=system_id,
                        threat_id=threat.id,
                        title=f"{row.title[:440]} affects observed technology",
                        likelihood=assessment.likelihood,
                        impact=assessment.impact,
                        score=assessment.score,
                        level=assessment.level,
                        rationale=rationale,
                    )
                    self.session.add(risk)
                else:
                    risk.title = f"{row.title[:440]} affects observed technology"
                    risk.likelihood = assessment.likelihood
                    risk.impact = assessment.impact
                    risk.score = assessment.score
                    risk.level = assessment.level
                    risk.status = "open"
                    risk.evidence_status = "current"
                    risk.rationale = rationale
            elif risk is not None:
                risk.status = "closed"
                risk.evidence_status = "stale"
                risk.rationale = {
                    **risk.rationale,
                    "closed_reason": (
                        "The source record is pending review or was rejected."
                        if row.review_status != "approved"
                        else "The source record is revoked or expired."
                        if not _is_active(row, now)
                        else "No current asset, CPE, product or CVE finding matches the record."
                    ),
                }

        self.session.flush()
        risk_count_after = self.session.scalar(
            select(func.count(RiskRow.id)).where(RiskRow.system_id == system_id)
        ) or 0
        risks_created = max(0, risk_count_after - risk_count_before)
        self.repository.audit(
            actor,
            "intelligence.global_correlated",
            "system",
            system_id,
            {
                "scan_id": str(scan.id),
                "records_considered": len(considered_ids),
                "finding_matches": finding_matches,
                "threat_records_matched": threat_records_matched,
            },
        )
        return IntelCorrelationResult(
            system_id=system_id,
            scan_id=scan.id,
            records_considered=len(considered_ids),
            vulnerability_records_applied=len(vulnerability_rows),
            finding_matches=finding_matches,
            findings_created=findings_created,
            threat_records_matched=threat_records_matched,
            threats_created=threats_created,
            risks_created=risks_created,
            warnings=warnings,
        )

    @staticmethod
    def _row_values(
        *,
        organization_id: UUID,
        payload: CanonicalIntelFeed,
        item: CanonicalIntelRecord,
        raw_sha256: str,
        analysis_sha256: str,
        now: datetime,
    ) -> dict[str, Any]:
        return {
            "organization_id": organization_id,
            "source_kind": item.source_kind,
            "provider": item.provider,
            "provider_key": item.provider.casefold(),
            "external_id": item.external_id,
            "record_type": item.record_type,
            "title": item.title,
            "summary": item.summary,
            "source_url": str(item.source_url) if item.source_url else None,
            "published_at": item.published_at,
            "modified_at": item.modified_at,
            "retrieved_at": item.retrieved_at,
            "severity": item.severity,
            "confidence": item.confidence,
            "cve_ids": item.cve_ids,
            "cpes": item.cpes,
            "affected_products": item.affected_products,
            "mitre_attack_ids": item.mitre_attack_ids,
            "indicators": [indicator.model_dump() for indicator in item.indicators],
            "tags": item.tags,
            "sectors": item.sectors,
            "regions": item.regions,
            "markings": item.markings,
            "distribution_tlp": tlp_marking(item.markings),
            "review_status": "pending",
            "reviewed_by": None,
            "reviewed_at": None,
            "review_note": None,
            "valid_from": item.valid_from,
            "valid_until": item.valid_until,
            "revoked": item.revoked,
            "raw_evidence": item.raw_evidence,
            "raw_sha256": raw_sha256,
            "ai_analysis": item.ai_analysis.model_dump(mode="json") if item.ai_analysis else None,
            "analysis_sha256": analysis_sha256,
            "vulnerability": (
                item.vulnerability.model_dump(mode="json") if item.vulnerability else None
            ),
            "feed_id": payload.feed_id,
            "feed_version": payload.feed_version,
            "feed_generated_at": payload.generated_at,
            "last_ingested_at": now,
        }

    @staticmethod
    def _confidence(row: GlobalIntelRecordRow) -> float:
        if row.confidence is not None:
            return row.confidence
        if row.ai_analysis and isinstance(row.ai_analysis.get("confidence"), (int, float)):
            return float(row.ai_analysis["confidence"])
        return 0.5

    def _replace_observables(self, rows: list[GlobalIntelRecordRow]) -> None:
        if not rows:
            return
        self.session.execute(
            delete(GlobalIntelObservableRow).where(
                GlobalIntelObservableRow.record_id.in_([row.id for row in rows])
            )
        )
        observable_rows: list[GlobalIntelObservableRow] = []
        for row in rows:
            values: set[tuple[str, str, str]] = set()
            for cve_id in row.cve_ids:
                values.add(("cve", cve_id.upper(), cve_id))
            vulnerability_cpes = (
                row.vulnerability.get("affected_cpes", []) if row.vulnerability else []
            )
            for cpe in [*row.cpes, *vulnerability_cpes]:
                values.add(("cpe", cpe.casefold(), cpe))
                product_key = _cpe_product_key(cpe)
                if product_key:
                    values.add(("cpe_product", product_key, cpe))
            for product in row.affected_products:
                for product_key in _product_keys(product):
                    values.add(("product", product_key, product))
            for indicator in row.indicators:
                indicator_type = indicator.get("type")
                indicator_value = indicator.get("value")
                if not isinstance(indicator_type, str) or not isinstance(
                    indicator_value, str
                ):
                    continue
                for kind, normalized in _indicator_index_values(
                    indicator_type, indicator_value
                ):
                    values.add((kind, normalized, indicator_value))
            observable_rows.extend(
                GlobalIntelObservableRow(
                    record_id=row.id,
                    kind=kind,
                    value_normalized=normalized,
                    value_display=display,
                )
                for kind, normalized, display in values
            )
        self.session.add_all(observable_rows)

    def _candidate_rows(
        self,
        system_id: UUID,
        assets: list[AssetRow],
        services: list[ServiceRow],
        findings: list[FindingRow],
    ) -> list[GlobalIntelRecordRow]:
        lookup: dict[str, set[str]] = {
            "cve": {finding.cve_id.upper() for finding in findings if finding.cve_id},
            "cpe": set(),
            "cpe_product": set(),
            "product": set(),
            "ipv4": set(),
            "ipv6": set(),
            "domain": set(),
        }
        for asset in assets:
            parsed_ip = ip_address(asset.primary_ip)
            lookup[f"ipv{parsed_ip.version}"].add(str(parsed_ip))
            if asset.hostname:
                lookup["domain"].add(asset.hostname.rstrip(".").casefold())
        for service in services:
            for cpe in service.cpes:
                lookup["cpe"].add(cpe.casefold())
                product_key = _cpe_product_key(cpe)
                if product_key:
                    lookup["cpe_product"].add(product_key)
            for product in (service.product, service.service_name):
                if product:
                    lookup["product"].update(_product_keys(product))

        clauses = [
            and_(
                GlobalIntelObservableRow.kind == kind,
                GlobalIntelObservableRow.value_normalized.in_(values),
            )
            for kind, values in lookup.items()
            if values
        ]
        record_ids = set(
            self.session.scalars(
                select(GlobalIntelObservableRow.record_id)
                .where(or_(*clauses))
                .distinct()
            )
        ) if clauses else set()
        existing_threats = list(
            self.session.scalars(
                select(ThreatRow).where(
                    ThreatRow.system_id == system_id,
                    ThreatRow.source.like("intel-hub:%"),
                )
            )
        )
        for threat in existing_threats:
            value = threat.provenance.get("global_intel_record_id")
            if isinstance(value, str):
                try:
                    record_ids.add(UUID(value))
                except ValueError:
                    continue
        if not record_ids:
            return []
        return list(
            self.session.scalars(
                select(GlobalIntelRecordRow)
                .where(
                    GlobalIntelRecordRow.id.in_(record_ids),
                    GlobalIntelRecordRow.organization_id == self.organization_id,
                )
                .order_by(GlobalIntelRecordRow.modified_at.desc())
            )
        )

    @staticmethod
    def _match_assets(
        row: GlobalIntelRecordRow,
        assets: list[AssetRow],
        services: list[ServiceRow],
        findings_by_cve: dict[str, list[FindingRow]],
    ) -> dict[str, list[dict[str, Any]]]:
        matches: dict[str, list[dict[str, Any]]] = {}
        assets_by_ip = {str(ip_address(asset.primary_ip)): asset for asset in assets}
        assets_by_hostname = {
            asset.hostname.rstrip(".").casefold(): asset
            for asset in assets
            if asset.hostname
        }
        for indicator in row.indicators:
            indicator_type = indicator.get("type")
            indicator_value = indicator.get("value")
            indicator_role = indicator.get("role", "unknown")
            if not isinstance(indicator_type, str) or not isinstance(indicator_value, str):
                continue
            if indicator_role not in {"host", "destination"}:
                continue
            asset = None
            if indicator_type in {"ipv4", "ipv6"}:
                asset = assets_by_ip.get(str(ip_address(indicator_value)))
            elif indicator_type == "domain":
                asset = assets_by_hostname.get(indicator_value.rstrip(".").casefold())
            elif indicator_type == "url":
                hostname = urlsplit(indicator_value).hostname
                if hostname:
                    asset = assets_by_hostname.get(hostname.rstrip(".").casefold())
            if asset is not None:
                matches.setdefault(str(asset.id), []).append(
                    {
                        "method": f"indicator:{indicator_type}",
                        "value": indicator_value,
                        "role": indicator_role,
                        "confidence": 0.85 if indicator_role == "host" else 0.65,
                    }
                )
        for cve_id in row.cve_ids:
            for finding in findings_by_cve.get(cve_id, []):
                service = next(
                    (
                        candidate
                        for candidate in services
                        if candidate.id == finding.service_id
                    ),
                    None,
                )
                if service is not None:
                    matches.setdefault(str(service.asset_id), []).append(
                        {"method": "cve", "value": cve_id, "confidence": 0.95}
                    )
        for service in services:
            cpe_confidence = _best_cpe_match(service.cpes, row.cpes)
            if cpe_confidence is not None:
                matches.setdefault(str(service.asset_id), []).append(
                    {"method": "cpe", "value": row.cpes, "confidence": cpe_confidence}
                )
            if row.affected_products and _product_matches(service, row.affected_products):
                matches.setdefault(str(service.asset_id), []).append(
                    {
                        "method": "product",
                        "value": row.affected_products,
                        "confidence": 0.55,
                    }
                )
        return matches

    def _annotate_and_retire_vulnerability_sources(
        self,
        rows: list[GlobalIntelRecordRow],
        findings: list[FindingRow],
        system: Any,
        now: datetime,
        warnings: list[str],
    ) -> None:
        rows_by_source = {f"intel-hub:{row.id}": row for row in rows}
        for finding in findings:
            changed = False
            retired = False
            reactivated = False
            next_sources: list[dict[str, Any]] = []
            for source in finding.sources:
                source_name = source.get("source")
                row = rows_by_source.get(source_name)
                if row is None:
                    next_sources.append(source)
                    continue
                changed = True
                evidence = self.session.scalar(
                    select(FindingEvidenceRow).where(
                        FindingEvidenceRow.finding_id == finding.id,
                        FindingEvidenceRow.source_kind == "intelligence",
                        FindingEvidenceRow.source_name == source_name,
                    )
                )
                if not _is_processable(row, now):
                    retired = True
                    if evidence is not None:
                        evidence.lifecycle_status = "fixed"
                        evidence.payload = {
                            **evidence.payload,
                            "global_intel_record_id": str(row.id),
                            "markings": row.markings,
                            "distribution_tlp": row.distribution_tlp,
                            "review_status": row.review_status,
                        }
                    continue
                if evidence is not None and evidence.lifecycle_status != "open":
                    evidence.lifecycle_status = "open"
                    reactivated = True
                if evidence is not None:
                    evidence.payload = {
                        **evidence.payload,
                        "global_intel_record_id": str(row.id),
                        "markings": row.markings,
                        "distribution_tlp": row.distribution_tlp,
                        "review_status": row.review_status,
                    }
                next_sources.append(
                    {
                        **source,
                        "global_intel_record_id": str(row.id),
                        "raw_sha256": row.raw_sha256,
                        "analysis_sha256": row.analysis_sha256,
                        "markings": row.markings,
                        "exploit_status": (
                            row.vulnerability.get("exploit_status")
                            if row.vulnerability
                            else None
                        ),
                    }
                )
            if changed:
                finding.sources = next_sources
            if reactivated and finding.lifecycle_status == "fixed":
                self.repository._transition_finding_lifecycle(
                    finding,
                    "open",
                    now,
                    source_kind="intelligence",
                )
                self.repository._reassess_finding(system, finding)
            if not retired:
                continue
            # Session autoflush is intentionally disabled. Persist evidence
            # lifecycle transitions before asking SQL whether any active
            # evidence remains, otherwise the just-retired source is counted
            # as open and can leave its finding and risk active.
            self.session.flush()
            self.repository.recompute_primary_finding_evidence(finding)
            risk = self.session.scalar(select(RiskRow).where(RiskRow.finding_id == finding.id))
            has_active_evidence = self.session.scalar(
                select(func.count(FindingEvidenceRow.id)).where(
                    FindingEvidenceRow.finding_id == finding.id,
                    FindingEvidenceRow.lifecycle_status.in_(("open", "reopened")),
                )
            )
            if not has_active_evidence:
                if finding.lifecycle_status not in {
                    "accepted",
                    "false_positive",
                    "out_of_scope",
                }:
                    finding.lifecycle_status = "fixed"
                    finding.resolved_at = now
                    finding.status_updated_at = now
                if risk is not None:
                    risk.status = "closed"
                    risk.closed_at = now
                    risk.rationale = {
                        **risk.rationale,
                        "closed_reason": (
                            "The only global vulnerability source is not approved and active."
                        ),
                    }
            else:
                self.repository._reassess_finding(system, finding)
                warnings.append(
                    f"{finding.cve_id} retained other evidence after a global source retired; "
                    "its selected metrics require analyst review."
                )


def _cpe_product_key(cpe: str) -> str | None:
    parts = cpe.split(":")
    if len(parts) != 13:
        return None
    return f"{parts[2].casefold()}:{parts[3].casefold()}:{parts[4].casefold()}"


def _product_keys(value: str) -> set[str]:
    normalized = " ".join(value.casefold().split())
    keys = {normalized} if normalized else set()
    keys.update(token for token in re.findall(r"[a-z0-9][a-z0-9._+-]{2,}", normalized))
    return keys


def _indicator_index_values(indicator_type: str, value: str) -> set[tuple[str, str]]:
    if indicator_type in {"ipv4", "ipv6"}:
        return {(indicator_type, str(ip_address(value)))}
    if indicator_type == "domain":
        return {("domain", value.rstrip(".").casefold())}
    if indicator_type == "url":
        hostname = urlsplit(value).hostname
        return {("domain", hostname.rstrip(".").casefold())} if hostname else set()
    return {(indicator_type, value.casefold())}
