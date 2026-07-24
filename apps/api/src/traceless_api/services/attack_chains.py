"""Persistence and authorization boundary for reachable attack-chain analysis."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select

from traceless_api.attack_chains.pipeline import analysis_input_sha256, analyze_document
from traceless_api.attack_chains.reasoning import reason
from traceless_api.attack_chains.vocabulary import DEFAULT_VOCABULARY
from traceless_api.core.markings import permits_automated_processing, tlp_marking
from traceless_api.db.attack_chain_models import AttackChainAnalysisRow
from traceless_api.db.models import GlobalIntelRecordRow, OrganizationRow
from traceless_api.models.attack_chains import (
    AttackChainAnalysisPage,
    AttackChainAnalysisResult,
    AttackChainAnalysisSummary,
    AttackChainAnalysisView,
    AttackChainAnalyzeRequest,
    AttackChainReasonRequest,
    ReasoningResult,
)
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalNotFoundError,
    OperationalRepository,
)


class AttackChainService:
    def __init__(self, repository: OperationalRepository) -> None:
        if repository.organization_id is None:
            raise OperationalConflictError(
                "Attack-chain analysis requires an explicit organization scope"
            )
        self.repository = repository
        self.session = repository.session
        self.organization_id = repository.organization_id

    def analyze(
        self,
        payload: AttackChainAnalyzeRequest,
        actor: str,
    ) -> tuple[AttackChainAnalysisView, bool]:
        self.repository.ensure_organization()
        organization = self.session.scalar(
            select(OrganizationRow)
            .where(OrganizationRow.id == self.organization_id)
            .with_for_update()
        )
        if organization is None:  # pragma: no cover - ensure_organization created it
            raise OperationalConflictError("The analysis organization is unavailable")

        record = self._source_record(payload.source_record_id)
        source_text = payload.source_text or self._record_text(record)
        source_title = payload.title or (
            record.title if record is not None else "Untitled CTI report"
        )
        markings = record.markings if record is not None else payload.markings
        if not permits_automated_processing(markings):
            raise OperationalConflictError(
                "TLP:RED material requires named-recipient controls and cannot be analyzed here"
            )
        distribution_tlp = record.distribution_tlp if record is not None else tlp_marking(markings)
        if len(source_text.encode("utf-8")) > 1_000_000:
            raise OperationalConflictError("Attack-chain source text exceeds 1,000,000 bytes")
        effective_payload = payload.model_copy(
            update={
                "title": source_title,
                "markings": markings,
            }
        )
        if distribution_tlp == "TLP:RED":
            raise OperationalConflictError("TLP:RED material cannot enter automated analysis")

        input_sha256 = analysis_input_sha256(effective_payload, source_text)
        existing = self.session.scalar(
            select(AttackChainAnalysisRow).where(
                AttackChainAnalysisRow.organization_id == self.organization_id,
                AttackChainAnalysisRow.input_sha256 == input_sha256,
            )
        )
        if existing is not None:
            return self._view(existing), True

        try:
            analysis = analyze_document(effective_payload, source_text)
        except ValueError as error:
            raise OperationalConflictError(str(error)) from error
        result = analysis.model_dump(mode="json")
        repair_rounds = max((action.round for action in analysis.repair_actions), default=0)
        row = AttackChainAnalysisRow(
            organization_id=self.organization_id,
            source_record_id=record.id if record is not None else None,
            source_title=source_title,
            distribution_tlp=distribution_tlp,
            input_sha256=input_sha256,
            source_sha256=analysis.document_sha256,
            source_text=source_text if effective_payload.retain_source_text else None,
            source_text_retained=effective_payload.retain_source_text,
            pipeline_version=analysis.pipeline_version,
            vocabulary_version=analysis.vocabulary_version,
            status="reachable" if analysis.reasoning.reachable else "unreachable",
            reachable=analysis.reasoning.reachable,
            unit_count=len(analysis.units),
            path_count=len(analysis.reasoning.paths),
            issue_count=len(analysis.issues),
            repair_rounds=repair_rounds,
            analysis=result,
            created_by=actor,
        )
        self.session.add(row)
        self.session.flush()
        self.repository.audit(
            actor,
            "attack_chain.analysis_created",
            "attack_chain_analysis",
            row.id,
            {
                "source_record_id": str(row.source_record_id) if row.source_record_id else None,
                "input_sha256": row.input_sha256,
                "reachable": row.reachable,
                "unit_count": row.unit_count,
                "path_count": row.path_count,
                "issue_count": row.issue_count,
                "source_text_retained": row.source_text_retained,
            },
        )
        return self._view(row), False

    def list(self, *, limit: int, offset: int) -> AttackChainAnalysisPage:
        filters = (AttackChainAnalysisRow.organization_id == self.organization_id,)
        total = self.session.scalar(
            select(func.count()).select_from(AttackChainAnalysisRow).where(*filters)
        ) or 0
        rows = list(
            self.session.scalars(
                select(AttackChainAnalysisRow)
                .where(*filters)
                .order_by(AttackChainAnalysisRow.created_at.desc(), AttackChainAnalysisRow.id)
                .offset(offset)
                .limit(limit)
            )
        )
        return AttackChainAnalysisPage(
            items=[self._summary(row) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
            has_more=offset + len(rows) < total,
        )

    def get(self, analysis_id: UUID) -> AttackChainAnalysisView:
        return self._view(self._row(analysis_id))

    def reason_again(
        self,
        analysis_id: UUID,
        payload: AttackChainReasonRequest,
    ) -> ReasoningResult:
        row = self._row(analysis_id)
        analysis = AttackChainAnalysisResult.model_validate(row.analysis)
        if analysis.vocabulary_version != DEFAULT_VOCABULARY.version:
            raise OperationalConflictError(
                "The stored analysis uses an unsupported predicate vocabulary version"
            )
        initial_facts = [
            DEFAULT_VOCABULARY.canonicalize(predicate)
            for predicate in payload.initial_facts
        ]
        goal = DEFAULT_VOCABULARY.canonicalize(payload.goal)
        invalid = [
            error
            for predicate in [*initial_facts, goal]
            if (error := DEFAULT_VOCABULARY.validation_error(predicate)) is not None
        ]
        if invalid:
            raise OperationalConflictError(
                "Reasoning inputs contain predicates outside the stored vocabulary: "
                + "; ".join(sorted(set(invalid)))
            )
        return reason(
            analysis.units,
            initial_facts,
            goal,
            max_paths=payload.max_paths,
        )

    def _row(self, analysis_id: UUID) -> AttackChainAnalysisRow:
        row = self.session.scalar(
            select(AttackChainAnalysisRow).where(
                AttackChainAnalysisRow.id == analysis_id,
                AttackChainAnalysisRow.organization_id == self.organization_id,
            )
        )
        if row is None:
            raise OperationalNotFoundError("Attack-chain analysis was not found")
        return row

    def _source_record(self, record_id: UUID | None) -> GlobalIntelRecordRow | None:
        if record_id is None:
            return None
        row = self.session.scalar(
            select(GlobalIntelRecordRow).where(
                GlobalIntelRecordRow.id == record_id,
                GlobalIntelRecordRow.organization_id == self.organization_id,
                GlobalIntelRecordRow.distribution_tlp != "TLP:RED",
            )
        )
        if row is None:
            raise OperationalNotFoundError("Global intelligence record was not found")
        now = datetime.now(UTC)
        if (
            row.review_status != "approved"
            or row.revoked
            or (row.valid_from is not None and _as_aware(row.valid_from) > now)
            or (row.valid_until is not None and _as_aware(row.valid_until) <= now)
        ):
            raise OperationalConflictError(
                "Global intelligence record is not currently approved and processable"
            )
        return row

    @staticmethod
    def _record_text(record: GlobalIntelRecordRow | None) -> str:
        if record is None:
            raise OperationalConflictError("The source record is unavailable")
        raw = json.dumps(
            record.raw_evidence,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        return "\n\n".join((record.title, record.summary, raw))

    @staticmethod
    def _summary(row: AttackChainAnalysisRow) -> AttackChainAnalysisSummary:
        return AttackChainAnalysisSummary(
            id=row.id,
            source_record_id=row.source_record_id,
            source_title=row.source_title,
            distribution_tlp=row.distribution_tlp,
            input_sha256=row.input_sha256,
            source_sha256=row.source_sha256,
            source_text_retained=row.source_text_retained,
            status=row.status,
            reachable=row.reachable,
            unit_count=row.unit_count,
            path_count=row.path_count,
            issue_count=row.issue_count,
            repair_rounds=row.repair_rounds,
            created_by=row.created_by,
            created_at=row.created_at,
        )

    @staticmethod
    def _view(row: AttackChainAnalysisRow) -> AttackChainAnalysisView:
        return AttackChainAnalysisView(
            id=row.id,
            source_record_id=row.source_record_id,
            source_title=row.source_title,
            distribution_tlp=row.distribution_tlp,
            input_sha256=row.input_sha256,
            source_sha256=row.source_sha256,
            source_text_retained=row.source_text_retained,
            status=row.status,
            reachable=row.reachable,
            unit_count=row.unit_count,
            path_count=row.path_count,
            issue_count=row.issue_count,
            repair_rounds=row.repair_rounds,
            created_by=row.created_by,
            created_at=row.created_at,
            analysis=AttackChainAnalysisResult.model_validate(row.analysis),
        )


def _as_aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
