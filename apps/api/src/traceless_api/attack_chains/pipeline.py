"""Multi-stage CTI-to-attack-unit pipeline with bounded repair and reasoning."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy

from traceless_api.attack_chains.diagnosis import diagnose, repair
from traceless_api.attack_chains.extraction import (
    RuleBasedExtractionBackend,
    StagedExtractionBackend,
    build_units,
)
from traceless_api.attack_chains.reasoning import compile_rules, reason
from traceless_api.attack_chains.vocabulary import DEFAULT_VOCABULARY, PredicateVocabulary
from traceless_api.models.attack_chains import (
    AttackChainAnalysisResult,
    AttackChainAnalyzeRequest,
    AttackUnit,
    Predicate,
)

PIPELINE_VERSION = "reachable-attack-chain-1.0"


def normalize_document(source_text: str) -> str:
    lines = source_text.replace("\r\n", "\n").splitlines()
    return "\n".join(line.strip() for line in lines if line.strip())


class StagedExtractionPipeline:
    def __init__(
        self,
        *,
        backend: StagedExtractionBackend | None = None,
        vocabulary: PredicateVocabulary = DEFAULT_VOCABULARY,
    ) -> None:
        self.backend = backend or RuleBasedExtractionBackend()
        self.vocabulary = vocabulary

    def analyze(
        self, payload: AttackChainAnalyzeRequest, source_text: str
    ) -> AttackChainAnalysisResult:
        normalized_source = normalize_document(source_text)
        document_sha256 = hashlib.sha256(normalized_source.encode()).hexdigest()
        if payload.candidate_units:
            units = deepcopy(payload.candidate_units)
            extracted_initial: list[Predicate] = []
            backend_name = "explicit-candidate-units"
        else:
            units, extracted_initial = build_units(normalized_source, self.backend)
            backend_name = self.backend.name
        if not units:
            raise ValueError(
                "No state-changing attack behaviors could be extracted from the source"
            )

        units = [self._canonical_unit(unit) for unit in units]
        initial_facts = self._canonical_predicates([*payload.initial_facts, *extracted_initial])
        evidence_backed_initial = {fact.key for fact in extracted_initial}
        goal = self.vocabulary.canonicalize(payload.goal or units[-1].postconditions[-1])
        self._validate_reasoning_inputs(initial_facts, goal)

        repair_actions = []
        diagnosis_rounds = 0
        for repair_round in range(1, payload.max_repair_rounds + 1):
            diagnosis_rounds += 1
            issues = diagnose(units, initial_facts, self.vocabulary)
            repairable = [
                issue
                for issue in issues
                if issue.issue_type in {"unsupported_precondition", "invalid_predicate"}
            ]
            if not repairable:
                break
            units, initial_facts, actions = repair(
                units,
                initial_facts,
                repairable,
                self.vocabulary,
                repair_round=repair_round,
                evidence_backed_initial_facts=evidence_backed_initial,
            )
            repair_actions.extend(actions)
            if not any(action.action != "no_safe_repair" for action in actions):
                break
        diagnosis_rounds += 1
        final_issues = diagnose(units, initial_facts, self.vocabulary)
        invalid = [
            issue for issue in final_issues if issue.issue_type == "invalid_predicate"
        ]
        if invalid:
            raise ValueError(
                "Attack-chain normalization left predicates outside the closed vocabulary"
            )
        rules = compile_rules(units)
        reasoning = reason(
            units,
            initial_facts,
            goal,
            max_paths=payload.max_paths,
        )
        return AttackChainAnalysisResult(
            pipeline_version=PIPELINE_VERSION,
            vocabulary_version=self.vocabulary.version,
            extraction_backend=backend_name,
            document_sha256=document_sha256,
            units=units,
            initial_facts=initial_facts,
            goal=goal,
            rules=rules,
            reasoning=reasoning,
            issues=final_issues,
            repair_actions=repair_actions,
            diagnosis_rounds=min(diagnosis_rounds, 3),
        )

    def _canonical_unit(self, unit: AttackUnit) -> AttackUnit:
        return unit.model_copy(
            update={
                "preconditions": self._canonical_predicates(unit.preconditions),
                "postconditions": self._canonical_predicates(unit.postconditions),
            }
        )

    def _canonical_predicates(self, predicates: list[Predicate]) -> list[Predicate]:
        canonical = [self.vocabulary.canonicalize(predicate) for predicate in predicates]
        return list({predicate.key: predicate for predicate in canonical}.values())

    def _validate_reasoning_inputs(
        self,
        initial_facts: list[Predicate],
        goal: Predicate,
    ) -> None:
        invalid: list[str] = []
        for predicate in [*initial_facts, goal]:
            error = self.vocabulary.validation_error(predicate)
            if error is not None:
                invalid.append(error)
        if invalid:
            raise ValueError(
                "Attack-chain reasoning inputs contain predicates outside the closed "
                f"vocabulary: {'; '.join(sorted(set(invalid)))}"
            )


def analyze_document(
    payload: AttackChainAnalyzeRequest,
    source_text: str,
    *,
    backend: StagedExtractionBackend | None = None,
    vocabulary: PredicateVocabulary = DEFAULT_VOCABULARY,
) -> AttackChainAnalysisResult:
    return StagedExtractionPipeline(backend=backend, vocabulary=vocabulary).analyze(
        payload,
        source_text,
    )


def analysis_input_sha256(payload: AttackChainAnalyzeRequest, source_text: str) -> str:
    material = {
        "source_sha256": hashlib.sha256(normalize_document(source_text).encode()).hexdigest(),
        "initial_facts": sorted(predicate.key for predicate in payload.initial_facts),
        "goal": payload.goal.key if payload.goal is not None else None,
        "candidate_units": [unit.model_dump(mode="json") for unit in payload.candidate_units],
        "source_record_id": str(payload.source_record_id) if payload.source_record_id else None,
        "title": payload.title,
        "markings": sorted(payload.markings),
        "retain_source_text": payload.retain_source_text,
        "max_repair_rounds": payload.max_repair_rounds,
        "max_paths": payload.max_paths,
        "pipeline_version": PIPELINE_VERSION,
        "vocabulary_version": DEFAULT_VOCABULARY.version,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()
