"""Strict API and reasoning models for reachable attack-chain analysis."""

from __future__ import annotations

import json
import re
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator

from traceless_api.core.markings import normalize_markings
from traceless_api.models.common import StrictModel

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_UNIT_ID = re.compile(r"^[A-Za-z0-9:._/-]{1,120}$")

BehaviorClass = Literal[
    "user_action",
    "delivery",
    "download",
    "exploitation",
    "execute",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "communication",
    "exfiltration",
    "impact",
    "other",
]
DiagnosisIssueType = Literal[
    "unsupported_precondition",
    "future_dependency",
    "invalid_predicate",
    "branch_merge",
    "non_progressing_unit",
]
DiagnosisSeverity = Literal["low", "medium", "high"]


class Predicate(StrictModel):
    """Ground predicate instance used as both a fact and a rule atom."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    category: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=64)
    arguments: tuple[str, ...] = Field(min_length=1, max_length=8)

    @field_validator("category", "name")
    @classmethod
    def identifiers_are_safe(cls, value: str) -> str:
        normalized = value.casefold()
        if not _IDENTIFIER.fullmatch(normalized):
            raise ValueError("predicate identifiers must use lower snake_case")
        return normalized

    @field_validator("arguments")
    @classmethod
    def arguments_are_bounded(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value or len(value) > 500 for value in values):
            raise ValueError("predicate arguments must contain 1-500 characters")
        return values

    @property
    def identifier(self) -> str:
        return f"{self.category}.{self.name}"

    @property
    def key(self) -> str:
        encoded = json.dumps(
            self.arguments,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return f"{self.identifier}:{encoded}"


class EvidenceSpan(StrictModel):
    channel: Literal["local", "global", "explicit", "heuristic"]
    quote: str = Field(min_length=1, max_length=2_000)
    sentence_index: int | None = Field(default=None, ge=0)
    start: int | None = Field(default=None, ge=0)
    end: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def offsets_are_ordered(self) -> EvidenceSpan:
        if self.start is not None and self.end is not None and self.end <= self.start:
            raise ValueError("evidence end must be greater than start")
        return self


class BranchChoice(StrictModel):
    group: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9:._/-]+$")
    option: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9:._/-]+$")


class AttackBehavior(StrictModel):
    behavior_class: BehaviorClass
    summary: str = Field(min_length=2, max_length=2_000)
    sequence: int = Field(ge=0, le=1_000)
    attack_ids: list[str] = Field(default_factory=list, max_length=50)
    confidence: float = Field(default=0.7, ge=0, le=1)
    evidence: list[EvidenceSpan] = Field(default_factory=list, max_length=20)

    @field_validator("attack_ids")
    @classmethod
    def attack_ids_are_normalized(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            candidate = value.upper()
            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", candidate):
                raise ValueError("ATT&CK IDs must use T#### or T####.###")
            if candidate not in normalized:
                normalized.append(candidate)
        return normalized


class AttackUnit(StrictModel):
    unit_id: str = Field(min_length=1, max_length=120)
    behavior: AttackBehavior
    preconditions: list[Predicate] = Field(default_factory=list, max_length=20)
    postconditions: list[Predicate] = Field(min_length=1, max_length=20)
    branch: BranchChoice | None = None

    @field_validator("unit_id")
    @classmethod
    def unit_id_is_safe(cls, value: str) -> str:
        if not _UNIT_ID.fullmatch(value):
            raise ValueError("unit_id contains unsupported characters")
        return value

    @model_validator(mode="after")
    def atoms_are_unique(self) -> AttackUnit:
        for field_name in ("preconditions", "postconditions"):
            atoms = getattr(self, field_name)
            keys = [atom.key for atom in atoms]
            if len(keys) != len(set(keys)):
                raise ValueError(f"{field_name} must contain unique predicates")
        return self


class DiagnosisIssue(StrictModel):
    issue_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    issue_type: DiagnosisIssueType
    severity: DiagnosisSeverity
    unit_id: str
    predicate: Predicate | None = None
    message: str = Field(min_length=2, max_length=2_000)
    suggestion: str = Field(min_length=2, max_length=2_000)


class RepairAction(StrictModel):
    round: int = Field(ge=1, le=2)
    issue_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    action: Literal[
        "add_initial_fact",
        "canonicalize_predicate",
        "no_safe_repair",
    ]
    before: str | None = Field(default=None, max_length=2_000)
    after: str | None = Field(default=None, max_length=2_000)


class Rule(StrictModel):
    rule_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    unit_id: str
    head: Predicate
    body: list[Predicate] = Field(default_factory=list, max_length=20)
    branch: BranchChoice | None = None


class AttackPath(StrictModel):
    path_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    unit_ids: list[str]
    rule_ids: list[str]
    derived_facts: list[Predicate]
    branch_choices: dict[str, str]
    confidence: float = Field(ge=0, le=1)


class ReasoningResult(StrictModel):
    reachable: bool
    goal: Predicate
    initial_facts: list[Predicate]
    derived_facts: list[Predicate]
    fired_rule_ids: list[str]
    paths: list[AttackPath]
    unresolved_preconditions: list[Predicate]


class AttackChainAnalyzeRequest(StrictModel):
    source_text: str | None = Field(default=None, min_length=1, max_length=1_000_000)
    source_record_id: UUID | None = None
    title: str | None = Field(default=None, min_length=1, max_length=500)
    markings: list[str] = Field(default_factory=lambda: ["TLP:AMBER"], max_length=20)
    initial_facts: list[Predicate] = Field(default_factory=list, max_length=500)
    goal: Predicate | None = None
    candidate_units: list[AttackUnit] = Field(default_factory=list, max_length=200)
    max_repair_rounds: int = Field(default=2, ge=0, le=2)
    max_paths: int = Field(default=20, ge=1, le=50)
    retain_source_text: bool = False

    @field_validator("markings")
    @classmethod
    def markings_are_normalized(cls, values: list[str]) -> list[str]:
        return normalize_markings(values)

    @model_validator(mode="after")
    def source_is_available(self) -> AttackChainAnalyzeRequest:
        supplied = int(self.source_text is not None) + int(self.source_record_id is not None)
        if supplied != 1:
            raise ValueError("exactly one of source_text or source_record_id is required")
        return self


class AttackChainReasonRequest(StrictModel):
    initial_facts: list[Predicate] = Field(max_length=500)
    goal: Predicate
    max_paths: int = Field(default=20, ge=1, le=50)


class AttackChainAnalysisResult(StrictModel):
    pipeline_version: str
    vocabulary_version: str
    extraction_backend: str
    document_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    units: list[AttackUnit]
    initial_facts: list[Predicate]
    goal: Predicate
    rules: list[Rule]
    reasoning: ReasoningResult
    issues: list[DiagnosisIssue]
    repair_actions: list[RepairAction]
    diagnosis_rounds: int = Field(ge=1, le=3)


class AttackChainAnalysisSummary(StrictModel):
    id: UUID
    source_record_id: UUID | None
    source_title: str
    distribution_tlp: str
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_text_retained: bool
    status: Literal["reachable", "unreachable"]
    reachable: bool
    unit_count: int = Field(ge=0)
    path_count: int = Field(ge=0)
    issue_count: int = Field(ge=0)
    repair_rounds: int = Field(ge=0, le=2)
    created_by: str
    created_at: AwareDatetime


class AttackChainAnalysisView(AttackChainAnalysisSummary):
    analysis: AttackChainAnalysisResult


class AttackChainAnalyzeResponse(StrictModel):
    analysis: AttackChainAnalysisView
    reused: bool


class AttackChainAnalysisPage(StrictModel):
    items: list[AttackChainAnalysisSummary]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)
    has_more: bool

    @model_validator(mode="after")
    def pagination_is_consistent(self) -> AttackChainAnalysisPage:
        if len(self.items) > self.limit:
            raise ValueError("page contains more items than its declared limit")
        expected = self.offset + len(self.items) < self.total
        if self.has_more != expected:
            raise ValueError("has_more is inconsistent with total, offset and items")
        return self
