"""Deterministic dependency diagnosis and bounded issue-driven repair."""

from __future__ import annotations

import hashlib
import itertools
from collections import defaultdict
from copy import deepcopy

from traceless_api.attack_chains.vocabulary import PredicateVocabulary
from traceless_api.models.attack_chains import (
    AttackUnit,
    DiagnosisIssue,
    Predicate,
    RepairAction,
)


def _issue_id(issue_type: str, unit_id: str, predicate_key: str = "") -> str:
    return hashlib.sha256(f"{issue_type}|{unit_id}|{predicate_key}".encode()).hexdigest()[:16]


def diagnose(
    units: list[AttackUnit],
    initial_facts: list[Predicate],
    vocabulary: PredicateVocabulary,
) -> list[DiagnosisIssue]:
    issues: list[DiagnosisIssue] = []
    initial_keys = {fact.key for fact in initial_facts}
    producers: dict[str, list[AttackUnit]] = defaultdict(list)
    for unit in units:
        for postcondition in unit.postconditions:
            producers[postcondition.key].append(unit)

    produced_before = set(initial_keys)
    for unit in sorted(units, key=lambda item: (item.behavior.sequence, item.unit_id)):
        for predicate in [*unit.preconditions, *unit.postconditions]:
            error = vocabulary.validation_error(predicate)
            if error is not None:
                issues.append(
                    DiagnosisIssue(
                        issue_id=_issue_id("invalid_predicate", unit.unit_id, predicate.key),
                        issue_type="invalid_predicate",
                        severity="high",
                        unit_id=unit.unit_id,
                        predicate=predicate,
                        message=error,
                        suggestion="Map the condition to a predicate in the closed vocabulary.",
                    )
                )
        for predicate in unit.preconditions:
            if predicate.key in produced_before:
                continue
            later = [
                producer
                for producer in producers.get(predicate.key, [])
                if producer.behavior.sequence >= unit.behavior.sequence
            ]
            issue_type = "future_dependency" if later else "unsupported_precondition"
            issues.append(
                DiagnosisIssue(
                    issue_id=_issue_id(issue_type, unit.unit_id, predicate.key),
                    issue_type=issue_type,
                    severity="high" if later else "medium",
                    unit_id=unit.unit_id,
                    predicate=predicate,
                    message=(
                        f"{predicate.key} is produced only by a later unit."
                        if later
                        else f"{predicate.key} is neither an initial fact nor an earlier effect."
                    ),
                    suggestion=(
                        "Review step order or move the condition to the correct behavior."
                        if later
                        else "Add an evidence-backed initial fact or a missing intermediate unit."
                    ),
                )
            )

        pre_keys = {predicate.key for predicate in unit.preconditions}
        post_keys = {predicate.key for predicate in unit.postconditions}
        if post_keys and post_keys.issubset(pre_keys):
            issues.append(
                DiagnosisIssue(
                    issue_id=_issue_id("non_progressing_unit", unit.unit_id),
                    issue_type="non_progressing_unit",
                    severity="medium",
                    unit_id=unit.unit_id,
                    message="The unit produces no state that was not already required.",
                    suggestion="Restore the state-changing postcondition supported by the report.",
                )
            )

        branch_candidates: list[list[tuple[str, str] | None]] = []
        mentioned_choices: dict[str, set[str]] = defaultdict(set)
        for predicate in unit.preconditions:
            if predicate.key in initial_keys:
                branch_candidates.append([None])
                continue
            candidates: list[tuple[str, str] | None] = []
            for producer in producers.get(predicate.key, []):
                if producer.behavior.sequence >= unit.behavior.sequence:
                    continue
                if producer.branch is None:
                    candidates.append(None)
                    continue
                choice = (producer.branch.group, producer.branch.option)
                candidates.append(choice)
                mentioned_choices[choice[0]].add(choice[1])
            if candidates:
                branch_candidates.append(candidates)
        if branch_candidates and not _has_compatible_branch_selection(branch_candidates):
            rendered = ", ".join(
                f"{group}={{{', '.join(sorted(options))}}}"
                for group, options in sorted(mentioned_choices.items())
            )
            issues.append(
                DiagnosisIssue(
                    issue_id=_issue_id("branch_merge", unit.unit_id, rendered),
                    issue_type="branch_merge",
                    severity="high",
                    unit_id=unit.unit_id,
                    message=(
                        "The unit requires mutually exclusive branch states"
                        + (f": {rendered}." if rendered else ".")
                    ),
                    suggestion=(
                        "Split the downstream unit by branch or remove the "
                        "unsupported dependency."
                    ),
                )
            )
        produced_before.update(post_keys)

    unique = {issue.issue_id: issue for issue in issues}
    return sorted(
        unique.values(),
        key=lambda issue: (
            {"high": 0, "medium": 1, "low": 2}[issue.severity],
            issue.unit_id,
            issue.issue_id,
        ),
    )


def _has_compatible_branch_selection(
    candidates: list[list[tuple[str, str] | None]],
) -> bool:
    for combination in itertools.product(*candidates):
        selected: dict[str, str] = {}
        compatible = True
        for choice in combination:
            if choice is None:
                continue
            group, option = choice
            existing = selected.get(group)
            if existing is not None and existing != option:
                compatible = False
                break
            selected[group] = option
        if compatible:
            return True
    return False


def repair(
    units: list[AttackUnit],
    initial_facts: list[Predicate],
    issues: list[DiagnosisIssue],
    vocabulary: PredicateVocabulary,
    *,
    repair_round: int,
    evidence_backed_initial_facts: set[str],
) -> tuple[list[AttackUnit], list[Predicate], list[RepairAction]]:
    repaired_units = deepcopy(units)
    repaired_initial = list(initial_facts)
    initial_keys = {fact.key for fact in repaired_initial}
    actions: list[RepairAction] = []
    unit_map = {unit.unit_id: unit for unit in repaired_units}

    for issue in issues:
        if issue.issue_type == "unsupported_precondition" and issue.predicate is not None:
            predicate = issue.predicate
            if (
                predicate.key in evidence_backed_initial_facts
                and vocabulary.initial_fact_eligible(predicate)
                and predicate.key not in initial_keys
            ):
                repaired_initial.append(predicate)
                initial_keys.add(predicate.key)
                actions.append(
                    RepairAction(
                        round=repair_round,
                        issue_id=issue.issue_id,
                        action="add_initial_fact",
                        before=None,
                        after=predicate.key,
                    )
                )
                continue
        if issue.issue_type == "invalid_predicate" and issue.predicate is not None:
            unit = unit_map.get(issue.unit_id)
            if unit is not None:
                canonical = vocabulary.canonicalize(issue.predicate)
                if vocabulary.validation_error(canonical) is None:
                    for field_name in ("preconditions", "postconditions"):
                        values = getattr(unit, field_name)
                        replacement = [
                            canonical if value.key == issue.predicate.key else value
                            for value in values
                        ]
                        setattr(unit, field_name, replacement)
                    actions.append(
                        RepairAction(
                            round=repair_round,
                            issue_id=issue.issue_id,
                            action="canonicalize_predicate",
                            before=issue.predicate.key,
                            after=canonical.key,
                        )
                    )
                    continue
        actions.append(
            RepairAction(
                round=repair_round,
                issue_id=issue.issue_id,
                action="no_safe_repair",
                before=issue.predicate.key if issue.predicate else None,
                after=None,
            )
        )
    return repaired_units, repaired_initial, actions
