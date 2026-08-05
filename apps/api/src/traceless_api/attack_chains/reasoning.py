"""Ground Datalog-style compilation, forward chaining and proof reconstruction."""

from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass

from traceless_api.models.attack_chains import (
    AttackPath,
    AttackUnit,
    BranchChoice,
    Predicate,
    ReasoningResult,
    Rule,
)

_MAX_DERIVED_FACTS = 10_000
_MAX_PROOF_COMBINATIONS = 5_000
_MAX_CONTEXTS_PER_FACT = 100


def _short_hash(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def compile_rules(units: list[AttackUnit]) -> list[Rule]:
    rules: list[Rule] = []
    for unit in sorted(units, key=lambda item: (item.behavior.sequence, item.unit_id)):
        for index, postcondition in enumerate(unit.postconditions):
            rules.append(
                Rule(
                    rule_id=_short_hash(unit.unit_id, str(index), postcondition.key),
                    unit_id=unit.unit_id,
                    head=postcondition,
                    body=unit.preconditions,
                    branch=unit.branch,
                )
            )
    return rules


@dataclass(frozen=True, slots=True)
class _Proof:
    unit_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]
    fact_keys: frozenset[str]
    choices: tuple[tuple[str, str], ...]


def _merge_choices(
    left: tuple[tuple[str, str], ...], right: tuple[tuple[str, str], ...]
) -> tuple[tuple[str, str], ...] | None:
    combined = dict(left)
    for group, option in right:
        current = combined.get(group)
        if current is not None and current != option:
            return None
        combined[group] = option
    return tuple(sorted(combined.items()))


def _branch_tuple(branch: BranchChoice | None) -> tuple[tuple[str, str], ...]:
    return ((branch.group, branch.option),) if branch is not None else ()


def reason(
    units: list[AttackUnit],
    initial_facts: list[Predicate],
    goal: Predicate,
    *,
    max_paths: int = 20,
) -> ReasoningResult:
    rules = compile_rules(units)
    known: dict[str, Predicate] = {fact.key: fact for fact in initial_facts}
    initial_keys = frozenset(known)
    empty_context: tuple[tuple[str, str], ...] = ()
    contexts: dict[str, set[tuple[tuple[str, str], ...]]] = {
        fact.key: {empty_context} for fact in initial_facts
    }
    derivations: dict[str, list[Rule]] = {}
    fired_contexts: set[tuple[str, tuple[tuple[str, str], ...]]] = set()

    changed = True
    while changed:
        changed = False
        for rule in rules:
            body_contexts = [contexts.get(atom.key, set()) for atom in rule.body]
            if any(not values for values in body_contexts):
                continue
            combinations = itertools.product(*body_contexts) if body_contexts else [()]
            for index, combination in enumerate(combinations):
                if index >= _MAX_PROOF_COMBINATIONS:
                    break
                merged = _branch_tuple(rule.branch)
                compatible = True
                for context in combination:
                    candidate = _merge_choices(merged, context)
                    if candidate is None:
                        compatible = False
                        break
                    merged = candidate
                if not compatible:
                    continue
                fire_key = (rule.rule_id, merged)
                if fire_key in fired_contexts:
                    continue
                fired_contexts.add(fire_key)
                head_derivations = derivations.setdefault(rule.head.key, [])
                if not any(item.rule_id == rule.rule_id for item in head_derivations):
                    head_derivations.append(rule)
                head_contexts = contexts.setdefault(rule.head.key, set())
                if merged not in head_contexts:
                    if len(head_contexts) >= _MAX_CONTEXTS_PER_FACT:
                        continue
                    head_contexts.add(merged)
                    if rule.head.key not in known:
                        if len(known) >= _MAX_DERIVED_FACTS:
                            raise ValueError(
                                "attack-chain reasoning exceeded the derived-fact limit"
                            )
                        known[rule.head.key] = rule.head
                    changed = True

    order_by_unit = {unit.unit_id: unit.behavior.sequence for unit in units}
    confidence_by_unit = {unit.unit_id: unit.behavior.confidence for unit in units}
    memo: dict[str, list[_Proof]] = {}

    def prove(fact_key: str, stack: frozenset[str]) -> list[_Proof]:
        if fact_key in initial_keys:
            return [_Proof((), (), frozenset({fact_key}), ())]
        if fact_key in stack:
            return []
        if fact_key in memo:
            return memo[fact_key]
        proofs: list[_Proof] = []
        for rule in derivations.get(fact_key, []):
            body_proofs = [prove(atom.key, stack | {fact_key}) for atom in rule.body]
            if any(not candidates for candidates in body_proofs):
                continue
            combinations = itertools.product(*body_proofs) if body_proofs else [()]
            for index, combination in enumerate(combinations):
                if index >= _MAX_PROOF_COMBINATIONS:
                    break
                choices = _branch_tuple(rule.branch)
                fact_keys = {fact_key}
                unit_ids = {rule.unit_id}
                rule_ids = {rule.rule_id}
                compatible = True
                for proof in combination:
                    merged = _merge_choices(choices, proof.choices)
                    if merged is None:
                        compatible = False
                        break
                    choices = merged
                    fact_keys.update(proof.fact_keys)
                    unit_ids.update(proof.unit_ids)
                    rule_ids.update(proof.rule_ids)
                if not compatible:
                    continue
                proofs.append(
                    _Proof(
                        unit_ids=tuple(
                            sorted(
                                unit_ids,
                                key=lambda value: (
                                    order_by_unit.get(value, 10_000),
                                    value,
                                ),
                            )
                        ),
                        rule_ids=tuple(sorted(rule_ids)),
                        fact_keys=frozenset(fact_keys),
                        choices=choices,
                    )
                )
                if len(proofs) >= max_paths * 4:
                    break
        deduplicated: dict[
            tuple[tuple[str, ...], tuple[tuple[str, str], ...]], _Proof
        ] = {}
        for proof in proofs:
            deduplicated[(proof.unit_ids, proof.choices)] = proof
        memo[fact_key] = list(deduplicated.values())[: max_paths * 2]
        return memo[fact_key]

    proof_models: list[AttackPath] = []
    if goal.key in known:
        for proof in prove(goal.key, frozenset())[:max_paths]:
            unit_confidences = [confidence_by_unit[item] for item in proof.unit_ids]
            facts = [
                known[key]
                for key in sorted(proof.fact_keys - initial_keys)
                if key in known
            ]
            proof_models.append(
                AttackPath(
                    path_id=_short_hash(goal.key, *proof.unit_ids, repr(proof.choices)),
                    unit_ids=list(proof.unit_ids),
                    rule_ids=list(proof.rule_ids),
                    derived_facts=facts,
                    branch_choices=dict(proof.choices),
                    confidence=min(unit_confidences) if unit_confidences else 1.0,
                )
            )

    unresolved = {
        atom.key: atom
        for rule in rules
        for atom in rule.body
        if atom.key not in known
    }
    reachable = bool(proof_models)
    return ReasoningResult(
        reachable=reachable,
        goal=goal,
        initial_facts=[known[key] for key in sorted(initial_keys)],
        derived_facts=[known[key] for key in sorted(set(known) - set(initial_keys))],
        fired_rule_ids=sorted({rule_id for rule_id, _ in fired_contexts}),
        paths=proof_models,
        unresolved_preconditions=[unresolved[key] for key in sorted(unresolved)],
    )
