"""Reproducible, curated quality gate for deterministic attack-chain extraction."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from traceless_api.attack_chains.extraction import RuleBasedExtractionBackend, build_units
from traceless_api.attack_chains.pipeline import analyze_document
from traceless_api.models.attack_chains import AttackChainAnalyzeRequest


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    cases: int
    behavior_precision: float
    behavior_recall: float
    behavior_f1: float
    attack_id_f1: float
    evidence_coverage: float
    reachability_accuracy: float
    brier_score: float
    expected_calibration_error: float
    language_recall: dict[str, float]

    def as_dict(self) -> dict[str, Any]:
        return {
            "cases": self.cases,
            "behavior_precision": self.behavior_precision,
            "behavior_recall": self.behavior_recall,
            "behavior_f1": self.behavior_f1,
            "attack_id_f1": self.attack_id_f1,
            "evidence_coverage": self.evidence_coverage,
            "reachability_accuracy": self.reachability_accuracy,
            "brier_score": self.brier_score,
            "expected_calibration_error": self.expected_calibration_error,
            "language_recall": self.language_recall,
        }


def load_cases(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not value:
        raise ValueError("attack-chain evaluation dataset must be a non-empty list")
    return value


def evaluate_cases(cases: list[dict[str, Any]]) -> EvaluationMetrics:
    backend = RuleBasedExtractionBackend()
    behavior_tp = behavior_fp = behavior_fn = 0
    attack_tp = attack_fp = attack_fn = 0
    evidence_units = total_units = 0
    reachability_correct = reachability_total = 0
    language_counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    calibration: list[tuple[float, int]] = []

    for case in cases:
        text = str(case["text"])
        expected_behaviors = set(case.get("expected_behaviors", []))
        expected_attack_ids = {str(value).upper() for value in case.get("expected_attack_ids", [])}
        units, _ = build_units(text, backend)
        predicted_behaviors = {unit.behavior.behavior_class for unit in units}
        predicted_attack_ids = {
            attack_id for unit in units for attack_id in unit.behavior.attack_ids
        }
        behavior_tp += len(expected_behaviors & predicted_behaviors)
        behavior_fp += len(predicted_behaviors - expected_behaviors)
        behavior_fn += len(expected_behaviors - predicted_behaviors)
        attack_tp += len(expected_attack_ids & predicted_attack_ids)
        attack_fp += len(predicted_attack_ids - expected_attack_ids)
        attack_fn += len(expected_attack_ids - predicted_attack_ids)
        total_units += len(units)
        evidence_units += sum(bool(unit.behavior.evidence) for unit in units)
        language = str(case.get("language", "unknown"))
        language_counts[language][0] += len(expected_behaviors & predicted_behaviors)
        language_counts[language][1] += len(expected_behaviors)
        for unit in units:
            calibration.append(
                (unit.behavior.confidence, int(unit.behavior.behavior_class in expected_behaviors))
            )
        for missed in expected_behaviors - predicted_behaviors:
            _ = missed
            calibration.append((0.0, 1))

        if "expected_reachable" in case:
            reachability_total += 1
            try:
                result = analyze_document(
                    AttackChainAnalyzeRequest(source_text=text, markings=["TLP:CLEAR"]),
                    text,
                    backend=backend,
                )
                predicted_reachable = result.reasoning.reachable
            except ValueError:
                predicted_reachable = False
            reachability_correct += int(
                predicted_reachable is bool(case["expected_reachable"])
            )

    precision = _ratio(behavior_tp, behavior_tp + behavior_fp)
    recall = _ratio(behavior_tp, behavior_tp + behavior_fn)
    return EvaluationMetrics(
        cases=len(cases),
        behavior_precision=precision,
        behavior_recall=recall,
        behavior_f1=_f1(precision, recall),
        attack_id_f1=_f1(
            _ratio(attack_tp, attack_tp + attack_fp),
            _ratio(attack_tp, attack_tp + attack_fn),
        ),
        evidence_coverage=_ratio(evidence_units, total_units),
        reachability_accuracy=_ratio(reachability_correct, reachability_total),
        brier_score=_ratio(
            sum((confidence - outcome) ** 2 for confidence, outcome in calibration),
            len(calibration),
        ),
        expected_calibration_error=_ece(calibration),
        language_recall={
            language: _ratio(values[0], values[1])
            for language, values in sorted(language_counts.items())
        },
    )


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 1.0


def _f1(precision: float, recall: float) -> float:
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def _ece(values: list[tuple[float, int]], bins: int = 5) -> float:
    if not values:
        return 0.0
    total = len(values)
    error = 0.0
    for index in range(bins):
        lower = index / bins
        upper = (index + 1) / bins
        if index == bins - 1:
            bucket = [
                (confidence, outcome)
                for confidence, outcome in values
                if lower <= confidence <= upper
            ]
        else:
            bucket = [
                (confidence, outcome)
                for confidence, outcome in values
                if lower <= confidence < upper
            ]
        if not bucket:
            continue
        mean_confidence = sum(value[0] for value in bucket) / len(bucket)
        accuracy = sum(value[1] for value in bucket) / len(bucket)
        error += (len(bucket) / total) * abs(mean_confidence - accuracy)
    return error
