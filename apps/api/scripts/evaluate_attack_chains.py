#!/usr/bin/env python3
"""Run the curated attack-chain extraction quality gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from traceless_api.attack_chains.evaluation import evaluate_cases, load_cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("evaluation/attack_chains.json"))
    parser.add_argument("--min-behavior-f1", type=float, default=0.90)
    parser.add_argument("--min-language-recall", type=float, default=0.85)
    parser.add_argument("--min-reachability", type=float, default=0.75)
    parser.add_argument("--max-brier", type=float, default=0.20)
    parser.add_argument("--max-ece", type=float, default=0.25)
    args = parser.parse_args()
    metrics = evaluate_cases(load_cases(args.dataset))
    print(json.dumps(metrics.as_dict(), indent=2, sort_keys=True))
    failures: list[str] = []
    if metrics.behavior_f1 < args.min_behavior_f1:
        failures.append("behavior F1")
    if any(value < args.min_language_recall for value in metrics.language_recall.values()):
        failures.append("language recall")
    if metrics.reachability_accuracy < args.min_reachability:
        failures.append("reachability accuracy")
    if metrics.brier_score > args.max_brier:
        failures.append("Brier score")
    if metrics.expected_calibration_error > args.max_ece:
        failures.append("calibration error")
    if failures:
        raise SystemExit("Attack-chain quality gate failed: " + ", ".join(failures))


if __name__ == "__main__":
    main()
