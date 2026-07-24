from pathlib import Path

from traceless_api.attack_chains.evaluation import evaluate_cases, load_cases


def test_curated_attack_chain_quality_gate() -> None:
    dataset = Path(__file__).parents[1] / "evaluation" / "attack_chains.json"
    metrics = evaluate_cases(load_cases(dataset))

    assert metrics.cases >= 16
    assert metrics.behavior_f1 >= 0.90
    assert metrics.attack_id_f1 >= 0.90
    assert metrics.evidence_coverage == 1.0
    assert metrics.reachability_accuracy >= 0.75
    assert metrics.brier_score <= 0.20
    assert metrics.expected_calibration_error <= 0.25
    assert all(value >= 0.85 for value in metrics.language_recall.values())
