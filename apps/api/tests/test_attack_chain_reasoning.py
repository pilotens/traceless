import pytest

from traceless_api.attack_chains.diagnosis import diagnose
from traceless_api.attack_chains.pipeline import analyze_document
from traceless_api.attack_chains.reasoning import reason
from traceless_api.attack_chains.vocabulary import DEFAULT_VOCABULARY
from traceless_api.models.attack_chains import (
    AttackBehavior,
    AttackChainAnalyzeRequest,
    AttackUnit,
    BranchChoice,
    Predicate,
)


def p(category: str, name: str, *arguments: str) -> Predicate:
    return Predicate(category=category, name=name, arguments=list(arguments))


def unit(
    unit_id: str,
    sequence: int,
    pre: list[Predicate],
    post: list[Predicate],
    *,
    branch: BranchChoice | None = None,
) -> AttackUnit:
    return AttackUnit(
        unit_id=unit_id,
        behavior=AttackBehavior(
            behavior_class="execute",
            summary=unit_id,
            sequence=sequence,
            confidence=0.9,
        ),
        preconditions=pre,
        postconditions=post,
        branch=branch,
    )


def test_forward_reasoning_and_backward_path() -> None:
    delivered = p("file", "delivered", "victim_host", "invoice.pdf")
    opened = p("user", "opened", "victim_host", "invoice.pdf")
    executed = p("privilege", "code_execution", "victim_host", "attacker")
    c2 = p("data", "c2_channel", "victim_host", "c2_server", "HTTPS")
    units = [
        unit("open", 0, [delivered], [opened]),
        unit("exploit", 1, [opened], [executed]),
        unit("beacon", 2, [executed], [c2]),
    ]

    result = reason(units, [delivered], c2, max_paths=10)

    assert result.reachable is True
    assert [path.unit_ids for path in result.paths] == [["open", "exploit", "beacon"]]
    assert {fact.key for fact in result.derived_facts} == {opened.key, executed.key, c2.key}


def test_backward_search_keeps_alternative_branches_separate() -> None:
    start = p("network", "reachable", "attacker", "victim_host", "HTTPS")
    foothold = p("host", "access", "victim_host", "attacker")
    goal = p("host", "impacted", "victim_host", "encrypted")
    branches = [
        unit(
            "phishing",
            0,
            [start],
            [foothold],
            branch=BranchChoice(group="initial-access", option="phishing"),
        ),
        unit(
            "exploit",
            0,
            [start],
            [foothold],
            branch=BranchChoice(group="initial-access", option="exploit"),
        ),
        unit("impact", 1, [foothold], [goal]),
    ]

    result = reason(branches, [start], goal, max_paths=10)

    assert result.reachable is True
    assert len(result.paths) == 2
    assert {tuple(path.unit_ids) for path in result.paths} == {
        ("exploit", "impact"),
        ("phishing", "impact"),
    }
    assert {tuple(path.branch_choices.items()) for path in result.paths} == {
        (("initial-access", "exploit"),),
        (("initial-access", "phishing"),),
    }


def test_diagnosis_flags_unsupported_and_future_dependencies() -> None:
    missing = p("file", "present", "victim_host", "payload")
    running = p("process", "running", "victim_host", "payload")
    units = [
        unit("execute", 0, [missing], [running]),
        unit("download", 1, [], [missing]),
    ]

    issues = diagnose(units, [], DEFAULT_VOCABULARY)

    assert any(issue.issue_type == "future_dependency" for issue in issues)


def test_pipeline_uses_explicit_units_and_produces_reachable_chain() -> None:
    initial = p("file", "delivered", "victim_host", "invoice.pdf")
    opened = p("user", "opened", "victim_host", "invoice.pdf")
    execution = p("privilege", "code_execution", "victim_host", "attacker")
    units = [
        unit("open", 0, [initial], [opened]),
        unit("exploit", 1, [opened], [execution]),
    ]
    payload = AttackChainAnalyzeRequest(
        source_text="The victim opened invoice.pdf. The document enabled code execution.",
        initial_facts=[initial],
        goal=execution,
        candidate_units=units,
    )

    result = analyze_document(payload, payload.source_text or "")

    assert result.extraction_backend == "explicit-candidate-units"
    assert result.reasoning.reachable is True
    assert result.reasoning.paths[0].unit_ids == ["open", "exploit"]
    assert result.issues == []


def test_rule_backend_extracts_staged_behavior_units() -> None:
    source = (
        "The victim received invoice.pdf and opened the attachment. "
        "It downloaded payload.exe. The attacker executed payload.exe and the malware "
        "connected to a command and control server over HTTPS."
    )
    payload = AttackChainAnalyzeRequest(
        source_text=source,
        initial_facts=[p("file", "delivered", "victim_host", "invoice.pdf")],
    )

    result = analyze_document(payload, source)

    classes = [item.behavior.behavior_class for item in result.units]
    assert "user_action" in classes
    assert "download" in classes
    assert "execute" in classes
    assert "communication" in classes
    assert result.rules


def test_reasoning_rejects_a_path_that_merges_exclusive_branches() -> None:
    start = p("network", "reachable", "attacker", "victim_host", "HTTPS")
    phishing_state = p("file", "delivered", "victim_host", "invoice.pdf")
    exploit_state = p("privilege", "code_execution", "victim_host", "attacker")
    impossible_goal = p("host", "impacted", "victim_host", "combined")
    units = [
        unit(
            "phishing",
            0,
            [start],
            [phishing_state],
            branch=BranchChoice(group="initial-access", option="phishing"),
        ),
        unit(
            "network-exploit",
            0,
            [start],
            [exploit_state],
            branch=BranchChoice(group="initial-access", option="exploit"),
        ),
        unit(
            "invalid-merge",
            1,
            [phishing_state, exploit_state],
            [impossible_goal],
        ),
    ]

    result = reason(units, [start], impossible_goal)

    assert result.reachable is False
    assert result.paths == []
    issues = diagnose(units, [start], DEFAULT_VOCABULARY)
    assert any(issue.issue_type == "branch_merge" for issue in issues)


def test_pipeline_fails_closed_for_unknown_predicates() -> None:
    unknown = p("custom", "invented_state", "victim_host")
    payload = AttackChainAnalyzeRequest(
        source_text="A report with one explicit candidate unit.",
        candidate_units=[unit("unknown", 0, [], [unknown])],
    )

    with pytest.raises(ValueError, match="closed vocabulary"):
        analyze_document(payload, payload.source_text or "")


def test_diagnosis_allows_alternative_producers_without_forcing_a_branch_merge() -> None:
    start = p("network", "reachable", "attacker", "victim_host", "HTTPS")
    foothold = p("host", "access", "victim_host", "attacker")
    goal = p("host", "impacted", "victim_host", "encrypted")
    units = [
        unit(
            "phishing",
            0,
            [start],
            [foothold],
            branch=BranchChoice(group="initial-access", option="phishing"),
        ),
        unit(
            "exploit",
            0,
            [start],
            [foothold],
            branch=BranchChoice(group="initial-access", option="exploit"),
        ),
        unit("impact", 1, [foothold], [goal]),
    ]

    issues = diagnose(units, [start], DEFAULT_VOCABULARY)

    assert not any(issue.issue_type == "branch_merge" for issue in issues)


def test_pipeline_rejects_unknown_initial_facts_and_goal() -> None:
    delivered = p("file", "delivered", "victim_host", "invoice.pdf")
    opened = p("user", "opened", "victim_host", "invoice.pdf")
    unknown = p("custom", "invented_state", "victim_host")
    units = [unit("open", 0, [delivered], [opened])]

    with pytest.raises(ValueError, match="reasoning inputs"):
        analyze_document(
            AttackChainAnalyzeRequest(
                source_text="The victim opened invoice.pdf.",
                initial_facts=[unknown],
                candidate_units=units,
            ),
            "The victim opened invoice.pdf.",
        )

    with pytest.raises(ValueError, match="reasoning inputs"):
        analyze_document(
            AttackChainAnalyzeRequest(
                source_text="The victim opened invoice.pdf.",
                initial_facts=[delivered],
                goal=unknown,
                candidate_units=units,
            ),
            "The victim opened invoice.pdf.",
        )


def test_rule_backend_skips_negated_behavior_sentences() -> None:
    payload = AttackChainAnalyzeRequest(
        source_text=(
            "The gateway blocked the attachment and the victim did not open it. "
            "The attacker executed payload.exe."
        )
    )

    result = analyze_document(payload, payload.source_text or "")

    assert [unit.behavior.behavior_class for unit in result.units] == ["execute"]
