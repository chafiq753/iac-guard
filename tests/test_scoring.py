"""Score (repris du backend) et décision de blocage locale (nouveau)."""

from __future__ import annotations

import pytest

from iacguard.schema import Category, Finding, Severity, ToolName
from iacguard.scoring import SEVERITY_WEIGHTS, compute_score, evaluate


def _f(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        source=ToolName.CHECKOV,
        category=Category.MISCONFIGURATION,
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
    )


# --------------------------------------------------------------------------- #
# compute_score : mêmes tests que backend/tests/test_scoring.py, pour garantir
# que l'outil et le dashboard donnent la même note.
# --------------------------------------------------------------------------- #


def test_perfect_score_when_no_findings() -> None:
    result = compute_score({})
    assert result.score == 100
    assert result.grade == "A"
    assert result.total_findings == 0
    assert result.by_severity == {sev: 0 for sev in SEVERITY_WEIGHTS}


def test_penalty_matches_weights() -> None:
    result = compute_score({"critical": 1, "high": 1, "medium": 1})
    assert result.score == 62
    assert result.grade == "C"


def test_score_never_below_zero() -> None:
    assert compute_score({"critical": 100}).score == 0


@pytest.mark.parametrize(
    ("counts", "expected_grade"),
    [
        ({}, "A"),
        ({"medium": 3, "low": 1}, "A"),
        ({"high": 1, "medium": 5}, "B"),
        ({"critical": 1, "high": 1}, "C"),
        ({"critical": 2, "high": 1}, "D"),
        ({"critical": 3}, "F"),
    ],
)
def test_grade_boundaries(counts: dict[str, int], expected_grade: str) -> None:
    assert compute_score(counts).grade == expected_grade


def test_same_weights_as_backend() -> None:
    import importlib.util
    import sys
    from pathlib import Path

    backend = Path(__file__).resolve().parents[1] / "backend" / "app" / "services" / "scoring.py"
    spec = importlib.util.spec_from_file_location("backend_scoring", backend)
    module = importlib.util.module_from_spec(spec)
    # Les dataclasses du module ont besoin qu'il soit enregistré pour se construire.
    sys.modules["backend_scoring"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    assert module.SEVERITY_WEIGHTS == SEVERITY_WEIGHTS
    assert module.SEVERITY_ORDER == ["info", "low", "medium", "high", "critical"]


# --------------------------------------------------------------------------- #
# evaluate : la décision de blocage prise localement
# --------------------------------------------------------------------------- #


def test_no_threshold_never_blocks() -> None:
    decision = evaluate([_f("A", Severity.CRITICAL)], fail_on=None)
    assert decision.blocked is False
    assert decision.reason is None
    assert decision.score.score == 75


def test_blocks_at_threshold_and_above() -> None:
    assert evaluate([_f("A", Severity.HIGH)], fail_on="high").blocked is True
    assert evaluate([_f("A", Severity.CRITICAL)], fail_on="high").blocked is True
    assert evaluate([_f("A", Severity.MEDIUM)], fail_on="high").blocked is False


def test_blocked_decision_explains_why() -> None:
    decision = evaluate([_f("A", Severity.HIGH)], fail_on="high")
    assert "high" in (decision.reason or "")


def test_ignored_rules_excluded_from_score_and_blocking() -> None:
    findings = [_f("CKV_AWS_20", Severity.HIGH), _f("CKV_AWS_21", Severity.LOW)]
    decision = evaluate(findings, fail_on="high", ignored_rules=["CKV_AWS_20"])
    assert decision.blocked is False
    assert decision.score.score == 99          # seul le LOW compte
    assert decision.ignored_count == 1


def test_unknown_threshold_fails_closed() -> None:
    # Une faute de frappe ne doit pas désactiver le blocage en silence.
    with pytest.raises(ValueError, match="hight"):
        evaluate([_f("A", Severity.CRITICAL)], fail_on="hight")
