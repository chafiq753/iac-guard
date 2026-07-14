"""Tests du calcul de score de conformité (app/services/scoring.py)."""

from __future__ import annotations

import pytest

from app.services.scoring import SEVERITY_WEIGHTS, compute_score


def test_perfect_score_when_no_findings() -> None:
    result = compute_score({})
    assert result.score == 100
    assert result.grade == "A"
    assert result.total_findings == 0
    assert result.by_severity == {sev: 0 for sev in SEVERITY_WEIGHTS}


def test_penalty_matches_weights() -> None:
    # 1 critical (25) + 1 high (10) + 1 medium (3) = 38 de pénalité -> 62.
    result = compute_score({"critical": 1, "high": 1, "medium": 1})
    assert result.score == 62
    assert result.grade == "C"
    assert result.total_findings == 3


def test_score_never_below_zero() -> None:
    result = compute_score({"critical": 100})
    assert result.score == 0
    assert result.grade == "F"


def test_info_findings_do_not_lower_score() -> None:
    result = compute_score({"info": 50})
    assert result.score == 100
    assert result.total_findings == 50


def test_unknown_severities_are_ignored_in_penalty() -> None:
    # Une gravité inconnue ne doit pas planter ni pénaliser.
    result = compute_score({"bogus": 10, "low": 2})
    assert result.score == 98  # seulement 2 * low(1)
    assert "bogus" not in result.by_severity


@pytest.mark.parametrize(
    ("counts", "expected_grade"),
    [
        ({}, "A"),                        # 100
        ({"medium": 3, "low": 1}, "A"),   # 100 - 10 = 90
        ({"high": 1, "medium": 5}, "B"),  # 100 - 25 = 75
        ({"critical": 1, "high": 1},      "C"),  # 100 - 35 = 65
        ({"critical": 2, "high": 1},      "D"),  # 100 - 60 = 40
        ({"critical": 3},                 "F"),  # 100 - 75 = 25
    ],
)
def test_grade_boundaries(counts: dict[str, int], expected_grade: str) -> None:
    assert compute_score(counts).grade == expected_grade


def test_string_counts_are_coerced() -> None:
    # by_severity peut venir d'une agrégation SQL renvoyant des types variés.
    result = compute_score({"high": "2"})  # type: ignore[dict-item]
    assert result.score == 80
    assert result.by_severity["high"] == 2
