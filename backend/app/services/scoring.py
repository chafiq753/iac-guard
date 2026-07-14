"""Calcul du score de conformité à partir des findings.

Principe (simple et explicable à un auditeur) : on part de 100 et on retire
des points selon la gravité de chaque problème. Un secret exposé (critical)
coûte beaucoup plus cher qu'un tag manquant (low). Le score ne descend pas
sous 0.

Le score se calcule à la lecture (pas stocké) : on peut ajuster les poids
sans devoir re-scanner.
"""

from __future__ import annotations

from dataclasses import dataclass

# Points retirés par finding, selon la gravité.
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 1,
    "info": 0,
}


@dataclass
class ScoreResult:
    score: int              # 0 à 100
    grade: str              # A, B, C, D, F
    total_findings: int
    by_severity: dict[str, int]


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def compute_score(by_severity: dict[str, int]) -> ScoreResult:
    """
    `by_severity` : nombre de findings par gravité, ex {"critical": 2, "low": 5}.
    Les gravités absentes valent 0.
    """
    counts = {sev: int(by_severity.get(sev, 0)) for sev in SEVERITY_WEIGHTS}
    penalty = sum(counts[sev] * weight for sev, weight in SEVERITY_WEIGHTS.items())
    score = max(0, 100 - penalty)
    return ScoreResult(
        score=score,
        grade=_grade(score),
        total_findings=sum(counts.values()),
        by_severity=counts,
    )
