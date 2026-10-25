"""Score de conformité et décision de blocage, calculés localement.

Le calcul du score est repris de backend/app/services/scoring.py à
l'identique (mêmes poids, mêmes notes) : l'outil et le dashboard affichent
donc la même note pour un même scan.

Ce qui est nouveau : `evaluate()`. Avant, la décision de bloquer la PR
était prise par l'API (champ `should_fail` de POST /api/scans), à partir du
seuil et des règles ignorées stockés en base. Sans API, rien ne bloquait.
Maintenant la décision se prend ici, à partir du fichier .iacguard.yml.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from iacguard.schema import Finding

# Points retirés par finding, selon la gravité.
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 1,
    "info": 0,
}

# Du moins grave au plus grave — sert à comparer un finding à un seuil de
# blocage ("fail_on") : tout ce qui est à cet index ou après compte.
SEVERITY_ORDER: list[str] = ["info", "low", "medium", "high", "critical"]


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


def exceeds_threshold(by_severity: dict[str, int], threshold: str | None) -> bool:
    """Vrai si un finding atteint ou dépasse la gravité de blocage.

    `threshold=None` : politique désactivée, ne bloque jamais.
    """
    if not threshold or threshold not in SEVERITY_ORDER:
        return False
    idx = SEVERITY_ORDER.index(threshold)
    return any(by_severity.get(sev, 0) > 0 for sev in SEVERITY_ORDER[idx:])


@dataclass
class Decision:
    """Résultat final d'un scan : la note et la décision de blocage."""

    score: ScoreResult
    blocked: bool
    reason: str | None
    ignored_count: int       # findings exclus par une règle ignorée (.iacguard.yml)


def evaluate(
    findings: list[Finding],
    fail_on: str | None = None,
    ignored_rules: Iterable[str] = (),
    ignored_fingerprints: Iterable[str] = (),
) -> Decision:
    """Calcule le score et décide si le scan doit faire échouer le pipeline.

    - `fail_on` : gravité de blocage ("high" bloque sur high ET critical).
      None = ne bloque jamais (mode « rapport seulement »).
    - `ignored_rules` : règles acceptées comme risque connu. Leurs findings
      restent dans le rapport mais ne comptent ni dans le score ni dans le
      blocage — même comportement que `IgnoredRule` côté dashboard.

    Contrairement à `exceeds_threshold`, un seuil inconnu lève une erreur :
    une faute de frappe dans la config (« hight ») ne doit pas désactiver
    le blocage en silence. Pour un outil de sécurité, on échoue fermé.
    """
    if fail_on is not None and fail_on not in SEVERITY_ORDER:
        raise ValueError(
            f"Seuil de blocage inconnu : {fail_on!r}. "
            f"Valeurs possibles : {', '.join(SEVERITY_ORDER)}."
        )

    ignored = set(ignored_rules)
    ignored_fp = set(ignored_fingerprints)   # exceptions ciblées (.iacguard.yml)
    counted = [f for f in findings
               if f.rule_id not in ignored and f.fingerprint not in ignored_fp]
    counts = dict(Counter(f.severity.value for f in counted))

    score = compute_score(counts)
    blocked = exceeds_threshold(counts, fail_on)
    reason = (
        f"Blocage : au moins un finding atteint la gravité '{fail_on}' ou pire."
        if blocked
        else None
    )
    return Decision(
        score=score,
        blocked=blocked,
        reason=reason,
        ignored_count=len(findings) - len(counted),
    )
