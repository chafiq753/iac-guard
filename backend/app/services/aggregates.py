"""Petites requêtes d'agrégation réutilisées par les routes de lecture."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.ignored_rule import IgnoredRule


def ignored_rule_ids(db: Session, project_id: int) -> set[str]:
    """Règles acceptées comme risque connu pour ce projet (politique de scan)."""
    return set(
        db.scalars(
            select(IgnoredRule.rule_id).where(IgnoredRule.project_id == project_id)
        ).all()
    )


def severity_counts(
    db: Session, scan_id: int, exclude_rule_ids: set[str] | None = None
) -> dict[str, int]:
    """Nombre de findings par gravité pour un scan donné.

    `exclude_rule_ids` : règles couvertes par une exception de politique
    (`IgnoredRule`) — ces findings ne comptent ni dans le score ni dans le
    seuil de blocage du pipeline, mais restent visibles dans la liste.
    """
    stmt = select(Finding.severity, func.count()).where(Finding.scan_id == scan_id)
    if exclude_rule_ids:
        stmt = stmt.where(Finding.rule_id.not_in(exclude_rule_ids))
    rows = db.execute(stmt.group_by(Finding.severity)).all()
    return {sev: count for sev, count in rows}
