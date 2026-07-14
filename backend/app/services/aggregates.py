"""Petites requêtes d'agrégation réutilisées par les routes de lecture."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.finding import Finding


def severity_counts(db: Session, scan_id: int) -> dict[str, int]:
    """Nombre de findings par gravité pour un scan donné."""
    rows = db.execute(
        select(Finding.severity, func.count())
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
    ).all()
    return {sev: count for sev, count in rows}
