"""Modèle IgnoredRule : une règle de scanner acceptée comme risque connu.

Différent du triage (`FindingTriage`, par empreinte de finding précis) : ici
on exclut TOUTE occurrence d'une règle (ex. "CKV_AWS_3") sur un projet, quelle
que soit la ressource concernée — une exception de politique, pas un jugement
au cas par cas. Utilisé pour ne plus compter ces findings dans le score ni
dans le seuil de blocage du pipeline.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class IgnoredRule(Base):
    __tablename__ = "ignored_rules"
    __table_args__ = (
        UniqueConstraint("project_id", "rule_id", name="uq_ignored_rule_project"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(120))

    # Justification ("bucket public volontaire, usage CDN") — visible dans
    # l'audit log et utile lors d'un audit de conformité externe.
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
