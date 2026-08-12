"""Modèle TriageAuditLog : historique en lecture seule des décisions de triage.

Contrairement à `FindingTriage` (qui ne garde que l'état ACTUEL — chaque
décision écrase la précédente), cette table est append-only : chaque
changement crée une nouvelle ligne. C'est elle qui répond à la question d'un
auditeur : « qui a marqué quoi comme résolu, et quand ? »
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class TriageAuditLog(Base):
    __tablename__ = "triage_audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    # Dénormalisés volontairement : l'audit doit rester lisible ET filtrable
    # par propriétaire même si le projet est supprimé plus tard (un journal
    # d'audit ne doit jamais dépendre de la survie de ce qu'il audite).
    project_name: Mapped[str] = mapped_column(String(200))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    finding_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    finding_title: Mapped[str] = mapped_column(Text)

    from_status: Mapped[str] = mapped_column(String(20))
    to_status: Mapped[str] = mapped_column(String(20))
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
