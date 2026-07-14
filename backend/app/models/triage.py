"""Modèle FindingTriage : la décision d'un analyste sur un finding.

Le triage est attaché au FINGERPRINT (identité stable du problème), pas à une
ligne `findings` : si le scan suivant redétecte le même problème, il garde le
statut décidé par l'analyste au lieu de redevenir « nouveau ».
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

# Statuts autorisés. "open" est l'état implicite : on ne crée une ligne de
# triage que lorsqu'un analyste prend une décision.
TRIAGE_STATUSES = ("open", "acknowledged", "resolved", "false_positive")


class FindingTriage(Base):
    __tablename__ = "finding_triage"
    __table_args__ = (
        # Une seule décision par problème et par projet.
        UniqueConstraint("project_id", "fingerprint", name="uq_triage_project_fp"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    status: Mapped[str] = mapped_column(String(20), default="open")
    # Justification optionnelle ("faux positif : bucket public volontaire").
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Qui a décidé, et quand (audit).
    updated_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
