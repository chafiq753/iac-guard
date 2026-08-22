"""Modèle ProjectAccess : octroi explicite d'un projet à un utilisateur.

Ne concerne que les rôles SANS accès global (developer/auditor/viewer) :
un admin ou security_lead voit déjà tous les projets de son organisation
sans avoir besoin d'une ligne ici. Règle produit : un utilisateur à accès
non-global qui n'a AUCUNE ligne dans cette table ne voit aucun projet.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class ProjectAccess(Base):
    __tablename__ = "project_access"
    __table_args__ = (
        UniqueConstraint("user_id", "project_id", name="uq_project_access_user_project"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)

    granted_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
