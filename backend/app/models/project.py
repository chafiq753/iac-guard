"""Modèle Project : un dépôt Terraform suivi par un client."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        # Deux projets d'un même utilisateur ne peuvent pas porter le même nom
        # (évite les doublons/projets orphelins créés par erreur).
        UniqueConstraint("owner_id", "name", name="uq_project_owner_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))

    # Propriétaire : un utilisateur ne voit que SES projets, plus ceux que
    # l'admin de son organisation lui a explicitement partagés (voir
    # ProjectAccess) ou, pour admin/security_lead, tous ceux possédés par un
    # membre de la même organisation (voir deps.list_accessible_projects).
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    # Authentification pipeline -> API : on ne stocke JAMAIS le token en clair,
    # seulement son hash. `token_prefix` sert juste à l'afficher (ex: iacg_ab12…).
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(20))

    # Politique de scan : si renseigné, le pipeline doit échouer dès qu'un
    # finding (non ignoré) atteint cette gravité ou pire. None = ne jamais
    # bloquer (comportement historique, rétro-compatible).
    fail_on_severity: Mapped[str | None] = mapped_column(String(10), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    owner: Mapped["User"] = relationship(back_populates="projects")  # noqa: F821
    scans: Mapped[list["Scan"]] = relationship(  # noqa: F821
        back_populates="project", cascade="all, delete-orphan"
    )
    ignored_rules: Mapped[list["IgnoredRule"]] = relationship(  # noqa: F821
        cascade="all, delete-orphan"
    )
