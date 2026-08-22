"""Modèle Organization : le compte client, qui regroupe plusieurs utilisateurs.

Sert de périmètre à l'administration des comptes : un admin ne gère que les
membres de SON organisation. Les projets, eux, gardent leur propriétaire
individuel (`Project.owner_id`) — l'organisation ne change pas qui possède
quoi, elle définit seulement qui peut administrer qui.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    members: Mapped[list["User"]] = relationship(back_populates="organization")  # noqa: F821
