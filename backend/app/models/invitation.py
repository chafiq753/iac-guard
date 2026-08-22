"""Modèle Invitation : preuve d'une invitation envoyée, à usage unique.

Le compte `User` correspondant existe DÈS l'envoi de l'invitation (avec
`hashed_password=None`, voir `User.status`) — l'invitation ne fait que porter
le jeton d'activation. Ça évite toute divergence entre "qui a été invité" et
"qui existe en base" quand on renvoie une invitation ou qu'on liste les
comptes en attente.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class Invitation(Base):
    __tablename__ = "invitations"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    role: Mapped[str] = mapped_column(String(20))

    # Compte `User` (en attente) que cette invitation active à l'acceptation.
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    # Jamais le jeton en clair : seul son hash (SHA-256, comme les tokens de
    # projet — le jeton est long et aléatoire, donc non attaquable par
    # dictionnaire).
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    invited_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
