"""Modèle User : un utilisateur du dashboard (client du SaaS).

À ne pas confondre avec l'authentification du pipeline : le pipeline
(GitHub Actions) s'authentifie avec un TOKEN DE PROJET, un humain sur le
dashboard s'authentifie avec e-mail + mot de passe puis un JWT.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)

    # Jamais le mot de passe en clair : uniquement son hash Argon2id (salé).
    # 255 : un hash Argon2id fait ~100 caractères, on garde de la marge pour
    # d'éventuels paramètres plus lourds à l'avenir.
    hashed_password: Mapped[str] = mapped_column(String(255))

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    # --- 2FA par TOTP (code à 6 chiffres) --------------------------------- #
    # Le secret n'est utilisable qu'une fois la 2FA confirmée : on le stocke
    # dès le setup, mais `totp_enabled` ne passe à True qu'après qu'un premier
    # code valide a été saisi (preuve que l'app d'authentification est bien
    # configurée — sinon on enfermerait l'utilisateur dehors).
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- Anti-brute-force -------------------------------------------------- #
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    projects: Mapped[list["Project"]] = relationship(  # noqa: F821
        back_populates="owner", cascade="all, delete-orphan"
    )
    credentials: Mapped[list["WebAuthnCredential"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )
    recovery_codes: Mapped[list["RecoveryCode"]] = relationship(  # noqa: F821
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def webauthn_enabled(self) -> bool:
        return len(self.credentials) > 0

    @property
    def has_mfa(self) -> bool:
        """Vrai si au moins une méthode de 2FA est active."""
        return self.totp_enabled or self.webauthn_enabled

    @property
    def mfa_methods(self) -> list[str]:
        """Méthodes de 2FA que l'utilisateur a choisi d'activer."""
        methods: list[str] = []
        if self.webauthn_enabled:
            methods.append("webauthn")
        if self.totp_enabled:
            methods.append("totp")
        return methods
