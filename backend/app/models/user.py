"""Modèle User : un utilisateur du dashboard (membre d'une organisation cliente).

À ne pas confondre avec l'authentification du pipeline : le pipeline
(GitHub Actions) s'authentifie avec un TOKEN DE PROJET, un humain sur le
dashboard s'authentifie avec e-mail + mot de passe puis un JWT.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

# Les 5 rôles RBAC. admin/security_lead ont un accès global à tous les
# projets de leur organisation ; les autres n'accèdent qu'aux projets pour
# lesquels un admin leur a explicitement donné accès (voir ProjectAccess).
ROLES = ("admin", "security_lead", "developer", "auditor", "viewer")
GLOBAL_ACCESS_ROLES = ("admin", "security_lead")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # Jamais le mot de passe en clair : uniquement son hash Argon2id (salé).
    # NULL tant qu'une invitation est en attente (le compte existe, mais
    # l'invité n'a pas encore choisi de mot de passe) — voir `status`.
    # 255 : un hash Argon2id fait ~100 caractères, on garde de la marge pour
    # d'éventuels paramètres plus lourds à l'avenir.
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # --- Organisation & rôle ------------------------------------------------ #
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    role: Mapped[str] = mapped_column(String(20), default="admin")
    # Qui a créé ce compte : NULL pour le premier utilisateur d'une org
    # (auto-inscription), sinon l'admin qui a envoyé l'invitation.
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
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

    organization: Mapped["Organization"] = relationship(back_populates="members")  # noqa: F821
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
    def status(self) -> str:
        """Dérivé plutôt que stocké : `hashed_password`/`is_active` restent la
        seule source de vérité, pas de risque de désynchronisation."""
        if self.hashed_password is None:
            return "pending_invitation"
        return "active" if self.is_active else "disabled"

    @property
    def has_global_project_access(self) -> bool:
        """Vrai si le rôle donne accès à TOUS les projets de l'organisation
        sans avoir besoin d'une ligne ProjectAccess explicite."""
        return self.role in GLOBAL_ACCESS_ROLES

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
