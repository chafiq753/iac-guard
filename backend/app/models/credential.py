"""Modèles 2FA : clés WebAuthn (biométrie/passkey), codes de récupération,
challenges.

Point clé WebAuthn : le serveur ne stocke QUE la clé publique. L'empreinte
digitale et la clé privée ne quittent jamais l'appareil (TPM / Secure Enclave).
Une fuite de cette base ne permet donc à personne de se faire passer pour
l'utilisateur — contrairement à un secret TOTP, qui, lui, est partagé.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class WebAuthnCredential(Base):
    """Une clé (passkey) enregistrée par l'utilisateur : Windows Hello, Touch ID,
    YubiKey… Un utilisateur peut en enrôler plusieurs (un par appareil)."""

    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    # Identifiant de la clé, fourni par l'authentificateur. Unique globalement.
    credential_id: Mapped[bytes] = mapped_column(
        LargeBinary(1024), unique=True, index=True
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary(1024))

    # Compteur anti-clonage : l'authentificateur l'incrémente à chaque usage.
    # S'il régresse, c'est le signe d'une clé clonée -> on refuse.
    sign_count: Mapped[int] = mapped_column(Integer, default=0)

    # Nom lisible, choisi par l'utilisateur ("PC du bureau", "iPhone").
    name: Mapped[str] = mapped_column(String(100), default="Appareil")
    transports: Mapped[str | None] = mapped_column(String(120), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship(back_populates="credentials")  # noqa: F821


class RecoveryCode(Base):
    """Code de secours à usage unique, si l'utilisateur perd son appareil.

    Sans ça, perdre son téléphone/PC = perdre son compte définitivement.
    Stocké haché ; `used_at` garantit qu'un code ne sert qu'une fois.
    """

    __tablename__ = "recovery_codes"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    code_hash: Mapped[str] = mapped_column(String(64), index=True)
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship(back_populates="recovery_codes")  # noqa: F821

    @property
    def is_used(self) -> bool:
        return self.used_at is not None


class AuthChallenge(Base):
    """Challenge WebAuthn en attente (enrôlement ou connexion).

    Stocké côté serveur — et non dans un cookie — pour être SUPPRIMÉ après
    usage : un challenge doit être à usage unique, sinon une signature
    interceptée pourrait être rejouée tant que le cookie reste valide.
    """

    __tablename__ = "auth_challenges"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    challenge: Mapped[bytes] = mapped_column(LargeBinary(256))
    purpose: Mapped[str] = mapped_column(String(30))  # register | authenticate
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
