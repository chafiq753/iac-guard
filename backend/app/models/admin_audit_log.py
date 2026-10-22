"""Modèle AdminAuditLog : trace append-only des actions d'administration de
comptes (invitation, changement de rôle, activation/désactivation, reset
WebAuthn, changement d'accès aux projets).

À ne pas confondre avec `TriageAuditLog` (décisions de triage sur des
findings) : deux journaux distincts, deux publics (ici : "qui a changé quoi
sur quel compte", pas "qui a résolu quelle alerte").
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.db.audit_guard import install_append_only_guard
from app.db.session import Base


class AdminAuditLog(Base):
    __tablename__ = "admin_audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)

    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(50), index=True)
    target_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    # Contexte libre par action, ex: {"old_role": "viewer", "new_role": "admin"}.
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# Append-only garanti par la base (triggers), pas seulement par l'API.
install_append_only_guard(AdminAuditLog.__table__)
