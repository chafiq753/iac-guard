"""Écriture du journal d'audit des actions d'administration de comptes.

Append-only : appelé après chaque action admin réussie (invite, changement de
rôle/statut, reset WebAuthn, changement d'accès projet). N'appelle pas
`db.commit()` — le routeur appelant commite l'action et sa ligne d'audit dans
la même transaction, pour ne jamais avoir l'une sans l'autre.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.admin_audit_log import AdminAuditLog
from app.models.user import User


def log_admin_action(
    db: Session,
    *,
    actor: User,
    action: str,
    target_user: User | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AdminAuditLog(
            org_id=actor.org_id,
            actor_id=actor.id,
            action=action,
            target_user_id=target_user.id if target_user else None,
            details=details or {},
        )
    )
