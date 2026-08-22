"""Routes d'administration des comptes (invitation, rôle, statut, accès aux
projets, reset WebAuthn, audit log).

Deux routeurs : `router` (8 routes, chacune protégée par `require_role("admin")`)
et `public_router` (la seule route publique — accepter une invitation, puisque
l'invité n'a par définition pas encore de session).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.core.config import settings
from app.core.security import generate_invitation_token, hash_password, hash_token
from app.db.session import get_db
from app.models.admin_audit_log import AdminAuditLog
from app.models.credential import WebAuthnCredential
from app.models.invitation import Invitation
from app.models.project import Project
from app.models.project_access import ProjectAccess
from app.models.user import User
from app.schemas.admin import (
    AdminAuditLogOut,
    AdminAuditLogPage,
    AdminUserOut,
    AdminUsersPage,
    InvitationAcceptIn,
    InvitationOut,
    InviteIn,
    ProjectAccessIn,
    ProjectAccessOut,
    RoleUpdateIn,
    StatusUpdateIn,
)
from app.schemas.user import UserOut
from app.services.admin_audit import log_admin_action
from app.services.email import send_invitation_email

router = APIRouter(prefix="/api/admin", tags=["admin"])
public_router = APIRouter(prefix="/api/admin", tags=["admin"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_USER_NOT_FOUND = HTTPException(status_code=404, detail="Utilisateur introuvable.")


def _get_org_member(db: Session, current_user: User, user_id: int) -> User:
    """Charge un utilisateur en vérifiant qu'il appartient à la même organisation."""
    target = db.get(User, user_id)
    if target is None or target.org_id != current_user.org_id:
        raise _USER_NOT_FOUND
    return target


def _active_admin_count(db: Session, org_id: int) -> int:
    count = db.scalar(
        select(func.count())
        .select_from(User)
        .where(
            User.org_id == org_id,
            User.role == "admin",
            User.is_active.is_(True),
            User.hashed_password.is_not(None),
        )
    )
    return count or 0


def _is_last_active_admin(db: Session, user: User) -> bool:
    if user.role != "admin" or user.status != "active":
        return False
    return _active_admin_count(db, user.org_id) <= 1


def _to_admin_user_out(db: Session, user: User) -> AdminUserOut:
    return AdminUserOut(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        status=user.status,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        is_last_active_admin=_is_last_active_admin(db, user),
    )


# --------------------------------------------------------------------------- #
# Comptes
# --------------------------------------------------------------------------- #


@router.get("/users", response_model=AdminUsersPage)
def list_users(
    current_user: User = Depends(require_role("admin")),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> AdminUsersPage:
    stmt = (
        select(User)
        .where(User.org_id == current_user.org_id)
        .order_by(User.created_at)
    )
    all_rows = db.scalars(stmt).all()
    total = len(all_rows)
    start = (page - 1) * page_size
    page_rows = all_rows[start : start + page_size]
    return AdminUsersPage(
        items=[_to_admin_user_out(db, u) for u in page_rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/users/invite", response_model=InvitationOut, status_code=201)
def invite_user(
    payload: InviteIn,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> InvitationOut:
    """Crée (ou ré-invite) un compte et envoie le lien d'activation par e-mail.

    Le jeton n'est JAMAIS renvoyé dans la réponse HTTP : seul l'e-mail le
    porte. Renvoyer la même adresse régénère un jeton et invalide l'ancien.
    """
    window_start = datetime.now(timezone.utc) - timedelta(hours=1)
    recent_invites = db.scalar(
        select(func.count())
        .select_from(AdminAuditLog)
        .where(
            AdminAuditLog.actor_id == current_user.id,
            AdminAuditLog.action == "user.invited",
            AdminAuditLog.created_at >= window_start,
        )
    )
    if (recent_invites or 0) >= settings.max_invites_per_hour:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Trop d'invitations envoyées récemment (max {settings.max_invites_per_hour}/heure).",
        )

    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing is not None:
        if existing.org_id != current_user.org_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cet e-mail est déjà associé à un compte.",
            )
        if existing.hashed_password is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cet utilisateur a déjà un compte actif.",
            )
        target = existing
        target.role = payload.role
    else:
        target = User(
            email=payload.email,
            hashed_password=None,
            org_id=current_user.org_id,
            role=payload.role,
            created_by_id=current_user.id,
        )
        db.add(target)
        db.flush()  # obtient target.id

    # Ré-invitation : toute invitation précédente non acceptée devient caduque.
    db.execute(
        delete(Invitation).where(
            Invitation.user_id == target.id, Invitation.accepted_at.is_(None)
        )
    )

    raw_token = generate_invitation_token()
    expires_at = datetime.now(timezone.utc) + timedelta(
        hours=settings.invitation_expire_hours
    )
    db.add(
        Invitation(
            email=target.email,
            org_id=current_user.org_id,
            role=payload.role,
            user_id=target.id,
            token_hash=hash_token(raw_token),
            invited_by_id=current_user.id,
            expires_at=expires_at,
        )
    )
    log_admin_action(
        db,
        actor=current_user,
        action="user.invited",
        target_user=target,
        details={"role": payload.role},
    )
    db.commit()

    send_invitation_email(
        to_email=target.email,
        token=raw_token,
        inviter_name=current_user.name or current_user.email,
    )

    return InvitationOut(email=target.email, role=target.role, expires_at=expires_at)


@router.patch("/users/{user_id}/role", response_model=AdminUserOut)
def change_role(
    user_id: int,
    payload: RoleUpdateIn,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> AdminUserOut:
    target = _get_org_member(db, current_user, user_id)

    if payload.role != "admin" and _is_last_active_admin(db, target):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Impossible de rétrograder le dernier administrateur actif.",
        )

    old_role = target.role
    target.role = payload.role
    log_admin_action(
        db,
        actor=current_user,
        action="user.role_changed",
        target_user=target,
        details={"old_role": old_role, "new_role": payload.role},
    )
    db.commit()
    return _to_admin_user_out(db, target)


@router.patch("/users/{user_id}/status", response_model=AdminUserOut)
def change_status(
    user_id: int,
    payload: StatusUpdateIn,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> AdminUserOut:
    target = _get_org_member(db, current_user, user_id)

    if not payload.is_active:
        if target.id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Vous ne pouvez pas désactiver votre propre compte.",
            )
        if _is_last_active_admin(db, target):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Impossible de désactiver le dernier administrateur actif.",
            )

    target.is_active = payload.is_active
    log_admin_action(
        db,
        actor=current_user,
        action="user.enabled" if payload.is_active else "user.disabled",
        target_user=target,
    )
    db.commit()
    return _to_admin_user_out(db, target)


@router.post("/users/{user_id}/reset-webauthn", status_code=204)
def reset_webauthn(
    user_id: int,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> None:
    """Révoque toutes les passkeys de l'utilisateur : ré-enrôlement obligatoire
    à la prochaine connexion nécessitant la 2FA."""
    target = _get_org_member(db, current_user, user_id)
    db.execute(delete(WebAuthnCredential).where(WebAuthnCredential.user_id == target.id))
    log_admin_action(db, actor=current_user, action="user.webauthn_reset", target_user=target)
    db.commit()


# --------------------------------------------------------------------------- #
# Accès aux projets
# --------------------------------------------------------------------------- #


@router.get("/users/{user_id}/project-access", response_model=list[ProjectAccessOut])
def get_project_access(
    user_id: int,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> list[Project]:
    target = _get_org_member(db, current_user, user_id)
    return list(
        db.scalars(
            select(Project)
            .join(ProjectAccess, ProjectAccess.project_id == Project.id)
            .where(ProjectAccess.user_id == target.id)
        ).all()
    )


@router.put("/users/{user_id}/project-access", response_model=list[ProjectAccessOut])
def set_project_access(
    user_id: int,
    payload: ProjectAccessIn,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> list[Project]:
    """Remplace intégralement la liste des projets accessibles à l'utilisateur.

    Les ids hors de l'organisation de l'admin (ou inexistants) sont
    silencieusement ignorés plutôt que rejetés en bloc : un id périmé (projet
    supprimé entre-temps) ne doit pas faire échouer tout le formulaire.
    """
    target = _get_org_member(db, current_user, user_id)
    # Un admin ne peut partager que des projets possédés par un membre de son
    # organisation — jamais ceux d'un autre client.
    org_member_ids = select(User.id).where(User.org_id == current_user.org_id)
    valid_ids = list(
        db.scalars(
            select(Project.id).where(
                Project.owner_id.in_(org_member_ids),
                Project.id.in_(payload.project_ids),
            )
        ).all()
    )

    db.execute(delete(ProjectAccess).where(ProjectAccess.user_id == target.id))
    for project_id in valid_ids:
        db.add(
            ProjectAccess(
                user_id=target.id, project_id=project_id, granted_by_id=current_user.id
            )
        )
    log_admin_action(
        db,
        actor=current_user,
        action="user.project_access_updated",
        target_user=target,
        details={"project_ids": sorted(valid_ids)},
    )
    db.commit()

    return list(db.scalars(select(Project).where(Project.id.in_(valid_ids))).all())


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #


@router.get("/audit-logs", response_model=AdminAuditLogPage)
def list_admin_audit_logs(
    current_user: User = Depends(require_role("admin")),
    actor_id: int | None = Query(None),
    target_user_id: int | None = Query(None),
    action: str | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> AdminAuditLogPage:
    stmt = select(AdminAuditLog).where(AdminAuditLog.org_id == current_user.org_id)
    if actor_id is not None:
        stmt = stmt.where(AdminAuditLog.actor_id == actor_id)
    if target_user_id is not None:
        stmt = stmt.where(AdminAuditLog.target_user_id == target_user_id)
    if action is not None:
        stmt = stmt.where(AdminAuditLog.action == action)
    if since is not None:
        stmt = stmt.where(AdminAuditLog.created_at >= since)
    if until is not None:
        stmt = stmt.where(AdminAuditLog.created_at <= until)
    stmt = stmt.order_by(AdminAuditLog.created_at.desc())

    all_rows = db.scalars(stmt).all()
    total = len(all_rows)
    start = (page - 1) * page_size
    page_rows = all_rows[start : start + page_size]

    user_ids = {r.actor_id for r in page_rows} | {
        r.target_user_id for r in page_rows if r.target_user_id is not None
    }
    emails = {
        u.id: u.email for u in db.scalars(select(User).where(User.id.in_(user_ids))).all()
    }

    items = [
        AdminAuditLogOut(
            id=r.id,
            actor_id=r.actor_id,
            actor_email=emails.get(r.actor_id, "?"),
            action=r.action,
            target_user_id=r.target_user_id,
            target_user_email=emails.get(r.target_user_id) if r.target_user_id else None,
            details=r.details,
            created_at=r.created_at,
        )
        for r in page_rows
    ]
    return AdminAuditLogPage(items=items, total=total, page=page, page_size=page_size)


# --------------------------------------------------------------------------- #
# Acceptation d'invitation (route PUBLIQUE — l'invité n'a pas encore de session)
# --------------------------------------------------------------------------- #


@public_router.post("/invitations/{token}/accept", response_model=UserOut)
def accept_invitation(
    token: str, payload: InvitationAcceptIn, db: Session = Depends(get_db)
) -> User:
    invitation = db.scalar(
        select(Invitation).where(Invitation.token_hash == hash_token(token))
    )
    if invitation is None or invitation.accepted_at is not None:
        raise HTTPException(status_code=400, detail="Invitation invalide ou déjà utilisée.")

    expires_at = invitation.expires_at
    if expires_at.tzinfo is None:  # SQLite renvoie des datetimes naïfs
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Cette invitation a expiré. Demandez à un admin de la renvoyer.",
        )

    user = db.get(User, invitation.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="Invitation invalide.")

    user.hashed_password = hash_password(payload.password)
    user.is_active = True
    invitation.accepted_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return user
