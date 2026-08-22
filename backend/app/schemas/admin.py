"""Schémas Pydantic pour la gestion des comptes par l'admin."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.user import ROLES
from app.schemas.user import PASSWORD_MAX, PASSWORD_MIN, _check_password_complexity


def _valid_role(value: str) -> str:
    if value not in ROLES:
        raise ValueError(f"Rôle invalide. Attendu : {', '.join(ROLES)}.")
    return value


# --------------------------------------------------------------------------- #
# Comptes
# --------------------------------------------------------------------------- #


class AdminUserOut(BaseModel):
    id: int
    email: EmailStr
    name: str | None = None
    role: str
    status: str
    created_at: datetime
    last_login_at: datetime | None = None
    # Pilote la désactivation des actions "changer de rôle"/"désactiver" côté
    # front (voir règle métier : jamais de lockout total de l'organisation).
    is_last_active_admin: bool = False


class AdminUsersPage(BaseModel):
    items: list[AdminUserOut]
    total: int
    page: int
    page_size: int


class InviteIn(BaseModel):
    email: EmailStr
    role: str

    _role_valid = field_validator("role")(_valid_role)


class InvitationOut(BaseModel):
    """Confirmation d'envoi — ne contient JAMAIS le jeton (livré par e-mail)."""

    email: EmailStr
    role: str
    expires_at: datetime


class InvitationAcceptIn(BaseModel):
    password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)

    _complexity = field_validator("password")(_check_password_complexity)


class RoleUpdateIn(BaseModel):
    role: str

    _role_valid = field_validator("role")(_valid_role)


class StatusUpdateIn(BaseModel):
    is_active: bool


# --------------------------------------------------------------------------- #
# Accès aux projets
# --------------------------------------------------------------------------- #


class ProjectAccessOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class ProjectAccessIn(BaseModel):
    """Remplace intégralement la liste des projets accessibles à l'utilisateur."""

    project_ids: list[int]


# --------------------------------------------------------------------------- #
# Audit log admin
# --------------------------------------------------------------------------- #


class AdminAuditLogOut(BaseModel):
    id: int
    actor_id: int
    actor_email: str
    action: str
    target_user_id: int | None = None
    target_user_email: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class AdminAuditLogPage(BaseModel):
    items: list[AdminAuditLogOut]
    total: int
    page: int
    page_size: int
