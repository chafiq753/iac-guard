"""Dépendances FastAPI partagées entre les routes.

Trois authentifications coexistent, sur des routes différentes :
  - `get_project_from_token` : le PIPELINE, via un token de projet (iacg_…),
                               en-tête `Authorization: Bearer` ;
  - `get_current_user`       : un HUMAIN connecté, via un JWT de portée
                               `session` (cookie httpOnly, ou en-tête Bearer
                               pour les clients non-navigateur) ;
  - `get_mfa_user`           : un humain qui a validé son MOT DE PASSE mais pas
                               encore sa 2FA (JWT de portée `mfa`, très court).
                               Il ne donne accès qu'aux routes de vérification 2FA.
"""

from __future__ import annotations

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import SCOPE_MFA, SCOPE_SESSION, decode_access_token, hash_token
from app.db.session import get_db
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User

_CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Identifiants invalides ou session expirée.",
    headers={"WWW-Authenticate": "Bearer"},
)


def _bearer_token(authorization: str) -> str:
    """Extrait le token d'un en-tête `Authorization: Bearer <token>`."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _CREDENTIALS_ERROR
    return token


def _resolve_user(db: Session, token: str | None, scope: str) -> User:
    if not token:
        raise _CREDENTIALS_ERROR

    user_id = decode_access_token(token, expected_scope=scope)
    if user_id is None:
        raise _CREDENTIALS_ERROR

    user = db.get(User, user_id)
    # Le compte a pu être supprimé ou désactivé depuis l'émission du JWT.
    if user is None or not user.is_active:
        raise _CREDENTIALS_ERROR
    return user


def get_current_user(
    session: str | None = Cookie(default=None, alias=settings.session_cookie_name),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    """Authentifie un utilisateur connecté (2FA déjà validée si elle est active).

    Le navigateur envoie le cookie httpOnly ; les clients non-navigateur
    peuvent utiliser l'en-tête `Authorization: Bearer <JWT>`.
    """
    token = session or (_bearer_token(authorization) if authorization else None)
    return _resolve_user(db, token, SCOPE_SESSION)


def get_mfa_user(
    mfa: str | None = Cookie(default=None, alias=settings.mfa_cookie_name),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    """Utilisateur en cours de 2FA : mot de passe validé, second facteur attendu."""
    token = mfa or (_bearer_token(authorization) if authorization else None)
    return _resolve_user(db, token, SCOPE_MFA)


def get_project_from_token(
    authorization: str = Header(..., description="Bearer <token projet>"),
    db: Session = Depends(get_db),
) -> Project:
    """Authentifie le pipeline via son token projet (header Authorization: Bearer)."""
    token = _bearer_token(authorization)

    project = db.scalar(select(Project).where(Project.token_hash == hash_token(token)))
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token projet inconnu ou révoqué.",
        )
    return project


# --------------------------------------------------------------------------- #
# Cloisonnement : un utilisateur n'accède qu'à ses propres ressources.
#
# On répond 404 (et non 403) quand la ressource appartient à quelqu'un d'autre :
# un 403 confirmerait son existence. De l'extérieur, « ça n'existe pas » et
# « ça ne t'appartient pas » doivent être indiscernables.
# --------------------------------------------------------------------------- #

_PROJECT_NOT_FOUND = HTTPException(status_code=404, detail="Projet introuvable.")
_SCAN_NOT_FOUND = HTTPException(status_code=404, detail="Scan introuvable.")


def get_owned_project(
    project_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Project:
    """Charge un projet en vérifiant qu'il appartient à l'utilisateur connecté."""
    project = db.get(Project, project_id)
    if project is None or project.owner_id != current_user.id:
        raise _PROJECT_NOT_FOUND
    return project


def get_owned_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    """Charge un scan en vérifiant qu'il appartient à un projet de l'utilisateur."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise _SCAN_NOT_FOUND
    project = db.get(Project, scan.project_id)
    if project is None or project.owner_id != current_user.id:
        raise _SCAN_NOT_FOUND
    return scan
