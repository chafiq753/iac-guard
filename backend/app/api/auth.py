"""Routes d'authentification utilisateur : inscription, connexion, profil.

Le dashboard s'authentifie ici (e-mail + mot de passe -> éventuelle 2FA -> cookie
de session). Le pipeline, lui, n'utilise PAS ces routes : il s'authentifie par
token de projet.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.cookies import clear_session_cookie, set_mfa_cookie, set_session_cookie
from app.api.deps import get_current_user
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_mfa_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.db.session import get_db
from app.models.organization import Organization
from app.models.user import User
from app.schemas.user import (
    EmailIn,
    LoginMethodsOut,
    LoginResult,
    PasswordChange,
    ProfileUpdate,
    UserCreate,
    UserLogin,
    UserOut,
    WebAuthnLoginVerifyIn,
)
from app.services import mfa as mfa_service

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Message unique quels que soient l'e-mail et le mot de passe : ne jamais
# révéler si un compte existe (énumération de comptes).
_BAD_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="E-mail ou mot de passe incorrect.",
    headers={"WWW-Authenticate": "Bearer"},
)


def _is_locked(user: User) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:  # SQLite renvoie des datetimes naïfs
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > datetime.now(timezone.utc)


def _register_failure(db: Session, user: User) -> None:
    """Compte l'échec et verrouille le compte au-delà du seuil."""
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.max_login_attempts:
        user.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=settings.lockout_minutes
        )
        user.failed_login_attempts = 0  # le compteur repart après le verrou
    db.commit()


@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    """Crée un compte. L'e-mail doit être unique.

    Auto-inscription = création d'une nouvelle organisation dont ce compte
    devient l'admin. Les collègues rejoignent ensuite cette organisation par
    invitation (voir /api/admin/users/invite), jamais par un second register.
    """
    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Un compte existe déjà avec cet e-mail.",
        )

    org_name = (payload.org_name or payload.email.split("@", 1)[0]).strip()
    organization = Organization(name=org_name or payload.email)
    db.add(organization)
    db.flush()  # obtient organization.id avant de créer l'utilisateur

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        org_id=organization.id,
        role="admin",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=LoginResult)
def login(
    payload: UserLogin,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResult:
    """Vérifie les identifiants.

    Si l'utilisateur a activé une 2FA, on ne pose PAS la session : on pose un
    cookie MFA de courte durée, et le front doit valider le second facteur.
    """
    user = db.scalar(select(User).where(User.email == payload.email))

    if user is None:
        # On hache quand même un mot de passe factice : sans ça, une réponse
        # instantanée trahirait qu'aucun compte n'existe pour cet e-mail
        # (attaque temporelle sur l'énumération de comptes).
        hash_password(payload.password)
        raise _BAD_CREDENTIALS

    if user.hashed_password is None:
        # Invitation en attente : aucun mot de passe n'a encore été choisi.
        # Même traitement qu'un compte inconnu (anti-énumération + anti-timing).
        hash_password(payload.password)
        raise _BAD_CREDENTIALS

    if _is_locked(user):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Trop de tentatives échouées. Compte temporairement verrouillé "
                f"({settings.lockout_minutes} minutes)."
            ),
        )

    if not verify_password(payload.password, user.hashed_password):
        _register_failure(db, user)
        raise _BAD_CREDENTIALS

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ce compte est désactivé.",
        )

    # Connexion réussie : on remet les compteurs à zéro.
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)

    # Migration transparente : le mot de passe est en clair ICI et nulle part
    # ailleurs — c'est le seul moment où l'on peut convertir un vieux hash
    # bcrypt en Argon2id.
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(payload.password)
    db.commit()

    if user.has_mfa:
        set_mfa_cookie(response, create_mfa_token(user.id))
        return LoginResult(mfa_required=True, methods=user.mfa_methods)

    set_session_cookie(response, create_access_token(user.id))
    return LoginResult(mfa_required=False, user=UserOut.model_validate(user))


@router.post("/methods", response_model=LoginMethodsOut)
def login_methods(payload: EmailIn, db: Session = Depends(get_db)) -> LoginMethodsOut:
    """Étape 1 du login : quelles méthodes proposer pour cet e-mail ?

    Anti-énumération : un e-mail inconnu répond EXACTEMENT comme un compte à
    mot de passe seul (["password"]). "webauthn" n'apparaît que si le compte a
    enrôlé une passkey — et cette information est inutilisable sans l'appareil.
    """
    user = db.scalar(select(User).where(User.email == payload.email))
    methods = ["password"]
    if user is not None and user.is_active and user.webauthn_enabled:
        # En tête de liste : le front la propose en priorité visuelle.
        methods.insert(0, "webauthn")
    # (futur) "github" quand le compte aura été lié à un compte GitHub (OAuth).
    return LoginMethodsOut(methods=methods)


@router.post("/webauthn/login/options")
def webauthn_login_options(payload: EmailIn, db: Session = Depends(get_db)) -> dict:
    """Challenge de connexion par passkey (1er facteur, sans mot de passe).

    La passkey vaut à elle seule une authentification forte : possession de
    l'appareil + déverrouillage biométrique/PIN (user_verification=required).
    """
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None or not user.is_active or not user.credentials:
        raise HTTPException(
            status_code=400, detail="Connexion biométrique indisponible pour ce compte."
        )
    try:
        return json.loads(mfa_service.webauthn_authentication_options(db, user))
    except mfa_service.MfaError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/webauthn/login/verify", response_model=UserOut)
def webauthn_login_verify(
    payload: WebAuthnLoginVerifyIn,
    response: Response,
    db: Session = Depends(get_db),
) -> User:
    """Vérifie l'assertion de la passkey et ouvre directement la session."""
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None or not user.is_active or not user.credentials:
        raise HTTPException(status_code=401, detail="Connexion refusée.")

    try:
        mfa_service.webauthn_verify_authentication(db, user, payload.credential)
    except mfa_service.MfaError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    set_session_cookie(response, create_access_token(user.id))
    return user


@router.post("/forgot-password", status_code=202)
def forgot_password(payload: EmailIn) -> dict[str, str]:
    """Demande de réinitialisation du mot de passe.

    Anti-énumération : réponse STRICTEMENT identique que le compte existe ou
    non. NB : l'envoi d'e-mail n'est pas encore branché (pas de SMTP configuré) —
    cette route accuse réception et sera complétée avec le service d'e-mail.
    """
    _ = payload
    return {
        "message": "Si un compte existe pour cet e-mail, un lien de "
        "réinitialisation sera envoyé."
    }


@router.post("/logout", status_code=204)
def logout(response: Response) -> None:
    """Ferme la session en effaçant le cookie."""
    clear_session_cookie(response)


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    """Profil de l'utilisateur connecté (vérifie que la session est valide)."""
    return current_user


@router.patch("/me", response_model=UserOut)
def update_profile(
    payload: ProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """Change le nom et/ou l'e-mail affichés. Le mot de passe a sa propre route."""
    if payload.email is not None and payload.email != current_user.email:
        existing = db.scalar(select(User).where(User.email == payload.email))
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Un compte existe déjà avec cet e-mail.",
            )
        current_user.email = payload.email

    if payload.name is not None:
        current_user.name = payload.name.strip() or None

    db.commit()
    db.refresh(current_user)
    return current_user


@router.post("/me/password", status_code=204)
def change_password(
    payload: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Change le mot de passe : exige l'actuel pour éviter qu'une session

    volée (XSS, appareil laissé ouvert) suffise à verrouiller le compte hors
    de portée du vrai propriétaire.
    """
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Mot de passe actuel incorrect.",
        )
    current_user.hashed_password = hash_password(payload.new_password)
    db.commit()
