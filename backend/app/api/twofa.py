"""Routes 2FA — l'utilisateur choisit sa méthode : biométrie et/ou code TOTP.

Deux familles de routes, à ne pas confondre :

  * ENRÔLEMENT (`/setup`, `/register/…`) : réservé à un utilisateur DÉJÀ connecté
    (cookie de session). On n'active jamais une 2FA sans preuve que l'utilisateur
    sait s'en servir — sinon on l'enferme dehors.

  * VÉRIFICATION (`/verify`, `/authenticate/…`) : réservé à un utilisateur en
    cours de connexion (cookie MFA : mot de passe validé, 2FA en attente).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.cookies import set_session_cookie
from app.api.deps import get_current_user, get_mfa_user
from app.core.security import (
    create_access_token,
    generate_recovery_codes,
    hash_recovery_code,
    recovery_code_matches,
)
from app.db.session import get_db
from app.models.credential import RecoveryCode, WebAuthnCredential
from app.models.user import User
from app.schemas.user import (
    MfaEnabledOut,
    MfaStatus,
    RecoveryCodeIn,
    RecoveryCodesOut,
    TotpCode,
    TotpSetupOut,
    WebAuthnAuthVerify,
    WebAuthnDeviceOut,
    WebAuthnRegisterVerify,
)
from app.services import mfa as mfa_service

router = APIRouter(prefix="/api/auth/2fa", tags=["2fa"])


def _issue_recovery_codes(db: Session, user: User) -> list[str]:
    """(Re)génère les codes de secours. Les anciens sont invalidés."""
    db.query(RecoveryCode).filter(RecoveryCode.user_id == user.id).delete()
    codes = generate_recovery_codes()
    for code in codes:
        db.add(RecoveryCode(user_id=user.id, code_hash=hash_recovery_code(code)))
    db.commit()
    return codes


def _mfa_error(exc: mfa_service.MfaError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


# --------------------------------------------------------------------------- #
# État de la 2FA (page « Sécurité »)
# --------------------------------------------------------------------------- #


@router.get("/status", response_model=MfaStatus)
def mfa_status(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> MfaStatus:
    count = db.scalar(
        select(func.count())
        .select_from(RecoveryCode)
        .where(
            RecoveryCode.user_id == current_user.id,
            RecoveryCode.used_at.is_(None),
        )
    )
    return MfaStatus(
        totp_enabled=current_user.totp_enabled,
        webauthn_enabled=current_user.webauthn_enabled,
        devices=[
            WebAuthnDeviceOut.model_validate(c) for c in current_user.credentials
        ],
        recovery_codes_remaining=count or 0,
    )


# --------------------------------------------------------------------------- #
# WebAuthn — enrôlement (biométrie : Windows Hello, Touch ID, clé physique)
# --------------------------------------------------------------------------- #


@router.post("/webauthn/register/options")
def webauthn_register_options(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> dict:
    """Options pour `navigator.credentials.create()`."""
    try:
        options = mfa_service.webauthn_registration_options(db, current_user)
    except mfa_service.MfaError as exc:
        raise _mfa_error(exc) from exc
    return json.loads(options)


@router.post("/webauthn/register/verify", response_model=MfaEnabledOut)
def webauthn_register_verify(
    payload: WebAuthnRegisterVerify,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MfaEnabledOut:
    """Enregistre la clé publique de l'appareil (la clé privée y reste)."""
    first_method = not current_user.has_mfa
    try:
        mfa_service.webauthn_verify_registration(
            db, current_user, payload.credential, payload.device_name
        )
    except mfa_service.MfaError as exc:
        raise _mfa_error(exc) from exc

    # Codes de secours générés à la PREMIÈRE activation d'une 2FA : sans eux,
    # perdre l'appareil = perdre le compte.
    codes = _issue_recovery_codes(db, current_user) if first_method else []
    return MfaEnabledOut(method="webauthn", recovery_codes=codes)


@router.delete("/webauthn/{credential_id}", status_code=204)
def webauthn_delete_device(
    credential_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    credential = db.get(WebAuthnCredential, credential_id)
    if credential is None or credential.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Appareil introuvable.")
    db.delete(credential)
    db.commit()


# --------------------------------------------------------------------------- #
# WebAuthn — vérification à la connexion
# --------------------------------------------------------------------------- #


@router.post("/webauthn/authenticate/options")
def webauthn_auth_options(
    mfa_user: User = Depends(get_mfa_user), db: Session = Depends(get_db)
) -> dict:
    """Options pour `navigator.credentials.get()` (challenge à signer)."""
    try:
        options = mfa_service.webauthn_authentication_options(db, mfa_user)
    except mfa_service.MfaError as exc:
        raise _mfa_error(exc) from exc
    return json.loads(options)


@router.post("/webauthn/authenticate/verify")
def webauthn_auth_verify(
    payload: WebAuthnAuthVerify,
    response: Response,
    mfa_user: User = Depends(get_mfa_user),
    db: Session = Depends(get_db),
) -> dict:
    """Vérifie la signature biométrique et ouvre la session."""
    try:
        mfa_service.webauthn_verify_authentication(db, mfa_user, payload.credential)
    except mfa_service.MfaError as exc:
        raise _mfa_error(exc) from exc

    mfa_user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    set_session_cookie(response, create_access_token(mfa_user.id))
    return {"id": mfa_user.id, "email": mfa_user.email}


# --------------------------------------------------------------------------- #
# TOTP — enrôlement
# --------------------------------------------------------------------------- #


@router.post("/totp/setup", response_model=TotpSetupOut)
def totp_setup(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> TotpSetupOut:
    """Génère un secret à scanner. La 2FA n'est PAS encore active à ce stade."""
    secret = mfa_service.totp_generate_secret()
    current_user.totp_secret = secret
    current_user.totp_enabled = False
    db.commit()
    return TotpSetupOut(
        secret=secret,
        otpauth_uri=mfa_service.totp_provisioning_uri(current_user, secret),
    )


@router.post("/totp/confirm", response_model=MfaEnabledOut)
def totp_confirm(
    payload: TotpCode,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MfaEnabledOut:
    """Active le TOTP après qu'un premier code valide a été saisi."""
    if not current_user.totp_secret:
        raise HTTPException(
            status_code=400, detail="Aucun secret TOTP en attente. Refaites le setup."
        )
    if not mfa_service.totp_verify(current_user.totp_secret, payload.code):
        raise HTTPException(status_code=400, detail="Code invalide.")

    first_method = not current_user.has_mfa
    current_user.totp_enabled = True
    db.commit()

    codes = _issue_recovery_codes(db, current_user) if first_method else []
    return MfaEnabledOut(method="totp", recovery_codes=codes)


@router.delete("/totp", status_code=204)
def totp_disable(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> None:
    current_user.totp_enabled = False
    current_user.totp_secret = None
    db.commit()


# --------------------------------------------------------------------------- #
# TOTP — vérification à la connexion
# --------------------------------------------------------------------------- #


@router.post("/totp/verify")
def totp_verify_login(
    payload: TotpCode,
    response: Response,
    mfa_user: User = Depends(get_mfa_user),
    db: Session = Depends(get_db),
) -> dict:
    if not mfa_user.totp_enabled or not mfa_user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP non activé sur ce compte.")
    if not mfa_service.totp_verify(mfa_user.totp_secret, payload.code):
        raise HTTPException(status_code=401, detail="Code invalide.")

    mfa_user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    set_session_cookie(response, create_access_token(mfa_user.id))
    return {"id": mfa_user.id, "email": mfa_user.email}


# --------------------------------------------------------------------------- #
# Codes de récupération
# --------------------------------------------------------------------------- #


@router.post("/recovery/verify")
def recovery_verify(
    payload: RecoveryCodeIn,
    response: Response,
    mfa_user: User = Depends(get_mfa_user),
    db: Session = Depends(get_db),
) -> dict:
    """Connexion de secours si l'appareil 2FA est perdu. Code à usage unique."""
    codes = db.scalars(
        select(RecoveryCode).where(
            RecoveryCode.user_id == mfa_user.id, RecoveryCode.used_at.is_(None)
        )
    ).all()

    match = next(
        (c for c in codes if recovery_code_matches(payload.code, c.code_hash)), None
    )
    if match is None:
        raise HTTPException(status_code=401, detail="Code de récupération invalide.")

    match.used_at = datetime.now(timezone.utc)  # consommé : plus jamais réutilisable
    mfa_user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    set_session_cookie(response, create_access_token(mfa_user.id))
    return {"id": mfa_user.id, "email": mfa_user.email}


@router.post("/recovery/regenerate", response_model=RecoveryCodesOut)
def recovery_regenerate(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> RecoveryCodesOut:
    """Régénère les codes (invalide les anciens). Nécessite une session active."""
    if not current_user.has_mfa:
        raise HTTPException(status_code=400, detail="Aucune 2FA active.")
    return RecoveryCodesOut(codes=_issue_recovery_codes(db, current_user))
