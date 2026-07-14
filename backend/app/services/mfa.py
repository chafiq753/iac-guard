"""Service 2FA : WebAuthn (biométrie / passkey) et TOTP (code à 6 chiffres).

L'utilisateur choisit la méthode qu'il préfère — les deux peuvent coexister.

WebAuthn en deux mots : le serveur envoie un « challenge » aléatoire, l'appareil
le signe avec une clé privée qui ne sort jamais du TPM/Secure Enclave (débloquée
par l'empreinte ou le PIN), et le serveur vérifie la signature avec la clé
publique. Le serveur ne voit jamais la biométrie.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pyotp
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json
# WebAuthnException est la base de toutes les erreurs de la lib (parsing JSON,
# signature invalide, structure CBOR corrompue…) : on la capture en entier
# plutôt que d'énumérer chaque sous-classe et d'en oublier une (-> 500).
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.core.config import settings
from app.models.credential import AuthChallenge, WebAuthnCredential
from app.models.user import User

CHALLENGE_TTL_SECONDS = 300

PURPOSE_REGISTER = "register"
PURPOSE_AUTHENTICATE = "authenticate"


class MfaError(Exception):
    """Échec de vérification 2FA (signature invalide, code faux, challenge expiré)."""


# --------------------------------------------------------------------------- #
# Challenges (stockés en base, à usage unique)
# --------------------------------------------------------------------------- #


def _store_challenge(db: Session, user_id: int, challenge: bytes, purpose: str) -> None:
    # Un seul challenge en cours par (utilisateur, usage) : on écrase l'ancien.
    db.execute(
        delete(AuthChallenge).where(
            AuthChallenge.user_id == user_id, AuthChallenge.purpose == purpose
        )
    )
    db.add(
        AuthChallenge(
            user_id=user_id,
            challenge=challenge,
            purpose=purpose,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=CHALLENGE_TTL_SECONDS),
        )
    )
    db.commit()


def _consume_challenge(db: Session, user_id: int, purpose: str) -> bytes:
    """Récupère le challenge ET le supprime : il ne doit servir qu'une fois."""
    row = db.scalar(
        select(AuthChallenge).where(
            AuthChallenge.user_id == user_id, AuthChallenge.purpose == purpose
        )
    )
    if row is None:
        raise MfaError("Aucun challenge en cours. Recommencez.")

    challenge, expires_at = row.challenge, row.expires_at
    db.delete(row)
    db.commit()

    # `expires_at` peut revenir naïf de SQLite : on le re-situe en UTC.
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise MfaError("Challenge expiré. Recommencez.")

    return challenge


# --------------------------------------------------------------------------- #
# WebAuthn — enrôlement d'un appareil
# --------------------------------------------------------------------------- #


def webauthn_registration_options(db: Session, user: User) -> str:
    """Options à passer à `navigator.credentials.create()` (JSON)."""
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=str(user.id).encode("utf-8"),
        user_name=user.email,
        user_display_name=user.email,
        # Empêche d'enrôler deux fois le même appareil.
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=c.credential_id) for c in user.credentials
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            # REQUIRED = l'appareil DOIT vérifier l'utilisateur (empreinte,
            # visage ou PIN). Sans ça, une simple présence suffirait et on
            # n'aurait pas un vrai second facteur.
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
    )
    _store_challenge(db, user.id, options.challenge, PURPOSE_REGISTER)
    return options_to_json(options)


def webauthn_verify_registration(
    db: Session, user: User, credential: dict, device_name: str
) -> WebAuthnCredential:
    """Vérifie la réponse de l'appareil et enregistre sa CLÉ PUBLIQUE."""
    expected_challenge = _consume_challenge(db, user.id, PURPOSE_REGISTER)

    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origins,
            require_user_verification=True,
        )
    except WebAuthnException as exc:
        raise MfaError(f"Enrôlement refusé : {exc}") from exc

    record = WebAuthnCredential(
        user_id=user.id,
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        name=device_name or "Appareil",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


# --------------------------------------------------------------------------- #
# WebAuthn — connexion
# --------------------------------------------------------------------------- #


def webauthn_authentication_options(db: Session, user: User) -> str:
    """Options à passer à `navigator.credentials.get()` (JSON)."""
    if not user.credentials:
        raise MfaError("Aucun appareil biométrique enregistré.")

    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=c.credential_id) for c in user.credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    _store_challenge(db, user.id, options.challenge, PURPOSE_AUTHENTICATE)
    return options_to_json(options)


def webauthn_verify_authentication(
    db: Session, user: User, credential: dict
) -> WebAuthnCredential:
    """Vérifie la signature produite par l'appareil (empreinte / Windows Hello)."""
    expected_challenge = _consume_challenge(db, user.id, PURPOSE_AUTHENTICATE)

    raw_id = credential.get("rawId") or credential.get("id")
    if not raw_id:
        raise MfaError("Réponse d'authentification invalide.")

    from webauthn.helpers import base64url_to_bytes  # noqa: PLC0415

    try:
        credential_id = base64url_to_bytes(raw_id)
    except Exception as exc:  # noqa: BLE001
        raise MfaError("Identifiant de clé illisible.") from exc

    stored = next(
        (c for c in user.credentials if c.credential_id == credential_id), None
    )
    if stored is None:
        raise MfaError("Cette clé n'est pas enregistrée pour ce compte.")

    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origins,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
    except WebAuthnException as exc:
        raise MfaError(f"Authentification refusée : {exc}") from exc

    # Compteur anti-clonage : il doit progresser. Certains authentificateurs
    # (dont beaucoup de passkeys) renvoient toujours 0 — dans ce cas on ne peut
    # rien en déduire et on n'applique pas la vérification.
    if verified.new_sign_count != 0 and verified.new_sign_count <= stored.sign_count:
        raise MfaError("Clé potentiellement clonée : authentification refusée.")

    stored.sign_count = verified.new_sign_count
    stored.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return stored


# --------------------------------------------------------------------------- #
# TOTP (Google Authenticator, Authy…)
# --------------------------------------------------------------------------- #


def totp_generate_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(user: User, secret: str) -> str:
    """URI `otpauth://` — c'est ce que le QR code encode."""
    return pyotp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name=settings.webauthn_rp_name
    )


def totp_verify(secret: str, code: str) -> bool:
    """Vérifie un code à 6 chiffres.

    `valid_window=1` tolère la fenêtre précédente/suivante (±30 s) : les horloges
    des téléphones dérivent, sans ça des codes valides seraient refusés.
    """
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)
