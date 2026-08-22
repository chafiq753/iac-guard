"""Schémas Pydantic pour les utilisateurs, l'authentification et la 2FA."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

# 12 caractères minimum. Argon2 n'a pas la limite de 72 octets de bcrypt,
# mais on borne quand même pour ne pas transformer le login en DoS.
PASSWORD_MIN = 12
PASSWORD_MAX = 1024

# Règles de composition : chaque classe de caractères doit être présente.
_PASSWORD_RULES: list[tuple[str, str]] = [
    (r"[a-z]", "une minuscule"),
    (r"[A-Z]", "une majuscule"),
    (r"\d", "un chiffre"),
    (r"[^A-Za-z0-9]", "un caractère spécial (!@#$%…)"),
]


def _check_password_complexity(value: str) -> str:
    missing = [label for rx, label in _PASSWORD_RULES if not re.search(rx, value)]
    if missing:
        raise ValueError(
            "Le mot de passe doit contenir au moins " + ", ".join(missing) + "."
        )
    return value


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)
    # Nom de l'organisation créée pour ce compte (le premier utilisateur d'une
    # organisation en devient admin). Optionnel : à défaut, dérivé de l'e-mail.
    org_name: str | None = Field(default=None, max_length=200)

    # La politique est appliquée ICI, côté serveur : la validation du
    # formulaire front n'est qu'un confort, elle se contourne en un curl.
    _complexity = field_validator("password")(_check_password_complexity)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class EmailIn(BaseModel):
    """Payload ne contenant qu'un e-mail (étape 1 du login, mot de passe oublié)."""

    email: EmailStr


class LoginMethodsOut(BaseModel):
    """Méthodes de connexion proposables pour un e-mail donné.

    Anti-énumération : contient TOUJOURS "password", et un e-mail inconnu
    répond exactement comme un compte à mot de passe seul. Seuls les comptes
    ayant explicitement enrôlé une passkey exposent "webauthn" — information
    inutilisable sans l'appareil physique.
    """

    methods: list[str]


class WebAuthnLoginVerifyIn(BaseModel):
    """Connexion par passkey (1er facteur) : e-mail + assertion signée."""

    email: EmailStr
    credential: dict


class UserOut(BaseModel):
    """Utilisateur exposé par l'API : jamais le hash du mot de passe."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    name: str | None = None
    role: str
    created_at: datetime
    mfa_methods: list[str] = []


class ProfileUpdate(BaseModel):
    """Changement de nom et/ou d'e-mail (onglet Compte des Settings)."""

    name: str | None = Field(default=None, max_length=200)
    email: EmailStr | None = None


class PasswordChange(BaseModel):
    """Changement de mot de passe : exige l'actuel (évite un vol de session)."""

    current_password: str
    new_password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)

    _complexity = field_validator("new_password")(_check_password_complexity)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginResult(BaseModel):
    """Réponse de POST /api/auth/login.

    - `mfa_required=False` : la session est ouverte (cookie posé).
    - `mfa_required=True`  : il reste à valider un second facteur ; `methods`
      indique les choix de l'utilisateur (biométrie et/ou code).
    """

    mfa_required: bool
    methods: list[str] = []
    user: UserOut | None = None


# --------------------------------------------------------------------------- #
# 2FA
# --------------------------------------------------------------------------- #


class MfaStatus(BaseModel):
    """Ce que l'utilisateur a activé — pilote la page « Sécurité »."""

    totp_enabled: bool
    webauthn_enabled: bool
    devices: list["WebAuthnDeviceOut"] = []
    recovery_codes_remaining: int = 0


class WebAuthnDeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    last_used_at: datetime | None = None


class WebAuthnRegisterVerify(BaseModel):
    """Réponse brute de `navigator.credentials.create()` + nom de l'appareil."""

    credential: dict
    device_name: str = Field(default="Appareil", max_length=100)


class WebAuthnAuthVerify(BaseModel):
    """Réponse brute de `navigator.credentials.get()`."""

    credential: dict


class TotpSetupOut(BaseModel):
    """Secret à scanner. `otpauth_uri` est ce que le QR code encode."""

    secret: str
    otpauth_uri: str


class TotpCode(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class RecoveryCodeIn(BaseModel):
    code: str = Field(min_length=4, max_length=32)


class RecoveryCodesOut(BaseModel):
    """Montrés UNE seule fois : on ne stocke que leur hash."""

    codes: list[str]


class MfaEnabledOut(BaseModel):
    """Résultat d'une activation de 2FA."""

    method: Literal["totp", "webauthn"]
    recovery_codes: list[str] = []


MfaStatus.model_rebuild()
