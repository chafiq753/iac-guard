"""Sécurité : deux mécanismes d'authentification distincts.

1. TOKEN DE PROJET (pipeline -> API) : authentifie GitHub Actions.
   Montré UNE seule fois à la création ; en base on ne garde que son hash
   SHA-256. Impossible de le retrouver s'il est perdu : on en régénère un.
   SHA-256 (sans sel) suffit ici : le token est long et aléatoire (256 bits),
   donc non attaquable par dictionnaire.

2. MOT DE PASSE + JWT (humain -> dashboard) : authentifie un utilisateur.
   Le mot de passe est choisi par un humain (donc devinable) : il est haché
   avec **Argon2id** (recommandation OWASP), jamais avec SHA-256.

   Argon2id est "memory-hard" : il impose au vérificateur d'utiliser beaucoup
   de RAM, ce qui rend le crassage massif sur GPU/ASIC bien plus coûteux que
   bcrypt. Les anciens hash bcrypt restent acceptés à la connexion, puis sont
   re-hachés en Argon2id de façon transparente (voir `needs_rehash`).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from jose import JWTError, jwt

from app.core.config import settings

# Argon2id avec les paramètres par défaut d'argon2-cffi (alignés OWASP :
# m=64 MiB, t=3, p=4). Le sel est généré et embarqué dans le hash.
_argon2 = PasswordHasher()

# bcrypt ignore silencieusement les octets au-delà de 72 : on refuse plutôt
# que de tronquer, sinon deux mots de passe différents ouvriraient le même
# compte. Argon2 n'a pas cette limite, mais on garde une borne raisonnable
# pour ne pas transformer le login en déni de service (hacher 1 Mo de "a").
MAX_PASSWORD_BYTES = 1024
BCRYPT_MAX_BYTES = 72

JWT_ALGORITHM = "HS256"

# Portée d'un JWT : une session complète, ou seulement l'étape 2FA.
# Un jeton "mfa" ne doit JAMAIS ouvrir l'API — uniquement finir la 2FA.
SCOPE_SESSION = "session"
SCOPE_MFA = "mfa"

TOKEN_PREFIX = "iacg_"


def generate_project_token() -> str:
    """Crée un nouveau token en clair, à donner au client (non stocké tel quel)."""
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash déterministe du token, pour stockage et comparaison."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_preview(token: str) -> str:
    """Début du token, affichable dans l'UI (ex: iacg_ab12…)."""
    return token[: len(TOKEN_PREFIX) + 4] + "…"


# --------------------------------------------------------------------------- #
# Mots de passe utilisateurs (Argon2id, avec repli bcrypt en lecture)
# --------------------------------------------------------------------------- #


class PasswordTooLongError(ValueError):
    """Mot de passe déraisonnablement long (protection contre le DoS au login)."""


def hash_password(password: str) -> str:
    """Hache un mot de passe avec Argon2id (sel aléatoire embarqué dans le hash)."""
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise PasswordTooLongError(
            f"Le mot de passe ne doit pas dépasser {MAX_PASSWORD_BYTES} octets."
        )
    return _argon2.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Vérifie un mot de passe. Ne lève jamais : renvoie False en cas de doute.

    Accepte les hash Argon2id (actuels) ET bcrypt (anciens comptes), pour que
    la migration soit transparente pour l'utilisateur.
    """
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        return False

    # Ancien hash bcrypt : `$2a$` / `$2b$` / `$2y$`.
    if hashed.startswith("$2"):
        # bcrypt tronque au-delà de 72 octets : refuser plutôt que de laisser
        # un mot de passe trop long valider par sa seule troncature.
        if len(raw) > BCRYPT_MAX_BYTES:
            return False
        try:
            return bcrypt.checkpw(raw, hashed.encode("utf-8"))
        except ValueError:
            return False

    try:
        return _argon2.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        # Mot de passe faux, hash corrompu ou format inconnu : on refuse.
        return False


def needs_rehash(hashed: str) -> bool:
    """Vrai si le hash doit être régénéré (ancien bcrypt, ou paramètres Argon2
    obsolètes). Appelé après une connexion réussie : on connaît alors le mot de
    passe en clair, c'est le seul moment où l'on peut re-hacher."""
    if hashed.startswith("$2"):
        return True
    try:
        return _argon2.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


# --------------------------------------------------------------------------- #
# JWT utilisateurs
# --------------------------------------------------------------------------- #


def _create_token(user_id: int, scope: str, expires_in: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),  # la spec JWT impose une chaîne pour `sub`
        "scope": scope,
        "iat": now,
        "exp": now + expires_in,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM)


def create_access_token(user_id: int) -> str:
    """JWT de session complète : ouvre l'API."""
    return _create_token(
        user_id,
        SCOPE_SESSION,
        timedelta(minutes=settings.access_token_expire_minutes),
    )


def create_mfa_token(user_id: int) -> str:
    """JWT intermédiaire : mot de passe validé, 2FA encore à faire.

    Volontairement de courte durée et de portée `mfa` : il ne permet QUE de
    terminer la 2FA, jamais d'accéder aux données.
    """
    return _create_token(
        user_id, SCOPE_MFA, timedelta(minutes=settings.mfa_token_expire_minutes)
    )


def decode_access_token(token: str, expected_scope: str = SCOPE_SESSION) -> int | None:
    """Renvoie l'id utilisateur si le JWT est valide, non expiré ET de la bonne
    portée. Sinon None.

    La vérification de portée est essentielle : sans elle, le jeton délivré
    après le mot de passe (mais avant la 2FA) ouvrirait l'API — la 2FA
    deviendrait contournable.
    """
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[JWT_ALGORITHM])
    except JWTError:
        # Signature invalide, token expiré ou malformé.
        return None

    if payload.get("scope") != expected_scope:
        return None

    sub = payload.get("sub")
    if sub is None:
        return None
    try:
        return int(sub)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Codes de récupération (si l'appareil biométrique est perdu)
# --------------------------------------------------------------------------- #

RECOVERY_CODE_COUNT = 8


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Codes à usage unique, montrés UNE seule fois à l'activation de la 2FA."""
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(count)]


def hash_recovery_code(code: str) -> str:
    """Hash d'un code de récupération.

    SHA-256 suffit (contrairement au mot de passe) : le code est généré
    aléatoirement, donc non devinable par dictionnaire.
    """
    return hashlib.sha256(code.strip().lower().encode("utf-8")).hexdigest()


def recovery_code_matches(code: str, hashed: str) -> bool:
    """Comparaison à temps constant (évite les attaques temporelles)."""
    return hmac.compare_digest(hash_recovery_code(code), hashed)
