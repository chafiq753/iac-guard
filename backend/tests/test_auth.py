"""Tests de l'authentification : Argon2id, cookie de session, anti-brute-force."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import select

from app.core.config import settings
from app.core.security import (
    BCRYPT_MAX_BYTES,
    JWT_ALGORITHM,
    MAX_PASSWORD_BYTES,
    SCOPE_MFA,
    SCOPE_SESSION,
    PasswordTooLongError,
    create_access_token,
    create_mfa_token,
    decode_access_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.models.user import User
from tests.conftest import USER_EMAIL, USER_PASSWORD, register, register_and_login


# --------------------------------------------------------------------------- #
# Hachage Argon2id
# --------------------------------------------------------------------------- #


def test_password_is_hashed_with_argon2id() -> None:
    hashed = hash_password(USER_PASSWORD)
    assert hashed.startswith("$argon2id$")  # bien Argon2id, pas Argon2i/d
    assert USER_PASSWORD not in hashed


def test_password_hash_is_salted_and_verifiable() -> None:
    h1 = hash_password(USER_PASSWORD)
    h2 = hash_password(USER_PASSWORD)

    assert h1 != h2  # sel aléatoire différent à chaque hachage
    assert verify_password(USER_PASSWORD, h1)
    assert verify_password(USER_PASSWORD, h2)
    assert not verify_password("mauvais-mot-de-passe", h1)


def test_absurdly_long_password_is_rejected() -> None:
    """Borne anti-DoS : hacher 1 Mo de données à chaque login coûterait cher."""
    with pytest.raises(PasswordTooLongError):
        hash_password("a" * (MAX_PASSWORD_BYTES + 1))


def test_verify_password_on_corrupted_hash_returns_false() -> None:
    assert not verify_password("peu importe", "pas-un-hash")


# --------------------------------------------------------------------------- #
# Migration transparente bcrypt -> Argon2id
# --------------------------------------------------------------------------- #


def test_legacy_bcrypt_hash_still_verifies() -> None:
    """Un compte créé avant la migration doit continuer à pouvoir se connecter."""
    legacy = bcrypt.hashpw(USER_PASSWORD.encode(), bcrypt.gensalt()).decode()
    assert verify_password(USER_PASSWORD, legacy)
    assert not verify_password("mauvais", legacy)
    assert needs_rehash(legacy)  # ... et doit être converti


def test_argon2_hash_does_not_need_rehash() -> None:
    assert not needs_rehash(hash_password(USER_PASSWORD))


def test_long_password_cannot_pass_via_bcrypt_truncation() -> None:
    """bcrypt ignore au-delà de 72 octets : deux mots de passe différents
    partageant les 72 premiers octets ne doivent PAS ouvrir le même compte."""
    base = "a" * BCRYPT_MAX_BYTES
    legacy = bcrypt.hashpw(base.encode(), bcrypt.gensalt()).decode()
    assert not verify_password(base + "SUFFIXE-DIFFERENT", legacy)


def test_login_upgrades_legacy_bcrypt_hash_to_argon2(client: TestClient) -> None:
    """À la connexion, un vieux hash bcrypt est silencieusement re-haché en Argon2."""
    register(client)

    # On rétrograde volontairement le hash en bcrypt, comme un ancien compte.
    from tests.conftest import _TestingSession  # noqa: PLC0415

    with _TestingSession() as db:
        user = db.scalar(select(User).where(User.email == USER_EMAIL))
        user.hashed_password = bcrypt.hashpw(
            USER_PASSWORD.encode(), bcrypt.gensalt()
        ).decode()
        db.commit()

    resp = client.post(
        "/api/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    assert resp.status_code == 200

    with _TestingSession() as db:
        user = db.scalar(select(User).where(User.email == USER_EMAIL))
        assert user.hashed_password.startswith("$argon2id$")


# --------------------------------------------------------------------------- #
# JWT et portées (session vs mfa)
# --------------------------------------------------------------------------- #


def test_jwt_roundtrip() -> None:
    assert decode_access_token(create_access_token(42), SCOPE_SESSION) == 42


def test_mfa_token_cannot_be_used_as_a_session(client: TestClient) -> None:
    """LE test critique : le jeton émis après le mot de passe (mais avant la 2FA)
    ne doit JAMAIS ouvrir l'API — sinon la 2FA serait contournable."""
    mfa_token = create_mfa_token(42)
    assert decode_access_token(mfa_token, SCOPE_SESSION) is None
    assert decode_access_token(mfa_token, SCOPE_MFA) == 42

    resp = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {mfa_token}"}
    )
    assert resp.status_code == 401


def test_jwt_with_wrong_signature_is_rejected() -> None:
    forged = jwt.encode(
        {
            "sub": "42",
            "scope": SCOPE_SESSION,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        "mauvaise-cle",
        algorithm=JWT_ALGORITHM,
    )
    assert decode_access_token(forged) is None


def test_expired_jwt_is_rejected() -> None:
    expired = jwt.encode(
        {
            "sub": "42",
            "scope": SCOPE_SESSION,
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        },
        settings.secret_key,
        algorithm=JWT_ALGORITHM,
    )
    assert decode_access_token(expired) is None


def test_malformed_jwt_is_rejected() -> None:
    assert decode_access_token("pas.un.jwt") is None


# --------------------------------------------------------------------------- #
# Inscription
# --------------------------------------------------------------------------- #


def test_register_never_returns_password(client: TestClient) -> None:
    resp = client.post(
        "/api/auth/register", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["email"] == USER_EMAIL
    assert "password" not in body
    assert "hashed_password" not in body


def test_register_duplicate_email_conflicts(client: TestClient) -> None:
    payload = {"email": USER_EMAIL, "password": USER_PASSWORD}
    assert client.post("/api/auth/register", json=payload).status_code == 201
    assert client.post("/api/auth/register", json=payload).status_code == 409


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "pas-un-email", "password": USER_PASSWORD},
        {"email": USER_EMAIL, "password": "court"},        # < 12 caractères
        {"email": USER_EMAIL, "password": "onze-chars!"},  # 11 caractères
        {"email": USER_EMAIL},                             # mot de passe absent
        # Politique de composition : chaque classe doit être présente.
        {"email": USER_EMAIL, "password": "tout-minuscule-9!"},   # pas de majuscule
        {"email": USER_EMAIL, "password": "TOUT-MAJUSCULE-9!"},   # pas de minuscule
        {"email": USER_EMAIL, "password": "Pas-De-Chiffre-Ici!"}, # pas de chiffre
        {"email": USER_EMAIL, "password": "PasDeSpecial12345"},   # pas de spécial
    ],
)
def test_register_rejects_invalid_payloads(client: TestClient, payload: dict) -> None:
    assert client.post("/api/auth/register", json=payload).status_code == 422


# --------------------------------------------------------------------------- #
# Connexion + cookie de session
# --------------------------------------------------------------------------- #


def test_login_sets_httponly_session_cookie(client: TestClient) -> None:
    register(client)
    resp = client.post(
        "/api/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mfa_required"] is False
    assert body["user"]["email"] == USER_EMAIL

    raw = resp.headers["set-cookie"]
    assert settings.session_cookie_name in raw
    # httpOnly : JavaScript ne peut pas lire le cookie -> un XSS ne vole pas la session.
    assert "httponly" in raw.lower()
    assert "samesite=lax" in raw.lower()

    # Le cookie seul (sans en-tête Authorization) suffit à ouvrir l'API.
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == USER_EMAIL


def test_logout_clears_the_session(client: TestClient) -> None:
    register(client)
    client.post(
        "/api/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    assert client.get("/api/auth/me").status_code == 200

    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_login_with_wrong_password_is_401(client: TestClient) -> None:
    register(client)
    resp = client.post(
        "/api/auth/login", json={"email": USER_EMAIL, "password": "mauvais-mdp-xyz"}
    )
    assert resp.status_code == 401
    assert settings.session_cookie_name not in resp.headers.get("set-cookie", "")


def test_login_unknown_email_gives_same_error_as_wrong_password(
    client: TestClient,
) -> None:
    """Ne pas révéler quels e-mails sont enregistrés (énumération de comptes)."""
    register(client)
    unknown = client.post(
        "/api/auth/login",
        json={"email": "inconnu@iac-guard.io", "password": "peu-importe-123"},
    )
    wrong = client.post(
        "/api/auth/login", json={"email": USER_EMAIL, "password": "mauvais-mdp-xyz"}
    )
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]


# --------------------------------------------------------------------------- #
# Anti-brute-force
# --------------------------------------------------------------------------- #


def test_account_locks_after_too_many_failed_attempts(client: TestClient) -> None:
    register(client)
    bad = {"email": USER_EMAIL, "password": "mauvais-mdp-xyz"}

    for _ in range(settings.max_login_attempts):
        assert client.post("/api/auth/login", json=bad).status_code == 401

    # Au-delà du seuil : verrouillé (429), même avec le BON mot de passe.
    locked = client.post(
        "/api/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    assert locked.status_code == 429


def test_successful_login_resets_the_failure_counter(client: TestClient) -> None:
    register(client)
    bad = {"email": USER_EMAIL, "password": "mauvais-mdp-xyz"}
    good = {"email": USER_EMAIL, "password": USER_PASSWORD}

    for _ in range(settings.max_login_attempts - 1):
        client.post("/api/auth/login", json=bad)

    assert client.post("/api/auth/login", json=good).status_code == 200
    client.cookies.clear()

    # Le compteur est reparti de zéro : on peut de nouveau échouer sans verrou.
    for _ in range(settings.max_login_attempts - 1):
        assert client.post("/api/auth/login", json=bad).status_code == 401
    assert client.post("/api/auth/login", json=good).status_code == 200


# --------------------------------------------------------------------------- #
# Routes protégées
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/auth/me"),
        ("get", "/api/auth/2fa/status"),
        ("get", "/api/projects"),
        ("post", "/api/projects"),
        ("get", "/api/projects/1"),
        ("get", "/api/projects/1/scans"),
        ("get", "/api/scans/1"),
        ("get", "/api/scans/1/findings"),
    ],
)
def test_protected_routes_require_authentication(
    client: TestClient, method: str, path: str
) -> None:
    assert getattr(client, method)(path).status_code == 401
    bad = getattr(client, method)(
        path, headers={"Authorization": "Bearer pas.un.jwt"}
    )
    assert bad.status_code == 401


def test_jwt_of_deleted_user_is_rejected(client: TestClient) -> None:
    token = create_access_token(9999)  # aucun utilisateur avec cet id
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_me_exposes_no_secret(client: TestClient) -> None:
    headers = register_and_login(client)
    body = client.get("/api/auth/me", headers=headers).json()
    for leaked in ("hashed_password", "password", "totp_secret"):
        assert leaked not in body


# --------------------------------------------------------------------------- #
# Login en 2 étapes : découverte des méthodes + passkey 1er facteur
# --------------------------------------------------------------------------- #


def test_login_methods_do_not_reveal_account_existence(client: TestClient) -> None:
    """E-mail inconnu et compte à mot de passe seul : réponses identiques."""
    register(client)
    known = client.post("/api/auth/methods", json={"email": USER_EMAIL}).json()
    unknown = client.post(
        "/api/auth/methods", json={"email": "fantome@iac-guard.io"}
    ).json()
    assert known == unknown == {"methods": ["password"]}


def test_login_methods_offer_webauthn_first_when_enrolled(client: TestClient) -> None:
    register(client)

    # On enrôle une passkey directement en base (la cérémonie complète exige
    # un vrai authentificateur, hors de portée d'un test serveur).
    from app.models.credential import WebAuthnCredential  # noqa: PLC0415
    from tests.conftest import _TestingSession  # noqa: PLC0415

    with _TestingSession() as db:
        user = db.scalar(select(User).where(User.email == USER_EMAIL))
        db.add(
            WebAuthnCredential(
                user_id=user.id,
                credential_id=b"cred-test",
                public_key=b"pk-test",
                sign_count=0,
                name="Appareil de test",
            )
        )
        db.commit()

    methods = client.post("/api/auth/methods", json={"email": USER_EMAIL}).json()[
        "methods"
    ]
    # webauthn en tête : le front la met en priorité visuelle,
    # le mot de passe reste toujours proposé en repli.
    assert methods == ["webauthn", "password"]


def test_webauthn_login_options_unavailable_without_device(
    client: TestClient,
) -> None:
    register(client)
    resp = client.post(
        "/api/auth/webauthn/login/options", json={"email": USER_EMAIL}
    )
    assert resp.status_code == 400


def test_webauthn_login_verify_rejects_garbage(client: TestClient) -> None:
    register(client)
    resp = client.post(
        "/api/auth/webauthn/login/verify",
        json={"email": USER_EMAIL, "credential": {"id": "bidon"}},
    )
    assert resp.status_code == 401
    # Et surtout : aucune session n'a été ouverte.
    assert client.get("/api/auth/me").status_code == 401


def test_forgot_password_is_indistinguishable(client: TestClient) -> None:
    """Même statut et même corps, que le compte existe ou non."""
    register(client)
    known = client.post("/api/auth/forgot-password", json={"email": USER_EMAIL})
    unknown = client.post(
        "/api/auth/forgot-password", json={"email": "fantome@iac-guard.io"}
    )
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
