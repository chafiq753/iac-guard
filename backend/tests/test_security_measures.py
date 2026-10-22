"""Mesures de sécurité qui n'avaient pas de test dédié (numérotation de
PROJECT_ANALYSIS.md §10) : 10, 11, 17, 20, 21, 24, 25 — et 8, couvert par le
même test que 24."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pyotp
import pytest
from pydantic import ValidationError
from sqlalchemy import select
from webauthn.helpers import bytes_to_base64url

from app.core.config import DEV_SECRET_KEY, Settings
from app.models.credential import AuthChallenge, RecoveryCode, WebAuthnCredential
from app.models.user import User
from app.services import mfa
from tests.conftest import USER_EMAIL
from tests.test_triage_rbac import _member

STRONG_KEY = "k" * 48


def _user(db_session) -> User:
    return db_session.scalar(select(User).where(User.email == USER_EMAIL))


# --- 10. Rôle relu en base : une rétrogradation prend effet immédiatement -- #


def test_demotion_takes_effect_on_the_existing_token(client, auth_headers, db_session):
    second = _member(client, auth_headers, db_session, "admin", [])
    assert client.get("/api/admin/users", headers=second).status_code == 200

    second_id = db_session.scalar(
        select(User.id).where(User.email == "admin@iac-guard.io")
    )
    client.patch(
        f"/api/admin/users/{second_id}/role", json={"role": "viewer"}, headers=auth_headers
    )

    # Même JWT, émis quand il était admin : refusé dès la requête suivante.
    assert client.get("/api/admin/users", headers=second).status_code == 403


# --- 11. CORS restrictif ------------------------------------------------- #


def test_cors_allows_only_configured_origins(client):
    preflight = {"Access-Control-Request-Method": "GET"}

    ok = client.options(
        "/api/projects", headers={"Origin": "http://localhost:3000", **preflight}
    )
    assert ok.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert ok.headers["access-control-allow-credentials"] == "true"

    evil = client.options(
        "/api/projects", headers={"Origin": "https://evil.example", **preflight}
    )
    assert "access-control-allow-origin" not in evil.headers
    simple = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in simple.headers


# --- 17. Codes de secours stockés hachés --------------------------------- #


def test_recovery_codes_are_stored_hashed(client, auth_headers, db_session):
    secret = client.post("/api/auth/2fa/totp/setup", headers=auth_headers).json()["secret"]
    codes = client.post(
        "/api/auth/2fa/totp/confirm",
        json={"code": pyotp.TOTP(secret).now()},
        headers=auth_headers,
    ).json()["recovery_codes"]

    stored = {r.code_hash for r in db_session.scalars(select(RecoveryCode)).all()}
    assert len(codes) == len(stored) == 8
    assert not stored & set(codes)  # aucun code en clair
    assert stored == {hashlib.sha256(c.encode()).hexdigest() for c in codes}


# --- 20. Challenge WebAuthn à usage unique (et à durée limitée) ---------- #


def test_webauthn_challenge_is_single_use(auth_headers, db_session):
    user = _user(db_session)
    mfa._store_challenge(db_session, user.id, b"challenge-1", mfa.PURPOSE_AUTHENTICATE)

    assert mfa._consume_challenge(db_session, user.id, mfa.PURPOSE_AUTHENTICATE) == b"challenge-1"
    with pytest.raises(mfa.MfaError):  # rejeu
        mfa._consume_challenge(db_session, user.id, mfa.PURPOSE_AUTHENTICATE)


def test_expired_webauthn_challenge_is_rejected(auth_headers, db_session):
    user = _user(db_session)
    mfa._store_challenge(db_session, user.id, b"old", mfa.PURPOSE_AUTHENTICATE)
    row = db_session.scalar(select(AuthChallenge))
    row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()

    with pytest.raises(mfa.MfaError, match="expiré"):
        mfa._consume_challenge(db_session, user.id, mfa.PURPOSE_AUTHENTICATE)


# --- 21. Détection de clé clonée (compteur de signatures) ---------------- #


@pytest.mark.parametrize(("new_count", "accepted"), [(5, False), (10, False), (11, True), (0, True)])
def test_cloned_key_is_rejected(auth_headers, db_session, monkeypatch, new_count, accepted):
    user = _user(db_session)
    credential_id = b"cred-1"
    db_session.add(
        WebAuthnCredential(
            user_id=user.id, credential_id=credential_id, public_key=b"pk", sign_count=10
        )
    )
    db_session.commit()
    mfa._store_challenge(db_session, user.id, b"chal", mfa.PURPOSE_AUTHENTICATE)
    # La signature elle-même n'est pas l'objet du test : seule la règle
    # anti-clonage d'iac-guard l'est.
    monkeypatch.setattr(
        mfa,
        "verify_authentication_response",
        lambda **_: SimpleNamespace(new_sign_count=new_count),
    )
    credential = {"rawId": bytes_to_base64url(credential_id)}

    if accepted:
        stored = mfa.webauthn_verify_authentication(db_session, user, credential)
        assert stored.sign_count == new_count
    else:
        with pytest.raises(mfa.MfaError, match="clonée"):
            mfa.webauthn_verify_authentication(db_session, user, credential)


# --- 24 (et 8). Refus de démarrer en production mal configurée ----------- #


@pytest.mark.parametrize(
    "overrides",
    [
        {"secret_key": DEV_SECRET_KEY, "cookie_secure": True},  # clé publique
        {"secret_key": "court", "cookie_secure": True},  # clé trop courte
        {"secret_key": STRONG_KEY, "cookie_secure": False},  # 8 : HTTPS non imposé
    ],
)
def test_production_refuses_dangerous_configuration(overrides):
    with pytest.raises(ValidationError):
        Settings(environment="production", **overrides)


def test_production_starts_with_safe_configuration():
    settings = Settings(environment="production", secret_key=STRONG_KEY, cookie_secure=True)
    assert settings.is_production


# --- 25. Limitation du nombre d'invitations ------------------------------ #


def test_invitations_are_rate_limited(client, auth_headers):
    limit = Settings().max_invites_per_hour
    for i in range(limit):
        resp = client.post(
            "/api/admin/users/invite",
            json={"email": f"invite{i}@iac-guard.io", "role": "viewer"},
            headers=auth_headers,
        )
        assert resp.status_code == 201, resp.text

    over = client.post(
        "/api/admin/users/invite",
        json={"email": "one-too-many@iac-guard.io", "role": "viewer"},
        headers=auth_headers,
    )
    assert over.status_code == 429
