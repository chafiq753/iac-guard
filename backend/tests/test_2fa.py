"""Tests de la 2FA : TOTP, WebAuthn (biométrie) et codes de récupération.

L'assertion WebAuthn complète exige un vrai authentificateur (Windows Hello,
Touch ID) : impossible à simuler ici. On teste donc tout ce qui est testable
côté serveur — génération du challenge, rejet des réponses invalides, portée
des jetons — et la cérémonie biométrique réelle se vérifie dans le navigateur.
"""

from __future__ import annotations

from urllib.parse import unquote

import pyotp
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from tests.conftest import USER_EMAIL, USER_PASSWORD, register, register_and_login


def _login(client: TestClient) -> dict:
    return client.post(
        "/api/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    ).json()


def _enable_totp(client: TestClient, headers: dict[str, str]) -> str:
    """Active le TOTP et renvoie le secret."""
    setup = client.post("/api/auth/2fa/totp/setup", headers=headers).json()
    secret = setup["secret"]
    code = pyotp.TOTP(secret).now()
    resp = client.post(
        "/api/auth/2fa/totp/confirm", json={"code": code}, headers=headers
    )
    assert resp.status_code == 200, resp.text
    return secret


# --------------------------------------------------------------------------- #
# État initial
# --------------------------------------------------------------------------- #


def test_no_mfa_by_default(client: TestClient) -> None:
    headers = register_and_login(client)
    status = client.get("/api/auth/2fa/status", headers=headers).json()
    assert status["totp_enabled"] is False
    assert status["webauthn_enabled"] is False
    assert status["devices"] == []


# --------------------------------------------------------------------------- #
# TOTP — enrôlement
# --------------------------------------------------------------------------- #


def test_totp_setup_returns_secret_and_qr_uri(client: TestClient) -> None:
    headers = register_and_login(client)
    resp = client.post("/api/auth/2fa/totp/setup", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["secret"]
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    # L'e-mail est URL-encodé dans l'URI (@ -> %40) : on décode pour comparer.
    assert USER_EMAIL in unquote(body["otpauth_uri"])

    # Le setup seul n'active RIEN : il faut confirmer avec un vrai code.
    status = client.get("/api/auth/2fa/status", headers=headers).json()
    assert status["totp_enabled"] is False


def test_totp_confirm_with_wrong_code_does_not_enable(client: TestClient) -> None:
    headers = register_and_login(client)
    client.post("/api/auth/2fa/totp/setup", headers=headers)

    resp = client.post(
        "/api/auth/2fa/totp/confirm", json={"code": "000000"}, headers=headers
    )
    assert resp.status_code == 400
    status = client.get("/api/auth/2fa/status", headers=headers).json()
    assert status["totp_enabled"] is False


def test_totp_confirm_enables_and_returns_recovery_codes(client: TestClient) -> None:
    headers = register_and_login(client)
    setup = client.post("/api/auth/2fa/totp/setup", headers=headers).json()
    code = pyotp.TOTP(setup["secret"]).now()

    resp = client.post(
        "/api/auth/2fa/totp/confirm", json={"code": code}, headers=headers
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["method"] == "totp"
    # Codes de secours : sans eux, perdre son téléphone = perdre le compte.
    assert len(body["recovery_codes"]) == 8

    status = client.get("/api/auth/2fa/status", headers=headers).json()
    assert status["totp_enabled"] is True
    assert status["recovery_codes_remaining"] == 8


# --------------------------------------------------------------------------- #
# TOTP — connexion en deux étapes
# --------------------------------------------------------------------------- #


def test_login_with_totp_requires_second_factor(client: TestClient) -> None:
    headers = register_and_login(client)
    secret = _enable_totp(client, headers)
    client.cookies.clear()

    # 1) Mot de passe correct -> PAS de session, mais une demande de 2FA.
    resp = client.post(
        "/api/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mfa_required"] is True
    assert body["methods"] == ["totp"]
    assert body["user"] is None

    # Le cookie posé est le cookie MFA, PAS le cookie de session.
    raw = resp.headers["set-cookie"]
    assert settings.mfa_cookie_name in raw

    # À ce stade, l'API reste fermée.
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/projects").status_code == 401

    # 2) Second facteur -> session ouverte.
    verify = client.post(
        "/api/auth/2fa/totp/verify", json={"code": pyotp.TOTP(secret).now()}
    )
    assert verify.status_code == 200
    assert client.get("/api/auth/me").status_code == 200


def test_wrong_totp_code_at_login_is_rejected(client: TestClient) -> None:
    headers = register_and_login(client)
    _enable_totp(client, headers)
    client.cookies.clear()

    _login(client)  # pose le cookie MFA
    resp = client.post("/api/auth/2fa/totp/verify", json={"code": "000000"})
    assert resp.status_code == 401
    assert client.get("/api/auth/me").status_code == 401  # toujours fermé


def test_totp_verify_requires_the_mfa_cookie(client: TestClient) -> None:
    """Sans avoir passé l'étape mot de passe, impossible de valider un code."""
    headers = register_and_login(client)
    secret = _enable_totp(client, headers)
    client.cookies.clear()

    resp = client.post(
        "/api/auth/2fa/totp/verify", json={"code": pyotp.TOTP(secret).now()}
    )
    assert resp.status_code == 401


def test_session_token_cannot_replace_the_mfa_token(client: TestClient) -> None:
    """Un JWT de session ne doit pas servir à franchir l'étape 2FA (portées)."""
    headers = register_and_login(client)  # session obtenue AVANT d'activer la 2FA
    secret = _enable_totp(client, headers)
    client.cookies.clear()

    resp = client.post(
        "/api/auth/2fa/totp/verify",
        json={"code": pyotp.TOTP(secret).now()},
        headers=headers,  # jeton de portée `session`, pas `mfa`
    )
    assert resp.status_code == 401


def test_disabling_totp_restores_single_factor_login(client: TestClient) -> None:
    headers = register_and_login(client)
    _enable_totp(client, headers)

    assert client.delete("/api/auth/2fa/totp", headers=headers).status_code == 204

    client.cookies.clear()
    assert _login(client)["mfa_required"] is False


# --------------------------------------------------------------------------- #
# Codes de récupération
# --------------------------------------------------------------------------- #


def test_recovery_code_logs_in_and_is_single_use(client: TestClient) -> None:
    headers = register_and_login(client)
    setup = client.post("/api/auth/2fa/totp/setup", headers=headers).json()
    confirmed = client.post(
        "/api/auth/2fa/totp/confirm",
        json={"code": pyotp.TOTP(setup["secret"]).now()},
        headers=headers,
    ).json()
    code = confirmed["recovery_codes"][0]
    client.cookies.clear()

    # 1er usage : ouvre la session.
    _login(client)
    assert client.post("/api/auth/2fa/recovery/verify", json={"code": code}).status_code == 200
    assert client.get("/api/auth/me").status_code == 200

    # 2e usage du MÊME code : refusé (usage unique).
    client.cookies.clear()
    _login(client)
    replay = client.post("/api/auth/2fa/recovery/verify", json={"code": code})
    assert replay.status_code == 401


def test_unknown_recovery_code_is_rejected(client: TestClient) -> None:
    headers = register_and_login(client)
    _enable_totp(client, headers)
    client.cookies.clear()

    _login(client)
    resp = client.post("/api/auth/2fa/recovery/verify", json={"code": "dead-beef"})
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# WebAuthn (biométrie)
# --------------------------------------------------------------------------- #


def test_webauthn_registration_options_are_well_formed(client: TestClient) -> None:
    headers = register_and_login(client)
    resp = client.post("/api/auth/2fa/webauthn/register/options", headers=headers)
    assert resp.status_code == 200
    opts = resp.json()

    assert opts["rp"]["id"] == settings.webauthn_rp_id
    assert opts["challenge"]  # aléa à signer par l'appareil
    # « required » force l'appareil à vérifier l'utilisateur (empreinte/visage/PIN) :
    # sans ça, ce ne serait pas un vrai second facteur.
    assert opts["authenticatorSelection"]["userVerification"] == "required"


def test_webauthn_registration_rejects_garbage(client: TestClient) -> None:
    headers = register_and_login(client)
    client.post("/api/auth/2fa/webauthn/register/options", headers=headers)

    resp = client.post(
        "/api/auth/2fa/webauthn/register/verify",
        json={"credential": {"id": "bidon"}, "device_name": "Faux"},
        headers=headers,
    )
    assert resp.status_code == 400
    status = client.get("/api/auth/2fa/status", headers=headers).json()
    assert status["webauthn_enabled"] is False


def test_webauthn_auth_options_require_an_enrolled_device(client: TestClient) -> None:
    """Sans appareil enrôlé, on ne peut pas demander un challenge biométrique."""
    register(client)
    client.post(
        "/api/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    # L'utilisateur n'a pas de 2FA : pas de cookie MFA -> 401.
    assert (
        client.post("/api/auth/2fa/webauthn/authenticate/options").status_code == 401
    )


def test_webauthn_endpoints_require_authentication(client: TestClient) -> None:
    assert client.post("/api/auth/2fa/webauthn/register/options").status_code == 401
    assert client.get("/api/auth/2fa/status").status_code == 401


@pytest.mark.parametrize("path", ["/api/auth/2fa/totp/setup", "/api/auth/2fa/status"])
def test_2fa_management_needs_a_full_session_not_an_mfa_token(
    client: TestClient, path: str
) -> None:
    """On ne doit pas pouvoir gérer sa 2FA avec le jeton intermédiaire de login."""
    headers = register_and_login(client)
    _enable_totp(client, headers)
    client.cookies.clear()

    _login(client)  # cookie MFA seulement
    method = client.get if path.endswith("status") else client.post
    assert method(path).status_code == 401
