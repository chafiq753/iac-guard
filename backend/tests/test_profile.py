"""Tests du profil utilisateur : nom, e-mail, mot de passe (Settings > Compte)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import USER_EMAIL, USER_PASSWORD, register_and_login


def test_update_name(client: TestClient, auth_headers: dict[str, str]) -> None:
    resp = client.patch("/api/auth/me", json={"name": "Ada Lovelace"}, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "Ada Lovelace"

    me = client.get("/api/auth/me", headers=auth_headers).json()
    assert me["name"] == "Ada Lovelace"


def test_update_email(client: TestClient, auth_headers: dict[str, str]) -> None:
    resp = client.patch(
        "/api/auth/me", json={"email": "nouveau@iac-guard.io"}, headers=auth_headers
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["email"] == "nouveau@iac-guard.io"


def test_update_email_conflict(client: TestClient, auth_headers: dict[str, str]) -> None:
    register_and_login(client, email="deja-pris@iac-guard.io")
    resp = client.patch(
        "/api/auth/me", json={"email": "deja-pris@iac-guard.io"}, headers=auth_headers
    )
    assert resp.status_code == 409


def test_change_password_requires_current(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    resp = client.post(
        "/api/auth/me/password",
        json={"current_password": "WrongPassword123!", "new_password": "NewSecret-Pass1!"},
        headers=auth_headers,
    )
    assert resp.status_code == 401


def test_change_password_success_and_relogin(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    resp = client.post(
        "/api/auth/me/password",
        json={"current_password": USER_PASSWORD, "new_password": "NewSecret-Pass1!"},
        headers=auth_headers,
    )
    assert resp.status_code == 204

    # L'ancien mot de passe ne fonctionne plus, le nouveau oui.
    old = client.post(
        "/api/auth/login", json={"email": USER_EMAIL, "password": USER_PASSWORD}
    )
    assert old.status_code == 401

    new = client.post(
        "/api/auth/login",
        json={"email": USER_EMAIL, "password": "NewSecret-Pass1!"},
    )
    assert new.status_code == 200


def test_change_password_rejects_weak_new_password(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    resp = client.post(
        "/api/auth/me/password",
        json={"current_password": USER_PASSWORD, "new_password": "weak"},
        headers=auth_headers,
    )
    assert resp.status_code == 422
