"""Tests de la gestion des comptes par l'admin (RBAC)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_token
from app.models.invitation import Invitation
from app.models.user import User
from tests.conftest import USER_PASSWORD, register_and_login

INVITEE_EMAIL = "analyste@iac-guard.io"
INVITEE_PASSWORD = "An0ther-Passw0rd!"


def _invite(
    client: TestClient,
    admin_headers: dict[str, str],
    email: str = INVITEE_EMAIL,
    role: str = "viewer",
):
    return client.post(
        "/api/admin/users/invite",
        json={"email": email, "role": role},
        headers=admin_headers,
    )


def _invitation_token(db_session, email: str = INVITEE_EMAIL) -> str:
    """Le jeton en clair n'est jamais renvoyé par l'API : en test on en forge
    un et on écrase le hash stocké, ce qui revient à « lire l'e-mail »."""
    invitation = db_session.scalar(
        select(Invitation).where(Invitation.email == email)
    )
    raw = "test-token-" + email
    invitation.token_hash = hash_token(raw)
    db_session.commit()
    return raw


# --------------------------------------------------------------------------- #
# Contrôle d'accès
# --------------------------------------------------------------------------- #


def test_admin_routes_require_authentication(client: TestClient) -> None:
    assert client.get("/api/admin/users").status_code == 401


def test_non_admin_cannot_access_admin_routes(
    client: TestClient, db_session
) -> None:
    """Un rôle non-admin reçoit 403 sur TOUTES les routes /api/admin/*."""
    admin_headers = register_and_login(client)
    _invite(client, admin_headers, role="developer")
    token = _invitation_token(db_session)
    client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )
    dev_headers = _login(client, INVITEE_EMAIL, INVITEE_PASSWORD)

    target_id = _find_user_id(db_session, INVITEE_EMAIL)
    routes = [
        ("get", "/api/admin/users", None),
        ("post", "/api/admin/users/invite", {"email": "x@y.io", "role": "viewer"}),
        ("patch", f"/api/admin/users/{target_id}/role", {"role": "admin"}),
        ("patch", f"/api/admin/users/{target_id}/status", {"is_active": False}),
        ("post", f"/api/admin/users/{target_id}/reset-webauthn", None),
        ("get", f"/api/admin/users/{target_id}/project-access", None),
        ("put", f"/api/admin/users/{target_id}/project-access", {"project_ids": []}),
        ("get", "/api/admin/audit-logs", None),
    ]
    for method, url, body in routes:
        call = getattr(client, method)
        resp = call(url, json=body, headers=dev_headers) if body is not None else call(
            url, headers=dev_headers
        )
        assert resp.status_code == 403, f"{method.upper()} {url} -> {resp.status_code}"


def _login(client: TestClient, email: str, password: str) -> dict[str, str]:
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    token = resp.cookies.get("iacguard_session")
    client.cookies.clear()
    return {"Authorization": f"Bearer {token}"}


def _find_user_id(db_session, email: str) -> int:
    return db_session.scalar(select(User.id).where(User.email == email))


# --------------------------------------------------------------------------- #
# Invitations
# --------------------------------------------------------------------------- #


def test_invite_creates_pending_account(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    resp = _invite(client, auth_headers)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == INVITEE_EMAIL
    # Le jeton ne doit JAMAIS transiter par la réponse HTTP.
    assert "token" not in body

    users = client.get("/api/admin/users", headers=auth_headers).json()
    invited = next(u for u in users["items"] if u["email"] == INVITEE_EMAIL)
    assert invited["status"] == "pending_invitation"
    assert invited["last_login_at"] is None


def test_accept_invitation_activates_account(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    _invite(client, auth_headers, role="auditor")
    token = _invitation_token(db_session)

    resp = client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["role"] == "auditor"

    # Le compte est désormais utilisable.
    assert _login(client, INVITEE_EMAIL, INVITEE_PASSWORD)


def test_expired_invitation_is_rejected(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    _invite(client, auth_headers)
    token = _invitation_token(db_session)
    invitation = db_session.scalar(
        select(Invitation).where(Invitation.email == INVITEE_EMAIL)
    )
    invitation.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()

    resp = client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )
    assert resp.status_code == 400
    assert "expir" in resp.json()["detail"].lower()


def test_invitation_token_is_single_use(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    _invite(client, auth_headers)
    token = _invitation_token(db_session)
    first = client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )
    assert first.status_code == 200
    second = client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )
    assert second.status_code == 400


def test_reinvite_invalidates_previous_token(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    """Renvoyer l'invitation régénère un jeton : l'ancien ne doit plus marcher."""
    _invite(client, auth_headers)
    old_token = _invitation_token(db_session)

    assert _invite(client, auth_headers).status_code == 201
    resp = client.post(
        f"/api/admin/invitations/{old_token}/accept",
        json={"password": INVITEE_PASSWORD},
    )
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# Rôles et statuts
# --------------------------------------------------------------------------- #


def test_change_role_is_audited(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    _invite(client, auth_headers, role="viewer")
    target_id = _find_user_id(db_session, INVITEE_EMAIL)

    resp = client.patch(
        f"/api/admin/users/{target_id}/role",
        json={"role": "security_lead"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "security_lead"

    logs = client.get(
        "/api/admin/audit-logs?action=user.role_changed", headers=auth_headers
    ).json()
    assert logs["total"] == 1
    entry = logs["items"][0]
    assert entry["details"] == {"old_role": "viewer", "new_role": "security_lead"}
    assert entry["target_user_email"] == INVITEE_EMAIL


def test_last_active_admin_cannot_be_demoted(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    admin_id = _find_user_id(db_session, "dev@iac-guard.io")
    resp = client.patch(
        f"/api/admin/users/{admin_id}/role",
        json={"role": "viewer"},
        headers=auth_headers,
    )
    assert resp.status_code == 409
    assert "dernier administrateur" in resp.json()["detail"].lower()


def test_last_active_admin_cannot_be_disabled(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    admin_id = _find_user_id(db_session, "dev@iac-guard.io")
    resp = client.patch(
        f"/api/admin/users/{admin_id}/status",
        json={"is_active": False},
        headers=auth_headers,
    )
    assert resp.status_code == 409


def test_admin_cannot_disable_self_even_with_another_admin(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    """Second admin présent : la règle « pas d'auto-désactivation » s'applique
    quand même (elle protège de l'erreur de manipulation, pas du lockout)."""
    _invite(client, auth_headers, role="admin")
    token = _invitation_token(db_session)
    client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )

    admin_id = _find_user_id(db_session, "dev@iac-guard.io")
    resp = client.patch(
        f"/api/admin/users/{admin_id}/status",
        json={"is_active": False},
        headers=auth_headers,
    )
    assert resp.status_code == 409
    assert "propre compte" in resp.json()["detail"].lower()


def test_disabled_user_cannot_log_in(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    _invite(client, auth_headers)
    token = _invitation_token(db_session)
    client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )
    target_id = _find_user_id(db_session, INVITEE_EMAIL)

    client.patch(
        f"/api/admin/users/{target_id}/status",
        json={"is_active": False},
        headers=auth_headers,
    )
    resp = client.post(
        "/api/auth/login",
        json={"email": INVITEE_EMAIL, "password": INVITEE_PASSWORD},
    )
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# Accès aux projets
# --------------------------------------------------------------------------- #


def test_user_without_project_access_sees_nothing(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    """Rôle non-global + aucun accès accordé = aucun projet visible."""
    client.post("/api/projects", json={"name": "acme/infra"}, headers=auth_headers)
    _invite(client, auth_headers, role="viewer")
    token = _invitation_token(db_session)
    client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )
    viewer_headers = _login(client, INVITEE_EMAIL, INVITEE_PASSWORD)

    assert client.get("/api/projects", headers=viewer_headers).json() == []
    assert client.get("/api/alerts", headers=viewer_headers).json()["total"] == 0


def test_granting_project_access_makes_it_visible(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    created = client.post(
        "/api/projects", json={"name": "acme/infra"}, headers=auth_headers
    ).json()
    _invite(client, auth_headers, role="viewer")
    token = _invitation_token(db_session)
    client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )
    target_id = _find_user_id(db_session, INVITEE_EMAIL)

    resp = client.put(
        f"/api/admin/users/{target_id}/project-access",
        json={"project_ids": [created["id"]]},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert [p["id"] for p in resp.json()] == [created["id"]]

    viewer_headers = _login(client, INVITEE_EMAIL, INVITEE_PASSWORD)
    visible = client.get("/api/projects", headers=viewer_headers).json()
    assert [p["id"] for p in visible] == [created["id"]]


def test_revoking_project_access_hides_it_again(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    created = client.post(
        "/api/projects", json={"name": "acme/infra"}, headers=auth_headers
    ).json()
    _invite(client, auth_headers, role="viewer")
    token = _invitation_token(db_session)
    client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )
    target_id = _find_user_id(db_session, INVITEE_EMAIL)

    client.put(
        f"/api/admin/users/{target_id}/project-access",
        json={"project_ids": [created["id"]]},
        headers=auth_headers,
    )
    client.put(
        f"/api/admin/users/{target_id}/project-access",
        json={"project_ids": []},
        headers=auth_headers,
    )

    viewer_headers = _login(client, INVITEE_EMAIL, INVITEE_PASSWORD)
    assert client.get("/api/projects", headers=viewer_headers).json() == []
    assert (
        client.get(f"/api/projects/{created['id']}", headers=viewer_headers).status_code
        == 404
    )


def test_security_lead_sees_all_org_projects_without_grant(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    """security_lead a un accès global : aucun ProjectAccess nécessaire."""
    created = client.post(
        "/api/projects", json={"name": "acme/infra"}, headers=auth_headers
    ).json()
    _invite(client, auth_headers, role="security_lead")
    token = _invitation_token(db_session)
    client.post(
        f"/api/admin/invitations/{token}/accept", json={"password": INVITEE_PASSWORD}
    )
    lead_headers = _login(client, INVITEE_EMAIL, INVITEE_PASSWORD)

    visible = client.get("/api/projects", headers=lead_headers).json()
    assert [p["id"] for p in visible] == [created["id"]]


def test_admin_cannot_manage_user_of_another_org(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    """Cloisonnement : un admin ne voit ni ne gère les comptes d'un autre client."""
    other_headers = register_and_login(
        client, email="autre@client.ma", password=USER_PASSWORD
    )
    other_id = _find_user_id(db_session, "autre@client.ma")

    listed = client.get("/api/admin/users", headers=auth_headers).json()
    assert all(u["email"] != "autre@client.ma" for u in listed["items"])

    resp = client.patch(
        f"/api/admin/users/{other_id}/role",
        json={"role": "viewer"},
        headers=auth_headers,
    )
    assert resp.status_code == 404
    assert other_headers  # l'autre compte reste utilisable


# --------------------------------------------------------------------------- #
# Reset WebAuthn
# --------------------------------------------------------------------------- #


def test_reset_webauthn_is_audited(
    client: TestClient, auth_headers: dict[str, str], db_session
) -> None:
    _invite(client, auth_headers)
    target_id = _find_user_id(db_session, INVITEE_EMAIL)

    resp = client.post(
        f"/api/admin/users/{target_id}/reset-webauthn", headers=auth_headers
    )
    assert resp.status_code == 204

    logs = client.get(
        "/api/admin/audit-logs?action=user.webauthn_reset", headers=auth_headers
    ).json()
    assert logs["total"] == 1
    assert logs["items"][0]["target_user_email"] == INVITEE_EMAIL
