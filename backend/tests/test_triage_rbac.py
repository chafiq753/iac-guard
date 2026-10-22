"""RBAC du triage et des exceptions de politique.

  - triage : admin, security_lead, developer (ce dernier sur ses projets
    accessibles uniquement) ; auditor et viewer sont en lecture seule (403) ;
  - exceptions (règles ignorées) : admin et security_lead uniquement.

Les comptes auditor / viewer / developer reçoivent un ACCÈS au projet : le
refus testé vient donc bien du rôle, pas du cloisonnement.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_token
from app.models.invitation import Invitation
from app.models.user import User
from tests.conftest import sample_report

PASSWORD = "An0ther-Passw0rd!"


def _member(client, admin_headers, db_session, role: str, project_ids: list[int]) -> dict:
    """Invite un membre, active son compte, lui partage des projets, le connecte."""
    email = f"{role}@iac-guard.io"
    resp = client.post(
        "/api/admin/users/invite", json={"email": email, "role": role}, headers=admin_headers
    )
    assert resp.status_code == 201, resp.text

    # Le jeton n'existe que dans l'e-mail : on en forge un (cf. test_admin.py).
    invitation = db_session.scalar(select(Invitation).where(Invitation.email == email))
    invitation.token_hash = hash_token("t-" + email)
    db_session.commit()
    client.post(f"/api/admin/invitations/t-{email}/accept", json={"password": PASSWORD})

    if project_ids:
        user_id = db_session.scalar(select(User.id).where(User.email == email))
        client.put(
            f"/api/admin/users/{user_id}/project-access",
            json={"project_ids": project_ids},
            headers=admin_headers,
        )

    resp = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    token = resp.cookies.get("iacguard_session")
    client.cookies.clear()
    return {"Authorization": f"Bearer {token}"}


def _project_with_scan(client, admin_headers, name: str) -> tuple[int, int, int]:
    """Crée un projet + un scan ; renvoie (project_id, scan_id, finding_id)."""
    created = client.post("/api/projects", json={"name": name}, headers=admin_headers).json()
    scan_id = client.post(
        "/api/scans",
        json=sample_report(),
        headers={"Authorization": f"Bearer {created['token']}"},
    ).json()["scan_id"]
    finding = client.get(f"/api/scans/{scan_id}/findings", headers=admin_headers).json()[0]
    return created["id"], scan_id, finding["id"]


def _triage(client, headers, scan_id: int, finding_id: int, note: str | None = None):
    return client.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}/triage",
        json={"status": "acknowledged", "note": note},
        headers=headers,
    )


@pytest.mark.parametrize("role", ["viewer", "auditor"])
def test_read_only_roles_cannot_triage(client, auth_headers, db_session, role):
    project_id, scan_id, finding_id = _project_with_scan(client, auth_headers, "acme/a")
    headers = _member(client, auth_headers, db_session, role, [project_id])

    # Il voit bien le projet...
    assert client.get(f"/api/scans/{scan_id}/findings", headers=headers).status_code == 200
    # ... mais ne peut pas trier, et rien n'est écrit.
    assert _triage(client, headers, scan_id, finding_id).status_code == 403
    assert client.get("/api/audit-log", headers=auth_headers).json()["total"] == 0


def test_developer_can_triage_shared_project_with_note(client, auth_headers, db_session):
    project_id, scan_id, finding_id = _project_with_scan(client, auth_headers, "acme/a")
    headers = _member(client, auth_headers, db_session, "developer", [project_id])

    resp = _triage(client, headers, scan_id, finding_id, note="Corrigé dans la PR #42")
    assert resp.status_code == 200, resp.text
    assert resp.json()["triage_note"] == "Corrigé dans la PR #42"

    entry = client.get("/api/audit-log", headers=auth_headers).json()["items"][0]
    assert entry["user_email"] == "developer@iac-guard.io"
    assert entry["note"] == "Corrigé dans la PR #42"


def test_developer_cannot_triage_unshared_project(client, auth_headers, db_session):
    shared_id, _, _ = _project_with_scan(client, auth_headers, "acme/a")
    _, other_scan, other_finding = _project_with_scan(client, auth_headers, "acme/b")
    headers = _member(client, auth_headers, db_session, "developer", [shared_id])

    # 404 et non 403 : le projet non partagé doit rester invisible.
    assert _triage(client, headers, other_scan, other_finding).status_code == 404


def test_security_lead_can_triage_without_grant(client, auth_headers, db_session):
    _, scan_id, finding_id = _project_with_scan(client, auth_headers, "acme/a")
    headers = _member(client, auth_headers, db_session, "security_lead", [])

    assert _triage(client, headers, scan_id, finding_id).status_code == 200


@pytest.mark.parametrize("role", ["developer", "auditor", "viewer"])
def test_only_admin_and_security_lead_manage_exceptions(
    client: TestClient, auth_headers, db_session, role
):
    project_id, _, _ = _project_with_scan(client, auth_headers, "acme/a")
    headers = _member(client, auth_headers, db_session, role, [project_id])
    url = f"/api/projects/{project_id}/ignored-rules"

    assert client.post(url, json={"rule_id": "CKV_AWS_20", "note": "CDN public"}, headers=headers).status_code == 403

    rule = client.post(url, json={"rule_id": "CKV_AWS_20", "note": "CDN public"}, headers=auth_headers).json()
    assert client.delete(f"{url}/{rule['id']}", headers=headers).status_code == 403
    # L'exception est toujours là.
    policy = client.get(f"/api/projects/{project_id}/policy", headers=auth_headers).json()
    assert [r["rule_id"] for r in policy["ignored_rules"]] == ["CKV_AWS_20"]


def test_security_lead_can_manage_exceptions(client, auth_headers, db_session):
    project_id, _, _ = _project_with_scan(client, auth_headers, "acme/a")
    headers = _member(client, auth_headers, db_session, "security_lead", [])
    url = f"/api/projects/{project_id}/ignored-rules"

    rule = client.post(url, json={"rule_id": "CKV_AWS_20", "note": "CDN"}, headers=headers)
    assert rule.status_code == 201, rule.text
    assert client.delete(f"{url}/{rule.json()['id']}", headers=headers).status_code == 204
