"""Tests d'intégration de l'API (routes projects / scans / findings).

Rappel des deux authentifications :
  - routes de lecture / création de projet -> JWT utilisateur (`auth_headers`) ;
  - POST /api/scans (pipeline)             -> token de projet (`project_token`).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import register_and_login, sample_report


# --------------------------------------------------------------------------- #
# Meta
# --------------------------------------------------------------------------- #


def test_health_is_public(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# --------------------------------------------------------------------------- #
# Projects
# --------------------------------------------------------------------------- #


def test_create_project_returns_token_once(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    resp = client.post(
        "/api/projects", json={"name": "acme/infra"}, headers=auth_headers
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "acme/infra"
    assert body["token"].startswith("iacg_")
    assert body["token_prefix"].endswith("…")

    # La liste des projets ne doit JAMAIS exposer le token ni son hash.
    listed = client.get("/api/projects", headers=auth_headers).json()
    assert len(listed) == 1
    assert "token" not in listed[0]
    assert "token_hash" not in listed[0]


def test_get_unknown_project_404(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    assert client.get("/api/projects/999", headers=auth_headers).status_code == 404


# --------------------------------------------------------------------------- #
# Ingestion (auth par TOKEN DE PROJET, pas par JWT)
# --------------------------------------------------------------------------- #


def test_ingest_requires_valid_project_token(client: TestClient) -> None:
    # Sans en-tête Authorization -> 422 (header obligatoire).
    assert client.post("/api/scans", json=sample_report()).status_code == 422
    # Avec un token inconnu -> 401.
    bad = client.post(
        "/api/scans",
        json=sample_report(),
        headers={"Authorization": "Bearer iacg_nope"},
    )
    assert bad.status_code == 401


def test_user_jwt_cannot_be_used_to_ingest(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """Un JWT utilisateur n'est PAS un token de projet : l'ingestion doit refuser."""
    resp = client.post("/api/scans", json=sample_report(), headers=auth_headers)
    assert resp.status_code == 401


def test_ingest_persists_scan_and_findings(
    client: TestClient,
    auth_headers: dict[str, str],
    project_token: tuple[int, str],
) -> None:
    project_id, token = project_token
    resp = client.post(
        "/api/scans",
        json=sample_report(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["project_id"] == project_id
    assert body["total_findings"] == 3

    detail = client.get(f"/api/projects/{project_id}", headers=auth_headers).json()
    assert detail["scan_count"] == 1
    assert detail["latest_score"]["score"] == 62
    assert detail["latest_score"]["grade"] == "C"


def test_ingest_writes_only_to_own_project(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # Deux projets du même utilisateur ; le token de A n'écrit que dans A.
    a = client.post(
        "/api/projects", json={"name": "team-a"}, headers=auth_headers
    ).json()
    b = client.post(
        "/api/projects", json={"name": "team-b"}, headers=auth_headers
    ).json()

    client.post(
        "/api/scans",
        json=sample_report(),
        headers={"Authorization": f"Bearer {a['token']}"},
    )

    a_detail = client.get(f"/api/projects/{a['id']}", headers=auth_headers).json()
    b_detail = client.get(f"/api/projects/{b['id']}", headers=auth_headers).json()
    assert a_detail["scan_count"] == 1
    assert b_detail["scan_count"] == 0


# --------------------------------------------------------------------------- #
# Lecture des scans / findings
# --------------------------------------------------------------------------- #


def _ingest(client: TestClient, token: str) -> int:
    resp = client.post(
        "/api/scans",
        json=sample_report(),
        headers={"Authorization": f"Bearer {token}"},
    )
    return resp.json()["scan_id"]


def test_scan_detail_includes_score(
    client: TestClient,
    auth_headers: dict[str, str],
    project_token: tuple[int, str],
) -> None:
    _, token = project_token
    scan_id = _ingest(client, token)

    resp = client.get(f"/api/scans/{scan_id}", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_findings"] == 3
    assert body["score"]["by_severity"] == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "info": 0,
    }


def test_list_findings_and_filters(
    client: TestClient,
    auth_headers: dict[str, str],
    project_token: tuple[int, str],
) -> None:
    _, token = project_token
    scan_id = _ingest(client, token)

    all_findings = client.get(
        f"/api/scans/{scan_id}/findings", headers=auth_headers
    ).json()
    assert len(all_findings) == 3

    criticals = client.get(
        f"/api/scans/{scan_id}/findings",
        params={"severity": "critical"},
        headers=auth_headers,
    ).json()
    assert len(criticals) == 1
    assert criticals[0]["severity"] == "critical"

    secrets = client.get(
        f"/api/scans/{scan_id}/findings",
        params={"category": "secret"},
        headers=auth_headers,
    ).json()
    assert len(secrets) == 1
    assert secrets[0]["category"] == "secret"

    # Un filtre sans correspondance renvoie une liste vide (pas une erreur).
    empty = client.get(
        f"/api/scans/{scan_id}/findings",
        params={"severity": "low"},
        headers=auth_headers,
    ).json()
    assert empty == []


def test_read_unknown_scan_404(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    assert client.get("/api/scans/999", headers=auth_headers).status_code == 404
    assert (
        client.get("/api/scans/999/findings", headers=auth_headers).status_code == 404
    )


def test_list_scans_ordered_recent_first(
    client: TestClient,
    auth_headers: dict[str, str],
    project_token: tuple[int, str],
) -> None:
    project_id, token = project_token

    older = sample_report()
    older["scan"]["created_at"] = "2026-07-01T08:00:00Z"
    newer = sample_report()
    newer["scan"]["created_at"] = "2026-07-09T08:00:00Z"
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/api/scans", json=older, headers=headers)
    client.post("/api/scans", json=newer, headers=headers)

    scans = client.get(
        f"/api/projects/{project_id}/scans", headers=auth_headers
    ).json()
    assert len(scans) == 2
    assert scans[0]["scanned_at"] > scans[1]["scanned_at"]


# --------------------------------------------------------------------------- #
# Cloisonnement entre utilisateurs
# --------------------------------------------------------------------------- #


def test_user_cannot_see_other_users_project(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    """Alice possède un projet ; Bob ne doit ni le lister, ni y accéder."""
    project_id, token = project_token
    scan_id = _ingest(client, token)

    bob = register_and_login(client, email="bob@iac-guard.io", password="B0b-Password!")

    # Bob ne voit aucun projet.
    assert client.get("/api/projects", headers=bob).json() == []

    # Et se voit répondre 404 (pas 403 : ne pas révéler que la ressource existe).
    assert client.get(f"/api/projects/{project_id}", headers=bob).status_code == 404
    assert (
        client.get(f"/api/projects/{project_id}/scans", headers=bob).status_code == 404
    )
    assert client.get(f"/api/scans/{scan_id}", headers=bob).status_code == 404
    assert client.get(f"/api/scans/{scan_id}/findings", headers=bob).status_code == 404

    # Alice, elle, y accède normalement.
    assert client.get(f"/api/scans/{scan_id}", headers=auth_headers).status_code == 200
