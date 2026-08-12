"""Tests de l'audit log : historique append-only des décisions de triage."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import USER_EMAIL, register_and_login, sample_report


def _ingest(client: TestClient, token: str) -> int:
    resp = client.post(
        "/api/scans",
        json=sample_report(),
        headers={"Authorization": f"Bearer {token}"},
    )
    return resp.json()["scan_id"]


def test_triage_creates_audit_entry(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    _, token = project_token
    scan_id = _ingest(client, token)
    finding = client.get(f"/api/scans/{scan_id}/findings", headers=auth_headers).json()[0]

    client.patch(
        f"/api/scans/{scan_id}/findings/{finding['id']}/triage",
        json={"status": "resolved", "note": "Corrigé dans le commit abc123"},
        headers=auth_headers,
    )

    log = client.get("/api/audit-log", headers=auth_headers).json()
    assert log["total"] == 1
    entry = log["items"][0]
    assert entry["from_status"] == "open"
    assert entry["to_status"] == "resolved"
    assert entry["note"] == "Corrigé dans le commit abc123"
    assert entry["user_email"] == USER_EMAIL
    assert entry["finding_title"] == finding["title"]


def test_audit_log_is_append_only(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    """Ack puis resolve puis reopen -> 3 lignes distinctes, pas une réécrite."""
    _, token = project_token
    scan_id = _ingest(client, token)
    finding = client.get(f"/api/scans/{scan_id}/findings", headers=auth_headers).json()[0]
    url = f"/api/scans/{scan_id}/findings/{finding['id']}/triage"

    client.patch(url, json={"status": "acknowledged"}, headers=auth_headers)
    client.patch(url, json={"status": "resolved"}, headers=auth_headers)
    client.patch(url, json={"status": "open"}, headers=auth_headers)

    log = client.get("/api/audit-log", headers=auth_headers).json()
    assert log["total"] == 3
    transitions = [(e["from_status"], e["to_status"]) for e in log["items"]]
    assert ("open", "acknowledged") in transitions
    assert ("acknowledged", "resolved") in transitions
    assert ("resolved", "open") in transitions


def test_no_op_status_change_not_logged(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    """Ré-ouvrir un finding déjà ouvert ne doit rien ajouter au log."""
    _, token = project_token
    scan_id = _ingest(client, token)
    finding = client.get(f"/api/scans/{scan_id}/findings", headers=auth_headers).json()[0]

    client.patch(
        f"/api/scans/{scan_id}/findings/{finding['id']}/triage",
        json={"status": "open"},
        headers=auth_headers,
    )
    log = client.get("/api/audit-log", headers=auth_headers).json()
    assert log["total"] == 0


def test_audit_log_survives_project_deletion(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """Le journal d'audit doit rester lisible même après suppression du projet."""
    created = client.post(
        "/api/projects", json={"name": "ephemere"}, headers=auth_headers
    ).json()
    scan_id = _ingest(client, created["token"])
    finding = client.get(f"/api/scans/{scan_id}/findings", headers=auth_headers).json()[0]
    client.patch(
        f"/api/scans/{scan_id}/findings/{finding['id']}/triage",
        json={"status": "false_positive"},
        headers=auth_headers,
    )

    assert client.delete(f"/api/projects/{created['id']}", headers=auth_headers).status_code == 204

    log = client.get("/api/audit-log", headers=auth_headers).json()
    assert log["total"] == 1
    assert log["items"][0]["project_name"] == "ephemere"


def test_audit_log_isolated_per_user(client: TestClient) -> None:
    a = register_and_login(client, email="auditA@iac-guard.io")
    b = register_and_login(client, email="auditB@iac-guard.io")
    project = client.post("/api/projects", json={"name": "p"}, headers=a).json()
    scan_id = _ingest(client, project["token"])
    finding = client.get(f"/api/scans/{scan_id}/findings", headers=a).json()[0]
    client.patch(
        f"/api/scans/{scan_id}/findings/{finding['id']}/triage",
        json={"status": "resolved"},
        headers=a,
    )

    assert client.get("/api/audit-log", headers=a).json()["total"] == 1
    assert client.get("/api/audit-log", headers=b).json()["total"] == 0


def test_audit_log_filter_by_project(client: TestClient, auth_headers: dict[str, str]) -> None:
    p1 = client.post("/api/projects", json={"name": "p1"}, headers=auth_headers).json()
    p2 = client.post("/api/projects", json={"name": "p2"}, headers=auth_headers).json()
    s1 = _ingest(client, p1["token"])
    s2 = _ingest(client, p2["token"])
    f1 = client.get(f"/api/scans/{s1}/findings", headers=auth_headers).json()[0]
    f2 = client.get(f"/api/scans/{s2}/findings", headers=auth_headers).json()[0]

    client.patch(
        f"/api/scans/{s1}/findings/{f1['id']}/triage",
        json={"status": "resolved"},
        headers=auth_headers,
    )
    client.patch(
        f"/api/scans/{s2}/findings/{f2['id']}/triage",
        json={"status": "resolved"},
        headers=auth_headers,
    )

    filtered = client.get(
        "/api/audit-log", params={"project_id": p1["id"]}, headers=auth_headers
    ).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["project_name"] == "p1"
