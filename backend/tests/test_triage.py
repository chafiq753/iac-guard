"""Tests du cycle de vie des findings (triage).

Le point clé : la décision est attachée au FINGERPRINT du problème (par
projet), pas à la ligne du scan. Elle doit donc survivre à un nouveau scan
qui redétecte le même problème.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import register_and_login, sample_report


def _ingest(client: TestClient, token: str, report: dict | None = None) -> int:
    resp = client.post(
        "/api/scans",
        json=report or sample_report(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["scan_id"]


def _findings(client: TestClient, scan_id: int, headers: dict, **params) -> list[dict]:
    resp = client.get(f"/api/scans/{scan_id}/findings", headers=headers, params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_findings_default_to_open(client, auth_headers, project_token):
    _, token = project_token
    scan_id = _ingest(client, token)

    findings = _findings(client, scan_id, auth_headers)
    assert len(findings) == 3
    assert all(f["status"] == "open" for f in findings)


def test_triage_sets_status_and_note(client, auth_headers, project_token):
    _, token = project_token
    scan_id = _ingest(client, token)
    finding = _findings(client, scan_id, auth_headers)[0]

    resp = client.patch(
        f"/api/scans/{scan_id}/findings/{finding['id']}/triage",
        json={"status": "acknowledged", "note": "Vu, correctif planifié."},
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "acknowledged"
    assert body["triage_note"] == "Vu, correctif planifié."

    # La lecture reflète la décision.
    updated = _findings(client, scan_id, auth_headers)
    by_id = {f["id"]: f for f in updated}
    assert by_id[finding["id"]]["status"] == "acknowledged"


def test_triage_survives_rescan(client, auth_headers, project_token):
    """Un problème traité reste traité quand un nouveau scan le redétecte."""
    _, token = project_token
    scan1 = _ingest(client, token)
    finding = _findings(client, scan1, auth_headers)[0]

    resp = client.patch(
        f"/api/scans/{scan1}/findings/{finding['id']}/triage",
        json={"status": "false_positive"},
        headers=auth_headers,
    )
    assert resp.status_code == 200

    # Nouveau scan : mêmes fingerprints.
    scan2 = _ingest(client, token)
    findings2 = _findings(client, scan2, auth_headers)
    by_fp = {f["fingerprint"]: f for f in findings2}
    assert by_fp[finding["fingerprint"]]["status"] == "false_positive"
    # Les autres restent ouverts.
    others = [f for f in findings2 if f["fingerprint"] != finding["fingerprint"]]
    assert all(f["status"] == "open" for f in others)


def test_reopen_removes_decision(client, auth_headers, project_token):
    _, token = project_token
    scan_id = _ingest(client, token)
    finding = _findings(client, scan_id, auth_headers)[0]
    url = f"/api/scans/{scan_id}/findings/{finding['id']}/triage"

    assert (
        client.patch(url, json={"status": "resolved"}, headers=auth_headers).status_code
        == 200
    )
    resp = client.patch(url, json={"status": "open"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "open"


def test_invalid_status_rejected(client, auth_headers, project_token):
    _, token = project_token
    scan_id = _ingest(client, token)
    finding = _findings(client, scan_id, auth_headers)[0]

    resp = client.patch(
        f"/api/scans/{scan_id}/findings/{finding['id']}/triage",
        json={"status": "whatever"},
        headers=auth_headers,
    )
    assert resp.status_code == 422


def test_status_filter(client, auth_headers, project_token):
    _, token = project_token
    scan_id = _ingest(client, token)
    finding = _findings(client, scan_id, auth_headers)[0]

    client.patch(
        f"/api/scans/{scan_id}/findings/{finding['id']}/triage",
        json={"status": "acknowledged"},
        headers=auth_headers,
    )

    open_only = _findings(client, scan_id, auth_headers, status="open")
    assert len(open_only) == 2
    acked = _findings(client, scan_id, auth_headers, status="acknowledged")
    assert len(acked) == 1


def test_triage_is_isolated_per_user(client, auth_headers, project_token):
    """Un autre utilisateur ne peut pas trier les findings d'autrui (404)."""
    _, token = project_token
    scan_id = _ingest(client, token)
    finding = _findings(client, scan_id, auth_headers)[0]

    other = register_and_login(client, email="intrus@iac-guard.io")
    resp = client.patch(
        f"/api/scans/{scan_id}/findings/{finding['id']}/triage",
        json={"status": "resolved"},
        headers=other,
    )
    assert resp.status_code == 404
