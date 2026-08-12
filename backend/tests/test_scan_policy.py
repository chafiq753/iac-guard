"""Tests de la politique de scan : seuil de blocage du pipeline + exceptions.

Le rapport d'exemple (`sample_report`) contient 1 critical, 1 high, 1 medium.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import register_and_login, sample_report


def _ingest(client: TestClient, token: str) -> dict:
    resp = client.post(
        "/api/scans",
        json=sample_report(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_no_policy_never_fails(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    _, token = project_token
    body = _ingest(client, token)
    assert body["should_fail"] is False


def test_threshold_blocks_on_critical(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    project_id, token = project_token
    resp = client.patch(
        f"/api/projects/{project_id}/policy",
        json={"fail_on_severity": "critical"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["fail_on_severity"] == "critical"

    body = _ingest(client, token)
    assert body["should_fail"] is True
    assert body["fail_reason"]


def test_threshold_does_not_block_below_it(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    """Seuil 'critical' : un rapport sans critical ne bloque pas, même avec des high."""
    project_id, token = project_token
    client.patch(
        f"/api/projects/{project_id}/policy",
        json={"fail_on_severity": "critical"},
        headers=auth_headers,
    )
    report = sample_report()
    report["findings"] = [f for f in report["findings"] if f["severity"] != "critical"]
    resp = client.post(
        "/api/scans", json=report, headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.json()["should_fail"] is False


def test_invalid_severity_rejected(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    project_id, _ = project_token
    resp = client.patch(
        f"/api/projects/{project_id}/policy",
        json={"fail_on_severity": "apocalyptic"},
        headers=auth_headers,
    )
    assert resp.status_code == 422


def test_ignored_rule_excluded_from_threshold(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    """La règle critique ignorée ne doit plus déclencher le blocage."""
    project_id, token = project_token
    client.patch(
        f"/api/projects/{project_id}/policy",
        json={"fail_on_severity": "critical"},
        headers=auth_headers,
    )
    critical_rule = sample_report()["findings"][0]["rule_id"]
    add = client.post(
        f"/api/projects/{project_id}/ignored-rules",
        json={"rule_id": critical_rule, "note": "Accepté par la sécurité"},
        headers=auth_headers,
    )
    assert add.status_code == 201, add.text

    body = _ingest(client, token)
    assert body["should_fail"] is False


def test_ignored_rule_excluded_from_score(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    project_id, token = project_token
    scan = _ingest(client, token)

    before = client.get(f"/api/scans/{scan['scan_id']}", headers=auth_headers).json()
    critical_rule = sample_report()["findings"][0]["rule_id"]

    client.post(
        f"/api/projects/{project_id}/ignored-rules",
        json={"rule_id": critical_rule},
        headers=auth_headers,
    )
    after = client.get(f"/api/scans/{scan['scan_id']}", headers=auth_headers).json()
    assert after["score"]["score"] > before["score"]["score"]
    assert after["score"]["by_severity"]["critical"] == 0


def test_duplicate_ignored_rule_rejected(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    project_id, _ = project_token
    payload = {"rule_id": "CKV_AWS_20"}
    assert (
        client.post(
            f"/api/projects/{project_id}/ignored-rules",
            json=payload,
            headers=auth_headers,
        ).status_code
        == 201
    )
    resp = client.post(
        f"/api/projects/{project_id}/ignored-rules",
        json=payload,
        headers=auth_headers,
    )
    assert resp.status_code == 409


def test_remove_ignored_rule_restores_score(
    client: TestClient, auth_headers: dict[str, str], project_token: tuple[int, str]
) -> None:
    project_id, token = project_token
    scan = _ingest(client, token)
    critical_rule = sample_report()["findings"][0]["rule_id"]

    added = client.post(
        f"/api/projects/{project_id}/ignored-rules",
        json={"rule_id": critical_rule},
        headers=auth_headers,
    ).json()
    ignored_score = client.get(
        f"/api/scans/{scan['scan_id']}", headers=auth_headers
    ).json()["score"]["score"]

    resp = client.delete(
        f"/api/projects/{project_id}/ignored-rules/{added['id']}",
        headers=auth_headers,
    )
    assert resp.status_code == 204

    restored_score = client.get(
        f"/api/scans/{scan['scan_id']}", headers=auth_headers
    ).json()["score"]["score"]
    assert restored_score < ignored_score


def test_policy_isolated_per_user(client: TestClient) -> None:
    a = register_and_login(client, email="polA@iac-guard.io")
    b = register_and_login(client, email="polB@iac-guard.io")
    project = client.post("/api/projects", json={"name": "p"}, headers=a).json()

    resp = client.patch(
        f"/api/projects/{project['id']}/policy",
        json={"fail_on_severity": "high"},
        headers=b,
    )
    assert resp.status_code == 404
