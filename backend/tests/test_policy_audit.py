"""Politique de blocage, exceptions et journaux d'audit.

  - le seuil `fail_on_severity` n'est modifiable que par admin / security_lead ;
  - une exception exige une justification, est journalisée (ajout ET retrait)
    et signalée sur les findings qu'elle couvre (`excepted`) ;
  - un projet se supprime même avec un historique de triage, et son audit
    reste lisible ;
  - les lignes d'audit sont immuables AU NIVEAU DE LA BASE (triggers).
"""

from __future__ import annotations

import pytest
from sqlalchemy import delete, text, update
from sqlalchemy.exc import DBAPIError

from app.models.admin_audit_log import AdminAuditLog
from app.models.audit_log import TriageAuditLog
from tests.test_triage_rbac import _member, _project_with_scan


def _policy(client, headers, project_id: int, severity: str | None):
    return client.patch(
        f"/api/projects/{project_id}/policy",
        json={"fail_on_severity": severity},
        headers=headers,
    )


def _admin_log(client, admin_headers, action: str) -> list[dict]:
    resp = client.get(
        "/api/admin/audit-logs", params={"action": action}, headers=admin_headers
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["items"]


# --------------------------------------------------------------------------- #
# Politique de blocage
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("role", ["developer", "auditor", "viewer"])
def test_only_security_roles_change_blocking_policy(client, auth_headers, db_session, role):
    project_id, _, _ = _project_with_scan(client, auth_headers, "acme/a")
    assert _policy(client, auth_headers, project_id, "high").status_code == 200
    headers = _member(client, auth_headers, db_session, role, [project_id])

    # Le développeur ne peut pas baisser le seuil pour débloquer sa PR.
    assert _policy(client, headers, project_id, None).status_code == 403
    policy = client.get(f"/api/projects/{project_id}/policy", headers=auth_headers).json()
    assert policy["fail_on_severity"] == "high"


def test_policy_outside_scope_is_404(client, auth_headers, db_session):
    shared_id, _, _ = _project_with_scan(client, auth_headers, "acme/a")
    other_id, _, _ = _project_with_scan(client, auth_headers, "acme/b")
    headers = _member(client, auth_headers, db_session, "developer", [shared_id])

    assert _policy(client, headers, other_id, None).status_code == 404


def test_security_lead_changes_blocking_policy(client, auth_headers, db_session):
    project_id, _, _ = _project_with_scan(client, auth_headers, "acme/a")
    headers = _member(client, auth_headers, db_session, "security_lead", [])

    resp = _policy(client, headers, project_id, "critical")
    assert resp.status_code == 200, resp.text
    assert resp.json()["fail_on_severity"] == "critical"


# --------------------------------------------------------------------------- #
# Exceptions (règles ignorées)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("payload", [{"rule_id": "CKV_AWS_20"}, {"rule_id": "CKV_AWS_20", "note": "   "}])
def test_exception_requires_justification(client, auth_headers, payload):
    project_id, _, _ = _project_with_scan(client, auth_headers, "acme/a")
    resp = client.post(
        f"/api/projects/{project_id}/ignored-rules", json=payload, headers=auth_headers
    )
    assert resp.status_code == 422


def test_exception_add_and_remove_are_audited(client, auth_headers, db_session):
    project_id, _, _ = _project_with_scan(client, auth_headers, "acme/a")
    secops = _member(client, auth_headers, db_session, "security_lead", [])
    url = f"/api/projects/{project_id}/ignored-rules"

    rule = client.post(
        url, json={"rule_id": "CKV_AWS_20", "note": "  Bucket CDN public  "}, headers=secops
    ).json()
    assert rule["note"] == "Bucket CDN public"
    assert client.delete(f"{url}/{rule['id']}", headers=secops).status_code == 204

    expected = {
        "project_id": project_id,
        "project_name": "acme/a",
        "rule_id": "CKV_AWS_20",
        "note": "Bucket CDN public",
    }
    for action in ("policy.exception_added", "policy.exception_removed"):
        [entry] = _admin_log(client, auth_headers, action)
        assert entry["actor_email"] == "security_lead@iac-guard.io"
        assert entry["details"] == expected
        assert entry["created_at"]


def test_findings_covered_by_exception_are_flagged(client, auth_headers):
    project_id, scan_id, _ = _project_with_scan(client, auth_headers, "acme/a")
    findings = client.get(f"/api/scans/{scan_id}/findings", headers=auth_headers).json()
    assert not any(f["excepted"] for f in findings)
    rule_id = findings[0]["rule_id"]

    client.post(
        f"/api/projects/{project_id}/ignored-rules",
        json={"rule_id": rule_id, "note": "Accepté"},
        headers=auth_headers,
    )

    findings = client.get(f"/api/scans/{scan_id}/findings", headers=auth_headers).json()
    alerts = client.get("/api/alerts", headers=auth_headers).json()["items"]
    for items in (findings, alerts):
        # Toujours visibles, mais signalés.
        assert len(items) == 3
        assert {f["rule_id"] for f in items if f["excepted"]} == {rule_id}


# --------------------------------------------------------------------------- #
# Journal d'audit
# --------------------------------------------------------------------------- #


def test_foreign_keys_are_enforced_in_tests(db_session):
    """Garde-fou : sans ça, les tests SQLite ne refléteraient pas PostgreSQL."""
    assert db_session.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_project_with_history_can_be_deleted_and_audit_stays(client, auth_headers, db_session):
    project_id, scan_id, finding_id = _project_with_scan(client, auth_headers, "acme/a")
    # Tout ce qui référence le projet : triage, partage, exception.
    client.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}/triage",
        json={"status": "false_positive", "note": "Bucket de test"},
        headers=auth_headers,
    )
    _member(client, auth_headers, db_session, "developer", [project_id])
    client.post(
        f"/api/projects/{project_id}/ignored-rules",
        json={"rule_id": "CKV_AWS_20", "note": "CDN"},
        headers=auth_headers,
    )

    assert client.delete(f"/api/projects/{project_id}", headers=auth_headers).status_code == 204

    triage_log = client.get("/api/audit-log", headers=auth_headers).json()["items"]
    assert [(e["project_name"], e["to_status"]) for e in triage_log] == [
        ("acme/a", "false_positive")
    ]
    [added] = _admin_log(client, auth_headers, "policy.exception_added")
    assert added["details"]["project_name"] == "acme/a"


@pytest.mark.parametrize("model", [TriageAuditLog, AdminAuditLog])
def test_audit_rows_cannot_be_modified_or_deleted_in_database(
    client, auth_headers, db_session, model
):
    project_id, scan_id, finding_id = _project_with_scan(client, auth_headers, "acme/a")
    client.patch(
        f"/api/scans/{scan_id}/findings/{finding_id}/triage",
        json={"status": "acknowledged"},
        headers=auth_headers,
    )
    client.post(
        f"/api/projects/{project_id}/ignored-rules",
        json={"rule_id": "CKV_AWS_20", "note": "CDN"},
        headers=auth_headers,
    )
    assert db_session.query(model).count() == 1

    column = model.note if model is TriageAuditLog else model.action
    for statement in (update(model).values({column: "falsifié"}), delete(model)):
        with pytest.raises(DBAPIError, match="append-only"):
            db_session.execute(statement)
        db_session.rollback()

    assert db_session.query(model).count() == 1
