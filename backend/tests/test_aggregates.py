"""Tests des agrégations SQL (app/services/aggregates.py)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.services.aggregates import severity_counts


def _seed_scan(db: Session, severities: list[str]) -> int:
    """Crée un utilisateur + projet + scan + findings, renvoie l'id du scan."""
    # e-mail et token_hash sont UNIQUE en base : chaque seed a les siens.
    owner = User(email=f"{uuid4().hex}@test.io", hashed_password="x")
    db.add(owner)
    db.flush()
    project = Project(
        name="p",
        owner_id=owner.id,
        token_hash=uuid4().hex,
        token_prefix="iacg_x…",
    )
    db.add(project)
    db.flush()
    scan = Scan(
        project_id=project.id,
        repo="r",
        scanned_at=datetime(2026, 7, 9, 8, 0, tzinfo=timezone.utc),
    )
    db.add(scan)
    db.flush()
    for i, sev in enumerate(severities):
        db.add(
            Finding(
                scan_id=scan.id,
                fingerprint=f"fp{i}",
                source="checkov",
                category="misconfiguration",
                rule_id="CKV",
                title="t",
                severity=sev,
            )
        )
    db.commit()
    return scan.id


def test_severity_counts_groups_correctly(db_session: Session) -> None:
    scan_id = _seed_scan(
        db_session, ["critical", "high", "high", "medium", "medium", "medium"]
    )
    counts = severity_counts(db_session, scan_id)
    assert counts == {"critical": 1, "high": 2, "medium": 3}


def test_severity_counts_empty_scan_returns_empty(db_session: Session) -> None:
    scan_id = _seed_scan(db_session, [])
    assert severity_counts(db_session, scan_id) == {}


def test_severity_counts_isolated_per_scan(db_session: Session) -> None:
    first = _seed_scan(db_session, ["critical", "critical"])
    second = _seed_scan(db_session, ["low"])
    assert severity_counts(db_session, first) == {"critical": 2}
    assert severity_counts(db_session, second) == {"low": 1}
