"""Schémas de lecture : ce que l'API renvoie au dashboard."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScoreOut(BaseModel):
    score: int
    grade: str
    total_findings: int
    by_severity: dict[str, int]


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    fingerprint: str
    source: str
    category: str
    rule_id: str
    title: str
    severity: str
    resource: str | None = None
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    remediation: str | None = None
    # Statut de triage (décision analyste, suivi par fingerprint).
    status: str = "open"
    triage_note: str | None = None
    # Couvert par une exception de politique (règle ignorée sur le projet).
    excepted: bool = False


class TriageIn(BaseModel):
    """Décision de triage envoyée par le dashboard."""

    status: str
    note: str | None = None


class ScanListItem(BaseModel):
    """Une ligne dans l'historique des scans d'un projet."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    repo: str
    branch: str | None = None
    commit_sha: str | None = None
    scanned_at: datetime
    total_findings: int


class ScanDetail(ScanListItem):
    """Un scan avec son score calculé."""

    score: ScoreOut


class ProjectDetail(BaseModel):
    """Vue d'ensemble d'un projet : dernier score + nb de scans."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    scan_count: int
    latest_score: ScoreOut | None = None
    last_scan_at: datetime | None = None


class ProjectTokenRotated(BaseModel):
    """Renvoyé UNE seule fois après rotation : contient le nouveau token en clair."""

    token_prefix: str
    token: str


class FindingWithProject(FindingOut):
    """Un finding enrichi du nom de son projet (vue cross-projets)."""

    project_id: int
    project_name: str
    repo: str
    scan_id: int
    detected_at: datetime
    # Commit où le problème a été détecté. Sert à construire un lien vers la
    # ligne exacte SUR CE COMMIT — pointer vers `main` donnerait une ligne
    # décalée dès que le fichier bouge.
    commit_sha: str | None = None


class FindingsPage(BaseModel):
    """Page de résultats paginée pour la vue « toutes les alertes »."""

    items: list[FindingWithProject]
    total: int
    page: int
    page_size: int


class AuditLogEntryOut(BaseModel):
    """Une ligne d'audit : qui a changé le statut de quel finding, et quand."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    project_name: str
    finding_fingerprint: str
    finding_title: str
    from_status: str
    to_status: str
    note: str | None = None
    user_email: str | None = None
    created_at: datetime


class AuditLogPage(BaseModel):
    items: list[AuditLogEntryOut]
    total: int
    page: int
    page_size: int
