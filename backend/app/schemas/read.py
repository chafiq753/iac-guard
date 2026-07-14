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
