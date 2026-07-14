"""Schéma d'ingestion : ce que l'API reçoit du pipeline (POST /api/scans).

Miroir du schéma unifié produit par l'aggregator. Sert à valider le payload
entrant : si le pipeline envoie un JSON malformé, FastAPI répond 422 avant
même de toucher la base.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ToolIn(BaseModel):
    name: str
    version: str | None = None


class ScanMetaIn(BaseModel):
    repo: str
    branch: str | None = None
    commit_sha: str | None = None
    created_at: datetime
    tools: list[ToolIn] = Field(default_factory=list)


class FindingIn(BaseModel):
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
    raw: dict = Field(default_factory=dict)


class ScanReportIn(BaseModel):
    schema_version: str = "1.0"
    scan: ScanMetaIn
    findings: list[FindingIn]
    # `summary` est envoyé par le pipeline mais recalculé côté serveur ;
    # on l'accepte sans l'exiger.
    summary: dict | None = None


class ScanAccepted(BaseModel):
    """Réponse de l'API après ingestion réussie."""

    scan_id: int
    project_id: int
    total_findings: int
