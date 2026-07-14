"""Route d'ingestion des scans : POST /api/scans (appelée par le pipeline)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_project_from_token
from app.db.session import get_db
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.ingest import ScanAccepted, ScanReportIn

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanAccepted, status_code=201)
def ingest_scan(
    report: ScanReportIn,
    project: Project = Depends(get_project_from_token),
    db: Session = Depends(get_db),
) -> ScanAccepted:
    """
    Reçoit un rapport de scan normalisé et le persiste.

    Le projet est identifié par le token (pas par le payload) : un client ne
    peut donc écrire que dans son propre projet.
    """
    scan = Scan(
        project_id=project.id,
        schema_version=report.schema_version,
        repo=report.scan.repo,
        branch=report.scan.branch,
        commit_sha=report.scan.commit_sha,
        scanned_at=report.scan.created_at,
        total_findings=len(report.findings),
    )
    db.add(scan)
    db.flush()  # obtient scan.id avant d'insérer les findings

    for f in report.findings:
        db.add(
            Finding(
                scan_id=scan.id,
                fingerprint=f.fingerprint,
                source=f.source,
                category=f.category,
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                resource=f.resource,
                file=f.file,
                line_start=f.line_start,
                line_end=f.line_end,
                remediation=f.remediation,
                raw=f.raw,
            )
        )

    db.commit()
    return ScanAccepted(
        scan_id=scan.id, project_id=project.id, total_findings=scan.total_findings
    )
