"""Routes de lecture des scans et findings (consommées par le dashboard).

Toutes ces routes exigent un JWT utilisateur et sont cloisonnées : on ne peut
lire que les scans/findings des projets qu'on possède.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_owned_project, get_owned_scan
from app.db.session import get_db
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.triage import TRIAGE_STATUSES, FindingTriage
from app.models.user import User
from app.schemas.read import FindingOut, ScanDetail, ScanListItem, ScoreOut, TriageIn
from app.services.aggregates import severity_counts
from app.services.scoring import compute_score

router = APIRouter(tags=["scans-read"])


def _score_out(db: Session, scan_id: int) -> ScoreOut:
    result = compute_score(severity_counts(db, scan_id))
    return ScoreOut(**result.__dict__)


def _triage_map(db: Session, project_id: int) -> dict[str, FindingTriage]:
    """Décisions de triage du projet, indexées par fingerprint."""
    rows = db.scalars(
        select(FindingTriage).where(FindingTriage.project_id == project_id)
    ).all()
    return {t.fingerprint: t for t in rows}


@router.get("/api/projects/{project_id}/scans", response_model=list[ScanListItem])
def list_scans(
    project: Project = Depends(get_owned_project),
    db: Session = Depends(get_db),
) -> list[Scan]:
    """Historique des scans d'un projet, du plus récent au plus ancien."""
    return list(
        db.scalars(
            select(Scan)
            .where(Scan.project_id == project.id)
            .order_by(desc(Scan.scanned_at))
        ).all()
    )


@router.get("/api/scans/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan: Scan = Depends(get_owned_scan),
    db: Session = Depends(get_db),
) -> ScanDetail:
    """Un scan avec son score de conformité calculé."""
    return ScanDetail(
        id=scan.id,
        repo=scan.repo,
        branch=scan.branch,
        commit_sha=scan.commit_sha,
        scanned_at=scan.scanned_at,
        total_findings=scan.total_findings,
        score=_score_out(db, scan.id),
    )


@router.get("/api/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_findings(
    scan: Scan = Depends(get_owned_scan),
    severity: str | None = Query(None, description="Filtrer par gravité"),
    category: str | None = Query(None, description="Filtrer par catégorie"),
    status: str | None = Query(None, description="Filtrer par statut de triage"),
    db: Session = Depends(get_db),
) -> list[FindingOut]:
    """Findings d'un scan, enrichis de leur statut de triage.

    Le statut vit au niveau du fingerprint (projet) : un problème déjà traité
    reste traité même s'il est redétecté par un scan plus récent.
    """
    stmt = select(Finding).where(Finding.scan_id == scan.id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if category:
        stmt = stmt.where(Finding.category == category)

    triage = _triage_map(db, scan.project_id)
    out: list[FindingOut] = []
    for f in db.scalars(stmt).all():
        decision = triage.get(f.fingerprint)
        item = FindingOut.model_validate(f).model_copy(
            update={
                "status": decision.status if decision else "open",
                "triage_note": decision.note if decision else None,
            }
        )
        if status and item.status != status:
            continue
        out.append(item)
    return out


@router.patch("/api/scans/{scan_id}/findings/{finding_id}/triage", response_model=FindingOut)
def triage_finding(
    finding_id: int,
    payload: TriageIn,
    scan: Scan = Depends(get_owned_scan),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FindingOut:
    """Enregistre la décision d'un analyste sur un finding (par fingerprint)."""
    if payload.status not in TRIAGE_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Statut invalide. Attendu : {', '.join(TRIAGE_STATUSES)}.",
        )

    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan.id:
        raise HTTPException(status_code=404, detail="Finding introuvable.")

    decision = db.scalar(
        select(FindingTriage).where(
            FindingTriage.project_id == scan.project_id,
            FindingTriage.fingerprint == finding.fingerprint,
        )
    )
    if payload.status == "open":
        # Ré-ouvrir = supprimer la décision : "open" est l'état implicite.
        if decision is not None:
            db.delete(decision)
        db.commit()
        return FindingOut.model_validate(finding)

    if decision is None:
        decision = FindingTriage(
            project_id=scan.project_id, fingerprint=finding.fingerprint
        )
        db.add(decision)
    decision.status = payload.status
    decision.note = payload.note
    decision.updated_by_id = current_user.id
    db.commit()

    return FindingOut.model_validate(finding).model_copy(
        update={"status": decision.status, "triage_note": decision.note}
    )
