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
from app.models.audit_log import TriageAuditLog
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.triage import TRIAGE_STATUSES, FindingTriage
from app.models.user import User
from app.schemas.read import (
    AuditLogEntryOut,
    AuditLogPage,
    FindingOut,
    FindingsPage,
    FindingWithProject,
    ScanDetail,
    ScanListItem,
    ScoreOut,
    TriageIn,
)
from app.services.aggregates import ignored_rule_ids, severity_counts
from app.services.scoring import SEVERITY_WEIGHTS, compute_score

router = APIRouter(tags=["scans-read"])


def _score_out(db: Session, scan_id: int, project_id: int) -> ScoreOut:
    excluded = ignored_rule_ids(db, project_id)
    result = compute_score(severity_counts(db, scan_id, excluded))
    return ScoreOut(**result.__dict__)


def _triage_map(db: Session, project_id: int) -> dict[str, FindingTriage]:
    """Décisions de triage du projet, indexées par fingerprint."""
    rows = db.scalars(
        select(FindingTriage).where(FindingTriage.project_id == project_id)
    ).all()
    return {t.fingerprint: t for t in rows}


@router.get("/api/audit-log", response_model=AuditLogPage)
def list_audit_log(
    current_user: User = Depends(get_current_user),
    project_id: int | None = Query(None, description="Filtrer sur un seul projet"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> AuditLogPage:
    """Historique des décisions de triage, tous projets confondus.

    Append-only : contrairement aux findings, une ligne d'audit n'est jamais
    modifiée ni supprimée — c'est ce qui en fait une preuve fiable pour un
    auditeur externe (CNDP, Bank Al-Maghrib...).
    """
    stmt = select(TriageAuditLog).where(TriageAuditLog.owner_id == current_user.id)
    if project_id is not None:
        stmt = stmt.where(TriageAuditLog.project_id == project_id)
    stmt = stmt.order_by(desc(TriageAuditLog.created_at))

    all_rows = db.scalars(stmt).all()
    total = len(all_rows)
    start = (page - 1) * page_size
    page_rows = all_rows[start : start + page_size]

    user_ids = {r.user_id for r in page_rows if r.user_id is not None}
    emails = {
        u.id: u.email
        for u in db.scalars(select(User).where(User.id.in_(user_ids))).all()
    }

    items = [
        AuditLogEntryOut(
            id=r.id,
            project_id=r.project_id,
            project_name=r.project_name,
            finding_fingerprint=r.finding_fingerprint,
            finding_title=r.finding_title,
            from_status=r.from_status,
            to_status=r.to_status,
            note=r.note,
            user_email=emails.get(r.user_id) if r.user_id else None,
            created_at=r.created_at,
        )
        for r in page_rows
    ]
    return AuditLogPage(items=items, total=total, page=page, page_size=page_size)


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


@router.get("/api/alerts", response_model=FindingsPage)
def list_alerts(
    current_user: User = Depends(get_current_user),
    project_id: int | None = Query(None, description="Filtrer sur un seul projet"),
    severity: str | None = Query(None),
    category: str | None = Query(None),
    status: str | None = Query(None, description="Filtrer par statut de triage"),
    q: str | None = Query(None, description="Recherche libre (titre, ressource, fichier)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> FindingsPage:
    """Toutes les alertes de l'utilisateur, tous projets confondus.

    Vue « dernier état » : pour chaque projet, seules les findings du DERNIER
    scan sont montrées (pas tout l'historique) — sinon un même problème
    redétecté à chaque scan apparaîtrait en double, en triple...
    """
    projects = list(
        db.scalars(
            select(Project).where(Project.owner_id == current_user.id)
        ).all()
    )
    if project_id is not None:
        projects = [p for p in projects if p.id == project_id]

    rows: list[FindingWithProject] = []
    for project in projects:
        latest_scan = db.scalar(
            select(Scan)
            .where(Scan.project_id == project.id)
            .order_by(desc(Scan.scanned_at))
            .limit(1)
        )
        if latest_scan is None:
            continue

        stmt = select(Finding).where(Finding.scan_id == latest_scan.id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if category:
            stmt = stmt.where(Finding.category == category)

        triage = _triage_map(db, project.id)
        for f in db.scalars(stmt).all():
            decision = triage.get(f.fingerprint)
            item_status = decision.status if decision else "open"
            if status and item_status != status:
                continue
            if q:
                haystack = " ".join(
                    filter(None, [f.title, f.resource, f.file, f.rule_id])
                ).lower()
                if q.lower() not in haystack:
                    continue
            base = FindingOut.model_validate(f).model_dump()
            base.update(
                status=item_status,
                triage_note=decision.note if decision else None,
            )
            rows.append(
                FindingWithProject(
                    **base,
                    project_id=project.id,
                    project_name=project.name,
                    repo=latest_scan.repo,
                    scan_id=latest_scan.id,
                    detected_at=latest_scan.scanned_at,
                    commit_sha=latest_scan.commit_sha,
                )
            )

    # Plus grave d'abord, puis le plus récemment détecté.
    rows.sort(
        key=lambda r: (SEVERITY_WEIGHTS.get(r.severity, 0), r.id), reverse=True
    )

    total = len(rows)
    start = (page - 1) * page_size
    return FindingsPage(
        items=rows[start : start + page_size],
        total=total,
        page=page,
        page_size=page_size,
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
        score=_score_out(db, scan.id, scan.project_id),
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
    previous_status = decision.status if decision else "open"

    def _log_change() -> None:
        # Append-only : contrairement à FindingTriage (qui écrase l'état
        # précédent), chaque décision garde une trace pour l'audit log.
        if previous_status == payload.status:
            return
        project = db.get(Project, scan.project_id)
        db.add(
            TriageAuditLog(
                project_id=scan.project_id,
                project_name=project.name if project else "?",
                owner_id=project.owner_id if project else current_user.id,
                finding_fingerprint=finding.fingerprint,
                finding_title=finding.title,
                from_status=previous_status,
                to_status=payload.status,
                note=payload.note,
                user_id=current_user.id,
            )
        )

    if payload.status == "open":
        # Ré-ouvrir = supprimer la décision : "open" est l'état implicite.
        if decision is not None:
            db.delete(decision)
        _log_change()
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
    _log_change()
    db.commit()

    return FindingOut.model_validate(finding).model_copy(
        update={"status": decision.status, "triage_note": decision.note}
    )
