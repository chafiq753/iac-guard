"""Routes projets : création (renvoie le token) et liste.

Toutes ces routes exigent un JWT utilisateur : un projet appartient à son
créateur. Un utilisateur voit ses propres projets, plus ceux que l'admin de
son organisation lui a partagés (voir deps.list_accessible_projects).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import (
    get_accessible_project,
    get_current_user,
    list_accessible_projects,
    require_role,
)
from app.core.security import generate_project_token, hash_token, token_preview
from app.db.session import get_db
from app.models.ignored_rule import IgnoredRule
from app.models.project import Project
from app.models.project_access import ProjectAccess
from app.models.scan import Scan
from app.models.triage import FindingTriage
from app.models.user import User
from app.schemas.project import (
    IgnoredRuleCreate,
    IgnoredRuleOut,
    ProjectCreate,
    ProjectCreated,
    ProjectOut,
    ScanPolicyOut,
    ScanPolicyUpdate,
)
from app.schemas.read import ProjectDetail, ProjectTokenRotated, ScoreOut
from app.services.admin_audit import log_admin_action
from app.services.aggregates import ignored_rule_ids, severity_counts
from app.services.scoring import compute_score

router = APIRouter(prefix="/api/projects", tags=["projects"])

_DUPLICATE_NAME = HTTPException(
    status_code=409, detail="Vous avez déjà un projet avec ce nom."
)


@router.post("", response_model=ProjectCreated, status_code=201)
def create_project(
    payload: ProjectCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProjectCreated:
    """Crée un projet (possédé par l'utilisateur) et renvoie son token API.

    Le token n'est affiché QU'ICI : seul son hash est conservé en base.
    """
    token = generate_project_token()
    project = Project(
        name=payload.name,
        owner_id=current_user.id,
        token_hash=hash_token(token),
        token_prefix=token_preview(token),
    )
    db.add(project)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise _DUPLICATE_NAME from None
    db.refresh(project)

    return ProjectCreated(
        id=project.id,
        name=project.name,
        token_prefix=project.token_prefix,
        created_at=project.created_at,
        token=token,
    )


@router.get("", response_model=list[ProjectOut])
def list_projects(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Project]:
    """Liste les projets visibles par l'utilisateur connecté (sans les tokens)."""
    return list_accessible_projects(db, current_user)


@router.get("/{project_id}", response_model=ProjectDetail)
def get_project(
    project: Project = Depends(get_accessible_project),
    db: Session = Depends(get_db),
) -> ProjectDetail:
    """Vue d'ensemble d'un projet : nombre de scans + score du dernier scan."""
    scan_count = db.scalar(
        select(func.count()).select_from(Scan).where(Scan.project_id == project.id)
    )
    latest = db.scalar(
        select(Scan)
        .where(Scan.project_id == project.id)
        .order_by(desc(Scan.scanned_at))
        .limit(1)
    )
    latest_score = None
    if latest is not None:
        excluded = ignored_rule_ids(db, project.id)
        result = compute_score(severity_counts(db, latest.id, excluded))
        latest_score = ScoreOut(**result.__dict__)

    return ProjectDetail(
        id=project.id,
        name=project.name,
        created_at=project.created_at,
        scan_count=scan_count or 0,
        latest_score=latest_score,
        last_scan_at=latest.scanned_at if latest is not None else None,
    )


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project: Project = Depends(get_accessible_project),
    db: Session = Depends(get_db),
) -> None:
    """Supprime un projet et tout son historique (scans, findings, triage).

    Irréversible : le token cesse aussitôt de fonctionner. Le dashboard doit
    faire confirmer cette action avant d'appeler cette route.

    Les journaux d'audit, eux, sont conservés (dénormalisés, sans clé
    étrangère vers le projet) : ils restent lisibles après la suppression.
    """
    # Tables liées sans cascade ORM : à vider avant, sinon PostgreSQL refuse.
    db.execute(delete(FindingTriage).where(FindingTriage.project_id == project.id))
    db.execute(delete(ProjectAccess).where(ProjectAccess.project_id == project.id))
    db.delete(project)
    db.commit()


@router.post("/{project_id}/rotate-token", response_model=ProjectTokenRotated)
def rotate_token(
    project: Project = Depends(get_accessible_project),
    db: Session = Depends(get_db),
) -> ProjectTokenRotated:
    """Invalide l'ancien token et en émet un nouveau (affiché une seule fois).

    À utiliser si le token a pu fuiter (commit accidentel, log exposé...).
    L'ancien cesse de fonctionner immédiatement : le pipeline devra être
    reconfiguré avec le nouveau avant son prochain scan.
    """
    token = generate_project_token()
    project.token_hash = hash_token(token)
    project.token_prefix = token_preview(token)
    db.commit()
    return ProjectTokenRotated(token_prefix=project.token_prefix, token=token)


# --------------------------------------------------------------------------- #
# Politique de scan : seuil de blocage du pipeline + règles ignorées.
# --------------------------------------------------------------------------- #


@router.get("/{project_id}/policy", response_model=ScanPolicyOut)
def get_policy(
    project: Project = Depends(get_accessible_project),
    db: Session = Depends(get_db),
) -> ScanPolicyOut:
    rules = db.scalars(
        select(IgnoredRule)
        .where(IgnoredRule.project_id == project.id)
        .order_by(desc(IgnoredRule.created_at))
    ).all()
    return ScanPolicyOut(
        fail_on_severity=project.fail_on_severity,
        ignored_rules=[IgnoredRuleOut.model_validate(r) for r in rules],
    )


@router.patch("/{project_id}/policy", response_model=ScanPolicyOut)
def update_policy(
    payload: ScanPolicyUpdate,
    project: Project = Depends(get_accessible_project),
    # Baisser le seuil débloquerait une PR : décision réservée à la sécurité.
    _: User = Depends(require_role("admin", "security_lead")),
    db: Session = Depends(get_db),
) -> ScanPolicyOut:
    """Change le seuil de blocage du pipeline (null = ne jamais bloquer)."""
    project.fail_on_severity = payload.fail_on_severity
    db.commit()
    return get_policy(project=project, db=db)


@router.post(
    "/{project_id}/ignored-rules", response_model=IgnoredRuleOut, status_code=201
)
def add_ignored_rule(
    payload: IgnoredRuleCreate,
    project: Project = Depends(get_accessible_project),
    # Accepter un risque est une décision de sécurité : admin / security_lead.
    current_user: User = Depends(require_role("admin", "security_lead")),
    db: Session = Depends(get_db),
) -> IgnoredRule:
    """Accepte une règle comme risque connu : elle ne compte plus dans le

    score ni dans le seuil de blocage, mais reste visible dans les alertes.
    """
    existing = db.scalar(
        select(IgnoredRule).where(
            IgnoredRule.project_id == project.id,
            IgnoredRule.rule_id == payload.rule_id,
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=409, detail="Cette règle est déjà dans les exceptions."
        )

    rule = IgnoredRule(
        project_id=project.id,
        rule_id=payload.rule_id,
        note=payload.note,
        created_by_id=current_user.id,
    )
    db.add(rule)
    log_admin_action(
        db,
        actor=current_user,
        action="policy.exception_added",
        details={
            "project_id": project.id,
            "project_name": project.name,
            "rule_id": rule.rule_id,
            "note": rule.note,
        },
    )
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{project_id}/ignored-rules/{ignored_rule_id}", status_code=204)
def remove_ignored_rule(
    ignored_rule_id: int,
    project: Project = Depends(get_accessible_project),
    current_user: User = Depends(require_role("admin", "security_lead")),
    db: Session = Depends(get_db),
) -> None:
    """Ré-active la règle : ses findings recomptent dans le score."""
    rule = db.get(IgnoredRule, ignored_rule_id)
    if rule is None or rule.project_id != project.id:
        raise HTTPException(status_code=404, detail="Exception introuvable.")
    log_admin_action(
        db,
        actor=current_user,
        action="policy.exception_removed",
        # La justification d'origine est recopiée : la ligne `ignored_rules`
        # disparaît, l'audit doit rester complet sans elle.
        details={
            "project_id": project.id,
            "project_name": project.name,
            "rule_id": rule.rule_id,
            "note": rule.note,
        },
    )
    db.delete(rule)
    db.commit()
