"""Routes projets : création (renvoie le token) et liste.

Toutes ces routes exigent un JWT utilisateur : un projet appartient à son
créateur, et un utilisateur ne voit jamais les projets des autres.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_owned_project
from app.core.security import generate_project_token, hash_token, token_preview
from app.db.session import get_db
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.project import ProjectCreate, ProjectCreated, ProjectOut
from app.schemas.read import ProjectDetail, ScoreOut
from app.services.aggregates import severity_counts
from app.services.scoring import compute_score

router = APIRouter(prefix="/api/projects", tags=["projects"])


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
    db.commit()
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
    """Liste les projets de l'utilisateur connecté (sans les tokens)."""
    return list(
        db.scalars(select(Project).where(Project.owner_id == current_user.id)).all()
    )


@router.get("/{project_id}", response_model=ProjectDetail)
def get_project(
    project: Project = Depends(get_owned_project),
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
        result = compute_score(severity_counts(db, latest.id))
        latest_score = ScoreOut(**result.__dict__)

    return ProjectDetail(
        id=project.id,
        name=project.name,
        created_at=project.created_at,
        scan_count=scan_count or 0,
        latest_score=latest_score,
    )
