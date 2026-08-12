"""Point d'entrée de l'API FastAPI iac-guard."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.db.session import Base, engine

# Import des modèles pour que SQLAlchemy connaisse les tables avant create_all.
from app.models import (  # noqa: F401
    audit_log,
    credential,
    finding,
    ignored_rule,
    project,
    scan,
    triage,
    user,
)
from app.api import auth, findings, projects, scans, twofa


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # MVP : création automatique des tables au démarrage. On passera à Alembic
    # (migrations) quand le schéma se stabilisera.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)

# `allow_credentials=True` est indispensable pour que le navigateur envoie le
# cookie de session. Il interdit `allow_origins=["*"]` : la liste doit rester
# explicite — c'est justement ce qui empêche un site tiers de lire l'API avec
# le cookie de la victime.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "app": settings.app_name}


app.include_router(auth.router)
app.include_router(twofa.router)
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(findings.router)
