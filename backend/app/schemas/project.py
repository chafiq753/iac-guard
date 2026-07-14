"""Schémas Pydantic pour les projets (création / lecture)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ProjectCreate(BaseModel):
    name: str


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    token_prefix: str
    created_at: datetime


class ProjectCreated(ProjectOut):
    """Renvoyé UNE seule fois à la création : contient le token en clair."""

    token: str
