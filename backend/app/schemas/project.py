"""Schémas Pydantic pour les projets (création / lecture)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

# Valeurs acceptées pour la politique de blocage du pipeline.
FAIL_SEVERITY_CHOICES = ("critical", "high", "medium", "low", "info")


class ProjectCreate(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Le nom du projet ne peut pas être vide.")
        return cleaned


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    token_prefix: str
    created_at: datetime


class ProjectCreated(ProjectOut):
    """Renvoyé UNE seule fois à la création : contient le token en clair."""

    token: str


class IgnoredRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    note: str | None = None
    created_at: datetime


class IgnoredRuleCreate(BaseModel):
    rule_id: str
    note: str | None = None

    @field_validator("rule_id")
    @classmethod
    def _rule_id_not_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("L'identifiant de règle ne peut pas être vide.")
        return cleaned


class ScanPolicyOut(BaseModel):
    """Politique de scan d'un projet : seuil de blocage + exceptions."""

    fail_on_severity: str | None = None
    ignored_rules: list[IgnoredRuleOut] = []


class ScanPolicyUpdate(BaseModel):
    """`fail_on_severity=None` désactive le blocage (comportement par défaut)."""

    fail_on_severity: str | None = None

    @field_validator("fail_on_severity")
    @classmethod
    def _valid_choice(cls, value: str | None) -> str | None:
        if value is not None and value not in FAIL_SEVERITY_CHOICES:
            raise ValueError(
                f"Valeur invalide. Attendu : {', '.join(FAIL_SEVERITY_CHOICES)} ou null."
            )
        return value
