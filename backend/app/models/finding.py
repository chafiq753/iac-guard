"""Modèle Finding : un problème détecté, normalisé (schéma unifié)."""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.session import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)

    # Identité stable du finding (dédup / suivi dans le temps).
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    source: Mapped[str] = mapped_column(String(20))       # gitleaks / checkov / conftest
    category: Mapped[str] = mapped_column(String(30))     # secret / misconfiguration / policy
    rule_id: Mapped[str] = mapped_column(String(120))
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(10), index=True)

    resource: Mapped[str | None] = mapped_column(String(300), nullable=True)
    file: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Objet brut de l'outil, conservé pour l'audit / debug.
    raw: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped["Scan"] = relationship(back_populates="findings")  # noqa: F821
