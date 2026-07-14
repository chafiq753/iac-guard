"""Modèle Scan : un scan reçu du pipeline pour un projet donné."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)

    schema_version: Mapped[str] = mapped_column(String(10), default="1.0")
    repo: Mapped[str] = mapped_column(String(300))
    branch: Mapped[str | None] = mapped_column(String(200), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Instant du scan côté pipeline (fourni par le rapport).
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Instant de réception côté API.
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    total_findings: Mapped[int] = mapped_column(Integer, default=0)

    project: Mapped["Project"] = relationship(back_populates="scans")  # noqa: F821
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        back_populates="scan", cascade="all, delete-orphan"
    )
