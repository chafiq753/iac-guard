"""Connexion à la base de données et session SQLAlchemy."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

# SQLite a besoin de ce flag pour être utilisé avec FastAPI (multi-thread).
_connect_args = (
    {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
)

engine = create_engine(settings.database_url, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    """Classe de base pour tous les modèles ORM."""


def get_db() -> Generator[Session, None, None]:
    """Dépendance FastAPI : fournit une session DB par requête, puis la ferme."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
