"""Fixtures partagées pour les tests.

Les tests tournent sur une base SQLite EN MÉMOIRE (rapide, isolée, aucune trace
sur disque) — indépendante du Postgres de production. On surcharge la
dépendance `get_db` de FastAPI pour que l'API et les tests partagent la même
session de test.

Note : on n'utilise PAS `TestClient` comme context manager, afin de ne pas
déclencher le `lifespan` de l'app (qui créerait les tables sur le VRAI engine).
Les tables de test sont créées ici, à la main, sur l'engine en mémoire.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.session import Base, get_db

# Import des modèles pour que create_all connaisse toutes les tables.
from app.models import credential, finding, project, scan, triage, user  # noqa: F401
from app.main import app


# StaticPool + une seule connexion partagée : la base en mémoire survit entre
# les requêtes d'un même test (sinon chaque connexion aurait sa propre base vide).
_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    future=True,
)
_TestingSession = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


@pytest.fixture
def db_session() -> Iterator[Session]:
    """Session DB directe, pour tester les services (schéma frais par test)."""
    Base.metadata.create_all(bind=_engine)
    session = _TestingSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=_engine)


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Client HTTP de test, câblé sur la base en mémoire (schéma frais par test)."""
    Base.metadata.create_all(bind=_engine)

    def _override_get_db() -> Iterator[Session]:
        db = _TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=_engine)


# Identifiants du compte de test par défaut.
# Conforme à la politique : >= 12 caractères, minuscule, majuscule, chiffre,
# caractère spécial.
USER_EMAIL = "dev@iac-guard.io"
USER_PASSWORD = "S3cret-Password!"


def register(
    client: TestClient, email: str = USER_EMAIL, password: str = USER_PASSWORD
) -> None:
    resp = client.post(
        "/api/auth/register", json={"email": email, "password": password}
    )
    assert resp.status_code == 201, resp.text


def register_and_login(
    client: TestClient, email: str = USER_EMAIL, password: str = USER_PASSWORD
) -> dict[str, str]:
    """Crée un compte, se connecte, et renvoie un en-tête Authorization.

    La connexion pose un cookie httpOnly de session. On récupère sa valeur pour
    la renvoyer en `Bearer`, puis on VIDE les cookies du client : sans ça, le
    client resterait authentifié « tout seul » et les tests qui vérifient
    l'absence d'authentification passeraient pour de mauvaises raisons.
    """
    register(client, email, password)
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    assert resp.json()["mfa_required"] is False

    token = resp.cookies.get(settings.session_cookie_name)
    assert token, "le login aurait dû poser un cookie de session"
    client.cookies.clear()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_headers(client: TestClient) -> dict[str, str]:
    """En-tête Authorization d'un utilisateur connecté."""
    return register_and_login(client)


@pytest.fixture
def project_token(
    client: TestClient, auth_headers: dict[str, str]
) -> tuple[int, str]:
    """Crée un projet et renvoie (project_id, token projet) pour l'ingestion.

    Attention : le token renvoyé est le TOKEN DE PROJET (pipeline), pas le JWT.
    """
    resp = client.post(
        "/api/projects", json={"name": "acme/demo"}, headers=auth_headers
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return body["id"], body["token"]


def sample_report(repo: str = "acme/demo") -> dict:
    """Rapport de scan minimal et valide (1 critical, 1 high, 1 medium)."""
    return {
        "schema_version": "1.0",
        "scan": {
            "repo": repo,
            "branch": "main",
            "commit_sha": "abc123",
            "created_at": "2026-07-09T08:00:00Z",
            "tools": [{"name": "checkov", "version": "3.2"}],
        },
        "findings": [
            {
                "fingerprint": "f1",
                "source": "gitleaks",
                "category": "secret",
                "rule_id": "aws-access-token",
                "title": "AWS key committed",
                "severity": "critical",
                "resource": "main.tf",
            },
            {
                "fingerprint": "f2",
                "source": "checkov",
                "category": "misconfiguration",
                "rule_id": "CKV_AWS_20",
                "title": "S3 public read",
                "severity": "high",
            },
            {
                "fingerprint": "f3",
                "source": "checkov",
                "category": "misconfiguration",
                "rule_id": "CKV_AWS_16",
                "title": "RDS not encrypted",
                "severity": "medium",
            },
        ],
    }
