"""Fixtures communes aux tests du cœur iacguard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "pipeline" / "aggregator" / "samples"
DEMO_TF = ROOT / "docs" / "demo-vulnerable-main.tf"


def load_sample(name: str) -> Any:
    with (SAMPLES / name).open(encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def gitleaks_sample() -> Any:
    return load_sample("gitleaks.json")


@pytest.fixture
def checkov_sample() -> Any:
    return load_sample("checkov.json")


@pytest.fixture
def conftest_sample() -> Any:
    return load_sample("conftest.json")


@pytest.fixture
def semgrep_sample() -> dict[str, Any]:
    # Pas de fichier exemple Semgrep dans le repo : sortie minimale réaliste.
    return {
        "version": "1.78.0",
        "results": [
            {
                "check_id": "python.lang.security.audit.formatted-sql-query",
                "path": "app/db.py",
                "start": {"line": 12},
                "end": {"line": 12},
                "extra": {
                    "message": "Requête SQL construite par formatage de chaîne.\nRisque d'injection.",
                    "severity": "ERROR",
                },
            },
            {
                "check_id": "javascript.express.security.audit.xss",
                "path": "web/app.js",
                "start": {"line": 3},
                "end": {"line": 4},
                "extra": {"message": "XSS possible", "severity": "WARNING", "fix": "escape()"},
            },
        ],
    }
