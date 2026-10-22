"""Schéma : le fingerprint doit rester compatible avec le dashboard."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from iacguard.parsers import parse_checkov, parse_gitleaks
from iacguard.schema import ScanMeta, ScanReport, Severity

ROOT = Path(__file__).resolve().parents[1]


def _load_pipeline_schema():
    """Charge pipeline/aggregator/schema.py (ancien contrat pipeline -> API)."""
    path = ROOT / "pipeline" / "aggregator" / "schema.py"
    spec = importlib.util.spec_from_file_location("pipeline_schema", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["pipeline_schema"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_fingerprint_matches_pipeline_schema(checkov_sample, gitleaks_sample) -> None:
    old = _load_pipeline_schema()
    for f in parse_checkov(checkov_sample) + parse_gitleaks(gitleaks_sample):
        legacy = old.Finding(**f.model_dump(exclude={"fingerprint"}))
        assert f.fingerprint == legacy.fingerprint


def test_fingerprint_ignores_raw_payload(checkov_sample) -> None:
    f = parse_checkov(checkov_sample)[0]
    g = f.model_copy(update={"raw": {"autre": "contenu"}})
    assert f.fingerprint == g.fingerprint


def test_report_summary_counts(checkov_sample) -> None:
    from datetime import datetime, timezone

    findings = parse_checkov(checkov_sample)
    meta = ScanMeta(repo="demo", created_at=datetime.now(timezone.utc))
    report = ScanReport.build(meta, findings)
    assert report.summary.total == 3
    assert report.summary.by_severity[Severity.HIGH] == 1
    # Le JSON produit doit être relisible tel quel (contrat avec le dashboard).
    again = ScanReport.model_validate_json(report.model_dump_json())
    assert again.summary.total == 3
