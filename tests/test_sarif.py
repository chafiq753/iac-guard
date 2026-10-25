"""Export SARIF (GitHub Code scanning)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from iacguard.cli import EXIT_BLOCKED, app
from iacguard.runners import RUNNERS, ToolRun
from iacguard.sarif import to_sarif
from iacguard.schema import Category, Finding, Severity, ToolName

runner = CliRunner()


def _f(rule: str, sev: Severity, file: str | None = "/infra/main.tf", line: int | None = 10,
       end: int | None = 12, remediation: str | None = None) -> Finding:
    return Finding(source=ToolName.CHECKOV, category=Category.MISCONFIGURATION, rule_id=rule,
                   title=f"Titre {rule}", severity=sev, resource="aws_s3_bucket.b",
                   file=file, line_start=line, line_end=end, remediation=remediation)


def test_sarif_structure(tmp_path: Path) -> None:
    findings = [
        _f("CKV_AWS_20", Severity.HIGH, remediation="https://docs.example/fix"),
        _f("CKV_AWS_20", Severity.HIGH, line=30, end=31),      # même règle : une seule définition
        _f("CKV_AWS_21", Severity.LOW, line=None, end=None),
        _f("NO_FILE", Severity.MEDIUM, file=None),             # sans emplacement : ignoré
    ]
    doc = to_sarif(findings, tmp_path)
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["CKV_AWS_20", "CKV_AWS_21"]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "8.0"
    assert rule["helpUri"] == "https://docs.example/fix"
    assert len(run["results"]) == 3
    first = run["results"][0]
    loc = first["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "infra/main.tf"          # sans le / de Checkov
    assert loc["region"] == {"startLine": 10, "endLine": 12}
    assert first["level"] == "error"
    assert first["partialFingerprints"]["iacguardFingerprint/v1"] == findings[0].fingerprint
    assert run["results"][2]["locations"][0]["physicalLocation"]["region"] == {"startLine": 1}


def test_ignored_findings_are_suppressed_not_dropped(tmp_path: Path) -> None:
    f = _f("CKV_AWS_20", Severity.HIGH)
    doc = to_sarif([f], tmp_path, ignored={f.fingerprint: "Site statique public"})
    result = doc["runs"][0]["results"][0]
    assert result["suppressions"] == [{"kind": "external", "justification": "Site statique public"}]


def test_cli_writes_sarif(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "cache"))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    for tool in RUNNERS:
        monkeypatch.setitem(RUNNERS, tool, lambda p, *, _t=tool, **k: ToolRun(
            _t, "ok", findings=[_f("CKV_AWS_20", Severity.HIGH)] if _t is ToolName.CHECKOV else []))
    out = tmp_path / "r.sarif"
    result = runner.invoke(app, ["scan", str(tmp_path), "--sarif", str(out), "--no-annotations"])
    assert result.exit_code == EXIT_BLOCKED, result.output
    assert json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"][0]["ruleId"] == "CKV_AWS_20"
    assert "::error" not in result.stdout                    # --no-annotations

    result = runner.invoke(app, ["scan", str(tmp_path), "-f", "sarif"])
    assert json.loads(result.stdout)["version"] == "2.1.0"
