"""Fichier .iacguard.yml : lecture, validation, exclusions et exceptions."""

from __future__ import annotations

import shutil
import subprocess
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iacguard.cli import EXIT_BLOCKED, EXIT_ERROR, EXIT_OK, app
from iacguard.config import ConfigError, IgnoreEntry, load_config, path_matches
from iacguard.runners import RUNNERS, ToolRun
from iacguard.schema import Category, Finding, Severity, ToolName

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path_factory.mktemp("cache")))
    for var in ("GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "GITHUB_BASE_REF"):
        monkeypatch.delenv(var, raising=False)


def _f(rule: str, severity: Severity, file: str = "main.tf", line: int = 1) -> Finding:
    return Finding(source=ToolName.CHECKOV, category=Category.MISCONFIGURATION, rule_id=rule,
                   title=rule, severity=severity, file=file, line_start=line)


@pytest.fixture
def fake_checkov(monkeypatch):
    def install(findings: list[Finding]):
        for tool in RUNNERS:
            def fake(path, *, _t=tool, **_kw):
                return ToolRun(_t, "ok", findings=list(findings) if _t is ToolName.CHECKOV else [])
            monkeypatch.setitem(RUNNERS, tool, fake)
    return install


def _write(tmp_path: Path, text: str) -> Path:
    cfg = tmp_path / ".iacguard.yml"
    cfg.write_text(text, encoding="utf-8")
    return cfg


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def test_valid_config(tmp_path: Path) -> None:
    cfg = load_config(_write(tmp_path, """
fail_on: critical
tools: [checkov]
exclude: [examples/]
ignore:
  - rule: CKV_AWS_20
    path: site/
    reason: "Site statique public, lecture voulue"
    expires: 2030-01-01
"""))
    assert cfg.fail_on == "critical"
    assert cfg.ignore[0].expires == date(2030, 1, 1)


def test_empty_config_is_fine(tmp_path: Path) -> None:
    assert load_config(_write(tmp_path, "")).ignore == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("fail-on: high\n", "clé inconnue"),                                     # faute de frappe
        ("fail_on: hight\n", "fail_on"),                                         # valeur inconnue
        ("ignore:\n  - rule: CKV_AWS_20\n", "obligatoire"),                     # pas de raison
        ("ignore:\n  - rule: CKV_AWS_20\n    reason: ok\n", "trop courte"),      # raison bidon
        ("ignore: [\n", "YAML"),
        ("- juste une liste\n", "clés"),
    ],
)
def test_invalid_config_is_rejected(tmp_path: Path, text: str, expected: str) -> None:
    with pytest.raises(ConfigError, match=expected):
        load_config(_write(tmp_path, text))


@pytest.mark.parametrize(
    ("file", "pattern", "match"),
    [
        ("examples/a.tf", "examples/", True),
        ("/examples/sub/a.tf", "examples", True),       # format Checkov
        ("examples2/a.tf", "examples", False),          # pas un simple préfixe
        ("infra/a_test.tf", "**/*_test.tf", True),
        ("a_test.tf", "**/*_test.tf", True),
        ("infra/main.tf", "*.json", False),
        (None, "examples/", False),
    ],
)
def test_path_matches(file: str | None, pattern: str, match: bool) -> None:
    assert path_matches(file, pattern) is match


def test_expired_ignore() -> None:
    entry = IgnoreEntry(rule="X", reason="raison suffisante", expires=date(2026, 1, 1))
    assert entry.expired(today=date(2026, 1, 2))
    assert not entry.expired(today=date(2026, 1, 1))


# --------------------------------------------------------------------------- #
# Effet sur le scan
# --------------------------------------------------------------------------- #


def test_ignored_finding_does_not_block(fake_checkov, tmp_path: Path) -> None:
    _write(tmp_path, 'ignore:\n  - rule: CKV_AWS_20\n    reason: "Bucket public voulu (site statique)"\n')
    fake_checkov([_f("CKV_AWS_20", Severity.HIGH)])
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_OK, result.output
    assert "(ignoré)" in result.stdout
    assert "Bucket public voulu" in runner.invoke(app, ["show", "1"]).stdout


def test_ignore_limited_to_path(fake_checkov, tmp_path: Path) -> None:
    _write(tmp_path, 'ignore:\n  - rule: CKV_AWS_20\n    path: site/\n'
                     '    reason: "Seul le site statique est public"\n')
    fake_checkov([_f("CKV_AWS_20", Severity.HIGH, file="/site/s3.tf"),
                  _f("CKV_AWS_20", Severity.HIGH, file="/data/s3.tf")])
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_BLOCKED, result.output   # data/ n'est pas couvert


def test_expired_ignore_blocks_again(fake_checkov, tmp_path: Path) -> None:
    _write(tmp_path, 'ignore:\n  - rule: CKV_AWS_20\n    reason: "Exception temporaire"\n'
                     '    expires: 2020-01-01\n')
    fake_checkov([_f("CKV_AWS_20", Severity.HIGH)])
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_BLOCKED
    assert "expirée" in result.stderr


def test_excluded_path_removed_from_report(fake_checkov, tmp_path: Path) -> None:
    _write(tmp_path, "exclude:\n  - examples/\n")
    fake_checkov([_f("CKV_AWS_20", Severity.HIGH, file="/examples/demo.tf")])
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_OK, result.output
    assert "chemins exclus" in result.stdout


def test_cli_option_overrides_config(fake_checkov, tmp_path: Path) -> None:
    _write(tmp_path, "fail_on: critical\n")
    fake_checkov([_f("CKV_AWS_20", Severity.HIGH)])
    assert runner.invoke(app, ["scan", str(tmp_path)]).exit_code == EXIT_OK
    assert runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high"]).exit_code == EXIT_BLOCKED


def test_config_tools(fake_checkov, tmp_path: Path, monkeypatch) -> None:
    calls = []
    for tool in RUNNERS:
        monkeypatch.setitem(RUNNERS, tool, lambda p, *, _t=tool, **k: calls.append(_t) or ToolRun(_t, "ok"))
    _write(tmp_path, "tools: [checkov]\n")
    runner.invoke(app, ["scan", str(tmp_path)])
    assert calls == [ToolName.CHECKOV]


def test_invalid_config_stops_scan(fake_checkov, tmp_path: Path) -> None:
    _write(tmp_path, "fail-on: high\n")
    fake_checkov([])
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_ERROR
    assert "clé inconnue" in result.stderr


# --------------------------------------------------------------------------- #
# Gitleaks en pull request : seulement les commits de la PR
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(not (shutil.which("gitleaks") and shutil.which("git")), reason="gitleaks/git absent")
def test_old_secret_in_main_does_not_block_pr(tmp_path: Path, monkeypatch) -> None:
    from test_runners import _fake_github_token

    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t",
                        *args], check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    (tmp_path / "old.py").write_text(f'TOKEN = "{_fake_github_token()}"\n', encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "ancien secret")
    git("update-ref", "refs/remotes/origin/main", "HEAD")
    git("checkout", "-qb", "feature")
    (tmp_path / "new.py").write_text("print('ok')\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "feature propre")

    full = runner.invoke(app, ["scan", str(tmp_path), "-t", "gitleaks"])
    assert full.exit_code == EXIT_BLOCKED, full.output

    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    pr = runner.invoke(app, ["scan", str(tmp_path), "-t", "gitleaks"])
    assert pr.exit_code == EXIT_OK, pr.output
