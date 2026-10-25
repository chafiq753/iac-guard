"""CLI : options, codes de sortie et formats de sortie.

La plupart des tests remplacent les vrais scanners par des faux (rapides,
résultat connu d'avance). Un test d'intégration lance le vrai Checkov sur
le Terraform de démo.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import DEMO_TF
from iacguard import __version__
from iacguard.cli import EXIT_BLOCKED, EXIT_ERROR, EXIT_OK, app
from iacguard.gitinfo import detect, repo_from_remote
from iacguard.runners import RUNNERS, ToolRun
from iacguard.schema import Category, Finding, ScanReport, Severity, ToolName

runner = CliRunner()


def _finding(tool: ToolName, severity: Severity, rule: str = "RULE_1", file: str = "main.tf") -> Finding:
    return Finding(
        source=tool,
        category=Category.MISCONFIGURATION,
        rule_id=rule,
        title=f"Problème {rule}",
        severity=severity,
        file=file,
        line_start=3,
    )


@pytest.fixture
def fake_tools(monkeypatch: pytest.MonkeyPatch):
    """Remplace les runners. Usage : fake_tools(checkov=[...], gitleaks=None)

    Une liste = le scanner tourne et renvoie ces findings ; None = absent.
    Un outil non précisé tourne et ne trouve rien.
    """
    calls: list[ToolName] = []

    def install(**spec: list[Finding] | None) -> list[ToolName]:
        for tool in RUNNERS:
            findings = spec.get(tool.value, [])

            def fake(path: Path, *, _tool=tool, _findings=findings, **_kw) -> ToolRun:
                calls.append(_tool)
                if _findings is None:
                    return ToolRun(_tool, "missing", message=f"{_tool.value} introuvable dans le PATH")
                return ToolRun(_tool, "ok", findings=list(_findings), version="1.0")

            monkeypatch.setitem(RUNNERS, tool, fake)
        return calls

    return install


# --------------------------------------------------------------------------- #
# Codes de sortie
# --------------------------------------------------------------------------- #


def test_clean_scan_passes(fake_tools, tmp_path: Path) -> None:
    fake_tools()
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_OK, result.output
    assert "PASSÉ" in result.stdout
    assert "Aucun problème" in result.stdout


def test_high_blocks_by_default(fake_tools, tmp_path: Path) -> None:
    fake_tools(checkov=[_finding(ToolName.CHECKOV, Severity.HIGH)])
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_BLOCKED, result.output
    assert "BLOQUÉ" in result.stdout


def test_medium_does_not_block_by_default(fake_tools, tmp_path: Path) -> None:
    fake_tools(checkov=[_finding(ToolName.CHECKOV, Severity.MEDIUM)])
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_OK, result.output


def test_fail_on_critical_lets_high_pass(fake_tools, tmp_path: Path) -> None:
    fake_tools(checkov=[_finding(ToolName.CHECKOV, Severity.HIGH)])
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == EXIT_OK, result.output


def test_fail_on_is_case_insensitive(fake_tools, tmp_path: Path) -> None:
    fake_tools(checkov=[_finding(ToolName.CHECKOV, Severity.HIGH)])
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "HIGH"])
    assert result.exit_code == EXIT_BLOCKED, result.output


def test_fail_on_none_never_blocks(fake_tools, tmp_path: Path) -> None:
    fake_tools(gitleaks=[_finding(ToolName.GITLEAKS, Severity.CRITICAL)])
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "none"])
    assert result.exit_code == EXIT_OK, result.output
    assert "RAPPORT SEULEMENT" in result.stdout


def test_typo_in_fail_on_is_rejected(fake_tools, tmp_path: Path) -> None:
    # « hight » ne doit pas désactiver le blocage en silence.
    fake_tools()
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "hight"])
    assert result.exit_code == EXIT_ERROR


def test_missing_folder_is_an_error(fake_tools, tmp_path: Path) -> None:
    fake_tools()
    result = runner.invoke(app, ["scan", str(tmp_path / "nope")])
    assert result.exit_code == EXIT_ERROR


# --------------------------------------------------------------------------- #
# Scanners absents
# --------------------------------------------------------------------------- #


def test_missing_scanner_warns_but_does_not_fail(fake_tools, tmp_path: Path) -> None:
    fake_tools(semgrep=None)
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_OK, result.output
    assert "scan partiel" in result.stderr
    assert "--strict" in result.stderr


def test_missing_scanner_fails_with_strict(fake_tools, tmp_path: Path) -> None:
    fake_tools(semgrep=None)
    result = runner.invoke(app, ["scan", str(tmp_path), "--strict"])
    assert result.exit_code == EXIT_ERROR, result.output


def test_blocking_finding_wins_over_missing_scanner(fake_tools, tmp_path: Path) -> None:
    fake_tools(semgrep=None, checkov=[_finding(ToolName.CHECKOV, Severity.CRITICAL)])
    result = runner.invoke(app, ["scan", str(tmp_path), "--strict"])
    assert result.exit_code == EXIT_BLOCKED, result.output


def test_no_scanner_at_all_is_an_error(fake_tools, tmp_path: Path) -> None:
    # Rien n'a été vérifié : on ne peut pas répondre « passé ».
    fake_tools(gitleaks=None, checkov=None, semgrep=None)
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_ERROR, result.output
    assert "Aucun scanner" in result.stderr


# --------------------------------------------------------------------------- #
# Choix des scanners
# --------------------------------------------------------------------------- #


def test_tools_option_selects_scanners(fake_tools, tmp_path: Path) -> None:
    calls = fake_tools()
    result = runner.invoke(app, ["scan", str(tmp_path), "-t", "checkov, GITLEAKS"])
    assert result.exit_code == EXIT_OK, result.output
    assert calls == [ToolName.GITLEAKS, ToolName.CHECKOV]   # ordre fixe, pas celui tapé


def test_unknown_tool_is_rejected(fake_tools, tmp_path: Path) -> None:
    fake_tools()
    result = runner.invoke(app, ["scan", str(tmp_path), "-t", "checkov,trivy"])
    assert result.exit_code == EXIT_ERROR
    assert "trivy" in result.output


# --------------------------------------------------------------------------- #
# Formats de sortie
# --------------------------------------------------------------------------- #


def test_json_on_stdout_is_a_clean_report(fake_tools, tmp_path: Path) -> None:
    fake_tools(checkov=[_finding(ToolName.CHECKOV, Severity.LOW)])
    result = runner.invoke(app, ["scan", str(tmp_path), "-f", "json"])
    assert result.exit_code == EXIT_OK, result.output
    # stdout = uniquement le JSON (progression et verdict sont sur stderr)
    report = ScanReport.model_validate_json(result.stdout)
    assert report.summary.total == 1
    assert "Score" in result.stderr


def test_output_file_json(fake_tools, tmp_path: Path) -> None:
    fake_tools(checkov=[_finding(ToolName.CHECKOV, Severity.HIGH)])
    out = tmp_path / "rapport.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "-f", "json", "-o", str(out)])
    assert result.exit_code == EXIT_BLOCKED, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["findings"][0]["rule_id"] == "RULE_1"
    assert result.stdout == ""
    assert "BLOQUÉ" in result.stderr


def test_output_file_table(fake_tools, tmp_path: Path) -> None:
    fake_tools(checkov=[_finding(ToolName.CHECKOV, Severity.MEDIUM, rule="CKV_AWS_21")])
    out = tmp_path / "rapport.txt"
    result = runner.invoke(app, ["scan", str(tmp_path), "-o", str(out)])
    assert result.exit_code == EXIT_OK, result.output
    text = out.read_text(encoding="utf-8")
    assert "CKV_AWS_21" in text and "PASSÉ" in text


def test_table_sorted_most_severe_first(fake_tools, tmp_path: Path) -> None:
    fake_tools(checkov=[
        _finding(ToolName.CHECKOV, Severity.LOW, rule="RULE_LOW"),
        _finding(ToolName.CHECKOV, Severity.CRITICAL, rule="RULE_CRIT"),
    ])
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "none"])
    assert result.stdout.index("RULE_CRIT") < result.stdout.index("RULE_LOW")


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


# --------------------------------------------------------------------------- #
# Contexte Git
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/chafiq753/iac-guard.git", "chafiq753/iac-guard"),
        ("https://github.com/chafiq753/iac-guard", "chafiq753/iac-guard"),
        ("git@github.com:chafiq753/iac-guard.git", "chafiq753/iac-guard"),
        # Identifiants dans l'URL : ils ne doivent jamais sortir.
        ("https://user:ghp_secret123@github.com/chafiq753/iac-guard.git", "chafiq753/iac-guard"),
        ("", None),
        ("pas-une-url", None),
    ],
)
def test_repo_from_remote(url: str, expected: str | None) -> None:
    assert repo_from_remote(url) == expected


def test_git_context_from_github_actions(tmp_path: Path) -> None:
    env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "chafiq753/demo",
        "GITHUB_REF_NAME": "12/merge",
        "GITHUB_HEAD_REF": "feature-x",
        "GITHUB_SHA": "abc123",
    }
    info = detect(tmp_path, env=env)
    assert (info.repo, info.branch, info.commit) == ("chafiq753/demo", "feature-x", "abc123")


@pytest.mark.skipif(not shutil.which("git"), reason="git non installé")
def test_git_context_from_local_repo(tmp_path: Path) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    git("remote", "add", "origin", "https://tok@github.com/someone/infra.git")
    (tmp_path / "a.tf").write_text("# vide\n", encoding="utf-8")
    git("add", ".")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init")

    info = detect(tmp_path, env={})
    assert info.repo == "someone/infra"
    assert info.branch == "main"
    assert info.commit and len(info.commit) == 40


# --------------------------------------------------------------------------- #
# Intégration : vrai Checkov sur le Terraform de démo
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@pytest.mark.skipif(not shutil.which("checkov"), reason="checkov non installé")
def test_cli_blocks_demo_terraform(tmp_path: Path) -> None:
    shutil.copy(DEMO_TF, tmp_path / "main.tf")
    out = tmp_path / "r.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "-t", "checkov", "-f", "json", "-o", str(out)])
    assert result.exit_code == EXIT_BLOCKED, result.output
    report = ScanReport.model_validate_json(out.read_text(encoding="utf-8"))
    # Chemins relatifs au dossier scanné, comme dans l'ancien pipeline CI.
    assert {f.file for f in report.findings} == {"/main.tf"}
    assert report.summary.by_severity[Severity.CRITICAL] >= 1


# --------------------------------------------------------------------------- #
# GitHub Actions : annotations, résumé, outputs
# --------------------------------------------------------------------------- #


def test_github_annotations_and_summary(fake_tools, tmp_path: Path, monkeypatch) -> None:
    fake_tools(checkov=[
        Finding(source=ToolName.CHECKOV, category=Category.MISCONFIGURATION, rule_id="CKV_AWS_20",
                title="Bucket public, risque: fuite", severity=Severity.HIGH,
                resource="aws_s3_bucket.data", file="/infra/main.tf", line_start=28, line_end=31),
        _finding(ToolName.CHECKOV, Severity.LOW, rule="CKV_AWS_21"),
    ])
    summary, outputs = tmp_path / "summary.md", tmp_path / "out.txt"
    for k, v in {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(tmp_path),
                 "GITHUB_REPOSITORY": "o/r", "GITHUB_SHA": "abc",
                 "GITHUB_STEP_SUMMARY": str(summary), "GITHUB_OUTPUT": str(outputs)}.items():
        monkeypatch.setenv(k, v)

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == EXIT_BLOCKED, result.output
    lines = [l for l in result.stdout.splitlines() if l.startswith("::")]
    # le high bloque -> error, sur la bonne ligne, chemin relatif au dépôt
    assert lines[0].startswith("::error file=infra/main.tf,")
    assert "line=28,endLine=31" in lines[0]
    assert "risque%3A" not in lines[0].split("::")[2]     # ':' échappé seulement dans les propriétés
    assert lines[1].startswith("::notice ")                # low -> simple note
    md = summary.read_text(encoding="utf-8")
    assert "BLOQUÉ" in md and "](https://github.com/o/r/blob/abc/infra/main.tf#L28-L31)" in md
    assert "blocked=true" in outputs.read_text(encoding="utf-8")


def test_no_annotations_outside_github(fake_tools, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    fake_tools(checkov=[_finding(ToolName.CHECKOV, Severity.HIGH)])
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert "::error" not in result.stdout


# --------------------------------------------------------------------------- #
# --details : code affiché, secrets jamais
# --------------------------------------------------------------------------- #


def test_details_shows_code_but_never_secrets(fake_tools, tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'
        'provider "aws" {\n  access_key = "AKIA_FAUX_POUR_TEST"\n}\n',
        encoding="utf-8",
    )
    fake_tools(
        checkov=[
            Finding(source=ToolName.CHECKOV, category=Category.MISCONFIGURATION, rule_id="CKV_AWS_20",
                    title="Bucket public", severity=Severity.HIGH, file="/main.tf", line_start=1, line_end=3),
            Finding(source=ToolName.CHECKOV, category=Category.MISCONFIGURATION, rule_id="CKV_AWS_41",
                    title="Clé en dur", severity=Severity.HIGH, file="/main.tf", line_start=4, line_end=6),
        ],
        gitleaks=[Finding(source=ToolName.GITLEAKS, category=Category.SECRET, rule_id="aws-access-token",
                          title="Clé AWS", severity=Severity.CRITICAL, file="main.tf", line_start=5)],
    )
    result = runner.invoke(app, ["scan", str(tmp_path), "--details"])
    assert 'acl = "public-read"' in result.stdout
    assert "AKIA_FAUX_POUR_TEST" not in result.stdout
    assert "masqué" in result.stdout
