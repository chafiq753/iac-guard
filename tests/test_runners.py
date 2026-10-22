"""Runners : lancement des vrais scanners.

Les tests d'intégration sont sautés si le scanner n'est pas installé : ils
tournent en CI et dans l'image Docker, pas forcément sur un poste de dev.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import string
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import DEMO_TF
from iacguard.core import report_from_files, scan
from iacguard.runners import run_checkov, run_gitleaks, run_semgrep
from iacguard.schema import Category, ToolName

needs_gitleaks = pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks non installé")
needs_checkov = pytest.mark.skipif(not shutil.which("checkov"), reason="checkov non installé")
needs_semgrep = pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep non installé")
needs_git = pytest.mark.skipif(not shutil.which("git"), reason="git non installé")


def _fake_github_token() -> str:
    """Token au format GitHub (ghp_ + 36 car.), généré à l'exécution.

    Il n'est jamais écrit dans ce fichier : sinon Gitleaks le trouverait
    dans le repo iac-guard lui-même.
    """
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"},
    )


# --------------------------------------------------------------------------- #
# Scanner absent / défaillant
# --------------------------------------------------------------------------- #


def test_missing_binary_is_reported_not_raised(tmp_path: Path) -> None:
    for runner in (run_gitleaks, run_checkov, run_semgrep):
        run = runner(tmp_path, binary="scanner-qui-n-existe-pas")
        assert run.status == "missing"
        assert "introuvable" in (run.message or "")
        assert run.findings == []


@pytest.mark.skipif(sys.platform == "win32", reason="script shell factice")
def test_garbage_output_is_an_error(tmp_path: Path) -> None:
    fake = tmp_path / "fake-checkov"
    fake.write_text("#!/bin/sh\necho 'ceci nest pas du json'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    run = run_checkov(tmp_path, binary=str(fake))
    assert run.status == "error"
    assert "non JSON" in (run.message or "")


# --------------------------------------------------------------------------- #
# Intégration avec les vrais scanners
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@needs_gitleaks
@needs_git
def test_gitleaks_finds_secret_in_git_history(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    leaked = repo / "deploy.sh"
    leaked.write_text(f'export GITHUB_TOKEN="{_fake_github_token()}"\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "oops")
    # Le secret est supprimé du code... mais il reste dans l'historique.
    leaked.unlink()
    _git(repo, "commit", "-q", "-am", "retire le token")

    run = run_gitleaks(repo)
    assert run.status == "ok", run.message
    assert len(run.findings) == 1
    finding = run.findings[0]
    assert finding.category is Category.SECRET
    assert finding.file == "deploy.sh"
    assert "ghp_" not in str(finding.raw.get("Secret", ""))  # --redact


@pytest.mark.integration
@needs_gitleaks
def test_gitleaks_without_git_scans_files(tmp_path: Path) -> None:
    (tmp_path / "config.env").write_text(f"TOKEN={_fake_github_token()}\n")
    run = run_gitleaks(tmp_path)
    assert run.status == "ok", run.message
    assert len(run.findings) == 1


@pytest.mark.integration
@needs_checkov
def test_checkov_on_demo_terraform(tmp_path: Path) -> None:
    shutil.copy(DEMO_TF, tmp_path / "main.tf")
    run = run_checkov(tmp_path)
    assert run.status == "ok", run.message
    assert run.version
    rule_ids = {f.rule_id for f in run.findings}
    assert "CKV_AWS_20" in rule_ids        # bucket S3 public en lecture
    assert all(f.file and f.file.endswith("main.tf") for f in run.findings)


@pytest.mark.integration
@needs_checkov
def test_checkov_on_empty_folder(tmp_path: Path) -> None:
    run = run_checkov(tmp_path)
    assert run.status == "ok", run.message
    assert run.findings == []


@pytest.mark.integration
@needs_semgrep
def test_semgrep_with_local_rules(tmp_path: Path) -> None:
    # Règle locale : pas besoin du registre Semgrep (ni du réseau).
    rules = tmp_path / "rules.yml"
    rules.write_text(
        "rules:\n"
        "  - id: no-eval\n"
        "    languages: [python]\n"
        "    severity: ERROR\n"
        "    message: eval() sur une entrée utilisateur\n"
        "    pattern: eval(...)\n"
    )
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("x = input()\neval(x)\n")

    run = run_semgrep(src, config=str(rules))
    assert run.status == "ok", run.message
    assert [f.rule_id.split(".")[-1] for f in run.findings] == ["no-eval"]
    assert run.findings[0].line_start == 2


# --------------------------------------------------------------------------- #
# Scan complet
# --------------------------------------------------------------------------- #


@pytest.mark.integration
@needs_gitleaks
@needs_checkov
def test_full_scan_blocks_vulnerable_terraform(tmp_path: Path) -> None:
    shutil.copy(DEMO_TF, tmp_path / "main.tf")
    (tmp_path / "secrets.tf").write_text(f'token = "{_fake_github_token()}"\n')

    result = scan(
        tmp_path,
        tools=[ToolName.GITLEAKS, ToolName.CHECKOV],
        fail_on="critical",
    )
    assert not result.failed_tools, [r.message for r in result.failed_tools]
    assert result.decision.blocked is True          # le secret est critical
    assert result.decision.score.grade == "F"
    sources = {f.source for f in result.report.findings}
    assert sources == {ToolName.GITLEAKS, ToolName.CHECKOV}


def test_scan_rejects_missing_folder(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        scan(tmp_path / "absent")


def test_report_from_files_matches_old_aggregator(tmp_path: Path) -> None:
    from conftest import SAMPLES

    report = report_from_files(
        {
            ToolName.GITLEAKS: SAMPLES / "gitleaks.json",
            ToolName.CHECKOV: SAMPLES / "checkov.json",
            ToolName.CONFTEST: SAMPLES / "conftest.json",
            ToolName.SEMGREP: tmp_path / "absent.json",   # ignoré
        },
        repo="acme/infra",
    )
    assert report.summary.total == 2 + 3 + 3
    assert {t.name for t in report.scan.tools} == {
        ToolName.GITLEAKS, ToolName.CHECKOV, ToolName.CONFTEST,
    }
