"""Point d'entrée du cœur : lancer un scan complet et construire le rapport.

    from iacguard.core import scan
    result = scan(Path("."))
    print(result.report.summary.total, result.decision.score.grade)

`report_from_files()` fait la même chose à partir de JSON déjà produits par
les scanners : c'est le mode de l'ancien aggregator du pipeline.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from iacguard.config import IgnoreEntry, path_matches
from iacguard.parsers import PARSERS
from iacguard.runners import DEFAULT_TOOLS, RUNNERS, ToolRun
from iacguard.schema import Finding, ScanMeta, ScanReport, ToolInfo, ToolName
from iacguard.scoring import Decision, evaluate


@dataclass
class ScanResult:
    report: ScanReport
    runs: list[ToolRun]
    decision: Decision
    # fingerprint -> justification, pour les findings couverts par un ignore
    ignored: dict[str, str] = field(default_factory=dict)
    excluded_count: int = 0                     # findings dans un chemin exclu
    expired_ignores: list[IgnoreEntry] = field(default_factory=list)

    @property
    def failed_tools(self) -> list[ToolRun]:
        """Scanners qui n'ont pas pu tourner (absents ou en erreur)."""
        return [r for r in self.runs if not r.ok]


def _meta(repo: str, branch: str | None, commit: str | None, tools: list[ToolInfo]) -> ScanMeta:
    return ScanMeta(
        repo=repo,
        branch=branch,
        commit_sha=commit,
        created_at=datetime.now(timezone.utc),
        tools=tools,
    )


def scan(
    path: Path,
    tools: Iterable[ToolName] = DEFAULT_TOOLS,
    *,
    repo: str | None = None,
    branch: str | None = None,
    commit: str | None = None,
    fail_on: str | None = None,
    ignored_rules: Iterable[str] = (),
    semgrep_config: str = "auto",
    exclude: Iterable[str] = (),
    ignores: Iterable[IgnoreEntry] = (),
    gitleaks_since: str | None = None,
    on_start: Callable[[ToolName], None] | None = None,
    on_done: Callable[[ToolRun], None] | None = None,
) -> ScanResult:
    """Lance les scanners demandés sur `path` et renvoie rapport + décision.

    `on_start` / `on_done` : appelés avant et après chaque scanner, pour que
    la CLI affiche la progression (le cœur, lui, n'affiche rien).
    """
    path = Path(path).resolve()
    if not path.is_dir():
        raise NotADirectoryError(f"Dossier introuvable : {path}")

    runs: list[ToolRun] = []
    for tool in tools:
        runner = RUNNERS.get(tool)
        if runner is None:
            raise ValueError(f"Aucun runner pour l'outil {tool.value!r}.")
        if on_start:
            on_start(tool)
        if tool is ToolName.SEMGREP:
            run = runner(path, config=semgrep_config)
        elif tool is ToolName.GITLEAKS and gitleaks_since:
            run = runner(path, since=gitleaks_since)
        else:
            run = runner(path)
        runs.append(run)
        if on_done:
            on_done(run)

    findings: list[Finding] = [f for run in runs for f in run.findings]
    for f in findings:
        # Sous Windows certains scanners renvoient infra\\main.tf : on garde
        # le format de la CI (Linux), sinon le fingerprint change selon l'OS.
        if f.file and "\\" in f.file:
            f.file = f.file.replace("\\", "/")
    # Chemins exclus (.iacguard.yml) : hors du rapport.
    patterns = list(exclude)
    kept = [f for f in findings if not any(path_matches(f.file, p) for p in patterns)]
    excluded_count = len(findings) - len(kept)
    findings = kept

    # Risques acceptés : restent dans le rapport, ne comptent plus.
    active = [i for i in ignores if not i.expired()]
    expired = [i for i in ignores if i.expired()]
    ignored: dict[str, str] = {}
    for f in findings:
        entry = next((i for i in active if i.matches(f)), None)
        if entry:
            ignored[f.fingerprint] = entry.reason

    tool_infos = [ToolInfo(name=run.tool, version=run.version) for run in runs if run.ok]
    report = ScanReport.build(_meta(repo or path.name, branch, commit, tool_infos), findings)
    decision = evaluate(findings, fail_on=fail_on, ignored_rules=ignored_rules,
                        ignored_fingerprints=ignored)
    return ScanResult(report=report, runs=runs, decision=decision, ignored=ignored,
                      excluded_count=excluded_count, expired_ignores=expired)


def report_from_files(
    files: dict[ToolName, Path | str | None],
    *,
    repo: str,
    branch: str | None = None,
    commit: str | None = None,
) -> ScanReport:
    """Construit un rapport à partir de sorties JSON déjà sur disque.

    Un chemin absent ou un fichier vide est ignoré (l'outil n'a pas tourné).
    """
    findings: list[Finding] = []
    tool_infos: list[ToolInfo] = []
    for tool, file in files.items():
        if not file:
            continue
        p = Path(file)
        if not p.exists() or p.stat().st_size == 0:
            continue
        with p.open(encoding="utf-8") as fh:
            data = json.load(fh)
        findings += PARSERS[tool](data)
        version = None
        if tool is ToolName.CHECKOV and isinstance(data, dict):
            version = (data.get("summary") or {}).get("checkov_version")
        elif tool is ToolName.SEMGREP and isinstance(data, dict):
            version = data.get("version")
        tool_infos.append(ToolInfo(name=tool, version=version))
    return ScanReport.build(_meta(repo, branch, commit, tool_infos), findings)
