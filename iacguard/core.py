"""Point d'entrée du cœur : lancer un scan complet et construire le rapport.

    from iacguard.core import scan
    result = scan(Path("."))
    print(result.report.summary.total, result.decision.score.grade)

`report_from_files()` fait la même chose à partir de JSON déjà produits par
les scanners : c'est le mode de l'ancien aggregator du pipeline.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from iacguard.parsers import PARSERS
from iacguard.runners import DEFAULT_TOOLS, RUNNERS, ToolRun
from iacguard.schema import Finding, ScanMeta, ScanReport, ToolInfo, ToolName
from iacguard.scoring import Decision, evaluate


@dataclass
class ScanResult:
    report: ScanReport
    runs: list[ToolRun]
    decision: Decision

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
) -> ScanResult:
    """Lance les scanners demandés sur `path` et renvoie rapport + décision."""
    path = Path(path).resolve()
    if not path.is_dir():
        raise NotADirectoryError(f"Dossier introuvable : {path}")

    runs: list[ToolRun] = []
    for tool in tools:
        runner = RUNNERS.get(tool)
        if runner is None:
            raise ValueError(f"Aucun runner pour l'outil {tool.value!r}.")
        if tool is ToolName.SEMGREP:
            runs.append(runner(path, config=semgrep_config))
        else:
            runs.append(runner(path))

    findings: list[Finding] = [f for run in runs for f in run.findings]
    tool_infos = [ToolInfo(name=run.tool, version=run.version) for run in runs if run.ok]
    report = ScanReport.build(_meta(repo or path.name, branch, commit, tool_infos), findings)
    decision = evaluate(findings, fail_on=fail_on, ignored_rules=ignored_rules)
    return ScanResult(report=report, runs=runs, decision=decision)


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
