"""Intégration GitHub Actions, sans API ni token.

Deux mécanismes natifs de GitHub, activés quand GITHUB_ACTIONS=true :

1. Annotations : une ligne `::error file=...,line=...::message` sur stdout.
   GitHub affiche alors le problème DIRECTEMENT sur la ligne concernée,
   dans l'onglet « Files changed » de la pull request.
   Limite GitHub : 10 erreurs + 10 avertissements affichés par étape. Les
   plus graves passent en premier ; le rapport complet viendra avec SARIF.

2. Résumé du job : du Markdown écrit dans le fichier $GITHUB_STEP_SUMMARY,
   affiché sur la page du run (score, verdict, tableau des findings).

Le blocage du merge, lui, vient du code de sortie (1) : le job échoue, et
une règle de protection de branche exige que ce job passe.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from iacguard.schema import Finding
from iacguard.scoring import SEVERITY_ORDER

MAX_ANNOTATIONS = 50       # GitHub n'en garde pas plus par job
MAX_SUMMARY_ROWS = 100


def in_github_actions(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return env.get("GITHUB_ACTIONS") == "true"


def _escape_data(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_prop(s: str) -> str:
    return _escape_data(s).replace(":", "%3A").replace(",", "%2C")


def repo_path(f: Finding, root: Path, workspace: Path | None) -> str | None:
    """Chemin du fichier relatif à la racine du dépôt (ce qu'attend GitHub)."""
    if not f.file:
        return None
    absolute = (root / f.file.lstrip("/")).resolve()
    base = workspace.resolve() if workspace else root.resolve()
    try:
        return absolute.relative_to(base).as_posix()
    except ValueError:
        return f.file.lstrip("/")


def _level(severity: str, fail_on: str | None) -> str:
    """error si le finding bloque, warning pour le reste du medium+, notice sinon."""
    rank = SEVERITY_ORDER.index(severity)
    if fail_on and rank >= SEVERITY_ORDER.index(fail_on):
        return "error"
    return "warning" if rank >= SEVERITY_ORDER.index("medium") else "notice"


def annotations(findings: list[Finding], root: Path, fail_on: str | None,
                env: Mapping[str, str] | None = None) -> list[str]:
    """Lignes de commandes d'annotation, du plus grave au moins grave."""
    env = os.environ if env is None else env
    ws = env.get("GITHUB_WORKSPACE")
    workspace = Path(ws) if ws else None
    lines: list[str] = []
    for f in findings[:MAX_ANNOTATIONS]:
        props = [f"title={_escape_prop(f'[{f.severity.value.upper()}] {f.rule_id}')}"]
        path = repo_path(f, root, workspace)
        if path:
            props.insert(0, f"file={_escape_prop(path)}")
            if f.line_start:
                props.append(f"line={f.line_start}")
                if f.line_end and f.line_end >= f.line_start:
                    props.append(f"endLine={f.line_end}")
        message = f.title
        if f.resource:
            message += f"\nResource: {f.resource}"
        if f.remediation:
            message += f"\nFix: {f.remediation}"
        message += f"\n(found by {f.source.value})"
        lines.append(f"::{_level(f.severity.value, fail_on)} {','.join(props)}::{_escape_data(message)}")
    return lines


def step_summary(findings: list[Finding], root: Path, score: int, grade: str,
                 verdict: str, env: Mapping[str, str] | None = None) -> str:
    """Résumé Markdown du scan, avec liens vers les lignes concernées."""
    env = os.environ if env is None else env
    ws = env.get("GITHUB_WORKSPACE")
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    repo = env.get("GITHUB_REPOSITORY")
    sha = env.get("GITHUB_SHA")

    out = ["## iac-guard", "", f"**Score: {score}/100 (grade {grade})** — {verdict}", ""]
    if not findings:
        out.append("No issues found.")
        return "\n".join(out) + "\n"

    out += ["| Severity | Tool | Rule | Location | Issue |", "|---|---|---|---|---|"]
    for f in findings[:MAX_SUMMARY_ROWS]:
        path = repo_path(f, root, Path(ws) if ws else None)
        loc = "-"
        if path:
            loc = f"{path}:{f.line_start}" if f.line_start else path
            # Secret trouvé dans un ancien commit : lien vers CE commit, le
            # fichier n'existe peut-être plus dans la version actuelle.
            ref = (f.raw.get("Commit") if f.source.value == "gitleaks" else None) or sha
            if repo and ref:
                anchor = f"#L{f.line_start}" if f.line_start else ""
                if f.line_end and f.line_start and f.line_end > f.line_start:
                    anchor += f"-L{f.line_end}"
                loc = f"[{loc}]({server}/{repo}/blob/{ref}/{path}{anchor})"
        title = f.title.replace("|", "\\|").replace("\n", " ")
        out.append(f"| {f.severity.value.upper()} | {f.source.value} | `{f.rule_id}` | {loc} | {title} |")
    if len(findings) > MAX_SUMMARY_ROWS:
        out.append(f"\n… and {len(findings) - MAX_SUMMARY_ROWS} more (see the JSON report).")
    return "\n".join(out) + "\n"
