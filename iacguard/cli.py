"""Ligne de commande iac-guard.

    iacguard scan .                      # scan complet, tableau dans le terminal
    iacguard scan infra/ --fail-on critical
    iacguard scan . -f json -o rapport.json
    iacguard doctor                      # quels scanners sont installés ?

Codes de sortie (c'est ce que lit la CI pour bloquer une pull request) :

    0  le scan est passé
    1  bloqué : au moins un finding atteint le seuil --fail-on
    2  le scan n'a pas pu se faire correctement (aucun scanner n'a tourné,
       scanner manquant avec --strict, mauvaise option...)

Si un finding bloque ET qu'un scanner manque, on renvoie 1 : le problème
trouvé est réel, quel que soit le scanner absent.

Tout ce qui est progression, avertissement et verdict part sur stderr, pour
que `-f json` donne sur stdout un JSON propre qu'on peut rediriger.
"""

from __future__ import annotations

import os
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.style import Style
from rich.table import Table
from rich.text import Text

from iacguard import __version__
from iacguard.core import ScanResult, scan as run_scan
from iacguard import github
from iacguard.gitinfo import detect as detect_git
from iacguard.runners import DEFAULT_TOOLS, RUNNERS, ToolRun, _resolve, _version
from iacguard.schema import Finding, ToolName
from iacguard.severity import SECRET_PREFIX
from iacguard.scoring import SEVERITY_ORDER

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

TOOL_LABEL = {
    ToolName.GITLEAKS: "Gitleaks",
    ToolName.CHECKOV: "Checkov",
    ToolName.SEMGREP: "Semgrep",
    ToolName.CONFTEST: "Conftest",
}

# Comment installer chaque scanner (affiché par `doctor`).
INSTALL_HINT = {
    ToolName.GITLEAKS: "binaire à télécharger : https://github.com/gitleaks/gitleaks/releases",
    ToolName.CHECKOV: "pip install checkov",
    ToolName.SEMGREP: "pip install semgrep",
}

VERSION_ARGS = {
    ToolName.GITLEAKS: ["version"],
    ToolName.CHECKOV: ["--version"],
    ToolName.SEMGREP: ["--version"],
}


class OutputFormat(str, Enum):
    table = "table"
    json = "json"


class FailOn(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    none = "none"


app = typer.Typer(
    name="iacguard",
    help="Scanner de sécurité pour Infrastructure as Code : secrets (Gitleaks), "
    "mauvaises configurations (Checkov) et vulnérabilités du code (Semgrep), "
    "dans un seul rapport avec un score et un verdict.",
    no_args_is_help=True,
    add_completion=False,
)


# --------------------------------------------------------------------------- #
# Helpers d'affichage
# --------------------------------------------------------------------------- #


def _safe_streams() -> None:
    """Sous Windows, une sortie redirigée est en cp1252 : un caractère qui
    n'y existe pas ferait planter l'affichage. On le remplace par « ? »."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


def _parse_tools(value: str) -> list[ToolName]:
    names = [v.strip().lower() for v in value.split(",") if v.strip()]
    allowed = {t.value: t for t in RUNNERS}
    unknown = [n for n in names if n not in allowed]
    if unknown or not names:
        raise typer.BadParameter(
            f"outil inconnu : {', '.join(unknown) or '(vide)'}. "
            f"Choix possibles : {', '.join(allowed)}.",
            param_hint="--tools",
        )
    # Ordre fixe (celui de DEFAULT_TOOLS), sans doublon.
    return [t for t in DEFAULT_TOOLS if t.value in names]


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' if n > 1 else ''}"


def _abs_file(f: Finding, root: Path) -> Path | None:
    if not f.file:
        return None
    return (root / f.file.lstrip("/")).resolve()   # Checkov écrit /main.tf


def _display_path(p: Path) -> str:
    """Chemin relatif au dossier courant : VS Code le rend cliquable
    (Ctrl+clic ouvre le fichier à la bonne ligne)."""
    try:
        return p.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return str(p)


def _commit(f: Finding) -> str | None:
    """Secret trouvé dans l'historique Git : le commit où il apparaît."""
    if f.source is ToolName.GITLEAKS:
        commit = f.raw.get("Commit")
        return str(commit)[:7] if commit else None
    return None


def _location(f: Finding, root: Path) -> Text:
    absolute = _abs_file(f, root)
    if absolute is None:
        return Text(f.resource or "-")
    loc = _display_path(absolute)
    if f.line_start:
        loc += f":{f.line_start}"
    # Lien OSC 8 : cliquable dans Windows Terminal et VS Code.
    text = Text(loc, style=Style(link=absolute.as_uri(), underline=True))
    extra = []
    if f.line_end and f.line_start and f.line_end > f.line_start:
        extra.append(f"lignes {f.line_start}-{f.line_end}")
    if f.resource:
        extra.append(f.resource)
    if commit := _commit(f):
        extra.append(f"commit {commit}")
    if extra:
        text.append("\n" + " · ".join(extra), style="dim")
    return text


# Règles Checkov qui portent sur un secret en dur : leur bloc de code
# contient le secret, on ne l'affiche pas.
_SECRET_RULES = {"CKV_AWS_41", "CKV_AWS_45", "CKV_AWS_46", "CKV_AZURE_41", "CKV_GCP_1"}


def _is_secret(f: Finding) -> bool:
    return (f.source is ToolName.GITLEAKS or f.rule_id in _SECRET_RULES
            or f.rule_id.startswith(SECRET_PREFIX))


def _secret_lines(findings: list[Finding], root: Path) -> set[tuple[Path, int]]:
    """(fichier, ligne) où Gitleaks a trouvé un secret : masquées partout."""
    out: set[tuple[Path, int]] = set()
    for f in findings:
        if f.source is ToolName.GITLEAKS and f.line_start and (a := _abs_file(f, root)):
            for n in range(f.line_start, (f.line_end or f.line_start) + 1):
                out.add((a, n))
    return out


def _snippet(f: Finding, root: Path, context: int = 0, max_lines: int = 8) -> list[tuple[int, str]]:
    """Lignes de code concernées. Jamais pour un secret : on afficherait le secret."""
    if _is_secret(f) or not f.line_start:
        return []
    absolute = _abs_file(f, root)
    if absolute is None or not absolute.is_file():
        return []
    try:
        lines = absolute.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    start = max(1, f.line_start - context)
    end = min(len(lines), (f.line_end or f.line_start) + context, start + max_lines - 1)
    return [(n, lines[n - 1]) for n in range(start, end + 1)]


def _render_details(console: Console, findings: list[Finding], root: Path) -> None:
    console.print(Text("Détails", style="bold"))
    hidden = _secret_lines(findings, root)
    for i, f in enumerate(findings, 1):
        console.print()
        console.print(Text.assemble(
            (f"{i}. ", "bold"),
            (f" {f.severity.value.upper()} ", SEVERITY_STYLE[f.severity.value]),
            f"  {f.title}",
        ))
        loc = _location(f, root)
        first, *rest = loc.split("\n")
        console.print(Text.assemble("   Où      : ", first))
        for extra in rest:
            console.print(Text.assemble("             ", extra))
        console.print(f"   Règle   : {f.rule_id} ({f.source.value})", highlight=False)
        if f.remediation:
            console.print(f"   Corriger: {f.remediation}", highlight=False)
        if _is_secret(f):
            console.print(Text("   Code    : masqué (contient un secret)", style="dim"))
            continue
        absolute = _abs_file(f, root)
        for n, line in _snippet(f, root):
            shown = "*** masqué (secret) ***" if (absolute, n) in hidden else line.rstrip()
            console.print(Text(f"   {n:>5} | {shown}", style="dim"))


def _sorted(findings: list[Finding]) -> list[Finding]:
    rank = {sev: i for i, sev in enumerate(reversed(SEVERITY_ORDER))}  # critical = 0
    return sorted(
        findings,
        key=lambda f: (rank[f.severity.value], f.source.value, f.file or "", f.line_start or 0),
    )


def _tool_line(run: ToolRun) -> Text:
    label = TOOL_LABEL[run.tool].ljust(9)
    if run.ok:
        version = f" {run.version}" if run.version else ""
        return Text.assemble(
            "  ", ("OK     ", "green"), label, (version, "dim"),
            f"  {_plural(len(run.findings), 'finding')}",
        )
    status = "ABSENT " if run.status == "missing" else "ERREUR "
    # Le message peut finir par la sortie d'erreur du scanner (traceback...) :
    # on montre la phrase d'explication et la dernière ligne, pas tout.
    lines = [line.strip() for line in (run.message or "").splitlines() if line.strip()]
    text = Text.assemble("  ", (status, "bold yellow"), label, f" {lines[0] if lines else ''}")
    if len(lines) > 1:
        text.append(f"\n{' ' * 18}{lines[-1]}", style="dim")
    return text


def _counts_line(result: ScanResult) -> Text:
    by_sev = result.decision.score.by_severity
    text = Text(f"{_plural(result.report.summary.total, 'finding')}  (")
    parts = [sev for sev in reversed(SEVERITY_ORDER)]
    for i, sev in enumerate(parts):
        n = by_sev.get(sev, 0)
        text.append(f"{sev} {n}", style=SEVERITY_STYLE[sev] if n else "dim")
        if i < len(parts) - 1:
            text.append(" · ")
    text.append(")")
    if result.decision.ignored_count:
        text.append(f"  dont {result.decision.ignored_count} ignoré(s)", style="dim")
    return text


def _verdict(result: ScanResult, fail_on: FailOn) -> Text:
    score = result.decision.score
    text = Text.assemble(
        "Score : ", (f"{score.score}/100", "bold"), f" (note {score.grade})   Verdict : ",
    )
    if result.decision.blocked:
        text.append("BLOQUÉ", style="bold white on red")
        text.append(f"  au moins un finding de gravité '{fail_on.value}' ou pire")
    elif fail_on is FailOn.none:
        text.append("RAPPORT SEULEMENT", style="bold")
        text.append("  (--fail-on none : ne bloque jamais)")
    else:
        text.append("PASSÉ", style="bold green")
        text.append(f"  aucun finding de gravité '{fail_on.value}' ou pire")
    return text


def _render_table(console: Console, result: ScanResult, path: Path, fail_on: FailOn,
                  details: bool = False) -> None:
    meta = result.report.scan
    console.print(Text(f"iac-guard {__version__}  -  scan de {path}", style="bold"))
    ctx = [f"Dépôt : {meta.repo}"]
    if meta.branch:
        ctx.append(f"Branche : {meta.branch}")
    if meta.commit_sha:
        ctx.append(f"Commit : {meta.commit_sha[:7]}")
    console.print(Text("   ".join(ctx), style="dim"))
    console.print()

    findings = _sorted(result.report.findings)
    if findings:
        table = Table(show_lines=False, header_style="bold", expand=False)
        table.add_column("Gravité", no_wrap=True)
        table.add_column("Outil", no_wrap=True)
        table.add_column("Règle", overflow="fold")
        table.add_column("Emplacement", overflow="fold")
        table.add_column("Problème")
        for f in findings:
            table.add_row(
                Text(f.severity.value.upper(), style=SEVERITY_STYLE[f.severity.value]),
                f.source.value,
                f.rule_id,
                _location(f, path),
                f.title,
            )
        console.print(table)
        if details:
            console.print()
            _render_details(console, findings, path)
    else:
        console.print(Text("Aucun problème détecté.", style="green"))
    console.print()
    console.print(_counts_line(result))
    console.print(_verdict(result, fail_on))


def _write_output(result: ScanResult, fmt: OutputFormat, path: Path, fail_on: FailOn,
                  output: Path | None, details: bool = False) -> None:
    if fmt is OutputFormat.json:
        content = result.report.model_dump_json(indent=2)
        if output:
            output.write_text(content + "\n", encoding="utf-8")
        else:
            sys.stdout.write(content + "\n")
        return

    if output:
        with output.open("w", encoding="utf-8") as fh:
            _render_table(Console(file=fh, width=160, no_color=True, emoji=False), result, path, fail_on, details)
    else:
        _render_table(Console(emoji=False, highlight=False), result, path, fail_on, details)


# --------------------------------------------------------------------------- #
# Commandes
# --------------------------------------------------------------------------- #


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"iacguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", "-V", help="Affiche la version et quitte.",
                     callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    _safe_streams()


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(help="Dossier à scanner.", exists=True, file_okay=False,
                       dir_okay=True, resolve_path=True),
    ] = Path("."),
    fail_on: Annotated[
        FailOn,
        typer.Option("--fail-on", case_sensitive=False,
                     help="Gravité à partir de laquelle le scan échoue (code 1). "
                     "'high' bloque sur high ET critical. 'none' : ne bloque jamais."),
    ] = FailOn.high,
    fmt: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="Format du rapport."),
    ] = OutputFormat.table,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", dir_okay=False, writable=True,
                     help="Écrit le rapport dans ce fichier (UTF-8) au lieu du terminal."),
    ] = None,
    tools: Annotated[
        str,
        typer.Option("--tools", "-t",
                     help="Scanners à lancer, séparés par des virgules."),
    ] = ",".join(t.value for t in DEFAULT_TOOLS),
    strict: Annotated[
        bool,
        typer.Option("--strict",
                     help="Échoue (code 2) si un scanner n'a pas pu tourner. "
                     "Recommandé en CI : sinon un scanner absent passe inaperçu."),
    ] = False,
    details: Annotated[
        bool,
        typer.Option("--details", "-d",
                     help="Après le tableau : pour chaque problème, la ressource, "
                     "la correction et les lignes de code concernées."),
    ] = False,
    semgrep_config: Annotated[
        str,
        typer.Option("--semgrep-config",
                     help="Règles Semgrep : 'auto' (registre en ligne) ou un fichier local."),
    ] = "auto",
) -> None:
    """Scanne un dossier et affiche les problèmes trouvés, le score et le verdict."""
    selected = _parse_tools(tools)
    err = Console(stderr=True, emoji=False, highlight=False)
    git = detect_git(path)

    def on_start(tool: ToolName) -> None:
        if err.is_terminal:
            status.update(f"{TOOL_LABEL[tool]} en cours...")

    def on_done(run: ToolRun) -> None:
        err.print(_tool_line(run))

    err.print(Text(f"Scanners ({', '.join(t.value for t in selected)}) :", style="bold"))
    with err.status("Démarrage...", spinner="dots") as status:
        result = run_scan(
            path,
            selected,
            repo=git.repo,
            branch=git.branch,
            commit=git.commit,
            fail_on=None if fail_on is FailOn.none else fail_on.value,
            semgrep_config=semgrep_config,
            on_start=on_start,
            on_done=on_done,
        )
    err.print()

    failed = result.failed_tools
    if len(failed) == len(result.runs):
        err.print(Text("Aucun scanner n'a pu tourner : rien n'a été vérifié. "
                       "Lance `iacguard doctor` pour voir ce qui manque.", style="bold red"))
        raise typer.Exit(EXIT_ERROR)

    _write_output(result, fmt, path, fail_on, output, details)
    _github_report(result, path, fail_on)

    # Le verdict reste visible dans le terminal quand le rapport part ailleurs.
    if fmt is OutputFormat.json or output:
        err.print(_counts_line(result))
        err.print(_verdict(result, fail_on))
    if output:
        err.print(Text(f"Rapport écrit dans {output}", style="dim"))

    if failed:
        names = " et ".join(TOOL_LABEL[r.tool] for r in failed)
        verb = "n'ont pas tourné" if len(failed) > 1 else "n'a pas tourné"
        hint = "" if strict else " Ajoute --strict pour faire échouer le scan dans ce cas."
        err.print(Text(f"Attention : scan partiel, {names} {verb}.{hint}",
                       style="bold yellow"))

    if result.decision.blocked:
        raise typer.Exit(EXIT_BLOCKED)
    if failed and strict:
        raise typer.Exit(EXIT_ERROR)
    raise typer.Exit(EXIT_OK)


def _github_report(result: ScanResult, path: Path, fail_on: FailOn) -> None:
    """Dans GitHub Actions : annotations sur les lignes de la PR + résumé du job."""
    if not github.in_github_actions():
        return
    findings = _sorted(result.report.findings)
    threshold = None if fail_on is FailOn.none else fail_on.value
    # Les annotations doivent sortir sur stdout pour que GitHub les lise. En
    # JSON sur stdout, on les envoie quand même : le runner les retire du log.
    for line in github.annotations(findings, path, threshold):
        sys.stdout.write(line + "\n")
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        d = result.decision
        verdict = ("BLOQUÉ" if d.blocked else
                   "rapport seulement" if threshold is None else "passé")
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(github.step_summary(findings, path, d.score.score, d.score.grade, verdict))
    # Pour les étapes suivantes du workflow (et la future GitHub Action).
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(f"score={result.decision.score.score}\n")
            fh.write(f"grade={result.decision.score.grade}\n")
            fh.write(f"blocked={'true' if result.decision.blocked else 'false'}\n")
            fh.write(f"findings={result.report.summary.total}\n")


@app.command()
def doctor() -> None:
    """Vérifie que les scanners sont installés (code 1 s'il en manque un)."""
    console = Console(emoji=False, highlight=False)
    missing = 0
    for tool in DEFAULT_TOOLS:
        exe = _resolve(tool.value)
        label = TOOL_LABEL[tool].ljust(9)
        if exe:
            version = _version(exe, VERSION_ARGS[tool]) or "?"
            console.print(Text.assemble(("  OK     ", "green"), label, f" {version}", (f"  {exe}", "dim")))
        else:
            missing += 1
            console.print(Text.assemble(("  ABSENT ", "bold yellow"), label, f" {INSTALL_HINT[tool]}"))
    git = _resolve("git")
    console.print(Text.assemble(
        ("  OK     ", "green") if git else ("  ABSENT ", "yellow"), "Git".ljust(9),
        ("  historique Git scanné par Gitleaks", "dim") if git else " sans git, Gitleaks ne lit que les fichiers",
    ))
    raise typer.Exit(EXIT_BLOCKED if missing else EXIT_OK)


if __name__ == "__main__":  # pragma: no cover
    app()
