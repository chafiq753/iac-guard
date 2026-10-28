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

import json
import os
import sys
from importlib import resources
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
from iacguard.config import Config, ConfigError, find_config, load_config
from iacguard.gitinfo import detect as detect_git, pull_request_base, ref_exists
from iacguard.runners import DEFAULT_TOOLS, RUNNERS, ToolRun, _resolve, _version
from iacguard.sarif import to_sarif
from iacguard.schema import Finding, ScanReport, ToolName
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
    sarif = "sarif"


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
    """`fichier:ligne`, comme avant. Le lien (OSC 8) ne change rien à
    l'affichage ; dans VS Code / Windows Terminal, Ctrl+clic ouvre le fichier."""
    absolute = _abs_file(f, root)
    if absolute is None:
        return Text(f.resource or "-")
    loc = _display_path(absolute)
    if f.line_start:
        loc += f":{f.line_start}"
    return Text(loc, style=Style(link=absolute.as_uri()))


def _location_extra(f: Finding) -> str | None:
    extra = []
    if f.line_end and f.line_start and f.line_end > f.line_start:
        extra.append(f"lignes {f.line_start}-{f.line_end}")
    if f.resource:
        extra.append(f.resource)
    if commit := _commit(f):
        extra.append(f"commit {commit}")
    return " · ".join(extra) or None


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


def _render_finding(console: Console, n: int, f: Finding, root: Path,
                    hidden: set[tuple[Path, int]], ignored_reason: str | None = None) -> None:
    console.print(Text.assemble(
        (f"#{n} ", "bold"),
        (f" {f.severity.value.upper()} ", SEVERITY_STYLE[f.severity.value]),
        f"  {f.title}",
    ))
    console.print(Text.assemble("   Fichier   : ", _location(f, root)))
    if extra := _location_extra(f):
        console.print(f"   Détail    : {extra}", highlight=False)
    console.print(f"   Règle     : {f.rule_id} ({f.source.value})", highlight=False)
    if ignored_reason:
        console.print(Text(f"   Ignoré    : {ignored_reason} (.iacguard.yml, ne compte pas)",
                           style="yellow"))
    if f.remediation:
        console.print(f"   Corriger  : {f.remediation}", highlight=False)
    if _is_secret(f):
        console.print(Text("   Code      : masqué (contient un secret)", style="dim"))
        return
    absolute = _abs_file(f, root)
    snippet = _snippet(f, root)
    if snippet:
        console.print("   Code      :")
    for num, line in snippet:
        shown = "*** masqué (secret) ***" if (absolute, num) in hidden else line.rstrip()
        console.print(Text(f"   {num:>6} | {shown}", style="dim"))


def _render_details(console: Console, findings: list[Finding], root: Path,
                    ignored: dict[str, str]) -> None:
    hidden = _secret_lines(findings, root)
    for n, f in enumerate(findings, 1):
        console.print()
        _render_finding(console, n, f, root, hidden, ignored.get(f.fingerprint))


def _sorted(findings: list[Finding]) -> list[Finding]:
    rank = {sev: i for i, sev in enumerate(reversed(SEVERITY_ORDER))}  # critical = 0
    return sorted(
        findings,
        key=lambda f: (rank[f.severity.value], f.source.value, f.file or "", f.line_start or 0,
                       f.rule_id),   # ordre stable : `show 5` = toujours la même ligne
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
    if result.excluded_count:
        text.append(f"  + {result.excluded_count} dans des chemins exclus", style="dim")
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
        table.add_column("#", justify="right", style="dim", no_wrap=True)
        table.add_column("Gravité", no_wrap=True)
        table.add_column("Outil", no_wrap=True)
        table.add_column("Règle", overflow="fold")
        table.add_column("Emplacement", overflow="fold")
        table.add_column("Problème")
        for n, f in enumerate(findings, 1):
            is_ignored = f.fingerprint in result.ignored
            table.add_row(
                str(n),
                Text(f.severity.value.upper(),
                     style="dim strike" if is_ignored else SEVERITY_STYLE[f.severity.value]),
                f.source.value,
                f.rule_id + (" (ignoré)" if is_ignored else ""),
                _location(f, path),
                f.title,
                style="dim" if is_ignored else None,
            )
        console.print(table)
        if details:
            _render_details(console, findings, path, result.ignored)
        else:
            console.print(Text("Détails d'un problème : iacguard show <#>   (ex : iacguard show 1)",
                               style="dim"))
    else:
        console.print(Text("Aucun problème détecté.", style="green"))
    console.print()
    console.print(_counts_line(result))
    console.print(_verdict(result, fail_on))


def _sarif_json(result: ScanResult, path: Path) -> str:
    ws = os.environ.get("GITHUB_WORKSPACE")
    doc = to_sarif(_sorted(result.report.findings), path, result.ignored, Path(ws) if ws else None)
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _write_output(result: ScanResult, fmt: OutputFormat, path: Path, fail_on: FailOn,
                  output: Path | None, details: bool = False) -> None:
    if fmt in (OutputFormat.json, OutputFormat.sarif):
        content = (result.report.model_dump_json(indent=2) if fmt is OutputFormat.json
                   else _sarif_json(result, path))
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
        FailOn | None,
        typer.Option("--fail-on", case_sensitive=False,
                     help="Gravité à partir de laquelle le scan échoue (code 1). "
                     "'high' bloque sur high ET critical. 'none' : ne bloque jamais. "
                     "Défaut : celui de .iacguard.yml, sinon high."),
    ] = None,
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
        str | None,
        typer.Option("--tools", "-t",
                     help="Scanners à lancer, séparés par des virgules "
                     "(défaut : gitleaks,checkov,semgrep)."),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict",
                     help="Échoue (code 2) si un scanner n'a pas pu tourner. "
                     "Recommandé en CI : sinon un scanner absent passe inaperçu."),
    ] = False,
    details: Annotated[
        bool,
        typer.Option("--details", "-d",
                     help="Après le tableau, les détails de TOUS les problèmes "
                     "(pour un seul : iacguard show <#>)."),
    ] = False,
    semgrep_config: Annotated[
        str | None,
        typer.Option("--semgrep-config",
                     help="Règles Semgrep : 'auto' (registre en ligne) ou un fichier local."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", exists=True, dir_okay=False,
                     help="Fichier de configuration (défaut : .iacguard.yml du dossier scanné)."),
    ] = None,
    sarif: Annotated[
        Path | None,
        typer.Option("--sarif", dir_okay=False, writable=True,
                     help="Écrit AUSSI un rapport SARIF dans ce fichier (pour GitHub Code scanning)."),
    ] = None,
    annotations: Annotated[
        bool,
        typer.Option("--annotations/--no-annotations",
                     help="GitHub Actions : annoter les lignes de la PR. Désactiver si le "
                     "SARIF est envoyé à Code scanning (sinon chaque problème apparaît deux fois)."),
    ] = True,
    since: Annotated[
        str | None,
        typer.Option("--since",
                     help="Gitleaks : seulement les commits après cette référence "
                     "(ex : origin/main). Automatique dans une pull request GitHub."),
    ] = None,
) -> None:
    """Scanne un dossier et affiche les problèmes trouvés, le score et le verdict."""
    err = Console(stderr=True, emoji=False, highlight=False)

    # Configuration : option de la ligne de commande > .iacguard.yml > défaut.
    cfg_file = config or find_config(path)
    try:
        cfg = load_config(cfg_file) if cfg_file else Config()
    except ConfigError as exc:
        err.print(Text(str(exc), style="bold red"))
        raise typer.Exit(EXIT_ERROR)
    if cfg_file:
        err.print(Text(f"Configuration : {_display_path(cfg_file.resolve())}", style="dim"))
    if fail_on is None:
        fail_on = FailOn(cfg.fail_on) if cfg.fail_on else FailOn.high
    if tools is None:
        tools = ",".join(cfg.tools) if cfg.tools else ",".join(t.value for t in DEFAULT_TOOLS)
    semgrep_config = semgrep_config or cfg.semgrep_config or "auto"
    selected = _parse_tools(tools)
    git = detect_git(path)

    # Pull request : Gitleaks ne lit que les commits de la PR.
    since = since or pull_request_base()
    if since and not ref_exists(path, since):
        err.print(Text(f"Référence {since} introuvable : Gitleaks scanne tout l'historique "
                       "(dans le workflow, checkout avec fetch-depth: 0).", style="yellow"))
        since = None

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
            exclude=cfg.exclude,
            ignores=cfg.ignore,
            gitleaks_since=since,
            on_start=on_start,
            on_done=on_done,
        )
    err.print()

    failed = result.failed_tools
    if len(failed) == len(result.runs):
        err.print(Text("Aucun scanner n'a pu tourner : rien n'a été vérifié. "
                       "Lance `iacguard doctor` pour voir ce qui manque.", style="bold red"))
        raise typer.Exit(EXIT_ERROR)

    for entry in result.expired_ignores:
        err.print(Text(f"Exception expirée le {entry.expires} pour {entry.rule} : "
                       "le problème compte de nouveau (à revoir dans .iacguard.yml).",
                       style="yellow"))

    _write_output(result, fmt, path, fail_on, output, details)
    # JSON/SARIF sur stdout : rien d'autre ne doit s'y mélanger.
    stdout_is_data = fmt is not OutputFormat.table and not output
    _github_report(result, path, fail_on, annotations and not stdout_is_data)
    _save_last_scan(result, path)

    # Le verdict reste visible dans le terminal quand le rapport part ailleurs.
    if sarif:
        sarif.write_text(_sarif_json(result, path) + "\n", encoding="utf-8")

    if fmt is not OutputFormat.table or output:
        err.print(_counts_line(result))
        err.print(_verdict(result, fail_on))
    if output:
        err.print(Text(f"Rapport écrit dans {output}", style="dim"))
    if sarif:
        err.print(Text(f"Rapport SARIF écrit dans {sarif}", style="dim"))

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


def _github_report(result: ScanResult, path: Path, fail_on: FailOn,
                   annotations: bool = True) -> None:
    """Dans GitHub Actions : annotations sur les lignes de la PR + résumé du job."""
    if not github.in_github_actions():
        return
    # Les risques acceptés (.iacguard.yml) ne s'affichent pas dans la PR.
    findings = [f for f in _sorted(result.report.findings) if f.fingerprint not in result.ignored]
    threshold = None if fail_on is FailOn.none else fail_on.value
    # Les annotations doivent sortir sur stdout pour que GitHub les lise.
    if annotations:
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


def _cache_file() -> Path:
    """Dernier scan, pour `iacguard show`. Hors du dépôt : rien à ignorer dans Git."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") \
        or str(Path.home() / ".cache")
    return Path(base) / "iacguard" / "last-scan.json"


def _save_last_scan(result: ScanResult, root: Path) -> None:
    try:
        cache = _cache_file()
        cache.parent.mkdir(parents=True, exist_ok=True)
        payload = {"root": str(root), "report": result.report.model_dump(mode="json"),
                   "ignored": result.ignored}
        cache.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass   # pas de cache = `show` indisponible, le scan reste valide


@app.command()
def show(
    number: Annotated[int, typer.Argument(help="Numéro du problème (colonne # du tableau).", min=1)],
) -> None:
    """Détails d'un problème du dernier scan : fichier, ligne, ressource, code, correction."""
    console = Console(emoji=False, highlight=False)
    try:
        data = json.loads(_cache_file().read_text(encoding="utf-8"))
        report = ScanReport.model_validate(data["report"])
        root = Path(data["root"])
    except (OSError, ValueError, KeyError):
        console.print(Text("Aucun scan récent : lance d'abord `iacguard scan .`", style="bold red"))
        raise typer.Exit(EXIT_ERROR)

    findings = _sorted(report.findings)
    if number > len(findings):
        console.print(Text(f"Il n'y a que {len(findings)} problème(s) dans le dernier scan.",
                           style="bold red"))
        raise typer.Exit(EXIT_ERROR)
    f = findings[number - 1]
    _render_finding(console, number, f, root, _secret_lines(findings, root),
                    (data.get("ignored") or {}).get(f.fingerprint))
    raise typer.Exit(EXIT_OK)


# Version de l'action GitHub écrite par `iacguard init --github`.
ACTION_REF = "v1"   # tag majeur, déplacé à chaque release par release.yml


def _default_branch(path: Path) -> str:
    from iacguard.gitinfo import _git  # lecture seule
    head = _git(path, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")   # origin/main
    if head and "/" in head:
        return head.split("/", 1)[1]
    return _git(path, "rev-parse", "--abbrev-ref", "HEAD") or "main"


@app.command()
def init(
    path: Annotated[
        Path,
        typer.Argument(help="Racine du dépôt.", exists=True, file_okay=False, resolve_path=True),
    ] = Path("."),
    github: Annotated[
        bool,
        typer.Option("--github", help="Ajoute aussi le workflow GitHub Actions "
                     "(scan à chaque pull request, alertes dans la PR)."),
    ] = False,
    force: Annotated[bool, typer.Option("--force", help="Remplace les fichiers existants.")] = False,
) -> None:
    """Prépare un dépôt : crée .iacguard.yml (et le workflow GitHub avec --github)."""
    console = Console(emoji=False, highlight=False)
    templates = resources.files("iacguard") / "templates"
    files = {path / ".iacguard.yml": (templates / "iacguard.yml").read_text(encoding="utf-8")}
    if github:
        workflow = (templates / "github-workflow.yml").read_text(encoding="utf-8")
        workflow = workflow.replace("__REF__", ACTION_REF).replace("__BRANCH__", _default_branch(path))
        files[path / ".github" / "workflows" / "iacguard.yml"] = workflow

    for target, content in files.items():
        shown = _display_path(target)
        if target.exists() and not force:
            console.print(Text.assemble(("  EXISTE ", "yellow"), shown, ("  (--force pour remplacer)", "dim")))
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        console.print(Text.assemble(("  CRÉÉ   ", "green"), shown))

    console.print()
    console.print(Text("Ensuite :", style="bold"))
    console.print("  1. iacguard scan .            (scan local)")
    if github:
        console.print("  2. git add .iacguard.yml .github && git commit -m \"Ajout iac-guard\" && git push")
        console.print("  3. Sur GitHub : Settings > Rules > Rulesets > New branch ruleset")
        console.print("     > Require status checks to pass > ajouter « iac-guard »")
        console.print("     (le check apparaît après le premier scan : bloque le merge si le scan échoue)")
    else:
        console.print("  Pour scanner à chaque pull request GitHub : iacguard init --github")
    raise typer.Exit(EXIT_OK)


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
