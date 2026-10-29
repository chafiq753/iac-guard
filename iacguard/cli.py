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
    ToolName.GITLEAKS: "download the binary: https://github.com/gitleaks/gitleaks/releases",
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
    help="Security scanner for Infrastructure as Code: secrets (Gitleaks), "
    "misconfigurations (Checkov) and code vulnerabilities (Semgrep), "
    "in one report with a score and a verdict.",
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
            f"unknown tool: {', '.join(unknown) or '(empty)'}. "
            f"Allowed: {', '.join(allowed)}.",
            param_hint="--tools",
        )
    # Ordre fixe (celui de DEFAULT_TOOLS), sans doublon.
    return [t for t in DEFAULT_TOOLS if t.value in names]


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


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
        extra.append(f"lines {f.line_start}-{f.line_end}")
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
    console.print(Text.assemble("   File      : ", _location(f, root)))
    if extra := _location_extra(f):
        console.print(f"   Details   : {extra}", highlight=False)
    console.print(f"   Rule      : {f.rule_id} ({f.source.value})", highlight=False)
    if ignored_reason:
        console.print(Text(f"   Ignored   : {ignored_reason} (.iacguard.yml, not counted)",
                           style="yellow"))
    if f.remediation:
        console.print(f"   Fix       : {f.remediation}", highlight=False)
    if _is_secret(f):
        console.print(Text("   Code      : hidden (contains a secret)", style="dim"))
        return
    absolute = _abs_file(f, root)
    snippet = _snippet(f, root)
    if snippet:
        console.print("   Code      :")
    for num, line in snippet:
        shown = "*** hidden (secret) ***" if (absolute, num) in hidden else line.rstrip()
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
            "  ", ("OK      ", "green"), label, (version, "dim"),
            f"  {_plural(len(run.findings), 'finding')}",
        )
    status = "MISSING " if run.status == "missing" else "ERROR   "
    # Le message peut finir par la sortie d'erreur du scanner (traceback...) :
    # on montre la phrase d'explication et la dernière ligne, pas tout.
    lines = [line.strip() for line in (run.message or "").splitlines() if line.strip()]
    text = Text.assemble("  ", (status, "bold yellow"), label, f" {lines[0] if lines else ''}")
    if len(lines) > 1:
        text.append(f"\n{' ' * 19}{lines[-1]}", style="dim")
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
        text.append(f"  incl. {result.decision.ignored_count} ignored", style="dim")
    if result.excluded_count:
        text.append(f"  + {result.excluded_count} in excluded paths", style="dim")
    return text


def _verdict(result: ScanResult, fail_on: FailOn) -> Text:
    score = result.decision.score
    text = Text.assemble(
        "Score: ", (f"{score.score}/100", "bold"), f" (grade {score.grade})   Verdict: ",
    )
    if result.decision.blocked:
        text.append("BLOCKED", style="bold white on red")
        text.append(f"  at least one finding is '{fail_on.value}' or worse")
    elif fail_on is FailOn.none:
        text.append("REPORT ONLY", style="bold")
        text.append("  (--fail-on none: never blocks)")
    else:
        text.append("PASSED", style="bold green")
        text.append(f"  no finding is '{fail_on.value}' or worse")
    return text


def _render_table(console: Console, result: ScanResult, path: Path, fail_on: FailOn,
                  details: bool = False) -> None:
    meta = result.report.scan
    console.print(Text(f"iac-guard {__version__}  -  scanning {path}", style="bold"))
    ctx = [f"Repo: {meta.repo}"]
    if meta.branch:
        ctx.append(f"Branch: {meta.branch}")
    if meta.commit_sha:
        ctx.append(f"Commit: {meta.commit_sha[:7]}")
    console.print(Text("   ".join(ctx), style="dim"))
    console.print()

    findings = _sorted(result.report.findings)
    if findings:
        table = Table(show_lines=False, header_style="bold", expand=False)
        table.add_column("#", justify="right", style="dim", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Tool", no_wrap=True)
        table.add_column("Rule", overflow="fold")
        table.add_column("Location", overflow="fold")
        table.add_column("Issue")
        for n, f in enumerate(findings, 1):
            is_ignored = f.fingerprint in result.ignored
            table.add_row(
                str(n),
                Text(f.severity.value.upper(),
                     style="dim strike" if is_ignored else SEVERITY_STYLE[f.severity.value]),
                f.source.value,
                f.rule_id + (" (ignored)" if is_ignored else ""),
                _location(f, path),
                f.title,
                style="dim" if is_ignored else None,
            )
        console.print(table)
        if details:
            _render_details(console, findings, path, result.ignored)
        else:
            console.print(Text("Details of an issue: iacguard show <#>   (e.g. iacguard show 1)",
                               style="dim"))
    else:
        console.print(Text("No issues found.", style="green"))
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
        typer.Option("--version", "-V", help="Show the version and exit.",
                     callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    _safe_streams()


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(help="Directory to scan.", exists=True, file_okay=False,
                       dir_okay=True, resolve_path=True),
    ] = Path("."),
    fail_on: Annotated[
        FailOn | None,
        typer.Option("--fail-on", case_sensitive=False,
                     help="Lowest severity that fails the scan (exit code 1). "
                     "'high' blocks on high AND critical. 'none': never blocks. "
                     "Default: .iacguard.yml, otherwise high."),
    ] = None,
    fmt: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="Report format."),
    ] = OutputFormat.table,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", dir_okay=False, writable=True,
                     help="Write the report to this file (UTF-8) instead of the terminal."),
    ] = None,
    tools: Annotated[
        str | None,
        typer.Option("--tools", "-t",
                     help="Scanners to run, comma-separated "
                     "(default: gitleaks,checkov,semgrep)."),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict",
                     help="Fail (exit code 2) if a scanner could not run. "
                     "Recommended in CI, otherwise a missing scanner goes unnoticed."),
    ] = False,
    details: Annotated[
        bool,
        typer.Option("--details", "-d",
                     help="After the table, print details of ALL issues "
                     "(for a single one: iacguard show <#>)."),
    ] = False,
    semgrep_config: Annotated[
        str | None,
        typer.Option("--semgrep-config",
                     help="Semgrep rules: 'auto' (online registry) or a local rules file."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", exists=True, dir_okay=False,
                     help="Configuration file (default: .iacguard.yml in the scanned directory)."),
    ] = None,
    sarif: Annotated[
        Path | None,
        typer.Option("--sarif", dir_okay=False, writable=True,
                     help="ALSO write a SARIF report to this file (for GitHub Code scanning)."),
    ] = None,
    annotations: Annotated[
        bool,
        typer.Option("--annotations/--no-annotations",
                     help="GitHub Actions: annotate the PR lines. Disable when the SARIF is "
                     "uploaded to Code scanning (otherwise each issue appears twice)."),
    ] = True,
    since: Annotated[
        str | None,
        typer.Option("--since",
                     help="Gitleaks: only scan commits after this ref "
                     "(e.g. origin/main). Automatic in GitHub pull requests."),
    ] = None,
) -> None:
    """Scan a directory and show the issues found, the score and the verdict."""
    err = Console(stderr=True, emoji=False, highlight=False)

    # Configuration : option de la ligne de commande > .iacguard.yml > défaut.
    cfg_file = config or find_config(path)
    try:
        cfg = load_config(cfg_file) if cfg_file else Config()
    except ConfigError as exc:
        err.print(Text(str(exc), style="bold red"))
        raise typer.Exit(EXIT_ERROR)
    if cfg_file:
        err.print(Text(f"Config: {_display_path(cfg_file.resolve())}", style="dim"))
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
        err.print(Text(f"Ref {since} not found: Gitleaks scans the whole history "
                       "(in the workflow, use checkout with fetch-depth: 0).", style="yellow"))
        since = None

    def on_start(tool: ToolName) -> None:
        if err.is_terminal:
            status.update(f"Running {TOOL_LABEL[tool]}...")

    def on_done(run: ToolRun) -> None:
        err.print(_tool_line(run))

    err.print(Text(f"Scanners ({', '.join(t.value for t in selected)}):", style="bold"))
    with err.status("Starting...", spinner="dots") as status:
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
        err.print(Text("No scanner could run: nothing was checked. "
                       "Run `iacguard doctor` to see what is missing.", style="bold red"))
        raise typer.Exit(EXIT_ERROR)

    for entry in result.expired_ignores:
        err.print(Text(f"Exception for {entry.rule} expired on {entry.expires}: "
                       "the issue counts again (review it in .iacguard.yml).",
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
        err.print(Text(f"Report written to {output}", style="dim"))
    if sarif:
        err.print(Text(f"SARIF report written to {sarif}", style="dim"))

    if failed:
        names = " and ".join(TOOL_LABEL[r.tool] for r in failed)
        verb = "did not run"
        hint = "" if strict else " Add --strict to fail the scan in this case."
        err.print(Text(f"Warning: partial scan, {names} {verb}.{hint}",
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
        verdict = ("BLOCKED" if d.blocked else
                   "report only" if threshold is None else "passed")
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
    number: Annotated[int, typer.Argument(help="Issue number (the # column of the table).", min=1)],
) -> None:
    """Details of an issue from the last scan: file, line, resource, code, fix."""
    console = Console(emoji=False, highlight=False)
    try:
        data = json.loads(_cache_file().read_text(encoding="utf-8"))
        report = ScanReport.model_validate(data["report"])
        root = Path(data["root"])
    except (OSError, ValueError, KeyError):
        console.print(Text("No recent scan: run `iacguard scan .` first", style="bold red"))
        raise typer.Exit(EXIT_ERROR)

    findings = _sorted(report.findings)
    if number > len(findings):
        console.print(Text(f"The last scan only has {len(findings)} issue(s).",
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
        typer.Argument(help="Repository root.", exists=True, file_okay=False, resolve_path=True),
    ] = Path("."),
    github: Annotated[
        bool,
        typer.Option("--github", help="Also add the GitHub Actions workflow "
                     "(scan on every pull request, alerts in the PR)."),
    ] = False,
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files.")] = False,
) -> None:
    """Set up a repository: create .iacguard.yml (and the GitHub workflow with --github)."""
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
            console.print(Text.assemble(("  EXISTS  ", "yellow"), shown, ("  (--force to overwrite)", "dim")))
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        console.print(Text.assemble(("  CREATED ", "green"), shown))

    console.print()
    console.print(Text("Next:", style="bold"))
    console.print("  1. iacguard scan .            (local scan)")
    if github:
        console.print("  2. git add .iacguard.yml .github && git commit -m \"Add iac-guard\" && git push")
        console.print("  3. On GitHub: Settings > Rules > Rulesets > New branch ruleset")
        console.print("     > Require status checks to pass > add \"iac-guard\"")
        console.print("     (the check appears after the first scan; it blocks the merge if the scan fails)")
    else:
        console.print("  To scan every GitHub pull request: iacguard init --github")
    raise typer.Exit(EXIT_OK)


@app.command()
def doctor() -> None:
    """Check that the scanners are installed (exit code 1 if one is missing)."""
    console = Console(emoji=False, highlight=False)
    missing = 0
    for tool in DEFAULT_TOOLS:
        exe = _resolve(tool.value)
        label = TOOL_LABEL[tool].ljust(9)
        if exe:
            version = _version(exe, VERSION_ARGS[tool]) or "?"
            console.print(Text.assemble(("  OK      ", "green"), label, f" {version}", (f"  {exe}", "dim")))
        else:
            missing += 1
            console.print(Text.assemble(("  MISSING ", "bold yellow"), label, f" {INSTALL_HINT[tool]}"))
    git = _resolve("git")
    console.print(Text.assemble(
        ("  OK      ", "green") if git else ("  MISSING ", "yellow"), "Git".ljust(9),
        ("  Git history scanned by Gitleaks", "dim") if git else " without git, Gitleaks only reads the files",
    ))
    raise typer.Exit(EXIT_BLOCKED if missing else EXIT_OK)


if __name__ == "__main__":  # pragma: no cover
    app()
