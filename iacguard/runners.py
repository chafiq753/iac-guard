"""Runners : lancent chaque scanner et renvoient des findings normalisés.

Un runner = un sous-processus (jamais via un shell : les arguments sont
passés en liste, un chemin contenant des espaces ou des `;` ne peut pas
injecter de commande). Chaque scanner écrit son JSON dans un dossier
temporaire, le parser correspondant le transforme en `Finding`.

Un scanner absent ou qui plante ne fait pas planter tout le scan : le
runner renvoie un `ToolRun` avec status "missing" ou "error" et un message.
C'est à l'appelant (la CLI) de décider si c'est bloquant.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iacguard.parsers import parse_checkov, parse_gitleaks, parse_semgrep
from iacguard.schema import Finding, ToolName

DEFAULT_TIMEOUT = 900  # secondes, par scanner

# Ordre d'exécution par défaut. Conftest n'en fait pas partie : sans règles
# Rego fournies, il ne détecte rien (son parser reste disponible).
DEFAULT_TOOLS: tuple[ToolName, ...] = (
    ToolName.GITLEAKS,
    ToolName.CHECKOV,
    ToolName.SEMGREP,
)


@dataclass
class ToolRun:
    """Résultat de l'exécution d'un scanner."""

    tool: ToolName
    status: str                          # "ok" | "missing" | "error"
    findings: list[Finding] = field(default_factory=list)
    version: str | None = None
    message: str | None = None           # explication si status != "ok"

    @property
    def ok(self) -> bool:
        return self.status == "ok"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _resolve(binary: str) -> str | None:
    """Chemin absolu de l'exécutable, ou None s'il n'est pas installé.

    Sous Windows, shutil.which trouve aussi checkov.cmd / semgrep.exe.
    """
    return shutil.which(binary)


def _run(
    cmd: list[str],
    timeout: int,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - arguments en liste, pas de shell
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        cwd=cwd,
        env={**os.environ, **env} if env else None,
        check=False,
    )


def _tail(text: str | None, lines: int = 5) -> str:
    """Dernières lignes d'une sortie d'erreur, pour un message lisible."""
    if not text:
        return ""
    return "\n".join(text.strip().splitlines()[-lines:])


def _load_json_file(path: Path) -> Any:
    if not path.exists() or path.stat().st_size == 0:
        return None
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _version(binary: str, args: list[str]) -> str | None:
    try:
        out = _run([binary, *args], timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or out.stderr).strip()
    return text.splitlines()[0].strip() if text else None


def _missing(tool: ToolName, binary: str) -> ToolRun:
    return ToolRun(
        tool=tool,
        status="missing",
        message=f"{binary} introuvable dans le PATH : installe-le ou utilise l'image Docker iac-guard.",
    )


# --------------------------------------------------------------------------- #
# Runners
# --------------------------------------------------------------------------- #


def run_gitleaks(path: Path, *, binary: str = "gitleaks", timeout: int = DEFAULT_TIMEOUT) -> ToolRun:
    """Secrets. Si `path` est un dépôt Git, tout l'historique est scanné
    (un secret supprimé du code reste dans les anciens commits) ; sinon on
    scanne seulement les fichiers présents (--no-git).
    """
    exe = _resolve(binary)
    if not exe:
        return _missing(ToolName.GITLEAKS, binary)

    with tempfile.TemporaryDirectory(prefix="iacguard-") as tmp:
        report = Path(tmp) / "gitleaks.json"
        cmd = [
            exe, "detect",
            "--source", str(path),
            "--report-format", "json",
            "--report-path", str(report),
            "--redact",          # le secret n'apparaît jamais en clair dans le rapport
            "--exit-code", "0",  # trouver un secret n'est pas une erreur d'exécution
            "--no-banner",
        ]
        if not (path / ".git").exists():
            cmd.append("--no-git")
        try:
            proc = _run(cmd, timeout)
        except subprocess.TimeoutExpired:
            return ToolRun(ToolName.GITLEAKS, "error", message=f"Gitleaks a dépassé {timeout}s.")

        if proc.returncode != 0:
            return ToolRun(
                ToolName.GITLEAKS, "error",
                message=f"Gitleaks a échoué (code {proc.returncode}). {_tail(proc.stderr)}",
            )
        try:
            data = _load_json_file(report)
        except json.JSONDecodeError as exc:
            return ToolRun(ToolName.GITLEAKS, "error", message=f"Rapport Gitleaks illisible : {exc}")

    return ToolRun(
        ToolName.GITLEAKS, "ok",
        findings=parse_gitleaks(data),
        version=_version(exe, ["version"]),
    )


def run_checkov(path: Path, *, binary: str = "checkov", timeout: int = DEFAULT_TIMEOUT) -> ToolRun:
    """Mauvaises configurations IaC (Terraform, CloudFormation, K8s, Dockerfile...)."""
    exe = _resolve(binary)
    if not exe:
        return _missing(ToolName.CHECKOV, binary)

    cmd = [exe, "-d", str(path), "-o", "json", "--soft-fail"]
    try:
        proc = _run(cmd, timeout)
    except subprocess.TimeoutExpired:
        return ToolRun(ToolName.CHECKOV, "error", message=f"Checkov a dépassé {timeout}s.")

    if not proc.stdout.strip():
        return ToolRun(
            ToolName.CHECKOV, "error",
            message=f"Checkov n'a rien renvoyé (code {proc.returncode}). {_tail(proc.stderr)}",
        )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return ToolRun(
            ToolName.CHECKOV, "error",
            message=f"Sortie Checkov non JSON (code {proc.returncode}). {_tail(proc.stdout)}",
        )

    # Version : dans `summary` (rapport complet) ou à la racine (aucun fichier
    # supporté trouvé : Checkov renvoie alors juste un résumé à plat).
    first = data[0] if isinstance(data, list) and data else data
    version = None
    if isinstance(first, dict):
        version = (first.get("summary") or {}).get("checkov_version") or first.get("checkov_version")

    return ToolRun(ToolName.CHECKOV, "ok", findings=parse_checkov(data), version=version)


def run_semgrep(
    path: Path,
    *,
    binary: str = "semgrep",
    config: str = "auto",
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolRun:
    """Vulnérabilités du code applicatif (SAST).

    `config="auto"` télécharge les règles adaptées depuis le registre
    Semgrep (réseau nécessaire). On peut passer un fichier de règles local.
    """
    exe = _resolve(binary)
    if not exe:
        return _missing(ToolName.SEMGREP, binary)

    with tempfile.TemporaryDirectory(prefix="iacguard-") as tmp:
        report = Path(tmp) / "semgrep.json"
        cmd = [
            exe, "scan",
            "--config", config,
            "--json", "--output", str(report),
            # Pas de --quiet : il masque aussi les erreurs (réseau, config),
            # et on a besoin de stderr pour expliquer un échec.
        ]
        # Avec des règles locales, rien ne doit partir sur le réseau. Semgrep
        # refuse `--config auto` sans métriques, donc on ne coupe que là.
        if config != "auto":
            cmd.append("--metrics=off")
        cmd.append(str(path))
        try:
            # Pas de vérification de nouvelle version à chaque scan.
            proc = _run(cmd, timeout, env={"SEMGREP_ENABLE_VERSION_CHECK": "0"})
        except subprocess.TimeoutExpired:
            return ToolRun(ToolName.SEMGREP, "error", message=f"Semgrep a dépassé {timeout}s.")

        try:
            data = _load_json_file(report)
        except json.JSONDecodeError as exc:
            return ToolRun(ToolName.SEMGREP, "error", message=f"Rapport Semgrep illisible : {exc}")

    # Sans --error, Semgrep sort en 0 même s'il trouve des problèmes : un
    # code non nul veut dire qu'il n'a pas pu tourner (config, réseau...).
    if proc.returncode != 0 or data is None:
        return ToolRun(
            ToolName.SEMGREP, "error",
            message=f"Semgrep a échoué (code {proc.returncode}). {_tail(proc.stderr)}",
        )

    return ToolRun(
        ToolName.SEMGREP, "ok",
        findings=parse_semgrep(data),
        version=data.get("version"),
    )


RUNNERS = {
    ToolName.GITLEAKS: run_gitleaks,
    ToolName.CHECKOV: run_checkov,
    ToolName.SEMGREP: run_semgrep,
}
