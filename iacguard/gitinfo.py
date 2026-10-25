"""Contexte Git du scan : dépôt, branche, commit.

Sert à remplir `ScanMeta` dans le rapport. Deux sources :

1. Dans GitHub Actions : les variables GITHUB_* (fiables, pas besoin de git).
2. Ailleurs : quelques commandes `git` en lecture seule sur le dossier scanné.

Si rien n'est trouvé (pas un dépôt, git absent), les champs restent à None :
ce n'est que du contexte, jamais une raison de faire échouer le scan.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass
class GitInfo:
    repo: str | None = None      # "owner/repo"
    branch: str | None = None
    commit: str | None = None


# Les deux derniers segments d'une URL de remote : ".../owner/repo(.git)"
# ou "git@host:owner/repo(.git)". On ne garde QUE ça : une URL du type
# https://user:TOKEN@github.com/... ne doit jamais finir dans un rapport.
_REMOTE_RE = re.compile(r"[:/]([^/:@\s]+/[^/:@\s]+?)(?:\.git)?/*$")


def repo_from_remote(url: str | None) -> str | None:
    """`owner/repo` à partir d'une URL de remote Git, sans identifiants."""
    if not url:
        return None
    m = _REMOTE_RE.search(url.strip())
    return m.group(1) if m else None


def _git(path: Path, *args: str) -> str | None:
    git = shutil.which("git")
    if not git:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - arguments en liste, pas de shell
            [git, "-C", str(path), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = proc.stdout.strip()
    return out if proc.returncode == 0 and out else None


def detect(path: Path, env: Mapping[str, str] | None = None) -> GitInfo:
    """Dépôt, branche et commit du dossier scanné (au mieux)."""
    env = os.environ if env is None else env

    if env.get("GITHUB_ACTIONS") == "true":
        return GitInfo(
            repo=env.get("GITHUB_REPOSITORY") or None,
            # Sur une pull request, GITHUB_REF_NAME vaut "12/merge" : la
            # vraie branche est dans GITHUB_HEAD_REF.
            branch=env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME") or None,
            commit=env.get("GITHUB_SHA") or None,
        )

    if _git(path, "rev-parse", "--is-inside-work-tree") != "true":
        return GitInfo()

    branch = _git(path, "rev-parse", "--abbrev-ref", "HEAD")
    return GitInfo(
        repo=repo_from_remote(_git(path, "config", "--get", "remote.origin.url")),
        branch=None if branch == "HEAD" else branch,   # "HEAD" = commit détaché
        commit=_git(path, "rev-parse", "HEAD"),
    )
