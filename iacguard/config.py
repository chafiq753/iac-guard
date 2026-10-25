"""Fichier de configuration `.iacguard.yml`, à la racine du dépôt scanné.

    fail_on: high                 # gravité qui fait échouer le scan
    tools: [gitleaks, checkov]    # optionnel : scanners à lancer
    exclude:                      # chemins à ne pas prendre en compte
      - examples/
      - "**/*_test.tf"
    ignore:                       # risques acceptés, un par un
      - rule: CKV_AWS_144
        reason: "Pas de réplication multi-région : données non critiques"
      - rule: CKV_AWS_20
        path: modules/site-public/
        reason: "Site statique public, le bucket doit être lisible"
        expires: 2026-12-31

Il remplace les seuils et les règles ignorées stockés en base par le
dashboard : la politique de sécurité vit dans le dépôt, versionnée et
relue en pull request comme le reste du code.

Choix de sécurité :
- `reason` est obligatoire : on ne fait pas taire un scanner sans dire
  pourquoi (c'est ce qu'un auditeur demandera).
- `expires` : passé la date, l'exception ne s'applique plus et le problème
  compte de nouveau. Un risque accepté doit être revu.
- Une clé inconnue (faute de frappe : `fail-on`, `ignores`) est une erreur,
  pas un réglage ignoré en silence.
"""

from __future__ import annotations

import fnmatch
from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from iacguard.schema import Finding

CONFIG_NAMES = (".iacguard.yml", ".iacguard.yaml")
MIN_REASON_LENGTH = 10

FailOnValue = Literal["critical", "high", "medium", "low", "info", "none"]


class ConfigError(Exception):
    """Configuration illisible ou invalide (message prêt à afficher)."""


class IgnoreEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: str
    reason: str
    path: str | None = None
    expires: date | None = None

    @field_validator("rule")
    @classmethod
    def _rule_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("`rule` est vide")
        return v

    @field_validator("reason")
    @classmethod
    def _reason_required(cls, v: str) -> str:
        v = v.strip()
        if len(v) < MIN_REASON_LENGTH:
            raise ValueError(
                f"justification trop courte ({MIN_REASON_LENGTH} caractères minimum) : "
                "explique pourquoi ce risque est accepté"
            )
        return v

    def expired(self, today: date | None = None) -> bool:
        return self.expires is not None and (today or date.today()) > self.expires

    def matches(self, finding: Finding) -> bool:
        if finding.rule_id != self.rule:
            return False
        return self.path is None or path_matches(finding.file, self.path)


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fail_on: FailOnValue | None = None
    tools: list[str] | None = None
    exclude: list[str] = []
    ignore: list[IgnoreEntry] = []
    semgrep_config: str | None = None


def path_matches(file: str | None, pattern: str) -> bool:
    """`file` (relatif au dépôt) correspond-il à `pattern` ?

    - `examples/` ou `examples` : tout ce qui est dans ce dossier ;
    - `**/*_test.tf`, `*.json` : motif glob (`*` traverse les dossiers).
    """
    if not file:
        return False
    f = file.replace("\\", "/").lstrip("/")
    p = pattern.replace("\\", "/").strip().lstrip("/").removeprefix("./")
    if not p:
        return False
    if any(c in p for c in "*?["):
        return fnmatch.fnmatch(f, p) or fnmatch.fnmatch(f, p.removeprefix("**/"))
    p = p.rstrip("/")
    return f == p or f.startswith(p + "/")


def find_config(root: Path) -> Path | None:
    for name in CONFIG_NAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path) -> Config:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Impossible de lire {path} : {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path.name} n'est pas un YAML valide : {exc}") from exc
    if data is None:
        return Config()
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name} doit contenir des clés (fail_on, exclude, ignore...).")
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        lines = []
        for err in exc.errors():
            where = ".".join(str(x) for x in err["loc"]) or "(racine)"
            msg = err["msg"].removeprefix("Value error, ")
            if err["type"] == "extra_forbidden":
                msg = "clé inconnue (faute de frappe ?)"
            elif err["type"] == "missing":
                msg = "obligatoire"
            lines.append(f"  - {where} : {msg}")
        raise ConfigError(f"Erreur dans {path.name} :\n" + "\n".join(lines)) from exc
