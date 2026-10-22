"""
Parsers : un par outil, sortie JSON brute -> list[Finding].

Repris de pipeline/aggregator/aggregator.py sans changement de logique.
Ces fonctions sont pures (aucun accès disque ni réseau) : on leur donne le
JSON déjà chargé, elles renvoient des findings normalisés.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from iacguard.schema import Category, Finding, Severity, ToolName

# Sévérité déclarée en toutes lettres (Checkov, metadata Rego, Semgrep) -> enum.
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
    # Semgrep utilise ERROR/WARNING/INFO (`extra.severity`) plutôt que
    # critical/high/medium/low.
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
}


def _norm_severity(value: Any, default: Severity) -> Severity:
    """Convertit une sévérité texte en enum, avec fallback si absente/inconnue."""
    if not value:
        return default
    return _SEVERITY_MAP.get(str(value).strip().lower(), default)


def parse_gitleaks(data: Any) -> list[Finding]:
    """
    Gitleaks (`gitleaks detect -f json`) : liste plate de secrets détectés.
    Pas de sévérité native -> un secret exposé est traité comme CRITICAL.
    """
    if not data:
        return []
    findings: list[Finding] = []
    for item in data:
        findings.append(
            Finding(
                source=ToolName.GITLEAKS,
                category=Category.SECRET,
                rule_id=item.get("RuleID", "unknown"),
                title=item.get("Description", "Secret détecté"),
                severity=Severity.CRITICAL,
                resource=None,
                file=item.get("File"),
                line_start=item.get("StartLine"),
                line_end=item.get("EndLine"),
                remediation="Retirer le secret du code, le révoquer et le stocker "
                "dans un gestionnaire de secrets (Vault, SSM, GitHub Secrets).",
                raw=item,
            )
        )
    return findings


def parse_checkov(data: Any) -> list[Finding]:
    """
    Checkov (`checkov -o json`) : objet {results: {failed_checks: [...]}}.
    Peut aussi être une liste d'objets (plusieurs frameworks) -> on gère les deux.
    Sévérité présente seulement si liée à la plateforme Prisma, sinon MEDIUM.
    """
    if not data:
        return []
    reports = data if isinstance(data, list) else [data]
    findings: list[Finding] = []
    for report in reports:
        failed = (report.get("results") or {}).get("failed_checks") or []
        for chk in failed:
            line_range = chk.get("file_line_range") or [None, None]
            findings.append(
                Finding(
                    source=ToolName.CHECKOV,
                    category=Category.MISCONFIGURATION,
                    rule_id=chk.get("check_id", "unknown"),
                    title=chk.get("check_name", "Mauvaise configuration"),
                    severity=_norm_severity(chk.get("severity"), Severity.MEDIUM),
                    resource=chk.get("resource"),
                    file=chk.get("repo_file_path") or chk.get("file_path"),
                    line_start=line_range[0],
                    line_end=line_range[1] if len(line_range) > 1 else None,
                    remediation=chk.get("guideline"),
                    raw=chk,
                )
            )
    return findings


def parse_conftest(data: Any) -> list[Finding]:
    """
    Conftest (`conftest test -o json`) : liste de résultats par fichier.
    `failures` -> findings, `warnings` -> findings de plus faible sévérité.
    La sévérité/titre/remédiation viennent de la metadata Rego quand présents ;
    sinon fallback (choix produit : la règle Rego porte sa sévérité).
    """
    if not data:
        return []
    findings: list[Finding] = []
    for block in data:
        filename = block.get("filename")
        for kind, default_sev in (("failures", Severity.HIGH), ("warnings", Severity.LOW)):
            for entry in block.get(kind) or []:
                meta = entry.get("metadata") or {}
                findings.append(
                    Finding(
                        source=ToolName.CONFTEST,
                        category=Category.POLICY,
                        rule_id=meta.get("rule_id") or block.get("namespace") or "policy",
                        title=meta.get("title") or entry.get("msg", "Violation de règle métier"),
                        severity=_norm_severity(meta.get("severity"), default_sev),
                        resource=meta.get("resource"),
                        file=filename,
                        line_start=None,
                        line_end=None,
                        remediation=meta.get("remediation"),
                        raw=entry,
                    )
                )
    return findings


def parse_semgrep(data: Any) -> list[Finding]:
    """
    Semgrep (`semgrep --config=auto --json`) : objet {results: [...]}.
    SAST sur le code applicatif (pas l'IaC) -> pas de `resource` cloud.
    Sévérité déclarée dans `extra.severity` (ERROR/WARNING/INFO).
    """
    if not data:
        return []
    results = data.get("results") or []
    findings: list[Finding] = []
    for item in results:
        extra = item.get("extra") or {}
        start = item.get("start") or {}
        end = item.get("end") or {}
        findings.append(
            Finding(
                source=ToolName.SEMGREP,
                category=Category.VULNERABILITY,
                rule_id=item.get("check_id", "unknown"),
                title=extra.get("message", "Vulnérabilité détectée").split("\n")[0],
                severity=_norm_severity(extra.get("severity"), Severity.MEDIUM),
                resource=None,
                file=item.get("path"),
                line_start=start.get("line"),
                line_end=end.get("line"),
                remediation=extra.get("fix"),
                raw=item,
            )
        )
    return findings


PARSERS: dict[ToolName, Callable[[Any], list[Finding]]] = {
    ToolName.GITLEAKS: parse_gitleaks,
    ToolName.CHECKOV: parse_checkov,
    ToolName.CONFTEST: parse_conftest,
    ToolName.SEMGREP: parse_semgrep,
}
