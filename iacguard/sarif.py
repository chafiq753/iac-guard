"""Export SARIF 2.1.0 : le format standard des outils d'analyse.

GitHub le lit (action github/codeql-action/upload-sarif) : chaque problème
devient une alerte dans l'onglet Security > Code scanning du dépôt, et
apparaît sur la ligne concernée dans la pull request. Contrairement aux
annotations (10 erreurs max par étape), il n'y a pas de limite pratique, et
les alertes ont un historique (ouverte, corrigée, rejetée).

Spécification : https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

from pathlib import Path

from iacguard import __version__
from iacguard.github import repo_path
from iacguard.schema import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/chafiq753/iac-guard"

# GitHub classe les alertes avec `security-severity` (0 à 10, comme CVSS) :
# >= 9 critical, >= 7 high, >= 4 medium, sinon low.
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _rule(f: Finding) -> dict:
    rule: dict = {
        "id": f.rule_id,
        "name": f.rule_id,
        "shortDescription": {"text": f.title[:1000]},
        "fullDescription": {"text": f.title},
        "defaultConfiguration": {"level": LEVEL[f.severity.value]},
        "properties": {
            "tags": ["security", f.source.value, f.category.value],
            "security-severity": SECURITY_SEVERITY[f.severity.value],
        },
    }
    if f.remediation:
        rule["help"] = {"text": f.remediation}
        if f.remediation.startswith("http"):
            rule["helpUri"] = f.remediation
    return rule


def to_sarif(
    findings: list[Finding],
    root: Path,
    ignored: dict[str, str] | None = None,
    workspace: Path | None = None,
) -> dict:
    """Rapport SARIF. Les findings ignorés (.iacguard.yml) sont marqués
    « supprimés » avec leur justification, pas effacés : un auditeur voit
    qu'un risque a été accepté, et pourquoi."""
    ignored = ignored or {}
    rules: dict[str, int] = {}
    rule_defs: list[dict] = []
    results: list[dict] = []

    for f in findings:
        path = repo_path(f, root, workspace)
        if not path:
            continue   # GitHub refuse une alerte sans emplacement
        if f.rule_id not in rules:
            rules[f.rule_id] = len(rule_defs)
            rule_defs.append(_rule(f))

        region: dict = {"startLine": max(1, f.line_start or 1)}
        if f.line_end and f.line_end >= region["startLine"]:
            region["endLine"] = f.line_end

        text = f.title
        if f.resource:
            text += f" (ressource : {f.resource})"
        result: dict = {
            "ruleId": f.rule_id,
            "ruleIndex": rules[f.rule_id],
            "level": LEVEL[f.severity.value],
            "message": {"text": f"[{f.severity.value.upper()}] {text}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
                    "region": region,
                },
            }],
            # Même empreinte que le dashboard : GitHub suit l'alerte d'un scan
            # à l'autre au lieu d'en recréer une à chaque push.
            "partialFingerprints": {"iacguardFingerprint/v1": f.fingerprint},
            "properties": {"tool": f.source.value, "severity": f.severity.value},
        }
        if f.fingerprint in ignored:
            result["suppressions"] = [{"kind": "external", "justification": ignored[f.fingerprint]}]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "iac-guard",
                "informationUri": INFORMATION_URI,
                "semanticVersion": __version__,
                "version": __version__,
                "rules": rule_defs,
            }},
            "results": results,
        }],
    }
