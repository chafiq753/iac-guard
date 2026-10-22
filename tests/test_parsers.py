"""Parsers : sortie brute de chaque scanner -> findings normalisés."""

from __future__ import annotations

from iacguard.parsers import (
    PARSERS,
    parse_checkov,
    parse_conftest,
    parse_gitleaks,
    parse_semgrep,
)
from iacguard.schema import Category, Severity, ToolName


def test_gitleaks_secrets_are_critical(gitleaks_sample) -> None:
    findings = parse_gitleaks(gitleaks_sample)
    assert len(findings) == 2
    assert {f.rule_id for f in findings} == {"aws-access-token", "generic-api-key"}
    assert all(f.severity is Severity.CRITICAL for f in findings)
    assert all(f.category is Category.SECRET for f in findings)
    assert all(f.source is ToolName.GITLEAKS for f in findings)


def test_checkov_severity_and_lines(checkov_sample) -> None:
    findings = {f.rule_id: f for f in parse_checkov(checkov_sample)}
    assert set(findings) == {"CKV_AWS_21", "CKV_AWS_23", "CKV_AWS_79"}
    assert findings["CKV_AWS_21"].severity is Severity.LOW
    assert findings["CKV_AWS_79"].severity is Severity.HIGH
    # Sans sévérité (cas normal hors plateforme Prisma) -> MEDIUM.
    assert findings["CKV_AWS_23"].severity is Severity.MEDIUM
    assert (findings["CKV_AWS_21"].line_start, findings["CKV_AWS_21"].line_end) == (12, 18)


def test_checkov_list_output_is_flattened(checkov_sample) -> None:
    # Plusieurs frameworks -> Checkov renvoie une liste de rapports.
    findings = parse_checkov([checkov_sample, checkov_sample])
    assert len(findings) == 6


def test_checkov_summary_only_output_gives_no_findings() -> None:
    # Aucun fichier supporté : Checkov renvoie un résumé à plat, sans `results`.
    assert parse_checkov({"passed": 0, "failed": 0, "checkov_version": "3.3.30"}) == []


def test_conftest_failures_and_warnings(conftest_sample) -> None:
    findings = parse_conftest(conftest_sample)
    by_rule = {f.rule_id: f for f in findings}
    assert len(findings) == 3
    assert by_rule["IAC_RDS_ENCRYPTION"].severity is Severity.CRITICAL  # metadata Rego
    assert by_rule["IAC_S3_TAGGING"].severity is Severity.LOW
    assert all(f.category is Category.POLICY for f in findings)


def test_semgrep_severity_mapping(semgrep_sample) -> None:
    findings = parse_semgrep(semgrep_sample)
    assert [f.severity for f in findings] == [Severity.HIGH, Severity.MEDIUM]
    # Seule la première ligne du message sert de titre.
    assert findings[0].title == "Requête SQL construite par formatage de chaîne."
    assert findings[1].remediation == "escape()"
    assert (findings[1].line_start, findings[1].line_end) == (3, 4)


def test_empty_inputs_give_no_findings() -> None:
    for parser in PARSERS.values():
        assert parser(None) == []
        assert parser([]) == []
