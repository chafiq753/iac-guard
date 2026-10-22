"""Table de gravité Checkov propre à iac-guard."""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from iacguard.schema import Severity
from iacguard.severity import CHECKOV_SEVERITY, checkov_default_severity

_ID = re.compile(r"^CKV2?_[A-Z0-9]+_\d+$")


def test_table_ids_are_well_formed() -> None:
    bad = [i for i in CHECKOV_SEVERITY if not _ID.match(i)]
    assert bad == []


def test_medium_is_never_listed_explicitly() -> None:
    # MEDIUM est la valeur par défaut : la lister serait du bruit.
    assert Severity.MEDIUM not in CHECKOV_SEVERITY.values()


def test_internet_exposures_are_at_least_high() -> None:
    for rule in ("CKV_AWS_20", "CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_17", "CKV_AWS_277"):
        assert checkov_default_severity(rule) in (Severity.HIGH, Severity.CRITICAL), rule


@pytest.mark.integration
@pytest.mark.skipif(not shutil.which("checkov"), reason="checkov non installé")
def test_every_rule_exists_in_installed_checkov() -> None:
    # Une faute de frappe dans la table = une règle grave restée en MEDIUM.
    out = subprocess.run(
        [shutil.which("checkov"), "--list"],  # type: ignore[list-item]
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=300, check=False,
    ).stdout
    known = set(re.findall(r"\|\s*(CKV2?_[A-Z0-9]+_\d+)\s*\|", out))
    assert known, "checkov --list n'a renvoyé aucune règle"
    missing = sorted(set(CHECKOV_SEVERITY) - known)
    assert missing == []
