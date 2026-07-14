"""Tests des tokens projet (app/core/security.py)."""

from __future__ import annotations

from app.core.security import (
    TOKEN_PREFIX,
    generate_project_token,
    hash_token,
    token_preview,
)


def test_generated_token_has_prefix_and_is_unique() -> None:
    t1 = generate_project_token()
    t2 = generate_project_token()
    assert t1.startswith(TOKEN_PREFIX)
    assert t1 != t2
    assert len(t1) > len(TOKEN_PREFIX) + 20  # partie aléatoire non triviale


def test_hash_is_deterministic_and_hides_token() -> None:
    token = generate_project_token()
    h1 = hash_token(token)
    h2 = hash_token(token)
    assert h1 == h2                 # déterministe -> comparable en base
    assert h1 != token              # ne révèle pas le token
    assert len(h1) == 64            # SHA-256 en hexadécimal


def test_different_tokens_hash_differently() -> None:
    assert hash_token(generate_project_token()) != hash_token(
        generate_project_token()
    )


def test_preview_shows_prefix_only() -> None:
    token = "iacg_ABCDEF1234567890"
    preview = token_preview(token)
    assert preview.startswith("iacg_ABCD")
    assert preview.endswith("…")
    # Le preview ne doit pas divulguer la fin du token.
    assert "567890" not in preview
