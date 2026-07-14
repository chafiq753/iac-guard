"""Pose et retrait des cookies de session / MFA.

Pourquoi un cookie httpOnly plutôt qu'un token en localStorage : `httponly=True`
rend le cookie invisible au JavaScript. Une faille XSS sur le dashboard ne peut
donc PAS exfiltrer la session. En localStorage, le moindre script injecté la vole.

`samesite="lax"` : le navigateur n'envoie pas le cookie sur une requête POST
venue d'un autre site, ce qui neutralise l'essentiel des attaques CSRF.
"""

from __future__ import annotations

from fastapi import Response

from app.core.config import settings


def set_session_cookie(response: Response, token: str) -> None:
    """Ouvre la session : 2FA validée (ou non requise)."""
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,  # True en prod (HTTPS obligatoire)
        samesite=settings.cookie_samesite,
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )
    # Le cookie MFA a rempli son rôle : on le retire.
    clear_mfa_cookie(response)


def set_mfa_cookie(response: Response, token: str) -> None:
    """Étape intermédiaire : mot de passe OK, second facteur attendu."""
    response.set_cookie(
        key=settings.mfa_cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.mfa_token_expire_minutes * 60,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def clear_mfa_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.mfa_cookie_name,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
