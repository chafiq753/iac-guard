"""Envoi d'e-mails transactionnels — STUB.

Comme `forgot_password` (voir app/api/auth.py) : aucun fournisseur (Resend,
SendGrid...) n'est branché pour l'instant. En attendant, on journalise le
lien pour pouvoir tester le flux d'invitation en dev/local sans dépendance
externe. À remplacer par un vrai envoi avant la mise en prod — le call site
(`send_invitation_email`) ne changera pas, seule son implémentation le sera.
"""

from __future__ import annotations

import logging

from app.core.config import settings

logger = logging.getLogger("iacguard.email")


def send_invitation_email(*, to_email: str, token: str, inviter_name: str) -> None:
    link = f"{settings.frontend_url}/accept-invite?token={token}"
    # WARNING et non INFO : le niveau par défaut de Python filtre INFO, et le
    # lien serait alors invisible dans la console — or c'est aujourd'hui le
    # SEUL moyen de le récupérer. C'en est un, d'avertissement : un lien
    # d'activation en clair dans les logs ne doit pas passer en prod.
    logger.warning(
        "AUCUN SMTP CONFIGURÉ — invitation pour %s (par %s) non envoyée. "
        "Lien d'activation à transmettre manuellement : %s",
        to_email,
        inviter_name,
        link,
    )
