"""Configuration centrale de l'application (variables d'environnement)."""

from __future__ import annotations

import logging
import secrets

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("iacguard.config")

# Valeur de `secret_key` livrée avec le dépôt. Elle est publique par
# construction : quiconque lit le code la connaît. Un JWT signé avec elle est
# donc forgeable par n'importe qui — d'où le refus de démarrer en production.
DEV_SECRET_KEY = "dev-secret-change-me"

# En dessous de cette longueur, une clé HS256 devient attaquable hors ligne.
MIN_SECRET_KEY_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Nom de l'app
    app_name: str = "iac-guard"

    # "development" ou "production". Pilote les garde-fous ci-dessous : en
    # production, un secret faible ou par défaut empêche le démarrage.
    environment: str = "development"

    # Base de données.
    # Par défaut SQLite (dev, aucun service à lancer). En prod on met une URL
    # PostgreSQL : postgresql+psycopg://user:pass@host:5432/iacguard
    database_url: str = "sqlite:///./iacguard.db"

    # Clé secrète pour signer les JWT utilisateurs.
    # Générer une valeur propre avec : python -c "import secrets;
    # print(secrets.token_urlsafe(48))"
    secret_key: str = DEV_SECRET_KEY
    access_token_expire_minutes: int = 60 * 24

    # Origines autorisées pour le frontend (CORS).
    # Doit être une liste EXPLICITE (jamais "*") : les cookies de session ne
    # sont envoyés qu'avec `allow_credentials=True`, incompatible avec "*".
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # --- Session (cookie) -------------------------------------------------- #
    # Le JWT est déposé dans un cookie httpOnly : JavaScript ne peut pas le
    # lire, donc une faille XSS ne permet pas de voler la session.
    session_cookie_name: str = "iacguard_session"
    mfa_cookie_name: str = "iacguard_mfa"
    # `secure=True` impose HTTPS. False en dev (http://localhost), True en prod.
    cookie_secure: bool = False
    # "lax" : le cookie n'est pas envoyé sur les requêtes cross-site POST,
    # ce qui bloque l'essentiel des attaques CSRF.
    cookie_samesite: str = "lax"

    # Jeton intermédiaire entre "mot de passe validé" et "2FA validée".
    # Volontairement court : il ne donne accès à rien d'autre qu'à la 2FA.
    mfa_token_expire_minutes: int = 5

    # --- Anti-brute-force -------------------------------------------------- #
    max_login_attempts: int = 5
    lockout_minutes: int = 15

    # --- WebAuthn (biométrie / passkey) ------------------------------------ #
    # rp_id = domaine "propriétaire" de la clé. Il doit être le domaine du
    # FRONTEND (ou un de ses parents), pas celui de l'API. C'est ce qui rend
    # les passkeys résistantes au phishing : une clé créée pour `localhost`
    # ne peut pas être utilisée par un site pirate.
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "iac-guard"
    # Origines exactes autorisées à présenter une assertion WebAuthn.
    webauthn_origins: list[str] = ["http://localhost:3000"]

    # --- Comptes admin / invitations ---------------------------------------- #
    # URL du dashboard : sert à construire le lien d'invitation dans l'e-mail.
    frontend_url: str = "http://localhost:3000"
    invitation_expire_hours: int = 72
    # Anti-spam sur POST /api/admin/users/invite : au-delà, un admin doit
    # attendre. Compté sur les entrées "user.invited" de admin_audit_logs.
    max_invites_per_hour: int = 10

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() in ("production", "prod")

    @model_validator(mode="after")
    def _verifier_secrets(self) -> "Settings":
        """Refuse de démarrer en production avec une configuration dangereuse.

        Le code de ce dépôt est public : la clé par défaut l'est donc aussi.
        Démarrer en production avec elle laisserait n'importe qui forger un
        jeton de session valide — sans mot de passe ni second facteur. Mieux
        vaut un démarrage qui échoue bruyamment qu'une authentification qui
        semble fonctionner tout en étant contournable.
        """
        faible = (
            self.secret_key == DEV_SECRET_KEY
            or len(self.secret_key) < MIN_SECRET_KEY_LENGTH
        )

        if self.is_production:
            if faible:
                raise ValueError(
                    "SECRET_KEY absente, trop courte ou laissée à sa valeur par "
                    f"défaut alors que ENVIRONMENT=production. Il faut au moins "
                    f"{MIN_SECRET_KEY_LENGTH} caractères. Générer une clé avec :\n"
                    '    python -c "import secrets; print(secrets.token_urlsafe(48))"'
                )
            if not self.cookie_secure:
                raise ValueError(
                    "COOKIE_SECURE doit valoir true en production : sans HTTPS "
                    "imposé, le cookie de session circule en clair."
                )
        elif faible:
            # En développement on ne bloque pas, mais on le dit : cette ligne
            # doit sauter aux yeux dans les logs.
            logger.warning(
                "Clé de signature de développement utilisée. Ne JAMAIS déployer "
                "ainsi : définir SECRET_KEY et ENVIRONMENT=production."
            )
        return self


def generer_secret_key() -> str:
    """Clé adaptée à HS256, à placer dans la variable SECRET_KEY."""
    return secrets.token_urlsafe(48)


settings = Settings()
