"""Configuration centrale de l'application (variables d'environnement)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Nom de l'app
    app_name: str = "iac-guard"

    # Base de données.
    # Par défaut SQLite (dev, aucun service à lancer). En prod on met une URL
    # PostgreSQL : postgresql+psycopg://user:pass@host:5432/iacguard
    database_url: str = "sqlite:///./iacguard.db"

    # Clé secrète pour signer les JWT utilisateurs (à changer en prod).
    secret_key: str = "dev-secret-change-me"
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


settings = Settings()
