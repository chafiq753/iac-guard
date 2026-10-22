"""Données de démonstration iac-guard — BASE LOCALE DE DÉVELOPPEMENT UNIQUEMENT.

Alimente la base locale (Postgres de docker compose par défaut) avec une
organisation fictive, 5 comptes (un par rôle), 4 projets et leur historique de
scans, pour les captures d'écran de soutenance.

Principe : AUCUNE valeur métier n'est écrite à la main. Le script pilote
l'application réelle :
  - les findings partent du format BRUT de chaque outil (JSON Gitleaks /
    Checkov / Conftest / Semgrep), passent par les parsers de l'aggregator du
    pipeline (qui calculent le fingerprint), puis sont POSTés sur /api/scans
    avec le token du projet ;
  - score, grade et should_fail sont calculés par l'API ;
  - comptes, rôles, accès, triage, TOTP : via les routes HTTP de l'API, donc
    avec leurs contrôles RBAC et leurs écritures d'audit.

L'API est appelée en mémoire (FastAPI TestClient) sur la même base que celle
du conteneur : mêmes routes, mêmes dépendances, même base. Seule exception :
l'e-mail d'invitation (stub qui journalise le lien) est intercepté DANS CE
PROCESSUS pour récupérer le lien d'activation, comme le ferait un capteur de
mails de dev. Aucun fichier de l'application n'est modifié.

Usage (depuis la racine iac-guard/, stack lancée par `docker compose up -d`).
Dans un conteneur jetable du réseau compose (PowerShell) — recommandé si un
PostgreSQL natif occupe déjà le port 5432 de l'hôte :

    docker compose run --rm --no-deps -v "${PWD}:/demo" -w /demo api `
        sh -c "pip install -q httpx && python scripts/seed_demo.py"

Ou directement sur l'hôte (dépendances backend + httpx installées) :

    python scripts/seed_demo.py           # crée / complète (idempotent)
    python scripts/seed_demo.py --reset   # explique le nettoyage, n'efface rien

Variable optionnelle : DATABASE_URL (défaut : Postgres de docker compose sur
localhost:5432).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
AGGREGATOR = ROOT / "pipeline" / "aggregator"

DEFAULT_DATABASE_URL = "postgresql+psycopg://iacguard:iacguard@localhost:5432/iacguard"
# Lancement dans un conteneur jetable du réseau compose (la base y est `db`) :
# utile quand un PostgreSQL natif occupe déjà le port 5432 de l'hôte.
DOCKER_SEED_CMD = (
    'docker compose run --rm --no-deps -v "${PWD}:/demo" -w /demo api '
    'sh -c "pip install -q httpx && python scripts/seed_demo.py"'
)
# Hôtes acceptés : la machine locale, ou le service `db` de docker compose.
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "db"}

DEMO_ORG = "Demo Org"
DEMO_PASSWORD = "Demo-IacGuard-2026!"

# email, nom affiché, rôle FINAL, rôle à l'invitation.
# Le viewer est d'abord invité admin puis rétrogradé : c'est ce qui produit
# l'entrée d'audit « changement de rôle admin -> viewer ».
USERS = [
    ("demo.admin@example.com", "Salma Bennani", "admin", None),
    ("demo.secops@example.com", "Youssef Alaoui", "security_lead", "security_lead"),
    ("demo.dev@example.com", "Inès Tazi", "developer", "developer"),
    ("demo.audit@example.com", "Karim El Idrissi", "auditor", "auditor"),
    ("demo.viewer@example.com", "Nadia Berrada", "viewer", "admin"),
]
ADMIN_EMAIL = USERS[0][0]
SECOPS_EMAIL = USERS[1][0]

# Auteurs de commits fictifs (domaine example.com uniquement).
AUTHORS = [
    ("Inès Tazi", "ines.tazi@example.com"),
    ("Omar Chraibi", "omar.chraibi@example.com"),
    ("Leila Fassi", "leila.fassi@example.com"),
    ("Mehdi Squalli", "mehdi.squalli@example.com"),
]


# --------------------------------------------------------------------------- #
# Garde-fou : base locale uniquement (vérifié AVANT d'importer l'application)
# --------------------------------------------------------------------------- #


def check_local_database() -> str:
    url = os.environ.setdefault("DATABASE_URL", DEFAULT_DATABASE_URL)
    env = os.environ.get("ENVIRONMENT", "development").strip().lower()
    if env in ("production", "prod"):
        sys.exit("REFUS : ENVIRONMENT=production. Ce script ne vise que la base locale.")

    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    if parsed.drivername.startswith("sqlite"):
        return url
    if (parsed.host or "").lower() not in LOCAL_HOSTS:
        sys.exit(
            f"REFUS : la base '{parsed.host}' n'est pas locale. Hôtes acceptés : "
            f"{', '.join(sorted(LOCAL_HOSTS))} (ou un fichier SQLite)."
        )
    return url


# --------------------------------------------------------------------------- #
# Catalogue des findings (format brut de chaque outil)
# --------------------------------------------------------------------------- #
# Une entrée = (outil, règle, sévérité, fichier, ligne, ressource, titre).
# La sévérité Checkov est celle de la plateforme Prisma (champ `severity`) ;
# Gitleaks n'en a pas (l'aggregator le classe CRITICAL) ; Semgrep utilise
# ERROR/WARNING ; Conftest la porte dans la metadata Rego.


def ck(rule, sev, file, line, resource, title):
    return ("checkov", rule, sev, file, line, resource, title)


def gl(rule, file, line, title, match):
    return ("gitleaks", rule, None, file, line, match, title)


def sg(rule, sev, file, line, title):
    return ("semgrep", rule, sev, file, line, None, title)


def cf(rule, sev, file, resource, title):
    return ("conftest", rule, sev, file, None, resource, title)


# --- app-infra ------------------------------------------------------------- #
AI_C1 = gl("aws-access-token", "providers.tf", 5, "AWS Access Key",
           'access_key = "AKIAIOSFODNN7EXAMPLE"')
AI_H1 = ck("CKV_AWS_24", "HIGH", "/network.tf", 12, "aws_security_group.bastion",
           "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22")
AI_H2 = ck("CKV_AWS_20", "HIGH", "/s3.tf", 3, "aws_s3_bucket.assets",
           "S3 Bucket has an ACL defined which allows public READ access.")
AI_M1 = ck("CKV_AWS_21", "MEDIUM", "/s3.tf", 9, "aws_s3_bucket.backups",
           "Ensure all data stored in the S3 bucket have versioning enabled")
AI_M2 = ck("CKV_AWS_18", "MEDIUM", "/s3.tf", 3, "aws_s3_bucket.assets",
           "Ensure the S3 bucket has access logging enabled")
AI_M3 = ck("CKV_AWS_23", "MEDIUM", "/network.tf", 12, "aws_security_group.bastion",
           "Ensure every security group and rule has a description")
AI_M4 = ck("CKV_AWS_126", "MEDIUM", "/compute.tf", 1, "aws_instance.bastion",
           "Ensure that detailed monitoring is enabled for EC2 instances")
AI_L1 = ck("CKV2_AWS_5", "LOW", "/network.tf", 30, "aws_security_group.legacy",
           "Ensure that Security Groups are attached to another resource")
AI_L2 = ck("CKV_AWS_135", "LOW", "/compute.tf", 1, "aws_instance.bastion",
           "Ensure that EC2 is EBS optimized")

# Le scan de la PR feature/add-rds : exactement 5 findings sur main.tf.
PR_FINDINGS = [
    gl("generic-api-key", "main.tf", 6,
       "Mot de passe en clair dans la ressource aws_db_instance",
       'password = "Sup3rS3cret-RDS-2026"'),
    ck("CKV_AWS_16", "MEDIUM", "/main.tf", 7, "aws_db_instance.app",
       "Ensure all data stored in the RDS is securely encrypted at rest"),
    ck("CKV_AWS_17", "HIGH", "/main.tf", 8, "aws_db_instance.app",
       "Ensure all data stored in RDS is not publicly accessible"),
    ck("CKV_AWS_24", "HIGH", "/main.tf", 16, "aws_security_group.db_admin",
       "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"),
    ck("CKV_AWS_63", "HIGH", "/main.tf", 23, "aws_iam_policy.rds_admin",
       'Ensure no IAM policies documents allow "*" as a statement\'s actions'),
]

# --- api-paiement ---------------------------------------------------------- #
AP_H1 = sg("python.lang.security.audit.formatted-sql-query.formatted-sql-query",
           "ERROR", "app/payments/repository.py", 58,
           "Detected possible formatted SQL query. Use parameterized queries instead.")
AP_M1 = ck("CKV_AWS_158", "MEDIUM", "/infra/logs.tf", 4, "aws_cloudwatch_log_group.api",
           "Ensure that CloudWatch Log Group is encrypted by KMS")
AP_M2 = ck("CKV_AWS_338", "MEDIUM", "/infra/logs.tf", 4, "aws_cloudwatch_log_group.api",
           "Ensure CloudWatch log groups retains logs for at least 1 year")
AP_M3 = sg("javascript.express.security.audit.express-cookie-session-no-httponly."
           "express-cookie-session-no-httponly", "WARNING", "web/session.js", 18,
           "A cookie was detected without setting the 'httpOnly' flag.")
AP_L1 = ck("CKV_AWS_117", "LOW", "/infra/lambda.tf", 1, "aws_lambda_function.webhook",
           "Ensure that AWS Lambda function is configured inside a VPC")
AP_L2 = ck("CKV_AWS_116", "LOW", "/infra/lambda.tf", 1, "aws_lambda_function.webhook",
           "Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ)")

# --- portail-client -------------------------------------------------------- #
PC_H1 = ck("CKV_AWS_2", "HIGH", "/alb.tf", 14, "aws_lb_listener.http",
           "Ensure ALB protocol is HTTPS")
PC_H2 = ck("CKV_AWS_86", "HIGH", "/cdn.tf", 1, "aws_cloudfront_distribution.portal",
           "Ensure CloudFront distribution has Access Logging enabled")
PC_M1 = ck("CKV_AWS_91", "MEDIUM", "/alb.tf", 1, "aws_lb.portal",
           "Ensure the ELBv2 (Application/Network) has access logging enabled")
PC_M2 = ck("CKV_AWS_150", "MEDIUM", "/alb.tf", 1, "aws_lb.portal",
           "Ensure that Load Balancer has deletion protection enabled")
PC_M3 = cf("tags.required", "medium", "cdn.tf", "aws_cloudfront_distribution.portal",
           "Ressource sans tags obligatoires (owner, cost-center)")
PC_L1 = ck("CKV_AWS_131", "LOW", "/alb.tf", 1, "aws_lb.portal",
           "Ensure that ALB drops HTTP headers")
PC_L2 = ck("CKV2_AWS_28", "LOW", "/alb.tf", 1, "aws_lb.portal",
           "Ensure public facing ALB are protected by WAF")

# --- data-lake ------------------------------------------------------------- #
DL_H1 = ck("CKV_AWS_19", "HIGH", "/buckets.tf", 1, "aws_s3_bucket.raw_zone",
           "Ensure all data stored in the S3 bucket is securely encrypted at rest")
DL_H2 = ck("CKV_AWS_53", "HIGH", "/buckets.tf", 20, "aws_s3_bucket_public_access_block.curated",
           "Ensure S3 bucket has block public ACLS enabled")
DL_H3 = ck("CKV_AWS_7", "HIGH", "/kms.tf", 1, "aws_kms_key.lake",
           "Ensure rotation for customer created CMKs is enabled")
DL_M1 = ck("CKV_AWS_144", "MEDIUM", "/buckets.tf", 1, "aws_s3_bucket.raw_zone",
           "Ensure that S3 bucket has cross-region replication enabled")
DL_M2 = ck("CKV_AWS_18", "MEDIUM", "/buckets.tf", 40, "aws_s3_bucket.access_logs",
           "Ensure the S3 bucket has access logging enabled")
DL_M3 = ck("CKV_AWS_21", "MEDIUM", "/buckets.tf", 1, "aws_s3_bucket.raw_zone",
           "Ensure all data stored in the S3 bucket have versioning enabled")
DL_M4 = ck("CKV_AWS_145", "MEDIUM", "/buckets.tf", 30, "aws_s3_bucket.curated",
           "Ensure that S3 buckets are encrypted with KMS by default")
DL_M5 = cf("tags.data_classification", "medium", "glue.tf", "aws_glue_catalog_database.lake",
           "Base Glue sans tag de classification des données (CNDP)")
DL_M6 = ck("CKV_AWS_195", "MEDIUM", "/glue.tf", 12, "aws_glue_crawler.raw",
           "Ensure Glue component has a security configuration associated")
DL_L1 = ck("CKV2_AWS_62", "LOW", "/buckets.tf", 30, "aws_s3_bucket.curated",
           "Ensure S3 buckets should have event notifications enabled")
DL_L2 = ck("CKV2_AWS_61", "LOW", "/buckets.tf", 40, "aws_s3_bucket.access_logs",
           "Ensure that an S3 bucket has a lifecycle configuration")

# Triage data-lake (sur le dernier scan) : (finding, statut, justification).
TRIAGE = [
    (DL_M1, "acknowledged",
     "Risque accepté : la réplication inter-régions n'est pas requise pour la "
     "raw-zone — les données sont reproductibles depuis les sources (topics "
     "Kafka rejouables 7 jours). Coût jugé disproportionné au regard du "
     "risque. Validé en comité sécurité, revue prévue au T1 2027."),
    (DL_M2, "false_positive",
     "Faux positif : ce bucket EST la cible des journaux d'accès S3. Activer la "
     "journalisation sur lui-même créerait une boucle de logs."),
]

# Scans : (jours avant aujourd'hui, heure, branche, findings).
NOW = datetime.now(timezone.utc).replace(second=0, microsecond=0)

PROJECTS = [
    {
        "name": "app-infra",
        "repo": "demo-org/app-infra",
        "fail_on_severity": "high",
        "scans": [
            (29, "09:42", "main", [AI_C1, AI_M1, AI_M2, AI_M3]),                      # 66
            (24, "14:05", "main", [AI_H1, AI_H2, AI_M1, AI_M2, AI_M3, AI_L1, AI_L2]),  # 69
            (18, "10:31", "main", [AI_H1, AI_H2, AI_M1, AI_M2, AI_L1, AI_L2]),         # 72
            (13, "16:48", "main", [AI_H1, AI_H2, AI_M1, AI_M2]),                       # 74
            (8, "11:12", "main", [AI_H1, AI_H2, AI_M1]),                               # 77
            (3, "15:26", "main", [AI_H1, AI_M1, AI_M2, AI_M4, AI_L1]),                 # 80
            (0, None, "feature/add-rds", PR_FINDINGS),                                 # 42
        ],
    },
    {
        "name": "api-paiement",
        "repo": "demo-org/api-paiement",
        "fail_on_severity": "critical",
        "scans": [
            (27, "10:02", "main", [AP_H1, AP_L1, AP_L2]),          # 88
            (19, "13:37", "main", [AP_M1, AP_M2, AP_M3]),          # 91
            (11, "09:15", "main", [AP_M1, AP_M2, AP_L1]),          # 93
            (4, "17:21", "main", [AP_M1, AP_M2]),                  # 94
        ],
    },
    {
        "name": "portail-client",
        "repo": "demo-org/portail-client",
        "fail_on_severity": "critical",
        "scans": [
            (26, "11:44", "main", [PC_H1, PC_H2, PC_M1, PC_M2]),                # 74
            (17, "15:09", "main", [PC_H1, PC_H2, PC_M1]),                       # 77
            (9, "10:53", "main", [PC_H1, PC_M1, PC_M2, PC_M3, PC_L1, PC_L2]),   # 79
            (2, "14:30", "main", [PC_H1, PC_M1, PC_M2, PC_M3, PC_L1]),          # 80
        ],
    },
    {
        "name": "data-lake",
        "repo": "demo-org/data-lake",
        "fail_on_severity": None,
        "scans": [
            (28, "08:58", "main", [DL_H1, DL_H2, DL_H3, DL_M1, DL_M2, DL_M3, DL_M4]),   # 58
            (21, "12:20", "main", [DL_H1, DL_H2, DL_H3, DL_M1, DL_M2, DL_M3]),          # 61
            (12, "16:05", "main", [DL_H1, DL_H2, DL_M1, DL_M2, DL_M3, DL_M5, DL_M6,
                                   DL_L1, DL_L2]),                                       # 63
            (1, "10:40", "main", [DL_H1, DL_H2, DL_M1, DL_M2, DL_M3, DL_M5, DL_M6,
                                  DL_L1]),                                               # 64
        ],
    },
]

# Accès explicites (rôles sans accès global).
PROJECT_ACCESS = {
    "demo.dev@example.com": ["app-infra", "api-paiement"],
    "demo.audit@example.com": ["app-infra", "api-paiement", "portail-client", "data-lake"],
    "demo.viewer@example.com": ["portail-client"],
}
WEBAUTHN_RESET_TARGET = "demo.dev@example.com"


def scan_time(days_ago: int, hhmm: str | None) -> datetime:
    if hhmm is None:  # le scan de la PR : il y a une heure, donc le plus récent
        return NOW - timedelta(hours=1)
    h, m = map(int, hhmm.split(":"))
    day = (NOW - timedelta(days=days_ago)).replace(hour=h, minute=m)
    return min(day, NOW - timedelta(hours=2))


def commit_sha(project: str, index: int) -> str:
    return hashlib.sha1(f"iacguard-demo:{project}:{index}".encode()).hexdigest()


def raw_tool_outputs(findings, sha: str, when: datetime, author: tuple[str, str]):
    """Construit les JSON bruts tels que les produisent les outils."""
    gitleaks, checkov, conftest, semgrep = [], [], [], []
    for tool, rule, sev, file, line, extra, title in findings:
        if tool == "gitleaks":
            gitleaks.append({
                "Description": title, "StartLine": line, "EndLine": line,
                "StartColumn": 3, "EndColumn": 3 + len(extra), "Match": extra,
                "Secret": "REDACTED", "File": file, "SymlinkFile": "",
                "Commit": sha, "Entropy": 3.92, "Author": author[0], "Email": author[1],
                "Date": when.isoformat().replace("+00:00", "Z"),
                "Message": "feat: add RDS instance for orders service"
                if file == "main.tf" else "chore: provider config",
                "Tags": [], "RuleID": rule, "Fingerprint": f"{sha}:{file}:{rule}:{line}",
            })
        elif tool == "checkov":
            checkov.append({
                "check_id": rule, "check_name": title,
                "check_result": {"result": "FAILED"},
                "file_path": file, "repo_file_path": file,
                "file_line_range": [line, line], "resource": extra,
                "severity": sev,
                "guideline": "https://docs.prismacloud.io/en/enterprise-edition/"
                             "policy-reference/aws-policies",
            })
        elif tool == "semgrep":
            semgrep.append({
                "check_id": rule, "path": file,
                "start": {"line": line, "col": 5}, "end": {"line": line, "col": 60},
                "extra": {"message": title, "severity": sev, "metadata": {}},
            })
        elif tool == "conftest":
            conftest.append({"filename": file, "namespace": "main", "failures": [{
                "msg": title,
                "metadata": {"rule_id": rule, "title": title, "severity": sev,
                             "resource": extra,
                             "remediation": "Ajouter les tags requis par la politique."},
            }]})
    checkov_doc = ({"check_type": "terraform", "results": {"failed_checks": checkov},
                    "summary": {"checkov_version": "3.2.255"}} if checkov else None)
    semgrep_doc = {"version": "1.78.0", "results": semgrep} if semgrep else None
    return gitleaks or None, checkov_doc, conftest or None, semgrep_doc


# --------------------------------------------------------------------------- #
# Client API (en mémoire)
# --------------------------------------------------------------------------- #


class Api:
    """Un client HTTP par utilisateur : chacun a son propre cookie de session."""

    def __init__(self, app, label: str):
        from fastapi.testclient import TestClient

        self.c = TestClient(app)
        self.label = label

    def call(self, method: str, path: str, expect=(200, 201, 204), **kw):
        resp = self.c.request(method, path, **kw)
        if resp.status_code not in expect:
            raise RuntimeError(
                f"[{self.label}] {method} {path} -> HTTP {resp.status_code} : {resp.text}"
            )
        return resp.json() if resp.content else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--reset", action="store_true",
                        help="Nettoyage des données de démo (voir l'explication)")
    args = parser.parse_args()

    db_url = check_local_database()
    os.environ.setdefault("ENVIRONMENT", "development")
    sys.path[:0] = [str(BACKEND), str(AGGREGATOR)]

    # Imports APRÈS le garde-fou : la config de l'app lit DATABASE_URL à l'import.
    import pyotp
    from sqlalchemy import func, select

    import aggregator
    import app.api.admin as admin_routes
    from app.db.session import SessionLocal
    from app.main import app
    from app.models.admin_audit_log import AdminAuditLog
    from app.models.audit_log import TriageAuditLog
    from app.models.organization import Organization
    from app.models.project import Project
    from app.models.project_access import ProjectAccess
    from app.models.scan import Scan
    from app.models.triage import FindingTriage
    from app.models.user import User
    from schema import ScanMeta, ScanReport, ToolInfo, ToolName

    print(f"Base cible : {db_url.split('@')[-1]}")

    if args.reset:
        return reset_info(SessionLocal, Organization, User, Project, Scan,
                          AdminAuditLog, TriageAuditLog, func, select)

    # Lecture seule, pour l'idempotence uniquement (aucune écriture directe).
    def db_user(email):
        with SessionLocal() as s:
            return s.scalar(select(User).where(User.email == email))

    # --- Capteur d'invitations (stub e-mail du processus courant) --------- #
    invite_links: dict[str, str] = {}

    def capture_invitation(*, to_email: str, token: str, inviter_name: str) -> None:
        invite_links[to_email] = token

    admin_routes.send_invitation_email = capture_invitation

    def login(email: str) -> Api:
        """Connexion par la vraie route (avec 2FA TOTP si elle est active)."""
        api = Api(app, email)
        res = api.call("POST", "/api/auth/login",
                       json={"email": email, "password": DEMO_PASSWORD})
        if res.get("mfa_required"):
            secret = db_user(email).totp_secret
            api.call("POST", "/api/auth/2fa/totp/verify",
                     json={"code": pyotp.TOTP(secret).now()})
        return api

    # --- 1. Admin + organisation ---------------------------------------- #
    if db_user(ADMIN_EMAIL) is None:
        Api(app, "register").call("POST", "/api/auth/register", json={
            "email": ADMIN_EMAIL, "password": DEMO_PASSWORD, "org_name": DEMO_ORG})
        print(f"+ compte {ADMIN_EMAIL} (admin, organisation « {DEMO_ORG} »)")
    admin = login(ADMIN_EMAIL)
    admin_user = db_user(ADMIN_EMAIL)
    if admin_user.role != "admin":
        sys.exit(f"{ADMIN_EMAIL} existe mais n'est plus admin : lancez --reset.")

    # --- 2. Invitations (un compte par rôle) ------------------------------ #
    for email, _name, _final, invite_role in USERS[1:]:
        u = db_user(email)
        if u is not None and u.hashed_password is not None:
            continue
        admin.call("POST", "/api/admin/users/invite",
                   json={"email": email, "role": invite_role})
        Api(app, "invite").call("POST", f"/api/admin/invitations/{invite_links[email]}/accept",
                                json={"password": DEMO_PASSWORD})
        print(f"+ compte {email} (invité en tant que {invite_role}, invitation acceptée)")

    # Noms affichés (route profil de chaque utilisateur) + connexions.
    sessions: dict[str, Api] = {}
    for email, name, _final, _inv in USERS:
        api = admin if email == ADMIN_EMAIL else login(email)
        sessions[email] = api
        if db_user(email).name != name:
            api.call("PATCH", "/api/auth/me", json={"name": name})

    # --- 3. Changement de rôle admin -> viewer ---------------------------- #
    for email, _name, final_role, _inv in USERS[1:]:
        u = db_user(email)
        if u.role != final_role:
            admin.call("PATCH", f"/api/admin/users/{u.id}/role", json={"role": final_role})
            print(f"~ rôle de {email} : {u.role} -> {final_role}")

    # --- 4. 2FA TOTP pour le security_lead (écran MFA des captures) ------- #
    if not db_user(SECOPS_EMAIL).totp_enabled:
        secops = sessions[SECOPS_EMAIL]
        setup = secops.call("POST", "/api/auth/2fa/totp/setup")
        secops.call("POST", "/api/auth/2fa/totp/confirm",
                    json={"code": pyotp.TOTP(setup["secret"]).now()})
        print(f"+ TOTP activé pour {SECOPS_EMAIL}")

    # --- 5. Projets, politiques, scans ------------------------------------ #
    existing = {p["name"]: p for p in admin.call("GET", "/api/projects")}
    project_ids: dict[str, int] = {}
    responses: dict[str, dict] = {}

    for spec in PROJECTS:
        name = spec["name"]
        token = None
        if name in existing:
            pid = existing[name]["id"]
        else:
            created = admin.call("POST", "/api/projects", json={"name": name})
            pid, token = created["id"], created["token"]
            print(f"+ projet {name}")
        project_ids[name] = pid

        policy = admin.call("GET", f"/api/projects/{pid}/policy")
        if policy["fail_on_severity"] != spec["fail_on_severity"]:
            admin.call("PATCH", f"/api/projects/{pid}/policy",
                       json={"fail_on_severity": spec["fail_on_severity"]})

        known = {s["commit_sha"] for s in admin.call("GET", f"/api/projects/{pid}/scans")}
        for i, (days, hhmm, branch, findings) in enumerate(spec["scans"]):
            sha = commit_sha(name, i)
            if sha in known:
                continue
            if token is None:
                # Le token n'est jamais relisible : on en émet un neuf (vraie route).
                token = admin.call("POST", f"/api/projects/{pid}/rotate-token")["token"]
            when = scan_time(days, hhmm)
            gitleaks, checkov, conftest, semgrep = raw_tool_outputs(
                findings, sha, when, AUTHORS[(i + len(name)) % len(AUTHORS)])

            # Parsers de l'aggregator du pipeline (fingerprint calculé ici).
            parsed = (aggregator.parse_gitleaks(gitleaks) + aggregator.parse_checkov(checkov)
                      + aggregator.parse_conftest(conftest) + aggregator.parse_semgrep(semgrep))
            tools = [ToolInfo(name=t) for t, d in (
                (ToolName.GITLEAKS, gitleaks), (ToolName.CHECKOV, checkov),
                (ToolName.CONFTEST, conftest), (ToolName.SEMGREP, semgrep)) if d]
            report = ScanReport.build(
                ScanMeta(repo=spec["repo"], branch=branch, commit_sha=sha,
                         created_at=when, tools=tools),
                parsed,
            )
            res = Api(app, f"pipeline:{name}").call(
                "POST", "/api/scans", content=report.model_dump_json(),
                headers={"Authorization": f"Bearer {token}",
                         "Content-Type": "application/json"})
            detail = admin.call("GET", f"/api/scans/{res['scan_id']}")
            print(f"+ scan {name}@{branch} {when:%Y-%m-%d %H:%M} : "
                  f"{detail['score']['score']}/100 ({detail['score']['grade']}), "
                  f"should_fail={res['should_fail']}")
            if branch == "feature/add-rds":
                responses["pr"] = res

    # --- 6. Accès projets (developer / auditor / viewer) ------------------ #
    for email, names in PROJECT_ACCESS.items():
        u = db_user(email)
        wanted = sorted(project_ids[n] for n in names)
        current = sorted(p["id"] for p in admin.call(
            "GET", f"/api/admin/users/{u.id}/project-access"))
        if current != wanted:
            admin.call("PUT", f"/api/admin/users/{u.id}/project-access",
                       json={"project_ids": wanted})
            print(f"~ accès de {email} : {', '.join(names)}")

    # --- 7. Réinitialisation WebAuthn (une seule fois) -------------------- #
    target = db_user(WEBAUTHN_RESET_TARGET)
    with SessionLocal() as s:
        already = s.scalar(select(func.count()).select_from(AdminAuditLog).where(
            AdminAuditLog.action == "user.webauthn_reset",
            AdminAuditLog.target_user_id == target.id))
    if not already:
        admin.call("POST", f"/api/admin/users/{target.id}/reset-webauthn")
        print(f"~ passkeys de {WEBAUTHN_RESET_TARGET} réinitialisées")

    # --- 8. Triage data-lake, par le security_lead ------------------------ #
    secops = sessions[SECOPS_EMAIL]
    dl_scans = secops.call("GET", f"/api/projects/{project_ids['data-lake']}/scans")
    latest_dl = dl_scans[0]["id"]
    dl_findings = secops.call("GET", f"/api/scans/{latest_dl}/findings")
    for (tool, rule, _sev, file, line, resource, _t), status, note in TRIAGE:
        f = next(x for x in dl_findings if x["rule_id"] == rule and x["resource"] == resource)
        if f["status"] != status:
            secops.call("PATCH", f"/api/scans/{latest_dl}/findings/{f['id']}/triage",
                        json={"status": status, "note": note})
            print(f"~ triage data-lake {rule} -> {status}")

    # --- Vérification : valeurs calculées par l'application --------------- #
    ai_id = project_ids["app-infra"]
    ai_scans = admin.call("GET", f"/api/projects/{ai_id}/scans")
    pr_scan = ai_scans[0]
    detail = admin.call("GET", f"/api/scans/{pr_scan['id']}")
    findings = admin.call("GET", f"/api/scans/{pr_scan['id']}/findings")
    by = detail["score"]["by_severity"]
    high_plus = by.get("critical", 0) + by.get("high", 0)

    print("\n=== Vérification (valeurs calculées par l'API) ===")
    print(f"app-infra, dernier scan : branche {pr_scan['branch']}, "
          f"{len(findings)} findings, tous ouverts : "
          f"{all(f['status'] == 'open' for f in findings)}")
    print(f"  score {detail['score']['score']} / grade {detail['score']['grade']}")
    print(f"  {high_plus} finding(s) >= HIGH ({by.get('critical', 0)} critical, "
          f"{by.get('high', 0)} high)")
    if "pr" in responses:
        print(f"  POST /api/scans -> should_fail={responses['pr']['should_fail']}, "
              f"fail_reason=« {responses['pr']['fail_reason']} »")
    else:
        print("  (scan PR déjà présent : should_fail n'est renvoyé qu'à l'ingestion,"
              " voir la première exécution)")
    for name, pid in project_ids.items():
        d = admin.call("GET", f"/api/projects/{pid}")
        s = d["latest_score"]
        print(f"  {name:<15} {d['scan_count']} scans, dernier score "
              f"{s['score']}/100 ({s['grade']})")

    ok = (detail["score"]["score"] == 42 and detail["score"]["grade"] == "D"
          and high_plus == 4 and len(findings) == 5)
    print("\nComptes de démo (mot de passe commun : " + DEMO_PASSWORD + ")")
    for email, name, role, _ in USERS:
        mfa = "  [2FA TOTP]" if email == SECOPS_EMAIL else ""
        print(f"  {role:<14} {email:<26} {name}{mfa}")
    print("\nOK" if ok else "\nATTENTION : valeurs inattendues, voir ci-dessus.")
    return 0 if ok else 1


def reset_info(SessionLocal, Organization, User, Project, Scan,
               AdminAuditLog, TriageAuditLog, func, select) -> int:
    """--reset : n'efface RIEN.

    Les journaux d'audit (admin_audit_logs, triage_audit_log) sont append-only
    par conception, et leurs clés étrangères vers users/projects rendent
    impossible la suppression des comptes et projets de démo sans effacer
    aussi l'audit. On ne contourne pas ce principe : le nettoyage propre est
    de recréer la base locale.
    """
    with SessionLocal() as s:
        org = s.scalar(select(Organization).where(Organization.name == DEMO_ORG))
        demo_users = s.scalars(select(User).where(User.email.like("demo.%@example.com"))).all()
        ids = [u.id for u in demo_users]
        n_proj = s.scalar(select(func.count()).select_from(Project)
                          .where(Project.owner_id.in_(ids))) if ids else 0
        n_admin = s.scalar(select(func.count()).select_from(AdminAuditLog)
                           .where(AdminAuditLog.org_id == org.id)) if org else 0
        n_triage = s.scalar(select(func.count()).select_from(TriageAuditLog)
                            .where(TriageAuditLog.owner_id.in_(ids))) if ids else 0
        others = s.scalar(select(func.count()).select_from(Organization)
                          .where(Organization.name != DEMO_ORG))

    print(f"Données de démo présentes : {len(ids)} comptes, {n_proj} projets, "
          f"{n_admin} entrées d'audit admin, {n_triage} entrées d'audit triage.")
    print(
        "\nSuppression partielle REFUSÉE : le journal d'audit est append-only\n"
        "(triggers en base) et référence les comptes de démo (clés étrangères).\n"
        "Supprimer ces comptes obligerait à effacer l'audit — ce script ne le\n"
        "fait pas, et la base le refuserait.\n"
        "\nNettoyage recommandé : recréer la base locale.\n"
    )
    if others:
        print(f"  ATTENTION : la base contient aussi {others} autre(s) organisation(s)\n"
              "  qui seront effacées. Sauvegarde préalable :\n"
              "    docker compose exec -T db pg_dump -U iacguard iacguard > backup-local.sql\n")
    print("  docker compose down -v\n"
          "  docker compose up -d db\n"
          "  # (optionnel) restaurer la sauvegarde AVANT de démarrer l'API :\n"
          "  #   docker compose exec -T db psql -U iacguard -d iacguard < backup-local.sql\n"
          "  docker compose up -d --build\n"
          f"  {DOCKER_SEED_CMD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
