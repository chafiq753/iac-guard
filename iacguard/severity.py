"""Gravité iac-guard pour les règles Checkov.

Pourquoi ce fichier : sans compte Prisma Cloud, Checkov ne renvoie aucune
gravité. Tout sortait donc en MEDIUM, et un seuil de blocage `high` ne
bloquait jamais rien, même un bucket S3 public ou SSH ouvert à Internet.

Principe de classement (une phrase par niveau, pour pouvoir le justifier) :

- CRITICAL : exploitable tout de suite par n'importe qui, impact maximal
  (droits administrateur « * », stockage modifiable par tout le monde,
  secret en clair).
- HIGH : surface sensible exposée directement à Internet, ou chemin connu
  vers une prise de contrôle (SSH/RDP/BDD ouverts au monde, bucket lisible
  par tous, IMDSv1, escalade de privilèges IAM).
- MEDIUM : valeur par défaut. Chiffrement au repos, journalisation, TLS :
  importants pour la conformité et la détection, pas exploitables seuls.
- LOW : hygiène, résilience, observabilité fine (versioning, multi-AZ,
  description des règles...). Ils ne doivent pas noyer les vrais risques.

Si Checkov fournit lui-même une gravité (plateforme Prisma), elle reste
prioritaire. Tous les identifiants ci-dessous ont été vérifiés contre
`checkov --list` (Checkov 3.3) ; un test le revérifie quand Checkov est installé.
"""

from __future__ import annotations

from iacguard.schema import Severity

_C, _H, _L = Severity.CRITICAL, Severity.HIGH, Severity.LOW

CHECKOV_SEVERITY: dict[str, Severity] = {
    # ------------------------------------------------------------------ #
    # CRITICAL
    # ------------------------------------------------------------------ #
    "CKV_AWS_1": _C,     # politique IAM « *:* » (admin complet)
    "CKV_AWS_62": _C,    # politique IAM « *:* » (admin complet)
    "CKV_AWS_57": _C,    # bucket S3 modifiable par tout le monde

    # ------------------------------------------------------------------ #
    # HIGH — AWS
    # ------------------------------------------------------------------ #
    "CKV_AWS_20": _H,    # bucket S3 lisible par tout le monde
    "CKV_AWS_70": _H,    # politique de bucket S3 ouverte à n'importe quel Principal
    "CKV_AWS_17": _H,    # base RDS accessible publiquement
    "CKV_AWS_24": _H,    # SSH (22) ouvert à 0.0.0.0/0
    "CKV_AWS_25": _H,    # RDP (3389) ouvert à 0.0.0.0/0
    "CKV_AWS_277": _H,   # tous les ports ouverts à 0.0.0.0/0
    "CKV_AWS_79": _H,    # IMDSv1 actif (vol de credentials via SSRF)
    "CKV_AWS_41": _H,    # clés AWS écrites en dur dans le provider
    "CKV_AWS_45": _H,    # secrets en dur dans l'environnement d'une Lambda
    "CKV_AWS_46": _H,    # secrets en dur dans le user data EC2
    "CKV_AWS_63": _H,    # politique IAM avec action « * »
    "CKV2_AWS_40": _H,   # politique IAM avec tous les droits IAM
    "CKV_AWS_107": _H,   # IAM : exposition de credentials
    "CKV_AWS_287": _H,   # IAM : exposition de credentials
    "CKV_AWS_108": _H,   # IAM : exfiltration de données
    "CKV_AWS_288": _H,   # IAM : exfiltration de données
    "CKV_AWS_110": _H,   # IAM : escalade de privilèges
    "CKV_AWS_286": _H,   # IAM : escalade de privilèges
    "CKV_AWS_60": _H,    # rôle IAM assumable par n'importe quel principal
    "CKV_AWS_61": _H,    # assume role autorisé pour tous les services
    "CKV_AWS_301": _H,   # fonction Lambda accessible publiquement
    "CKV_AWS_38": _H,    # endpoint EKS public ouvert à 0.0.0.0/0
    "CKV_AWS_59": _H,    # API Gateway sans contrôle d'accès vers le back-end

    # ------------------------------------------------------------------ #
    # HIGH — Azure / GCP / Kubernetes (expositions équivalentes)
    # ------------------------------------------------------------------ #
    "CKV_AZURE_9": _H,   # RDP ouvert depuis Internet
    "CKV_AZURE_10": _H,  # SSH ouvert depuis Internet
    "CKV_AZURE_11": _H,  # base SQL ouverte à 0.0.0.0/0
    "CKV_AZURE_59": _H,  # compte de stockage public
    "CKV_AZURE_190": _H, # blobs publics
    "CKV_AZURE_34": _H,  # conteneur blob en accès public
    "CKV_GCP_2": _H,     # SSH ouvert sans restriction
    "CKV_GCP_3": _H,     # RDP ouvert sans restriction
    "CKV_GCP_88": _H,    # MySQL ouvert sans restriction
    "CKV_GCP_11": _H,    # Cloud SQL ouvert au monde
    "CKV_GCP_28": _H,    # bucket Cloud Storage public
    "CKV_GCP_42": _H,    # compte de service avec droits admin
    "CKV_K8S_16": _H,    # conteneur privilégié
    "CKV_K8S_17": _H,    # partage du namespace PID de l'hôte
    "CKV_K8S_18": _H,    # partage du namespace IPC de l'hôte
    "CKV_K8S_19": _H,    # partage du réseau de l'hôte
    "CKV_K8S_27": _H,    # socket Docker exposé au conteneur

    # ------------------------------------------------------------------ #
    # LOW — hygiène, résilience, observabilité fine
    # ------------------------------------------------------------------ #
    "CKV_AWS_21": _L,    # versioning S3
    "CKV_AWS_144": _L,   # réplication S3 inter-régions
    "CKV2_AWS_61": _L,   # cycle de vie S3
    "CKV2_AWS_62": _L,   # notifications d'événements S3
    "CKV_AWS_157": _L,   # RDS multi-AZ
    "CKV_AWS_118": _L,   # monitoring avancé RDS
    "CKV_AWS_353": _L,   # performance insights RDS
    "CKV_AWS_226": _L,   # mises à jour mineures automatiques RDS
    "CKV_AWS_293": _L,   # protection contre la suppression (BDD)
    "CKV2_AWS_60": _L,   # copie des tags vers les snapshots RDS
    "CKV_AWS_126": _L,   # monitoring détaillé EC2
    "CKV_AWS_135": _L,   # EC2 optimisée EBS
    "CKV_AWS_23": _L,    # description des règles de security group
    "CKV2_AWS_5": _L,    # security group non attaché
    "CKV_AWS_150": _L,   # protection contre la suppression (load balancer)
    "CKV_AWS_252": _L,   # topic SNS pour CloudTrail
    "CKV_AWS_120": _L,   # cache API Gateway
}

# Règles du framework « secrets » de Checkov (CKV_SECRET_1, _2...) : même
# traitement que Gitleaks, un secret exposé est critique.
SECRET_PREFIX = "CKV_SECRET_"


def checkov_default_severity(check_id: str) -> Severity:
    """Gravité iac-guard d'une règle Checkov (MEDIUM si non classée)."""
    if check_id.startswith(SECRET_PREFIX):
        return Severity.CRITICAL
    return CHECKOV_SEVERITY.get(check_id, Severity.MEDIUM)
