/**
 * Explications pédagogiques pour un finding : pourquoi c'est un risque,
 * ce qu'un attaquant peut en faire, comment le corriger.
 *
 * Le backend ne stocke qu'un titre + une remédiation courte (parfois nulle).
 * Ce module comble le reste avec une base de connaissances par règle connue,
 * et un repli générique par catégorie sinon.
 */

import type { FindingCategory, FindingSource, Severity } from "@/lib/data";

export interface FindingExplanation {
  /** Ce qu'est concrètement le problème, en une phrase. */
  impact: string;
  /** Un scénario concret de ce qu'un attaquant peut en faire. */
  exploit: string;
  /** Comment corriger, si le backend n'a pas déjà fourni de remédiation. */
  fix: string;
}

/** Un extrait par règle connue (Checkov CKV_*, Gitleaks, Conftest). */
const BY_RULE: Record<string, FindingExplanation> = {
  CKV_AWS_20: {
    impact:
      "Ce bucket S3 est configuré en lecture publique : son contenu est accessible à quiconque possède l'URL, sans authentification.",
    exploit:
      "Un attaquant qui devine ou découvre le nom du bucket peut lister et télécharger tous les fichiers stockés dedans (documents, sauvegardes, données clients…).",
    fix: "Retirez l'ACL public-read et activez le blocage d'accès public S3 (Block Public Access) au niveau du bucket.",
  },
  CKV_AWS_21: {
    impact: "Le versioning n'est pas activé sur ce bucket S3.",
    exploit:
      "Une suppression accidentelle, un bug applicatif ou un attaquant qui écrase des fichiers rend la perte de données définitive : aucune version antérieure n'est récupérable.",
    fix: "Activez le versioning du bucket (`versioning { enabled = true }`).",
  },
  CKV_AWS_24: {
    impact:
      "Le port SSH (22) est ouvert à 0.0.0.0/0 : n'importe quelle adresse IP sur Internet peut tenter de s'y connecter.",
    exploit:
      "C'est la première chose que scannent les attaquants automatisés (bots) : ils tentent des connexions par force brute 24h/24 dès qu'un port 22 public est détecté.",
    fix: "Restreignez `cidr_blocks` à votre VPN ou vos IP de bureau connues, ou passez par un bastion / Session Manager.",
  },
  CKV_AWS_25: {
    impact:
      "Le port RDP (3389) est ouvert à 0.0.0.0/0 : accessible depuis n'importe où sur Internet.",
    exploit:
      "Même risque que le SSH ouvert : brute-force automatisé permanent, et RDP est une cible historique de ransomwares.",
    fix: "Restreignez `cidr_blocks` à une plage d'IP de confiance, ou utilisez un accès via bastion/VPN.",
  },
  CKV_AWS_3: {
    impact: "Ce volume EBS n'est pas chiffré au repos.",
    exploit:
      "Si un instantané (snapshot) du volume est partagé par erreur, ou si le disque physique sous-jacent est mal effacé en fin de vie, les données sont lisibles en clair.",
    fix: "Ajoutez `encrypted = true` (et éventuellement une clé KMS dédiée via `kms_key_id`).",
  },
  CKV_AWS_16: {
    impact: "Cette base de données RDS n'est pas chiffrée au repos.",
    exploit:
      "Un accès non autorisé au stockage sous-jacent (snapshot mal partagé, disque volé chez le cloud provider) expose toutes les données en clair.",
    fix: "Activez `storage_encrypted = true` (ne peut être fait qu'à la création de l'instance, pas après coup).",
  },
  CKV_AWS_17: {
    impact: "Cette base de données RDS est accessible publiquement.",
    exploit:
      "La base est directement joignable depuis Internet : un attaquant peut tenter de s'y connecter ou l'attaquer par force brute sans même être sur votre réseau.",
    fix: "Passez `publicly_accessible = false` et accédez-y uniquement depuis l'intérieur du VPC.",
  },
  CKV_AWS_63: {
    impact:
      "Cette policy IAM autorise `Action: \"*\"` sur `Resource: \"*\"` : elle donne un accès total à tous les services AWS.",
    exploit:
      "Si l'identité qui porte cette policy (utilisateur, rôle CI/CD) est compromise, l'attaquant obtient les droits d'administrateur complet du compte AWS.",
    fix: "Listez explicitement les actions et ressources nécessaires (principe du moindre privilège) au lieu d'utiliser des wildcards.",
  },
  CKV_AWS_1: {
    impact: "Cette policy IAM est trop permissive (actions ou ressources en wildcard).",
    exploit:
      "Un accès compromis hérite de bien plus de droits que nécessaire, élargissant ce qu'un attaquant peut faire une fois entré.",
    fix: "Réduisez la policy aux actions et ressources strictement nécessaires.",
  },
  CKV_AWS_62: {
    impact: "Cette policy IAM autorise des actions d'administration sensibles sans restriction.",
    exploit:
      "Un compte compromis pourrait modifier les permissions elles-mêmes (élévation de privilèges) ou d'autres ressources critiques.",
    fix: "Restreignez la policy aux actions réellement utilisées par le rôle.",
  },
  CKV_AWS_67: {
    impact: "La validation d'intégrité des logs CloudTrail est désactivée (ou CloudTrail lui-même est coupé).",
    exploit:
      "Sans piste d'audit fiable, un attaquant qui compromet le compte peut agir sans laisser de trace exploitable, et l'équipe sécurité ne pourra pas reconstituer l'incident après coup.",
    fix: "Activez `enable_logging = true` et `enable_log_file_validation = true` sur le trail CloudTrail.",
  },
  "aws-access-token": {
    impact: "Une clé d'accès AWS (Access Key ID + Secret) est écrite en clair dans le code.",
    exploit:
      "Quiconque lit ce fichier — un collègue, un fork public, un historique git mal nettoyé — peut utiliser cette clé pour agir sur le compte AWS avec les droits qui lui sont associés.",
    fix: "Révoquez immédiatement la clé dans IAM, purgez-la de l'historique git, et utilisez un secret manager (AWS Secrets Manager, variables d'environnement CI) à la place.",
  },
  "stripe-access-token": {
    impact: "Une clé secrète Stripe est écrite en clair dans le code ou un fichier de configuration.",
    exploit:
      "Cette clé permet de créer des paiements, rembourser des transactions ou lire les données clients Stripe au nom de votre compte.",
    fix: "Révoquez la clé dans le dashboard Stripe, régénérez-en une nouvelle, et stockez-la uniquement comme secret CI/environnement.",
  },
  "generic-api-key": {
    impact: "Une valeur qui ressemble à une clé d'API est écrite en clair dans le code.",
    exploit:
      "Selon le service concerné, cette clé peut permettre d'usurper des appels d'API en votre nom (envoi d'e-mails, appels facturés, accès à des données).",
    fix: "Vérifiez à quel service appartient cette clé, révoquez-la, et déplacez-la vers un secret manager.",
  },
  "python.lang.security.audit.dangerous-subprocess-use": {
    impact:
      "Une commande shell est construite avec `shell=True` à partir d'une entrée qui peut être influencée par l'utilisateur.",
    exploit:
      "Un attaquant qui contrôle cette entrée peut injecter des commandes arbitraires exécutées avec les droits du processus (Remote Code Execution).",
    fix: "Évitez `shell=True` : passez la commande sous forme de liste d'arguments à `subprocess.run()`, sans passer par un shell.",
  },
};

/** Repli par catégorie si la règle précise n'est pas dans la base ci-dessus. */
const BY_CATEGORY: Record<FindingCategory | string, FindingExplanation> = {
  secret: {
    impact: "Une information sensible (clé, mot de passe, jeton) est écrite en clair dans le code.",
    exploit:
      "Toute personne ayant accès au dépôt — y compris via l'historique git — peut réutiliser ce secret pour se faire passer pour votre application.",
    fix: "Révoquez le secret exposé, puis stockez les secrets dans un gestionnaire dédié (Vault, AWS Secrets Manager, secrets CI) au lieu du code.",
  },
  misconfiguration: {
    impact:
      "Cette ressource cloud est configurée de façon plus permissive ou moins protégée que recommandé.",
    exploit:
      "Une mauvaise configuration réseau ou de chiffrement élargit ce qu'un attaquant peut atteindre ou lire s'il obtient un point d'entrée, même limité.",
    fix: "Appliquez la configuration recommandée par le fournisseur cloud pour ce type de ressource (voir la remédiation ci-dessus si fournie).",
  },
  policy: {
    impact:
      "Cette ressource ne respecte pas une règle métier ou réglementaire définie pour votre organisation.",
    exploit:
      "Selon la règle, la conséquence est réglementaire (non-conformité CNDP/BAM lors d'un audit) plutôt qu'une exploitation technique directe.",
    fix: "Ajustez la ressource pour respecter la règle (voir la remédiation ci-dessus si fournie).",
  },
  vulnerability: {
    impact:
      "Le code applicatif contient un motif à risque connu (analyse statique / SAST), indépendant de la configuration cloud.",
    exploit:
      "Selon la faille, l'exploitation va de la fuite de données à l'exécution de code arbitraire si l'entrée concernée est atteignable par un utilisateur externe.",
    fix: "Corrigez le motif signalé dans le code source (voir la remédiation ci-dessus si fournie) et ajoutez un test de non-régression.",
  },
};

const DEFAULT_EXPLANATION: FindingExplanation = {
  impact: "Ce scanner a détecté un écart par rapport aux bonnes pratiques attendues.",
  exploit:
    "L'impact précis dépend du contexte de la ressource ; traitez-le avec la même rigueur qu'un autre finding de cette gravité.",
  fix: "Consultez la documentation de l'outil qui l'a détecté (source) pour la remédiation recommandée.",
};

export function explainFinding(finding: {
  rule_id: string;
  category: FindingCategory | string;
}): FindingExplanation {
  return (
    BY_RULE[finding.rule_id] ??
    BY_CATEGORY[finding.category] ??
    DEFAULT_EXPLANATION
  );
}

/** Libellés humains pour source/catégorie/sévérité, réutilisés dans l'UI. */
export const SOURCE_LABELS: Record<FindingSource | string, string> = {
  gitleaks: "Gitleaks — détection de secrets",
  checkov: "Checkov — mauvaises configurations IaC",
  conftest: "Conftest — règles métier (OPA/Rego)",
  semgrep: "Semgrep — analyse statique du code (SAST)",
};

export const CATEGORY_LABELS: Record<FindingCategory | string, string> = {
  secret: "Secret exposé",
  misconfiguration: "Mauvaise configuration",
  policy: "Non-conformité à une règle",
  vulnerability: "Vulnérabilité dans le code",
};

export const SEVERITY_LABELS: Record<Severity | string, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
  info: "Information",
};
