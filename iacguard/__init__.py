"""iac-guard : scanner DevSecOps pour Infrastructure as Code.

Lance Gitleaks (secrets), Checkov (mauvaises configurations IaC) et Semgrep
(vulnérabilités du code applicatif), normalise leurs sorties dans un schéma
unique, calcule un score et décide si la pull request doit être bloquée.

Ce package est le cœur autonome de l'outil : il ne dépend ni de FastAPI ni
de la base de données. Le dashboard (dossiers backend/ et frontend/) est une
option qui consomme les rapports produits ici.
"""

__version__ = "1.0.1"
