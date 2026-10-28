<!-- Ancien README de la version dashboard, conservé tel quel. Le README principal décrit maintenant l outil CLI. -->

# iac-guard

Plateforme de détection et de suivi des vulnérabilités pour les dépôts
d'Infrastructure as Code.

À chaque modification d'un dépôt client, trois analyseurs complémentaires sont
exécutés automatiquement. Leurs résultats sont normalisés dans un schéma
unique, historisés, et présentés dans un tableau de bord. Lorsqu'un problème
dépasse le seuil de gravité défini pour le projet, la fusion vers la branche
principale est refusée.

## Le problème

Le code d'infrastructure part en production sans relecture sécurité. Trois
catégories de défauts passent inaperçues :

- des secrets commités par erreur, qui restent dans l'historique Git ;
- des ressources mal configurées : stockage public, base non chiffrée, port
  d'administration ouvert sur Internet ;
- des vulnérabilités applicatives : injection SQL, injection de commande.

Des analyseurs existent pour chacune de ces catégories, mais ils sont rarement
exécutés, produisent des formats incompatibles, et n'empêchent rien.

## Architecture

```
Push / Pull Request
        |
        v
   GitHub Actions ---- Gitleaks   (secrets)
        |              Checkov    (configuration IaC)
        |              Semgrep    (code applicatif)
        v
   Aggregator     trois formats -> un schema unifie
        |
        v
   API FastAPI ---- PostgreSQL
        |
        +--> Tableau de bord Next.js
        +--> Verdict : bloquer ou laisser passer
```

Le pipeline s'authentifie avec un jeton propre à chaque projet : un client ne
peut écrire que dans son propre espace. Le jeton n'est affiché qu'une fois, la
base n'en conserve que l'empreinte.

## Fonctionnalités

**Authentification**
Mot de passe haché en Argon2id, double authentification par code TOTP ou par
clé WebAuthn (biométrie, Windows Hello), codes de récupération à usage unique,
verrouillage temporaire après échecs répétés, session en cookie `httpOnly`.

**Gestion des comptes**
Cinq rôles (`admin`, `security_lead`, `developer`, `auditor`, `viewer`),
invitation par jeton expirant, activation et désactivation d'un compte,
attribution de projets par utilisateur, réinitialisation forcée de
l'enrôlement WebAuthn.

**Projets**
Multi-projets, jeton d'ingestion par projet avec rotation, seuil de blocage
configurable, exceptions de règles justifiées.

**Analyse**
Score de conformité, filtres par gravité, outil, projet et statut, historique
des scans, suivi d'un même problème dans le temps par empreinte stable.

**Traçabilité**
Deux journaux d'audit en écriture seule : les actions d'administration de
comptes, et les décisions de traitement des alertes.

## Structure

```
backend/     API FastAPI, modeles SQLAlchemy, services, tests
frontend/    Tableau de bord Next.js
pipeline/    Aggregator et modeles de workflow GitHub Actions
docs/        Documentation
```

## Installation

Prérequis : Docker et Node.js 20.

```bash
# API et base de donnees
docker compose up -d --build

# Tableau de bord
cd frontend
npm install
npm run dev
```

L'API écoute sur `http://localhost:8000` (`/docs` pour la documentation
interactive), le tableau de bord sur `http://localhost:3000`.

### Développement sans Docker

```bash
cd backend
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
pytest
```

La base par défaut est SQLite. Pour PostgreSQL, renseigner `DATABASE_URL` dans
un fichier `.env` (voir `backend/.env.example`).

## Connecter un dépôt

1. Créer un projet depuis le tableau de bord et copier le jeton affiché.
2. Copier `pipeline/github-actions-template/scan-standalone.yml` dans
   `.github/workflows/` du dépôt à analyser, ainsi que le contenu de
   `pipeline/aggregator/` dans un dossier `.iacguard/`.
3. Dans le dépôt GitHub, sous *Settings > Secrets and variables > Actions* :
   - secret `IAC_GUARD_TOKEN` : le jeton du projet ;
   - variable `IAC_GUARD_API_URL` : l'URL publique de l'API.

Pour que le résultat conditionne les fusions, activer la protection de la
branche principale en exigeant le check `scan`.

## Sécurité

Le code de ce dépôt est public. Sa sécurité ne repose donc pas sur le secret
de son implémentation, mais sur celui des clés fournies au déploiement.

La configuration livrée est celle d'un poste de développement. Elle contient
une clé de signature connue de tous, puisqu'elle figure dans le code. Pour
qu'elle ne puisse pas être utilisée par inadvertance, l'application **refuse
de démarrer** lorsque `ENVIRONMENT=production` et que l'une de ces conditions
est réunie :

- `SECRET_KEY` absente, laissée à sa valeur par défaut, ou plus courte que
  32 caractères ;
- `COOKIE_SECURE` désactivé, ce qui laisserait le cookie de session circuler
  hors HTTPS.

En développement, l'application démarre mais journalise un avertissement.

Générer une clé de production :

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Mesures en place : mots de passe hachés en Argon2id, jetons de projet et codes
de récupération stockés sous forme d'empreinte, session en cookie `httpOnly`,
`SameSite=Lax` contre le CSRF, liste d'origines CORS explicite, verrouillage
après échecs répétés, réponses identiques pour un compte existant ou non afin
d'empêcher l'énumération, et vérification du rôle en base à chaque requête
sensible plutôt que dans le jeton.

## État du projet

La chaîne complète est fonctionnelle : analyse, ingestion, tableau de bord,
politique de blocage.

Travaux en cours :

- moteur de conformité associant les résultats techniques aux articles de la
  loi 09-08 (CNDP) et aux directives de Bank Al-Maghrib ;
- export PDF des rapports pour audit externe ;
- révision du calcul de score, qui sature sur les dépôts très vulnérables ;
- envoi des e-mails d'invitation, aujourd'hui journalisés faute de service
  transactionnel configuré ;
- migrations de schéma avec Alembic, en remplacement de `create_all`.

## Tests

```bash
cd backend
pytest
```
