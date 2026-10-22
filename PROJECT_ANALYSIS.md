# PROJECT_ANALYSIS.md — iac-guard

> Document d'analyse technique exhaustif du dépôt `iac-guard`, produit par lecture
> intégrale du code source. Il est destiné à servir de base factuelle unique à la
> rédaction d'un rapport de projet (PFA / stage). Toutes les valeurs, noms de
> fichiers, noms de variables et algorithmes cités ont été vérifiés dans le code.
>
> **Convention de statut employée dans ce document :**
> - **Terminé** : implémenté, fonctionnel, couvert par des tests ou observable dans l'UI.
> - **Partiel** : implémenté mais incomplet (dépendance manquante, données factices, cas non couverts).
> - **Stub** : la fonction existe et est appelée, mais son effet réel est absent (remplacé par un log).
> - **Absent** : mentionné dans la documentation ou prévu, mais aucun code correspondant.

---

## 1. Identification du projet

| Élément | Valeur |
|---|---|
| Nom | `iac-guard` |
| Dépôt distant | `https://github.com/chafiq753/iac-guard.git` |
| Branche | `main` (unique branche locale et distante) |
| Auteur des commits | CHAFIQ (`cboulghallat@gmail.com`) |
| Nombre de commits | 4 |
| Nature | Plateforme SaaS de détection et de suivi des vulnérabilités pour dépôts *Infrastructure as Code* (Terraform), avec blocage de merge |
| Langue du code et des commentaires | Français (commentaires, messages d'erreur, UI) ; identifiants en anglais |
| Contexte marché revendiqué | Maroc — références explicites à la loi 09-08 (CNDP) et à Bank Al-Maghrib |

### 1.1 Historique des commits (chronologie du développement)

| Hash | Date | Message | Portée (fichiers modifiés) |
|---|---|---|---|
| `d12824a` | 2026-07-14 | demo terraform vulnerable + pipeline iac-guard | Socle : backend, pipeline, frontend initial |
| `1690db0` | 2026-08-12 | Fix dropdown menu trigger in projects manager | +45 fichiers : triage, audit-log, politique de scan, panneau de détail, aggregator Semgrep, ~3956 insertions |
| `ad45932` | 2026-08-22 | Gestion des comptes par rôle, analyse SAST et documentation | +50 fichiers : RBAC complet, invitations, admin audit log, docs, ~3753 insertions. **Supprime** 6 fichiers placeholders vides : `backend/app/services/compliance_engine.py`, `backend/app/services/pdf_export.py`, `backend/app/api/exceptions.py`, `backend/app/models/exception.py`, `docs/cahier-des-charges.md`, `backend/Dockerfile.tmp` |
| `a2854f1` | 2026-08-22 | Refuser le démarrage en production avec une configuration dangereuse | Durcissement `config.py` : garde-fous `SECRET_KEY` / `COOKIE_SECURE` |

### 1.2 Volumétrie de code

| Zone | Lignes | Détail |
|---|---|---|
| Backend Python (`backend/app` + `tests` + `scripts`) | 6 741 | 12 modèles, 7 routeurs, 5 services, 11 fichiers de test |
| Pipeline (`pipeline/`, Python + YAML) | 662 | aggregator + schéma + 2 workflows |
| Frontend (`frontend/src`, TS/TSX/CSS) | 10 243 | 9 pages, 18 composants métier, 23 composants UI, 7 modules `lib/` |
| **Total code source (hors dépendances)** | **≈ 17 600** | |

---

## 2. Arborescence complète

```
iac-guard/
├── .gitignore                       Ignore *.db, *.bak*, *.sql, .env, rapports de scan JSON
├── .mcp.json                        Config MCP (serveur `shadcn` via npx) — outil de dev, hors produit
├── README.md                        Documentation principale (FR, 6 Ko)
├── docker-compose.yml               Stack de dev : PostgreSQL 16-alpine + API FastAPI
│
├── backend/                         API FastAPI + modèles + services + tests
│   ├── Dockerfile                   python:3.12-slim, uvicorn sur 0.0.0.0:8000
│   ├── .dockerignore
│   ├── .env.example                 Modèle de configuration commenté
│   ├── requirements.txt             Dépendances de production
│   ├── requirements-dev.txt         = requirements.txt + pytest + httpx
│   ├── pytest.ini                   pythonpath=. / testpaths=tests / addopts=-q
│   ├── iacguard.db                  Base SQLite de dev (non versionnée)
│   ├── iacguard.db.bak-20260820-182542    Sauvegarde SQLite (non versionnée)
│   ├── pg-iacguard.bak-20260820-183647.sql  Dump PostgreSQL (non versionné)
│   ├── app/
│   │   ├── main.py                  Point d'entrée FastAPI, CORS, lifespan, /health
│   │   ├── core/
│   │   │   ├── config.py            Settings (pydantic-settings) + garde-fous production
│   │   │   └── security.py          Argon2id, bcrypt legacy, JWT, tokens projet, codes de récup.
│   │   ├── db/
│   │   │   └── session.py           Engine SQLAlchemy, SessionLocal, Base, get_db
│   │   ├── models/                  12 modèles ORM (voir §5)
│   │   ├── schemas/                 5 modules Pydantic (admin, ingest, project, read, user)
│   │   ├── api/                     7 routeurs + deps.py + cookies.py
│   │   └── services/                admin_audit, aggregates, email, mfa, scoring
│   ├── scripts/
│   │   └── migrate_rbac.py          Migration manuelle vers le schéma RBAC (idempotente)
│   └── tests/                       11 fichiers, 151 tests (tous passants)
│
├── frontend/                        Dashboard Next.js 16 / React 19
│   ├── package.json                 Dépendances (voir §3.2)
│   ├── next.config.ts               turbopack.root = __dirname
│   ├── components.json              Config shadcn (style "base-nova", baseColor "neutral")
│   ├── tsconfig.json                strict:true, alias @/* -> ./src/*
│   ├── eslint.config.mjs, postcss.config.mjs
│   ├── .env.local                   NEXT_PUBLIC_API_URL=http://localhost:8000
│   ├── AGENTS.md / CLAUDE.md        Consignes pour agents IA (hors produit)
│   ├── public/                      5 SVG issus du template create-next-app
│   └── src/
│       ├── app/                     9 routes App Router (voir §7.1)
│       ├── components/              18 composants métier + 23 composants UI shadcn
│       ├── hooks/use-mobile.ts      Détection de largeur < 768 px
│       └── lib/                     7 modules (voir §7.3)
│
├── pipeline/
│   ├── aggregator/
│   │   ├── schema.py                Schéma unifié Pydantic (contrat pipeline → API)
│   │   ├── aggregator.py            4 parsers + assemblage + POST à l'API
│   │   ├── requirements.txt         pydantic>=2.10,<3 ; requests>=2.31,<3
│   │   └── samples/                 4 sorties JSON d'exemple (checkov, conftest, gitleaks, semgrep)
│   └── github-actions-template/
│       ├── scan.yml                 Workflow 4 scanners, aggregator téléchargé par curl
│       └── scan-standalone.yml      Workflow 3 scanners, aggregator vendored dans .iacguard/
│
├── policies/                        **DOSSIER VIDE** — aucune policy Rego écrite
│
└── docs/
    ├── demo-vulnerable-main.tf      Terraform volontairement vulnérable (12 failles annotées)
    ├── sample-scan.json             Rapport de scan d'exemple au format unifié (6 findings)
    ├── script-video-demo.md         Script minuté d'une démo de 5 minutes
    └── speech-presentation.md       Texte de présentation orale + Q/R anticipées
```

---

## 3. Stack technique et versions

### 3.1 Backend — `backend/requirements.txt`

| Paquet | Contrainte de version | Rôle exact dans le projet |
|---|---|---|
| `fastapi` | `>=0.115,<1` | Framework HTTP, validation, OpenAPI auto (`/docs`) |
| `uvicorn[standard]` | `>=0.30,<1` | Serveur ASGI |
| `sqlalchemy` | `>=2.0,<3` | ORM (style 2.0 : `Mapped`, `mapped_column`, `DeclarativeBase`) |
| `pydantic` | `>=2.10,<3` | Schémas de validation entrée/sortie |
| `pydantic-settings` | `>=2.5,<3` | Chargement de la configuration depuis `.env` / variables d'env. |
| `python-jose[cryptography]` | `>=3.3,<4` | Encodage/décodage JWT (HS256) |
| `argon2-cffi` | `>=23.1,<26` | Hachage des mots de passe (Argon2id) |
| `bcrypt` | `>=4.1,<6` | **Lecture seule** : vérification des anciens hash, puis re-hachage en Argon2id. Un commentaire du fichier explique le refus de `passlib` (non maintenu, lit `bcrypt.__about__` supprimé depuis bcrypt 4.1) |
| `webauthn` | `>=2.0,<3` | Enrôlement et vérification des passkeys (py_webauthn) |
| `pyotp` | `>=2.9,<3` | TOTP (RFC 6238) |
| `email-validator` | `>=2.0,<3` | Support de `pydantic.EmailStr` |
| `psycopg[binary]` | `>=3.2,<4` | Driver PostgreSQL (dialecte `postgresql+psycopg`) |

Dépendances de développement (`requirements-dev.txt`) : `pytest>=8.0,<9`, `httpx>=0.27,<1`.

Runtime : **Python 3.12** (image `python:3.12-slim`, `setup-python@v5` avec `python-version: "3.12"`).

### 3.2 Frontend — `frontend/package.json`

| Paquet | Version | Rôle |
|---|---|---|
| `next` | `16.2.10` | Framework React (App Router, Turbopack) |
| `react` / `react-dom` | `19.2.4` | Bibliothèque UI |
| `typescript` | `^5` | Typage strict (`strict: true`) |
| `tailwindcss` + `@tailwindcss/postcss` | `^4` | CSS utilitaire (Tailwind v4, config dans `globals.css`) |
| `@base-ui/react` | `^1.6.0` | Primitives accessibles sous-jacentes aux composants shadcn |
| `shadcn` | `^4.13.0` | Générateur de composants (style `base-nova`) |
| `@tanstack/react-table` | `^8.21.3` | Tableau d'alertes : tri, filtrage, pagination |
| `recharts` | `^3.8.0` | Graphique d'activité (AreaChart empilé) |
| `@simplewebauthn/browser` | `^13.3.0` | `startRegistration()` / `startAuthentication()` côté navigateur |
| `qrcode.react` | `^4.2.0` | Rendu du QR code `otpauth://` pour le TOTP |
| `input-otp` | `^1.4.2` | Champ de saisie du code à 6 chiffres |
| `sonner` | `^2.0.7` | Notifications toast |
| `lucide-react` | `^1.24.0` | Icônes |
| `next-themes` | `^0.4.6` | Support thème clair/sombre (installé ; classes `dark:` utilisées dans le CSS) |
| `class-variance-authority`, `clsx`, `tailwind-merge`, `tw-animate-css` | — | Composition de classes CSS |

Scripts npm : `dev` (`next dev`), `build` (`next build`), `start` (`next start`), `lint` (`eslint`).

### 3.3 Outils externes du pipeline

| Outil | Version épinglée | Fichier | Rôle |
|---|---|---|---|
| Gitleaks | `8.21.2` (`env.GITLEAKS_VERSION`) | `scan.yml`, `scan-standalone.yml` | Détection de secrets dans l'arbre **et l'historique Git** |
| Checkov | non épinglée (`pip install checkov`) | idem | Analyse statique des mauvaises configurations IaC |
| Conftest (OPA) | `0.56.0` (`env.CONFTEST_VERSION`) | `scan.yml` uniquement | Règles métier Rego, parser `hcl2` |
| Semgrep | `1.78.0` (`env.SEMGREP_VERSION`) | idem | SAST sur le code applicatif (`--config=auto`) |
| GitHub Actions | `actions/checkout@v4`, `actions/setup-python@v5`, `actions/upload-artifact@v4` | idem | Orchestration CI |

### 3.4 Infrastructure — `docker-compose.yml`

| Service | Image / build | Ports | Variables d'environnement |
|---|---|---|---|
| `db` | `postgres:16-alpine` | `5432:5432` | `POSTGRES_USER=iacguard`, `POSTGRES_PASSWORD=iacguard`, `POSTGRES_DB=iacguard` |
| `api` | `build: ./backend` | `8000:8000` | `DATABASE_URL=postgresql+psycopg://iacguard:iacguard@db:5432/iacguard`, `ENVIRONMENT=development`, `SECRET_KEY=${SECRET_KEY:-dev-secret-change-me}`, `CORS_ORIGINS='["http://localhost:3000","http://localhost:5173"]'` |

- Volume nommé `pgdata` monté sur `/var/lib/postgresql/data` (persistance entre redémarrages).
- Healthcheck sur `db` : `pg_isready -U iacguard -d iacguard`, `interval: 5s`, `timeout: 5s`, `retries: 10`.
- `api` dépend de `db` avec `condition: service_healthy` : l'API ne démarre qu'une fois Postgres prêt.
- Le frontend n'est **pas** conteneurisé : il tourne via `npm run dev` sur `localhost:3000`.

---

## 4. Architecture globale

### 4.1 Flux de données complet

```
┌───────────────────────────────────────────────────────────────────────────┐
│  DÉPÔT CLIENT (GitHub)                                                    │
│  Terraform (*.tf) + code applicatif (*.py, *.js)                          │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ push / pull_request / workflow_dispatch
                               ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  GITHUB ACTIONS  —  job `scan` (ubuntu-latest)                            │
│                                                                           │
│  1. actions/checkout@v4  (fetch-depth: 0 → historique Git complet)        │
│  2. actions/setup-python@v5 (3.12)                                        │
│  3. [standalone] Vérification GET $API_URL/health (échec rapide)          │
│  4. Gitleaks  → gitleaks.json   (continue-on-error: true)                 │
│  5. Checkov   → checkov.json    (continue-on-error: true, --soft-fail)    │
│  6. Conftest  → conftest.json   (scan.yml uniquement)                     │
│  7. Semgrep   → semgrep.json    (continue-on-error: true)                 │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ 4 fichiers JSON, 4 formats incompatibles
                               ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  AGGREGATOR  (pipeline/aggregator/aggregator.py)                          │
│                                                                           │
│  parse_gitleaks() ─┐                                                      │
│  parse_checkov()  ─┤                                                      │
│  parse_conftest() ─┼──► list[Finding]  ──► ScanReport.build()             │
│  parse_semgrep()  ─┘        │                    │                        │
│                             │                    ├─ summary calculé       │
│               fingerprint = SHA-1(source|rule_id|file|line_start|resource)│
│                                                  │                        │
│  PAS d'--api-url → print JSON sur stdout (mode debug)                     │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ POST /api/scans
                               │ Authorization: Bearer iacg_xxxxx  (token PROJET)
                               │ Content-Type: application/json, timeout=30 s
                               ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  API FastAPI  (backend/app)                                               │
│                                                                           │
│  deps.get_project_from_token → SHA-256(token) == projects.token_hash ?    │
│         │ non → 401 "Token projet inconnu ou révoqué."                    │
│         ▼ oui                                                             │
│  Insertion Scan + N × Finding (transaction unique)                        │
│         │                                                                 │
│         ├─► aggregates.ignored_rule_ids(project) → set[rule_id]           │
│         ├─► aggregates.severity_counts(scan, exclude) → {sev: n}          │
│         └─► scoring.exceeds_threshold(counts, project.fail_on_severity)   │
│                                                                           │
│  Réponse 201 : {scan_id, project_id, total_findings, should_fail,         │
│                 fail_reason}                                              │
└──────┬──────────────────────────────────────────┬─────────────────────────┘
       │                                          │
       │ PostgreSQL 16 (prod) / SQLite (dev)      │ should_fail == true
       │ 14 tables                                ▼
       │                              ┌───────────────────────────────────┐
       │                              │  aggregator : return 1            │
       │                              │  → job `scan` en échec            │
       │                              │  → branch protection GitHub :     │
       │                              │    bouton « Merge » grisé         │
       │                              └───────────────────────────────────┘
       ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  DASHBOARD Next.js  (localhost:3000)                                      │
│                                                                           │
│  fetch(..., credentials: "include")  ← cookie httpOnly `iacguard_session`  │
│                                                                           │
│  /              Dashboard : KPI, courbe 7 scans, score, table d'alertes   │
│  /projects      Projets, tokens, rotation, suppression                    │
│  /alerts        Toutes les alertes, filtres, panneau de détail            │
│  /settings      Compte · Sécurité · Politiques de scan · Audit            │
│  /admin         Comptes, rôles, accès projets, journal d'audit admin      │
│  /security      Gestion 2FA (page autonome)                               │
│  /login /signup /forgot-password /accept-invite                           │
│                                                                           │
│  Rafraîchissement silencieux toutes les 30 s (dashboard, alertes, header) │
└───────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Les trois circuits d'authentification (fondamental)

Le projet fait coexister **trois** mécanismes d'authentification distincts, sur des routes différentes. C'est une décision d'architecture centrale, documentée dans `backend/app/api/deps.py`.

| Circuit | Acteur | Porteur | Dépendance FastAPI | Portée |
|---|---|---|---|---|
| **Token de projet** | Pipeline GitHub Actions | En-tête `Authorization: Bearer iacg_…` | `get_project_from_token` | Écriture dans **un seul** projet (`POST /api/scans`) |
| **JWT de session** | Humain sur le dashboard | Cookie httpOnly `iacguard_session` **ou** en-tête `Authorization: Bearer <JWT>` | `get_current_user` | Toute l'API applicative |
| **JWT MFA** | Humain ayant validé son mot de passe mais pas encore sa 2FA | Cookie httpOnly `iacguard_mfa` | `get_mfa_user` | **Uniquement** les routes de vérification 2FA |

Le champ `scope` du JWT (`"session"` ou `"mfa"`) est vérifié à chaque décodage (`decode_access_token(token, expected_scope=...)`). C'est ce contrôle qui empêche de contourner la 2FA avec le jeton intermédiaire. Un test dédié le vérifie (`test_mfa_token_cannot_be_used_as_a_session`).

---

## 5. Modèle de données

14 tables (12 modèles ORM + tables liées). Base de dev SQLite (`backend/iacguard.db`), base cible PostgreSQL 16.

**Création du schéma** : `Base.metadata.create_all(bind=engine)` dans le `lifespan` de FastAPI (`backend/app/main.py:36`). **Alembic n'est pas utilisé** — c'est une limitation assumée et documentée.

### 5.1 `organizations` — `backend/app/models/organization.py`

| Colonne | Type | Contraintes |
|---|---|---|
| `id` | Integer | PK |
| `name` | String(200) | |
| `created_at` | DateTime(tz) | `server_default=func.now()` |

Relation : `members` → `list[User]` (back_populates `organization`).
**Rôle métier** : périmètre d'administration. Un admin ne gère que les membres de SON organisation. Les projets gardent un propriétaire individuel (`Project.owner_id`) : l'organisation définit *qui peut administrer qui*, pas *qui possède quoi*.

### 5.2 `users` — `backend/app/models/user.py`

| Colonne | Type | Contraintes / défaut |
|---|---|---|
| `id` | Integer | PK |
| `email` | String(320) | `unique=True`, `index=True` |
| `name` | String(200) | nullable |
| `hashed_password` | String(255) | **nullable** (NULL = invitation en attente) |
| `is_active` | Boolean | défaut `True` |
| `created_at` | DateTime(tz) | `server_default=func.now()` |
| `last_login_at` | DateTime(tz) | nullable |
| `org_id` | Integer | FK `organizations.id`, `index=True` |
| `role` | String(20) | défaut `"admin"` |
| `created_by_id` | Integer | FK `users.id`, nullable |
| `totp_secret` | String(64) | nullable |
| `totp_enabled` | Boolean | défaut `False` |
| `failed_login_attempts` | Integer | défaut `0` |
| `locked_until` | DateTime(tz) | nullable |

**Constantes du module :**
```python
ROLES = ("admin", "security_lead", "developer", "auditor", "viewer")
GLOBAL_ACCESS_ROLES = ("admin", "security_lead")
```

**Propriétés calculées (non stockées, pour éviter toute désynchronisation) :**

| Propriété | Logique exacte |
|---|---|
| `status` | `"pending_invitation"` si `hashed_password is None` ; sinon `"active"` si `is_active` sinon `"disabled"` |
| `has_global_project_access` | `self.role in GLOBAL_ACCESS_ROLES` |
| `webauthn_enabled` | `len(self.credentials) > 0` |
| `has_mfa` | `self.totp_enabled or self.webauthn_enabled` |
| `mfa_methods` | Liste ordonnée : `["webauthn"]` puis `["totp"]` selon ce qui est actif |

Relations en cascade `all, delete-orphan` : `projects`, `credentials`, `recovery_codes`.

### 5.3 `projects` — `backend/app/models/project.py`

| Colonne | Type | Contraintes |
|---|---|---|
| `id` | Integer | PK |
| `name` | String(200) | |
| `owner_id` | Integer | FK `users.id`, `index=True` |
| `token_hash` | String(128) | `unique=True`, `index=True` — SHA-256 hex du token |
| `token_prefix` | String(20) | ex. `iacg_ab12…` (affichage UI) |
| `fail_on_severity` | String(10) | nullable — `None` = ne jamais bloquer |
| `created_at` | DateTime(tz) | `server_default=func.now()` |

**Contrainte** : `UniqueConstraint("owner_id", "name", name="uq_project_owner_name")` — deux projets du même utilisateur ne peuvent porter le même nom (violation → HTTP 409). Deux utilisateurs différents peuvent en revanche avoir un projet homonyme (test `test_same_name_allowed_for_different_users`).

Relations : `owner` → User ; `scans` (cascade delete-orphan) ; `ignored_rules` (cascade delete-orphan).

### 5.4 `scans` — `backend/app/models/scan.py`

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `project_id` | Integer | FK `projects.id`, `index=True` |
| `schema_version` | String(10) | défaut `"1.0"` |
| `repo` | String(300) | ex. `acme/payments-infra` |
| `branch` | String(200) | nullable |
| `commit_sha` | String(64) | nullable |
| `scanned_at` | DateTime(tz) | **Instant du scan côté pipeline** (fourni par le rapport) |
| `received_at` | DateTime(tz) | **Instant de réception côté API**, `server_default=func.now()` |
| `total_findings` | Integer | défaut `0` |

La distinction `scanned_at` / `received_at` est explicite : les tris et l'historique utilisent `scanned_at`.

### 5.5 `findings` — `backend/app/models/finding.py`

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `scan_id` | Integer | FK `scans.id`, `index=True` |
| `fingerprint` | String(64) | `index=True` — identité stable, **pas** unique |
| `source` | String(20) | `gitleaks` / `checkov` / `conftest` / `semgrep` |
| `category` | String(30) | `secret` / `misconfiguration` / `policy` / `vulnerability` |
| `rule_id` | String(120) | ex. `CKV_AWS_21`, `aws-access-token` |
| `title` | Text | |
| `severity` | String(10) | `index=True` |
| `resource` | String(300) | nullable — ex. `aws_s3_bucket.data` |
| `file` | String(500) | nullable |
| `line_start` / `line_end` | Integer | nullable |
| `remediation` | Text | nullable |
| `raw` | JSON | objet brut de l'outil, conservé pour l'audit/debug, défaut `dict` |

### 5.6 `finding_triage` — `backend/app/models/triage.py`

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `project_id` | Integer | FK `projects.id`, `index=True` |
| `fingerprint` | String(64) | `index=True` |
| `status` | String(20) | défaut `"open"` |
| `note` | Text | nullable — justification |
| `updated_by_id` | Integer | FK `users.id`, nullable |
| `updated_at` | DateTime(tz) | `server_default=func.now()`, `onupdate=func.now()` |

**Constante** : `TRIAGE_STATUSES = ("open", "acknowledged", "resolved", "false_positive")`.
**Contrainte** : `UniqueConstraint("project_id", "fingerprint", name="uq_triage_project_fp")`.

**Point de conception clé** : le triage est attaché au **fingerprint** (identité stable du problème), pas à une ligne `findings`. Un problème redétecté par un scan ultérieur conserve donc son statut au lieu de redevenir « nouveau ». `"open"` est l'état **implicite** : aucune ligne n'est créée tant qu'aucune décision n'est prise ; ré-ouvrir supprime la ligne.

### 5.7 `triage_audit_log` — `backend/app/models/audit_log.py`

Journal **append-only** des décisions de triage.

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `project_id` | Integer | FK `projects.id`, `index=True` |
| `project_name` | String(200) | **dénormalisé volontairement** |
| `owner_id` | Integer | FK `users.id`, `index=True` — **dénormalisé** |
| `finding_fingerprint` | String(64) | `index=True` |
| `finding_title` | Text | **dénormalisé** |
| `from_status` / `to_status` | String(20) | |
| `note` | Text | nullable |
| `user_id` | Integer | FK `users.id`, nullable |
| `created_at` | DateTime(tz) | `server_default=func.now()` |

La dénormalisation est justifiée dans le code : *« un journal d'audit ne doit jamais dépendre de la survie de ce qu'il audite »*. Un test le vérifie : `test_audit_log_survives_project_deletion`.

### 5.8 `admin_audit_logs` — `backend/app/models/admin_audit_log.py`

Journal **append-only** des actions d'administration de comptes — distinct de `triage_audit_log`.

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `org_id` | Integer | FK `organizations.id`, `index=True` |
| `actor_id` | Integer | FK `users.id`, `index=True` |
| `action` | String(50) | `index=True` |
| `target_user_id` | Integer | FK `users.id`, nullable, `index=True` |
| `details` | JSON | contexte libre par action, défaut `dict` |
| `created_at` | DateTime(tz) | `server_default=func.now()` |

**Valeurs de `action` réellement écrites par le code** (6) :

| `action` | Écrite dans | `details` |
|---|---|---|
| `user.invited` | `admin.invite_user` | `{"role": <role>}` |
| `user.role_changed` | `admin.change_role` | `{"old_role": …, "new_role": …}` |
| `user.enabled` | `admin.change_status` (is_active=true) | `{}` |
| `user.disabled` | `admin.change_status` (is_active=false) | `{}` |
| `user.webauthn_reset` | `admin.reset_webauthn` | `{}` |
| `user.project_access_updated` | `admin.set_project_access` | `{"project_ids": [ids triés]}` |

### 5.9 `ignored_rules` — `backend/app/models/ignored_rule.py`

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `project_id` | Integer | FK `projects.id`, `index=True` |
| `rule_id` | String(120) | ex. `CKV_AWS_3` |
| `note` | Text | nullable — justification |
| `created_by_id` | Integer | FK `users.id`, nullable |
| `created_at` | DateTime(tz) | `server_default=func.now()` |

**Contrainte** : `UniqueConstraint("project_id", "rule_id", name="uq_ignored_rule_project")`.
**Différence avec le triage** : une `IgnoredRule` exclut **toute occurrence** d'une règle sur un projet (exception de politique), alors que `FindingTriage` juge un problème précis. Les findings d'une règle ignorée restent **visibles** dans la liste, mais ne comptent ni dans le score ni dans le seuil de blocage.

### 5.10 `project_access` — `backend/app/models/project_access.py`

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `user_id` | Integer | FK `users.id`, `index=True` |
| `project_id` | Integer | FK `projects.id`, `index=True` |
| `granted_by_id` | Integer | FK `users.id`, nullable |
| `granted_at` | DateTime(tz) | `server_default=func.now()` |

**Contrainte** : `UniqueConstraint("user_id", "project_id", name="uq_project_access_user_project")`.
**Règle produit** : ne concerne que les rôles **sans** accès global (`developer`, `auditor`, `viewer`). Un utilisateur non-global sans aucune ligne ici **ne voit aucun projet**.

### 5.11 `invitations` — `backend/app/models/invitation.py`

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `email` | String(320) | `index=True` |
| `org_id` | Integer | FK `organizations.id`, `index=True` |
| `role` | String(20) | |
| `user_id` | Integer | FK `users.id`, `index=True` |
| `token_hash` | String(64) | `unique=True`, `index=True` — SHA-256, jamais le jeton en clair |
| `invited_by_id` | Integer | FK `users.id` |
| `expires_at` | DateTime(tz) | |
| `accepted_at` | DateTime(tz) | nullable |
| `created_at` | DateTime(tz) | `server_default=func.now()` |

**Décision de conception** : le compte `User` existe **dès l'envoi** de l'invitation (avec `hashed_password=None`). L'invitation ne porte que le jeton d'activation. Cela évite toute divergence entre « qui a été invité » et « qui existe en base ».

### 5.12 `webauthn_credentials` — `backend/app/models/credential.py`

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `user_id` | Integer | FK `users.id`, `index=True` |
| `credential_id` | LargeBinary(1024) | `unique=True`, `index=True` |
| `public_key` | LargeBinary(1024) | **clé publique uniquement** |
| `sign_count` | Integer | défaut `0` — compteur anti-clonage |
| `name` | String(100) | défaut `"Appareil"` |
| `transports` | String(120) | nullable |
| `created_at` | DateTime(tz) | `server_default=func.now()` |
| `last_used_at` | DateTime(tz) | nullable |

**Propriété de sécurité documentée** : le serveur ne stocke que la clé publique. L'empreinte digitale et la clé privée ne quittent jamais le TPM / Secure Enclave. Une fuite de cette table ne permet donc à personne d'usurper l'utilisateur — contrairement à un secret TOTP, qui est partagé.

### 5.13 `recovery_codes` — `backend/app/models/credential.py`

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `user_id` | Integer | FK `users.id`, `index=True` |
| `code_hash` | String(64) | `index=True` — SHA-256 |
| `used_at` | DateTime(tz) | nullable — garantit l'usage unique |

Propriété : `is_used` → `used_at is not None`.

### 5.14 `auth_challenges` — `backend/app/models/credential.py`

| Colonne | Type | Détail |
|---|---|---|
| `id` | Integer | PK |
| `user_id` | Integer | FK `users.id`, `index=True` |
| `challenge` | LargeBinary(256) | |
| `purpose` | String(30) | `"register"` ou `"authenticate"` |
| `expires_at` | DateTime(tz) | TTL = 300 s (`CHALLENGE_TTL_SECONDS`) |

**Justification du stockage serveur** (et non en cookie) : le challenge doit être **supprimé après usage** pour être à usage unique ; sinon une signature interceptée pourrait être rejouée tant que le cookie reste valide.

### 5.15 Diagramme relationnel (texte)

```
organizations 1───N users
                     │ 1
                     ├──N projects ──1──N scans ──1──N findings
                     │       │                          (fingerprint, non unique)
                     │       ├──N ignored_rules
                     │       ├──N finding_triage  (UQ: project_id + fingerprint)
                     │       └──N triage_audit_log (append-only, dénormalisé)
                     │
                     ├──N webauthn_credentials
                     ├──N recovery_codes
                     ├──N auth_challenges
                     ├──N project_access ──N──1 projects  (table de jonction explicite)
                     └──N invitations

organizations 1───N admin_audit_logs ──N──1 users (actor_id, target_user_id)
```

### 5.16 État de la base de dev (`backend/iacguard.db`)

Constaté au moment de l'analyse — utile pour situer l'échelle de la démonstration :

| Table | Lignes |
|---|---|
| `findings` | 150 |
| `scans` | 4 |
| `finding_triage` | 4 |
| `triage_audit_log` | 4 |
| `projects` | 3 |
| `users` | 2 |
| `organizations` | 2 |
| `webauthn_credentials`, `recovery_codes`, `auth_challenges`, `ignored_rules`, `project_access`, `admin_audit_logs`, `invitations` | 0 |

---

## 6. API — inventaire complet des endpoints

**48 routes** exposées (47 sous `/api` + `/health`), comptées sur les décorateurs `@router.*` des six modules de `backend/app/api/` plus `@app.get("/health")`.

### 6.1 Méta

| Méthode | Route | Auth | Réponse |
|---|---|---|---|
| `GET` | `/health` | Aucune (publique) | `{"status": "ok", "app": "iac-guard"}` |

### 6.2 Authentification — `backend/app/api/auth.py` (préfixe `/api/auth`)

| Méthode | Route | Auth | Payload | Réponse | Codes |
|---|---|---|---|---|---|
| `POST` | `/register` | — | `UserCreate` : `email`, `password` (12-1024 c.), `org_name?` (≤200) | `UserOut` | 201, 409 (e-mail existant), 422 |
| `POST` | `/login` | — | `UserLogin` : `email`, `password` | `LoginResult` : `{mfa_required, methods[], user?}` + cookie posé | 200, 401, 403 (compte désactivé), 429 (verrouillé) |
| `POST` | `/methods` | — | `EmailIn` : `email` | `LoginMethodsOut` : `{methods: [...]}` | 200 |
| `POST` | `/webauthn/login/options` | — | `EmailIn` | Options WebAuthn (JSON brut) | 200, 400 |
| `POST` | `/webauthn/login/verify` | — | `WebAuthnLoginVerifyIn` : `email`, `credential` (dict) | `UserOut` + cookie session | 200, 401 |
| `POST` | `/forgot-password` | — | `EmailIn` | `{"message": "Si un compte existe…"}` | **202 systématique** |
| `POST` | `/logout` | — | — | — (efface le cookie) | 204 |
| `GET` | `/me` | Session | — | `UserOut` | 200, 401 |
| `PATCH` | `/me` | Session | `ProfileUpdate` : `name?` (≤200), `email?` | `UserOut` | 200, 409 |
| `POST` | `/me/password` | Session | `PasswordChange` : `current_password`, `new_password` | — | 204, 401 |

**`UserOut`** = `{id, email, name, role, created_at, mfa_methods[]}` — ne contient jamais le hash.

### 6.3 Double authentification — `backend/app/api/twofa.py` (préfixe `/api/auth/2fa`)

| Méthode | Route | Auth | Payload | Réponse |
|---|---|---|---|---|
| `GET` | `/status` | Session | — | `MfaStatus` : `{totp_enabled, webauthn_enabled, devices[], recovery_codes_remaining}` |
| `POST` | `/webauthn/register/options` | Session | — | Options `navigator.credentials.create()` |
| `POST` | `/webauthn/register/verify` | Session | `{credential, device_name (≤100)}` | `MfaEnabledOut` : `{method: "webauthn", recovery_codes[]}` |
| `DELETE` | `/webauthn/{credential_id}` | Session | — | 204 / 404 |
| `POST` | `/webauthn/authenticate/options` | **MFA** | — | Options `navigator.credentials.get()` |
| `POST` | `/webauthn/authenticate/verify` | **MFA** | `{credential}` | `{id, email}` + cookie session |
| `POST` | `/totp/setup` | Session | — | `TotpSetupOut` : `{secret, otpauth_uri}` |
| `POST` | `/totp/confirm` | Session | `{code}` (6-10 c.) | `MfaEnabledOut` : `{method: "totp", recovery_codes[]}` |
| `DELETE` | `/totp` | Session | — | 204 |
| `POST` | `/totp/verify` | **MFA** | `{code}` | `{id, email}` + cookie session |
| `POST` | `/recovery/verify` | **MFA** | `{code}` (4-32 c.) | `{id, email}` + cookie session |
| `POST` | `/recovery/regenerate` | Session | — | `RecoveryCodesOut` : `{codes[]}` |

### 6.4 Projets — `backend/app/api/projects.py` (préfixe `/api/projects`)

| Méthode | Route | Auth | Payload | Réponse |
|---|---|---|---|---|
| `POST` | `` | Session | `{name}` (non vide après strip) | `ProjectCreated` : `{id, name, token_prefix, created_at, token}` — **token en clair, une seule fois** |
| `GET` | `` | Session | — | `list[ProjectOut]` (projets accessibles, sans token) |
| `GET` | `/{project_id}` | Session + accès | — | `ProjectDetail` : `{id, name, created_at, scan_count, latest_score, last_scan_at}` |
| `DELETE` | `/{project_id}` | Session + accès | — | 204 (cascade : scans, findings, triage, règles ignorées) |
| `POST` | `/{project_id}/rotate-token` | Session + accès | — | `ProjectTokenRotated` : `{token_prefix, token}` |
| `GET` | `/{project_id}/policy` | Session + accès | — | `ScanPolicyOut` : `{fail_on_severity, ignored_rules[]}` |
| `PATCH` | `/{project_id}/policy` | Session + accès | `{fail_on_severity}` ∈ `{critical, high, medium, low, info, null}` | `ScanPolicyOut` |
| `POST` | `/{project_id}/ignored-rules` | Session + accès | `{rule_id, note?}` | `IgnoredRuleOut` — 409 si déjà présente |
| `DELETE` | `/{project_id}/ignored-rules/{ignored_rule_id}` | Session + accès | — | 204 / 404 |

### 6.5 Ingestion — `backend/app/api/scans.py`

| Méthode | Route | Auth | Payload | Réponse |
|---|---|---|---|---|
| `POST` | `/api/scans` | **Token de projet** (`Bearer iacg_…`) | `ScanReportIn` : `{schema_version, scan:{repo, branch?, commit_sha?, created_at, tools[]}, findings[], summary?}` | `ScanAccepted` : `{scan_id, project_id, total_findings, should_fail, fail_reason}` — 201 |

Le champ `summary` envoyé par le pipeline est **accepté mais ignoré** : les compteurs sont recalculés côté serveur.

### 6.6 Lecture des scans et findings — `backend/app/api/findings.py`

| Méthode | Route | Auth | Query params | Réponse |
|---|---|---|---|---|
| `GET` | `/api/audit-log` | Session | `project_id?`, `page` (≥1, déf. 1), `page_size` (1-100, déf. 20) | `AuditLogPage` |
| `GET` | `/api/projects/{project_id}/scans` | Session + accès | — | `list[ScanListItem]` (tri : `scanned_at` desc) |
| `GET` | `/api/alerts` | Session | `project_id?`, `severity?`, `category?`, `status?`, `q?`, `page`, `page_size` (1-100) | `FindingsPage` |
| `GET` | `/api/scans/{scan_id}` | Session + accès | — | `ScanDetail` (= `ScanListItem` + `score`) |
| `GET` | `/api/scans/{scan_id}/findings` | Session + accès | `severity?`, `category?`, `status?` | `list[FindingOut]` |
| `PATCH` | `/api/scans/{scan_id}/findings/{finding_id}/triage` | Session + accès | Body `TriageIn` : `{status, note?}` | `FindingOut` — 422 si statut invalide, 404 si finding hors scan |

### 6.7 Administration — `backend/app/api/admin.py` (préfixe `/api/admin`)

Deux routeurs distincts : `router` (8 routes, toutes protégées par `require_role("admin")`) et `public_router` (1 route publique).

| Méthode | Route | Auth | Payload / Query | Réponse |
|---|---|---|---|---|
| `GET` | `/users` | admin | `page`, `page_size` (1-100) | `AdminUsersPage` : `items[{id, email, name, role, status, created_at, last_login_at, is_last_active_admin}]` |
| `POST` | `/users/invite` | admin | `{email, role ∈ ROLES}` | `InvitationOut` : `{email, role, expires_at}` — **jamais le jeton** — 201, 409, 429 |
| `PATCH` | `/users/{user_id}/role` | admin | `{role}` | `AdminUserOut` — 409 si dernier admin actif |
| `PATCH` | `/users/{user_id}/status` | admin | `{is_active}` | `AdminUserOut` — 409 si auto-désactivation ou dernier admin |
| `POST` | `/users/{user_id}/reset-webauthn` | admin | — | 204 |
| `GET` | `/users/{user_id}/project-access` | admin | — | `list[ProjectAccessOut]` : `[{id, name}]` |
| `PUT` | `/users/{user_id}/project-access` | admin | `{project_ids: [int]}` | `list[ProjectAccessOut]` — **remplacement intégral** |
| `GET` | `/audit-logs` | admin | `actor_id?`, `target_user_id?`, `action?`, `since?`, `until?`, `page`, `page_size` | `AdminAuditLogPage` |
| `POST` | `/invitations/{token}/accept` | **publique** | `{password}` (12-1024 c. + complexité) | `UserOut` — 400 si invalide/expirée/déjà utilisée |

---

## 7. Frontend — inventaire détaillé

### 7.1 Pages (App Router, `frontend/src/app/`)

| Route | Fichier | Auth | Contenu |
|---|---|---|---|
| `/` | `page.tsx` | `AuthGuard` | Sidebar + header + `<DashboardLive>` (dans `<Suspense>` car `useSearchParams`) |
| `/projects` | `projects/page.tsx` | `AuthGuard` | `<ProjectsManager>` |
| `/alerts` | `alerts/page.tsx` | `AuthGuard` | `<AlertsManager>` (dans `<Suspense>`) |
| `/settings` | `settings/page.tsx` | `AuthGuard` | 4 onglets : Compte, Sécurité, Politiques de scan, Audit |
| `/admin` | `admin/page.tsx` | `AuthGuard` + `AdminOnly` | 2 onglets : Comptes, Journal d'audit |
| `/security` | `security/page.tsx` | `AuthGuard` | `<SecurityManager>` en pleine page (max-w-2xl) |
| `/login` | `login/page.tsx` | — | Login en 3 étapes (`email` → `auth` → `mfa`) |
| `/signup` | `signup/page.tsx` | — | Création de compte + checklist de mot de passe en direct |
| `/forgot-password` | `forgot-password/page.tsx` | — | Formulaire e-mail, message identique quoi qu'il arrive |
| `/accept-invite` | `accept-invite/page.tsx` | — | Activation via `?token=…` + choix du mot de passe |

`layout.tsx` : polices Google `Geist` / `Geist_Mono`, providers imbriqués `LangProvider > AuthProvider > TooltipProvider`, `<Toaster richColors position="top-center" />`. Métadonnées : titre `"iac-guard — Security Dashboard"`.

### 7.2 Composants métier (`frontend/src/components/`, 18 fichiers)

| Composant | Lignes | Rôle |
|---|---|---|
| `users-manager.tsx` | 616 | Tableau des comptes, invitation, changement de rôle/statut, périmètre projets, reset WebAuthn |
| `projects-manager.tsx` | 520 | Liste des projets, création, révélation du token, rotation, suppression, recherche |
| `dashboard-live.tsx` | 397 | Orchestrateur du dashboard : projets, scans, findings, KPI, courbe, triage |
| `alerts-data-table.tsx` | 389 | Table TanStack : tri, filtre, pagination, menu de triage par ligne |
| `security-manager.tsx` | 384 | 3 cartes : WebAuthn, TOTP (QR code), codes de récupération |
| `scan-policy-manager.tsx` | 294 | Seuil de blocage par projet + gestion des règles ignorées |
| `alerts-manager.tsx` | 289 | Vue « toutes les alertes » : 4 filtres + recherche depuis l'URL |
| `admin-audit-log.tsx` | 284 | Journal d'audit admin : filtres action / cible / date, pagination |
| `finding-detail-sheet.tsx` | 274 | Panneau latéral : localisation, explication, remédiation, lien GitHub, triage |
| `site-header.tsx` | 217 | Titre contextuel, recherche, notifications réelles, menu utilisateur |
| `audit-log-viewer.tsx` | 187 | Journal des décisions de triage, filtre projet, pagination |
| `mfa-login-step.tsx` | 184 | Étape 2FA du login : biométrie / TOTP / code de récupération |
| `account-settings.tsx` | 178 | Nom, e-mail, changement de mot de passe |
| `app-sidebar.tsx` | 118 | Navigation ; l'entrée « Administration » est filtrée sur `user?.role === "admin"` |
| `activity-chart.tsx` | 89 | AreaChart Recharts empilé (critical / high / medium) |
| `recovery-codes-dialog.tsx` | 86 | Affichage unique des codes + copie + téléchargement `.txt` |
| `auth-shell.tsx` | 73 | Cadre des pages d'auth + sélecteur FR/العربية + `dir="rtl"` |
| `auth-provider.tsx` | 62 | Contexte React : `{user, loading, refresh, logout}` |
| `compliance-card.tsx` | 55 | Score réel + **4 référentiels illustratifs** (données factices) |
| `severity-badge.tsx` | 53 | `SeverityBadge` (5 niveaux colorés) + `StatusBadge` (4 statuts) |
| `kpi-cards.tsx` | 51 | 4 cartes KPI avec badge de variation |
| `zenith-logo.tsx` | 45 | Logo ZenithSoft en SVG `currentColor` |
| `auth-guard.tsx` | 35 | Redirection vers `/login` si pas de session |

**23 composants UI shadcn** dans `components/ui/` : `alert`, `avatar`, `badge`, `breadcrumb`, `button`, `card`, `chart`, `dialog`, `dropdown-menu`, `input-otp`, `input`, `label`, `progress`, `select`, `separator`, `sheet`, `sidebar`, `skeleton`, `sonner`, `table`, `tabs`, `textarea`, `tooltip`.

### 7.3 Modules `lib/`

| Fichier | Lignes | Rôle |
|---|---|---|
| `auth-api.ts` | 209 | `request<T>()` générique + `ApiError` + `authApi` (23 méthodes d'auth/2FA) |
| `platform-api.ts` | 227 | `platformApi` (14 méthodes : projets, scans, findings, politique, audit) |
| `admin-api.ts` | 164 | `adminApi` (8 méthodes) + constantes `ROLES`, `ROLE_LABELS`, `STATUS_LABELS`, `ACTION_LABELS` |
| `data.ts` | 253 | Types partagés (`Severity`, `Alert`, `Kpi`…) **+ données factices** (11 alertes, 4 référentiels, série d'activité) |
| `finding-explainer.ts` | 190 | Base de connaissances pédagogique : 14 règles + 4 replis par catégorie |
| `i18n.tsx` | 169 | Contexte FR/AR + 44 clés de traduction, persistance `localStorage` |
| `utils.ts` | 6 | `cn()` = `twMerge(clsx(...))` |

**Fonction `request<T>()`** (`auth-api.ts:21`), pierre angulaire de tous les appels :
- Base URL : `process.env.NEXT_PUBLIC_API_URL` (défaut `http://localhost:8000`), slash final retiré.
- `credentials: "include"` — indispensable pour que le navigateur envoie le cookie httpOnly posé par l'origine `:8000`.
- En-tête `Content-Type: application/json` par défaut.
- `204` → renvoie `undefined`.
- Erreur réseau → `ApiError(0, "Impossible de joindre le serveur. Est-il démarré ?")`.
- Erreur HTTP → extrait `data.detail ?? data.message` ; si `detail` est un tableau (erreurs Pydantic), concatène les `msg`.

### 7.4 Usage réel vs données factices

| Zone du dashboard | Source des données |
|---|---|
| KPI (score, ouverts, critical&high, scans 7 j) | **API réelle** — calculés dans `dashboard-live.tsx` |
| Courbe d'activité | **API réelle** — un point par scan (7 derniers), `by_severity` de chaque `ScanDetail` |
| Table d'alertes | **API réelle** — `listFindings(scans[0].id)` |
| Notifications du header | **API réelle** — `listAlerts({status:"open", page_size:5})` |
| Carte « Compliance » : grade + score | **API réelle** |
| Carte « Compliance » : 4 référentiels (CNDP 38/45, BAM 27/34, CIS AWS 112/140, ISO 27001 61/78) | **DONNÉES FACTICES** (`data.ts:complianceFrameworks`) — le commentaire du composant l'assume : *« les référentiels restent illustratifs tant que le moteur de conformité n'est pas branché »* |
| `alerts`, `kpis`, `activitySeries`, `complianceScore` de `data.ts` | **Non consommés** par l'UI en production (seuls les *types* sont importés) — reliquat de la maquette initiale |

---

## 8. Fonctionnalités implémentées — inventaire exhaustif

### F1 — Ingestion de scans authentifiée par token de projet

- **Statut** : Terminé
- **Fichiers** : `backend/app/api/scans.py`, `backend/app/api/deps.py:82-95`, `backend/app/core/security.py:54-66`, `backend/app/schemas/ingest.py`
- **Fonctionnement** :
  1. Le pipeline POST `/api/scans` avec `Authorization: Bearer iacg_<43 caractères>`.
  2. `get_project_from_token` extrait le token, calcule `hashlib.sha256(token).hexdigest()`, cherche `Project.token_hash == hash`. Aucune correspondance → 401.
  3. **Le projet est identifié par le token, jamais par le payload** — un client ne peut donc écrire que dans son propre projet (test `test_ingest_writes_only_to_own_project`).
  4. Création du `Scan` (`db.flush()` pour obtenir `scan.id`), puis insertion de N `Finding`, puis `db.commit()` — transaction unique.
  5. Évaluation de la politique de blocage (voir F9) et réponse `ScanAccepted`.
- **Tests** : `test_ingest_requires_valid_project_token`, `test_user_jwt_cannot_be_used_to_ingest`, `test_ingest_persists_scan_and_findings`, `test_ingest_writes_only_to_own_project`.

### F2 — Normalisation multi-scanners (aggregator)

- **Statut** : Terminé (4 parsers) — mais Conftest n'est pas déclenché par le workflow recommandé (voir §9.3)
- **Fichiers** : `pipeline/aggregator/aggregator.py`, `pipeline/aggregator/schema.py`
- **Fonctionnement** : 4 fonctions de parsing, chacune produisant `list[Finding]`, puis `ScanReport.build()` qui calcule le `Summary`.

| Parser | Format d'entrée attendu | Mapping | Sévérité |
|---|---|---|---|
| `parse_gitleaks(data)` | Liste plate | `RuleID`→`rule_id`, `Description`→`title`, `File`→`file`, `StartLine`/`EndLine` | **Toujours `CRITICAL`** (un secret exposé n'a pas de sévérité native) ; remédiation en dur : *« Retirer le secret du code, le révoquer et le stocker dans un gestionnaire de secrets (Vault, SSM, GitHub Secrets). »* |
| `parse_checkov(data)` | `{results:{failed_checks:[…]}}` — accepte aussi une **liste** d'objets (multi-frameworks) | `check_id`→`rule_id`, `check_name`→`title`, `resource`, `repo_file_path` ou `file_path`, `file_line_range[0..1]`, `guideline`→`remediation` | `_norm_severity(chk["severity"], défaut MEDIUM)` |
| `parse_conftest(data)` | Liste de blocs par fichier | Itère `("failures", HIGH)` puis `("warnings", LOW)` ; `metadata.rule_id` ou `namespace` ou `"policy"` ; `metadata.title` ou `msg` | `_norm_severity(meta["severity"], défaut selon le type) ` |
| `parse_semgrep(data)` | `{results:[…]}` | `check_id`→`rule_id`, `extra.message` **première ligne seulement** (`.split("\n")[0]`), `path`, `start.line`/`end.line`, `extra.fix`→`remediation` | `_norm_severity(extra["severity"], défaut MEDIUM)` |

**Table de normalisation des sévérités** (`_SEVERITY_MAP`, valeurs exactes) :

```python
"critical" → CRITICAL     "high" → HIGH
"medium" → MEDIUM         "moderate" → MEDIUM
"low" → LOW               "info" → INFO
"informational" → INFO    "none" → INFO
"error" → HIGH            # Semgrep ERROR
"warning" → MEDIUM        # Semgrep WARNING
```
Comparaison faite sur `str(value).strip().lower()` ; valeur inconnue ou vide → défaut du parser.

**Détection des versions d'outils** : `gitleaks` sans version ; `checkov` → `data["summary"]["checkov_version"]` ; `conftest` sans version ; `semgrep` → `data["version"]`. Un outil dont le fichier JSON est absent ou vide (`_load_json` renvoie `None` si le fichier n'existe pas ou fait 0 octet) n'apparaît pas dans `tools[]`.

### F3 — Empreinte stable (fingerprint) et suivi dans le temps

- **Statut** : Terminé
- **Fichier** : `pipeline/aggregator/schema.py:90-101`
- **Algorithme exact** :
  ```python
  parts = [source.value, rule_id, file or "", str(line_start or ""), resource or ""]
  fingerprint = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
  ```
  C'est un `@computed_field` Pydantic : recalculé à chaque sérialisation, jamais stocké dans le pipeline.
- **Propriété** : indépendant du contenu `raw`. Un même problème redétecté d'un scan à l'autre produit le même fingerprint, ce qui permet au triage de survivre (F8).
- **Note factuelle** : SHA-1 est utilisé ici comme identifiant de déduplication, pas comme primitive de sécurité. La colonne `findings.fingerprint` est déclarée `String(64)` alors qu'un SHA-1 hexadécimal fait 40 caractères.

### F4 — Score de conformité pondéré

- **Statut** : Terminé (limitation connue : saturation)
- **Fichier** : `backend/app/services/scoring.py`
- **Poids exacts** (`SEVERITY_WEIGHTS`) :

| Sévérité | Points retirés par finding |
|---|---|
| `critical` | **25** |
| `high` | **10** |
| `medium` | **3** |
| `low` | **1** |
| `info` | **0** |

- **Formule** : `score = max(0, 100 - Σ(nombre[sev] × poids[sev]))`
- **Barème des grades** (`_grade`) : `≥90 → A` · `≥75 → B` · `≥60 → C` · `≥40 → D` · sinon `F`
- **Robustesse** : `counts = {sev: int(by_severity.get(sev, 0)) for sev in SEVERITY_WEIGHTS}` — les sévérités inconnues sont ignorées, les valeurs textuelles (`"2"`) sont converties. Tests dédiés : `test_unknown_severities_are_ignored_in_penalty`, `test_string_counts_are_coerced`.
- **Calculé à la lecture, jamais stocké** : les poids peuvent être ajustés sans re-scanner.
- **Limitation documentée** : avec 25 points par finding critique, 4 secrets exposés suffisent à atteindre 0. Le README liste explicitement *« révision du calcul de score, qui sature sur les dépôts très vulnérables »* dans les travaux en cours.
- **`ScoreResult`** (dataclass) : `{score: int, grade: str, total_findings: int, by_severity: dict[str,int]}`.

### F5 — Politique de blocage du pipeline (`fail_on_severity`)

- **Statut** : Terminé
- **Fichiers** : `backend/app/services/scoring.py:66-74`, `backend/app/api/scans.py:65-83`, `backend/app/api/projects.py:153-178`, `pipeline/aggregator/aggregator.py:293-302`
- **Ordre de gravité** : `SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]`
- **Algorithme `exceeds_threshold(by_severity, threshold)`** :
  ```python
  if not threshold or threshold not in SEVERITY_ORDER: return False   # politique désactivée
  idx = SEVERITY_ORDER.index(threshold)
  return any(by_severity.get(sev, 0) > 0 for sev in SEVERITY_ORDER[idx:])
  ```
  Autrement dit : bloque dès qu'un finding non exclu atteint le seuil **ou pire**.
- **Chaîne complète du blocage** :
  1. Le scan est **toujours enregistré**, même si la politique est dépassée.
  2. L'API renvoie `should_fail: true` + `fail_reason: "Politique du projet : blocage dès qu'un finding atteint la gravité '<seuil>' ou pire."`
  3. `aggregator.main()` lit `result.get("should_fail")`, imprime `[iac-guard] ÉCHEC DU PIPELINE : <raison>` et **retourne 1**.
  4. Le step GitHub Actions échoue (pas de `continue-on-error` sur cette étape — c'est délibéré et commenté).
  5. Avec la branch protection GitHub exigeant le check `scan`, le bouton « Merge » est grisé.
- **Configuration** : `PATCH /api/projects/{id}/policy` avec `fail_on_severity ∈ {critical, high, medium, low, info, null}` (validateur `FAIL_SEVERITY_CHOICES` dans `schemas/project.py`). `null` = ne jamais bloquer (comportement par défaut, rétro-compatible).
- **Tests** : `test_no_policy_never_fails`, `test_threshold_blocks_on_critical`, `test_threshold_does_not_block_below_it`, `test_invalid_severity_rejected`, `test_ignored_rule_excluded_from_threshold`, `test_policy_isolated_per_user`.

### F6 — Exceptions de règles (`IgnoredRule`)

- **Statut** : Terminé
- **Fichiers** : `backend/app/models/ignored_rule.py`, `backend/app/api/projects.py:181-227`, `backend/app/services/aggregates.py`
- **Fonctionnement** : `ignored_rule_ids(db, project_id)` renvoie un `set[str]` de `rule_id`. `severity_counts(db, scan_id, exclude_rule_ids)` ajoute `WHERE Finding.rule_id NOT IN (...)` au `GROUP BY Finding.severity`. Les findings exclus **restent visibles** dans les listes mais ne pèsent ni sur le score ni sur le seuil de blocage.
- **Justification obligatoire ?** Non — `note` est optionnel, mais l'UI l'encourage et il est affiché dans la vue Politiques.
- **Tests** : `test_ignored_rule_excluded_from_score`, `test_duplicate_ignored_rule_rejected` (409), `test_remove_ignored_rule_restores_score`.

### F7 — Vue « dernier état » des alertes multi-projets

- **Statut** : Terminé
- **Fichier** : `backend/app/api/findings.py:135-215`
- **Algorithme** :
  1. `list_accessible_projects(db, user)` → projets visibles (voir F13).
  2. Filtre optionnel sur `project_id`.
  3. **Pour chaque projet** : récupération du scan le plus récent (`ORDER BY scanned_at DESC LIMIT 1`). Projet sans scan → ignoré.
  4. Requête des `Finding` de ce seul scan, avec filtres SQL `severity` et `category`.
  5. Chargement de la carte de triage du projet (`_triage_map` : `{fingerprint: FindingTriage}`), statut par défaut `"open"`.
  6. Filtre `status` appliqué en Python.
  7. Filtre plein texte `q` : recherche insensible à la casse dans la concaténation de `title`, `resource`, `file`, `rule_id`.
  8. Enrichissement en `FindingWithProject` : `project_id`, `project_name`, `repo`, `scan_id`, `detected_at`, `commit_sha`.
  9. **Tri** : `key=(SEVERITY_WEIGHTS.get(severity, 0), id)`, `reverse=True` — plus grave d'abord, puis le plus récemment détecté.
  10. Pagination en mémoire : `rows[(page-1)*page_size : ...]`, `total` = longueur avant découpe.
- **Justification du « dernier scan seulement »** : sans cela, un même problème redétecté à chaque scan apparaîtrait en double, triple, etc.
- **Limite de performance connue** : la pagination et une partie du filtrage se font en mémoire Python, après avoir chargé toutes les lignes. Idem pour `/api/audit-log` et `/api/admin/*`. Acceptable à l'échelle de la démonstration (150 findings), pas à l'échelle d'un vrai SaaS.

### F8 — Triage des findings avec persistance par fingerprint

- **Statut** : Terminé
- **Fichier** : `backend/app/api/findings.py:270-338`
- **Statuts** : `open`, `acknowledged`, `resolved`, `false_positive`
- **Algorithme** :
  1. Validation du statut contre `TRIAGE_STATUSES` → 422 sinon.
  2. Vérification que le `finding_id` appartient bien au `scan_id` → 404 sinon.
  3. Lecture de la décision existante (`project_id` + `fingerprint`) → `previous_status` (`"open"` si aucune).
  4. **Si `status == "open"`** : suppression de la ligne `FindingTriage` (« open » est l'état implicite), journalisation, commit.
  5. **Sinon** : création ou mise à jour de la ligne, avec `note` et `updated_by_id`.
  6. **Journalisation** (`_log_change`) : n'écrit dans `triage_audit_log` **que si** `previous_status != payload.status` — un changement no-op n'est pas journalisé (test `test_no_op_status_change_not_logged`). L'entrée dénormalise `project_name`, `owner_id`, `finding_title`.
- **Persistance dans le temps** : le triage étant indexé par `fingerprint` et `project_id`, le scan suivant qui redétecte le même problème le retrouve avec son statut (test `test_triage_survives_rescan`).

### F9 — Deux journaux d'audit append-only

- **Statut** : Terminé
- **Journal 1 — décisions de triage** (`triage_audit_log`) : lisible via `GET /api/audit-log`, UI dans l'onglet Audit des Settings. Filtrage de visibilité **par `owner_id` dénormalisé** (et non par jointure sur `projects`), précisément pour que les lignes restent lisibles après suppression du projet.
- **Journal 2 — actions d'administration** (`admin_audit_logs`) : lisible via `GET /api/admin/audit-logs` (admin seul), UI dans l'onglet Journal d'audit de `/admin`. Filtres : `actor_id`, `target_user_id`, `action`, `since`, `until`.
- **Écriture** : `log_admin_action(db, actor=…, action=…, target_user=…, details=…)` (`services/admin_audit.py`) **n'appelle jamais `db.commit()`** — le routeur commite l'action métier et sa ligne d'audit dans la **même transaction**, pour ne jamais avoir l'une sans l'autre.
- **Aucune route de suppression ou de modification** n'existe sur ces deux tables.

### F10 — Authentification par mot de passe (Argon2id)

- **Statut** : Terminé
- **Fichier** : `backend/app/core/security.py`
- **Hachage** : `argon2.PasswordHasher()` avec les paramètres par défaut d'argon2-cffi, alignés OWASP (**m=64 MiB, t=3, p=4**), sel aléatoire embarqué dans le hash.
- **Bornes** : `MAX_PASSWORD_BYTES = 1024` (protection anti-DoS : hacher 1 Mo de « a » coûterait cher), `BCRYPT_MAX_BYTES = 72`.
- **Politique de complexité** (`schemas/user.py`) : `PASSWORD_MIN = 12`, `PASSWORD_MAX = 1024`, et 4 règles obligatoires appliquées **côté serveur** :

  | Regex | Exigence |
  |---|---|
  | `[a-z]` | une minuscule |
  | `[A-Z]` | une majuscule |
  | `\d` | un chiffre |
  | `[^A-Za-z0-9]` | un caractère spécial |

  Le frontend affiche la même checklist en direct (`signup/page.tsx`, `accept-invite/page.tsx`), avec le commentaire explicite : *« le serveur reste la référence, ceci n'est qu'un retour visuel »*.
- **Migration transparente bcrypt → Argon2id** : `verify_password` détecte un hash commençant par `$2` (bcrypt `$2a$`/`$2b$`/`$2y$`) et le vérifie avec `bcrypt.checkpw`. `needs_rehash` renvoie `True` pour tout hash bcrypt, ou si `_argon2.check_needs_rehash()` le demande. Au login réussi — **seul moment où le mot de passe est connu en clair** — le hash est régénéré en Argon2id. Test : `test_login_upgrades_legacy_bcrypt_hash_to_argon2`.
- **Protection contre la troncature bcrypt** : un mot de passe de plus de 72 octets est **refusé** plutôt que tronqué, sinon deux mots de passe différents ouvriraient le même compte (test `test_long_password_cannot_pass_via_bcrypt_truncation`).
- **`verify_password` ne lève jamais** : renvoie `False` sur `VerifyMismatchError`, `VerificationError`, `InvalidHashError` (hash corrompu ou format inconnu).

### F11 — Session par cookie httpOnly et JWT à portée

- **Statut** : Terminé
- **Fichiers** : `backend/app/core/security.py:142-196`, `backend/app/api/cookies.py`, `backend/app/core/config.py`
- **JWT** : algorithme **HS256**, payload `{sub: str(user_id), scope: "session"|"mfa", iat, exp}`. La spec JWT impose une chaîne pour `sub` — d'où le `str()`.
- **Le JWT ne contient JAMAIS le rôle** : `_resolve_user` recharge l'utilisateur depuis la base à chaque requête. Un changement de rôle ou une désactivation prend donc effet **immédiatement**, sans attendre l'expiration du jeton (test `test_jwt_of_deleted_user_is_rejected`, `test_disabled_user_cannot_log_in`).
- **Cookies** :

  | Cookie | Nom (configurable) | Durée | Attributs |
  |---|---|---|---|
  | Session | `iacguard_session` | `access_token_expire_minutes × 60` = **1440 min (24 h)** | `httponly=True`, `secure=settings.cookie_secure`, `samesite="lax"`, `path="/"` |
  | MFA | `iacguard_mfa` | `mfa_token_expire_minutes × 60` = **5 min** | idem |

- `set_session_cookie()` efface systématiquement le cookie MFA (il a rempli son rôle).
- **Justification httpOnly** : JavaScript ne peut pas lire le cookie ; une faille XSS sur le dashboard ne permet donc **pas** d'exfiltrer la session — contrairement à un token en `localStorage`.
- **Justification SameSite=Lax** : le navigateur n'envoie pas le cookie sur une requête POST venue d'un autre site, ce qui neutralise l'essentiel des attaques CSRF.
- Les clients non-navigateur peuvent utiliser `Authorization: Bearer <JWT>` — c'est ce que font les tests.

### F12 — Double authentification (WebAuthn + TOTP + codes de récupération)

- **Statut** : Terminé
- **Fichiers** : `backend/app/services/mfa.py`, `backend/app/api/twofa.py`, `frontend/src/components/security-manager.tsx`, `frontend/src/components/mfa-login-step.tsx`

**a) WebAuthn / passkey (biométrie, Windows Hello, Touch ID, clé physique)**

| Paramètre | Valeur exacte |
|---|---|
| `rp_id` | `settings.webauthn_rp_id` = `"localhost"` (doit être le domaine du **frontend**, pas de l'API) |
| `rp_name` | `"iac-guard"` |
| `expected_origin` | `settings.webauthn_origins` = `["http://localhost:3000"]` |
| `user_verification` | `UserVerificationRequirement.REQUIRED` — l'appareil DOIT vérifier l'utilisateur (empreinte/visage/PIN), sinon ce ne serait pas un vrai second facteur |
| `resident_key` | `ResidentKeyRequirement.PREFERRED` |
| `exclude_credentials` | Liste des `credential_id` déjà enrôlés — empêche d'enrôler deux fois le même appareil |
| `require_user_verification` (vérification) | `True` |
| TTL du challenge | `CHALLENGE_TTL_SECONDS = 300` (5 min) |

  - **Challenge à usage unique** : `_store_challenge` supprime tout challenge antérieur du même `(user_id, purpose)` puis en insère un nouveau. `_consume_challenge` **lit ET supprime** la ligne avant même de vérifier l'expiration.
  - **Anti-clonage** : après vérification, si `verified.new_sign_count != 0 and verified.new_sign_count <= stored.sign_count` → `MfaError("Clé potentiellement clonée : authentification refusée.")`. Le cas `new_sign_count == 0` est explicitement toléré : beaucoup de passkeys renvoient toujours 0, on ne peut alors rien en déduire.
  - **Gestion des erreurs** : capture de `WebAuthnException` (classe de base de toute la librairie) plutôt que d'énumérer les sous-classes et d'en oublier une — ce qui produirait un 500. Un test envoie du JSON invalide pour le vérifier (`test_webauthn_registration_rejects_garbage`).
  - Côté navigateur : `@simplewebauthn/browser` — `startRegistration({optionsJSON})` et `startAuthentication({optionsJSON})`. Le nom d'appareil par défaut est `navigator.platform`.

**b) TOTP**

  - Secret : `pyotp.random_base32()`, stocké dans `users.totp_secret`.
  - URI de provisionnement : `pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="iac-guard")` — encodé en QR code par `qrcode.react` (`QRCodeSVG`, `size=180`).
  - **Vérification** : `pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)` — la fenêtre ±1 (±30 s) compense la dérive d'horloge des téléphones.
  - **Le TOTP n'est activé qu'après un premier code valide** (`totp_confirm`) : `totp_setup` stocke le secret mais laisse `totp_enabled = False`. Sans cela on enfermerait l'utilisateur dehors si son application était mal configurée.

**c) Codes de récupération**

  - `RECOVERY_CODE_COUNT = 8`
  - Format : `f"{secrets.token_hex(2)}-{secrets.token_hex(2)}"` → 8 codes du type `a1b2-c3d4`.
  - Hachés en **SHA-256** de `code.strip().lower()`. Justification : le code est généré aléatoirement, donc non attaquable par dictionnaire — contrairement à un mot de passe humain.
  - Comparaison **à temps constant** : `hmac.compare_digest(hash_recovery_code(code), hashed)`.
  - **Générés uniquement à la PREMIÈRE activation d'une méthode 2FA** (`first_method = not current_user.has_mfa`). Régénération manuelle via `POST /recovery/regenerate` (invalide tous les anciens : `db.query(RecoveryCode).filter(...).delete()`).
  - Usage unique garanti par `used_at`.
  - UI : `RecoveryCodesDialog` propose la copie presse-papiers et le téléchargement en `iac-guard-recovery-codes.txt` (Blob + `URL.createObjectURL`).

**d) Flux de connexion complet**

```
POST /api/auth/methods {email}
  → {methods: ["webauthn","password"]} si passkey enrôlée, sinon ["password"]
       │
       ├─ Chemin A (passkey en 1er facteur, sans mot de passe)
       │   POST /api/auth/webauthn/login/options {email}
       │   → navigator.credentials.get()
       │   POST /api/auth/webauthn/login/verify {email, credential}
       │   → cookie SESSION posé directement
       │
       └─ Chemin B (mot de passe)
           POST /api/auth/login {email, password}
           ├─ pas de 2FA → cookie SESSION, {mfa_required:false, user}
           └─ 2FA active → cookie MFA (5 min), {mfa_required:true, methods:[…]}
                  │
                  ├─ POST /api/auth/2fa/webauthn/authenticate/{options,verify}
                  ├─ POST /api/auth/2fa/totp/verify {code}
                  └─ POST /api/auth/2fa/recovery/verify {code}
                          → cookie SESSION posé, cookie MFA effacé
```

### F13 — RBAC à 5 rôles et cloisonnement des projets

- **Statut** : Terminé
- **Fichiers** : `backend/app/api/deps.py:98-196`, `backend/app/models/user.py`, `backend/app/api/admin.py`

**Les 5 rôles :**

| Rôle | Libellé UI (`ROLE_LABELS`) | Accès global aux projets ? | Accès aux routes `/api/admin/*` ? |
|---|---|---|---|
| `admin` | Administrateur | **Oui** | **Oui** |
| `security_lead` | Responsable sécurité | **Oui** | Non |
| `developer` | Développeur | Non (octroi explicite requis) | Non |
| `auditor` | Auditeur | Non | Non |
| `viewer` | Lecteur | Non | Non |

**Deux mécanismes distincts :**

1. **`require_role(*roles)`** — dependency factory. Chaque route admin déclare `Depends(require_role("admin"))`. Le rôle est **relu en base** à chaque requête via `get_current_user`. Refus → 403 avec le message `"Action réservée aux rôles : admin."`

2. **Cloisonnement des projets** — `_accessible_projects_stmt(db, user)` :
   ```python
   if user.has_global_project_access:          # admin ou security_lead
       org_member_ids = select(User.id).where(User.org_id == user.org_id)
       return select(Project).where(Project.owner_id.in_(org_member_ids))
   shared_ids = select(ProjectAccess.project_id).where(ProjectAccess.user_id == user.id)
   return select(Project).where((Project.owner_id == user.id) | (Project.id.in_(shared_ids)))
   ```
   `_can_access(db, user, project)` applique la même logique pour un projet unique. `get_accessible_project` / `get_accessible_scan` sont les dépendances utilisées par les routes.

- **Choix de sécurité explicite** : hors périmètre → **404, pas 403**. Le commentaire du code : *« un 403 confirmerait son existence. De l'extérieur, "ça n'existe pas" et "tu n'y as pas accès" doivent être indiscernables. »* Messages : `"Projet introuvable."`, `"Scan introuvable."`
- **Garde-fou frontend** : le composant `AdminOnly` (`app/admin/page.tsx`) masque l'écran et la sidebar filtre l'entrée « Administration ». Le code documente que ce n'est **qu'un confort** : *« un non-admin qui forcerait l'URL recevrait de toute façon des 403 sur chaque appel »*.
- **Tests** : `test_non_admin_cannot_access_admin_routes`, `test_user_without_project_access_sees_nothing`, `test_granting_project_access_makes_it_visible`, `test_revoking_project_access_hides_it_again`, `test_security_lead_sees_all_org_projects_without_grant`, `test_admin_cannot_manage_user_of_another_org`, `test_user_cannot_see_other_users_project`.

### F14 — Invitations par jeton expirant

- **Statut** : Terminé **côté flux** / **Stub côté envoi d'e-mail**
- **Fichiers** : `backend/app/api/admin.py:125-214` et `:420-448`, `backend/app/services/email.py`, `frontend/src/app/accept-invite/page.tsx`
- **Paramètres** : `invitation_expire_hours = 72`, `max_invites_per_hour = 10`
- **Algorithme d'invitation** :
  1. **Rate limiting** : comptage des entrées `AdminAuditLog` avec `action == "user.invited"`, `actor_id == current_user.id`, `created_at >= now - 1h`. Si `>= 10` → **429** `"Trop d'invitations envoyées récemment (max 10/heure)."`
  2. Recherche d'un compte existant pour cet e-mail :
     - autre organisation → **409** `"Cet e-mail est déjà associé à un compte."`
     - même organisation avec mot de passe → **409** `"Cet utilisateur a déjà un compte actif."`
     - même organisation sans mot de passe (invitation en attente) → réutilisation, mise à jour du rôle
     - inexistant → création d'un `User` avec `hashed_password=None`, `created_by_id = admin.id`
  3. **Ré-invitation** : `DELETE FROM invitations WHERE user_id = X AND accepted_at IS NULL` — toute invitation antérieure non acceptée devient caduque (test `test_reinvite_invalidates_previous_token`).
  4. Génération du jeton : `secrets.token_urlsafe(32)`. **Seul son SHA-256 est stocké** ; le jeton n'est **jamais** renvoyé dans la réponse HTTP.
  5. Journalisation `user.invited` avec `details={"role": role}`.
  6. `send_invitation_email(to_email, token, inviter_name)`.
- **Acceptation** (`POST /api/admin/invitations/{token}/accept`, route publique) :
  - Lookup par `hash_token(token)` ; si introuvable **ou** `accepted_at is not None` → 400 `"Invitation invalide ou déjà utilisée."`
  - Vérification d'expiration avec re-localisation UTC des datetimes naïfs (SQLite) → 400 `"Cette invitation a expiré. Demandez à un admin de la renvoyer."`
  - Pose du mot de passe (Argon2id), `is_active = True`, `accepted_at = now`.
- **Le stub d'e-mail** (`services/email.py`) : construit `link = f"{settings.frontend_url}/accept-invite?token={token}"` puis appelle `logger.warning(...)`. Le choix du niveau **WARNING** (et non INFO) est justifié dans le code : le niveau par défaut de Python filtre INFO, et le lien serait invisible — or c'est **aujourd'hui le seul moyen de le récupérer**. Le message commence par `"AUCUN SMTP CONFIGURÉ — …"`.

### F15 — Règles métier de protection des comptes

- **Statut** : Terminé
- **Fichier** : `backend/app/api/admin.py:63-93, 217-274`

| Règle | Implémentation | Code HTTP | Message |
|---|---|---|---|
| Le dernier administrateur actif ne peut pas être rétrogradé | `_is_last_active_admin()` : `role == "admin"` ET `status == "active"` ET `_active_admin_count(org) <= 1` | 409 | `"Impossible de rétrograder le dernier administrateur actif."` |
| Le dernier administrateur actif ne peut pas être désactivé | idem | 409 | `"Impossible de désactiver le dernier administrateur actif."` |
| Un admin ne peut pas désactiver son propre compte | `target.id == current_user.id` | 409 | `"Vous ne pouvez pas désactiver votre propre compte."` |
| Un admin ne gère que les membres de son organisation | `_get_org_member()` : `target.org_id != current_user.org_id` → 404 | 404 | `"Utilisateur introuvable."` |
| Un admin ne partage que des projets de son organisation | `set_project_access` filtre les ids sur `Project.owner_id IN (membres de l'org)` | — | Ids invalides **silencieusement ignorés** (justification : un id périmé ne doit pas faire échouer tout le formulaire) |

`_active_admin_count` compte les `User` avec `org_id == X`, `role == "admin"`, `is_active IS TRUE`, `hashed_password IS NOT NULL` — un admin invité mais non activé ne compte donc pas.

Le champ `is_last_active_admin` est renvoyé dans `AdminUserOut` pour que le frontend désactive les actions correspondantes (tooltip `LAST_ADMIN_HINT`).

**Tests** : `test_last_active_admin_cannot_be_demoted`, `test_last_active_admin_cannot_be_disabled`, `test_admin_cannot_disable_self_even_with_another_admin`.

### F16 — Anti-brute-force et anti-énumération de comptes

- **Statut** : Terminé
- **Fichier** : `backend/app/api/auth.py`
- **Paramètres** : `max_login_attempts = 5`, `lockout_minutes = 15`
- **Verrouillage** (`_register_failure`) : `failed_login_attempts += 1` ; si `>= 5`, alors `locked_until = now + 15 min` et **le compteur est remis à 0** (il repart après le verrou). `_is_locked` gère la re-localisation UTC des datetimes naïfs SQLite. Compte verrouillé → **429** avec le message indiquant la durée.
- **Réinitialisation** : un login réussi remet `failed_login_attempts = 0` et `locked_until = None`.
- **Anti-énumération — 4 mesures distinctes** :

  1. **Message unique** : `_BAD_CREDENTIALS` = 401 `"E-mail ou mot de passe incorrect."` — identique que l'e-mail existe ou non (test `test_login_unknown_email_gives_same_error_as_wrong_password`).
  2. **Anti-timing** : si l'utilisateur est introuvable **ou** si son `hashed_password` est `None` (invitation en attente), le code appelle quand même `hash_password(payload.password)` — sinon une réponse instantanée trahirait l'absence de compte.
  3. **`POST /api/auth/methods`** : renvoie **toujours** `["password"]` au minimum. `"webauthn"` n'est ajouté (en tête) que si le compte existe, est actif et a enrôlé une passkey — information de toute façon inutilisable sans l'appareil physique (test `test_login_methods_do_not_reveal_account_existence`).
  4. **`POST /api/auth/forgot-password`** : réponse **202 strictement identique** dans tous les cas, `{"message": "Si un compte existe pour cet e-mail, un lien de réinitialisation sera envoyé."}` (test `test_forgot_password_is_indistinguishable`).

### F17 — Tokens de projet : génération, hachage, rotation

- **Statut** : Terminé
- **Fichier** : `backend/app/core/security.py:51-66`, `backend/app/api/projects.py:130-145`
- **Génération** : `TOKEN_PREFIX + secrets.token_urlsafe(32)` = `"iacg_"` + 43 caractères (256 bits d'entropie).
- **Stockage** : `hashlib.sha256(token).hexdigest()` dans `projects.token_hash`. **SHA-256 sans sel est délibéré et justifié** dans le code : le token est long et aléatoire (256 bits), donc non attaquable par dictionnaire — contrairement à un mot de passe humain qui, lui, exige Argon2id.
- **Aperçu UI** : `token_preview(token)` = `token[:9] + "…"` → `iacg_ab12…`. Le test `test_preview_shows_prefix_only` vérifie que la fin du token n'y figure pas.
- **Affichage unique** : le token en clair n'apparaît que dans `ProjectCreated` (à la création) et `ProjectTokenRotated` (à la rotation). Impossible à retrouver ensuite.
- **Rotation** : `POST /api/projects/{id}/rotate-token` régénère token + hash + prefix. L'ancien cesse de fonctionner immédiatement (test `test_rotate_token_invalidates_the_old_one`). L'UI affiche une confirmation avant, puis la modale « Affiché une seule fois » avec bouton de copie.

### F18 — Garde-fous de démarrage en production

- **Statut** : Terminé (commit `a2854f1`, le plus récent)
- **Fichier** : `backend/app/core/config.py:89-124`
- **Constantes** : `DEV_SECRET_KEY = "dev-secret-change-me"`, `MIN_SECRET_KEY_LENGTH = 32`
- **`is_production`** : `environment.strip().lower() in ("production", "prod")`
- **Validateur `_verifier_secrets`** (`@model_validator(mode="after")`) :
  ```python
  faible = (secret_key == DEV_SECRET_KEY) or (len(secret_key) < 32)
  if is_production:
      if faible:            raise ValueError(...)   # refus de démarrer
      if not cookie_secure: raise ValueError(...)   # refus de démarrer
  elif faible:
      logger.warning("Clé de signature de développement utilisée. Ne JAMAIS déployer ainsi…")
  ```
- **Justification documentée** : le dépôt étant public, la clé par défaut l'est aussi ; un JWT signé avec elle serait forgeable par n'importe qui — session valide sans mot de passe ni second facteur. *« Mieux vaut un démarrage qui échoue bruyamment qu'une authentification qui semble fonctionner tout en étant contournable. »*
- **Utilitaire fourni** : `generer_secret_key()` = `secrets.token_urlsafe(48)`.
- **Comportement observé** : au chargement de l'app en développement, le warning s'affiche bien dans les logs.

### F19 — Dashboard temps réel

- **Statut** : Terminé
- **Fichier** : `frontend/src/components/dashboard-live.tsx`
- **Chargement** :
  1. `listProjects()` → sélection du projet depuis `?project=<id>` ou, à défaut, le premier de la liste.
  2. `listScans(projectId)` → si aucun scan, état vide dédié.
  3. `Promise.all(scans.slice(0,7).map(s => getScan(s.id)))` — **détail (score) des 7 scans les plus récents, en parallèle**.
  4. `listFindings(scans[0].id)` → findings du dernier scan.
- **Rafraîchissement** : `setInterval(() => refresh(true), 30_000)`. Le mode `silent` ne remet pas l'écran en état de chargement et n'efface pas les données en cas d'erreur — une nouvelle livraison du pipeline apparaît donc toute seule.
- **Calculs de KPI (valeurs exactes)** :

  | KPI | Valeur | Delta |
  |---|---|---|
  | Compliance Score | `${latest.score.score} / 100` | `pctDelta(score, previous.score)` |
  | Findings ouverts | nombre de findings avec `status === "open"` | `pctDelta(total_findings, previous.total_findings)` |
  | Critical & High | findings `isActionable` ET (`critical` ou `high`) | `pctDelta` sur la somme critical+high |
  | Scans (7j) | scans dont `Date.now() - scanned_at < 7×24×3600×1000` | `0` |

  `isActionable(s) = s !== "resolved" && s !== "false_positive"`
  `pctDelta(cur, prev) = prev === null || prev === 0 ? 0 : Math.round(((cur-prev)/prev)*1000)/10` (une décimale)
- **Courbe d'activité** : `[...history].reverse()` (du plus ancien au plus récent), un point par scan avec `{date: scanned_at, critical, high, medium}`.
- **Triage optimiste** : après `triageFinding`, mise à jour locale de l'état sans re-fetch complet, plus toast `"Décision enregistrée."` ou `"Finding ré-ouvert."`

### F20 — Panneau de détail pédagogique d'un finding

- **Statut** : Terminé
- **Fichiers** : `frontend/src/components/finding-detail-sheet.tsx`, `frontend/src/lib/finding-explainer.ts`
- **Base de connaissances** (`BY_RULE`, 14 entrées) : chaque entrée fournit `{impact, exploit, fix}` en français.

  | Règles Checkov couvertes | Règles Gitleaks | Règles Semgrep |
  |---|---|---|
  | `CKV_AWS_20` (S3 public), `CKV_AWS_21` (versioning), `CKV_AWS_24` (SSH 0.0.0.0/0), `CKV_AWS_25` (RDP), `CKV_AWS_3` (EBS non chiffré), `CKV_AWS_16` (RDS non chiffré), `CKV_AWS_17` (RDS public), `CKV_AWS_63` / `CKV_AWS_1` / `CKV_AWS_62` (IAM wildcard), `CKV_AWS_67` (CloudTrail) | `aws-access-token`, `stripe-access-token`, `generic-api-key` | `python.lang.security.audit.dangerous-subprocess-use` |

- **Repli par catégorie** (`BY_CATEGORY`, 4 entrées) : `secret`, `misconfiguration`, `policy`, `vulnerability`. Puis `DEFAULT_EXPLANATION` en dernier recours.
- **Résolution** : `BY_RULE[rule_id] ?? BY_CATEGORY[category] ?? DEFAULT_EXPLANATION`.
- **Lien vers le code** (`codeUrl`) : `https://github.com/{repo}/blob/{commitSha}/{file}#L{start}[-L{end}]`. Le lien pointe **au commit scanné**, pas sur la branche par défaut — le fichier a pu bouger depuis et le lien tomberait à côté. `cleanPath()` retire le `/` initial que Checkov préfixe à ses chemins.
- **Localisation** (`locationLabel`) : `"main.tf:102"` ou `"main.tf:16-22"` si le finding couvre un bloc.
- **Libellés** : `SOURCE_LABELS` (4), `CATEGORY_LABELS` (4), `SEVERITY_LABELS` (5).

### F21 — Internationalisation FR / arabe avec RTL

- **Statut** : Partiel (limité aux écrans d'authentification, assumé)
- **Fichier** : `frontend/src/lib/i18n.tsx` (169 lignes)
- **Langues** : `fr` (défaut) et `ar`. **44 clés** traduites, couvrant : `tagline`, login (18 clés), signup (12 clés dont les 5 règles de mot de passe), mot de passe oublié (5 clés).
- **Persistance** : `localStorage["iacg-lang"]`, lue **après l'hydratation** (dans un `useEffect`) pour ne pas créer d'écart serveur/client.
- **RTL** : `dir = lang === "ar" ? "rtl" : "ltr"`, appliqué par `AuthShell` sur le conteneur. Les champs e-mail et les blocs de token portent `dir="ltr"` explicite.
- **Repli** : `translations[lang][key] ?? translations.fr[key]`.
- **Limitation documentée dans le code** : *« Le reste de l'app reste en français pour l'instant ; ce module est conçu pour s'étendre écran par écran. »*

### F22 — Gestion des projets (UI)

- **Statut** : Terminé
- **Fichier** : `frontend/src/components/projects-manager.tsx`
- Colonnes du tableau : Nom · Token (prefix) · Scans · Dernier score · Dernière activité · Créé le · Actions.
- **Chargement en deux temps** : `listProjects()` puis enrichissement par `Promise.all(list.map(p => getProject(p.id).catch(() => undefined)))` — un détail en échec n'empêche pas l'affichage.
- **Couleur du score** (`scoreBadgeClass`) : grade A ou B → vert (emerald) ; C ou D → orange (amber) ; F → rouge.
- **Indicateur de silence** (`LastActivity`) : `STALE_AFTER_DAYS = 14`. Au-delà, l'affichage passe en ambre avec une icône `AlertTriangle` et le texte `"Aucun scan depuis Nj"`. En deçà : `"aujourd'hui"` / `"il y a 1 jour"` / `"il y a N jours"`.
- Modales : création, révélation du token (« Affiché une seule fois » + copie presse-papiers), confirmation de rotation, confirmation de suppression (texte explicite sur l'irréversibilité).
- Recherche locale par nom (insensible à la casse) ; clic sur une ligne → `/?project={id}`.

### F23 — Script de migration RBAC

- **Statut** : Terminé (mais c'est un script ad hoc, pas Alembic)
- **Fichier** : `backend/scripts/migrate_rbac.py` (264 lignes)
- **Problème traité** : `Base.metadata.create_all` crée les tables manquantes mais **n'ajoute jamais de colonne à une table existante**. Une base créée avant le RBAC échoue donc sur `no such column: users.org_id`.
- **4 étapes, idempotentes** :
  1. `create_new_tables()` — `create_all` pour `organizations`, `invitations`, `project_access`, `admin_audit_logs`. **Exécutée en premier** car `users.org_id` référence `organizations`, que PostgreSQL exige d'exister avant d'accepter la clé étrangère.
  2. `add_missing_columns()` — `ALTER TABLE users ADD COLUMN` pour `org_id` (`INTEGER REFERENCES organizations(id)`), `role` (`VARCHAR(20)`), `last_login_at`, `created_by_id`. Le type temporel est adapté au dialecte : `DATETIME` sous SQLite, `TIMESTAMPTZ` sous PostgreSQL. `org_id` est volontairement déclaré **sans NOT NULL** : on ne peut pas remplir une colonne obligatoire sur des lignes existantes.
  3. `backfill_organizations()` — une organisation par compte existant (nom = partie locale de l'e-mail), rôle `admin`. Justification : *« c'est le seul choix sûr sans connaître qui travaille avec qui »*.
  4. `relax_password_not_null()` — rend `users.hashed_password` nullable. PostgreSQL : `ALTER COLUMN … DROP NOT NULL`. **SQLite ne sait pas le faire** : le script renomme la table en `users_old_rbac`, **supprime les index** (un index renommé suit sa table mais garde son nom, ce qui ferait échouer la recréation), recrée `users` **depuis la définition ORM** (source de vérité), recopie les colonnes communes aux deux versions, supprime l'ancienne table. `PRAGMA foreign_keys=OFF/ON` encadre l'échange.
  5. `verify()` — relit tous les utilisateurs via l'ORM et affiche `id / email / org / role / statut`.
- **Options** : `--dry-run` (aucune écriture ; le backfill est alors sauté car les colonnes n'existent pas encore).
- **Avertissement dans la docstring** : *« Faites une copie de votre base avant. »*

---

## 9. Pipelines CI/CD

### 9.1 `pipeline/github-actions-template/scan-standalone.yml` — workflow recommandé par le README

| Élément | Valeur |
|---|---|
| Nom | `iac-guard Scan` |
| Déclencheurs | `workflow_dispatch` ; `push` sur `**.tf`, `**.py`, `**.js`, `.github/workflows/scan.yml` ; `pull_request` (tous chemins) |
| Runner | `ubuntu-latest` |
| Variables d'env. | `GITLEAKS_VERSION: "8.21.2"`, `SEMGREP_VERSION: "1.78.0"` |
| Secret requis | `IAC_GUARD_TOKEN` |
| Variable requise | `IAC_GUARD_API_URL` |
| Scanners | **3** : Gitleaks, Checkov, Semgrep (**pas** Conftest) |
| Aggregator | Vendored dans `.iacguard/` du dépôt client |

**Étapes détaillées :**

1. **Checkout** — `actions/checkout@v4` avec `fetch-depth: 0` (historique complet → Gitleaks scanne aussi les commits passés).
2. **Python** — `actions/setup-python@v5`, `python-version: "3.12"`.
3. **Vérification de joignabilité de l'API** :
   ```bash
   API_URL="$(printf '%s' "$RAW_API_URL" | tr -d '[:space:]' | sed 's:/*$::')"
   [ -z "$API_URL" ] && { echo "::error::La variable IAC_GUARD_API_URL n'est pas définie."; exit 1; }
   echo "API_URL=$API_URL" >> "$GITHUB_ENV"
   curl -fsS --max-time 20 "$API_URL/health" || { echo "::error::API injoignable ($API_URL). Tunnel arrêté ou URL périmée ?"; exit 1; }
   ```
   Deux problèmes concrets traités et commentés : (a) un copier-coller depuis Windows colle un `\r\n` invisible que curl refuse avec un message opaque (« URL rejected: Malformed input ») ; (b) l'API tourne souvent derrière un tunnel éphémère — mieux vaut échouer ici, avec un message clair, qu'après 3 minutes de scan.
4. **Gitleaks** (`continue-on-error: true`) : téléchargement du binaire depuis les releases GitHub, puis
   `gitleaks detect --source . --report-format json --report-path gitleaks.json --redact --exit-code 0`.
   `--redact` masque la valeur du secret dans le rapport ; `--exit-code 0` force un code de sortie nul.
5. **Checkov** (`continue-on-error: true`) : `pip install checkov` puis `checkov -d . -o json --soft-fail > checkov.json`.
6. **Semgrep** (`continue-on-error: true`) : `pip install "semgrep==1.78.0"` puis `semgrep scan --config=auto --json --output semgrep.json || true`.
7. **Agrégation et envoi** — **sans `continue-on-error`**, délibérément :
   > *« si l'envoi échoue, le job DOIT échouer — un pipeline vert alors que le scan s'est perdu en route est pire que pas de scan du tout. »*
   ```bash
   pip install "pydantic>=2.10,<3" "requests>=2.31,<3"
   python .iacguard/aggregator.py --gitleaks gitleaks.json --checkov checkov.json --semgrep semgrep.json \
     --repo "${GITHUB_REPOSITORY}" --branch "${GITHUB_REF_NAME}" --commit "${GITHUB_SHA}" \
     --api-url "$API_URL" --token "${{ secrets.IAC_GUARD_TOKEN }}"
   ```
8. **Artefacts** (`if: always()`) — `actions/upload-artifact@v4`, nom `rapports-scanners`, contenu `gitleaks.json` / `checkov.json` / `semgrep.json`, `if-no-files-found: ignore`.

**Justification du `continue-on-error` sur les scanners** (commentée dans le YAML) : un scanner qui **trouve** des problèmes sort en code non-nul ; ce n'est pas un échec du job. On veut collecter les trois rapports plutôt que s'arrêter au premier.

### 9.2 `pipeline/github-actions-template/scan.yml` — variante à 4 scanners

| Différence | Détail |
|---|---|
| Déclencheurs | `push` (tous chemins) et `pull_request` |
| Variables d'env. | + `CONFTEST_VERSION: "0.56.0"`, + `IACGUARD_RAW: "https://raw.githubusercontent.com/ORG/iac-guard/main"` |
| Secret / variable | `IACGUARD_TOKEN` / `IACGUARD_API_URL` (**noms différents** de la variante standalone) |
| Scanners | **4**, avec Conftest : `conftest test . --parser hcl2 --policy iacguard-policies --all-namespaces -o json > conftest.json \|\| true` |
| Aggregator | **Téléchargé par curl** depuis `${IACGUARD_RAW}/pipeline/aggregator/{schema.py,aggregator.py,requirements.txt}` |
| Policies | `curl -sSL "${IACGUARD_RAW}/policies/bundle.tar.gz" \| tar -xz -C iacguard-policies \|\| true` |
| Pas de | Vérification `/health`, upload d'artefacts |

**Deux problèmes factuels dans ce fichier :**
- `IACGUARD_RAW` contient le placeholder `ORG/iac-guard` non substitué (le vrai dépôt est `chafiq753/iac-guard`).
- `policies/bundle.tar.gz` **n'existe pas** : le dossier `policies/` est vide. Le `|| true` fait que l'échec est silencieux, Conftest tourne alors sans aucune policy et produit un rapport vide.

### 9.3 Conséquence : le support Conftest est en pratique inactif

| Couche | État |
|---|---|
| Schéma unifié (`Category.POLICY`, `ToolName.CONFTEST`) | Présent |
| Parser `parse_conftest()` | Présent et complet (gère `failures`/`warnings`, metadata Rego) |
| Échantillon de test `samples/conftest.json` | Présent |
| Libellés UI (`SOURCE_LABELS["conftest"]`, `CATEGORY_LABELS["policy"]`) | Présents |
| **Règles Rego (`policies/`)** | **DOSSIER VIDE — aucune règle écrite** |
| Workflow recommandé (`scan-standalone.yml`) | **N'exécute pas Conftest** |

**Conclusion factuelle** : la catégorie `policy` est entièrement câblée de bout en bout, mais aucune règle métier n'existe. Aucun finding `policy` ne peut donc être produit en conditions réelles. Les findings `cndp.data_residency` et `bam.audit_logging` visibles dans `docs/sample-scan.json` et `frontend/src/lib/data.ts` sont des données d'exemple.

### 9.4 Procédure de connexion d'un dépôt client (README)

1. Créer un projet depuis le dashboard, copier le token affiché.
2. Copier `pipeline/github-actions-template/scan-standalone.yml` dans `.github/workflows/` du dépôt à analyser, et le contenu de `pipeline/aggregator/` dans un dossier `.iacguard/`.
3. Dans *Settings > Secrets and variables > Actions* : secret `IAC_GUARD_TOKEN` = le token ; variable `IAC_GUARD_API_URL` = l'URL publique de l'API.
4. Activer la protection de la branche principale en exigeant le check `scan` — c'est cette étape qui transforme le verdict en barrière effective.

---

## 10. Sécurité — synthèse des mesures implémentées

| # | Mesure | Implémentation exacte | Fichier |
|---|---|---|---|
| 1 | Hachage des mots de passe | Argon2id (m=64 MiB, t=3, p=4), sel embarqué | `core/security.py:35` |
| 2 | Migration transparente des anciens hash | Détection `$2*`, vérification bcrypt, re-hachage Argon2id au login | `core/security.py:97-134` |
| 3 | Refus de la troncature bcrypt | `len(raw) > 72` → `False` | `core/security.py:111-112` |
| 4 | Borne anti-DoS sur le mot de passe | `MAX_PASSWORD_BYTES = 1024` | `core/security.py:41` |
| 5 | Politique de complexité serveur | 12 caractères min. + 4 classes obligatoires | `schemas/user.py:13-31` |
| 6 | Session en cookie httpOnly | `httponly=True`, invisible au JS → XSS ne vole pas la session | `api/cookies.py:20-28` |
| 7 | Protection CSRF | `samesite="lax"` | `core/config.py:57` |
| 8 | HTTPS imposé en production | `COOKIE_SECURE` obligatoire si `ENVIRONMENT=production` | `core/config.py:112-116` |
| 9 | JWT à portée | `scope ∈ {session, mfa}` vérifié au décodage | `core/security.py:187-188` |
| 10 | Rôle jamais dans le JWT | Rechargement en base à chaque requête | `api/deps.py:43-55, 103-120` |
| 11 | CORS restrictif | Liste explicite, jamais `"*"` (incompatible avec `allow_credentials=True`) | `main.py:46-52` |
| 12 | Anti-brute-force | 5 tentatives → verrou de 15 min | `api/auth.py:63-71` |
| 13 | Anti-énumération (4 mesures) | Message unique, hachage factice, `/methods` neutre, `/forgot-password` 202 constant | `api/auth.py` |
| 14 | 404 au lieu de 403 hors périmètre | `_PROJECT_NOT_FOUND`, `_SCAN_NOT_FOUND` | `api/deps.py:133-134` |
| 15 | Tokens de projet non réversibles | SHA-256, affichage unique, rotation disponible | `core/security.py:54-66` |
| 16 | Jetons d'invitation non réversibles | SHA-256, jamais dans la réponse HTTP, TTL 72 h, usage unique | `api/admin.py`, `models/invitation.py` |
| 17 | Codes de récupération hachés | SHA-256 + comparaison à temps constant (`hmac.compare_digest`) | `core/security.py:211-222` |
| 18 | WebAuthn : clé publique seule | La clé privée reste dans le TPM / Secure Enclave | `models/credential.py:1-8` |
| 19 | WebAuthn : `user_verification=REQUIRED` | Empreinte / visage / PIN obligatoire | `services/mfa.py:118` |
| 20 | WebAuthn : challenge à usage unique | Stocké en base, supprimé à la consommation, TTL 300 s | `services/mfa.py:55-94` |
| 21 | WebAuthn : détection de clé clonée | Refus si `new_sign_count != 0 and <= stored.sign_count` | `services/mfa.py:216-217` |
| 22 | TOTP activé après preuve | `totp_enabled` ne passe à `True` qu'après un code valide | `api/twofa.py:197-216` |
| 23 | Changement de mot de passe protégé | Exige le mot de passe actuel | `api/auth.py:282-299` |
| 24 | Refus de démarrage en production non sûre | `SECRET_KEY` faible ou `COOKIE_SECURE` off → `ValueError` | `core/config.py:89-124` |
| 25 | Rate limiting des invitations | 10/heure/admin, compté sur `admin_audit_logs` | `api/admin.py:136-150` |
| 26 | Protection contre le lockout d'organisation | Dernier admin non rétrogradable / non désactivable | `api/admin.py:77-80` |
| 27 | Journaux d'audit inaltérables | Aucune route DELETE/UPDATE ; écriture dans la transaction métier | `services/admin_audit.py` |
| 28 | Secrets exclus du versionnement | `.gitignore` : `*.db`, `*.bak*`, `*.sql`, `.env`, `.env.local`, rapports de scan | `.gitignore` |

### 10.1 Points de sécurité à mentionner comme limites

| Point | Constat factuel |
|---|---|
| `webauthn_rp_id` codé à `"localhost"` | Valeur par défaut de la configuration. En déploiement réel il doit valoir le domaine du frontend, sinon les passkeys ne fonctionneront pas. Configurable, mais non documenté dans `.env.example`. |
| Mots de passe de la base Postgres en dur | `iacguard/iacguard` dans `docker-compose.yml` (fichier explicitement libellé « stack de DÉVELOPPEMENT »). |
| Lien d'invitation dans les logs | Le stub e-mail journalise le lien d'activation en clair, avec un avertissement explicite que cela ne doit pas passer en production. |
| Absence de rate limiting global | Seul `POST /api/admin/users/invite` est limité. Le login est protégé par verrouillage de compte, mais pas par limitation par IP. |
| Pas de rotation / révocation de JWT | Un JWT de session reste valide 24 h. La révocation effective passe par la désactivation du compte (vérifiée à chaque requête). |
| `POST /api/auth/register` ouvert | N'importe qui peut créer un compte et devenir admin d'une nouvelle organisation. C'est le modèle SaaS assumé (auto-inscription), pas une faille. |

---

## 11. Tests

### 11.1 Résultat d'exécution

**151 tests, 100 % passants** (`cd backend && python -m pytest -q` → `151 passed`).

### 11.2 Infrastructure de test — `backend/tests/conftest.py`

- **Base SQLite en mémoire** : `create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)`. `StaticPool` maintient une connexion unique partagée, sans quoi chaque connexion aurait sa propre base vide.
- **`TestClient` non utilisé comme context manager** — choix explicite : cela déclencherait le `lifespan` de l'app, qui créerait les tables sur le **vrai** engine. Les tables de test sont créées à la main.
- **Surcharge de dépendance** : `app.dependency_overrides[get_db] = _override_get_db`, nettoyée en `finally`.
- **Schéma frais par test** : `create_all` en entrée de fixture, `drop_all` en sortie.
- **Compte de test** : `dev@iac-guard.io` / `S3cret-Password!` (conforme à la politique : 16 caractères, minuscule, majuscule, chiffre, spécial).
- **`register_and_login()`** : s'inscrit, se connecte, récupère la valeur du cookie de session pour la renvoyer en en-tête `Bearer`, puis **vide les cookies du client**. Justification commentée : sans cela le client resterait authentifié tout seul, et les tests vérifiant l'absence d'authentification passeraient pour de mauvaises raisons.
- **Fixtures** : `db_session`, `client`, `auth_headers`, `project_token` (renvoie `(project_id, token_projet)`).
- **`sample_report()`** : rapport minimal valide — 1 critical (Gitleaks `aws-access-token`), 1 high (Checkov `CKV_AWS_20`), 1 medium (Checkov `CKV_AWS_16`). Score attendu : `100 - (25+10+3) = 62`, grade C.

### 11.3 Répartition

| Fichier | Tests | Couverture |
|---|---|---|
| `test_auth.py` | **44** | Argon2id, salage, bcrypt legacy, troncature, JWT (roundtrip, mauvaise signature, expiré, malformé, portée), inscription (doublon, payloads invalides paramétrés), cookie httpOnly, logout, verrouillage, `/methods`, WebAuthn login, `/forgot-password` |
| `test_api.py` | **25** | `/health`, création/lecture/suppression de projet, doublon de nom, nom vide, homonymie inter-utilisateurs, rotation de token, ingestion (token invalide, JWT refusé, persistance, cloisonnement), `/api/alerts` (multi-projets, dernier scan, filtre projet, statut de triage, recherche, pagination, isolation), score, filtres de findings, tri des scans, isolation |
| `test_admin.py` | **18** | Authentification requise, rôles non-admin refusés, invitation (compte en attente, acceptation, expiration, usage unique, ré-invitation), rôle audité, dernier admin (rétrogradation/désactivation), auto-désactivation, compte désactivé, accès projets (aucun/octroi/révocation), `security_lead` global, isolation inter-organisations, reset WebAuthn audité |
| `test_2fa.py` | **17** | Aucune 2FA par défaut, setup TOTP, code invalide, confirmation + codes de récupération, login à deux facteurs, mauvais code, cookie MFA requis, jeton session ≠ jeton MFA, désactivation, code de récupération (usage unique, inconnu), options WebAuthn bien formées, rejet de données invalides, appareil requis, authentification requise |
| `test_scoring.py` | **12** | Score parfait, pénalité conforme aux poids, plancher à 0, `info` neutre, sévérités inconnues, **6 bornes de grade paramétrées**, coercition de types |
| `test_scan_policy.py` | **9** | Aucune politique, seuil critical, seuil non atteint, sévérité invalide, règle ignorée (seuil + score), doublon, suppression, isolation |
| `test_triage.py` | **7** | Statut `open` par défaut, décision + note, **survie au re-scan**, ré-ouverture, statut invalide, filtre, isolation |
| `test_audit_log.py` | **6** | Création d'entrée, append-only, no-op non journalisé, **survie à la suppression du projet**, isolation, filtre projet |
| `test_profile.py` | **6** | Changement de nom, d'e-mail, conflit d'e-mail, mot de passe actuel exigé, reconnexion après changement, refus d'un nouveau mot de passe faible |
| `test_security.py` | **4** | Préfixe et unicité du token, hachage déterministe, collisions, aperçu qui ne divulgue pas la fin |
| `test_aggregates.py` | **3** | Groupement par sévérité, scan vide, isolation par scan |

### 11.4 Ce qui n'est pas testé

- **Aucun test frontend** : ni unitaire (Jest/Vitest), ni composant (Testing Library), ni bout en bout (Playwright/Cypress). Aucune dépendance de test dans `package.json`.
- **Aucun test de l'aggregator** : les 4 parsers (`parse_gitleaks`, `parse_checkov`, `parse_conftest`, `parse_semgrep`) ne sont couverts par aucun test automatisé, malgré la présence des échantillons dans `pipeline/aggregator/samples/`.
- **Aucun test du script de migration** `migrate_rbac.py`.
- **Aucune CI n'exécute les tests** : les seuls workflows du dépôt sont les *modèles* destinés aux dépôts clients ; le dépôt `iac-guard` lui-même n'a pas de `.github/workflows/`.
- **WebAuthn** : seuls les cas d'échec et le bien-formé des options sont testés (une signature valide exige un authentificateur matériel).

---

## 12. Configuration — référence complète

### 12.1 Backend — classe `Settings` (`backend/app/core/config.py`)

| Attribut | Variable d'env. | Valeur par défaut | Rôle |
|---|---|---|---|
| `app_name` | `APP_NAME` | `"iac-guard"` | Titre OpenAPI, réponse `/health` |
| `environment` | `ENVIRONMENT` | `"development"` | Pilote les garde-fous de production |
| `database_url` | `DATABASE_URL` | `"sqlite:///./iacguard.db"` | URL SQLAlchemy |
| `secret_key` | `SECRET_KEY` | `"dev-secret-change-me"` | Signature HS256 des JWT |
| `access_token_expire_minutes` | `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` (= 60×24) | Durée de la session |
| `cors_origins` | `CORS_ORIGINS` | `["http://localhost:5173", "http://localhost:3000"]` | Origines autorisées |
| `session_cookie_name` | — | `"iacguard_session"` | |
| `mfa_cookie_name` | — | `"iacguard_mfa"` | |
| `cookie_secure` | `COOKIE_SECURE` | `False` | Impose HTTPS |
| `cookie_samesite` | — | `"lax"` | Anti-CSRF |
| `mfa_token_expire_minutes` | — | `5` | Durée du jeton intermédiaire 2FA |
| `max_login_attempts` | — | `5` | Seuil de verrouillage |
| `lockout_minutes` | — | `15` | Durée du verrouillage |
| `webauthn_rp_id` | — | `"localhost"` | Domaine propriétaire des passkeys |
| `webauthn_rp_name` | — | `"iac-guard"` | Nom affiché (aussi `issuer_name` du TOTP) |
| `webauthn_origins` | — | `["http://localhost:3000"]` | Origines acceptées pour une assertion |
| `frontend_url` | — | `"http://localhost:3000"` | Base du lien d'invitation |
| `invitation_expire_hours` | — | `72` | TTL d'une invitation |
| `max_invites_per_hour` | — | `10` | Anti-spam d'invitations |

`model_config = SettingsConfigDict(env_file=".env", extra="ignore")` — les variables inconnues sont ignorées.

### 12.2 Frontend

| Variable | Fichier | Valeur | Rôle |
|---|---|---|---|
| `NEXT_PUBLIC_API_URL` | `frontend/.env.local` | `http://localhost:8000` | Base des appels API (slash final retiré au chargement) |

### 12.3 Configuration réseau

| Composant | Adresse | Port |
|---|---|---|
| PostgreSQL (Docker) | `db` sur le réseau Compose ; `localhost` depuis l'hôte | `5432` |
| API FastAPI (Docker) | `0.0.0.0` dans le conteneur ; `localhost` depuis l'hôte | `8000` |
| Documentation interactive | `http://localhost:8000/docs` (Swagger UI, générée par FastAPI) | `8000` |
| Endpoint de santé | `http://localhost:8000/health` | `8000` |
| Dashboard Next.js | `localhost` (hors Docker, `npm run dev`) | `3000` |
| Origine CORS supplémentaire autorisée | `http://localhost:5173` (port Vite — reliquat d'une maquette antérieure) | `5173` |

En démonstration, l'API est exposée à GitHub Actions par un **tunnel éphémère** (l'URL change à chaque relance) — c'est ce que documente `docs/script-video-demo.md` et ce que justifie le contrôle `/health` du workflow standalone.

---

## 13. Documentation du dépôt (`docs/`)

| Fichier | Contenu factuel |
|---|---|
| `demo-vulnerable-main.tf` | Terraform volontairement vulnérable, **12 failles numérotées en commentaire** : (1) clé AWS en dur (clé d'exemple inerte `AKIAIOSFODNN7EXAMPLE`), (2) bucket S3 `public-read` → `CKV_AWS_20`, (3) bucket sans versioning → `CKV_AWS_21`, (4) SSH 22 ouvert à `0.0.0.0/0` → `CKV_AWS_24`, (5) RDP 3389 ouvert → `CKV_AWS_25`, (6) EBS non chiffré → `CKV_AWS_3`, (7) RDS non chiffré + mot de passe en dur → `CKV_AWS_16`, (8) RDS publiquement accessible → `CKV_AWS_17`, (9) policy IAM `Action:"*"` → `CKV_AWS_1`/`CKV_AWS_62`, (10) CloudTrail avec `enable_logging = false` → `CKV_AWS_67`, (11) EC2 avec IP publique et sans monitoring, (12) user-data. Une section « 12-bis » **corrigée** montre le bon pattern : token stocké dans AWS Secrets Manager, rôle IAM à privilège minimal (`secretsmanager:GetSecretValue`, `DescribeSecret` sur l'ARN précis), variable Terraform `sensitive = true`. |
| `sample-scan.json` | Rapport au format unifié : 6 findings (1 gitleaks/critical, 2 checkov/high, 1 conftest/medium `cndp.data_residency`, 1 checkov/low, 1 semgrep/high), 3 outils déclarés avec versions. Score attendu : `100 - (25 + 10 + 10 + 3 + 1 + 10) = 41` → grade D. |
| `script-video-demo.md` | Script minuté d'une démo de 5 min sur le dépôt cible `github.com/chafiq753/atlas-pay` (projet iac-guard id 10, seuil `high`). Chiffres cités : **87 problèmes détectés** (6 secrets, 9 failles de code, 72 erreurs de configuration), score 0/100. Décrit la PR #1 bloquée avec `enforce_admins` actif. Inclut un tableau de rattrapage en cas de panne en direct. |
| `speech-presentation.md` | Texte de présentation orale (~1 min 30) + phrases de transition + **4 questions/réponses anticipées** : pourquoi trois outils, différenciation vs scanners bruts, risque de sur-blocage, état d'avancement. Contient le tableau récapitulatif des domaines fonctionnels. |

---

## 14. Ce qui est prévu mais non réalisé

### 14.1 Travaux en cours listés dans le README (§ « État du projet »)

| Chantier | État réel dans le code | Preuve |
|---|---|---|
| **Moteur de conformité CNDP (loi 09-08) / Bank Al-Maghrib** | **Absent.** Le fichier placeholder `backend/app/services/compliance_engine.py` a été créé vide puis **supprimé** au commit `ad45932`. Le mapping réglementaire est explicitement exclu du schéma pipeline (`schema.py:9-12` : *« Le mapping réglementaire n'apparaît PAS ici : le pipeline n'envoie que des faits techniques, l'enrichissement se fait côté backend à partir du champ `rule_id` »*) — mais cet enrichissement n'existe nulle part. La carte « Compliance » du dashboard affiche 4 référentiels **factices**. | `git show --raw ad45932`, `frontend/src/lib/data.ts:complianceFrameworks`, `compliance-card.tsx:12` |
| **Export PDF des rapports pour audit externe** | **Absent.** Placeholder `backend/app/services/pdf_export.py` créé vide puis supprimé. Aucune dépendance PDF dans `requirements.txt`. Aucune route d'export. | `git show --raw ad45932`, `requirements.txt` |
| **Révision du calcul de score (saturation)** | **Non fait.** Les poids sont inchangés : 4 findings critiques (4 × 25) suffisent à atteindre 0. | `services/scoring.py:17-23` |
| **Envoi des e-mails d'invitation** | **Stub.** `send_invitation_email` journalise le lien au niveau WARNING au lieu de l'envoyer. Aucun fournisseur (Resend, SendGrid, SMTP) configuré. La docstring l'assume : *« À remplacer par un vrai envoi avant la mise en prod — le call site ne changera pas, seule son implémentation le sera. »* | `services/email.py` |
| **Migrations Alembic (en remplacement de `create_all`)** | **Non fait.** `Base.metadata.create_all` reste dans le `lifespan`, avec le commentaire *« MVP : … On passera à Alembic quand le schéma se stabilisera. »* Le script ad hoc `migrate_rbac.py` comble le manque pour une transition précise. `alembic` n'est pas dans `requirements.txt`. | `main.py:34-36`, `scripts/migrate_rbac.py` |

### 14.2 Autres fonctionnalités incomplètes identifiées dans le code

| Élément | Statut | Preuve |
|---|---|---|
| **Réinitialisation de mot de passe** | **Partiel.** `POST /api/auth/forgot-password` accuse réception (202) mais n'envoie rien et **aucune route de réinitialisation par jeton n'existe**. La docstring : *« l'envoi d'e-mail n'est pas encore branché (pas de SMTP configuré) — cette route accuse réception et sera complétée. »* La page `/forgot-password` existe et est fonctionnelle côté UI. | `api/auth.py:231-243` |
| **Connexion OAuth GitHub** | **Absent.** Marqué `// futur` dans le code. Le bouton n'apparaît que si `methods` contient `"github"` — or le backend ne renvoie jamais cette valeur (commentaire : *« (futur) "github" quand le compte aura été lié à un compte GitHub (OAuth) »*). Le bouton est de toute façon rendu avec l'attribut `disabled`. | `api/auth.py:184`, `login/page.tsx:47, 266-272` |
| **Page « Compliance »** | **Absente.** L'entrée de sidebar existe mais son `href` est `"/"`. Le commentaire l'assume : *« les items pointant encore vers "/" (pages à venir) ne s'activent que sur l'accueil. »* | `app-sidebar.tsx:37, 51-54` |
| **Bouton « Help & Support »** | **Non fonctionnel.** Rendu sans `onClick` ni `href`. | `app-sidebar.tsx:99-103` |
| **Règles Rego / Conftest** | **Absentes.** Dossier `policies/` vide, `policies/bundle.tar.gz` référencé par `scan.yml` inexistant. Voir §9.3. | `ls policies/` |
| **i18n au-delà de l'authentification** | **Partiel, assumé.** 44 clés seulement, couvrant login / signup / mot de passe oublié. Le dashboard, les alertes et l'administration restent en français uniquement. | `lib/i18n.tsx:3-10` |
| **Données factices résiduelles** | `frontend/src/lib/data.ts` conserve 11 alertes, 4 KPI, une série d'activité et un score codés en dur. Seuls les **types** sont importés par l'UI de production — sauf `complianceFrameworks`, réellement rendu par `ComplianceCard`. | `data.ts`, `compliance-card.tsx:10` |
| **Incohérence de nommage des secrets CI** | `scan.yml` attend `IACGUARD_TOKEN`/`IACGUARD_API_URL` ; `scan-standalone.yml` (recommandé par le README) attend `IAC_GUARD_TOKEN`/`IAC_GUARD_API_URL`. | Les deux fichiers |
| **Placeholder `ORG/iac-guard`** | `scan.yml` contient `IACGUARD_RAW: "https://raw.githubusercontent.com/ORG/iac-guard/main"` — le nom d'organisation n'a jamais été substitué. | `scan.yml:30` |
| **Fichiers `.next/`, `tsconfig.tsbuildinfo`, `.pytest_cache/`** | Artefacts de build présents sur disque ; `.next/` et `.pytest_cache/` sont couverts par `.gitignore`, `tsconfig.tsbuildinfo` ne l'est pas. | `.gitignore` |
| **Sauvegardes de base sur disque** | `backend/iacguard.db.bak-20260820-182542` et `backend/pg-iacguard.bak-20260820-183647.sql` existent localement. Elles sont exclues du versionnement par `.gitignore` avec le commentaire *« contiennent des hachages de mots de passe et de jetons »*. | `.gitignore:5-7` |

### 14.3 Limites techniques connues

| Limite | Conséquence |
|---|---|
| Pagination et filtrage en mémoire | `/api/alerts`, `/api/audit-log`, `/api/admin/users`, `/api/admin/audit-logs` chargent l'intégralité des lignes avant de découper. Ne passe pas à l'échelle. |
| Requêtes N+1 sur `/api/alerts` | Une requête « dernier scan » plus une requête findings plus une requête triage **par projet**. |
| `Base.metadata.create_all` en production | Aucune gestion de l'évolution du schéma : ajouter une colonne à une table existante exige un script manuel. |
| Score non stocké | Recalculé à chaque lecture — souple pour ajuster les poids, coûteux à grande échelle. |
| Pas de tâches asynchrones | L'ingestion, le calcul de score et l'évaluation de politique sont synchrones dans la requête HTTP. |
| `POST /api/auth/register` non restreint | Crée systématiquement une nouvelle organisation dont l'inscrit devient admin. |
| Frontend non conteneurisé | `docker compose up` ne démarre que l'API et la base ; le dashboard exige `npm run dev` séparément. |

---

## 15. Résumé exécutif

1. **iac-guard** est une plateforme complète de sécurité *Infrastructure as Code* : elle exécute automatiquement plusieurs analyseurs à chaque modification d'un dépôt client, normalise leurs résultats, les historise, les présente dans un tableau de bord et **refuse la fusion** vers la branche principale quand un problème dépasse le seuil de gravité configuré.
2. **Le pipeline GitHub Actions** lance Gitleaks (secrets, historique Git complet), Checkov (mauvaises configurations Terraform) et Semgrep (SAST applicatif) en tolérant leurs codes d'erreur, puis échoue délibérément si l'envoi du rapport échoue.
3. **L'aggregator Python** convertit quatre formats JSON incompatibles en un schéma Pydantic unifié et calcule pour chaque problème une empreinte SHA-1 déterministe `sha1(source|rule_id|file|line_start|resource)` qui permet de le suivre d'un scan à l'autre.
4. **L'API FastAPI** expose 48 routes et persiste 14 tables sur PostgreSQL 16 (SQLite en développement), avec trois circuits d'authentification distincts : token de projet pour le pipeline, JWT de session pour l'humain, JWT de portée `mfa` pour l'étape 2FA.
5. **Le score de conformité** part de 100 et retire 25 points par finding critique, 10 par élevé, 3 par moyen, 1 par faible, 0 par informatif, avec un barème de grades A≥90 / B≥75 / C≥60 / D≥40 / F.
6. **La politique de blocage** (`fail_on_severity`, configurable par projet parmi critical/high/medium/low/info ou nul) fait retourner le code 1 à l'aggregator, ce qui échoue le check `scan` et grise le bouton « Merge » via la protection de branche GitHub.
7. **Les exceptions de règles** permettent d'accepter une règle entière comme risque connu, avec justification : ses findings restent visibles mais ne comptent plus ni dans le score ni dans le seuil de blocage.
8. **Le triage des alertes** (open / acknowledged / resolved / false_positive) est attaché à l'empreinte du problème, pas à une ligne de scan : une décision survit à la redétection lors du scan suivant.
9. **L'authentification** repose sur Argon2id (paramètres OWASP), avec migration transparente des anciens hash bcrypt au premier login réussi, une politique de 12 caractères minimum et 4 classes de caractères imposée côté serveur.
10. **La double authentification** propose au choix des passkeys WebAuthn (vérification utilisateur obligatoire, challenge à usage unique de 5 minutes, détection de clé clonée par compteur de signature) et/ou un code TOTP à 6 chiffres avec fenêtre de tolérance ±30 s, plus 8 codes de récupération à usage unique.
11. **Le RBAC à cinq rôles** (admin, security_lead, developer, auditor, viewer) combine un contrôle de rôle relu en base à chaque requête et un cloisonnement des projets par organisation, propriété ou octroi explicite — avec réponse 404 (jamais 403) hors périmètre pour ne pas révéler l'existence d'une ressource.
12. **La gestion des comptes** couvre l'invitation par jeton haché expirant en 72 h (limitée à 10/heure/admin), l'activation, la désactivation, l'attribution de projets et la réinitialisation forcée des passkeys, avec protection contre le verrouillage total de l'organisation (le dernier admin actif ne peut être ni rétrogradé ni désactivé).
13. **Deux journaux d'audit append-only et volontairement dénormalisés** tracent séparément les décisions de traitement des alertes et les actions d'administration de comptes ; ils survivent à la suppression de ce qu'ils documentent.
14. **Le tableau de bord Next.js 16 / React 19** affiche des KPI calculés en direct, une courbe d'activité sur les 7 derniers scans, une table d'alertes triable et filtrable, un panneau de détail pédagogique (impact, scénario d'attaque, remédiation, lien vers la ligne exacte au commit scanné) et se rafraîchit silencieusement toutes les 30 secondes.
15. **La qualité est mesurée par 151 tests backend tous passants** (auth, RBAC, 2FA, triage, audit, scoring, politique de scan) ; en revanche il n'existe aucun test frontend, aucun test de l'aggregator, et aucune CI n'exécute les tests du dépôt lui-même.
16. **Restent inachevés** : le moteur de conformité CNDP / Bank Al-Maghrib (les référentiels affichés sont factices), l'export PDF, l'envoi réel des e-mails d'invitation (aujourd'hui journalisés), la réinitialisation de mot de passe, les règles Rego Conftest (dossier `policies/` vide), les migrations Alembic, et la révision d'un score qui sature dès quatre findings critiques.
