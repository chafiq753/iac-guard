# Synthèse de l'analyse du dépôt `iac-guard`

> Compte rendu de la campagne d'analyse ayant produit [`PROJECT_ANALYSIS.md`](PROJECT_ANALYSIS.md).
> Ce fichier résume **comment** l'analyse a été menée, **ce qu'elle couvre**, et **les écarts**
> constatés entre la documentation du projet et son code réel.
> Document produit le 30 août 2026, sur la branche `main` au commit `a2854f1`.

---

## 1. Méthode suivie

L'analyse n'a reposé sur aucune supposition : chaque affirmation du rapport a été vérifiée par
lecture du code ou par exécution.

| Étape | Action concrète | Résultat |
|---|---|---|
| 1 | Lecture intégrale des 4 zones du dépôt : `backend/`, `frontend/`, `pipeline/`, `docs/` | ≈ 17 600 lignes de code source parcourues |
| 2 | Exécution de la suite de tests backend (`python -m pytest -q`) | **151 tests, 151 passants** |
| 3 | Extraction du schéma OpenAPI réel par appel de `app.openapi()` | Inventaire exact de **49 routes** (48 sous `/api` + `/health`) |
| 4 | Inspection directe de la base SQLite de développement (`backend/iacguard.db`) | **14 tables** confirmées, volumétrie relevée |
| 5 | `git log --stat` et `git show --raw` sur les 4 commits | Chronologie du développement + détection de fichiers créés puis supprimés |
| 6 | Vérification croisée README ↔ code | Identification des écarts listés en §4 |

---

## 2. Périmètre couvert par le rapport

`PROJECT_ANALYSIS.md` compte 15 sections et environ 1 480 lignes :

| Section | Contenu |
|---|---|
| 1–2 | Identification du projet, historique des commits, volumétrie, arborescence complète |
| 3 | Stack technique avec **versions exactes** issues de `requirements.txt` et `package.json` |
| 4 | Architecture globale en schéma ASCII : Push → GitHub Actions → Aggregator → API → Dashboard / Verdict, plus les 3 circuits d'authentification |
| 5 | Modèle de données : les 14 tables, toutes leurs colonnes, types, contraintes nommées et justifications de conception, plus le diagramme relationnel |
| 6 | Inventaire des 49 endpoints en tableaux : méthode, route, authentification, payload, réponse, codes HTTP |
| 7 | Frontend : 10 pages, 23 composants métier, 23 composants UI, 7 modules `lib/`, et distinction usage réel / données factices |
| 8 | **23 fonctionnalités (F1 à F23)** avec pour chacune : algorithme exact, fichiers sources, statut (terminé / partiel / stub / absent) |
| 9 | Les 2 workflows CI/CD étape par étape, et l'analyse du support Conftest |
| 10 | **28 mesures de sécurité** recensées avec leur implémentation exacte, plus 6 limites factuelles |
| 11 | Les 151 tests répartis par fichier, et l'inventaire de ce qui n'est **pas** testé |
| 12 | Référence complète de configuration : 20 attributs `Settings`, variables d'environnement, ports et adresses réseau |
| 13 | Contenu factuel des 4 fichiers de `docs/` |
| 14 | Ce qui est prévu mais non réalisé, avec preuve pour chaque point |
| 15 | Résumé exécutif en 16 points |

---

## 3. Valeurs exactes extraites (échantillon)

Le rapport privilégie systématiquement la valeur précise à l'approximation :

- **Poids de scoring** : `critical` 25, `high` 10, `medium` 3, `low` 1, `info` 0 — barème de grades A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, sinon F.
- **Formule d'empreinte** : `sha1("source|rule_id|file|line_start|resource")`.
- **Table `_SEVERITY_MAP`** de l'aggregator, ses 10 entrées, dont `"error" → HIGH` et `"warning" → MEDIUM` (spécifiques à Semgrep).
- **Argon2id** aux paramètres par défaut d'`argon2-cffi`, alignés OWASP : m = 64 MiB, t = 3, p = 4.
- **Anti-brute-force** : 5 tentatives, verrou de 15 minutes.
- **Durées** : session 1440 min (24 h), jeton MFA 5 min, challenge WebAuthn 300 s, invitation 72 h.
- **Rate limiting** : 10 invitations par heure et par administrateur.
- **8 codes de récupération** au format `token_hex(2)-token_hex(2)`.
- **TOTP** : `valid_window=1`, soit une tolérance de ± 30 s.
- **Rafraîchissement du dashboard** : 30 000 ms, en mode silencieux.

---

## 4. Écarts relevés entre la documentation et le code

Ces points sont documentés avec leur preuve dans la section 14 du rapport.

| # | Écart | Preuve |
|---|---|---|
| 1 | **`policies/` est vide.** Conftest est câblé de bout en bout (parser complet, enum `Category.POLICY`, échantillon JSON, libellés UI), mais aucune règle Rego n'existe et le workflow recommandé (`scan-standalone.yml`) ne l'exécute pas. Aucun finding de catégorie `policy` ne peut donc être produit en conditions réelles. | `ls policies/` → vide ; `scan-standalone.yml` n'a que 3 scanners |
| 2 | **`compliance_engine.py` et `pdf_export.py` n'existent pas.** Ils avaient été créés comme fichiers vides, puis supprimés. | `git show --raw ad45932` → statut `D` |
| 3 | **Les 4 référentiels de la carte « Compliance » sont factices** (CNDP 38/45, Bank Al-Maghrib 27/34, CIS AWS 112/140, ISO 27001 61/78). Seuls le score et le grade viennent de l'API. Le composant l'assume en commentaire. | `frontend/src/lib/data.ts:complianceFrameworks`, `compliance-card.tsx:12` |
| 4 | **L'envoi d'e-mail d'invitation est un stub** : `send_invitation_email` journalise le lien d'activation au niveau WARNING au lieu de l'envoyer. Aucun fournisseur SMTP n'est configuré. | `backend/app/services/email.py` |
| 5 | **La réinitialisation de mot de passe est incomplète** : `POST /api/auth/forgot-password` accuse réception (202) mais aucune route de réinitialisation par jeton n'existe. | `backend/app/api/auth.py:231-243` |
| 6 | **Incohérence de nommage des secrets CI** entre les deux workflows : `scan.yml` attend `IACGUARD_TOKEN` / `IACGUARD_API_URL`, `scan-standalone.yml` (celui que le README recommande) attend `IAC_GUARD_TOKEN` / `IAC_GUARD_API_URL`. | Les deux fichiers YAML |
| 7 | **Placeholder non substitué** : `scan.yml` contient `IACGUARD_RAW: "https://raw.githubusercontent.com/ORG/iac-guard/main"` alors que le dépôt réel est `chafiq753/iac-guard`. Il référence aussi `policies/bundle.tar.gz`, qui n'existe pas. | `scan.yml:30, 77` |
| 8 | **Alembic n'est pas en place** : `Base.metadata.create_all` reste utilisé au démarrage. Un script ad hoc (`migrate_rbac.py`) comble le manque pour la seule transition RBAC. | `backend/app/main.py:36` |
| 9 | **Page « Compliance » absente** : l'entrée de sidebar existe mais son `href` vaut `/`. Le bouton « Help & Support » n'a ni `onClick` ni `href`. | `app-sidebar.tsx:37, 99-103` |
| 10 | **OAuth GitHub absent** : le bouton n'apparaît que si l'API renvoie `"github"` dans `methods`, ce qu'elle ne fait jamais ; il est de toute façon rendu `disabled`. | `api/auth.py:184`, `login/page.tsx:266-272` |

---

## 5. Points forts constatés dans le code

- **Justification écrite des décisions de sécurité.** Presque chaque mesure est accompagnée d'un commentaire expliquant *pourquoi* : pourquoi SHA-256 suffit pour un token de projet mais pas pour un mot de passe, pourquoi 404 plutôt que 403 hors périmètre, pourquoi le challenge WebAuthn est stocké en base et non en cookie, pourquoi le niveau de log du stub e-mail est WARNING et non INFO.
- **Séparation nette des trois circuits d'authentification** (token de projet, JWT de session, JWT de portée `mfa`), avec vérification systématique du `scope` — et un test dédié qui vérifie qu'un jeton MFA n'ouvre pas l'API.
- **Le rôle n'est jamais porté par le JWT** : il est relu en base à chaque requête, ce qui rend un changement de rôle ou une désactivation immédiatement effectifs.
- **Journaux d'audit dénormalisés à dessein**, pour survivre à la suppression de ce qu'ils documentent — avec un test qui le vérifie.
- **Refus de démarrage en production** sur configuration dangereuse (clé de signature par défaut ou trop courte, cookie non sécurisé) — le commit le plus récent du dépôt.
- **151 tests backend passants**, couvrant l'authentification, le RBAC, la 2FA, le triage, l'audit, le scoring et la politique de scan.

---

## 6. Zones non couvertes par les tests

| Zone | État |
|---|---|
| Frontend | **Aucun test** : ni unitaire, ni composant, ni bout en bout. Aucune dépendance de test dans `package.json`. |
| Aggregator | **Aucun test** des 4 parsers, malgré la présence des 4 échantillons JSON dans `pipeline/aggregator/samples/`. |
| Script de migration | `migrate_rbac.py` n'est couvert par aucun test. |
| Intégration continue du dépôt | **Aucune CI n'exécute les tests** : les seuls workflows présents sont les *modèles* destinés aux dépôts clients ; `iac-guard` lui-même n'a pas de `.github/workflows/`. |
| WebAuthn | Seuls les cas d'échec et le bien-formé des options sont testés — une signature valide exigerait un authentificateur matériel. |

---

## 7. Documents produits

| Fichier | Objet | Public visé |
|---|---|---|
| [`PROJECT_ANALYSIS.md`](PROJECT_ANALYSIS.md) | Analyse technique exhaustive : architecture, modèle de données, API, fonctionnalités, sécurité, tests, limites | Rédaction du rapport de projet ; toute personne devant reprendre le code |
| [`SYNTHESE_ANALYSE.md`](SYNTHESE_ANALYSE.md) | Ce document : méthode, couverture, écarts constatés | Lecture rapide avant d'entrer dans le détail |
| [`PRESENTATION_PROJET.md`](PRESENTATION_PROJET.md) | Vue générale : problème traité, apport pour les développeurs, besoins fonctionnels et non fonctionnels | Introduction et chapitres « analyse des besoins » du rapport ; présentation orale |
