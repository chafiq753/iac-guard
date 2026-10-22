# iac-guard — Présentation générale du projet

> Document de cadrage : ce que fait le produit, à quel problème il répond, ce qu'il change
> concrètement pour un développeur, et l'expression structurée des besoins fonctionnels et
> non fonctionnels.
>
> Chaque besoin porte un identifiant traçable et un **statut vérifié dans le code** :
> **Réalisé** · **Partiel** · **Non réalisé**.
> Le détail technique de chaque point se trouve dans [`PROJECT_ANALYSIS.md`](PROJECT_ANALYSIS.md).

---

## 1. Le projet en une phrase

**iac-guard est une plateforme qui analyse automatiquement la sécurité du code d'infrastructure
à chaque modification d'un dépôt, unifie les résultats de plusieurs analyseurs dans un tableau de
bord unique, et refuse la fusion vers la production lorsqu'un problème dépasse le seuil de gravité
défini pour le projet.**

---

## 2. Le problème traité

### 2.1 Le contexte

Une équipe qui déploie une application ne clique plus dans une console cloud : elle **décrit son
infrastructure dans du code** — c'est l'*Infrastructure as Code* (IaC), avec Terraform notamment.
Ce code crée des bases de données, ouvre des ports réseau, attribue des droits d'accès. Il a donc
exactement le même pouvoir qu'un administrateur système — mais il est écrit par des développeurs,
relu comme du code applicatif, et rarement audité du point de vue sécurité.

### 2.2 Trois catégories de défauts passent inaperçues

| # | Catégorie | Exemples concrets | Conséquence |
|---|---|---|---|
| 1 | **Secrets commités par erreur** | Clé d'accès AWS, mot de passe de base de données, clé d'API Stripe écrits en clair dans un fichier | Le secret reste dans l'historique Git **pour toujours**, même après suppression du fichier. Quiconque accède au dépôt — collègue, fork public, sauvegarde — peut le réutiliser. |
| 2 | **Ressources mal configurées** | Stockage objet accessible publiquement, base de données non chiffrée au repos, port SSH (22) ou RDP (3389) ouvert à `0.0.0.0/0`, politique IAM avec `Action: "*"` | Élargit massivement la surface d'attaque. Un port d'administration public est scanné et attaqué en force brute par des robots dans les minutes qui suivent sa mise en ligne. |
| 3 | **Vulnérabilités du code applicatif** | Injection SQL, injection de commande système (`shell=True` sur une entrée utilisateur), signature JWT non vérifiée, cookie sans `httpOnly` | Va de la fuite de données à l'exécution de code arbitraire sur le serveur. |

### 2.3 Pourquoi les outils existants ne suffisent pas

Des analyseurs performants existent pour chacune de ces catégories — Gitleaks, Checkov, Semgrep.
Le problème n'est pas leur absence, mais leur **usage réel** :

| Obstacle | Description |
|---|---|
| **Personne ne les lance** | Ce sont des outils en ligne de commande, à installer et exécuter manuellement. Sous pression de livraison, cette étape saute. |
| **Trois formats incompatibles** | Gitleaks produit une liste plate, Checkov un objet `{results: {failed_checks: [...]}}`, Semgrep un objet `{results: [...]}` avec sa propre échelle de sévérité (`ERROR`/`WARNING`/`INFO`). Impossible de les lire ensemble, encore moins de les comparer dans le temps. |
| **Aucune mémoire** | Chaque exécution repart de zéro. Impossible de savoir si un problème est nouveau, s'il a déjà été jugé acceptable, ou s'il traîne depuis trois mois. |
| **Aucune conséquence** | Un fichier JSON dans un terminal n'empêche rien. Le code dangereux part quand même en production. |
| **Aucune notion d'équipe** | Pas de rôles, pas de périmètre par projet, pas de traçabilité de qui a décidé quoi. |

> **La proposition de valeur d'iac-guard n'est donc pas de détecter — les scanners le font déjà —
> mais d'orchestrer, normaliser, historiser, faire décider et bloquer.**

---

## 3. Ce que fait iac-guard

La chaîne complète se déroule en cinq temps, sans aucune action manuelle du développeur.

### 3.1 Automatiser

À chaque `push` et à chaque `pull request` sur le dépôt du client, un workflow GitHub Actions se
déclenche seul et exécute trois analyseurs complémentaires :

| Analyseur | Ce qu'il regarde | Particularité |
|---|---|---|
| **Gitleaks 8.21.2** | Les secrets, dans les fichiers **et dans tout l'historique Git** (`fetch-depth: 0`) | Détecte donc une clé présente dans une branche non fusionnée, ou dans un commit ancien |
| **Checkov** | La sémantique Terraform : chiffrement, exposition réseau, permissions IAM | Comprend les ressources cloud, pas seulement le texte |
| **Semgrep 1.78.0** | Le code applicatif (Python, JavaScript…), en analyse statique | `--config=auto` : jeu de règles adapté aux langages détectés |

Un scanner qui trouve des problèmes sort en code d'erreur : le workflow le tolère volontairement
(`continue-on-error: true`) pour **collecter les trois rapports** au lieu de s'arrêter au premier.

### 3.2 Unifier

Un agrégateur Python convertit ces formats incompatibles en un schéma unique. Pour chaque problème
il calcule une **empreinte déterministe** :

```
fingerprint = sha1( source | rule_id | fichier | ligne_début | ressource )
```

Cette empreinte est la clé de voûte du produit : elle ne dépend pas du contenu brut du rapport,
donc **un même problème redétecté d'un scan à l'autre garde la même identité**. C'est ce qui rend
possible le suivi dans le temps et la persistance des décisions.

### 3.3 Centraliser

Le rapport normalisé est envoyé à l'API, authentifié par un **jeton propre à chaque projet** :
un client ne peut écrire que dans son propre espace, jamais dans celui d'un autre. Le scan, ses
problèmes et leur contexte (dépôt, branche, commit, horodatage) sont persistés.

### 3.4 Faire décider

Un tableau de bord présente les résultats à hauteur d'équipe : score de conformité, courbe
d'évolution, alertes triables et filtrables, et pour chaque problème un panneau expliquant en
français **ce que c'est, ce qu'un attaquant peut en faire, et comment le corriger**, avec un lien
vers la ligne exacte du code au commit concerné.

Chaque alerte peut être **acceptée**, **résolue** ou **classée faux positif**, avec justification.
Grâce à l'empreinte, cette décision survit aux scans suivants.

### 3.5 Bloquer

C'est le point différenciant. Chaque projet définit un **seuil de gravité** (`critical`, `high`,
`medium`, `low`, `info`, ou aucun). Lorsqu'un problème non exclu atteint ce seuil ou pire :

```
API renvoie should_fail: true
   → l'agrégateur retourne le code de sortie 1
      → le job GitHub Actions « scan » échoue
         → la protection de branche refuse la fusion
            → le bouton « Merge pull request » est grisé
```

Ce n'est pas un avertissement que l'on peut ignorer : c'est une barrière. Avec l'option
`enforce_admins` de GitHub, même le propriétaire du dépôt ne peut pas passer outre.

Le scan est **toujours enregistré**, même quand la politique est dépassée : le blocage porte sur la
fusion, pas sur la collecte des données.

---

## 4. En quoi cela aide concrètement un développeur

### 4.1 Avant / après

| Situation | Sans iac-guard | Avec iac-guard |
|---|---|---|
| Un développeur colle une clé AWS dans `main.tf` pour tester | La clé part sur la branche, puis en production. Découverte des mois plus tard, ou jamais. | Détectée en une minute sur la pull request. Fusion refusée. Le développeur voit `infra/main.tf:12` et la marche à suivre pour révoquer. |
| Un bucket est créé en `public-read` | Personne ne le remarque : le code fonctionne. | Signalé comme `CKV_AWS_20`, gravité élevée, avec l'explication : *« un attaquant qui devine le nom du bucket peut lister et télécharger tous les fichiers »*. |
| Une requête SQL est construite par concaténation | Passe la revue de code si le relecteur ne connaît pas le motif. | Semgrep le signale, l'alerte apparaît dans le tableau de bord avec un scénario d'exploitation. |
| L'équipe veut savoir si la situation s'améliore | Aucune donnée. Impression subjective. | Score de conformité sur 100, courbe sur les 7 derniers scans, historique complet par projet. |
| Un problème est jugé acceptable | Discussion orale, oubliée. Ressignalé au scan suivant. | Marqué « faux positif » ou « accepté » avec justification. La décision persiste et reste consultable dans le journal d'audit. |
| Un dépôt n'a plus été scanné depuis 3 semaines | Invisible. | Signalé en orange dans la liste des projets : *« Aucun scan depuis 21j »*. |

### 4.2 Le coût d'adoption pour l'équipe cliente

C'est délibérément minimal — trois actions, une seule fois :

1. Copier un fichier de workflow dans `.github/workflows/` ;
2. Copier le dossier de l'agrégateur dans `.iacguard/` ;
3. Renseigner deux valeurs dans les paramètres GitHub : un secret (le jeton du projet) et une
   variable (l'URL de l'API).

**Rien à installer sur le poste du développeur. Rien à lancer à la main. Rien à apprendre.**
Le développeur ne rencontre l'outil que lorsqu'il a introduit un problème — et à ce moment-là,
il reçoit un fichier, une ligne, une explication et une correction.

### 4.3 Ce que gagnent les autres rôles

| Rôle | Bénéfice |
|---|---|
| **Responsable sécurité** (`security_lead`) | Vue sur tous les projets de l'organisation sans octroi individuel. Définit le seuil de blocage par projet. Arbitre les exceptions de règles. |
| **Auditeur** (`auditor`) | Deux journaux inaltérables : qui a classé quelle alerte et quand ; qui a modifié quel compte et quand. Ces journaux survivent à la suppression du projet qu'ils documentent. |
| **Administrateur** (`admin`) | Invite les collègues, attribue les rôles, définit le périmètre projet de chacun, désactive un compte, réinitialise une biométrie perdue. |
| **Direction / conformité** | Un score chiffré et une tendance, plutôt qu'une appréciation. *(La traduction en articles de la loi 09-08 CNDP et en directives Bank Al-Maghrib est le chantier suivant — voir §8.)* |

---

## 5. Périmètre du produit

### 5.1 Dans le périmètre

- Analyse automatique déclenchée par le cycle de vie Git (push, pull request, déclenchement manuel).
- Normalisation multi-analyseurs et suivi d'un problème dans le temps.
- Score de conformité, historique, filtres, recherche.
- Traitement des alertes avec justification et traçabilité.
- Politique de blocage configurable par projet, avec exceptions de règles.
- Gestion d'équipe : organisations, cinq rôles, invitations, périmètres d'accès par projet.
- Authentification forte : mot de passe, biométrie/passkey, code à usage unique, codes de secours.

### 5.2 Hors périmètre (assumé)

| Point | Raison |
|---|---|
| **Corriger le code automatiquement** | iac-guard signale et explique ; la correction reste la décision du développeur. |
| **Remplacer les analyseurs** | Le produit est la couche d'orchestration au-dessus. Gitleaks, Checkov et Semgrep restent les moteurs de détection. |
| **Analyser l'infrastructure déployée** (CSPM) | L'analyse porte sur le **code**, avant déploiement, pas sur l'état réel du compte cloud. |
| **Autres forges que GitHub** | Les modèles de pipeline fournis sont des workflows GitHub Actions. L'API elle-même est agnostique (un simple POST authentifié), mais aucun modèle GitLab CI ou Jenkins n'est fourni. |
| **Autres fournisseurs cloud que AWS** | Checkov couvre Azure et GCP, mais la base de connaissances pédagogique et le Terraform de démonstration ne traitent que des ressources AWS. |

---

## 6. Besoins fonctionnels

Statuts vérifiés dans le code au commit `a2854f1`.

### 6.1 Analyse et ingestion

| ID | Besoin | Statut | Implémentation |
|---|---|---|---|
| **BF-01** | Le système doit déclencher une analyse automatiquement à chaque `push` et `pull request` du dépôt client, ainsi qu'à la demande. | Réalisé | `scan-standalone.yml` (`push`, `pull_request`, `workflow_dispatch`) |
| **BF-02** | Le système doit détecter les secrets dans les fichiers **et dans l'historique Git complet**. | Réalisé | Gitleaks avec `fetch-depth: 0` et `--redact` |
| **BF-03** | Le système doit détecter les mauvaises configurations d'infrastructure Terraform. | Réalisé | Checkov `-d . -o json --soft-fail` |
| **BF-04** | Le système doit détecter les vulnérabilités du code applicatif par analyse statique. | Réalisé | Semgrep `--config=auto` |
| **BF-05** | Le système doit détecter les violations de règles métier définies par l'organisation (policies Rego). | **Non réalisé** | Le parser Conftest et la catégorie `policy` existent, mais le dossier `policies/` est **vide** et le workflow recommandé n'exécute pas Conftest |
| **BF-06** | Le système doit normaliser les sorties hétérogènes des analyseurs en un schéma unique. | Réalisé | `pipeline/aggregator/aggregator.py` — 4 parsers, table `_SEVERITY_MAP` |
| **BF-07** | Le système doit attribuer à chaque problème une identité stable permettant de le suivre d'un scan à l'autre. | Réalisé | `sha1(source\|rule_id\|file\|line_start\|resource)` |
| **BF-08** | Le système doit refuser un rapport de scan non authentifié ou dont le jeton est inconnu. | Réalisé | `get_project_from_token` → HTTP 401 |
| **BF-09** | Un client ne doit pouvoir écrire que dans son propre projet. | Réalisé | Le projet est déduit du jeton, jamais du contenu du message |
| **BF-10** | Le système doit conserver l'objet brut produit par l'analyseur, à des fins d'audit. | Réalisé | Colonne `findings.raw` (JSON) |
| **BF-11** | Le système doit conserver le contexte du scan : dépôt, branche, commit, horodatage du scan et horodatage de réception. | Réalisé | Table `scans` — `scanned_at` distinct de `received_at` |

### 6.2 Évaluation et politique

| ID | Besoin | Statut | Implémentation |
|---|---|---|---|
| **BF-12** | Le système doit calculer un score de conformité sur 100, explicable à un auditeur. | Réalisé | `100 − Σ(nombre × poids)`, plancher à 0 |
| **BF-13** | Le score doit pondérer les problèmes selon leur gravité. | Réalisé | `critical` 25, `high` 10, `medium` 3, `low` 1, `info` 0 |
| **BF-14** | Le système doit traduire le score en une note lisible. | Réalisé | A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, sinon F |
| **BF-15** | Chaque projet doit pouvoir définir un seuil de gravité à partir duquel la fusion est refusée. | Réalisé | `PATCH /api/projects/{id}/policy` — 5 valeurs ou `null` |
| **BF-16** | Le dépassement du seuil doit faire échouer le pipeline d'intégration continue. | Réalisé | `should_fail` → code de sortie 1 → check `scan` en échec |
| **BF-17** | Le scan doit être enregistré même lorsque la politique est dépassée. | Réalisé | Le commit précède l'évaluation de la politique |
| **BF-18** | Une règle jugée non pertinente doit pouvoir être acceptée comme risque connu, avec justification. | Réalisé | Table `ignored_rules` (`rule_id` + `note`) |
| **BF-19** | Les problèmes couverts par une exception ne doivent compter ni dans le score ni dans le seuil, tout en restant visibles. | Réalisé | `severity_counts(..., exclude_rule_ids)` |

### 6.3 Traitement des alertes

| ID | Besoin | Statut | Implémentation |
|---|---|---|---|
| **BF-20** | Un analyste doit pouvoir classer une alerte : ouverte, acceptée, résolue, faux positif. | Réalisé | `TRIAGE_STATUSES`, `PATCH .../triage` |
| **BF-21** | Une décision doit pouvoir être justifiée par une note libre. | Réalisé | Champ `note` |
| **BF-22** | Une décision doit persister lorsque le même problème est redétecté par un scan ultérieur. | Réalisé | Triage indexé sur `(project_id, fingerprint)` |
| **BF-23** | Une alerte doit pouvoir être ré-ouverte. | Réalisé | Statut `open` → suppression de la décision |
| **BF-24** | Chaque alerte doit être présentée avec sa localisation exacte, l'explication du risque, un scénario d'attaque et la correction attendue. | Réalisé | `finding-explainer.ts` : 14 règles documentées + 4 replis par catégorie |
| **BF-25** | L'alerte doit renvoyer vers la ligne de code concernée **telle qu'elle était au commit scanné**. | Réalisé | `github.com/{repo}/blob/{commit}/{file}#L{ligne}` |

### 6.4 Consultation

| ID | Besoin | Statut | Implémentation |
|---|---|---|---|
| **BF-26** | Le tableau de bord doit présenter les indicateurs clés du projet sélectionné. | Réalisé | 4 KPI : score, ouverts, critical & high, scans sur 7 jours |
| **BF-27** | Le tableau de bord doit montrer l'évolution des problèmes dans le temps. | Réalisé | Courbe empilée sur les 7 derniers scans |
| **BF-28** | L'utilisateur doit pouvoir consulter toutes les alertes, tous projets confondus. | Réalisé | `GET /api/alerts` — vue « dernier scan par projet » |
| **BF-29** | Les alertes doivent être filtrables par projet, gravité, catégorie et statut, et recherchables en texte libre. | Réalisé | 4 filtres + paramètre `q` |
| **BF-30** | Les alertes doivent être présentées les plus graves en premier. | Réalisé | Tri sur `(poids de gravité, id)` décroissant |
| **BF-31** | L'historique des scans d'un projet doit être consultable. | Réalisé | `GET /api/projects/{id}/scans` |
| **BF-32** | Une nouvelle livraison du pipeline doit apparaître sans rechargement manuel de la page. | Réalisé | Rafraîchissement silencieux toutes les 30 s |
| **BF-33** | Le système doit signaler un projet qui n'a plus été scanné depuis longtemps. | Réalisé | Seuil de 14 jours, affichage en orange |
| **BF-34** | Le système doit présenter la couverture des référentiels de conformité. | **Partiel** | La carte existe, mais les 4 référentiels affichés sont des **données factices** |

### 6.5 Gestion des projets

| ID | Besoin | Statut | Implémentation |
|---|---|---|---|
| **BF-35** | Un utilisateur doit pouvoir créer un projet et recevoir un jeton d'ingestion. | Réalisé | `POST /api/projects` |
| **BF-36** | Le jeton ne doit être affiché qu'une seule fois ; la base ne doit en conserver que l'empreinte. | Réalisé | SHA-256 en base, jeton en clair uniquement dans la réponse de création |
| **BF-37** | Un jeton compromis doit pouvoir être révoqué et remplacé. | Réalisé | `POST /api/projects/{id}/rotate-token` — l'ancien cesse immédiatement de fonctionner |
| **BF-38** | Deux projets d'un même utilisateur ne doivent pas porter le même nom. | Réalisé | Contrainte `uq_project_owner_name` → HTTP 409 |
| **BF-39** | La suppression d'un projet doit effacer tout son historique et exiger une confirmation. | Réalisé | Cascade `delete-orphan` + modale de confirmation |

### 6.6 Authentification

| ID | Besoin | Statut | Implémentation |
|---|---|---|---|
| **BF-40** | Un utilisateur doit pouvoir créer un compte et devenir administrateur de sa nouvelle organisation. | Réalisé | `POST /api/auth/register` |
| **BF-41** | Le mot de passe doit respecter une politique de complexité appliquée **côté serveur**. | Réalisé | 12 caractères minimum + minuscule + majuscule + chiffre + caractère spécial |
| **BF-42** | La session doit être portée par un cookie inaccessible au JavaScript. | Réalisé | Cookie `httpOnly`, `SameSite=Lax`, 24 h |
| **BF-43** | L'utilisateur doit pouvoir activer une double authentification par clé biométrique ou physique. | Réalisé | WebAuthn, vérification utilisateur obligatoire |
| **BF-44** | L'utilisateur doit pouvoir activer une double authentification par code temporaire. | Réalisé | TOTP, QR code, tolérance ± 30 s |
| **BF-45** | La double authentification ne doit être activée qu'après preuve que l'utilisateur sait s'en servir. | Réalisé | `totp_enabled` ne passe à `true` qu'après un premier code valide |
| **BF-46** | L'utilisateur doit disposer de codes de secours en cas de perte de son appareil. | Réalisé | 8 codes à usage unique, régénérables |
| **BF-47** | L'utilisateur doit pouvoir se connecter directement par passkey, sans mot de passe. | Réalisé | `POST /api/auth/webauthn/login/{options,verify}` |
| **BF-48** | L'utilisateur doit pouvoir modifier son nom, son e-mail et son mot de passe. | Réalisé | Le changement de mot de passe exige le mot de passe actuel |
| **BF-49** | L'utilisateur doit pouvoir réinitialiser un mot de passe oublié. | **Partiel** | La route accuse réception (202) ; aucun envoi d'e-mail ni route de réinitialisation par jeton |
| **BF-50** | L'utilisateur doit pouvoir se connecter via son compte GitHub. | **Non réalisé** | Marqué « futur » ; le bouton n'est jamais activé |

### 6.7 Gestion des comptes et des droits

| ID | Besoin | Statut | Implémentation |
|---|---|---|---|
| **BF-51** | Le système doit distinguer cinq rôles aux droits différenciés. | Réalisé | `admin`, `security_lead`, `developer`, `auditor`, `viewer` |
| **BF-52** | Un administrateur doit pouvoir inviter un collègue par e-mail avec un rôle. | Réalisé (flux) / **Stub** (envoi) | Le lien d'activation est **journalisé**, non envoyé |
| **BF-53** | Le lien d'invitation doit expirer et n'être utilisable qu'une fois. | Réalisé | 72 heures, `accepted_at` marque la consommation |
| **BF-54** | Renvoyer une invitation doit invalider la précédente. | Réalisé | Suppression des invitations non acceptées du même utilisateur |
| **BF-55** | Un administrateur doit pouvoir changer le rôle d'un membre et activer/désactiver son compte. | Réalisé | `PATCH .../role` et `PATCH .../status` |
| **BF-56** | Un administrateur doit pouvoir définir, pour chaque membre, la liste des projets accessibles. | Réalisé | `PUT .../project-access` — remplacement intégral |
| **BF-57** | Les rôles `admin` et `security_lead` doivent voir tous les projets de leur organisation sans octroi individuel. | Réalisé | `GLOBAL_ACCESS_ROLES` |
| **BF-58** | Un utilisateur sans accès global et sans octroi ne doit voir aucun projet. | Réalisé | Vérifié par test |
| **BF-59** | Le système doit empêcher la perte d'accès à l'administration : le dernier administrateur actif ne peut être ni rétrogradé ni désactivé, et nul ne peut se désactiver soi-même. | Réalisé | Trois contrôles distincts → HTTP 409 |
| **BF-60** | Un administrateur doit pouvoir révoquer les clés biométriques d'un membre ayant perdu son appareil. | Réalisé | `POST .../reset-webauthn` |
| **BF-61** | Un administrateur ne doit pouvoir gérer que les membres de sa propre organisation. | Réalisé | Contrôle `org_id` → HTTP 404 |
| **BF-62** | Le système doit limiter le nombre d'invitations par administrateur. | Réalisé | 10 par heure → HTTP 429 |

### 6.8 Traçabilité

| ID | Besoin | Statut | Implémentation |
|---|---|---|---|
| **BF-63** | Toute décision sur une alerte doit être enregistrée de façon inaltérable. | Réalisé | Table `triage_audit_log`, en ajout seul |
| **BF-64** | Toute action d'administration de compte doit être enregistrée de façon inaltérable. | Réalisé | Table `admin_audit_logs`, 6 types d'action |
| **BF-65** | Le journal d'audit doit rester lisible après la suppression du projet qu'il documente. | Réalisé | Dénormalisation volontaire de `project_name`, `owner_id`, `finding_title` |
| **BF-66** | Un changement sans effet ne doit pas polluer le journal. | Réalisé | Journalisation uniquement si `from_status != to_status` |
| **BF-67** | Les journaux doivent être filtrables (par projet, acteur, cible, action, période) et paginés. | Réalisé | `GET /api/audit-log`, `GET /api/admin/audit-logs` |

### 6.9 Conformité réglementaire

| ID | Besoin | Statut | Commentaire |
|---|---|---|---|
| **BF-68** | Le système doit associer chaque résultat technique aux articles de la loi 09-08 (CNDP) et aux directives de Bank Al-Maghrib. | **Non réalisé** | Chantier annoncé. Le schéma du pipeline exclut explicitement le mapping réglementaire, l'enrichissement étant prévu côté serveur à partir du `rule_id` — mais ce code n'existe pas |
| **BF-69** | Le système doit produire un rapport exportable en PDF pour un audit externe. | **Non réalisé** | Aucune route, aucune dépendance PDF |

---

## 7. Besoins non fonctionnels

### 7.1 Sécurité

| ID | Exigence | Comment elle est satisfaite |
|---|---|---|
| **BNF-01** | Aucun mot de passe ne doit être stocké en clair ni de façon réversible. | Argon2id, paramètres OWASP (m = 64 MiB, t = 3, p = 4), sel aléatoire embarqué |
| **BNF-02** | Les anciens hachages doivent pouvoir être modernisés sans intervention de l'utilisateur. | Détection des hachages bcrypt, vérification, puis re-hachage en Argon2id au premier login réussi — seul moment où le mot de passe est connu en clair |
| **BNF-03** | Aucun secret ne doit être stocké de façon réversible : ni jeton de projet, ni jeton d'invitation, ni code de secours. | SHA-256 pour tous. Justification : ces valeurs sont générées aléatoirement (256 bits), donc non attaquables par dictionnaire, contrairement à un mot de passe humain |
| **BNF-04** | Une faille XSS sur le tableau de bord ne doit pas permettre de voler une session. | Cookie `httpOnly` : invisible au JavaScript. Aucun jeton en `localStorage` |
| **BNF-05** | Le système doit résister aux attaques CSRF. | `SameSite=Lax` + liste CORS explicite, jamais `"*"` (incompatible avec `allow_credentials=True`) |
| **BNF-06** | Un changement de rôle ou une désactivation de compte doit prendre effet immédiatement. | Le rôle n'est **jamais** porté par le jeton : l'utilisateur est rechargé depuis la base à chaque requête |
| **BNF-07** | Le jeton délivré entre la validation du mot de passe et celle du second facteur ne doit ouvrir aucune donnée. | Portée `mfa` distincte de `session`, vérifiée à chaque décodage. Durée réduite à 5 minutes |
| **BNF-08** | Le système ne doit pas révéler l'existence d'un compte. | Quatre mesures : message d'erreur unique, hachage factice pour égaliser les temps de réponse, `/methods` neutre, `/forgot-password` toujours 202 |
| **BNF-09** | Le système ne doit pas révéler l'existence d'une ressource hors périmètre. | HTTP **404**, jamais 403 : « ça n'existe pas » et « tu n'y as pas accès » doivent être indiscernables |
| **BNF-10** | Le système doit résister aux tentatives de connexion par force brute. | 5 échecs → verrou de 15 minutes ; compteur remis à zéro après un succès |
| **BNF-11** | La biométrie de l'utilisateur ne doit jamais parvenir au serveur. | WebAuthn : seule la clé publique est stockée. La clé privée reste dans le TPM / Secure Enclave |
| **BNF-12** | Un challenge d'authentification ne doit servir qu'une fois. | Stocké en base, supprimé à la consommation, durée de vie 300 s |
| **BNF-13** | Le système doit détecter une clé de sécurité clonée. | Refus si le compteur de signature régresse — avec tolérance du cas `0`, que beaucoup de passkeys renvoient toujours |
| **BNF-14** | L'application doit refuser de démarrer en production avec une configuration dangereuse. | `ValueError` bloquante si `SECRET_KEY` est absente, par défaut ou de moins de 32 caractères, ou si `COOKIE_SECURE` est désactivé |
| **BNF-15** | Un mot de passe déraisonnablement long ne doit pas devenir un vecteur de déni de service. | Borne à 1024 octets ; refus (et non troncature) au-delà de 72 octets sur les hachages bcrypt |
| **BNF-16** | Les comparaisons de secrets doivent résister aux attaques temporelles. | `hmac.compare_digest` pour les codes de secours |
| **BNF-17** | Aucun secret ne doit être versionné. | `.gitignore` couvre `.env`, `.env.local`, `*.db`, `*.bak*`, `*.sql` et les rapports de scan |
| **BNF-18** | La sécurité ne doit pas reposer sur le secret de l'implémentation. | Le dépôt est public ; la sécurité repose sur les clés fournies au déploiement — d'où BNF-14 |

**Limites connues.** Le paramètre `webauthn_rp_id` vaut `"localhost"` par défaut et devra être ajusté
au domaine réel. Les identifiants PostgreSQL de `docker-compose.yml` sont en clair (fichier explicitement
libellé « développement »). Le lien d'invitation transite aujourd'hui par les journaux applicatifs.
Il n'existe pas de limitation de débit par adresse IP, ni de révocation explicite de jeton avant
expiration (la désactivation du compte joue ce rôle).

### 7.2 Performance et passage à l'échelle

| ID | Exigence | État |
|---|---|---|
| **BNF-19** | Un scan complet doit s'exécuter en quelques minutes. | Satisfait — environ 1 minute observée sur le dépôt de démonstration |
| **BNF-20** | Le tableau de bord doit s'afficher sans attente perceptible. | Satisfait — squelettes de chargement, détail des 7 derniers scans chargé en parallèle (`Promise.all`) |
| **BNF-21** | Le score doit pouvoir être recalculé sans re-scanner. | Satisfait — le score n'est pas stocké, il est calculé à la lecture ; ajuster les poids suffit |
| **BNF-22** | Les listes volumineuses doivent être paginées. | Satisfait fonctionnellement (`page`, `page_size` borné à 100) — **mais** la pagination et une partie du filtrage s'effectuent **en mémoire**, après chargement de toutes les lignes. Ne passe pas à l'échelle en l'état |
| **BNF-23** | Le nombre de requêtes SQL doit rester proportionné. | **Non satisfait** sur `/api/alerts` : trois requêtes par projet (dernier scan, problèmes, décisions de triage) |
| **BNF-24** | Les traitements longs ne doivent pas bloquer la requête HTTP. | **Non satisfait** — ingestion, calcul de score et évaluation de politique sont synchrones. Acceptable à l'échelle actuelle (150 problèmes pour le scan de démonstration) |

### 7.3 Fiabilité et disponibilité

| ID | Exigence | Comment elle est satisfaite |
|---|---|---|
| **BNF-25** | Un scan et ses problèmes doivent être écrits de façon atomique. | Transaction unique : `flush` pour obtenir l'identifiant du scan, puis insertions, puis `commit` |
| **BNF-26** | Une action d'administration et sa trace d'audit ne doivent jamais être dissociées. | `log_admin_action` n'appelle jamais `commit` : le routeur valide les deux dans la même transaction |
| **BNF-27** | Un analyseur en échec ne doit pas empêcher la collecte des autres. | `continue-on-error: true` sur chaque étape de scan |
| **BNF-28** | Un échec d'envoi du rapport doit faire échouer le pipeline. | Aucune tolérance d'erreur sur l'étape d'envoi — *« un pipeline vert alors que le scan s'est perdu en route est pire que pas de scan du tout »* |
| **BNF-29** | Le système doit échouer tôt et clairement lorsque l'API est injoignable. | Contrôle `GET /health` en début de workflow, avec message `::error::` explicite, plutôt qu'un échec après trois minutes d'analyse |
| **BNF-30** | Le système doit tolérer les artefacts de copier-coller dans la configuration CI. | Nettoyage des espaces, retours à la ligne et slash final de l'URL, côté workflow et côté agrégateur |
| **BNF-31** | Le système ne doit pas planter sur une donnée d'analyseur inattendue. | Sévérités inconnues ignorées, valeurs textuelles converties, fichiers absents ou vides traités comme « outil non exécuté » |
| **BNF-32** | La base doit survivre au redémarrage des conteneurs. | Volume Docker nommé `pgdata` |
| **BNF-33** | L'API ne doit démarrer qu'une fois la base prête. | `depends_on: condition: service_healthy` + `pg_isready` |

### 7.4 Utilisabilité

| ID | Exigence | Comment elle est satisfaite |
|---|---|---|
| **BNF-34** | L'interface doit être en français, langue de travail des utilisateurs cibles. | Intégralité de l'interface métier et des messages d'erreur de l'API |
| **BNF-35** | Les écrans d'authentification doivent être disponibles en arabe, avec sens de lecture adapté. | 44 clés traduites FR/AR, `dir="rtl"`, préférence conservée dans le navigateur. **Partiel** : limité aux écrans d'authentification, extension prévue écran par écran |
| **BNF-36** | Un problème doit être compréhensible par un développeur non spécialiste de la sécurité. | Impact, scénario d'attaque et correction en français pour 14 règles connues, avec repli par catégorie |
| **BNF-37** | Toute action destructrice doit être confirmée. | Modales de confirmation pour la suppression de projet et la rotation de jeton, avec conséquences énoncées |
| **BNF-38** | Une valeur affichée une seule fois doit être signalée comme telle et facile à copier. | Encadré « Affiché une seule fois », bouton de copie, téléchargement des codes de secours |
| **BNF-39** | L'interface doit refléter les droits de l'utilisateur. | Entrée « Administration » masquée, actions désactivées sur le dernier administrateur avec infobulle explicative. **Confort d'affichage uniquement** : le contrôle réel reste côté serveur |
| **BNF-40** | L'utilisateur doit être informé du résultat de chaque action. | Notifications (`sonner`) en succès comme en échec, avec le message d'erreur renvoyé par l'API |
| **BNF-41** | L'interface doit être exploitable sur écran étroit. | Composants responsives, colonnes secondaires masquées sous certaines largeurs, barre latérale rétractable |
| **BNF-42** | L'application doit s'adapter au thème clair et sombre. | Variables CSS et classes `dark:` sur l'ensemble des composants |

### 7.5 Maintenabilité et testabilité

| ID | Exigence | État |
|---|---|---|
| **BNF-43** | La logique métier doit être isolée et testable indépendamment de HTTP. | Satisfait — services `scoring`, `aggregates`, `mfa`, `admin_audit` séparés des routeurs |
| **BNF-44** | Les décisions non évidentes doivent être justifiées dans le code. | Satisfait — chaque mesure de sécurité porte un commentaire expliquant *pourquoi* ce choix |
| **BNF-45** | Le contrat entre le pipeline et l'API doit être formalisé et autonome. | Satisfait — `pipeline/aggregator/schema.py` ne dépend d'aucun module du backend, il est copiable tel quel |
| **BNF-46** | Les tests doivent être isolés et reproductibles. | Satisfait — SQLite en mémoire, schéma recréé à chaque test, `lifespan` de l'application non déclenché |
| **BNF-47** | La couverture de tests doit porter sur la logique critique. | Satisfait côté backend — **151 tests, tous passants** (authentification, RBAC, 2FA, triage, audit, scoring, politique) |
| **BNF-48** | Le frontend doit être couvert par des tests. | **Non satisfait** — aucun test, aucune dépendance de test |
| **BNF-49** | L'agrégateur doit être couvert par des tests. | **Non satisfait** — aucun test des 4 parsers, malgré la présence des échantillons |
| **BNF-50** | Les tests doivent s'exécuter automatiquement à chaque modification. | **Non satisfait** — le dépôt `iac-guard` n'a pas de `.github/workflows/` ; les seuls workflows présents sont les modèles destinés aux clients |
| **BNF-51** | L'évolution du schéma de base doit être gérée par des migrations versionnées. | **Non satisfait** — `create_all` au démarrage, complété par un script ad hoc pour la seule transition RBAC. Alembic annoncé, non intégré |
| **BNF-52** | Le code doit être typé. | Satisfait — annotations Python systématiques avec `from __future__ import annotations` ; TypeScript en mode `strict` |

### 7.6 Portabilité et déploiement

| ID | Exigence | État |
|---|---|---|
| **BNF-53** | L'installation doit être reproductible sans configuration manuelle. | Satisfait pour l'API et la base : `docker compose up -d --build`. **Le frontend n'est pas conteneurisé** : il exige `npm install && npm run dev` |
| **BNF-54** | Le développement doit être possible sans dépendance externe lourde. | Satisfait — SQLite par défaut, aucun service à lancer |
| **BNF-55** | Le passage de SQLite à PostgreSQL ne doit demander qu'un changement de configuration. | Satisfait — seule `DATABASE_URL` change. Les écarts de dialecte sont traités explicitement (datetimes naïfs re-localisés en UTC, DDL adapté dans le script de migration) |
| **BNF-56** | Toute la configuration sensible doit venir de l'environnement. | Satisfait — `pydantic-settings`, `.env.example` documenté, aucune valeur de production en dur |
| **BNF-57** | Les versions des outils d'analyse doivent être épinglées et modifiables en un seul endroit. | Partiellement satisfait — Gitleaks, Conftest et Semgrep sont épinglés dans le bloc `env` ; **Checkov ne l'est pas** (`pip install checkov`) |
| **BNF-58** | L'API doit être documentée automatiquement. | Satisfait — OpenAPI et Swagger UI sur `/docs`, générés par FastAPI |
| **BNF-59** | L'état de santé du service doit être interrogeable. | Satisfait — `GET /health`, public, utilisé par le workflow |

### 7.7 Conformité et gouvernance

| ID | Exigence | État |
|---|---|---|
| **BNF-60** | Les journaux d'audit doivent constituer une preuve opposable à un auditeur externe. | Satisfait sur le principe — ajout seul, aucune route de modification ou de suppression, dénormalisation pour survivre à la disparition de l'objet audité |
| **BNF-61** | Toute exception de politique doit être justifiée et traçable. | Satisfait — champ `note` sur les règles ignorées et sur les décisions de traitement |
| **BNF-62** | Les données de deux organisations clientes doivent être strictement cloisonnées. | Satisfait — cloisonnement à trois niveaux : organisation, propriété du projet, octroi explicite ; contrôlé sur chaque route et vérifié par tests |
| **BNF-63** | Le système doit rattacher les constats techniques au cadre réglementaire marocain (loi 09-08, Bank Al-Maghrib). | **Non satisfait** — chantier annoncé, aucun code correspondant |

---

## 8. Contraintes et hypothèses

| # | Contrainte ou hypothèse |
|---|---|
| 1 | Le dépôt du client est hébergé sur **GitHub** : les modèles de pipeline fournis sont des workflows GitHub Actions. L'API reste agnostique (un POST authentifié suffit), mais aucun modèle GitLab CI ou Jenkins n'existe. |
| 2 | Le blocage effectif suppose que le client **active la protection de branche** en exigeant le check `scan`. Sans cette étape, iac-guard signale mais n'empêche rien. |
| 3 | L'API doit être **joignable depuis les runners GitHub**. En démonstration, elle est exposée par un tunnel éphémère — d'où le contrôle `/health` en début de workflow. |
| 4 | Le code de ce dépôt est **public** : la sécurité repose entièrement sur les clés fournies au déploiement, pas sur le secret de l'implémentation. |
| 5 | Le paramètre `webauthn_rp_id` doit correspondre au **domaine du frontend** (et non à celui de l'API), sans quoi les passkeys ne fonctionnent pas. C'est précisément cette contrainte qui les rend résistantes à l'hameçonnage. |
| 6 | L'analyse porte sur le **code**, avant déploiement, et non sur l'état réel de l'infrastructure déployée. |
| 7 | Le premier compte créé par auto-inscription devient administrateur d'une nouvelle organisation ; les collègues rejoignent ensuite cette organisation par invitation, jamais par une seconde inscription. |

---

## 9. Comment vérifier que le produit fonctionne

| Vérification | Commande ou geste | Résultat attendu |
|---|---|---|
| Le backend est sain | `cd backend && python -m pytest` | `151 passed` |
| L'API répond | `curl http://localhost:8000/health` | `{"status":"ok","app":"iac-guard"}` |
| L'API est documentée | Ouvrir `http://localhost:8000/docs` | 49 routes listées |
| L'agrégateur normalise correctement | `python pipeline/aggregator/aggregator.py --gitleaks samples/gitleaks.json --checkov samples/checkov.json --conftest samples/conftest.json --semgrep samples/semgrep.json --repo demo/test` | Rapport unifié imprimé sur la sortie standard (aucun envoi, mode débogage) |
| Le scoring est conforme | 1 critique + 1 élevé + 1 moyen | `100 − (25 + 10 + 3) = 62`, grade **C** |
| Le blocage fonctionne | Définir le seuil `high` sur un projet, envoyer un scan contenant un problème `high` | L'API renvoie `should_fail: true` ; l'agrégateur retourne 1 ; le check `scan` échoue ; le bouton « Merge » est grisé |
| Le triage persiste | Marquer un problème « résolu », relancer le pipeline | Le problème revient avec le statut « résolu », non « ouvert » |
| Le cloisonnement tient | Se connecter avec un compte `viewer` sans octroi de projet | Aucun projet visible ; `/admin` renvoie 403 |

---

## 10. Synthèse en une page

**Ce que c'est.** Une plateforme d'analyse de sécurité pour le code d'infrastructure, qui
transforme des analyseurs isolés et jamais lancés en une barrière automatique intégrée au cycle de
développement.

**Le problème.** Le code d'infrastructure a le pouvoir d'un administrateur système mais est relu
comme du code ordinaire. Trois catégories de défauts passent : secrets commités, ressources mal
configurées, vulnérabilités applicatives. Des outils existent pour chacune, mais personne ne les
lance, leurs formats sont incompatibles, ils n'ont aucune mémoire et n'empêchent rien.

**La réponse, en cinq temps.** Automatiser (trois analyseurs déclenchés par le cycle Git) ·
Unifier (un schéma commun, une empreinte stable par problème) · Centraliser (une API, un historique,
un cloisonnement par jeton de projet) · Faire décider (un tableau de bord, des explications en
français, un traitement justifié) · **Bloquer** (le seuil dépassé fait échouer le pipeline et grise
le bouton de fusion).

**Le différenciant.** Les scanners donnent un fichier JSON dans un terminal. iac-guard donne à une
équipe un suivi dans le temps, une gouvernance par rôles, deux journaux d'audit inaltérables, et
surtout une barrière que même l'administrateur du dépôt ne peut contourner.

**L'état d'avancement.** La chaîne complète fonctionne de bout en bout, couverte par 151 tests
backend passants. Restent inachevés : le moteur de conformité CNDP / Bank Al-Maghrib, l'export PDF,
l'envoi réel des e-mails d'invitation, la réinitialisation de mot de passe, les règles métier Rego,
les migrations Alembic, et la révision d'un score qui sature dès quatre problèmes critiques.

---

## 11. Documents liés

| Fichier | Objet |
|---|---|
| [`PROJECT_ANALYSIS.md`](PROJECT_ANALYSIS.md) | Analyse technique exhaustive : architecture, modèle de données, 49 endpoints, 23 fonctionnalités, 28 mesures de sécurité, tests, limites |
| [`SYNTHESE_ANALYSE.md`](SYNTHESE_ANALYSE.md) | Méthode d'analyse, couverture, écarts entre documentation et code |
| [`README.md`](README.md) | Documentation d'installation et d'utilisation |
| [`docs/speech-presentation.md`](docs/speech-presentation.md) | Texte de présentation orale et questions anticipées |
| [`docs/script-video-demo.md`](docs/script-video-demo.md) | Script minuté d'une démonstration de 5 minutes |
