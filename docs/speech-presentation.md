# Speech de présentation — iac-guard

Texte à dire, écrit pour être **parlé** (phrases courtes, pas de jargon inutile).
Durée : ~1 min 30 d'introduction, puis les transitions pendant la démo.

---

## 1. Le problème (40 s)

> « Aujourd'hui, une équipe qui déploie une application ne clique plus dans une
> console cloud : elle décrit son infrastructure dans du code — c'est ce qu'on
> appelle l'Infrastructure as Code, avec Terraform par exemple.
>
> Le problème, c'est que ce code part en production **sans être relu du point de
> vue sécurité**. Trois choses passent alors inaperçues :
>
> - un **secret** commité par erreur — un mot de passe de base de données, une
>   clé d'API — qui reste dans l'historique Git pour toujours ;
> - une **ressource mal configurée** — un stockage accessible publiquement, une
>   base de données non chiffrée, un port SSH ouvert à tout Internet ;
> - une **faille dans le code applicatif** — une injection SQL, une commande
>   système construite avec ce que tape l'utilisateur.
>
> Et le vrai problème n'est pas qu'il n'existe pas d'outils. Il en existe. Le
> problème, c'est que **personne ne les lance**, et que **rien n'empêche** le
> code dangereux d'arriver en production. »

---

## 2. La solution (40 s)

> « iac-guard répond à ça en trois temps.
>
> **Premier temps : on automatise.** À chaque modification du code, trois
> scanners complémentaires se lancent tout seuls — Gitleaks pour les secrets,
> Checkov pour la configuration de l'infrastructure, Semgrep pour le code
> applicatif. Le développeur n'a rien à faire, rien à installer.
>
> **Deuxième temps : on unifie.** Ces trois outils produisent trois formats
> différents, illisibles séparément. Mon agrégateur les normalise en un seul
> schéma, calcule une empreinte pour chaque problème — ce qui permet de suivre
> le même problème d'un scan à l'autre — et envoie le tout à mon API.
>
> **Troisième temps, et c'est le plus important : on bloque.** Un tableau de
> bord que personne n'ouvre ne sert à rien. Alors quand un problème dépasse le
> seuil de gravité défini pour le projet, **la fusion vers la production est
> refusée**. Ce n'est pas un avertissement : c'est une barrière. »

---

## 3. L'architecture (20 s)

> « Techniquement : un backend **FastAPI** avec **PostgreSQL**, un tableau de
> bord **Next.js**, et un pipeline **GitHub Actions**. Le pipeline s'authentifie
> avec un jeton propre à chaque projet — un client ne peut donc écrire que dans
> son propre espace. »

```
Push / Pull Request
        │
        ▼
   GitHub Actions ──── Gitleaks · Checkov · Semgrep
        │
        ▼
   Aggregator  (3 formats → 1 schéma unifié)
        │
        ▼
   API FastAPI ──── PostgreSQL
        │
        ├──→ Dashboard Next.js
        └──→ Verdict : bloquer ou laisser passer
```

---

## 4. Les fonctionnalités construites (30 s)

> « Autour de ce cœur, j'ai construit ce qu'il faut pour que ce soit utilisable
> par une vraie équipe : »

| Domaine | Ce qui est fait |
|---|---|
| **Authentification** | mot de passe haché en Argon2id, double authentification par code TOTP **et** par biométrie (WebAuthn / Windows Hello), codes de secours, verrouillage après échecs répétés |
| **Gestion des comptes** | 5 rôles (admin, responsable sécurité, développeur, auditeur, lecteur), invitations par e-mail, activation/désactivation d'un compte, **périmètre par projet** — un développeur ne voit que les projets qu'on lui a attribués |
| **Traçabilité** | journal d'audit inaltérable : qui a changé quel rôle, qui a classé quelle alerte, et quand |
| **Analyse** | score de conformité, filtres par gravité, par outil, par projet, historique des scans |
| **Traitement** | chaque alerte peut être acceptée, résolue ou marquée en faux positif, avec justification ; une règle peut être ignorée pour tout un projet |
| **Politique** | seuil de blocage configurable par projet |

---

## 5. Pendant la démonstration — phrases de transition

**En montrant le dépôt :**
> « Voici une application réaliste : une API de paiement en Python, son
> infrastructure Terraform, et trois branches de développement. »

**En montrant le workflow :**
> « Ce fichier est la seule chose que le client ajoute à son dépôt, avec deux
> valeurs de configuration : le jeton de son projet et l'adresse de l'API. »

**En montrant le tableau de bord :**
> « 87 problèmes détectés : 6 secrets exposés, 9 failles de code, 72 erreurs de
> configuration. Et pour chacun : le fichier, la ligne exacte, pourquoi c'est
> un risque, et comment le corriger. »

**En montrant un secret trouvé dans une autre branche :**
> « Celui-ci est intéressant : cette clé n'est pas sur la branche principale,
> elle est dans une branche de fonctionnalité. Le scan remonte tout
> l'historique du dépôt. »

**Au moment du blocage :**
> « Le bouton de fusion est grisé. Mon outil a détecté une clé exposée et une
> injection SQL, et GitHub refuse la fusion. Et j'ai activé une option qui fait
> que **même le propriétaire du dépôt ne peut pas passer outre**. »

---

## 6. Conclusion et suite (20 s)

> « Pour résumer : trois scanners complémentaires, un format unifié, un tableau
> de bord centralisé, et surtout une barrière automatique qui empêche le code
> dangereux d'atteindre la production.
>
> La suite, c'est ce qui fera la différence sur le marché marocain : un moteur
> de conformité qui traduira ces résultats techniques en articles de la **loi
> 09-08 de la CNDP** et des directives de **Bank Al-Maghrib**. Aujourd'hui, un
> outil dit à un développeur "ce bucket est public". Demain, le mien dira à un
> responsable conformité "cette configuration vous met en infraction avec tel
> article, voici comment le corriger". »

---

## Si le prof pose des questions

**« Pourquoi trois outils et pas un seul ? »**
> « Parce qu'ils ne regardent pas la même chose. Gitleaks lit l'historique Git
> à la recherche de secrets. Checkov comprend la sémantique Terraform. Semgrep
> analyse le code applicatif. Aucun ne fait le travail des deux autres. »

**« Qu'est-ce qui vous distingue de ces outils, alors ? »**
> « Eux sont des scanners. Moi je suis la couche au-dessus : l'orchestration, la
> normalisation, l'historisation, la gestion d'équipe et le blocage. Un scanner
> vous donne un fichier JSON dans un terminal. Mon outil donne à une équipe un
> suivi dans le temps et une barrière automatique. »

**« Est-ce que ça ne bloque pas trop, en pratique ? »**
> « Le seuil est configurable par projet — on peut bloquer seulement sur les
> secrets exposés, par exemple. Et une règle jugée non pertinente peut être
> acceptée comme risque connu, avec une justification qui reste dans le journal
> d'audit. »

**« Où en êtes-vous exactement ? »**
> « La chaîne complète fonctionne de bout en bout, c'est ce que je viens de
> montrer. Il reste trois chantiers : le moteur de conformité CNDP, l'export
> PDF pour les auditeurs, et l'affinage du score — aujourd'hui il sature trop
> vite sur les dépôts très vulnérables. »
