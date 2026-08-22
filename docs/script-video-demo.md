# Script de démonstration — 5 minutes

Dépôt cible : **https://github.com/chafiq753/atlas-pay** (public)
Projet iac-guard : **atlas-pay** (id 10), seuil de blocage `high`

---

## À faire AVANT d'enregistrer

```bash
# 1. Backend + base
cd c:/Users/hp/Desktop/ZenithSoft/iac-guard
docker compose ps                  # les 2 conteneurs doivent être "Up"

# 2. Tunnel (l'URL change à chaque relance — vérifier qu'il répond)
curl https://<url-tunnel>/health

# 3. Dashboard
cd frontend && npm run dev         # http://localhost:3000
```

Se connecter au dashboard (`admin@gmail.com`) **avant** de lancer
l'enregistrement : personne n'a envie de voir un écran de login.

Onglets à ouvrir d'avance :
1. `github.com/chafiq753/atlas-pay` — code
2. `github.com/chafiq753/atlas-pay/actions` — runs
3. `github.com/chafiq753/atlas-pay/pull/1` — la PR bloquée
4. `localhost:3000/alerts` — le dashboard

> Le scan tourne en ~1 min sur GitHub. Il est **déjà passé** : ne pas
> l'attendre à l'écran, montrer le résultat.

---

## 0:00 — 0:40 · Le problème et la réponse

> « Quand une équipe déploie son infrastructure avec Terraform, trois
> risques passent inaperçus : un secret commité par erreur, une ressource
> mal configurée — un bucket public, une base non chiffrée — et une faille
> dans le code applicatif.
>
> iac-guard automatise ces trois contrôles à chaque modification du code,
> centralise les résultats, et **empêche la fusion** de ce qui est dangereux. »

Montrer le schéma :

```
Push / PR  →  GitHub Actions          →  Aggregator  →  API  →  Dashboard
              Gitleaks · Checkov          (schéma        (FastAPI  (Next.js)
              · Semgrep                    unifié)      + Postgres)
```

---

## 0:40 — 1:20 · Le projet scanné

**Onglet 1** — `atlas-pay`, une plateforme de paiement.

> « Voici une application réaliste : une API Flask, son infrastructure
> Terraform, trois branches — `main`, `develop`, et une branche de
> fonctionnalité en cours. »

- Montrer l'arborescence : `src/`, `infra/`, `config/`, `tests/`
- Cliquer sur le sélecteur de branches → les 3 branches
- Ouvrir `infra/storage.tf` → *« un bucket S3 en `public-read` »*
- Ouvrir `config/settings.py` → *« un mot de passe de base et des clés d'API en dur »*

---

## 1:20 — 2:00 · Le déclenchement

**Onglet 2** — Actions.

> « À chaque push, et sur chaque pull request, ce workflow se déclenche. »

- Montrer le fichier `.github/workflows/scan.yml`
- Pointer les 3 étapes de scan, puis l'étape d'agrégation
- Montrer le dernier run vert/rouge et sa durée (~1 min)

> « Il lance les trois scanners, normalise leurs formats — chacun produit
> un JSON différent — et envoie le tout à l'API. »

---

## 2:00 — 3:30 · Les résultats (le cœur de la démo)

**Onglet 4** — `localhost:3000`.

Tableau de bord :
> « 87 problèmes détectés sur ce dépôt : 6 secrets exposés, 9 failles de
> code, 72 erreurs de configuration. Score de conformité : 0 sur 100. »

Aller sur **Alertes**, filtrer par gravité **critique** :

| Fichier | Problème |
|---|---|
| `config/settings.py:12` | mot de passe de la base en clair |
| `config/settings.py:15` | clé de signature JWT en dur |
| `infra/main.tf:12` | clé secrète AWS |
| `src/payments.py:13` | clé Stripe *(dans une autre branche !)* |

> « Gitleaks remonte même un secret présent dans une **branche de
> fonctionnalité**, pas encore fusionnée. »

**Cliquer sur un finding** → panneau de détail :
- l'emplacement exact (fichier + ligne)
- l'explication : pourquoi c'est un risque, ce qu'un attaquant peut en faire
- la remédiation
- le lien vers la ligne sur GitHub

Filtrer sur **élevée** → montrer les failles Semgrep :
`src/auth.py:26` injection SQL · `src/utils.py:14` injection de commande ·
`src/auth.py:40` signature JWT non vérifiée

---

## 3:30 — 4:40 · Le blocage (le moment fort)

**Onglet 3** — la pull request #1.

> « Un développeur veut fusionner l'intégration Stripe dans `main`. »

- Montrer le diff : `src/payments.py`
- Descendre jusqu'aux checks :

```
scan — Failing after 1m
   Required status check "scan" is failing.
```

- **Le bouton « Merge pull request » est grisé.**

> « La fusion est refusée. Le projet est configuré pour bloquer dès qu'un
> problème de gravité `high` ou pire est détecté — ici une injection SQL et
> une clé Stripe en dur. Même un administrateur ne peut pas passer outre :
> l'option `enforce_admins` est active. »

Montrer côté dashboard (Paramètres du projet) que le seuil `high` vient
d'iac-guard, pas de GitHub — **c'est la politique du projet qui décide**.

---

## 4:40 — 5:00 · Conclusion

> « En résumé : trois scanners complémentaires, un schéma unifié, un
> tableau de bord centralisé, et surtout une **barrière automatique** qui
> empêche le code dangereux d'atteindre la production.
>
> La suite : le moteur de conformité, qui traduira ces résultats
> techniques en articles de la loi 09-08 de la CNDP. »

---

## Rattrapages si ça casse en direct

| Symptôme | Cause | Réponse |
|---|---|---|
| Le run échoue en 10 s, « API injoignable » | l'URL du tunnel a changé | Ne pas relancer à l'écran : montrer un run précédent réussi |
| Le dashboard est vide | session expirée | Se reconnecter avant d'enregistrer |
| `docker compose ps` vide | Docker Desktop a redémarré | `docker compose up -d` puis relancer le tunnel |

**Ne jamais relancer un scan en direct** : 1 minute d'attente à l'écran est
mortelle sur une vidéo de 5 minutes. Tout est déjà scanné.
