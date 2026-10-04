# 2. GitLab : groupe, projet, membres, protections

## 2.1 Groupe et projet
1. **Menu → Groups → Create group → Create group** : nom `devsecops-network`, visibilité **Private**.
2. Dans le groupe : **New project → Create blank project** : `network-security`, **sans** README (vous pousserez le contenu de ce dépôt).
3. Première publication depuis la VM :
```bash
cd network-security
git init -b main && git add . && git commit -m "feat: version initiale du pipeline DevSecOps réseau"
git remote add origin git@gitlab.com:devsecops-network/network-security.git
git push -u origin main
```
(Ajouter votre clé publique dans *User settings → SSH Keys* au préalable.)

## 2.2 Inviter les membres
Groupe → **Manage → Members → Invite members** → email ou identifiant → rôle → (date d'expiration) → *Invite*.

| Rôle | Pour qui | Droits utiles |
|---|---|---|
| Owner | Vous | Tout |
| Maintainer | Co-responsable | Merge sur `main`, variables CI, runners |
| Developer | Développeurs | Branches, merge requests, lancement des pipelines |
| Reporter | Encadrant / jury | Lecture du code, des pipelines, des artefacts, des tickets |

## 2.3 Protéger la branche principale (c'est ce qui matérialise le blocage)
* *Settings → Repository → Protected branches* → `main` : **Allowed to push = No one**, **Allowed to merge = Maintainers**.
* *Settings → Merge requests* : cocher **Pipelines must succeed** (une MR dont le pipeline échoue ne peut pas être fusionnée).
* Optionnel : *Squash commits*, et exiger une approbation (selon l'offre GitLab, cette fonction peut être payante).

## 2.4 Variables et jeton (Settings → CI/CD → Variables, cocher *Mask variable*)
| Variable | Usage |
|---|---|
| `SLACK_WEBHOOK_URL` | Slack → *Incoming Webhooks* (ou Discord/Mattermost compatibles) |
| `GITLAB_API_TOKEN` | *Settings → Access tokens* : jeton de projet, rôle Developer, portée `api` → crée le ticket d'incident |

Ne jamais mettre de jeton dans le dépôt. Les secrets des équipements sont des références `${VARIABLE}` résolues hors dépôt.

## 2.5 Workflow de l'équipe
1. `git switch -c feature/ssh-hardening` → modifier `configs/` → `git commit` (message explicite) → `git push`.
2. Ouvrir une **Merge Request** vers `main` : le pipeline s'exécute (étapes 1 à 4, sans déploiement).
3. Pipeline vert → un Maintainer fusionne → le pipeline sur `main` **déploie** dans le lab.
4. Pipeline rouge → *Merge* grisé, Slack alerté, ticket `security/incident` ouvert avec le rapport.

Traçabilité (BF7) : *qui* = auteur du commit, *quoi* = diff de la MR, *règle affectée* = rapport du pipeline, *accepté/rejeté* = statut du pipeline et de la MR.
Labels conseillés : `security`, `incident`, `network`.

## 2.6 Répartition possible à plusieurs (BNF7 demande un projet défendable individuellement : chacun doit connaître l'ensemble)
| Développeur | Périmètre |
|---|---|
| A | Politique de sécurité, `security_check.py`, tests de règles |
| B | `.gitlab-ci.yml`, runner, lab Docker, déploiement, notifications |
| C | Couche ML, rapports ISO, documentation |
