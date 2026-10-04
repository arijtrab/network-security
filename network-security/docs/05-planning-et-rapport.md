# 5. Planning et plan du rapport final

## 5.1 Planning (3 semaines, cf. cahier des charges)
| Étape | Livrable | Fait quand… |
|---|---|---|
| S1-J1 | VM + VS Code + runner | `make test` passe sur la VM |
| S1-J2 | Groupe GitLab, membres, `main` protégée | Push direct refusé, MR bloquée si pipeline rouge |
| S1-J3/4 | Politique, configs, schéma | `make demo-good` PASSED |
| S2 | Règles, scripts, tests, CI | Chaque règle a son test ; pipeline vert/rouge dans GitLab |
| S2 fin | Lab, déploiement, Slack, ticket | Fichier présent dans le conteneur ; message Slack reçu |
| S3-J1/2 | Couche ML, rapport ISO | `report.md` complet en artefact |
| S3-J3/4 | Scénarios, captures, reproductibilité | Deux démonstrations rejouables |
| S3-J5 | Rapport et soutenance | Relu |

Si le temps manque, couper dans cet ordre : ML → ticket d'incident → tests réseau.

## 5.2 Plan du rapport final (livrable 6)
1. Contexte, problématique, objectifs
2. Architecture (schéma mermaid, flux, lab) et choix technologiques justifiés (tableau 4.4)
3. Implémentation : politique, moteur de règles, pipeline, déploiement, notifications
4. Couche ML : données, modèle, évaluation, limites
5. Tests et résultats : 37 tests, scénarios 1 et 2, captures de pipelines, reproductibilité
6. Limites (formats, simulation, jeu de données ML) et perspectives
Annexes : politique complète, exemple de `report.md`, `.gitlab-ci.yml`
