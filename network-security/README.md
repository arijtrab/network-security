# Network-as-Code DevSecOps : audit et durcissement automatisés des configurations réseau

Les configurations réseau sont du **code** : versionnées dans GitLab, contrôlées par un pipeline CI/CD
qui **bloque** tout déploiement non conforme et produit un rapport d'audit rattaché à **ISO/IEC 27001:2022**.

```
Admin → Merge Request → GitLab CI
   1 Validation (yamllint + schéma JSON)   ──┐
   2 Audit de sécurité (19 règles)           │ un job en échec
   3 Conformité = DÉCISION PASS / FAIL       │ bloque les suivants
   4 Tests réseau (simulation de flux)       │
   5 Déploiement → lab Docker (main seul)  ──┘
   6 Rapport (ML + gabarit) + Slack + ticket GitLab  (toujours exécuté)
```

Tout tourne sur **une seule VM Linux** (aucun GNS3) : les « équipements » du lab sont 3 conteneurs Alpine.

## Démarrage rapide (sur la VM)
```bash
make install && source .venv/bin/activate
make test          # 37 tests
make demo-good     # scénario 1 : configuration conforme  → PASSED / ALLOWED
make demo-bad      # scénario 2 : SSH 0.0.0.0/0 + Telnet  → FAILED / BLOCKED
make demo-full     # configuration très vulnérable (27 constats)
make lab-up        # optionnel : conteneurs du lab (le déploiement les détecte seul)
```

## Contenu
| Dossier | Rôle |
|---|---|
| `configs/` | Configurations conformes (router01, firewall01, switch01) |
| `policies/` | `security-policy.yml` (règles, gravités, ISO, décision) et `network-tests.yml` (flux attendus) |
| `schemas/` | Schéma JSON des configurations |
| `scripts/` | `validate`, `security_check`, `compliance`, `flow_test`, `deploy`, `notify` |
| `ml/` | Jeu de données, entraînement, classifieur ISO/gravité, gabarit de rapport |
| `lab/` | `docker-compose.yml` du lab simulé |
| `tests/` | 37 tests pytest (une mutation par règle, décision, reproductibilité, garde-fous) |
| `demo/` | `secure/`, `vulnerable/` (scénario 2 du cahier des charges), `vulnerable-full/` |
| `docs/` | Guides pas à pas : environnement, GitLab, démo, architecture, planning |

## Ajouter une règle (sans toucher au code)
Ajouter un bloc dans `policies/security-policy.yml` avec un des types : `forbidden_value`, `required_value`,
`ssh_sources`, `any_any`, `dangerous_ports`, `source_restriction`, `sensitive_zone_access`, `plaintext_secrets`.
Ajouter un test dans `tests/test_rules.py` (dictionnaire `MUTATIONS`). Un nouveau *type* de contrôle = une fonction
dans `scripts/security_check.py` + une entrée dans `CHECKS`.

## Garanties
* **Décision déterministe** : le ML n'intervient jamais dans PASS/FAIL (BNF3). Deux scans identiques donnent la même empreinte SHA-256.
* **Intégrité** : `deploy.py` refuse si le verdict n'est pas PASSED ou si les fichiers ont changé depuis l'audit.
* **Anti-contournement** : si une règle obligatoire disparaît de la politique, le pipeline est bloqué.
* **Secrets** : les valeurs détectées ne sont jamais recopiées dans les rapports.

## Limites assumées
* Formats : YAML maison (pas de configuration Cisco/Juniper native). Les tests réseau simulent les règles, ils ne remplacent pas Batfish.
* Le déploiement vers Docker et les notifications Slack/GitLab n'ont pas pu être testés dans l'environnement de génération (pas de Docker ni de jetons) : le mode local de `deploy.py` et le mode `--dry-run` de `notify.py` le sont. À valider sur votre VM (voir `docs/03-demo.md`).
* Le modèle ML s'entraîne sur un jeu **synthétique** de 960 lignes : voir `docs/04-architecture.md`.
