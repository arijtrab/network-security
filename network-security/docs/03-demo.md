# 3. Démonstration : deux scénarios

## 3.0 En local (avant de passer par GitLab)
```bash
make demo-good   # ✓ ... PIPELINE: PASSED — DEPLOYMENT: ALLOWED
make demo-bad    # ✗ SSH accessible from 0.0.0.0/0, ✗ Telnet is enabled → PIPELINE: FAILED — DEPLOYMENT: BLOCKED
```
Le rapport complet est écrit dans `/tmp/tmp.XXXX/report.md` (chemin affiché).

## 3.1 Scénario 1 : modification sécurisée (via GitLab)
```bash
git switch -c demo/secure
# modification inoffensive : ajouter dans configs/firewall01.yml une règle  {id: 50, action: allow, src: users, dst: servers, port: 80, proto: tcp}
git commit -am "feat(firewall): autoriser HTTP interne" && git push -u origin demo/secure
```
Ouvrir la MR : yamllint ✓ · syntax-check ✓ · unit-tests ✓ · security-scan ✓ · compliance-check ✓ · network-policy-check ✓ → *Merge* disponible. Après fusion, `deploy-lab` s'exécute sur `main`.

## 3.2 Scénario 2 : vulnérabilité volontaire
```bash
git switch main && git pull && git switch -c demo/vulnerable
cp demo/vulnerable/firewall01.yml configs/firewall01.yml
git commit -am "chore: ouverture SSH (test)" && git push -u origin demo/vulnerable
```
Résultat attendu : `compliance-check` rouge → `network-policy-check` et `deploy-lab` **non exécutés** → *Merge* bloqué ; l'artefact `report.md` détaille la règle, le fichier, la gravité, la raison, la recommandation et le contrôle ISO ; Slack et un ticket sont créés si les variables sont définies.

Pour une démonstration plus riche : copier `demo/vulnerable-full/*.yml` dans `configs/` (27 constats).

## 3.3 Vérifier le lab Docker
```bash
make lab-up
# après un déploiement réussi sur main :
docker exec lab-firewall01 cat /etc/netconfig/firewall01.yml
```
Sans conteneurs, le déploiement écrit dans `lab/deployed/` et vérifie l'empreinte SHA-256.

## 3.4 Critères de réussite du cahier des charges : où le montrer
| Critère | Preuve |
|---|---|
| Configs versionnées | Historique Git |
| Pipeline déclenché automatiquement | Onglet *Pipelines* |
| Violations détectées / pipeline en échec | Scénario 2 |
| Configuration conforme poursuit | Scénario 1 |
| Résultats consultables | Artefacts `report.md`, `report.json` |
| Tests reproductibles | `pytest` (`test_scan_is_reproducible`) et relance du pipeline |
