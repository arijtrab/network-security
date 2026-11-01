#!/usr/bin/env bash
# Rejoue le pipeline en local sur un dossier de configurations.
# Usage : ./run_local.sh [dossier]   (défaut : configs/)   ex. ./run_local.sh demo/vulnerable
set -u
DIR="${1:-configs}"
OUT="$(mktemp -d)"
step() { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }
fail() { printf '\n\033[1;31m✗ PIPELINE: FAILED — DEPLOYMENT: BLOCKED\033[0m\n'; python ml/classify.py --report "$OUT/report.json" --verdict "$OUT/verdict.json" --network "$OUT/network_tests.json" --out-md "$OUT/report.md" --out-json "$OUT/report_enriched.json" >/dev/null 2>&1; python scripts/notify.py --report "$OUT/report.json" --verdict "$OUT/verdict.json" --dry-run; echo "Rapport : $OUT/report.md"; exit 1; }

step "1/5 Validation syntaxique";  yamllint -c .yamllint "$DIR" policies/ && python scripts/validate.py --configs "$DIR" || fail
step "2/5 Audit de sécurité";      python scripts/security_check.py --configs "$DIR" --out "$OUT/report.json" || fail
step "3/5 Conformité (décision)";  python scripts/compliance.py --report "$OUT/report.json" --out "$OUT/verdict.json" || fail
step "4/5 Tests réseau";           python scripts/flow_test.py --configs "$DIR" --out "$OUT/network_tests.json" || fail
step "5/5 Déploiement (lab)";      python scripts/deploy.py --configs "$DIR" --verdict "$OUT/verdict.json" --out "$OUT/deployment.json" || fail
python ml/classify.py --report "$OUT/report.json" --verdict "$OUT/verdict.json" --network "$OUT/network_tests.json" --out-md "$OUT/report.md" --out-json "$OUT/report_enriched.json"
printf '\n\033[1;32m✓ PIPELINE: PASSED — DEPLOYMENT: ALLOWED\033[0m\nRapport : %s/report.md\n' "$OUT"
