#!/usr/bin/env python3
"""Étape 2 : validation syntaxique (YAML + schéma JSON + cohérence). Exit 1 si invalide."""
import argparse
import sys

import yaml
from jsonschema import Draft7Validator

from common import ROOT, SEVERITIES, list_configs, load_json, load_yaml, parse_net
from security_check import CHECKS


def validate_config(path, schema):
    errors = []
    try:
        cfg = load_yaml(path)
    except yaml.YAMLError as e:
        return [f"YAML invalide : {str(e).splitlines()[0]}"]
    if not isinstance(cfg, dict):
        return ["le fichier doit contenir un objet YAML"]
    for e in sorted(Draft7Validator(schema).iter_errors(cfg), key=lambda e: list(e.path)):
        loc = ".".join(str(p) for p in e.path) or "(racine)"
        errors.append(f"schéma : {loc} : {e.message}")
    if errors:
        return errors
    if cfg["device"] != path.stem:
        errors.append(f"le champ device ('{cfg['device']}') doit correspondre au nom du fichier ('{path.stem}')")
    ids = [r["id"] for r in cfg.get("rules", [])]
    if len(ids) != len(set(ids)):
        errors.append("identifiants de règles dupliqués")
    zones = cfg.get("zones", {})
    tokens = list(cfg.get("management", {}).get("ssh", {}).get("allowed_sources", []))
    for r in cfg.get("rules", []):
        tokens += [r["src"], r["dst"]]
    tokens += [z["cidr"] for z in zones.values()]
    for t in tokens:
        try:
            parse_net(t, zones)
        except ValueError:
            errors.append(f"adresse, réseau ou zone inconnue : '{t}'")
    return errors


def validate_policy(path):
    errors, pol = [], load_yaml(path)
    seen = set()
    for r in pol.get("rules", []):
        rid = r.get("id", "?")
        if rid in seen:
            errors.append(f"politique : règle dupliquée {rid}")
        seen.add(rid)
        if r.get("severity") not in SEVERITIES:
            errors.append(f"politique : {rid} : gravité invalide")
        if r.get("check", {}).get("type") not in CHECKS:
            errors.append(f"politique : {rid} : type de contrôle inconnu")
        if not r.get("recommendation"):
            errors.append(f"politique : {rid} : recommandation manquante")
    for m in pol.get("decision", {}).get("mandatory_rules", []):
        if m not in seen:
            errors.append(f"politique : règle obligatoire inconnue {m}")
    return errors


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--configs", default=str(ROOT / "configs"))
    ap.add_argument("--policy", default=str(ROOT / "policies" / "security-policy.yml"))
    ap.add_argument("--schema", default=str(ROOT / "schemas" / "device.schema.json"))
    a = ap.parse_args()
    schema, failed = load_json(a.schema), False
    files = list_configs(a.configs)
    if not files:
        print(f"✗ aucune configuration trouvée dans {a.configs}")
        return 1
    for p in files:
        errs = validate_config(p, schema)
        print(f"{'✗' if errs else '✓'} {p.name}")
        for e in errs:
            print(f"    - {e}")
        failed |= bool(errs)
    perrs = validate_policy(a.policy)
    print(f"{'✗' if perrs else '✓'} {a.policy.split('/')[-1]}")
    for e in perrs:
        print(f"    - {e}")
    failed |= bool(perrs)
    print("SYNTAX CHECK:", "FAILED — Deployment: BLOCKED" if failed else "PASSED")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
