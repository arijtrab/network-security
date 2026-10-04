#!/usr/bin/env python3
"""Étape 5 : tests réseau. Simule l'évaluation des règles (première correspondance, deny par défaut)
pour vérifier des propriétés de connectivité attendues. Remplace Batfish dans la version de base."""
import argparse
import ipaddress
import sys

from common import ROOT, list_configs, load_yaml, parse_net, port_range, save_json


def decide(cfg, flow):
    zones = cfg.get("zones", {})
    sip, dip = ipaddress.ip_address(flow["src_ip"]), ipaddress.ip_address(flow["dst_ip"])
    for r in cfg.get("rules", []):
        proto_ok = r.get("proto", "any") in ("any", flow.get("proto", "tcp"))
        lo, hi = port_range(r.get("port"))
        if (sip in parse_net(r["src"], zones) and dip in parse_net(r["dst"], zones)
                and proto_ok and lo <= flow["port"] <= hi):
            return r["action"], r["id"]
    return cfg.get("default_policy", "deny"), "default"


def run(configs_dir, tests_path):
    cfgs = {c["device"]: c for c in (load_yaml(p) for p in list_configs(configs_dir))}
    results = []
    for fl in load_yaml(tests_path)["flows"]:
        if fl["device"] not in cfgs:
            results.append({**fl, "actual": "n/a", "rule": None, "ok": False})
            continue
        actual, rule = decide(cfgs[fl["device"]], fl)
        results.append({**fl, "actual": actual, "rule": rule, "ok": actual == fl["expect"]})
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--configs", default=str(ROOT / "configs"))
    ap.add_argument("--tests", default=str(ROOT / "policies" / "network-tests.yml"))
    ap.add_argument("--out", default="network_tests.json")
    a = ap.parse_args()
    results = run(a.configs, a.tests)
    save_json(a.out, results)
    print("NETWORK POLICY CHECK")
    for r in results:
        print(f"  {'✓' if r['ok'] else '✗'} {r['name']} : attendu={r['expect']} obtenu={r['actual']} (règle {r['rule']})")
    ok = all(r["ok"] for r in results)
    print("NETWORK POLICY:", "PASSED" if ok else "FAILED — Deployment: BLOCKED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
