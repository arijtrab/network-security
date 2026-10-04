#!/usr/bin/env python3
"""Étapes 4 et 6 : contrôle de conformité et décision automatique (exit 1 = déploiement bloqué)."""
import argparse
import sys

from common import ROOT, load_json, load_yaml, save_json


def decide(report, policy):
    dec = policy.get("decision", {})
    blocking_sev = set(dec.get("blocking_severities", ["CRITICAL", "HIGH"]))
    blocking = [f for f in report["findings"] if f["severity"] in blocking_sev]
    warnings = [f for f in report["findings"] if f["severity"] not in blocking_sev]
    missing = sorted(set(dec.get("mandatory_rules", [])) - set(report["rules_evaluated"]))
    blocked = bool(blocking or missing)
    return {
        "verdict": "FAILED" if blocked else "PASSED",
        "deployment": "BLOCKED" if blocked else "ALLOWED",
        "blocking": len(blocking), "warnings": len(warnings),
        "missing_mandatory_rules": missing,
        "configs_sha256": report["meta"]["configs_sha256"],
        "findings_sha256": report["meta"]["findings_sha256"],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", default="report.json")
    ap.add_argument("--policy", default=str(ROOT / "policies" / "security-policy.yml"))
    ap.add_argument("--out", default="verdict.json")
    a = ap.parse_args()
    report, policy = load_json(a.report), load_yaml(a.policy)
    verdict = decide(report, policy)
    save_json(a.out, verdict)
    blocking_sev = set(policy["decision"]["blocking_severities"])
    print(f"COMPLIANCE CHECK (politique v{policy['version']})")
    for f in report["findings"]:
        mark = "✗" if f["severity"] in blocking_sev else "!"
        print(f"  {mark} [{f['severity']}] {f['device']} · {f['rule_id']} · {f['detail']} ({f['location']})")
    for m in verdict["missing_mandatory_rules"]:
        print(f"  ✗ [CRITICAL] règle obligatoire {m} non évaluée (politique modifiée ?)")
    if not report["findings"]:
        print("  ✓ aucune violation")
    print(f"\nSECURITY POLICY: {verdict['verdict']} — DEPLOYMENT: {verdict['deployment']} "
          f"({verdict['blocking']} bloquant(s), {verdict['warnings']} avertissement(s))")
    return 0 if verdict["verdict"] == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
