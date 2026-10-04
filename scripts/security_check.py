#!/usr/bin/env python3
"""Étape 3 : audit de sécurité. Applique les règles de policies/security-policy.yml
aux configurations et produit report.json. Ne décide pas (c'est le rôle de compliance.py)."""
import argparse
import datetime
import hashlib
import json
import re
import sys

from common import (ROOT, SEV_RANK, ci_context, configs_digest, get_path, list_configs, load_yaml,
                    parse_net, port_range, same_value, save_json)

SECRET_KEY = re.compile(r"(password|passwd|secret|community|token|api_key|private_key)", re.I)
SECRET_REF = re.compile(r"^(\$\{[A-Z][A-Z0-9_]*\}|vault:.+)$")


def _v(location, detail):
    return {"location": location, "detail": detail}


def _when_ok(cfg, p):
    if "when" not in p:
        return True
    ok, val = get_path(cfg, p["when"])
    return ok and bool(val)


def _allow_rules(cfg):
    return [r for r in cfg.get("rules", []) if r.get("action") == "allow"]


def _loc(r):
    return f"rules[id={r['id']}]"


def check_forbidden_value(cfg, p):
    if not _when_ok(cfg, p):
        return []
    ok, val = get_path(cfg, p["path"])
    if ok and any(same_value(val, f) for f in p["forbidden"]):
        return [_v(p["path"], p.get("message", f"Forbidden value at {p['path']}"))]
    return []


def check_required_value(cfg, p):
    if not _when_ok(cfg, p):
        return []
    ok, val = get_path(cfg, p["path"])
    msg = p.get("message", f"Missing or invalid {p['path']}")
    if "equals" in p and not (ok and same_value(val, p["equals"])):
        return [_v(p["path"], msg)]
    if p.get("exists") and (not ok or val in (None, "", [])):
        return [_v(p["path"], msg)]
    return []


def check_ssh_sources(cfg, p):
    ssh = cfg.get("management", {}).get("ssh", {})
    if not ssh.get("enabled"):
        return []
    sources = ssh.get("allowed_sources")
    loc = "management.ssh.allowed_sources"
    if p["mode"] == "missing":
        return [] if sources else [_v(loc, "SSH enabled without source address restriction")]
    out = []
    for s in sources or []:
        net = parse_net(s, cfg.get("zones"))
        if p["mode"] == "any" and net.prefixlen == 0:
            out.append(_v(loc, f"SSH accessible from {net}"))
        elif p["mode"] == "wide" and 0 < net.prefixlen < p["min_prefix"]:
            out.append(_v(loc, f"SSH accessible from a wide network ({net})"))
    return out


def check_any_any(cfg, p):
    zones = cfg.get("zones")
    return [_v(_loc(r), f"Allow rule ANY -> ANY ({r.get('description', 'no description')})")
            for r in _allow_rules(cfg)
            if parse_net(r["src"], zones).prefixlen == 0 and parse_net(r["dst"], zones).prefixlen == 0]


def check_dangerous_ports(cfg, p):
    zones, out = cfg.get("zones"), []
    for r in _allow_rules(cfg):
        src = parse_net(r["src"], zones)
        if src.prefixlen >= p["max_broad_prefix"]:
            continue
        lo, hi = port_range(r.get("port"))
        if (lo, hi) == (0, 65535):
            out.append(_v(_loc(r), f"All ports open from {src}"))
            continue
        exposed = [x for x in p["ports"] if lo <= x <= hi]
        if exposed:
            out.append(_v(_loc(r), f"Dangerous port(s) {exposed} open from {src}"))
    return out


def check_source_restriction(cfg, p):
    zones, out = cfg.get("zones"), []
    for r in _allow_rules(cfg):
        if parse_net(r["src"], zones).prefixlen != 0:
            continue
        lo, hi = port_range(r.get("port"))
        if not (lo == hi and lo in p["public_ports"]):
            out.append(_v(_loc(r), f"Allow rule with unrestricted source (port {r.get('port', 'any')})"))
    return out


def check_sensitive_zone_access(cfg, p):
    zones = cfg.get("zones", {})
    sensitive = {n: parse_net(n, zones) for n, z in zones.items() if z.get("sensitive")}
    out = []
    for r in _allow_rules(cfg):
        src, dst = parse_net(r["src"], zones), parse_net(r["dst"], zones)
        if src.prefixlen >= p["max_broad_prefix"]:
            continue
        for name, net in sensitive.items():
            if dst.overlaps(net):
                out.append(_v(_loc(r), f"Broad source {src} can reach sensitive zone '{name}'"))
    return out


def check_plaintext_secrets(cfg, p):
    out = []

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                walk_item(k, v, f"{path}.{k}" if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    def walk_item(key, value, path):
        if isinstance(value, (dict, list)):
            walk(value, path)
        elif isinstance(value, str) and SECRET_KEY.search(str(key)) and not SECRET_REF.match(value):
            out.append(_v(path, f"Secret stored in clear text at {path}"))  # la valeur n'est jamais recopiée

    walk(cfg, "")
    return out


CHECKS = {
    "forbidden_value": check_forbidden_value,
    "required_value": check_required_value,
    "ssh_sources": check_ssh_sources,
    "any_any": check_any_any,
    "dangerous_ports": check_dangerous_ports,
    "source_restriction": check_source_restriction,
    "sensitive_zone_access": check_sensitive_zone_access,
    "plaintext_secrets": check_plaintext_secrets,
}


def scan(configs_dir, policy_path):
    policy = load_yaml(policy_path)
    findings, devices, evaluated = [], [], set()
    for path in list_configs(configs_dir):
        cfg = load_yaml(path)
        devices.append(cfg["device"])
        for rule in policy["rules"]:
            if "applies_to" in rule and cfg["type"] not in rule["applies_to"]:
                continue
            evaluated.add(rule["id"])
            for v in CHECKS[rule["check"]["type"]](cfg, rule["check"]):
                findings.append({
                    "rule_id": rule["id"], "title": rule["title"], "severity": rule["severity"],
                    "device": cfg["device"], "file": path.name, "location": v["location"],
                    "detail": v["detail"], "recommendation": rule["recommendation"], "iso": rule.get("iso"),
                })
    findings.sort(key=lambda f: (-SEV_RANK[f["severity"]], f["device"], f["rule_id"], f["location"]))
    digest = hashlib.sha256(json.dumps(findings, sort_keys=True).encode()).hexdigest()
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_RANK}
    return {
        "meta": {"generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                 "policy_version": policy.get("version"), "configs_sha256": configs_digest(configs_dir),
                 "findings_sha256": digest, **ci_context()},
        "devices": devices, "rules_evaluated": sorted(evaluated),
        "summary": {"total": len(findings), **counts}, "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--configs", default=str(ROOT / "configs"))
    ap.add_argument("--policy", default=str(ROOT / "policies" / "security-policy.yml"))
    ap.add_argument("--out", default="report.json")
    a = ap.parse_args()
    report = scan(a.configs, a.policy)
    save_json(a.out, report)
    print("SECURITY SCAN")
    for f in report["findings"]:
        print(f"  [{f['severity']}] {f['device']} · {f['rule_id']} · {f['detail']} ({f['location']})")
    if not report["findings"]:
        print("  (aucune violation détectée)")
    s = report["summary"]
    print(f"\n{len(report['devices'])} équipement(s), {len(report['rules_evaluated'])} règle(s), "
          f"{s['total']} constat(s) : {s['CRITICAL']} critique(s), {s['HIGH']} élevé(s), "
          f"{s['MEDIUM']} moyen(s), {s['LOW']} faible(s)")
    print(f"Rapport écrit dans {a.out}")


if __name__ == "__main__":
    sys.exit(main())
