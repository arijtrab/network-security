"""Tests de bout en bout : validation, décision, reproductibilité, tests réseau, garde-fou de déploiement."""
import json
import pathlib
import shutil

import pytest

from common import ROOT, configs_digest, load_json, load_yaml
from compliance import decide
from deploy import main as deploy_main
from flow_test import run as run_flows
from security_check import scan
from validate import validate_config, validate_policy

POLICY = ROOT / "policies" / "security-policy.yml"
TESTS = ROOT / "policies" / "network-tests.yml"
SCHEMA = load_json(ROOT / "schemas" / "device.schema.json")


def verdict_for(directory):
    return decide(scan(directory, POLICY), load_yaml(POLICY))


# ---- BF2 : validation syntaxique ------------------------------------------
def test_valid_configs_pass_validation():
    for p in (ROOT / "configs").glob("*.yml"):
        assert validate_config(p, SCHEMA) == [], p.name
    assert validate_policy(POLICY) == []


def test_broken_yaml_fails(tmp_path):
    f = tmp_path / "router01.yml"
    f.write_text("device: router01\n  type: [oops\n")
    assert any("YAML invalide" in e for e in validate_config(f, SCHEMA))


def test_missing_field_fails(tmp_path):
    f = tmp_path / "router01.yml"
    f.write_text("device: router01\ntype: router\n")
    assert validate_config(f, SCHEMA)


def test_invalid_cidr_fails(tmp_path):
    shutil.copy(ROOT / "configs" / "router01.yml", tmp_path / "router01.yml")
    text = (tmp_path / "router01.yml").read_text().replace("192.168.10.0/24\"]", "300.1.1.0/24\"]", 1)
    (tmp_path / "router01.yml").write_text(text)
    assert any("inconnu" in e for e in validate_config(tmp_path / "router01.yml", SCHEMA))


# ---- BF5 : décision automatique -------------------------------------------
def test_secure_config_is_allowed():
    v = verdict_for(ROOT / "configs")
    assert (v["verdict"], v["deployment"], v["blocking"]) == ("PASSED", "ALLOWED", 0)


def test_scenario2_is_blocked_with_expected_findings():
    report = scan(ROOT / "demo" / "vulnerable", POLICY)
    ids = {f["rule_id"] for f in report["findings"]}
    assert ids == {"NET-001", "NET-004"}
    assert decide(report, load_yaml(POLICY))["deployment"] == "BLOCKED"


def test_full_vulnerable_demo_is_blocked():
    assert verdict_for(ROOT / "demo" / "vulnerable-full")["deployment"] == "BLOCKED"


def test_removing_mandatory_rule_blocks(tmp_path):
    pol = load_yaml(POLICY)
    pol["rules"] = [r for r in pol["rules"] if r["id"] != "NET-004"]
    p = tmp_path / "policy.yml"
    import yaml
    p.write_text(yaml.safe_dump(pol))
    v = decide(scan(ROOT / "configs", p), pol)
    assert v["deployment"] == "BLOCKED" and v["missing_mandatory_rules"] == ["NET-004"]


def test_low_severity_only_warns(firewall, tmp_path):
    firewall["logging"].pop("server")
    import yaml
    for name in ("firewall01", "router01", "switch01"):
        shutil.copy(ROOT / "configs" / f"{name}.yml", tmp_path / f"{name}.yml")
    (tmp_path / "firewall01.yml").write_text(yaml.safe_dump(firewall))
    v = verdict_for(tmp_path)
    assert v["deployment"] == "ALLOWED" and v["warnings"] == 1


# ---- BNF3 : reproductibilité ----------------------------------------------
def test_scan_is_reproducible():
    a, b = scan(ROOT / "demo" / "vulnerable-full", POLICY), scan(ROOT / "demo" / "vulnerable-full", POLICY)
    assert a["meta"]["findings_sha256"] == b["meta"]["findings_sha256"]
    assert a["findings"] == b["findings"]


# ---- Étape 5 : tests réseau ------------------------------------------------
def test_flows_pass_on_secure_config():
    assert all(r["ok"] for r in run_flows(ROOT / "configs", TESTS))


def test_flows_fail_on_vulnerable_config():
    assert not all(r["ok"] for r in run_flows(ROOT / "demo" / "vulnerable-full", TESTS))


# ---- BNF1 : le déploiement refuse une config non auditée ou non conforme ---
def _run_deploy(configs, verdict_path, local_dir, tmp_path):
    import sys
    argv = sys.argv
    sys.argv = ["deploy.py", "--configs", str(configs), "--verdict", str(verdict_path),
                "--mode", "local", "--local-dir", str(local_dir), "--out", str(tmp_path / "d.json")]
    try:
        return deploy_main()
    finally:
        sys.argv = argv


def _write_verdict(directory, tmp_path):
    v = verdict_for(directory)
    path = tmp_path / "verdict.json"
    path.write_text(json.dumps(v))
    return path


def test_deploy_ok_when_allowed(tmp_path):
    vp = _write_verdict(ROOT / "configs", tmp_path)
    assert _run_deploy(ROOT / "configs", vp, tmp_path / "lab", tmp_path) == 0
    assert (tmp_path / "lab" / "firewall01.yml").exists()


def test_deploy_refused_when_blocked(tmp_path):
    vp = _write_verdict(ROOT / "demo" / "vulnerable", tmp_path)
    assert _run_deploy(ROOT / "demo" / "vulnerable", vp, tmp_path / "lab", tmp_path) == 1
    assert not (tmp_path / "lab").exists()


def test_deploy_refused_if_configs_changed_after_audit(tmp_path):
    work = tmp_path / "cfg"
    shutil.copytree(ROOT / "configs", work)
    vp = _write_verdict(work, tmp_path)
    (work / "firewall01.yml").write_text((work / "firewall01.yml").read_text() + "# modif\n")
    assert configs_digest(work) != load_json(vp)["configs_sha256"]
    assert _run_deploy(work, vp, tmp_path / "lab", tmp_path) == 1
