"""Un test par règle : la config conforme ne déclenche rien, la config mutée déclenche la bonne règle."""
import pytest

from security_check import CHECKS


def run(rule_id, cfg, policy):
    rule = next(r for r in policy["rules"] if r["id"] == rule_id)
    if "applies_to" in rule and cfg["type"] not in rule["applies_to"]:
        return []
    return CHECKS[rule["check"]["type"]](cfg, rule["check"])


def test_baseline_has_no_finding(firewall, switch, policy):
    for cfg in (firewall, switch):
        for rule in policy["rules"]:
            assert run(rule["id"], cfg, policy) == [], rule["id"]


MUTATIONS = {
    "NET-001": lambda c: c["management"]["telnet"].update(enabled=True),
    "NET-002": lambda c: c["management"]["ftp"].update(enabled=True),
    "NET-003": lambda c: c["management"]["http_admin"].update(enabled=True),
    "NET-004": lambda c: c["management"]["ssh"].update(allowed_sources=["0.0.0.0/0"]),
    "NET-005": lambda c: c["management"]["ssh"].update(allowed_sources=[]),
    "NET-006": lambda c: c["management"]["ssh"].update(allowed_sources=["10.0.0.0/8"]),
    "NET-007": lambda c: c["management"]["ssh"].update(version=1),
    "NET-008": lambda c: c["rules"].insert(0, {"id": 1, "action": "allow", "src": "any", "dst": "any", "port": "any"}),
    "NET-009": lambda c: c["rules"].insert(0, {"id": 1, "action": "allow", "src": "internet", "dst": "servers", "port": 3389}),
    "NET-010": lambda c: c["rules"].insert(0, {"id": 1, "action": "allow", "src": "any", "dst": "servers", "port": 8080}),
    "NET-011": lambda c: c["rules"].insert(0, {"id": 1, "action": "allow", "src": "internet", "dst": "admin", "port": 22}),
    "NET-012": lambda c: c["management"]["snmp"].update(version="2c"),
    "NET-013": lambda c: c.update(routing={"protocol": "rip1"}),
    "SEC-001": lambda c: c["management"].update(admin_password="Admin123!"),
    "LOG-001": lambda c: c["logging"].update(enabled=False),
    "LOG-002": lambda c: c["logging"].pop("server"),
    "CFG-001": lambda c: c["management"]["ssh"].pop("idle_timeout"),
}


@pytest.mark.parametrize("rule_id", sorted(MUTATIONS))
def test_rule_detects_violation(rule_id, firewall, policy):
    MUTATIONS[rule_id](firewall)
    assert run(rule_id, firewall, policy), f"{rule_id} aurait dû détecter la violation"


def test_switch_rules(switch, policy):
    switch["switch"].update(native_vlan=1, unused_ports_shutdown=False)
    assert run("SW-001", switch, policy)
    assert run("SW-002", switch, policy)


def test_secret_value_is_never_leaked(firewall, policy):
    firewall["management"]["admin_password"] = "SuperSecret42"
    findings = run("SEC-001", firewall, policy)
    assert findings and "SuperSecret42" not in str(findings)


def test_secret_reference_is_accepted(firewall, policy):
    firewall["management"]["admin_password"] = "vault:network/admin"
    assert run("SEC-001", firewall, policy) == []


def test_public_https_is_not_flagged(firewall, policy):
    # règle 20 (Internet -> serveurs:443) est légitime
    assert run("NET-010", firewall, policy) == []
