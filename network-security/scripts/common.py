"""Fonctions partagées par les scripts du pipeline."""
import hashlib
import ipaddress
import json
import os
import pathlib
import subprocess

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def list_configs(config_dir):
    return sorted(pathlib.Path(config_dir).glob("*.yml"))


def get_path(data, dotted):
    """Retourne (trouvé, valeur) pour un chemin pointé, ex. 'management.ssh.enabled'."""
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def same_value(a, b):
    """Égalité stricte en type (évite True == 1)."""
    return type(a) is type(b) and a == b


def parse_net(token, zones=None):
    """Résout 'any', un nom de zone ou un CIDR en ip_network."""
    t = str(token).strip()
    if t.lower() in ("any", "::/0"):
        return ipaddress.ip_network("0.0.0.0/0")
    if zones and t in zones:
        return ipaddress.ip_network(zones[t]["cidr"], strict=False)
    return ipaddress.ip_network(t, strict=False)


def port_range(port):
    if port is None or str(port).lower() == "any":
        return 0, 65535
    if isinstance(port, int):
        return port, port
    lo, _, hi = str(port).partition("-")
    return int(lo), int(hi or lo)


def configs_digest(config_dir):
    """Empreinte SHA-256 de l'ensemble des configurations (lie audit et déploiement)."""
    h = hashlib.sha256()
    for p in list_configs(config_dir):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def _git(*args):
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return None


def ci_context():
    """Traçabilité (BF7) : qui, quel commit, quel pipeline."""
    e = os.environ
    return {
        "commit": e.get("CI_COMMIT_SHA") or _git("rev-parse", "HEAD"),
        "author": e.get("CI_COMMIT_AUTHOR") or _git("log", "-1", "--format=%an <%ae>"),
        "message": e.get("CI_COMMIT_TITLE") or _git("log", "-1", "--format=%s"),
        "branch": e.get("CI_COMMIT_REF_NAME") or _git("rev-parse", "--abbrev-ref", "HEAD"),
        "pipeline_id": e.get("CI_PIPELINE_ID"),
        "pipeline_url": e.get("CI_PIPELINE_URL"),
    }
