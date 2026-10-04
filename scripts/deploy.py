#!/usr/bin/env python3
"""Étape de déploiement vers le lab simulé.
Garde-fous : refuse si le verdict n'est pas PASSED, ou si les configurations ont changé depuis l'audit."""
import argparse
import hashlib
import pathlib
import shutil
import subprocess
import sys

from common import ROOT, configs_digest, list_configs, load_json, save_json


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def docker_container_running(name):
    if not shutil.which("docker"):
        return False
    r = sh("docker", "inspect", "-f", "{{.State.Running}}", name)
    return r.returncode == 0 and r.stdout.strip() == "true"


def deploy_docker(device, path):
    c = f"lab-{device}"
    sh("docker", "exec", c, "mkdir", "-p", "/etc/netconfig")
    if sh("docker", "cp", str(path), f"{c}:/etc/netconfig/{device}.yml").returncode != 0:
        return False, "docker cp a échoué"
    r = sh("docker", "exec", c, "sha256sum", f"/etc/netconfig/{device}.yml")
    remote = r.stdout.split()[0] if r.returncode == 0 and r.stdout else ""
    return remote == hashlib.sha256(path.read_bytes()).hexdigest(), f"conteneur {c}"


def deploy_local(device, path, target_dir):
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / f"{device}.yml"
    shutil.copy2(path, dest)
    return dest.read_bytes() == path.read_bytes(), f"répertoire {dest}"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--configs", default=str(ROOT / "configs"))
    ap.add_argument("--verdict", default="verdict.json")
    ap.add_argument("--mode", choices=["auto", "docker", "local"], default="auto")
    ap.add_argument("--local-dir", default=str(ROOT / "lab" / "deployed"))
    ap.add_argument("--out", default="deployment.json")
    a = ap.parse_args()

    verdict = load_json(a.verdict)
    if verdict["deployment"] != "ALLOWED":
        print("✗ Déploiement refusé : le verdict est", verdict["verdict"])
        return 1
    if verdict["configs_sha256"] != configs_digest(a.configs):
        print("✗ Déploiement refusé : les configurations ont changé depuis l'audit")
        return 1

    results = []
    for p in list_configs(a.configs):
        device = p.stem
        use_docker = a.mode == "docker" or (a.mode == "auto" and docker_container_running(f"lab-{device}"))
        ok, where = deploy_docker(device, p) if use_docker else deploy_local(device, p, pathlib.Path(a.local_dir))
        results.append({"device": device, "target": where, "verified": ok})
        print(f"{'✓' if ok else '✗'} {device} -> {where}")
    save_json(a.out, results)
    ok = all(r["verified"] for r in results)
    print("DEPLOYMENT:", "DONE" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
