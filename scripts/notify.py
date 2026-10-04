#!/usr/bin/env python3
"""Étape 7 : notification Slack + ticket d'incident GitLab quand le déploiement est bloqué.
Sans variables d'environnement (usage local), le script affiche le message (dry-run)."""
import argparse
import os
import pathlib
import sys

import requests

from common import ROOT, ci_context, load_json


def build_message(report, verdict, ctx):
    lines = [f":no_entry: *Déploiement BLOQUÉ* — branche `{ctx.get('branch')}`",
             f"Auteur : {ctx.get('author')} · commit `{str(ctx.get('commit'))[:8]}`"]
    if verdict is None:
        lines.append("Le pipeline a échoué avant la décision (validation syntaxique ou erreur du scan).")
    else:
        lines.append(f"{verdict['blocking']} violation(s) bloquante(s), {verdict['warnings']} avertissement(s)")
    if report:
        for f in [x for x in report["findings"] if x["severity"] in ("CRITICAL", "HIGH")][:8]:
            lines.append(f"• [{f['severity']}] {f['device']} {f['rule_id']} : {f['detail']}")
    if ctx.get("pipeline_url"):
        lines.append(f"Pipeline : {ctx['pipeline_url']}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", default="report.json")
    ap.add_argument("--verdict", default="verdict.json")
    ap.add_argument("--markdown", default="report.md")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    rp, vp = pathlib.Path(a.report), pathlib.Path(a.verdict)
    report = load_json(rp) if rp.exists() else None
    verdict = load_json(vp) if vp.exists() else None
    if verdict and verdict["deployment"] == "ALLOWED":
        print("Déploiement autorisé : aucune notification.")
        return 0

    ctx = ci_context()
    msg = build_message(report, verdict, ctx)
    e = os.environ
    dry = a.dry_run or not (e.get("SLACK_WEBHOOK_URL") or e.get("GITLAB_API_TOKEN"))
    if dry:
        print("[dry-run] Notification qui serait envoyée :\n" + msg)
        return 0

    if e.get("SLACK_WEBHOOK_URL"):
        try:
            r = requests.post(e["SLACK_WEBHOOK_URL"], json={"text": msg}, timeout=10)
            print("Slack :", r.status_code)
        except requests.RequestException as ex:
            print("Slack : échec d'envoi", ex)
    if e.get("GITLAB_API_TOKEN") and e.get("CI_API_V4_URL") and e.get("CI_PROJECT_ID"):
        body = pathlib.Path(a.markdown).read_text(encoding="utf-8") if pathlib.Path(a.markdown).exists() else msg
        try:
            r = requests.post(
                f"{e['CI_API_V4_URL']}/projects/{e['CI_PROJECT_ID']}/issues",
                headers={"PRIVATE-TOKEN": e["GITLAB_API_TOKEN"]},
                data={"title": f"[SÉCURITÉ] Déploiement bloqué — pipeline {ctx.get('pipeline_id')}",
                      "description": body, "labels": "security,incident,network"},
                timeout=10)
            print("Ticket GitLab :", r.status_code, r.json().get("web_url", ""))
        except requests.RequestException as ex:
            print("Ticket GitLab : échec", ex)
    return 0  # une notification en échec ne doit jamais masquer le résultat du pipeline


if __name__ == "__main__":
    sys.exit(main())
