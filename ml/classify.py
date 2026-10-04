#!/usr/bin/env python3
"""Génère le rapport d'audit (report.md) : rattache chaque constat à un contrôle ISO 27001:2022.
 - Si la règle porte déjà un contrôle ISO : il fait foi (traçable, déterministe).
 - Sinon : le modèle ML propose un contrôle (marqué « suggéré », avec sa confiance).
Le ML ne participe jamais à la décision PASS/FAIL. Si le modèle est absent, le rapport est généré sans lui."""
import argparse
import pathlib
import sys

import joblib
import yaml
from jinja2 import Environment, FileSystemLoader

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "scripts"))
from common import SEV_RANK, ci_context, load_json, save_json  # noqa: E402

THRESHOLD = 0.40


def load_models():
    try:
        return joblib.load(HERE / "models" / "iso_clf.joblib"), joblib.load(HERE / "models" / "severity_clf.joblib")
    except Exception:
        return None, None


def enrich(findings, iso_clf, sev_clf, catalog):
    agree = total = 0
    for f in findings:
        f["iso_source"], f["iso_confidence"], f["ml_severity"] = None, None, None
        pred = None
        if iso_clf is not None:
            proba = iso_clf.predict_proba([f["title"]])[0]
            best = proba.argmax()
            pred, conf = iso_clf.classes_[best], float(proba[best])
            f["ml_severity"] = sev_clf.predict([f["title"]])[0]
        if f.get("iso"):
            f["iso_source"] = "règle"
            if pred is not None:
                total += 1
                agree += pred == f["iso"]
        elif pred is not None and conf >= THRESHOLD:
            f["iso"], f["iso_source"], f["iso_confidence"] = pred, "ML (suggéré)", round(conf, 2)
        else:
            f["iso_source"] = "à confirmer"
        f["iso_label"] = catalog.get(f["iso"], "—") if f.get("iso") else "—"
    return {"compared": total, "agreement": round(agree / total, 2) if total else None}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", default="report.json")
    ap.add_argument("--verdict", default="verdict.json")
    ap.add_argument("--network", default="network_tests.json")
    ap.add_argument("--out-md", default="report.md")
    ap.add_argument("--out-json", default="report_enriched.json")
    a = ap.parse_args()

    rp, vp, np_ = pathlib.Path(a.report), pathlib.Path(a.verdict), pathlib.Path(a.network)
    report = load_json(rp) if rp.exists() else None
    verdict = load_json(vp) if vp.exists() else None
    network = load_json(np_) if np_.exists() else None
    catalog = yaml.safe_load((HERE / "iso_catalog.yml").read_text(encoding="utf-8"))
    iso_clf, sev_clf = load_models()

    stats = {"compared": 0, "agreement": None}
    if report:
        stats = enrich(report["findings"], iso_clf, sev_clf, catalog)
        report["findings"].sort(key=lambda f: (-SEV_RANK[f["severity"]], f["device"], f["rule_id"]))
    by_iso = {}
    for f in (report["findings"] if report else []):
        if f.get("iso"):
            by_iso.setdefault(f["iso"], []).append(f)

    env = Environment(loader=FileSystemLoader(HERE / "templates"), trim_blocks=True, lstrip_blocks=True)
    md = env.get_template("report.md.j2").render(
        report=report, verdict=verdict, network=network, ctx=ci_context(), by_iso=by_iso,
        catalog=catalog, stats=stats, ml_active=iso_clf is not None, threshold=THRESHOLD)
    pathlib.Path(a.out_md).write_text(md, encoding="utf-8")
    if report:
        save_json(a.out_json, report)
    print(f"Rapport écrit : {a.out_md} (ML {'actif' if iso_clf else 'absent'})")


if __name__ == "__main__":
    main()
