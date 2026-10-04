#!/usr/bin/env python3
"""Entraîne deux classifieurs légers (TF-IDF caractères + régression logistique) :
 - texte du constat -> contrôle ISO 27001:2022 ; - texte du constat -> gravité.
Graine fixe : mêmes données = même modèle. Évaluation sur des gabarits jamais vus à l'entraînement."""
import json
import pathlib

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.pipeline import make_pipeline

HERE = pathlib.Path(__file__).parent


def build():
    return make_pipeline(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), lowercase=True, sublinear_tf=True),
        LogisticRegression(C=20, max_iter=2000, random_state=42),
    )


def main():
    df = pd.read_csv(HERE / "data" / "findings_labeled.csv")
    tr, te = df[df.split == "train"], df[df.split == "test"]
    metrics = {"n_train": len(tr), "n_test": len(te)}
    for target, fname in [("iso", "iso_clf.joblib"), ("severity", "severity_clf.joblib")]:
        model = build().fit(tr.text, tr[target])
        pred = model.predict(te.text)
        metrics[target] = {"accuracy": round(accuracy_score(te[target], pred), 3),
                           "report": classification_report(te[target], pred, output_dict=True, zero_division=0)}
        print(f"[{target}] accuracy sur jeu de test : {metrics[target]['accuracy']}")
        joblib.dump(build().fit(df.text, df[target]), HERE / "models" / fname)  # modèle final : tout le jeu
    (HERE / "models" / "metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
