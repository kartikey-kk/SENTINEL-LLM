"""Train a lightweight scikit-learn baseline (TF-IDF + logistic regression) for attack detection.

Trained on the *train* split only; the regularization strength C is selected on the *validation*
split by F1; the test split is never touched here. The artifact is saved for the pluggable
SklearnTextClassifier adapter and evaluated by evaluate_detectors.py.

Usage: backend/.venv/Scripts/python experiments/train_baseline.py
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.pipeline import FeatureUnion, Pipeline

from common import ROOT, load_split, write_result

OUT = ROOT / "models_cache" / "sentinel_sklearn" / "tfidf_lr.joblib"
ATTACK = {"prompt_injection", "jailbreak", "indirect_injection"}


def xy(rows):
    keep = [r for r in rows if r["category"] in ATTACK or r["label"] == 0]
    return [r["text"] for r in keep], [1 if r["category"] in ATTACK else 0 for r in keep]


def build(c: float) -> Pipeline:
    feats = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ])
    return Pipeline([("features", feats), ("clf", LogisticRegression(C=c, max_iter=2000, class_weight="balanced"))])


def main() -> None:
    x_tr, y_tr = xy(load_split("train"))
    x_va, y_va = xy(load_split("validation"))
    best = None
    for c in (0.1, 0.3, 1.0, 3.0, 10.0):
        pipe = build(c).fit(x_tr, y_tr)
        pred = pipe.predict(x_va)
        f1 = f1_score(y_va, pred, zero_division=0)
        print(f"C={c:<5} val F1={f1:.4f} P={precision_score(y_va, pred, zero_division=0):.4f} R={recall_score(y_va, pred, zero_division=0):.4f}")
        if best is None or f1 > best[1]:
            best = (c, f1, pipe)
    assert best is not None
    OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(best[2], OUT)
    print(f"selected C={best[0]} (val F1={best[1]:.4f}) -> {OUT}")
    write_result("training_sklearn_baseline", {
        "model": "tfidf(word 1-2 + char 3-5) + logistic regression (class_weight=balanced)",
        "train_samples": len(x_tr), "train_positives": sum(y_tr), "validation_samples": len(x_va),
        "selected_C": best[0], "validation_f1": round(best[1], 4), "artifact": str(OUT.relative_to(ROOT)),
        "summary": {"validation_f1": round(best[1], 4)},
    })


if __name__ == "__main__":
    main()
