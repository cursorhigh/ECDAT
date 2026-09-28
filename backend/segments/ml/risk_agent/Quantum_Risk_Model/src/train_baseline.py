"""
ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) - Quantum Risk Model
Baseline Model Training Pipeline

Trains minimal, interpretable baseline models (Dummy Classifier & Logistic Regression / Decision Tree)
on the preprocessed training set to establish performance floors prior to gradient boosting.
"""

import os
import sys
import json
import time
import argparse
import datetime
from pathlib import Path
from typing import Dict, Any, Tuple

# Safe stdout on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

CLASS_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def parse_args():
    parser = argparse.ArgumentParser(description="ECDAT Baseline Model Training Pipeline")
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/processed",
        help="Directory containing preprocessed NumPy arrays",
    )
    parser.add_argument(
        "--models-dir",
        type=str,
        default="models/baseline",
        help="Directory to save baseline model artifacts",
    )
    parser.add_argument(
        "--reports-dir",
        type=str,
        default="reports",
        help="Directory to save baseline reports",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=42,
        help="Random seed for deterministic execution",
    )
    return parser.parse_args()


def run_baseline_training(
    data_dir: str, models_dir: str, reports_dir: str, random_seed: int
) -> Dict[str, Any]:
    d_dir = Path(data_dir)
    m_dir = Path(models_dir)
    r_dir = Path(reports_dir)

    for p in [m_dir, r_dir]:
        p.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("      ECDAT QUANTUM RISK MODEL - BASELINE TRAINING PIPELINE")
    print("=" * 80)
    print(f"Timestamp: {datetime.datetime.now().isoformat()}")
    print(f"Random Seed: {random_seed}\n")

    X_train = np.load(d_dir / "X_train.npy")
    y_train = np.load(d_dir / "y_train.npy")
    X_val = np.load(d_dir / "X_val.npy")
    y_val = np.load(d_dir / "y_val.npy")

    print(f"[*] Training baseline models on {len(X_train):,} samples...")

    baselines = {
        "dummy_stratified": DummyClassifier(strategy="stratified", random_state=random_seed),
        "logistic_regression": LogisticRegression(max_iter=500, random_state=random_seed),
        "decision_tree": DecisionTreeClassifier(max_depth=10, random_state=random_seed),
    }

    results = {}
    for name, clf in baselines.items():
        t0 = time.time()
        clf.fit(X_train, y_train)
        fit_time = time.time() - t0

        y_pred = clf.predict(X_val)
        acc = float(accuracy_score(y_val, y_pred))
        f1_macro = float(f1_score(y_val, y_pred, average="macro", zero_division=0))
        f1_weighted = float(f1_score(y_val, y_pred, average="weighted", zero_division=0))

        results[name] = {
            "accuracy": round(acc, 4),
            "macro_f1": round(f1_macro, 4),
            "weighted_f1": round(f1_weighted, 4),
            "training_time_sec": round(fit_time, 2),
        }
        print(f"  • {name:<22}: Validation Macro F1 = {f1_macro:.4f} | Accuracy = {acc:.4f} ({fit_time:.2f}s)")

        # Save artifact
        joblib.dump(clf, m_dir / f"{name}.joblib")

    report_payload = {
        "trained_at": datetime.datetime.now().isoformat(),
        "random_seed": random_seed,
        "evaluation_split": "validation_set (15,000 samples)",
        "baselines": results,
    }

    report_path = r_dir / "baseline_metrics.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)
    print(f"\n[OK] Saved baseline metrics to: {report_path.resolve()}")
    print("=" * 80)
    return report_payload


def main():
    args = parse_args()
    try:
        run_baseline_training(
            data_dir=args.data_dir,
            models_dir=args.models_dir,
            reports_dir=args.reports_dir,
            random_seed=args.random_seed,
        )
    except Exception as exc:
        print(f"\n[!] Baseline training failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
