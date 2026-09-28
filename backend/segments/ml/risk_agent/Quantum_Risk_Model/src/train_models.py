"""
ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) - Quantum Risk Model
Model Comparison & Training Pipeline

Trains and compares candidate classifiers on preprocessed ECDAT training data:
1. Random Forest Classifier
2. XGBoost Classifier
3. CatBoost Classifier

Evaluates models strictly on the validation set using:
- Accuracy, Macro Precision, Macro Recall, Macro F1, Weighted F1
- Per-class F1 scores (LOW, MEDIUM, HIGH, CRITICAL)
- Confusion Matrices
- Training and Inference latencies

Saves:
- Model artifacts to models/candidates/<model_name>/
- reports/model_comparison.csv
- reports/model_comparison.json

Identifies the best candidate based on validation Macro F1 score without touching the test set.
"""

import os
import sys
import json
import time
import argparse
import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple

# Safe stdout on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from catboost import CatBoostClassifier

# Canonical class labels
CLASS_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CLASS_INDICES = [0, 1, 2, 3]


def parse_args():
    parser = argparse.ArgumentParser(
        description="ECDAT Quantum Risk Model Comparison Pipeline"
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/processed",
        help="Directory containing preprocessed NumPy / NPZ splits",
    )
    parser.add_argument(
        "--models-dir",
        type=str,
        default="models/candidates",
        help="Root directory to store candidate model artifacts",
    )
    parser.add_argument(
        "--reports-dir",
        type=str,
        default="reports",
        help="Directory to save comparison reports",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=42,
        help="Random seed for deterministic model training",
    )
    return parser.parse_args()


def load_processed_data(data_dir: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Loads preprocessed training and validation feature matrices and target arrays."""
    train_x_path = data_dir / "X_train.npy"
    train_y_path = data_dir / "y_train.npy"
    val_x_path = data_dir / "X_val.npy"
    val_y_path = data_dir / "y_val.npy"

    for p in [train_x_path, train_y_path, val_x_path, val_y_path]:
        if not p.exists():
            raise FileNotFoundError(
                f"Required dataset file not found: {p.resolve()}\n"
                f"Please run 'python src/preprocess.py' first to generate splits."
            )

    print(f"[*] Loading preprocessed datasets from: {data_dir.resolve()}...")
    X_train = np.load(train_x_path)
    y_train = np.load(train_y_path)
    X_val = np.load(val_x_path)
    y_val = np.load(val_y_path)

    print(f"[OK] X_train: {X_train.shape}, y_train: {y_train.shape}")
    print(f"[OK] X_val:   {X_val.shape}, y_val:   {y_val.shape}\n")
    return X_train, y_train, X_val, y_val


def get_candidate_models(random_seed: int) -> Dict[str, Any]:
    """Initializes the three candidate classifiers with robust hyperparameters."""
    models = {
        "random_forest": {
            "display_name": "Random Forest",
            "estimator": RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                n_jobs=-1,
                random_state=random_seed,
            ),
        },
        "xgboost": {
            "display_name": "XGBoost",
            "estimator": XGBClassifier(
                n_estimators=250,
                max_depth=6,
                learning_rate=0.08,
                subsample=0.85,
                colsample_bytree=0.85,
                random_state=random_seed,
                n_jobs=-1,
                eval_metric="mlogloss",
            ),
        },
        "catboost": {
            "display_name": "CatBoost",
            "estimator": CatBoostClassifier(
                iterations=350,
                depth=6,
                learning_rate=0.08,
                loss_function="MultiClass",
                random_seed=random_seed,
                thread_count=-1,
                verbose=False,
            ),
        },
    }
    return models


def evaluate_model(
    estimator: Any,
    X_val: np.ndarray,
    y_val: np.ndarray,
    train_time_sec: float,
    model_name: str,
) -> Dict[str, Any]:
    """Computes comprehensive multi-class classification metrics on validation set."""
    t0 = time.time()
    y_pred = estimator.predict(X_val)
    # Handle possible 2D array output from some libraries
    if hasattr(y_pred, "squeeze"):
        y_pred = y_pred.squeeze()
    y_pred = y_pred.astype(int)
    eval_time_sec = time.time() - t0

    acc = float(accuracy_score(y_val, y_pred))
    prec_macro = float(precision_score(y_val, y_pred, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_val, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_val, y_pred, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_val, y_pred, average="weighted", zero_division=0))

    # Per-class F1 scores
    per_class_f1 = f1_score(y_val, y_pred, average=None, zero_division=0)
    per_class_dict = {
        CLASS_NAMES[i]: round(float(per_class_f1[i]), 4) for i in range(len(CLASS_NAMES))
    }

    # Confusion matrix
    cm = confusion_matrix(y_val, y_pred, labels=CLASS_INDICES).tolist()

    # Model parameters
    params = {}
    try:
        params = estimator.get_params()
        # Clean un-serializable params
        params = {k: str(v) if not isinstance(v, (int, float, str, bool, list, dict, type(None))) else v for k, v in params.items()}
    except Exception:
        params = {"note": "get_params not available"}

    return {
        "model_key": model_name,
        "accuracy": round(acc, 4),
        "macro_precision": round(prec_macro, 4),
        "macro_recall": round(rec_macro, 4),
        "macro_f1": round(f1_macro, 4),
        "weighted_f1": round(f1_weighted, 4),
        "per_class_f1": per_class_dict,
        "confusion_matrix": cm,
        "training_time_sec": round(train_time_sec, 2),
        "inference_time_sec": round(eval_time_sec, 4),
        "hyperparameters": params,
    }


def save_candidate_model(
    model_name: str,
    estimator: Any,
    eval_metrics: Dict[str, Any],
    models_dir: Path,
) -> Path:
    """Saves candidate model artifact and associated metadata."""
    save_path = models_dir / model_name
    save_path.mkdir(parents=True, exist_ok=True)

    artifact_file = save_path / "model.joblib"
    joblib.dump(estimator, artifact_file)

    meta_file = save_path / "model_info.json"
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "model_name": model_name,
                "saved_at": datetime.datetime.now().isoformat(),
                "artifact_path": str(artifact_file.name),
                "validation_metrics": {
                    "accuracy": eval_metrics["accuracy"],
                    "macro_precision": eval_metrics["macro_precision"],
                    "macro_recall": eval_metrics["macro_recall"],
                    "macro_f1": eval_metrics["macro_f1"],
                    "weighted_f1": eval_metrics["weighted_f1"],
                    "per_class_f1": eval_metrics["per_class_f1"],
                },
                "training_time_sec": eval_metrics["training_time_sec"],
                "hyperparameters": eval_metrics["hyperparameters"],
            },
            f,
            indent=2,
        )

    return artifact_file


def run_comparison_pipeline(
    data_dir: str,
    models_dir: str,
    reports_dir: str,
    random_seed: int,
) -> None:
    data_path = Path(data_dir)
    models_path = Path(models_dir)
    reports_path = Path(reports_dir)

    for p in [models_path, reports_path]:
        p.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("      ECDAT QUANTUM RISK MODEL - CANDIDATE COMPARISON PIPELINE")
    print("=" * 80)
    print(f"Timestamp: {datetime.datetime.now().isoformat()}")
    print(f"Random Seed: {random_seed}\n")

    # 1. Load exact preprocessed training and validation splits
    X_train, y_train, X_val, y_val = load_processed_data(data_path)

    # 2. Candidate models setup
    candidates = get_candidate_models(random_seed)
    results: List[Dict[str, Any]] = []

    # 3. Train and Evaluate each candidate
    for key, spec in candidates.items():
        disp_name = spec["display_name"]
        clf = spec["estimator"]

        print(f"[*] Training [{disp_name}] on {len(X_train):,} samples...")
        t_start = time.time()
        clf.fit(X_train, y_train)
        t_elapsed = time.time() - t_start
        print(f"[OK] [{disp_name}] training completed in {t_elapsed:.2f}s.")

        # Validation Evaluation
        print(f"[*] Evaluating [{disp_name}] on validation set ({len(X_val):,} samples)...")
        metrics = evaluate_model(clf, X_val, y_val, t_elapsed, key)
        metrics["display_name"] = disp_name
        results.append(metrics)

        # Save model artifact
        art_path = save_candidate_model(key, clf, metrics, models_path)
        print(f"[OK] Saved model artifact: {art_path.resolve()}\n")

    # 4. Sort models by Macro F1 descending
    results.sort(key=lambda x: x["macro_f1"], reverse=True)

    # 5. Build and Save Comparison Reports (CSV and JSON)
    # CSV Data
    csv_rows = []
    for r in results:
        csv_rows.append({
            "model": r["display_name"],
            "model_key": r["model_key"],
            "accuracy": r["accuracy"],
            "macro_f1": r["macro_f1"],
            "weighted_f1": r["weighted_f1"],
            "macro_precision": r["macro_precision"],
            "macro_recall": r["macro_recall"],
            "f1_LOW": r["per_class_f1"]["LOW"],
            "f1_MEDIUM": r["per_class_f1"]["MEDIUM"],
            "f1_HIGH": r["per_class_f1"]["HIGH"],
            "f1_CRITICAL": r["per_class_f1"]["CRITICAL"],
            "train_time_sec": r["training_time_sec"],
            "inference_time_sec": r["inference_time_sec"],
        })
    df_comparison = pd.DataFrame(csv_rows)

    csv_path = reports_path / "model_comparison.csv"
    df_comparison.to_csv(csv_path, index=False, encoding="utf-8")
    print(f"[OK] Saved comparison CSV to: {csv_path.resolve()}")

    # JSON Data
    json_payload = {
        "metadata": {
            "created_at": datetime.datetime.now().isoformat(),
            "random_seed": random_seed,
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "metric_used_for_ranking": "macro_f1",
            "evaluation_set": "validation_set (test set untouched)",
        },
        "ranking": [r["display_name"] for r in results],
        "best_model": results[0]["display_name"],
        "best_model_key": results[0]["model_key"],
        "models": results,
    }
    json_path = reports_path / "model_comparison.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2)
    print(f"[OK] Saved comparison JSON to: {json_path.resolve()}")

    # 6. Display Comparison Summary Table
    print("\n" + "=" * 92)
    print(f"{'Model':<16} | {'Macro F1':<10} | {'Weighted F1':<12} | {'Accuracy':<10} | {'F1-Crit':<9} | {'Train (s)':<10}")
    print("-" * 92)
    for r in results:
        print(
            f"{r['display_name']:<16} | {r['macro_f1']:>9.4f} | {r['weighted_f1']:>11.4f} | "
            f"{r['accuracy']:>9.4f} | {r['per_class_f1']['CRITICAL']:>8.4f} | {r['training_time_sec']:>9.2f}"
        )
    print("=" * 92)

    # 7. Print Per-Class F1 Table
    print("\n" + "-" * 80)
    print(f"{'Model':<16} | {'LOW':<12} | {'MEDIUM':<12} | {'HIGH':<12} | {'CRITICAL':<12}")
    print("-" * 80)
    for r in results:
        pc = r["per_class_f1"]
        print(
            f"{r['display_name']:<16} | {pc['LOW']:>10.4f} | {pc['MEDIUM']:>10.4f} | "
            f"{pc['HIGH']:>10.4f} | {pc['CRITICAL']:>10.4f}"
        )
    print("-" * 80)

    # 8. Print Confusion Matrix for Best Model
    best = results[0]
    header_col = "Actual / Pred".ljust(14)
    print(f"\n--- CONFUSION MATRIX FOR BEST MODEL: {best['display_name']} ---")
    print(f"{header_col} | " + " | ".join(f"{c:>8}" for c in CLASS_NAMES))
    print("-" * 60)
    for i, actual_class in enumerate(CLASS_NAMES):
        row_str = " | ".join(f"{best['confusion_matrix'][i][j]:>8,}" for j in range(len(CLASS_NAMES)))
        print(f"{actual_class:<14} | {row_str}")

    print("\n" + "=" * 80)
    print(f"  RECOMMENDED CANDIDATE FOR TUNING / FINAL DEPLOYMENT: {best['display_name'].upper()}")
    print(f"  Validation Macro F1: {best['macro_f1']:.4f} (Accuracy: {best['accuracy']:.4f})")
    print("=" * 80)


def main():
    args = parse_args()
    try:
        run_comparison_pipeline(
            data_dir=args.data_dir,
            models_dir=args.models_dir,
            reports_dir=args.reports_dir,
            random_seed=args.random_seed,
        )
    except Exception as exc:
        print(f"\n[!] Model training & comparison failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
