"""
ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) - Quantum Risk Model
Hyperparameter Tuning Pipeline

Performs reproducible, controlled Bayesian optimization (via Optuna) for the best candidate model:
1. Loads the top-performing candidate identified in reports/model_comparison.json (default: CatBoost).
2. Preserves the exact 70/15 Train/Validation split without touching the test set.
3. Optimizes primarily for Macro F1 while tracking:
   - Accuracy
   - Weighted F1
   - Macro Precision
   - Macro Recall
   - Per-class Recall (LOW, MEDIUM, HIGH, CRITICAL)
   - Per-class F1
4. Explores class weighting strategies (e.g., auto_class_weights: None, Balanced, SqrtBalanced) to maximize minority detection.
5. Saves tuned model artifact and logs to:
   - models/tuned/ (model.joblib, tuned_model_info.json)
   - reports/tuning_results.json
   - reports/tuning_results.csv
"""

import os
import sys
import json
import time
import argparse
import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

# Safe stdout on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import joblib
import optuna
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from catboost import CatBoostClassifier
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier

# Set optuna verbosity to warning to keep clean logs
optuna.logging.set_verbosity(optuna.logging.WARNING)

CLASS_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CLASS_INDICES = [0, 1, 2, 3]


def parse_args():
    parser = argparse.ArgumentParser(
        description="ECDAT Quantum Risk Hyperparameter Tuning Pipeline"
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/processed",
        help="Directory containing preprocessed NumPy / NPZ splits",
    )
    parser.add_argument(
        "--comparison-report",
        type=str,
        default="reports/model_comparison.json",
        help="Path to previous candidate comparison report JSON",
    )
    parser.add_argument(
        "--model-type",
        type=str,
        default="auto",
        choices=["auto", "catboost", "xgboost", "random_forest"],
        help="Model architecture to tune ('auto' selects winner from comparison report)",
    )
    parser.add_argument(
        "--n-trials",
        type=int,
        default=25,
        help="Number of Bayesian optimization trials to run",
    )
    parser.add_argument(
        "--models-dir",
        type=str,
        default="models/tuned",
        help="Directory to save final tuned model artifact",
    )
    parser.add_argument(
        "--reports-dir",
        type=str,
        default="reports",
        help="Directory to save tuning results and CSV logs",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=42,
        help="Random seed for deterministic optimization and training",
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
                f"Please run 'python src/preprocess.py' first."
            )

    print(f"[*] Loading preprocessed splits from: {data_dir.resolve()}...")
    X_train = np.load(train_x_path)
    y_train = np.load(train_y_path)
    X_val = np.load(val_x_path)
    y_val = np.load(val_y_path)

    print(f"[OK] Training Split:   {X_train.shape} samples")
    print(f"[OK] Validation Split: {X_val.shape} samples (Test set untouched)\n")
    return X_train, y_train, X_val, y_val


def determine_target_model(comparison_report_path: Path, model_type_arg: str) -> Tuple[str, str]:
    """Determines which candidate model to tune."""
    if model_type_arg != "auto":
        return model_type_arg, model_type_arg.replace("_", " ").title()

    if comparison_report_path.exists():
        try:
            with open(comparison_report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            best_key = data.get("best_model_key", "catboost")
            best_name = data.get("best_model", "CatBoost")
            print(f"[*] Auto-detected best candidate from '{comparison_report_path.name}': {best_name} ({best_key})")
            return best_key, best_name
        except Exception as e:
            print(f"[!] Warning: Could not parse '{comparison_report_path}': {e}. Falling back to CatBoost.")

    return "catboost", "CatBoost"


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    """Calculates all key multi-class classification and per-class metrics."""
    acc = float(accuracy_score(y_true, y_pred))
    prec_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    per_class_rec = recall_score(y_true, y_pred, average=None, zero_division=0)
    per_class_f1 = f1_score(y_true, y_pred, average=None, zero_division=0)

    rec_dict = {f"rec_{CLASS_NAMES[i]}": round(float(per_class_rec[i]), 4) for i in range(len(CLASS_NAMES))}
    f1_dict = {f"f1_{CLASS_NAMES[i]}": round(float(per_class_f1[i]), 4) for i in range(len(CLASS_NAMES))}
    cm = confusion_matrix(y_true, y_pred, labels=CLASS_INDICES).tolist()

    return {
        "accuracy": round(acc, 4),
        "macro_precision": round(prec_macro, 4),
        "macro_recall": round(rec_macro, 4),
        "macro_f1": round(f1_macro, 4),
        "weighted_f1": round(f1_weighted, 4),
        "per_class_recall": rec_dict,
        "per_class_f1": f1_dict,
        "confusion_matrix": cm,
    }


def sample_hyperparameters(trial: optuna.Trial, model_key: str, random_seed: int) -> Dict[str, Any]:
    """Defines the search space for the respective model architecture."""
    if model_key == "catboost":
        iterations = trial.suggest_int("iterations", 300, 700, step=100)
        depth = trial.suggest_int("depth", 4, 8)
        learning_rate = trial.suggest_float("learning_rate", 0.03, 0.15, log=True)
        l2_leaf_reg = trial.suggest_float("l2_leaf_reg", 1.0, 10.0, log=True)
        auto_class_weights = trial.suggest_categorical("auto_class_weights", ["None", "Balanced", "SqrtBalanced"])
        random_strength = trial.suggest_float("random_strength", 0.1, 5.0)

        params: Dict[str, Any] = {
            "iterations": iterations,
            "depth": depth,
            "learning_rate": round(learning_rate, 5),
            "l2_leaf_reg": round(l2_leaf_reg, 4),
            "auto_class_weights": None if auto_class_weights == "None" else auto_class_weights,
            "random_strength": round(random_strength, 4),
            "loss_function": "MultiClass",
            "random_seed": random_seed,
            "thread_count": -1,
            "verbose": False,
        }
        return params

    elif model_key == "xgboost":
        n_estimators = trial.suggest_int("n_estimators", 200, 500, step=50)
        max_depth = trial.suggest_int("max_depth", 4, 8)
        learning_rate = trial.suggest_float("learning_rate", 0.03, 0.15, log=True)
        subsample = trial.suggest_float("subsample", 0.7, 1.0)
        colsample_bytree = trial.suggest_float("colsample_bytree", 0.7, 1.0)
        min_child_weight = trial.suggest_int("min_child_weight", 1, 6)

        params = {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "learning_rate": round(learning_rate, 5),
            "subsample": round(subsample, 4),
            "colsample_bytree": round(colsample_bytree, 4),
            "min_child_weight": min_child_weight,
            "random_state": random_seed,
            "n_jobs": -1,
            "eval_metric": "mlogloss",
        }
        return params

    elif model_key == "random_forest":
        n_estimators = trial.suggest_int("n_estimators", 150, 400, step=50)
        max_depth = trial.suggest_int("max_depth", 12, 30)
        min_samples_split = trial.suggest_int("min_samples_split", 2, 10)
        min_samples_leaf = trial.suggest_int("min_samples_leaf", 1, 4)
        class_weight = trial.suggest_categorical("class_weight", ["None", "balanced", "balanced_subsample"])

        params = {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "min_samples_split": min_samples_split,
            "min_samples_leaf": min_samples_leaf,
            "class_weight": None if class_weight == "None" else class_weight,
            "random_state": random_seed,
            "n_jobs": -1,
        }
        return params

    else:
        raise ValueError(f"Unsupported model key: {model_key}")


def instantiate_model(model_key: str, params: Dict[str, Any]) -> Any:
    """Instantiates the model with the given parameter dictionary."""
    if model_key == "catboost":
        return CatBoostClassifier(**params)
    elif model_key == "xgboost":
        return XGBClassifier(**params)
    elif model_key == "random_forest":
        return RandomForestClassifier(**params)
    else:
        raise ValueError(f"Unknown model_key: {model_key}")


def run_tuning(
    data_dir: str,
    comparison_report: str,
    model_type: str,
    n_trials: int,
    models_dir: str,
    reports_dir: str,
    random_seed: int,
) -> None:
    data_path = Path(data_dir)
    comp_path = Path(comparison_report)
    out_models_path = Path(models_dir)
    out_reports_path = Path(reports_dir)

    for p in [out_models_path, out_reports_path]:
        p.mkdir(parents=True, exist_ok=True)

    # 1. Determine model candidate to tune
    model_key, model_display_name = determine_target_model(comp_path, model_type)

    print("=" * 80)
    print("      ECDAT QUANTUM RISK MODEL - HYPERPARAMETER TUNING")
    print("=" * 80)
    print(f"Target Architecture: {model_display_name} ({model_key})")
    print(f"Optimization Budget: {n_trials} Bayesian Search Trials (Optuna TPESampler)")
    print(f"Primary Objective:   Maximize Validation Macro F1")
    print(f"Random Seed:         {random_seed}")
    print(f"Timestamp:           {datetime.datetime.now().isoformat()}\n")

    # 2. Load preprocessed training & validation data
    X_train, y_train, X_val, y_val = load_processed_data(data_path)

    trial_history: List[Dict[str, Any]] = []

    # 3. Define Optuna Objective Function
    def objective(trial: optuna.Trial) -> float:
        params = sample_hyperparameters(trial, model_key, random_seed)
        clf = instantiate_model(model_key, params)

        t0 = time.time()
        clf.fit(X_train, y_train)
        fit_time = time.time() - t0

        y_pred = clf.predict(X_val)
        if hasattr(y_pred, "squeeze"):
            y_pred = y_pred.squeeze()
        y_pred = y_pred.astype(int)

        metrics = compute_metrics(y_val, y_pred)
        score = metrics["macro_f1"]

        # Log trial metrics
        trial_info = {
            "trial_number": trial.number,
            "macro_f1": metrics["macro_f1"],
            "weighted_f1": metrics["weighted_f1"],
            "accuracy": metrics["accuracy"],
            "macro_precision": metrics["macro_precision"],
            "macro_recall": metrics["macro_recall"],
            **metrics["per_class_recall"],
            **metrics["per_class_f1"],
            "fit_time_sec": round(fit_time, 2),
            "parameters": {k: str(v) if v is not None and not isinstance(v, (int, float, str, bool)) else v for k, v in params.items()},
        }
        trial_history.append(trial_info)

        print(
            f"  [Trial {trial.number + 1:>2}/{n_trials}] Macro F1: {metrics['macro_f1']:.4f} | "
            f"Acc: {metrics['accuracy']:.4f} | Weighted F1: {metrics['weighted_f1']:.4f} | "
            f"Crit Recall: {metrics['per_class_recall']['rec_CRITICAL']:.4f} ({fit_time:.1f}s)"
        )
        return score

    # 4. Create and run study
    print("--- STARTING BAYESIAN HYPERPARAMETER SEARCH ---")
    sampler = optuna.samplers.TPESampler(seed=random_seed)
    study = optuna.create_study(direction="maximize", sampler=sampler)
    study.optimize(objective, n_trials=n_trials)

    print("\n--- HYPERPARAMETER OPTIMIZATION COMPLETE ---")
    best_trial = study.best_trial
    best_val_score = best_trial.value
    print(f"Best Trial Number:  #{best_trial.number + 1}")
    print(f"Best Validation F1: {best_val_score:.4f}")
    print(f"Best Parameters:")
    for k, v in best_trial.params.items():
        print(f"  - {k}: {v}")

    # 5. Fit Final Tuned Model with Best Parameters on X_train
    print(f"\n[*] Training final tuned {model_display_name} model on full training set (70,000 samples)...")
    best_params = sample_hyperparameters(best_trial, model_key, random_seed)
    final_model = instantiate_model(model_key, best_params)

    t_final_start = time.time()
    final_model.fit(X_train, y_train)
    final_train_time = time.time() - t_final_start

    # Final Validation Evaluation
    t_inf_start = time.time()
    y_val_pred = final_model.predict(X_val)
    if hasattr(y_val_pred, "squeeze"):
        y_val_pred = y_val_pred.squeeze()
    y_val_pred = y_val_pred.astype(int)
    final_inf_time = time.time() - t_inf_start

    final_metrics = compute_metrics(y_val, y_val_pred)

    # 6. Save Final Tuned Artifact
    artifact_path = out_models_path / "model.joblib"
    joblib.dump(final_model, artifact_path)
    print(f"[OK] Saved final tuned model artifact: {artifact_path.resolve()}")

    model_info_path = out_models_path / "tuned_model_info.json"
    with open(model_info_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "model_name": model_display_name,
                "model_key": model_key,
                "tuned_at": datetime.datetime.now().isoformat(),
                "random_seed": random_seed,
                "best_trial_number": best_trial.number + 1,
                "best_parameters": best_params,
                "validation_metrics": final_metrics,
                "training_time_sec": round(final_train_time, 2),
                "inference_time_sec": round(final_inf_time, 4),
            },
            f,
            indent=2,
        )
    print(f"[OK] Saved tuned model metadata: {model_info_path.resolve()}")

    # 7. Save Tuning Reports (CSV and JSON)
    # 7a. CSV Report
    csv_rows = []
    for t in trial_history:
        flat = {
            "trial_number": t["trial_number"] + 1,
            "macro_f1": t["macro_f1"],
            "weighted_f1": t["weighted_f1"],
            "accuracy": t["accuracy"],
            "macro_precision": t["macro_precision"],
            "macro_recall": t["macro_recall"],
            "rec_LOW": t.get("rec_LOW"),
            "rec_MEDIUM": t.get("rec_MEDIUM"),
            "rec_HIGH": t.get("rec_HIGH"),
            "rec_CRITICAL": t.get("rec_CRITICAL"),
            "f1_LOW": t.get("f1_LOW"),
            "f1_MEDIUM": t.get("f1_MEDIUM"),
            "f1_HIGH": t.get("f1_HIGH"),
            "f1_CRITICAL": t.get("f1_CRITICAL"),
            "fit_time_sec": t["fit_time_sec"],
        }
        for pk, pv in t["parameters"].items():
            flat[f"param_{pk}"] = pv
        csv_rows.append(flat)

    df_trials = pd.DataFrame(csv_rows).sort_values("macro_f1", ascending=False)
    csv_path = out_reports_path / "tuning_results.csv"
    df_trials.to_csv(csv_path, index=False, encoding="utf-8")
    print(f"[OK] Saved tuning results CSV: {csv_path.resolve()}")

    # 7b. JSON Report
    tuning_json = {
        "metadata": {
            "tuned_at": datetime.datetime.now().isoformat(),
            "model_architecture": model_display_name,
            "model_key": model_key,
            "random_seed": random_seed,
            "search_strategy": "Bayesian TPE (Optuna)",
            "n_trials_evaluated": len(trial_history),
            "primary_metric": "macro_f1",
            "evaluation_set": "validation_set (15,000 samples, test set untouched)",
        },
        "best_result": {
            "best_trial_number": best_trial.number + 1,
            "best_macro_f1": final_metrics["macro_f1"],
            "best_parameters": best_params,
            "validation_metrics": final_metrics,
        },
        "top_trials": df_trials.head(10).to_dict(orient="records"),
    }
    json_path = out_reports_path / "tuning_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(tuning_json, f, indent=2)
    print(f"[OK] Saved tuning results JSON: {json_path.resolve()}")

    # 8. Print Summary Table
    print("\n" + "=" * 80)
    print(f"                       TUNING SUMMARY ({model_display_name})")
    print("=" * 80)
    print(f"Baseline Validation Macro F1: ~0.9321")
    print(f"Tuned Validation Macro F1:    {final_metrics['macro_f1']:.4f}")
    print(f"Tuned Validation Accuracy:    {final_metrics['accuracy']:.4f}")
    print(f"Tuned Validation Weighted F1: {final_metrics['weighted_f1']:.4f}")

    print("\n--- PER-CLASS RECALL & F1 (TUNED MODEL) ---")
    for cls in CLASS_NAMES:
        rec = final_metrics["per_class_recall"][f"rec_{cls}"]
        f1 = final_metrics["per_class_f1"][f"f1_{cls}"]
        print(f"  - {cls:<10} | Recall: {rec:>6.4f} | F1: {f1:>6.4f}")

    header_col = "Actual / Pred".ljust(14)
    print(f"\n--- CONFUSION MATRIX (TUNED MODEL) ---")
    print(f"{header_col} | " + " | ".join(f"{c:>8}" for c in CLASS_NAMES))
    print("-" * 60)
    for i, actual_class in enumerate(CLASS_NAMES):
        row_str = " | ".join(f"{final_metrics['confusion_matrix'][i][j]:>8,}" for j in range(len(CLASS_NAMES)))
        print(f"{actual_class:<14} | {row_str}")

    print("=" * 80)
    print("Tuning completed successfully. Test set remains completely unseen.")
    print("=" * 80)


def main():
    args = parse_args()
    try:
        run_tuning(
            data_dir=args.data_dir,
            comparison_report=args.comparison_report,
            model_type=args.model_type,
            n_trials=args.n_trials,
            models_dir=args.models_dir,
            reports_dir=args.reports_dir,
            random_seed=args.random_seed,
        )
    except Exception as exc:
        print(f"\n[!] Hyperparameter tuning failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
