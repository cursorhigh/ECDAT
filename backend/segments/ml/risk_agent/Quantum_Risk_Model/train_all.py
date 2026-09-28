"""
ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) - Quantum Risk Model
Master End-to-End Orchestrator: train_all.py

Executes the complete machine learning lifecycle sequentially and reproducibly:
1. Dataset Audit (src/data_audit.py)
2. Preprocessing & Stratified Splitting (src/preprocess.py)
3. Baseline Training (src/train_baseline.py)
4. Candidate Model Training & Comparison (src/train_models.py)
5. Hyperparameter Tuning (src/tune_model.py)
6. Final Test Evaluation on Untouched Test Set (src/evaluate.py)
7. Robustness & Generalization Stress Testing (src/stress_test.py)
8. Global & Local SHAP Explainability (src/explain.py)
9. Production Release Packaging & Schema Export (src/export_model.py)
10. Automated Validation Tests (pytest -v)

Guarantees:
- Fixed random seed across all steps.
- Strict prevention of data leakage & identifier usage.
- Explicit versioning and non-destructive archival.
- Loud failure if any required artifact is missing.
- Verification that test data is never used during training/tuning.
"""

import os
import sys
import json
import time
import shutil
import argparse
import subprocess
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Safe stdout on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def parse_args():
    parser = argparse.ArgumentParser(
        description="ECDAT Quantum Risk Model Master Orchestration Pipeline"
    )
    parser.add_argument(
        "--data-file",
        type=str,
        default="data/ECDAT_Industry_Quantum_Risk_Dataset_100K.xlsx",
        help="Path to the original Excel dataset workbook",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=42,
        help="Deterministic random seed across all pipeline stages",
    )
    parser.add_argument(
        "--n-tuning-trials",
        type=int,
        default=20,
        help="Number of Bayesian optimization trials for model tuning",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip final pytest test suite execution",
    )
    return parser.parse_args()


def archive_previous_release(output_final_dir: Path) -> None:
    """Safely archives any existing release package without silent data destruction."""
    if output_final_dir.exists() and any(output_final_dir.iterdir()):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_dir = output_final_dir.parent / f"final_archive_{timestamp}"
        print(f"[*] Archiving previous release to: {archive_dir.resolve()}...")
        shutil.copytree(output_final_dir, archive_dir)
        print("[OK] Previous release safely archived.\n")


def execute_stage(
    stage_name: str,
    command: List[str],
    required_outputs: List[Path],
) -> float:
    """
    Executes a single pipeline stage via subprocess, streaming logs and verifying expected artifacts.
    """
    print("\n" + "=" * 80)
    print(f"  PHASE: {stage_name.upper()}")
    print("=" * 80)
    print(f"Executing: {' '.join(command)}")
    print(f"Timestamp: {datetime.datetime.now().isoformat()}\n")

    t_start = time.time()
    result = subprocess.run(command, text=True)
    elapsed = time.time() - t_start

    if result.returncode != 0:
        raise RuntimeError(
            f"\n[FATAL] Pipeline failed during phase '{stage_name}' (Exit Code {result.returncode})."
        )

    # Verify that all expected output files exist
    missing_artifacts = [p for p in required_outputs if not p.exists()]
    if missing_artifacts:
        raise FileNotFoundError(
            f"\n[FATAL] Phase '{stage_name}' succeeded but expected artifact(s) were NOT created:\n"
            + "\n".join(f"  - {p.resolve()}" for p in missing_artifacts)
        )

    print(f"\n[OK] Phase '{stage_name}' completed successfully in {elapsed:.2f}s.")
    return elapsed


def run_pipeline():
    args = parse_args()
    python_bin = sys.executable

    print("=" * 80)
    print("      ECDAT QUANTUM RISK CLASSIFIER - MASTER TRAINING PIPELINE")
    print("=" * 80)
    print(f"Dataset:        {Path(args.data_file).resolve()}")
    print(f"Random Seed:    {args.random_seed}")
    print(f"Tuning Budget:  {args.n_tuning_trials} Bayesian Optimization Trials")
    print(f"Timestamp:      {datetime.datetime.now().isoformat()}")
    print("=" * 80)

    # 0. Archive existing release
    final_models_dir = Path("models/final")
    archive_previous_release(final_models_dir)

    total_start_time = time.time()

    # Stage 1: Dataset Audit
    execute_stage(
        stage_name="1. Dataset Inspection & Audit",
        command=[
            python_bin,
            "src/data_audit.py",
            "--data-path",
            args.data_file,
            "--output-dir",
            "reports",
        ],
        required_outputs=[
            Path("reports/data_audit.json"),
            Path("reports/data_dictionary_detected.csv"),
        ],
    )

    # Stage 2: Data Preprocessing & Stratified Splitting
    execute_stage(
        stage_name="2. Preprocessing & Stratified Splitting (70/15/15)",
        command=[
            python_bin,
            "src/preprocess.py",
            "--data-path",
            args.data_file,
            "--random-seed",
            str(args.random_seed),
        ],
        required_outputs=[
            Path("data/processed/train_processed.npz"),
            Path("data/processed/val_processed.npz"),
            Path("data/processed/test_processed.npz"),
            Path("data/processed/X_train.npy"),
            Path("data/processed/y_train.npy"),
            Path("data/processed/X_val.npy"),
            Path("data/processed/y_val.npy"),
            Path("data/processed/X_test.npy"),
            Path("data/processed/y_test.npy"),
            Path("models/preprocessor/preprocessor.joblib"),
            Path("models/preprocessor/metadata.json"),
            Path("reports/split_distribution.json"),
        ],
    )

    # Stage 3: Baseline Model Training
    execute_stage(
        stage_name="3. Baseline Model Training",
        command=[
            python_bin,
            "src/train_baseline.py",
            "--random-seed",
            str(args.random_seed),
        ],
        required_outputs=[
            Path("reports/baseline_metrics.json"),
            Path("models/baseline/dummy_stratified.joblib"),
        ],
    )

    # Stage 4: Candidate Model Comparison
    execute_stage(
        stage_name="4. Candidate Model Comparison (RF, XGBoost, CatBoost)",
        command=[
            python_bin,
            "src/train_models.py",
            "--random-seed",
            str(args.random_seed),
        ],
        required_outputs=[
            Path("reports/model_comparison.json"),
            Path("reports/model_comparison.csv"),
            Path("models/candidates/catboost/model.joblib"),
            Path("models/candidates/xgboost/model.joblib"),
            Path("models/candidates/random_forest/model.joblib"),
        ],
    )

    # Stage 5: Hyperparameter Tuning
    execute_stage(
        stage_name="5. Hyperparameter Tuning (Bayesian Optimization)",
        command=[
            python_bin,
            "src/tune_model.py",
            "--n-trials",
            str(args.n_tuning_trials),
            "--random-seed",
            str(args.random_seed),
        ],
        required_outputs=[
            Path("reports/tuning_results.json"),
            Path("reports/tuning_results.csv"),
            Path("models/tuned/model.joblib"),
            Path("models/tuned/tuned_model_info.json"),
        ],
    )

    # Stage 6: Final Test Set Evaluation
    execute_stage(
        stage_name="6. Final Unbiased Test Set Evaluation",
        command=[
            python_bin,
            "src/evaluate.py",
        ],
        required_outputs=[
            Path("reports/final_metrics.json"),
            Path("reports/final_classification_report.json"),
            Path("reports/final_confusion_matrix.png"),
            Path("reports/final_roc_curve.png"),
        ],
    )

    # Stage 7: Subgroup Robustness & Generalization Stress Test
    execute_stage(
        stage_name="7. Subgroup Robustness & Generalization Audit",
        command=[
            python_bin,
            "src/stress_test.py",
        ],
        required_outputs=[
            Path("reports/stress_test.json"),
            Path("reports/stress_test.csv"),
            Path("reports/subgroup_performance.png"),
        ],
    )

    # Stage 8: Model Explainability & TreeSHAP Attributions
    execute_stage(
        stage_name="8. Model Explainability & SHAP Attributions",
        command=[
            python_bin,
            "src/explain.py",
        ],
        required_outputs=[
            Path("reports/shap/sample_explanations.json"),
            Path("reports/shap/global_shap_bar.png"),
            Path("reports/shap/global_shap_summary.png"),
        ],
    )

    # Stage 9: Packaging & Schema Export
    execute_stage(
        stage_name="9. Production Release Packaging & Schema Export",
        command=[
            python_bin,
            "src/export_model.py",
        ],
        required_outputs=[
            Path("models/final/model.joblib"),
            Path("models/final/preprocessor.joblib"),
            Path("models/final/feature_schema.json"),
            Path("models/final/model_metadata.json"),
            Path("models/final/target_mapping.json"),
        ],
    )

    # Stage 10: Validation Test Suite
    if not args.skip_tests:
        execute_stage(
            stage_name="10. Automated Validation Test Suite (pytest)",
            command=[
                python_bin,
                "-m",
                "pytest",
                "-v",
            ],
            required_outputs=[],
        )

    total_elapsed = time.time() - total_start_time

    # Load finalized release metrics for summary display
    with open("models/final/model_metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    with open("reports/final_metrics.json", "r", encoding="utf-8") as f:
        test_metrics = json.load(f)

    model_name = meta.get("model_architecture", "CatBoostClassifier")
    val_macro_f1 = meta["performance_benchmarks"]["validation_metrics"]["macro_f1"]
    test_macro_f1 = test_metrics["overall_metrics"]["macro_f1"]
    test_acc = test_metrics["overall_metrics"]["accuracy"]
    crit_recall = test_metrics["per_class_metrics"]["CRITICAL"]["recall"]
    final_model_path = Path("models/final/model.joblib").resolve()

    # Exact requested output block
    print("\n" + "=" * 80)
    print("MODEL TRAINING COMPLETE\n")
    print(f"Model:\n{model_name}\n")
    print(f"Validation Macro F1:\n{val_macro_f1:.4f}\n")
    print(f"Test Macro F1:\n{test_macro_f1:.4f}\n")
    print(f"Test Accuracy:\n{test_acc:.4f} ({test_acc*100:.2f}%)\n")
    print(f"CRITICAL Recall:\n{crit_recall:.4f} ({crit_recall*100:.2f}%)\n")
    print(f"Model saved to:\n{final_model_path}")
    print("=" * 80)
    print(f"\nTotal Pipeline Execution Time: {total_elapsed:.2f}s ({total_elapsed/60:.2f} minutes).")


if __name__ == "__main__":
    run_pipeline()
