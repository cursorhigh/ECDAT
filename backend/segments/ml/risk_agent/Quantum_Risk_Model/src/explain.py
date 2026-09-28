"""
ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) - Quantum Risk Model
Model Explainability & SHAP Feature Attribution Pipeline

Provides transparent, verifiable feature attributions using TreeSHAP:
1. Global Model-Based Feature Importance (Split & Gain based).
2. Global SHAP Feature Importance (Mean Absolute SHAP values across all risk classes).
3. SHAP Summary Plots (Distribution of feature effects across the dataset).
4. Individual Sample Prediction Explanations for representative risk tiers:
   - LOW Risk Representative Sample
   - MEDIUM Risk Representative Sample
   - HIGH Risk Representative Sample
   - CRITICAL Risk Representative Sample
5. For each sample:
   - Predicted class & full class probability vector
   - Top features increasing contribution toward the predicted class
   - Top features decreasing contribution (mitigating risk or pulling away)
   - Publication-quality waterfall/bar attribution visualizations
6. Structured JSON Export:
   - reports/shap/sample_explanations.json
7. Visualizations Saved Under:
   - reports/shap/

Explicit Methodological Note:
SHAP values quantify statistical feature contributions to the mathematical model prediction,
not proven empirical causality.
"""

import os
import sys
import json
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

# Use non-interactive backend for headless execution
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

import joblib
import shap
import numpy as np
import pandas as pd
import catboost

CLASS_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CLASS_MAPPING = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
REVERSE_CLASS_MAPPING = {v: k for k, v in CLASS_MAPPING.items()}


def parse_args():
    parser = argparse.ArgumentParser(
        description="ECDAT Quantum Risk Model Explainability Tool"
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/processed",
        help="Directory containing preprocessed arrays and raw parquet files",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="models/tuned/model.joblib",
        help="Path to the trained / tuned model artifact",
    )
    parser.add_argument(
        "--preprocessor-meta",
        type=str,
        default="models/preprocessor/metadata.json",
        help="Path to preprocessor feature metadata JSON",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports/shap",
        help="Directory to store SHAP plots and explanation JSON",
    )
    parser.add_argument(
        "--n-background",
        type=int,
        default=2000,
        help="Number of test samples to use for global SHAP analysis",
    )
    return parser.parse_args()


def load_explainability_environment(
    data_dir: Path, model_path: Path, preprocessor_meta: Path
) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray, Any, List[str]]:
    """Loads raw test data, preprocessed matrix, model, and feature names."""
    raw_path = data_dir / "test_raw.parquet"
    x_path = data_dir / "X_test.npy"
    y_path = data_dir / "y_test.npy"

    if not raw_path.exists() or not x_path.exists() or not y_path.exists():
        raise FileNotFoundError(f"Missing required test files in: {data_dir.resolve()}")

    df_raw = pd.read_parquet(raw_path)
    X_test = np.load(x_path)
    y_test = np.load(y_path)
    model = joblib.load(model_path)

    # Feature names
    feature_names = []
    if preprocessor_meta.exists():
        with open(preprocessor_meta, "r", encoding="utf-8") as f:
            meta = json.load(f)
            feature_names = meta.get("transformed_feature_names", [])

    if not feature_names:
        feature_names = [f"feature_{i}" for i in range(X_test.shape[1])]

    print(f"[*] Loaded model: {model_path.name}")
    print(f"[*] Loaded test data: {X_test.shape[0]:,} samples, {len(feature_names)} features.")
    return df_raw, X_test, y_test, model, feature_names


def compute_shap_values(model: Any, X: np.ndarray) -> np.ndarray:
    """
    Computes TreeSHAP values efficiently.
    Returns array of shape: (n_samples, n_features, n_classes).
    """
    if hasattr(model, "get_feature_importance"):
        pool = catboost.Pool(X)
        raw_shap = model.get_feature_importance(data=pool, type="ShapValues")
        # raw_shap shape is (N, C, F + 1) where last column is bias
        shap_values = np.transpose(raw_shap[:, :, :-1], (0, 2, 1))
        return shap_values
    else:
        explainer = shap.TreeExplainer(model)
        sv = explainer.shap_values(X)
        if isinstance(sv, list):
            sv = np.stack(sv, axis=-1)
        return sv


def clean_feature_display_name(name: str) -> str:
    """Creates a clean human-readable label from transformed column names."""
    if name.startswith("num__"):
        return name[5:].replace("_", " ").title()
    elif name.startswith("bin__"):
        return name[5:].replace("_", " ").title() + " (Flag)"
    elif name.startswith("cat__"):
        parts = name[5:].split("_", 1)
        if len(parts) == 2:
            return f"{parts[0].replace('_', ' ').title()}: {parts[1]}"
        return name[5:].replace("_", " ")
    return name.replace("_", " ")


def compute_global_shap_importance(
    shap_values: np.ndarray, feature_names: List[str]
) -> pd.DataFrame:
    """
    Computes mean absolute SHAP values across all samples and all classes.
    shap_values shape: (n_samples, n_features, n_classes)
    """
    mean_abs_shap = np.mean(np.abs(shap_values), axis=(0, 2))
    clean_names = [clean_feature_display_name(f) for f in feature_names]

    df = pd.DataFrame({
        "feature_raw": feature_names,
        "feature_display": clean_names,
        "mean_abs_shap": mean_abs_shap,
    }).sort_values("mean_abs_shap", ascending=False)

    df["importance_pct"] = (df["mean_abs_shap"] / df["mean_abs_shap"].sum()) * 100
    return df


def plot_global_shap_bar(df_importance: pd.DataFrame, output_path: Path, top_n: int = 15) -> None:
    """Plots top global features by mean absolute SHAP value."""
    top_df = df_importance.head(top_n).sort_values("mean_abs_shap", ascending=True)

    fig, ax = plt.subplots(figsize=(10, 7), dpi=300)
    sns.set_theme(style="whitegrid")

    colors = sns.color_palette("viridis", len(top_df))
    bars = ax.barh(
        top_df["feature_display"],
        top_df["mean_abs_shap"],
        color=colors,
        edgecolor="#2c3e50",
        height=0.65,
    )

    for bar in bars:
        w = bar.get_width()
        ax.text(
            w + 0.005,
            bar.get_y() + bar.get_height() / 2,
            f"{w:.3f}",
            va="center",
            ha="left",
            fontsize=9,
            fontweight="bold",
        )

    ax.set_xlabel("Mean |SHAP Value| (Average Impact on Risk Level Log-Odds)", fontsize=11, fontweight="bold", labelpad=10)
    ax.set_title(
        f"Top {top_n} Global Feature Contributions (SHAP Analysis)\nECDAT Quantum Risk Model (N=2,000 Test Subsample)",
        fontsize=13,
        fontweight="bold",
        pad=15,
    )
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[OK] Saved global SHAP bar plot: {output_path.resolve()}")


def plot_multiclass_shap_summary(
    shap_values: np.ndarray, X_sample: np.ndarray, feature_names: List[str], output_path: Path
) -> None:
    """Plots SHAP summary dot plot for highest severity class (CRITICAL)."""
    clean_names = [clean_feature_display_name(f) for f in feature_names]
    shap_crit = shap_values[:, :, 3]

    plt.figure(figsize=(11, 7.5), dpi=300)
    shap.summary_plot(
        shap_crit,
        X_sample,
        feature_names=clean_names,
        max_display=15,
        show=False,
    )
    plt.title(
        "SHAP Value Distribution - CRITICAL Risk Tier\n(Features Contributing to the Model Prediction)",
        fontsize=13,
        fontweight="bold",
        pad=15,
    )
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[OK] Saved SHAP summary plot: {output_path.resolve()}")


def find_representative_samples(
    df_raw: pd.DataFrame, X_test: np.ndarray, y_test: np.ndarray, model: Any
) -> Dict[str, Dict[str, Any]]:
    """Selects high-confidence, archetypal samples for each of the 4 risk classes."""
    probs = model.predict_proba(X_test)
    preds = model.predict(X_test)
    if hasattr(preds, "squeeze"):
        preds = preds.squeeze()
    preds = preds.astype(int)

    representatives = {}

    for cls_name, cls_idx in CLASS_MAPPING.items():
        match_mask = (y_test == cls_idx) & (preds == cls_idx)
        matching_indices = np.where(match_mask)[0]

        if len(matching_indices) == 0:
            matching_indices = np.where(preds == cls_idx)[0]

        confidences = probs[matching_indices, cls_idx]
        best_local_idx = np.argmax(confidences)
        global_idx = int(matching_indices[best_local_idx])

        representatives[cls_name] = {
            "test_sample_index": global_idx,
            "true_class": REVERSE_CLASS_MAPPING[int(y_test[global_idx])],
            "predicted_class": cls_name,
            "confidence": float(probs[global_idx, cls_idx]),
            "class_probabilities": {
                CLASS_NAMES[i]: round(float(probs[global_idx, i]), 4) for i in range(4)
            },
            "raw_attributes": df_raw.iloc[global_idx].to_dict(),
        }

    return representatives


def explain_individual_sample(
    sample_info: Dict[str, Any],
    shap_vals_sample: np.ndarray,
    feature_names: List[str],
    output_plot_path: Path,
) -> Dict[str, Any]:
    """
    Computes top positive and negative SHAP contributors for a single sample.
    shap_vals_sample shape: (n_features, n_classes)
    """
    pred_cls_name = sample_info["predicted_class"]
    pred_cls_idx = CLASS_MAPPING[pred_cls_name]

    class_shap = shap_vals_sample[:, pred_cls_idx]
    clean_names = [clean_feature_display_name(f) for f in feature_names]

    df_sample = pd.DataFrame({
        "feature_raw": feature_names,
        "feature_display": clean_names,
        "shap_value": class_shap,
    })

    df_increasing = df_sample[df_sample["shap_value"] > 0].sort_values("shap_value", ascending=False)
    df_decreasing = df_sample[df_sample["shap_value"] < 0].sort_values("shap_value", ascending=True)

    top_increasing = [
        {
            "feature": row["feature_display"],
            "raw_feature": row["feature_raw"],
            "shap_contribution": round(float(row["shap_value"]), 4),
        }
        for _, row in df_increasing.head(5).iterrows()
    ]

    top_decreasing = [
        {
            "feature": row["feature_display"],
            "raw_feature": row["feature_raw"],
            "shap_contribution": round(float(row["shap_value"]), 4),
        }
        for _, row in df_decreasing.head(5).iterrows()
    ]

    # Plot sample attribution bar chart
    top_plot_df = pd.concat([df_increasing.head(5), df_decreasing.head(5)]).sort_values("shap_value", ascending=True)

    fig, ax = plt.subplots(figsize=(9, 5.5), dpi=300)
    sns.set_theme(style="whitegrid")

    bar_colors = ["#e74c3c" if v > 0 else "#27ae60" for v in top_plot_df["shap_value"]]
    bars = ax.barh(
        top_plot_df["feature_display"],
        top_plot_df["shap_value"],
        color=bar_colors,
        edgecolor="#2c3e50",
        height=0.6,
    )

    ax.axvline(0, color="black", linewidth=1.0, linestyle="-")
    ax.set_xlabel(f"SHAP Attribution toward '{pred_cls_name}' Log-Odds", fontsize=10.5, fontweight="bold", labelpad=8)
    ax.set_title(
        f"Local Feature Attribution - {pred_cls_name} Risk Sample (Index #{sample_info['test_sample_index']})\n"
        f"Predicted: {pred_cls_name} (Confidence: {sample_info['confidence']*100:.1f}%) | "
        f"Algorithm: {sample_info['raw_attributes'].get('algorithm', 'N/A')}",
        fontsize=11.5,
        fontweight="bold",
        pad=12,
    )

    for bar in bars:
        w = bar.get_width()
        offset = 0.01 if w >= 0 else -0.01
        ha = "left" if w >= 0 else "right"
        ax.text(
            w + offset,
            bar.get_y() + bar.get_height() / 2,
            f"{w:+.3f}",
            va="center",
            ha=ha,
            fontsize=8.5,
            fontweight="bold",
        )

    plt.tight_layout()
    plt.savefig(output_plot_path, dpi=300)
    plt.close()
    print(f"[OK] Saved sample explanation plot: {output_plot_path.resolve()}")

    return {
        "sample_index": sample_info["test_sample_index"],
        "predicted_class": pred_cls_name,
        "true_class": sample_info["true_class"],
        "confidence": round(sample_info["confidence"], 4),
        "class_probabilities": sample_info["class_probabilities"],
        "cryptographic_profile": {
            "algorithm": sample_info["raw_attributes"].get("algorithm"),
            "algorithm_family": sample_info["raw_attributes"].get("algorithm_family"),
            "protocol": sample_info["raw_attributes"].get("protocol"),
            "deployment_environment": sample_info["raw_attributes"].get("deployment_environment"),
            "HNDL_exposure": sample_info["raw_attributes"].get("HNDL_exposure"),
            "quantum_vulnerable": sample_info["raw_attributes"].get("quantum_vulnerable"),
            "data_sensitivity": sample_info["raw_attributes"].get("data_sensitivity"),
            "business_criticality": sample_info["raw_attributes"].get("business_criticality"),
        },
        "strongest_features_increasing_risk": top_increasing,
        "strongest_features_decreasing_risk": top_decreasing,
    }


def run_explainability(
    data_dir: str,
    model_path: str,
    preprocessor_meta: str,
    output_dir: str,
    n_background: int,
) -> None:
    d_dir = Path(data_dir)
    m_path = Path(model_path)
    meta_path = Path(preprocessor_meta)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("      ECDAT QUANTUM RISK MODEL - SHAP EXPLAINABILITY PIPELINE")
    print("=" * 80)
    print(f"Timestamp: {datetime.datetime.now().isoformat()}")
    print(f"Output Directory: {out_dir.resolve()}\n")

    # 1. Load test data & model
    df_raw, X_test, y_test, model, feature_names = load_explainability_environment(
        d_dir, m_path, meta_path
    )

    # 2. Compute TreeSHAP values on representative subsample
    subsample_n = min(n_background, len(X_test))
    print(f"[*] Computing TreeSHAP values on {subsample_n:,} test samples...")
    X_sub = X_test[:subsample_n]

    shap_values = compute_shap_values(model, X_sub)
    print(f"[OK] Computed TreeSHAP values with shape: {shap_values.shape}\n")

    # 3. Global Feature Importance Analysis
    print("--- 1. GLOBAL SHAP FEATURE IMPORTANCE ---")
    df_global_imp = compute_global_shap_importance(shap_values, feature_names)
    print(f"{'Rank':<5} | {'Feature':<36} | {'Mean |SHAP|':<12} | {'Relative %':<10}")
    print("-" * 72)
    for idx, row in df_global_imp.head(10).reset_index().iterrows():
        print(f"{idx+1:<5} | {row['feature_display']:<36} | {row['mean_abs_shap']:>11.4f} | {row['importance_pct']:>9.2f}%")

    # 4. Generate Global Visualizations
    plot_global_shap_bar(df_global_imp, out_dir / "global_shap_bar.png", top_n=15)
    plot_multiclass_shap_summary(shap_values, X_sub, feature_names, out_dir / "global_shap_summary.png")

    # 5. Identify and Explain Representative Samples
    print("\n--- 2. REPRESENTATIVE RISK TIER SAMPLE EXPLANATIONS ---")
    reps = find_representative_samples(df_raw, X_test, y_test, model)
    sample_explanations_list = []

    for cls_name in CLASS_NAMES:
        sample_meta = reps[cls_name]
        g_idx = sample_meta["test_sample_index"]

        single_x = X_test[g_idx : g_idx + 1]
        single_shap = compute_shap_values(model, single_x)[0]

        plot_path = out_dir / f"sample_explanation_{cls_name}.png"
        explanation = explain_individual_sample(
            sample_meta, single_shap, feature_names, plot_path
        )
        sample_explanations_list.append(explanation)

        print(f"\n[Sample: {cls_name} Risk] -> Index #{g_idx} (Confidence: {sample_meta['confidence']*100:.1f}%)")
        print(f"  Algorithm: {sample_meta['raw_attributes'].get('algorithm')} ({sample_meta['raw_attributes'].get('algorithm_family')})")
        print("  Top Contributing Features (+):")
        for f_item in explanation["strongest_features_increasing_risk"][:3]:
            print(f"    + {f_item['feature']} (+{f_item['shap_contribution']:.4f})")
        print("  Top Mitigating Features (-):")
        for f_item in explanation["strongest_features_decreasing_risk"][:3]:
            print(f"    - {f_item['feature']} ({f_item['shap_contribution']:.4f})")

    # 6. Save Structured JSON
    structured_export = {
        "metadata": {
            "generated_at": datetime.datetime.now().isoformat(),
            "explainer_type": "TreeSHAP",
            "model_evaluated": str(m_path.name),
            "disclaimer": "SHAP values quantify statistical feature contributions to the mathematical model prediction, not proven empirical causality.",
        },
        "global_shap_importance_top20": df_global_imp.head(20).to_dict(orient="records"),
        "representative_sample_explanations": sample_explanations_list,
    }

    json_export_path = out_dir / "sample_explanations.json"
    with open(json_export_path, "w", encoding="utf-8") as f:
        json.dump(structured_export, f, indent=2)
    print(f"\n[OK] Saved structured explanations JSON to: {json_export_path.resolve()}")

    print("\n" + "=" * 80)
    print("                 EXPLAINABILITY AUDIT COMPLETED")
    print("=" * 80)
    print(
        "All visual and structured SHAP artifacts generated successfully.\n"
        "Interpretation Note: Described strictly as 'features contributing to the model prediction'."
    )
    print("=" * 80)


def main():
    args = parse_args()
    try:
        run_explainability(
            data_dir=args.data_dir,
            model_path=args.model_path,
            preprocessor_meta=args.preprocessor_meta,
            output_dir=args.output_dir,
            n_background=args.n_background,
        )
    except Exception as exc:
        print(f"\n[!] Explainability pipeline failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
