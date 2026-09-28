"""
ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) - Quantum Risk Model
Stress Testing, Robustness & Generalization Analysis

Audits model behavior across granular slices, edge cases, and feature combinations:
1. Subgroup Performance Breakdown:
   - algorithm_family
   - protocol
   - deployment_environment
   - environment_context
2. Quantum Specific Slices:
   - quantum_vulnerable (True vs False)
   - HNDL_exposure (Zero vs Active exposure tiers)
   - internet_exposed (True vs False)
   - external_facing (True vs False)
3. Rare Combinations of Categorical Features (Sparse domain permutations)
4. Class Distribution & Imbalance Sensitivity
5. Feature Dominance & Over-Reliance Detection (Feature Importance analysis)
6. Identification of Weakest Slices (lowest Macro F1, lowest Recall)
7. Generates:
   - reports/stress_test.json
   - reports/stress_test.csv
   - reports/subgroup_performance.png
"""

import os
import sys
import json
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
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

CLASS_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CLASS_MAPPING = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
REVERSE_CLASS_MAPPING = {v: k for k, v in CLASS_MAPPING.items()}


def parse_args():
    parser = argparse.ArgumentParser(
        description="ECDAT Quantum Risk Model Stress Testing and Generalization Audit"
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/processed",
        help="Directory containing preprocessed NumPy arrays and raw parquet files",
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
        help="Path to preprocessor metadata JSON",
    )
    parser.add_argument(
        "--reports-dir",
        type=str,
        default="reports",
        help="Directory to save stress test reports and plots",
    )
    return parser.parse_args()


def load_test_environment(
    data_dir: Path, model_path: Path, preprocessor_meta: Path
) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray, np.ndarray, Any, List[str]]:
    """Loads raw test DataFrame, preprocessed feature matrix, target array, and model."""
    raw_path = data_dir / "test_raw.parquet"
    x_path = data_dir / "X_test.npy"
    y_path = data_dir / "y_test.npy"

    if not raw_path.exists() or not x_path.exists() or not y_path.exists():
        raise FileNotFoundError(
            f"Missing required test files in '{data_dir}'. Please verify data/processed contents."
        )

    df_raw = pd.read_parquet(raw_path)
    X_test = np.load(x_path)
    y_test = np.load(y_path)
    model = joblib.load(model_path)

    # Load transformed feature names
    feature_names = []
    if preprocessor_meta.exists():
        with open(preprocessor_meta, "r", encoding="utf-8") as f:
            meta = json.load(f)
            feature_names = meta.get("transformed_feature_names", [])

    print(f"[*] Loaded raw test records: {len(df_raw):,} rows, {len(df_raw.columns)} columns.")
    print(f"[*] Loaded preprocessed test matrix: {X_test.shape}")
    print(f"[*] Loaded model artifact: {model_path.name}\n")

    # Run predictions once for consistency across all sub-analyses
    y_pred = model.predict(X_test)
    if hasattr(y_pred, "squeeze"):
        y_pred = y_pred.squeeze()
    y_pred = y_pred.astype(int)

    return df_raw, X_test, y_test, y_pred, model, feature_names


def calculate_slice_metrics(y_true_sub: np.ndarray, y_pred_sub: np.ndarray) -> Dict[str, Any]:
    """Calculates granular multi-class and per-class metrics for a specific data slice."""
    n_samples = len(y_true_sub)
    if n_samples == 0:
        return {"sample_count": 0, "macro_f1": 0.0, "accuracy": 0.0}

    acc = float(accuracy_score(y_true_sub, y_pred_sub))
    prec_macro = float(precision_score(y_true_sub, y_pred_sub, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_true_sub, y_pred_sub, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_true_sub, y_pred_sub, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_true_sub, y_pred_sub, average="weighted", zero_division=0))

    # Per-class scores
    per_class_f1 = f1_score(y_true_sub, y_pred_sub, average=None, labels=[0, 1, 2, 3], zero_division=0)
    per_class_rec = recall_score(y_true_sub, y_pred_sub, average=None, labels=[0, 1, 2, 3], zero_division=0)
    per_class_prec = precision_score(y_true_sub, y_pred_sub, average=None, labels=[0, 1, 2, 3], zero_division=0)

    # Class distribution in slice
    class_counts = {CLASS_NAMES[i]: int((y_true_sub == i).sum()) for i in range(4)}

    return {
        "sample_count": n_samples,
        "accuracy": round(acc, 4),
        "macro_f1": round(f1_macro, 4),
        "weighted_f1": round(f1_weighted, 4),
        "macro_precision": round(prec_macro, 4),
        "macro_recall": round(rec_macro, 4),
        "class_counts": class_counts,
        "per_class_f1": {CLASS_NAMES[i]: round(float(per_class_f1[i]), 4) for i in range(4)},
        "per_class_recall": {CLASS_NAMES[i]: round(float(per_class_rec[i]), 4) for i in range(4)},
        "per_class_precision": {CLASS_NAMES[i]: round(float(per_class_prec[i]), 4) for i in range(4)},
    }


def analyze_categorical_subgroups(
    df_raw: pd.DataFrame, y_true: np.ndarray, y_pred: np.ndarray, group_col: str
) -> List[Dict[str, Any]]:
    """Evaluates slices for each unique value of a categorical column."""
    results = []
    # Fill nulls with 'Missing / Unspecified'
    series = df_raw[group_col].fillna("Missing / Unspecified").astype(str)
    unique_vals = series.unique()

    for val in unique_vals:
        mask = (series == val).to_numpy()
        metrics = calculate_slice_metrics(y_true[mask], y_pred[mask])
        metrics["dimension"] = group_col
        metrics["subgroup_value"] = str(val)
        results.append(metrics)

    # Sort descending by sample count
    results.sort(key=lambda x: x["sample_count"], reverse=True)
    return results


def analyze_binary_slices(
    df_raw: pd.DataFrame, y_true: np.ndarray, y_pred: np.ndarray, flag_col: str, true_label: str = "True (1)", false_label: str = "False (0)"
) -> List[Dict[str, Any]]:
    """Evaluates binary / indicator flags (e.g. quantum_vulnerable, internet_exposed)."""
    series = df_raw[flag_col].fillna(0).astype(int)
    results = []

    for val, label in [(1, true_label), (0, false_label)]:
        mask = (series == val).to_numpy()
        metrics = calculate_slice_metrics(y_true[mask], y_pred[mask])
        metrics["dimension"] = flag_col
        metrics["subgroup_value"] = label
        results.append(metrics)

    return results


def analyze_hndl_exposure(
    df_raw: pd.DataFrame, y_true: np.ndarray, y_pred: np.ndarray
) -> List[Dict[str, Any]]:
    """Analyzes performance across Harvest Now, Decrypt Later (HNDL) exposure tiers."""
    hndl_series = df_raw["HNDL_exposure"].fillna(0.0).astype(float)
    results = []

    # 1. Zero vs Active HNDL
    zero_mask = (hndl_series == 0.0).to_numpy()
    active_mask = (hndl_series > 0.0).to_numpy()

    m_zero = calculate_slice_metrics(y_true[zero_mask], y_pred[zero_mask])
    m_zero["dimension"] = "HNDL_exposure_category"
    m_zero["subgroup_value"] = "Zero Exposure (HNDL == 0.0)"
    results.append(m_zero)

    m_act = calculate_slice_metrics(y_true[active_mask], y_pred[active_mask])
    m_act["dimension"] = "HNDL_exposure_category"
    m_act["subgroup_value"] = "Active Exposure (HNDL > 0.0)"
    results.append(m_act)

    # 2. Granular Active Tiers
    tiers = [
        ("Low HNDL (0.0 < x <= 0.33)", (hndl_series > 0.0) & (hndl_series <= 0.33)),
        ("Moderate HNDL (0.33 < x <= 0.66)", (hndl_series > 0.33) & (hndl_series <= 0.66)),
        ("Severe HNDL (x > 0.66)", (hndl_series > 0.66)),
    ]

    for label, mask_cond in tiers:
        mask = mask_cond.to_numpy()
        m = calculate_slice_metrics(y_true[mask], y_pred[mask])
        m["dimension"] = "HNDL_exposure_tier"
        m["subgroup_value"] = label
        results.append(m)

    return results


def analyze_rare_combinations(
    df_raw: pd.DataFrame, y_true: np.ndarray, y_pred: np.ndarray
) -> List[Dict[str, Any]]:
    """Identifies and evaluates rare combinations of algorithm_family, protocol, and deployment."""
    combo_series = (
        df_raw["algorithm_family"].astype(str) + " | " +
        df_raw["protocol"].fillna("Unknown").astype(str) + " | " +
        df_raw["deployment_environment"].astype(str)
    )

    counts = combo_series.value_counts()
    # Rare combinations defined as lowest 25th percentile of occurrences (or counts < 25)
    rare_combos = counts[counts < 25].index.tolist()

    rare_mask = combo_series.isin(rare_combos).to_numpy()
    common_mask = (~combo_series.isin(rare_combos)).to_numpy()

    m_rare = calculate_slice_metrics(y_true[rare_mask], y_pred[rare_mask])
    m_rare["dimension"] = "combination_rarity"
    m_rare["subgroup_value"] = f"Rare Triplet Combinations (<25 instances; N={m_rare['sample_count']})"

    m_common = calculate_slice_metrics(y_true[common_mask], y_pred[common_mask])
    m_common["dimension"] = "combination_rarity"
    m_common["subgroup_value"] = f"Standard Combinations (>=25 instances; N={m_common['sample_count']})"

    return [m_rare, m_common]


def analyze_feature_dominance(
    model: Any, feature_names: List[str]
) -> Dict[str, Any]:
    """Inspects feature importances to detect potential single-feature dominance or anomalies."""
    if hasattr(model, "get_feature_importance"):
        importances = model.get_feature_importance()
    elif hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    else:
        return {"note": "Feature importance extraction not supported by model."}

    if len(feature_names) == len(importances):
        feat_df = pd.DataFrame({
            "feature": feature_names,
            "importance": importances,
        }).sort_values("importance", ascending=False)
    else:
        feat_df = pd.DataFrame({
            "feature": [f"feature_{i}" for i in range(len(importances))],
            "importance": importances,
        }).sort_values("importance", ascending=False)

    total_imp = feat_df["importance"].sum()
    if total_imp > 0:
        feat_df["importance_pct"] = (feat_df["importance"] / total_imp) * 100
    else:
        feat_df["importance_pct"] = 0.0

    top_feature = feat_df.iloc[0]["feature"]
    top_pct = float(feat_df.iloc[0]["importance_pct"])
    top_5_pct = float(feat_df.head(5)["importance_pct"].sum())

    # Check for suspicious dominance threshold (> 45% single feature)
    is_dominant = top_pct > 45.0

    return {
        "is_single_feature_dominant": is_dominant,
        "top_feature_name": str(top_feature),
        "top_feature_importance_pct": round(top_pct, 2),
        "top_5_features_cumulative_pct": round(top_5_pct, 2),
        "top_10_features": feat_df.head(10).to_dict(orient="records"),
    }


def plot_subgroup_performance(
    all_slices: List[Dict[str, Any]], output_path: Path
) -> None:
    """Generates a comprehensive multi-panel visualization of subgroup robustness."""
    # Filter slices for key primary dimensions
    plot_dims = [
        "algorithm_family",
        "deployment_environment",
        "environment_context",
        "quantum_vulnerable",
        "HNDL_exposure_category",
    ]

    selected_slices = [
        s for s in all_slices
        if s.get("dimension") in plot_dims and s.get("sample_count", 0) >= 50
    ]

    df_plot = pd.DataFrame(selected_slices)
    df_plot = df_plot.sort_values(["dimension", "macro_f1"], ascending=[True, True])

    fig, ax = plt.subplots(figsize=(12, 8), dpi=300)
    sns.set_theme(style="whitegrid")

    palette = sns.color_palette("mako", len(df_plot))
    bars = ax.barh(
        y=range(len(df_plot)),
        width=df_plot["macro_f1"],
        color=palette,
        edgecolor="#2c3e50",
        height=0.65,
    )

    ax.set_yticks(range(len(df_plot)))
    labels = [
        f"[{row['dimension'].replace('_', ' ').title()}] {row['subgroup_value']} (N={row['sample_count']:,})"
        for _, row in df_plot.iterrows()
    ]
    ax.set_yticklabels(labels, fontsize=8.5)

    # Reference lines
    ax.axvline(0.9299, color="#e74c3c", linestyle="--", lw=1.5, label="Overall Test Set Macro F1 (0.9299)")
    ax.axvline(0.9000, color="#f39c12", linestyle=":", lw=1.2, label="Acceptable Robustness Floor (0.9000)")

    for bar in bars:
        w = bar.get_width()
        ax.text(
            w + 0.005,
            bar.get_y() + bar.get_height() / 2,
            f"{w:.3f}",
            va="center",
            ha="left",
            fontsize=8,
            fontweight="bold",
        )

    ax.set_xlim(0.80, 1.02)
    ax.set_xlabel("Validation / Test Macro F1 Score", fontsize=11, fontweight="bold", labelpad=10)
    ax.set_title(
        "ECDAT Quantum Risk Model - Subgroup Robustness & Generalization Audit\n(Synthetic Dataset Evaluation - Test Set: N=15,000)",
        fontsize=13,
        fontweight="bold",
        pad=15,
    )
    ax.legend(loc="lower left", frameon=True, facecolor="white", framealpha=0.9, fontsize=9)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[OK] Saved subgroup performance plot: {output_path.resolve()}")


def run_stress_test(
    data_dir: str,
    model_path: str,
    preprocessor_meta: str,
    reports_dir: str,
) -> None:
    d_dir = Path(data_dir)
    m_path = Path(model_path)
    meta_path = Path(preprocessor_meta)
    rep_dir = Path(reports_dir)
    rep_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("      ECDAT QUANTUM RISK MODEL - STRESS & GENERALIZATION AUDIT")
    print("=" * 80)
    print(f"Timestamp: {datetime.datetime.now().isoformat()}")
    print(f"Model Artifact: {m_path.resolve()}\n")

    # 1. Load data & model
    df_raw, X_test, y_test, y_pred, model, feature_names = load_test_environment(
        d_dir, m_path, meta_path
    )

    all_slices: List[Dict[str, Any]] = []

    # 2. Subgroup Performance Grouped by Core Categoricals
    print("--- 1. EVALUATING CATEGORICAL SUBGROUPS ---")
    for col in ["algorithm_family", "protocol", "deployment_environment", "environment_context"]:
        sub_results = analyze_categorical_subgroups(df_raw, y_test, y_pred, col)
        all_slices.extend(sub_results)
        print(f"  [OK] Audited {len(sub_results)} subgroups in '{col}'.")

    # 3. Quantum Vulnerable Slice (True vs False)
    print("\n--- 2. EVALUATING QUANTUM ATTACK VULNERABILITY SLICES ---")
    qv_results = analyze_binary_slices(
        df_raw, y_test, y_pred, "quantum_vulnerable", "Quantum Vulnerable (1)", "Quantum Resistant (0)"
    )
    all_slices.extend(qv_results)
    for r in qv_results:
        print(f"  • {r['subgroup_value']:<28} (N={r['sample_count']:>5,}): Macro F1 = {r['macro_f1']:.4f} | Acc = {r['accuracy']:.4f}")

    # 4. HNDL Exposure Slices
    print("\n--- 3. EVALUATING HARVEST NOW, DECRYPT LATER (HNDL) EXPOSURE SLICES ---")
    hndl_results = analyze_hndl_exposure(df_raw, y_test, y_pred)
    all_slices.extend(hndl_results)
    for r in hndl_results:
        print(f"  • {r['subgroup_value']:<36} (N={r['sample_count']:>5,}): Macro F1 = {r['macro_f1']:.4f} | Acc = {r['accuracy']:.4f}")

    # 5. Network Exposure Flags (Internet Exposed & External Facing)
    print("\n--- 4. EVALUATING NETWORK EXPOSURE FLAGS ---")
    net_results = []
    net_results.extend(analyze_binary_slices(df_raw, y_test, y_pred, "internet_exposed", "Internet Exposed (1)", "Internal Only (0)"))
    net_results.extend(analyze_binary_slices(df_raw, y_test, y_pred, "external_facing", "External Facing (1)", "Internal Facing (0)"))
    all_slices.extend(net_results)
    for r in net_results:
        print(f"  • [{r['dimension']}] {r['subgroup_value']:<24} (N={r['sample_count']:>5,}): Macro F1 = {r['macro_f1']:.4f} | Acc = {r['accuracy']:.4f}")

    # 6. Rare Combinations of Categorical Features
    print("\n--- 5. EVALUATING RARE CATEGORICAL COMBINATIONS ---")
    rare_results = analyze_rare_combinations(df_raw, y_test, y_pred)
    all_slices.extend(rare_results)
    for r in rare_results:
        print(f"  • {r['subgroup_value']:<60}: Macro F1 = {r['macro_f1']:.4f} | Acc = {r['accuracy']:.4f}")

    # 7. Feature Dominance & Importances
    print("\n--- 6. FEATURE DOMINANCE & OVER-RELIANCE AUDIT ---")
    dominance_audit = analyze_feature_dominance(model, feature_names)
    print(f"  • Top Feature: '{dominance_audit.get('top_feature_name')}' ({dominance_audit.get('top_feature_importance_pct')}%)")
    print(f"  • Top 5 Features Cumulative Weight: {dominance_audit.get('top_5_features_cumulative_pct')}%")
    if dominance_audit.get("is_single_feature_dominant"):
        print("  [!] WARNING: Suspiciously high single-feature dominance detected (>45%).")
    else:
        print("  [OK] Balanced feature contribution: No single feature displays suspicious monopoly (>45%).")

    # 8. Identify Weakest Subgroups & Class-Specific Vulnerabilities
    valid_slices = [s for s in all_slices if s.get("sample_count", 0) >= 30]
    valid_slices_sorted_f1 = sorted(valid_slices, key=lambda x: x["macro_f1"])
    valid_slices_sorted_crit_rec = sorted(valid_slices, key=lambda x: x["per_class_recall"]["CRITICAL"])

    worst_5_f1 = valid_slices_sorted_f1[:5]
    worst_5_crit_rec = valid_slices_sorted_crit_rec[:5]

    # 9. Save CSV Report
    csv_rows = []
    for s in all_slices:
        row = {
            "dimension": s["dimension"],
            "subgroup_value": s["subgroup_value"],
            "sample_count": s["sample_count"],
            "macro_f1": s["macro_f1"],
            "weighted_f1": s["weighted_f1"],
            "accuracy": s["accuracy"],
            "macro_precision": s["macro_precision"],
            "macro_recall": s["macro_recall"],
            "f1_LOW": s.get("per_class_f1", {}).get("LOW"),
            "f1_MEDIUM": s.get("per_class_f1", {}).get("MEDIUM"),
            "f1_HIGH": s.get("per_class_f1", {}).get("HIGH"),
            "f1_CRITICAL": s.get("per_class_f1", {}).get("CRITICAL"),
            "rec_LOW": s.get("per_class_recall", {}).get("LOW"),
            "rec_MEDIUM": s.get("per_class_recall", {}).get("MEDIUM"),
            "rec_HIGH": s.get("per_class_recall", {}).get("HIGH"),
            "rec_CRITICAL": s.get("per_class_recall", {}).get("CRITICAL"),
        }
        csv_rows.append(row)

    df_csv = pd.DataFrame(csv_rows)
    csv_out_path = rep_dir / "stress_test.csv"
    df_csv.to_csv(csv_out_path, index=False, encoding="utf-8")
    print(f"\n[OK] Saved stress test CSV report to: {csv_out_path.resolve()}")

    # 10. Save JSON Report
    json_payload = {
        "metadata": {
            "audited_at": datetime.datetime.now().isoformat(),
            "model_path": str(m_path.resolve()),
            "evaluation_dataset": "test_raw.parquet (15,000 samples)",
            "total_slices_evaluated": len(all_slices),
        },
        "feature_dominance_audit": dominance_audit,
        "worst_performing_subgroups_by_macro_f1": worst_5_f1,
        "worst_performing_subgroups_by_critical_recall": worst_5_crit_rec,
        "all_subgroups": all_slices,
    }

    json_out_path = rep_dir / "stress_test.json"
    with open(json_out_path, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2)
    print(f"[OK] Saved stress test JSON report to: {json_out_path.resolve()}")

    # 11. Plot Subgroup Performance Figure
    plot_subgroup_performance(all_slices, rep_dir / "subgroup_performance.png")

    # 12. Summary Tables
    print("\n" + "=" * 88)
    print("                     WORST-PERFORMING SUBGROUPS (BY MACRO F1)")
    print("=" * 88)
    print(f"{'Dimension':<25} | {'Subgroup':<25} | {'Count':<7} | {'Macro F1':<9} | {'Crit Rec':<9} | {'Acc':<7}")
    print("-" * 88)
    for s in worst_5_f1:
        print(
            f"{s['dimension']:<25} | {s['subgroup_value'][:25]:<25} | {s['sample_count']:>6,} | "
            f"{s['macro_f1']:>8.4f} | {s['per_class_recall']['CRITICAL']:>8.4f} | {s['accuracy']:>6.4f}"
        )
    print("=" * 88)

    print("\n" + "=" * 88)
    print("             SUBGROUPS WITH LOWEST CRITICAL-TIER RECALL (SAFETY AUDIT)")
    print("=" * 88)
    print(f"{'Dimension':<25} | {'Subgroup':<25} | {'Count':<7} | {'Crit Rec':<9} | {'Crit F1':<9} | {'Macro F1':<9}")
    print("-" * 88)
    for s in worst_5_crit_rec:
        print(
            f"{s['dimension']:<25} | {s['subgroup_value'][:25]:<25} | {s['sample_count']:>6,} | "
            f"{s['per_class_recall']['CRITICAL']:>8.4f} | {s['per_class_f1']['CRITICAL']:>8.4f} | {s['macro_f1']:>8.4f}"
        )
    print("=" * 88)


def main():
    args = parse_args()
    try:
        run_stress_test(
            data_dir=args.data_dir,
            model_path=args.model_path,
            preprocessor_meta=args.preprocessor_meta,
            reports_dir=args.reports_dir,
        )
    except Exception as exc:
        print(f"\n[!] Stress test execution failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
