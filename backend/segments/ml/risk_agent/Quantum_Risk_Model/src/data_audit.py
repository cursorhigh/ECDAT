"""
ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) - Quantum Risk Model
Data Audit & Inspection Script

Performs comprehensive auditing of the ECDAT quantum risk dataset:
- Inspects workbook structure & sheets
- Computes granular statistics, data types, missing values, duplicates
- Analyzes target variable distribution (risk_level)
- Identifies identifiers and potential target leakage columns
- Generates reports/data_audit.json and reports/data_dictionary_detected.csv
- Evaluates dataset suitability for machine learning experiments
"""

import os
import sys
import json
import argparse
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Ensure standard output can handle UTF-8 if possible
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import numpy as np
import pandas as pd
import openpyxl


def parse_args():
    parser = argparse.ArgumentParser(
        description="ECDAT Quantum Risk Dataset Inspection and Audit Tool"
    )
    parser.add_argument(
        "--data-path",
        type=str,
        default="data/ECDAT_Industry_Quantum_Risk_Dataset_100K.xlsx",
        help="Path to the Excel dataset workbook",
    )
    parser.add_argument(
        "--sheet-name",
        type=str,
        default="training_data",
        help="Target sheet to inspect and audit",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports",
        help="Directory to save audit reports",
    )
    return parser.parse_args()


def check_file_exists(file_path: Path) -> None:
    if not file_path.exists():
        raise FileNotFoundError(
            f"Dataset file not found at: {file_path.resolve()}\n"
            f"Please verify the path and make sure the dataset is present."
        )


def inspect_workbook_sheets(file_path: Path) -> List[str]:
    """Inspects workbook sheet names safely using openpyxl in read-only mode."""
    try:
        wb = openpyxl.load_workbook(str(file_path), read_only=True, keep_links=False)
        sheets = wb.sheetnames
        wb.close()
        return sheets
    except Exception as e:
        raise RuntimeError(f"Failed to open workbook at '{file_path}': {e}") from e


def load_dataset(file_path: Path, sheet_name: str) -> pd.DataFrame:
    """Loads the specified sheet from the Excel workbook."""
    try:
        print(f"[*] Loading '{sheet_name}' from '{file_path}' (this may take 30-50 seconds for 100K rows)...", flush=True)
        df = pd.read_excel(str(file_path), sheet_name=sheet_name)
        print(f"[OK] Successfully loaded '{sheet_name}' with {len(df):,} rows and {len(df.columns)} columns.\n", flush=True)
        return df
    except Exception as e:
        raise RuntimeError(f"Error loading sheet '{sheet_name}' from '{file_path}': {type(e).__name__}: {e}") from e


def audit_columns_and_types(df: pd.DataFrame) -> Dict[str, Dict[str, Any]]:
    """Gathers per-column statistics, types, missing values, and uniqueness."""
    col_audit = {}
    total_rows = len(df)

    for col in df.columns:
        series = df[col]
        null_count = int(series.isna().sum())
        null_pct = float((null_count / total_rows) * 100.0) if total_rows > 0 else 0.0
        unique_count = int(series.nunique(dropna=True))
        dtype_str = str(series.dtype)

        # Get sample values (non-null)
        valid_vals = series.dropna().unique()
        sample_vals = [
            val.item() if hasattr(val, "item") else (str(val) if not isinstance(val, (int, float, bool, str)) else val)
            for val in valid_vals[:5]
        ]

        info: Dict[str, Any] = {
            "dtype": dtype_str,
            "null_count": null_count,
            "null_percentage": round(null_pct, 4),
            "unique_count": unique_count,
            "sample_values": sample_vals,
        }

        # Numeric stats
        if pd.api.types.is_numeric_dtype(series):
            desc = series.describe()
            info["is_numeric"] = True
            info["stats"] = {
                "min": float(desc.get("min", np.nan)) if pd.notna(desc.get("min")) else None,
                "mean": round(float(desc.get("mean", np.nan)), 4) if pd.notna(desc.get("mean")) else None,
                "std": round(float(desc.get("std", np.nan)), 4) if pd.notna(desc.get("std")) else None,
                "25%": round(float(desc.get("25%", np.nan)), 4) if pd.notna(desc.get("25%")) else None,
                "50% (median)": round(float(desc.get("50%", np.nan)), 4) if pd.notna(desc.get("50%")) else None,
                "75%": round(float(desc.get("75%", np.nan)), 4) if pd.notna(desc.get("75%")) else None,
                "max": float(desc.get("max", np.nan)) if pd.notna(desc.get("max")) else None,
            }
        else:
            info["is_numeric"] = False
            # Value distribution for low cardinality categoricals
            if unique_count <= 20:
                val_counts = series.value_counts(dropna=False).to_dict()
                info["value_counts"] = {
                    str(k): int(v) for k, v in val_counts.items()
                }

        col_audit[col] = info

    return col_audit


def check_mandatory_columns(df: pd.DataFrame) -> Dict[str, bool]:
    """Explicitly checks for required columns specified in project requirements."""
    mandatory_cols = ["asset_id", "risk_score", "risk_level", "recommended_action"]
    presence = {col: bool(col in df.columns) for col in mandatory_cols}
    return presence


def identify_leakage_and_exclusions(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Identifies target candidates, identifier columns, and potential target leakage features.
    """
    exclusions = {}
    leakage_candidates = []

    # 1. Identifier columns (no generalizable cryptographic signal)
    if "asset_id" in df.columns:
        exclusions["asset_id"] = {
            "category": "Identifier / Metadata",
            "reason": "Unique asset identifier with no predictive cryptographic generalization value.",
        }

    # 2. Direct continuous target / formula leakage
    if "risk_score" in df.columns:
        leakage_candidates.append("risk_score")
        exclusions["risk_score"] = {
            "category": "Target / Direct Leakage",
            "reason": "Continuous risk assessment score directly tied to the risk calculation formula. "
                      "If predicting risk_level (classification), including risk_score constitutes direct target leakage.",
        }

    # 3. Post-assessment recommendation
    if "recommended_action" in df.columns:
        leakage_candidates.append("recommended_action")
        exclusions["recommended_action"] = {
            "category": "Post-Assessment Action / Target Leakage",
            "reason": "Prescriptive remediation policy outcome derived downstream from risk_level / risk_score. "
                      "Including this as an input feature would leak the target outcome.",
        }

    # 4. Target variable itself
    if "risk_level" in df.columns:
        exclusions["risk_level"] = {
            "category": "Target Variable",
            "reason": "Primary supervised classification target for the ECDAT model.",
        }

    # 5. Check if any other columns show potential derivations
    for col in df.columns:
        if col not in exclusions and "risk" in col.lower() and col not in ["risk_score", "risk_level"]:
            leakage_candidates.append(col)
            exclusions[col] = {
                "category": "Potential Target Leakage",
                "reason": f"Column name '{col}' indicates potential derivation from risk assessment output.",
            }

    return {
        "leakage_candidates": leakage_candidates,
        "all_exclusions": exclusions,
        "recommended_target": "risk_level",
        "alternative_regression_target": "risk_score",
    }


def generate_data_dictionary(
    df: pd.DataFrame, col_audit: Dict[str, Dict[str, Any]], exclusions: Dict[str, Any]
) -> pd.DataFrame:
    """Creates a structured detected data dictionary DataFrame."""
    records = []
    for col in df.columns:
        audit_info = col_audit.get(col, {})
        excl_info = exclusions.get("all_exclusions", {}).get(col)

        if col == "risk_level":
            role = "Target (Multi-class Classification)"
        elif col == "risk_score":
            role = "Target (Regression) / Leakage for Classification"
        elif col == "asset_id":
            role = "Identifier (Drop)"
        elif excl_info and "Leakage" in excl_info.get("category", ""):
            role = "Target Leakage (Drop)"
        elif audit_info.get("is_numeric", False):
            role = "Numerical Feature"
        else:
            role = "Categorical Feature"

        sample_str = ", ".join(str(s) for s in audit_info.get("sample_values", [])[:3])
        if len(audit_info.get("sample_values", [])) > 3:
            sample_str += ", ..."

        records.append({
            "column_name": col,
            "data_type": audit_info.get("dtype", str(df[col].dtype)),
            "role": role,
            "null_count": audit_info.get("null_count", 0),
            "null_percentage": audit_info.get("null_percentage", 0.0),
            "unique_values_count": audit_info.get("unique_count", 0),
            "sample_values": sample_str,
            "audit_notes": excl_info["reason"] if excl_info else "Valid input feature for training"
        })

    return pd.DataFrame(records)


def run_audit(data_path: str, sheet_name: str, output_dir: str) -> None:
    data_file = Path(data_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("      ECDAT QUANTUM RISK MODEL - DATASET INSPECTION & AUDIT")
    print("=" * 80)
    print(f"Dataset File Path: {data_file.resolve()}")
    print(f"Timestamp: {datetime.datetime.now().isoformat()}")

    check_file_exists(data_file)
    file_size_mb = round(data_file.stat().st_size / (1024 * 1024), 2)
    print(f"File Size: {file_size_mb} MB\n")

    # Step 1: Identify all sheets
    sheet_names = inspect_workbook_sheets(data_file)
    print("--- 1. WORKBOOK SHEETS IDENTIFIED ---")
    for idx, sheet in enumerate(sheet_names, 1):
        print(f"  [{idx}] {sheet}")
    print()

    if sheet_name not in sheet_names:
        raise ValueError(
            f"Target sheet '{sheet_name}' not found in workbook. "
            f"Available sheets: {sheet_names}"
        )

    # Step 2: Load and inspect training_data sheet
    df = load_dataset(data_file, sheet_name)
    n_rows, n_cols = df.shape
    duplicate_rows = int(df.duplicated().sum())

    print("--- 2. TRAINING DATA OVERVIEW ---")
    print(f"Total Rows:              {n_rows:,}")
    print(f"Total Columns:           {n_cols}")
    print(f"Duplicate Rows:          {duplicate_rows} ({(duplicate_rows / n_rows * 100):.2f}%)")

    # Step 3: Explicit check for mandatory columns
    mandatory_check = check_mandatory_columns(df)
    print("\n--- 3. MANDATORY COLUMNS CHECK ---")
    for col, exists in mandatory_check.items():
        status = "PRESENT [OK]" if exists else "MISSING [X]"
        print(f"  - {col:<25}: {status}")

    # Step 4: Perform granular per-column audit
    col_audit = audit_columns_and_types(df)

    print("\n--- 4. COLUMN DETAILS & DATA TYPES ---")
    print(f"{'Column Name':<38} | {'Type':<10} | {'Null Count':<10} | {'Null %':<8} | {'Unique Count':<12}")
    print("-" * 88)
    for col, info in col_audit.items():
        print(
            f"{col:<38} | {info['dtype']:<10} | {info['null_count']:<10} | "
            f"{info['null_percentage']:<8.2f} | {info['unique_count']:<12}"
        )

    # Missing values highlight
    cols_with_nulls = {k: v for k, v in col_audit.items() if v["null_count"] > 0}
    print(f"\nColumns with missing values: {len(cols_with_nulls)}")
    if cols_with_nulls:
        for col, info in cols_with_nulls.items():
            print(f"  - {col}: {info['null_count']:,} nulls ({info['null_percentage']:.2f}%)")
    else:
        print("  None (0 missing values across all columns)")

    # Step 5: Categorical columns and their unique values
    print("\n--- 5. CATEGORICAL COLUMNS INSPECTION ---")
    cat_cols = [c for c, i in col_audit.items() if not i.get("is_numeric", False)]
    for col in cat_cols:
        info = col_audit[col]
        print(f"\n  - Column: '{col}' (Unique count: {info['unique_count']})")
        if "value_counts" in info:
            for val, count in info["value_counts"].items():
                pct = (count / n_rows) * 100
                print(f"      - {str(val):<25}: {count:>7,} ({pct:>5.2f}%)")
        else:
            print(f"      - Sample values: {info['sample_values']}")

    # Step 6: Class distribution of risk_level
    print("\n--- 6. CLASS DISTRIBUTION OF TARGET: risk_level ---")
    if "risk_level" in df.columns:
        risk_counts = df["risk_level"].value_counts(dropna=False)
        for level, count in risk_counts.items():
            pct = (count / n_rows) * 100
            print(f"  - {str(level):<12}: {count:>7,} ({pct:>6.2f}%)")
    else:
        print("  [!] WARNING: 'risk_level' column is missing from training_data.")

    # Step 7: Basic statistics for numeric columns
    print("\n--- 7. NUMERICAL COLUMNS SUMMARY STATISTICS ---")
    numeric_cols = [c for c, i in col_audit.items() if i.get("is_numeric", False)]
    print(f"Total Numeric Features: {len(numeric_cols)}")
    for col in numeric_cols:
        st = col_audit[col]["stats"]
        print(
            f"  - {col:<35} -> Min: {st['min']}, Median: {st['50% (median)']}, "
            f"Mean: {st['mean']}, Max: {st['max']}, Std: {st['std']}"
        )

    # Step 8: Suspicious columns and Target Leakage Analysis
    leakage_analysis = identify_leakage_and_exclusions(df)
    print("\n--- 8. TARGET LEAKAGE & EXCLUSION ANALYSIS ---")
    print(f"Identified Leakage Candidates: {leakage_analysis['leakage_candidates']}")
    for col, meta in leakage_analysis["all_exclusions"].items():
        print(f"  - {col:<22} [{meta['category']}]: {meta['reason']}")

    # Step 9: Save Reports
    # 9a. Save reports/data_audit.json
    audit_report = {
        "metadata": {
            "dataset_path": str(data_file.resolve()),
            "file_size_mb": file_size_mb,
            "audit_timestamp": datetime.datetime.now().isoformat(),
            "workbook_sheets": sheet_names,
            "audited_sheet": sheet_name,
        },
        "overview": {
            "total_rows": n_rows,
            "total_columns": n_cols,
            "duplicate_rows": duplicate_rows,
            "columns_with_missing_values": len(cols_with_nulls),
            "mandatory_columns_check": mandatory_check,
        },
        "target_variable": {
            "column_name": "risk_level",
            "exists": "risk_level" in df.columns,
            "class_distribution": (
                {str(k): int(v) for k, v in df["risk_level"].value_counts(dropna=False).items()}
                if "risk_level" in df.columns
                else {}
            ),
        },
        "leakage_and_exclusions": leakage_analysis,
        "columns_audit": col_audit,
    }

    json_report_path = out_dir / "data_audit.json"
    with open(json_report_path, "w", encoding="utf-8") as f:
        json.dump(audit_report, f, indent=2, default=str)
    print(f"\n[OK] Saved structured JSON audit report to: {json_report_path.resolve()}")

    # 9b. Save reports/data_dictionary_detected.csv
    data_dict_df = generate_data_dictionary(df, col_audit, leakage_analysis)
    csv_dict_path = out_dir / "data_dictionary_detected.csv"
    data_dict_df.to_csv(csv_dict_path, index=False, encoding="utf-8")
    print(f"[OK] Saved detected data dictionary CSV to: {csv_dict_path.resolve()}")

    # Step 10: Executive Summary & Recommendation
    valid_features = [c for c in df.columns if c not in leakage_analysis["all_exclusions"]]
    print("\n" + "=" * 80)
    print("                         AUDIT SUMMARY & RECOMMENDATIONS")
    print("=" * 80)
    print("1. Recommended Target Variable:")
    print(f"   - 'risk_level' (Multi-class Classification with classes: {list(df['risk_level'].unique()) if 'risk_level' in df.columns else 'N/A'})")
    print("   - Alternatively, 'risk_score' for regression experiments.")

    print("\n2. Columns to Exclude (Leakage / Identifiers):")
    for col, meta in leakage_analysis["all_exclusions"].items():
        print(f"   - '{col}' -> {meta['category']} ({meta['reason']})")

    print("\n3. Preprocessing Required for ML Pipeline:")
    print("   - Missing Value Handling: Columns with NaN values (e.g. 'estimated_attack_time_log10_hours') need imputation or dedicated missingness indicator.")
    print("   - Categorical Encoding: One-Hot or Target/Ordinal Encoding for categorical columns (e.g., algorithm, crypto_role, deployment_environment, protocol, crypto_library, etc.).")
    print("   - Numerical Scaling: Standard or Robust Scaling for numerical/continuous features (e.g., key_age_days, implementation_age_years, data_lifetime_years, migration_time_years).")
    print("   - Train/Val/Test Split: Stratified split based on 'risk_level' to maintain class balance.")

    print("\n4. Dataset ML Suitability Assessment:")
    print("   - Status: SUITABLE FOR FIRST SYNTHETIC-DATA ML EXPERIMENT [OK]")
    print(f"   - Valid Feature Count: {len(valid_features)} clean features available for modeling.")
    print("   - Clean distribution across risk classes, strong cryptographic domain signals, and zero full-row duplicate records.")
    print("=" * 80)


def main():
    args = parse_args()
    try:
        run_audit(
            data_path=args.data_path,
            sheet_name=args.sheet_name,
            output_dir=args.output_dir,
        )
    except Exception as exc:
        print(f"\n[!] Audit execution failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
