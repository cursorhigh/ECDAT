"""
ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) - Quantum Risk Model
Data Preprocessing Pipeline

This script prepares the dataset for machine learning:
1. Loads training_data from ECDAT_Industry_Quantum_Risk_Dataset_100K.xlsx.
2. Extracts target 'risk_level' and strictly excludes leakage / metadata columns:
   - asset_id
   - risk_level
   - risk_score
   - recommended_action
3. Automatically categorizes features:
   - Numerical continuous / ordinal features
   - Categorical nominal features
   - Binary / Boolean indicator features
4. Performs a stratified 70% / 15% / 15% train/validation/test split.
5. Builds a scikit-learn ColumnTransformer pipeline:
   - Fits preprocessor ONLY on the training split
   - Handles missing values safely
   - Scales numerical features
   - One-Hot Encodes categorical features (handle_unknown='ignore')
6. Transforms train, validation, and test datasets.
7. Saves processed splits, preprocessor artifacts, feature metadata, and reports:
   - data/processed/ (raw split data & transformed feature matrices)
   - models/preprocessor/ (preprocessor.joblib, metadata.json, target_mapping.json)
   - reports/split_distribution.json
"""

import os
import sys
import json
import argparse
import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple

# Set stdout encoding safely
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, OneHotEncoder


# Mandatory exclusions to prevent target leakage and ID overfitting
EXCLUDED_COLUMNS = ["asset_id", "risk_level", "risk_score", "recommended_action"]
TARGET_COLUMN = "risk_level"

# Canonical ordered risk levels
TARGET_MAPPING = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}
REVERSE_TARGET_MAPPING = {v: k for k, v in TARGET_MAPPING.items()}


def parse_args():
    parser = argparse.ArgumentParser(
        description="ECDAT Quantum Risk Preprocessing Pipeline"
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
        help="Sheet name to read from the Excel workbook",
    )
    parser.add_argument(
        "--output-data-dir",
        type=str,
        default="data/processed",
        help="Directory to store processed dataset splits",
    )
    parser.add_argument(
        "--output-model-dir",
        type=str,
        default="models/preprocessor",
        help="Directory to store saved preprocessor artifact & metadata",
    )
    parser.add_argument(
        "--output-reports-dir",
        type=str,
        default="reports",
        help="Directory to store distribution reports",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=42,
        help="Random seed for deterministic stratified splitting",
    )
    return parser.parse_args()


def load_raw_data(data_path: Path, sheet_name: str) -> pd.DataFrame:
    """Loads training dataset safely from Excel workbook."""
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found at: {data_path.resolve()}")

    print(f"[*] Loading raw dataset from '{data_path}' (sheet: '{sheet_name}')...", flush=True)
    df = pd.read_excel(str(data_path), sheet_name=sheet_name)
    print(f"[OK] Loaded {len(df):,} records and {len(df.columns)} columns.\n", flush=True)
    return df


def validate_and_separate(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Validates target column presence and separates features X and target y."""
    if TARGET_COLUMN not in df.columns:
        raise KeyError(f"Target column '{TARGET_COLUMN}' not found in dataset columns: {list(df.columns)}")

    # Verify no unexpected target values
    unknown_targets = set(df[TARGET_COLUMN].dropna().unique()) - set(TARGET_MAPPING.keys())
    if unknown_targets:
        raise ValueError(f"Found unexpected target classes in '{TARGET_COLUMN}': {unknown_targets}")

    # Drop all leakage and ID columns from X
    cols_to_drop = [c for c in EXCLUDED_COLUMNS if c in df.columns]
    print(f"[*] Dropping {len(cols_to_drop)} excluded / leakage columns from feature matrix X:")
    for col in cols_to_drop:
        print(f"    - {col}")

    X = df.drop(columns=cols_to_drop).copy()
    y = df[TARGET_COLUMN].map(TARGET_MAPPING).astype(int)

    print(f"\n[OK] Feature matrix shape: {X.shape}, Target shape: {y.shape}")
    return X, y


def detect_column_types(X: pd.DataFrame) -> Dict[str, List[str]]:
    """
    Automatically detects column categories:
    - Binary / Boolean columns
    - Categorical nominal columns
    - Numerical continuous / ordinal columns
    """
    binary_cols = []
    categorical_cols = []
    numerical_cols = []

    for col in X.columns:
        series = X[col]
        n_unique = series.nunique(dropna=True)
        unique_vals = set(series.dropna().unique())

        # Check if binary (values are subset of {0, 1} or {True, False})
        if unique_vals.issubset({0, 1, 0.0, 1.0, True, False}) and n_unique <= 2:
            binary_cols.append(col)
        elif pd.api.types.is_object_dtype(series) or isinstance(series.dtype, pd.CategoricalDtype) or pd.api.types.is_string_dtype(series):
            categorical_cols.append(col)
        elif pd.api.types.is_numeric_dtype(series):
            numerical_cols.append(col)
        else:
            # Default fallback to categorical
            categorical_cols.append(col)

    print("\n--- DETECTED COLUMN TYPES ---")
    print(f"Numerical Columns ({len(numerical_cols)}):")
    for col in numerical_cols:
        print(f"  - {col}")

    print(f"\nCategorical Columns ({len(categorical_cols)}):")
    for col in categorical_cols:
        print(f"  - {col} (unique: {X[col].nunique()})")

    print(f"\nBinary / Indicator Columns ({len(binary_cols)}):")
    for col in binary_cols:
        print(f"  - {col}")

    return {
        "numerical": numerical_cols,
        "categorical": categorical_cols,
        "binary": binary_cols,
    }


def perform_stratified_split(
    X: pd.DataFrame, y: pd.Series, random_seed: int
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series]:
    """
    Splits data into 70% Train, 15% Validation, and 15% Test with exact stratification.
    """
    print("\n[*] Performing 70% / 15% / 15% stratified dataset split (seed={})...".format(random_seed))

    # Split 1: 70% Train, 30% Temp (Val + Test)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=random_seed, stratify=y
    )

    # Split 2: Split 30% Temp into 50% Val and 50% Test (15% and 15% of original)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=random_seed, stratify=y_temp
    )

    print(f"[OK] Split complete:")
    print(f"     Train: {len(X_train):>7,} rows ({(len(X_train)/len(X)*100):.1f}%)")
    print(f"     Val:   {len(X_val):>7,} rows ({(len(X_val)/len(X)*100):.1f}%)")
    print(f"     Test:  {len(X_test):>7,} rows ({(len(X_test)/len(X)*100):.1f}%)")

    return X_train, X_val, X_test, y_train, y_val, y_test


def build_preprocessor_pipeline(col_types: Dict[str, List[str]]) -> ColumnTransformer:
    """
    Constructs a robust, reproducible scikit-learn ColumnTransformer.
    - Numerical: SimpleImputer(strategy='median', add_indicator=True) -> StandardScaler()
    - Categorical: SimpleImputer(strategy='constant', fill_value='missing') -> OneHotEncoder(handle_unknown='ignore', sparse_output=False)
    - Binary: SimpleImputer(strategy='most_frequent') -> Passthrough
    """
    transformers = []

    if col_types["numerical"]:
        num_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ])
        transformers.append(("num", num_pipeline, col_types["numerical"]))

    if col_types["categorical"]:
        cat_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="constant", fill_value="missing")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ])
        transformers.append(("cat", cat_pipeline, col_types["categorical"]))

    if col_types["binary"]:
        bin_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
        ])
        transformers.append(("bin", bin_pipeline, col_types["binary"]))

    preprocessor = ColumnTransformer(
        transformers=transformers,
        remainder="drop",
        verbose_feature_names_out=True,
    )
    return preprocessor


def get_feature_names_from_preprocessor(preprocessor: ColumnTransformer) -> List[str]:
    """Extracts output feature names from the fitted ColumnTransformer."""
    try:
        return list(preprocessor.get_feature_names_out())
    except Exception:
        # Fallback manual reconstruction
        names = []
        for name, transformer, cols in preprocessor.transformers_:
            if name == "num":
                names.extend([f"num__{c}" for c in cols])
            elif name == "cat":
                try:
                    ohe = transformer.named_steps["onehot"]
                    cat_names = ohe.get_feature_names_out(cols)
                    names.extend([f"cat__{c}" for c in cat_names])
                except Exception:
                    names.extend([f"cat__{c}" for c in cols])
            elif name == "bin":
                names.extend([f"bin__{c}" for c in cols])
        return names


def compute_split_distribution_stats(
    y_full: pd.Series, y_train: pd.Series, y_val: pd.Series, y_test: pd.Series,
    random_seed: int, col_types: Dict[str, List[str]], n_features_out: int
) -> Dict[str, Any]:
    """Generates distribution report for split verification."""
    def get_dist(s: pd.Series) -> Dict[str, Any]:
        counts = s.value_counts().sort_index()
        total = len(s)
        return {
            "counts": {REVERSE_TARGET_MAPPING[k]: int(v) for k, v in counts.items()},
            "percentages": {REVERSE_TARGET_MAPPING[k]: round(float(v / total * 100), 2) for k, v in counts.items()},
        }

    return {
        "metadata": {
            "timestamp": datetime.datetime.now().isoformat(),
            "random_seed": random_seed,
            "target_column": TARGET_COLUMN,
            "classes": list(TARGET_MAPPING.keys()),
            "target_mapping": TARGET_MAPPING,
        },
        "splits": {
            "total_samples": len(y_full),
            "train": {
                "count": len(y_train),
                "percentage": round(len(y_train) / len(y_full) * 100, 2),
                "distribution": get_dist(y_train),
            },
            "validation": {
                "count": len(y_val),
                "percentage": round(len(y_val) / len(y_full) * 100, 2),
                "distribution": get_dist(y_val),
            },
            "test": {
                "count": len(y_test),
                "percentage": round(len(y_test) / len(y_full) * 100, 2),
                "distribution": get_dist(y_test),
            },
            "full_dataset": {
                "count": len(y_full),
                "percentage": 100.0,
                "distribution": get_dist(y_full),
            },
        },
        "features": {
            "input_raw_features_count": sum(len(v) for v in col_types.values()),
            "numerical_features_count": len(col_types["numerical"]),
            "categorical_features_count": len(col_types["categorical"]),
            "binary_features_count": len(col_types["binary"]),
            "output_transformed_features_count": n_features_out,
            "numerical_features": col_types["numerical"],
            "categorical_features": col_types["categorical"],
            "binary_features": col_types["binary"],
        },
    }


def run_pipeline(
    data_path: str,
    sheet_name: str,
    output_data_dir: str,
    output_model_dir: str,
    output_reports_dir: str,
    random_seed: int,
) -> None:
    data_file = Path(data_path)
    processed_dir = Path(output_data_dir)
    model_dir = Path(output_model_dir)
    reports_dir = Path(output_reports_dir)

    for d in [processed_dir, model_dir, reports_dir]:
        d.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("      ECDAT QUANTUM RISK MODEL - PREPROCESSING PIPELINE")
    print("=" * 80)

    # 1. Load raw dataset
    df = load_raw_data(data_file, sheet_name)

    # 2. Separate features X and target y
    X, y = validate_and_separate(df)

    # 3. Detect column types
    col_types = detect_column_types(X)

    # 4. Stratified Split (70/15/15)
    X_train, X_val, X_test, y_train, y_val, y_test = perform_stratified_split(
        X, y, random_seed=random_seed
    )

    # 5. Build and FIT preprocessor ONLY on training set
    print("\n[*] Fitting preprocessing pipeline ONLY on X_train...")
    preprocessor = build_preprocessor_pipeline(col_types)
    preprocessor.fit(X_train)
    print("[OK] Preprocessor fitted successfully.")

    # 6. Transform train, val, and test sets
    print("\n[*] Transforming X_train, X_val, and X_test...")
    X_train_trans = preprocessor.transform(X_train)
    X_val_trans = preprocessor.transform(X_val)
    X_test_trans = preprocessor.transform(X_test)

    feature_names_out = get_feature_names_from_preprocessor(preprocessor)
    print(f"[OK] Transformation complete.")
    print(f"     Transformed feature dimensions: {X_train_trans.shape[1]} features")

    # 7. Save Processed Datasets
    print("\n[*] Saving processed datasets to:", processed_dir.resolve())

    # Save as compressed .npz for fast ML loading
    np.savez_compressed(
        processed_dir / "train_processed.npz",
        X=X_train_trans.astype(np.float32),
        y=y_train.to_numpy(dtype=np.int64),
    )
    np.savez_compressed(
        processed_dir / "val_processed.npz",
        X=X_val_trans.astype(np.float32),
        y=y_val.to_numpy(dtype=np.int64),
    )
    np.savez_compressed(
        processed_dir / "test_processed.npz",
        X=X_test_trans.astype(np.float32),
        y=y_test.to_numpy(dtype=np.int64),
    )

    # Save individual arrays
    np.save(processed_dir / "X_train.npy", X_train_trans.astype(np.float32))
    np.save(processed_dir / "y_train.npy", y_train.to_numpy(dtype=np.int64))
    np.save(processed_dir / "X_val.npy", X_val_trans.astype(np.float32))
    np.save(processed_dir / "y_val.npy", y_val.to_numpy(dtype=np.int64))
    np.save(processed_dir / "X_test.npy", X_test_trans.astype(np.float32))
    np.save(processed_dir / "y_test.npy", y_test.to_numpy(dtype=np.int64))

    # Save raw split DataFrames as parquet for inspectability
    try:
        X_train.assign(risk_level=y_train.map(REVERSE_TARGET_MAPPING)).to_parquet(
            processed_dir / "train_raw.parquet", index=False
        )
        X_val.assign(risk_level=y_val.map(REVERSE_TARGET_MAPPING)).to_parquet(
            processed_dir / "val_raw.parquet", index=False
        )
        X_test.assign(risk_level=y_test.map(REVERSE_TARGET_MAPPING)).to_parquet(
            processed_dir / "test_raw.parquet", index=False
        )
        print("  [OK] Saved raw split partitions (train_raw, val_raw, test_raw.parquet)")
    except Exception as e:
        print(f"  [!] Note: Parquet save skipped ({e}); NumPy/compressed formats are fully saved.")

    print("  [OK] Saved train_processed.npz, val_processed.npz, test_processed.npz")
    print("  [OK] Saved individual X/y .npy arrays")

    # 8. Save Preprocessor Pipeline and Metadata Artifacts
    print("\n[*] Saving preprocessor pipeline and metadata to:", model_dir.resolve())
    preprocessor_path = model_dir / "preprocessor.joblib"
    joblib.dump(preprocessor, preprocessor_path)
    print(f"  [OK] Saved preprocessor artifact: {preprocessor_path.name}")

    metadata = {
        "created_at": datetime.datetime.now().isoformat(),
        "random_seed": random_seed,
        "input_dataset": str(data_file.resolve()),
        "target_column": TARGET_COLUMN,
        "target_classes": list(TARGET_MAPPING.keys()),
        "target_mapping": TARGET_MAPPING,
        "reverse_target_mapping": REVERSE_TARGET_MAPPING,
        "excluded_columns": EXCLUDED_COLUMNS,
        "raw_features": {
            "all": list(X.columns),
            "numerical": col_types["numerical"],
            "categorical": col_types["categorical"],
            "binary": col_types["binary"],
        },
        "transformed_features_count": len(feature_names_out),
        "transformed_feature_names": feature_names_out,
        "split_counts": {
            "train": len(X_train),
            "val": len(X_val),
            "test": len(X_test),
        },
    }

    metadata_path = model_dir / "metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"  [OK] Saved feature metadata: {metadata_path.name}")

    target_map_path = model_dir / "target_mapping.json"
    with open(target_map_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "target_mapping": TARGET_MAPPING,
                "reverse_target_mapping": REVERSE_TARGET_MAPPING,
            },
            f,
            indent=2,
        )
    print(f"  [OK] Saved target mapping: {target_map_path.name}")

    # 9. Generate and Save Split Distribution Report
    split_dist = compute_split_distribution_stats(
        y_full=y,
        y_train=y_train,
        y_val=y_val,
        y_test=y_test,
        random_seed=random_seed,
        col_types=col_types,
        n_features_out=len(feature_names_out),
    )

    split_report_path = reports_dir / "split_distribution.json"
    with open(split_report_path, "w", encoding="utf-8") as f:
        json.dump(split_dist, f, indent=2)
    print(f"\n[OK] Saved split distribution report to: {split_report_path.resolve()}")

    # 10. Print Split Verification Table
    print("\n" + "=" * 80)
    print("                     STRATIFIED SPLIT VERIFICATION")
    print("=" * 80)
    print(f"{'Risk Level':<12} | {'Full Dataset':<15} | {'Train (70%)':<15} | {'Val (15%)':<15} | {'Test (15%)':<15}")
    print("-" * 80)
    for label in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        full_pct = split_dist["splits"]["full_dataset"]["distribution"]["percentages"][label]
        train_pct = split_dist["splits"]["train"]["distribution"]["percentages"][label]
        val_pct = split_dist["splits"]["validation"]["distribution"]["percentages"][label]
        test_pct = split_dist["splits"]["test"]["distribution"]["percentages"][label]
        print(
            f"{label:<12} | {full_pct:>5.2f}% ({split_dist['splits']['full_dataset']['distribution']['counts'][label]:>6,}) | "
            f"{train_pct:>5.2f}% ({split_dist['splits']['train']['distribution']['counts'][label]:>6,}) | "
            f"{val_pct:>5.2f}% ({split_dist['splits']['validation']['distribution']['counts'][label]:>5,}) | "
            f"{test_pct:>5.2f}% ({split_dist['splits']['test']['distribution']['counts'][label]:>5,})"
        )
    print("=" * 80)
    print(f"[OK] Preprocessing completed successfully with 0 target leakage.")
    print("=" * 80)


def main():
    args = parse_args()
    try:
        run_pipeline(
            data_path=args.data_path,
            sheet_name=args.sheet_name,
            output_data_dir=args.output_data_dir,
            output_model_dir=args.output_model_dir,
            output_reports_dir=args.output_reports_dir,
            random_seed=args.random_seed,
        )
    except Exception as exc:
        print(f"\n[!] Preprocessing failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
