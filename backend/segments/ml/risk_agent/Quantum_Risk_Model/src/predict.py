"""
ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) - Quantum Risk Model
Production Inference Module

Provides a robust, self-contained inference API and CLI:
- predict_quantum_risk(input_data, model_dir="models/final")
  * Validates input schema against feature_schema.json
  * Canonicalizes input representations (e.g. NIST categories, HNDL exposure, scenario aliases)
  * Safely handles unknown categorical values & missing attributes
  * Blocks ML prediction if validation errors are detected
  * Executes fitted preprocessor and tuned CatBoost classifier when validation passes
  * Returns predicted risk_level, class probabilities, confidence, model version, and status

CLI Usage:
  python src/predict.py --input examples/sample_input.json
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path
from typing import Dict, Any, List, Union, Optional, Tuple

# Safe stdout on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import joblib
import numpy as np
import pandas as pd

# Robust directory resolution anchored to package location (supports Django / any CWD)
PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL_DIR = PACKAGE_ROOT / "models" / "final"
FALLBACK_MODEL_DIR = PACKAGE_ROOT / "models" / "tuned"
FALLBACK_PREP_DIR = PACKAGE_ROOT / "models" / "preprocessor"

CLASS_NAMES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Global lazy cache for high-throughput serving
_CACHED_MODEL = None
_CACHED_PREPROCESSOR = None
_CACHED_METADATA = None
_CACHED_SCHEMA = None
_CACHED_DIR = None


def get_model_artifacts(model_dir: Optional[Union[str, Path]] = None) -> Tuple[Any, Any, Dict[str, Any], Dict[str, Any]]:
    """Loads and caches preprocessor, model, metadata, and feature schema."""
    global _CACHED_MODEL, _CACHED_PREPROCESSOR, _CACHED_METADATA, _CACHED_SCHEMA, _CACHED_DIR

    target_dir = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR
    if not target_dir.exists():
        # Check if running in root or fallback
        if DEFAULT_MODEL_DIR.exists():
            target_dir = DEFAULT_MODEL_DIR
        elif FALLBACK_MODEL_DIR.exists():
            target_dir = FALLBACK_MODEL_DIR

    if _CACHED_DIR == str(target_dir.resolve()) and _CACHED_MODEL is not None:
        return _CACHED_MODEL, _CACHED_PREPROCESSOR, _CACHED_METADATA, _CACHED_SCHEMA

    model_file = target_dir / "model.joblib"
    prep_file = target_dir / "preprocessor.joblib"
    if not prep_file.exists():
        prep_file = FALLBACK_PREP_DIR / "preprocessor.joblib"

    if not model_file.exists() or not prep_file.exists():
        raise FileNotFoundError(
            f"Required model artifacts not found in '{target_dir.resolve()}'. "
            f"Please ensure the model has been trained and exported."
        )

    model = joblib.load(model_file)
    preprocessor = joblib.load(prep_file)

    # Load metadata
    meta_file = target_dir / "model_metadata.json"
    if meta_file.exists():
        with open(meta_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    else:
        metadata = {"model_version": "1.1.0", "model_name": "ECDAT Quantum Risk Classifier"}

    # Load schema
    schema_file = target_dir / "feature_schema.json"
    if schema_file.exists():
        with open(schema_file, "r", encoding="utf-8") as f:
            schema = json.load(f)
    else:
        schema = {}

    _CACHED_MODEL = model
    _CACHED_PREPROCESSOR = preprocessor
    _CACHED_METADATA = metadata
    _CACHED_SCHEMA = schema
    _CACHED_DIR = str(target_dir.resolve())

    return model, preprocessor, metadata, schema


def canonicalize_and_validate_record(
    record: Dict[str, Any], schema: Dict[str, Any]
) -> Tuple[bool, Dict[str, Any], List[str], List[str]]:
    """
    Validates and canonicalizes a single input record against schema requirements.

    Distinguishes:
    - valid / canonicalized value: matches schema type, domain/range, non-missing
    - unknown categorical value: categorical string not in allowed_values (warning, OOV handled by preprocessor)
    - out-of-range numeric value: numeric value outside observed training [min, max] (warning)
    - wrong datatype: non-numeric string for numeric feature, non-string for categorical, unparseable values (error)
    - missing value: required field missing or null (error)
    - domain bounds violation: value physically/logically impossible e.g. negative years, 1..5 score out of bounds (error)

    Returns: (is_valid, canonical_record, list_of_errors, list_of_warnings)
    """
    errors = []
    warnings = []
    canonical_record = {}

    if not isinstance(record, dict):
        return False, {}, ["Input record must be a dictionary/JSON object"], []

    schema_features = schema.get("features", [])
    schema_feature_names = {f["name"] for f in schema_features}
    excluded_names = {"asset_id", "risk_score", "risk_level", "recommended_action"}

    # Check for unrecognized extra keys
    for k in record.keys():
        if k not in schema_feature_names and k not in excluded_names:
            warnings.append(f"Unrecognized input feature '{k}'. It will be ignored during model inference.")

    for feat in schema_features:
        name = feat["name"]
        feat_type = feat.get("type", "numeric")
        is_required = feat.get("required", True)
        min_val = feat.get("min")
        max_val = feat.get("max")
        allowed_vals = feat.get("allowed_values")

        is_present = name in record
        val = record.get(name)
        is_null = (val is None) or (isinstance(val, float) and np.isnan(val))

        # Check missing status
        if not is_present or is_null:
            if is_required:
                errors.append(f"Missing required feature '{name}'.")
            else:
                canonical_record[name] = np.nan
            continue

        # Canonicalize and validate based on feature name and semantic type
        if name == "nist_security_category":
            if isinstance(val, bool):
                errors.append(
                    f"Wrong datatype for numeric feature 'nist_security_category': expected numeric value, got boolean ({val})."
                )
            elif isinstance(val, (int, float)):
                if val < 0 or val > 5:
                    errors.append(
                        f"Invalid value for 'nist_security_category': {val} is outside valid domain [0, 5]."
                    )
                else:
                    canonical_record[name] = int(val)
            elif isinstance(val, str):
                m = re.match(r"^(?:NIST\s*)?(?:Category|Cat)?\s*(\d+)$", val.strip(), re.IGNORECASE)
                if m:
                    cat_num = int(m.group(1))
                    if cat_num < 0 or cat_num > 5:
                        errors.append(
                            f"Invalid value for 'nist_security_category': {cat_num} is outside valid domain [0, 5]."
                        )
                    else:
                        canonical_record[name] = cat_num
                else:
                    errors.append(
                        f"Wrong datatype for numeric feature 'nist_security_category': expected numeric value, got string '{val}'."
                    )
            else:
                errors.append(
                    f"Wrong datatype for numeric feature 'nist_security_category': expected numeric value, got {type(val).__name__} ({val!r})."
                )

        elif name == "HNDL_exposure":
            if isinstance(val, bool):
                canonical_record[name] = 1.0 if val else 0.0
            elif isinstance(val, (int, float)):
                if val < 0.0 or val > 1.0:
                    errors.append(
                        f"Invalid value for 'HNDL_exposure': {val} is outside valid domain [0.0, 1.0]."
                    )
                else:
                    canonical_record[name] = float(val)
            elif isinstance(val, str):
                s_val = val.strip().lower()
                if s_val in ["true", "1", "yes"]:
                    canonical_record[name] = 1.0
                elif s_val in ["false", "0", "no"]:
                    canonical_record[name] = 0.0
                else:
                    try:
                        f_val = float(s_val)
                        if f_val < 0.0 or f_val > 1.0:
                            errors.append(
                                f"Invalid value for 'HNDL_exposure': {f_val} is outside valid domain [0.0, 1.0]."
                            )
                        else:
                            canonical_record[name] = f_val
                    except ValueError:
                        errors.append(
                            f"Wrong datatype for numeric feature 'HNDL_exposure': expected numeric value, got string '{val}'."
                        )
            else:
                errors.append(
                    f"Wrong datatype for numeric feature 'HNDL_exposure': expected numeric value, got {type(val).__name__} ({val!r})."
                )

        elif name == "quantum_estimate_confidence":
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                if val == 0 or val == 0.0:
                    canonical_record[name] = "not-applicable"
                else:
                    canonical_record[name] = "scenario-dependent"
            elif isinstance(val, str):
                s_val = val.strip().lower()
                if s_val in ["not-applicable", "not_applicable", "n/a", "none", "0", "0.0"]:
                    canonical_record[name] = "not-applicable"
                elif s_val in ["scenario-dependent", "scenario_dependent", "scenario", "high", "medium", "low", "1", "1.0"]:
                    canonical_record[name] = "scenario-dependent"
                else:
                    canonical_record[name] = val.strip()
                    if allowed_vals is not None and val.strip() not in allowed_vals:
                        warnings.append(
                            f"Unknown categorical value '{val}' for feature 'quantum_estimate_confidence'. Model preprocessor will handle safely as out-of-vocabulary."
                        )
            else:
                errors.append(
                    f"Wrong datatype for categorical feature 'quantum_estimate_confidence': expected string or numeric confidence score, got {type(val).__name__} ({val!r})."
                )

        elif name == "quantum_attack_scenario":
            if isinstance(val, str):
                s_val = val.strip().lower()
                if s_val in [
                    "crqc capable of breaking rsa",
                    "crqc capable of breaking ecc",
                    "crqc capable of breaking rsa/ecc",
                    "shor-based attack",
                    "shor based attack",
                    "shor",
                    "rsa",
                    "notional_future",
                    "notional future",
                    "notional",
                ]:
                    canonical_record[name] = "notional_future"
                elif s_val in [
                    "grover-based attack",
                    "grover based attack",
                    "grover",
                    "theoretical quantum attack",
                    "generic quantum effect",
                    "generic_quantum_effect",
                    "generic",
                ]:
                    canonical_record[name] = "generic_quantum_effect"
                elif s_val in ["no known quantum attack", "none known", "none_known", "none"]:
                    canonical_record[name] = "none_known"
                elif s_val in ["aggressive", "aggressive_future", "aggressive future"]:
                    canonical_record[name] = "aggressive_future"
                elif s_val in ["high_end", "high_end_future", "high end future"]:
                    canonical_record[name] = "high_end_future"
                else:
                    canonical_record[name] = val.strip()
                    if allowed_vals is not None and val.strip() not in allowed_vals:
                        warnings.append(
                            f"Unknown categorical value '{val}' for feature 'quantum_attack_scenario'. Model preprocessor will handle safely as out-of-vocabulary."
                        )
            else:
                errors.append(
                    f"Wrong datatype for categorical feature 'quantum_attack_scenario': expected string, got {type(val).__name__} ({val!r})."
                )

        elif name == "protocol":
            if isinstance(val, str):
                s_val = val.strip()
                if s_val.lower() in ["tls", "https", "ssl"]:
                    canonical_record[name] = "TLS1.2"
                else:
                    canonical_record[name] = s_val
                    if allowed_vals is not None and s_val not in allowed_vals:
                        warnings.append(
                            f"Unknown categorical value '{val}' for feature 'protocol'. Model preprocessor will handle safely as out-of-vocabulary."
                        )
            else:
                errors.append(
                    f"Wrong datatype for categorical feature 'protocol': expected string, got {type(val).__name__} ({val!r})."
                )

        elif feat_type == "binary":
            if isinstance(val, bool):
                canonical_record[name] = 1 if val else 0
            elif isinstance(val, (int, float)):
                if val in [0, 1, 0.0, 1.0]:
                    canonical_record[name] = int(val)
                else:
                    errors.append(
                        f"Wrong datatype for binary feature '{name}': expected boolean or 0/1, got {val}."
                    )
            elif isinstance(val, str):
                s_val = val.strip().lower()
                if s_val in ["true", "1", "yes"]:
                    canonical_record[name] = 1
                elif s_val in ["false", "0", "no"]:
                    canonical_record[name] = 0
                else:
                    errors.append(
                        f"Wrong datatype for binary feature '{name}': expected boolean or 0/1, got string '{val}'."
                    )
            else:
                errors.append(
                    f"Wrong datatype for binary feature '{name}': expected boolean or 0/1, got {type(val).__name__} ({val!r})."
                )

        elif name in [
            "data_sensitivity",
            "business_criticality",
            "migration_complexity",
            "crypto_agility",
            "vendor_support_score",
            "inventory_confidence",
            "compliance_criticality",
        ]:
            if isinstance(val, bool):
                errors.append(
                    f"Wrong datatype for numeric feature '{name}': expected numeric value, got boolean ({val})."
                )
            elif isinstance(val, (int, float)):
                int_val = int(val)
                if int_val < 1 or int_val > 5:
                    errors.append(
                        f"Invalid value for '{name}': {val} is outside valid domain [1, 5]."
                    )
                else:
                    canonical_record[name] = int_val
            elif isinstance(val, str):
                try:
                    int_val = int(float(val.strip()))
                    if int_val < 1 or int_val > 5:
                        errors.append(
                            f"Invalid value for '{name}': {int_val} is outside valid domain [1, 5]."
                        )
                    else:
                        canonical_record[name] = int_val
                except ValueError:
                    errors.append(
                        f"Wrong datatype for numeric feature '{name}': expected numeric value, got string '{val}'."
                    )
            else:
                errors.append(
                    f"Wrong datatype for numeric feature '{name}': expected numeric value, got {type(val).__name__} ({val!r})."
                )

        elif feat_type == "numeric":
            if isinstance(val, bool):
                errors.append(
                    f"Wrong datatype for numeric feature '{name}': expected numeric value, got boolean ({val})."
                )
            elif isinstance(val, (int, float)):
                if val < 0:
                    errors.append(
                        f"Invalid value for '{name}': {val} cannot be negative."
                    )
                else:
                    canonical_record[name] = float(val) if isinstance(val, float) else val
                    if min_val is not None and val < min_val:
                        warnings.append(
                            f"Out-of-range numeric value for '{name}': {val} is below observed training minimum {min_val}."
                        )
                    if max_val is not None and val > max_val:
                        warnings.append(
                            f"Out-of-range numeric value for '{name}': {val} is above observed training maximum {max_val}."
                        )
            elif isinstance(val, str):
                try:
                    num_val = float(val.strip())
                    if num_val < 0:
                        errors.append(
                            f"Invalid value for '{name}': {num_val} cannot be negative."
                        )
                    else:
                        canonical_record[name] = num_val
                        if min_val is not None and num_val < min_val:
                            warnings.append(
                                f"Out-of-range numeric value for '{name}': {num_val} is below observed training minimum {min_val}."
                            )
                        if max_val is not None and num_val > max_val:
                            warnings.append(
                                f"Out-of-range numeric value for '{name}': {num_val} is above observed training maximum {max_val}."
                            )
                except ValueError:
                    errors.append(
                        f"Wrong datatype for numeric feature '{name}': expected numeric value, got string '{val}'."
                    )
            else:
                errors.append(
                    f"Wrong datatype for numeric feature '{name}': expected numeric value, got {type(val).__name__} ({val!r})."
                )

        elif feat_type == "categorical":
            if isinstance(val, str):
                s_val = val.strip()
                canonical_record[name] = s_val
                if allowed_vals is not None and s_val not in allowed_vals:
                    warnings.append(
                        f"Unknown categorical value '{val}' for feature '{name}'. Model preprocessor will handle safely as out-of-vocabulary."
                    )
            else:
                errors.append(
                    f"Wrong datatype for categorical feature '{name}': expected string, got {type(val).__name__} ({val!r})."
                )
        else:
            canonical_record[name] = val

    return len(errors) == 0, canonical_record, errors, warnings


def validate_input_record(
    record: Dict[str, Any], schema: Dict[str, Any]
) -> Tuple[bool, List[str], List[str]]:
    """
    Public validation API preserving backwards compatibility.
    Returns: (is_valid, list_of_errors, list_of_warnings)
    """
    is_valid, _, errors, warnings = canonicalize_and_validate_record(record, schema)
    return is_valid, errors, warnings


def predict_quantum_risk(
    input_data: Union[Dict[str, Any], List[Dict[str, Any]], pd.DataFrame],
    model_dir: Optional[Union[str, Path]] = None,
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Production-grade inference function for the ECDAT quantum risk classifier.

    Validation Architecture:
    - Input records undergo schema validation and canonicalization.
    - If validation errors are present:
        * Model execution is strictly BLOCKED.
        * status = "validation_error"
        * risk_level = None, probabilities = None, model_confidence = None
        * validation_errors list is returned.
    - If validation passes with warnings:
        * Preprocessor and ML model execute.
        * status = "valid_with_warnings"
        * risk_level, probabilities, confidence, validation_warnings are returned.
    - If validation passes without warnings:
        * Preprocessor and ML model execute.
        * status = "valid"
        * risk_level, probabilities, confidence are returned with empty errors/warnings.

    Parameters:
    -----------
    input_data : dict, list of dicts, or pandas.DataFrame
        Cryptographic asset attribute dictionary or batch.
    model_dir : str or Path, optional
        Path to the exported model directory (defaults to models/final).

    Returns:
    --------
    dict or list of dicts:
        Prediction response object(s).
    """
    model, preprocessor, metadata, schema = get_model_artifacts(model_dir)
    version = metadata.get("model_version", "1.1.0")

    is_single_item = False
    if isinstance(input_data, dict):
        is_single_item = True
        records = [input_data]
    elif isinstance(input_data, list):
        records = input_data
    elif isinstance(input_data, pd.DataFrame):
        records = input_data.to_dict(orient="records")
    else:
        raise ValueError(
            f"Unsupported input type '{type(input_data)}'. "
            f"Expected dict, list of dicts, or pandas DataFrame."
        )

    if len(records) == 0:
        return []

    # Validate and canonicalize each record
    validation_summaries = []
    canonical_records = []
    has_any_errors = False

    for r in records:
        valid, clean_r, errs, warns = canonicalize_and_validate_record(r, schema)
        validation_summaries.append({"valid": valid, "errors": errs, "warnings": warns})
        canonical_records.append(clean_r)
        if not valid:
            has_any_errors = True

    # If single item has validation errors, block model prediction immediately
    if is_single_item and not validation_summaries[0]["valid"]:
        val_info = validation_summaries[0]
        return {
            "risk_level": None,
            "probabilities": None,
            "model_version": version,
            "model_confidence": None,
            "status": "validation_error",
            "validation_errors": val_info["errors"],
            "validation_warnings": val_info["warnings"],
        }

    # For batch records, construct per-record results
    results = []
    valid_indices = []
    valid_records_to_infer = []

    for i, val_info in enumerate(validation_summaries):
        if not val_info["valid"]:
            # Validation error blocks prediction for this item
            res = {
                "risk_level": None,
                "probabilities": None,
                "model_version": version,
                "model_confidence": None,
                "status": "validation_error",
                "validation_errors": val_info["errors"],
                "validation_warnings": val_info["warnings"],
            }
            results.append(res)
        else:
            results.append(None)  # Placeholder to fill after batch inference
            valid_indices.append(i)
            valid_records_to_infer.append(canonical_records[i])

    # If there are valid records, run inference
    if valid_records_to_infer:
        df_input = pd.DataFrame(valid_records_to_infer)

        expected_cols = None
        if hasattr(preprocessor, "feature_names_in_"):
            expected_cols = list(preprocessor.feature_names_in_)
        elif schema and "features" in schema:
            expected_cols = [f["name"] for f in schema["features"]]

        if expected_cols:
            for col in expected_cols:
                if col not in df_input.columns:
                    df_input[col] = np.nan
            df_input = df_input[expected_cols]

        try:
            X_trans = preprocessor.transform(df_input)
            preds = model.predict(X_trans)
            if hasattr(preds, "squeeze"):
                preds = preds.squeeze().astype(int)
            has_proba = hasattr(model, "predict_proba")
            probs = model.predict_proba(X_trans) if has_proba else None

            for local_idx, orig_idx in enumerate(valid_indices):
                p_idx = int(preds[local_idx]) if len(valid_indices) > 1 else int(preds)
                pred_label = CLASS_NAMES[p_idx]

                if probs is not None:
                    sample_probs = probs[local_idx] if len(valid_indices) > 1 else probs[0]
                    prob_dict = {CLASS_NAMES[c]: round(float(sample_probs[c]), 4) for c in range(4)}
                    conf = float(sample_probs[p_idx])
                else:
                    prob_dict = {CLASS_NAMES[c]: (1.0 if c == p_idx else 0.0) for c in range(4)}
                    conf = 1.0

                val_info = validation_summaries[orig_idx]
                item_status = "valid_with_warnings" if val_info["warnings"] else "valid"

                res = {
                    "risk_level": pred_label,
                    "probabilities": prob_dict,
                    "model_version": version,
                    "model_confidence": round(conf, 4),
                    "status": item_status,
                    "validation_warnings": val_info["warnings"],
                    "validation_errors": [],
                }
                results[orig_idx] = res

        except Exception as e:
            err_msg = f"Preprocessing transformation error: {str(e)}"
            for orig_idx in valid_indices:
                val_info = validation_summaries[orig_idx]
                results[orig_idx] = {
                    "risk_level": None,
                    "probabilities": None,
                    "model_version": version,
                    "model_confidence": None,
                    "status": "validation_error",
                    "validation_errors": [err_msg] + val_info["errors"],
                    "validation_warnings": val_info["warnings"],
                }

    return results[0] if is_single_item else results


def main():
    parser = argparse.ArgumentParser(
        description="ECDAT Quantum Risk Model Inference CLI"
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to JSON file containing single asset or list of assets",
    )
    parser.add_argument(
        "--model-dir",
        type=str,
        default="models/final",
        help="Directory containing packaged model artifacts",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional path to save output prediction JSON",
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] Error: Input file '{in_path}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(in_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error parsing input JSON '{in_path}': {e}", file=sys.stderr)
        sys.exit(1)

    result = predict_quantum_risk(data, model_dir=args.model_dir)

    output_str = json.dumps(result, indent=2)
    print(output_str)

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"\n[OK] Prediction written to: {out_p.resolve()}")


if __name__ == "__main__":
    main()
