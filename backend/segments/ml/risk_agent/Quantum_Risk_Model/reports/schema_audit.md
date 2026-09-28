# ECDAT Quantum Risk ML Model — Training & Inference Schema Audit Report

**Date:** 2026-09-25  
**Version:** 1.0.0  
**Status:** COMPLETE & VERIFIED  

---

## Executive Summary

An exhaustive audit of the **ECDAT Quantum Risk ML model** training dataset (`data/ECDAT_Industry_Quantum_Risk_Dataset_100K.xlsx`), preprocessing pipeline, exported feature schema (`models/final/feature_schema.json`), and production inference engine (`src/predict.py`) was conducted.

The audit determined that the model's training pipeline was mathematically consistent with the raw dataset. The three validation warnings observed during prior inference were caused by out-of-vocabulary and mismatched values in the user test input, coupled with loose validation logic in `src/predict.py`. All schema artifacts and inference validators have been updated, an exact-vocabulary test input (`examples/test_rsa_2048.json`) has been created, and automated regression tests now pass 100% (13/13 tests in pytest).

---

## Phase 1 — Training Dataset Audit Findings

Direct inspection of `training_data` sheet in `ECDAT_Industry_Quantum_Risk_Dataset_100K.xlsx` across 100,000 rows established:

| Feature Name | Pandas Dtype | Model Feature Type | Missing Values | Observed Domain / Range | Training Required Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `protocol` | `object` | Categorical | 3,127 nulls (3.13%) | 10 unique strings: `['Application', 'Database', 'IPsec', 'JWE/JWS', 'S/MIME', 'SSH', 'Storage', 'TLS1.2', 'TLS1.3', 'X.509/PKI']` | Optional (imputed as 'missing') |
| `quantum_attack_scenario` | `object` | Categorical | 0 nulls | 5 unique strings: `['aggressive_future', 'generic_quantum_effect', 'high_end_future', 'none_known', 'notional_future']` | Required |
| `quantum_estimate_confidence` | `object` | Categorical | 0 nulls | 2 unique strings: `['not-applicable', 'scenario-dependent']` | Required |
| `nist_security_category` | `int64` | Numeric | 0 nulls | Integers `[0, 1, 2, 3, 5]` (min: 0, max: 5) | Required |
| `algorithm` | `object` | Categorical | 0 nulls | 60 unique cryptographic algorithm identifiers | Required |
| `algorithm_family` | `object` | Categorical | 0 nulls | 4 unique strings: `['asymmetric', 'hash', 'pqc', 'symmetric']` | Required |
| `crypto_role` | `object` | Categorical | 0 nulls | 8 unique cryptographic roles | Required |
| `key_or_hash_size_bits` | `int64` | Numeric | 0 nulls | Range: [0, 4096] | Required |
| `quantum_attack_type` | `object` | Categorical | 0 nulls | 6 unique strings: `['Generic', 'Generic quantum', 'Grover', 'Legacy/weak', 'None known', 'Shor']` | Required |
| `quantum_vulnerable` | `int64` | Binary | 0 nulls | Domain: `{0, 1}` | Required |
| `classical_security_bits_est` | `int64` | Numeric | 0 nulls | Range: [0, 256] | Required |
| `deprecated_or_disallowed` | `int64` | Binary | 0 nulls | Domain: `{0, 1}` | Required |
| `crypto_library` | `object` | Categorical | 0 nulls | 14 unique library names | Required |
| `deployment_environment` | `object` | Categorical | 0 nulls | 6 unique environment types | Required |
| `environment_context` | `object` | Categorical | 0 nulls | 8 unique context domains | Required |
| `implementation_age_years` | `float64` | Numeric | 0 nulls | Range: [0.108, 18.0] | Required |
| `key_age_days` | `int64` | Numeric | 0 nulls | Range: [5, 3650] | Required |
| `key_rotation_interval_days` | `int64` | Numeric | 0 nulls | Range: [7, 1825] | Required |
| `certificate_remaining_days` | `int64` | Numeric | 0 nulls | Range: [1, 825] | Required |
| `data_sensitivity` | `int64` | Numeric | 0 nulls | Range: [1, 5] | Required |
| `business_criticality` | `int64` | Numeric | 0 nulls | Range: [1, 5] | Required |
| `data_lifetime_years` | `float64` | Numeric | 0 nulls | Range: [0.294, 50.0] | Required |
| `migration_time_years` | `float64` | Numeric | 0 nulls | Range: [0.1, 3.95] | Required |
| `migration_complexity` | `int64` | Numeric | 0 nulls | Range: [1, 5] | Required |
| `crypto_agility` | `int64` | Numeric | 0 nulls | Range: [1, 5] | Required |
| `internet_exposed` | `int64` | Binary | 0 nulls | Domain: `{0, 1}` | Required |
| `external_facing` | `int64` | Binary | 0 nulls | Domain: `{0, 1}` | Required |
| `dependency_count` | `int64` | Numeric | 0 nulls | Range: [0, 865] | Required |
| `downstream_system_count` | `int64` | Numeric | 0 nulls | Range: [0, 333] | Required |
| `HNDL_exposure` | `float64` | Numeric | 0 nulls | Range: [0.0, 1.0] | Required |
| `data_at_rest` | `int64` | Binary | 0 nulls | Domain: `{0, 1}` | Required |
| `key_reuse_detected` | `int64` | Binary | 0 nulls | Domain: `{0, 1}` | Required |
| `hardware_dependency` | `int64` | Binary | 0 nulls | Domain: `{0, 1}` | Required |
| `vendor_support_score` | `int64` | Numeric | 0 nulls | Range: [1, 5] | Required |
| `inventory_confidence` | `int64` | Numeric | 0 nulls | Range: [1, 5] | Required |
| `compliance_criticality` | `int64` | Numeric | 0 nulls | Range: [1, 5] | Required |
| `estimated_attack_time_log10_hours` | `float64` | Numeric | 53,061 nulls (53.06%) | Range: [0.12, 10.73] | Optional (imputed as median) |

---

## Phase 2 — Preprocessing & Datatype Verification

1. **`quantum_estimate_confidence` Status**:
   - In the raw Excel dataset, this feature is string/object with two values: `'not-applicable'` (53,061 records) and `'scenario-dependent'` (46,939 records).
   - In `src/preprocess.py`, it was correctly identified as a nominal categorical feature and one-hot encoded (`handle_unknown='ignore'`).
   - It is **NOT** a numerical float in the training dataset and was **NOT** incorrectly classified; treating it as categorical preserves the exact semantic partitioning of the training data.
2. **Preprocessing Artifact Consistency**:
   - The saved `models/final/preprocessor.joblib` pipeline contains the fitted ColumnTransformer trained on `X_train` (70,000 rows).
   - The pipeline handles all 37 features (20 numerical, 10 categorical, 7 binary), producing 151 transformed output features.

---

## Phase 3 — Feature Schema Alignment

`models/final/feature_schema.json` and `src/export_model.py` were updated to provide an exact, complete contract:
- Every feature explicitly defines `name`, `type` (`"numeric"`, `"categorical"`, `"binary"`), `required` (boolean), `training_datatype`, `description`, and `imputation_and_encoding`.
- Categorical features specify exhaustive `allowed_values` extracted from the real 100,000-row training dataset (e.g. 60 algorithms, 10 protocols, 5 attack scenarios).
- Numeric features specify exact observed `min` and `max` limits.
- Protocol no longer includes `"nan"` as a valid category string; missing values are correctly documented as `required: false`.

---

## Phase 4 — Inference Validation Enhancements

`src/predict.py` has been updated with a strict, five-way discriminator in `validate_input_record()`:
1. **Valid Value**: Passed directly to preprocessing.
2. **Unknown Categorical Value**: Logged under `validation_warnings` (e.g. `"TLS"` or `"CRQC capable of breaking RSA"`) and safely handled as out-of-vocabulary.
3. **Wrong Datatype**: Logged under `validation_errors` (e.g. passing a string `"Category 1"` to a numeric field, or boolean `True` to a continuous float). Dangerous silent regex conversions (such as `.str.extract(r'(\d+\.?\d*)')`) have been completely removed.
4. **Missing Value**: Flags missing required features under `validation_errors`.
5. **Out-of-Range Numeric Value**: Logged under `validation_warnings` if a value falls outside the observed training bounds `[min, max]`.

---

## Phase 5 — Verified Sample Test Payload

`examples/test_rsa_2048.json` was created using exact training vocabulary and data types:
- `protocol`: `"TLS1.2"` (valid category)
- `quantum_attack_scenario`: `"notional_future"` (valid category)
- `quantum_estimate_confidence`: `"scenario-dependent"` (valid category)
- `nist_security_category`: `1` (valid integer)

When tested against `src/predict.py`:
```json
{
  "risk_level": "CRITICAL",
  "probabilities": {
    "LOW": 0.0,
    "MEDIUM": 0.0,
    "HIGH": 0.0007,
    "CRITICAL": 0.9993
  },
  "model_version": "1.0.0",
  "model_confidence": 0.9993,
  "status": "success"
}
```
Validation warnings: **0**  
Validation errors: **0**  

---

## Phase 6 — Retraining Decision

**Retraining Required:** **NO**

**Rationale:**
The trained model (`models/final/model.joblib`) and preprocessing pipeline (`models/final/preprocessor.joblib`) were already trained on the genuine feature definitions and data types present in the Excel training set. The initial inference warnings were entirely caused by synthetic test input value mismatches (`"TLS"`, `"CRQC capable of breaking RSA"`, and `"0.7"`) rather than any pipeline bug. Retraining would not change feature dimensions or model weights.

---

## Phase 7 — Regression Testing

Added `test_13_rsa_2048_schema_and_inference_regression` in `tests/test_prediction.py`.  
Running `pytest -v` produces:
```
============================= 13 passed in 16.27s =============================
```

All 13 automated tests pass across data loading, target validation, leakage prevention, schema validation, probabilistic prediction, out-of-vocabulary handling, and RSA-2048 regression.

---

## Phase 8 — Changed Files

1. [src/export_model.py](file:///d:/Quantum_Risk_Model/src/export_model.py): Enhanced `generate_feature_schema` to extract exact training vocabulary and bounds from raw data.
2. [models/final/feature_schema.json](file:///d:/Quantum_Risk_Model/models/final/feature_schema.json): Complete 37-feature schema with exact `min`/`max` and `allowed_values`.
3. [src/predict.py](file:///d:/Quantum_Risk_Model/src/predict.py): Implemented strict schema validation distinguishing valid, unknown categorical, wrong datatype, missing required, and out-of-range numerics.
4. [examples/test_rsa_2048.json](file:///d:/Quantum_Risk_Model/examples/test_rsa_2048.json): Standard test payload aligned with training schema.
5. [tests/test_prediction.py](file:///d:/Quantum_Risk_Model/tests/test_prediction.py): Added regression test for schema validation and updated missing field assertions.
6. [reports/schema_audit.json](file:///d:/Quantum_Risk_Model/reports/schema_audit.json): Machine-readable audit results.
7. [reports/schema_audit.md](file:///d:/Quantum_Risk_Model/reports/schema_audit.md): Comprehensive schema audit report.
