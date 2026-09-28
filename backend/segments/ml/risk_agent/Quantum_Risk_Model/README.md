# ECDAT Quantum Risk Model

Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) — Machine Learning Risk Classification Component.

This repository implements a production-grade, reproducible machine learning pipeline that classifies enterprise cryptographic assets into four quantum risk tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) using **37 clean cryptographic features**, strictly excluding identifiers and leakage columns (`asset_id`, `risk_score`, `risk_level`, `recommended_action`).

---

## 📋 Canonical Feature Schema (v1.1.0)

The model expects 37 cryptographic features categorized into Numerical (20), Categorical (10), and Binary (7). The validation engine supports standard canonicalization to seamlessly ingest inputs from CBOM analyzers, network discovery tools, and manual configurations.

| Feature Name | Semantic Type | Datatype | Allowed Values / Domain | Canonicalization & Validation Rules |
| :--- | :--- | :--- | :--- | :--- |
| `algorithm` | Categorical | string | 60 standard algorithms (e.g. `RSA-2048`, `AES-256`, `Kyber768`) | Trim whitespace. Unknown categories trigger OOV warning. |
| `algorithm_family` | Categorical | string | `asymmetric`, `symmetric`, `hash`, `pqc` | Lowercase string. |
| `crypto_role` | Categorical | string | `AEAD`, `KDF`, `MAC`, `XOF`, `encryption`, `hash`, `key_establishment`, `signature` | Trim whitespace. |
| `key_or_hash_size_bits` | Numeric | integer | Range: $[0, 16384]$ | Must be non-negative integer/float. |
| `quantum_attack_type` | Categorical | string | `Generic`, `Generic quantum`, `Grover`, `Legacy/weak`, `None known`, `Shor` | Trim whitespace. |
| `quantum_vulnerable` | Binary | boolean / int | `{0, 1}` / `{True, False}` | `true`/`1` $\to 1$, `false`/`0` $\to 0$. |
| `classical_security_bits_est` | Numeric | integer | Range: $[0, 1024]$ | Must be non-negative. |
| `nist_security_category` | Numeric (ordinal) | integer | Range: $[0, 5]$ | Accepts integer $0..5$ or strings (`"Category 1"` $\to 1$, `"Cat 2"` $\to 2$). |
| `deprecated_or_disallowed` | Binary | boolean / int | `{0, 1}` / `{True, False}` | `true`/`1` $\to 1$, `false`/`0` $\to 0$. |
| `protocol` | Categorical | string | `TLS1.2`, `TLS1.3`, `SSH`, `IPsec`, `Database`, `Storage`, `Application`, `X.509/PKI`, `S/MIME`, `JWE/JWS` | Optional. Canonicalizes `"TLS"`, `"HTTPS"`, `"SSL"` $\to$ `"TLS1.2"`. |
| `crypto_library` | Categorical | string | 14 standard libraries (e.g. `OpenSSL`, `BoringSSL`, `Windows CNG`, `libsodium`) | Trim whitespace. |
| `deployment_environment` | Categorical | string | `cloud`, `container`, `edge`, `hybrid`, `on_prem`, `saas` | Lowercase string. |
| `environment_context` | Categorical | string | `critical_infrastructure`, `data_platform`, `developer_ci`, `enterprise_internal`, `financial`, `government`, `healthcare`, `internet_service` | Lowercase string. |
| `implementation_age_years` | Numeric | float | Domain: $[0.0, 50.0]$ | Non-negative float. |
| `key_age_days` | Numeric | integer | Domain: $[0, 36500]$ | Non-negative integer. |
| `key_rotation_interval_days` | Numeric | integer | Domain: $[0, 36500]$ | Non-negative integer. |
| `certificate_remaining_days` | Numeric | integer | Domain: $[0, 36500]$ | Non-negative integer. |
| `data_sensitivity` | Numeric (ordinal) | integer | Range: $[1, 5]$ (1 = Public, 5 = Top Secret) | Integer in $[1, 5]$. |
| `business_criticality` | Numeric (ordinal) | integer | Range: $[1, 5]$ (1 = Non-essential, 5 = Mission Critical) | Integer in $[1, 5]$. |
| `data_lifetime_years` | Numeric | float | Domain: $[0.0, 100.0]$ | Non-negative float. |
| `migration_time_years` | Numeric | float | Domain: $[0.0, 50.0]$ (Training max: $\approx 3.95$) | Non-negative float. Values $> 3.95$ generate OOD warning. |
| `migration_complexity` | Numeric (ordinal) | integer | Range: $[1, 5]$ (1 = Trivial, 5 = Extreme) | Integer in $[1, 5]$. |
| `crypto_agility` | Numeric (ordinal) | integer | Range: $[1, 5]$ (1 = Hardcoded, 5 = Fully Agile) | Integer in $[1, 5]$. |
| `internet_exposed` | Binary | boolean / int | `{0, 1}` / `{True, False}` | `true`/`1` $\to 1$, `false`/`0` $\to 0$. |
| `external_facing` | Binary | boolean / int | `{0, 1}` / `{True, False}` | `true`/`1` $\to 1$, `false`/`0` $\to 0$. |
| `dependency_count` | Numeric | integer | Domain: $[0, 10000]$ | Non-negative integer. |
| `downstream_system_count` | Numeric | integer | Domain: $[0, 5000]$ | Non-negative integer. |
| `HNDL_exposure` | Numeric | float | Range: $[0.0, 1.0]$ | Accepts continuous float or boolean (`True` $\to 1.0$, `False` $\to 0.0$). |
| `data_at_rest` | Binary | boolean / int | `{0, 1}` / `{True, False}` | `true`/`1` $\to 1$, `false`/`0` $\to 0$. |
| `key_reuse_detected` | Binary | boolean / int | `{0, 1}` / `{True, False}` | `true`/`1` $\to 1$, `false`/`0` $\to 0$. |
| `hardware_dependency` | Binary | boolean / int | `{0, 1}` / `{True, False}` | `true`/`1` $\to 1$, `false`/`0` $\to 0$. |
| `vendor_support_score` | Numeric (ordinal) | integer | Range: $[1, 5]$ (1 = Unsupported, 5 = Active) | Integer in $[1, 5]$. |
| `inventory_confidence` | Numeric (ordinal) | integer | Range: $[1, 5]$ (1 = Estimated, 5 = Verified) | Integer in $[1, 5]$. |
| `compliance_criticality` | Numeric (ordinal) | integer | Range: $[1, 5]$ (1 = Low, 5 = Strict) | Integer in $[1, 5]$. |
| `quantum_attack_scenario` | Categorical | string | `notional_future`, `aggressive_future`, `high_end_future`, `generic_quantum_effect`, `none_known` | Canonicalizes standard descriptions (e.g. `"CRQC capable of breaking RSA"` $\to$ `"notional_future"`). |
| `estimated_attack_time_log10_hours` | Numeric | float | Domain: $[0.0, 20.0]$ | Optional. Null when attack timeline not applicable. |
| `quantum_estimate_confidence` | Categorical | string | `not-applicable`, `scenario-dependent` | Accepts strings or numeric confidence ($0.0 \to$ `"not-applicable"`, $>0 \to$ `"scenario-dependent"`). |

---

## 🛡️ Validation & Execution Architecture

The prediction pipeline enforces a strict validation gate:

```
                  RAW ASSET INPUT (JSON / Dict / DataFrame)
                                    │
                                    ▼
                ┌───────────────────────────────────────┐
                │   Canonicalization & Type Parsing     │
                │ • NIST Category ("Category 1" -> 1)   │
                │ • HNDL Boolean (True -> 1.0)          │
                │ • Protocol ("TLS" -> "TLS1.2")        │
                │ • Threat Scenario Aliases             │
                └───────────────────┬───────────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │    Schema Validation    │
                       └────────────┬────────────┘
                                    │
                    Are there validation errors?
                   /                             \
                YES                               NO
               /                                   \
              ▼                                     ▼
 ┌───────────────────────────┐         ┌─────────────────────────┐
 │     BLOCK PREDICTION      │         │  Preprocessing Pipeline │
 │ status: "validation_error"│         │  (ColumnTransformer)    │
 │ risk_level: null          │         └────────────┬────────────┘
 │ probabilities: null       │                      │
 │ errors: [...]             │                      ▼
 └───────────────────────────┘         ┌─────────────────────────┐
                                       │   CatBoost Multi-Class  │
                                       │   Model Inference       │
                                       └────────────┬────────────┘
                                                    │
                                                    ▼
                                       ┌─────────────────────────┐
                                       │ status: "valid" /       │
                                       │ "valid_with_warnings"   │
                                       │ risk_level: TIER        │
                                       │ probabilities: {...}    │
                                       └─────────────────────────┘
```

### Response Status Definitions
- `valid`: All features match schema datatypes, domains, and known categories. Predictions returned.
- `valid_with_warnings`: Schema validation passed, but contains out-of-distribution numeric values (e.g. `migration_time_years = 4.0`) or unknown categorical values safely handled as out-of-vocabulary. Predictions returned.
- `validation_error`: Invalid datatype, missing required feature, or physical domain violation (e.g. negative time, out-of-bounds ordinal score). **Model execution is strictly blocked**.

---

## 📁 Repository Structure

```
quantum-risk-model/
│
├── data/
│   ├── ECDAT_Industry_Quantum_Risk_Dataset_100K.xlsx  # Raw dataset (100,000 assets)
│   └── processed/                                    # Stratified 70/15/15 splits (npy/npz/parquet)
│
├── src/
│   ├── data_audit.py          # Data inspection & leakage detection
│   ├── preprocess.py          # ColumnTransformer preprocessing pipeline
│   ├── train_baseline.py      # Baseline models (Dummy, Logistic Regression, Decision Tree)
│   ├── train_models.py        # RF, XGBoost, CatBoost comparison
│   ├── tune_model.py          # Optuna Bayesian hyperparameter tuning
│   ├── evaluate.py            # Final unbiased evaluation on untouched test set
│   ├── stress_test.py         # Subgroup, exposure & generalization audit
│   ├── explain.py             # Global & local TreeSHAP explainability
│   ├── export_model.py        # Production packaging & schema generator
│   └── predict.py             # Inference API & CLI module
│
├── models/
│   ├── baseline/              # Baseline models
│   ├── candidates/            # Candidate model binaries & validation metrics
│   ├── preprocessor/          # Fitted preprocessor & metadata
│   ├── tuned/                 # Tuned CatBoost model
│   └── final/                 # Release package (model, preprocessor, schema, metadata)
│
├── reports/
│   ├── data_audit.json
│   ├── split_distribution.json
│   ├── baseline_metrics.json
│   ├── model_comparison.json / .csv
│   ├── tuning_results.json / .csv
│   ├── final_metrics.json
│   ├── final_confusion_matrix.png
│   ├── final_roc_curve.png
│   ├── stress_test.json / .csv
│   └── shap/
│
├── tests/
│   ├── test_preprocessing.py   # Unit tests for preprocessing & splits
│   ├── test_model_artifact.py  # Unit tests for candidate & release packages
│   ├── test_prediction.py      # Comprehensive 14-test validation & inference suite
│   └── test_counterfactuals.py # Monotonicity & directional behavior tests
│
├── examples/
│   ├── sample_input.json       # Representative asset input payload
│   └── user_test_input.json    # Standard test input payload
│
├── train_all.py                # Master end-to-end orchestration pipeline
├── pytest.ini                  # Pytest configuration
├── requirements.txt            # Minimal required dependencies
└── README.md
```

---

## 🚀 Quickstart & Inference

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. CLI Inference
```bash
python src/predict.py --input examples/user_test_input.json
```

Output:
```json
{
  "risk_level": "CRITICAL",
  "probabilities": {
    "LOW": 0.0,
    "MEDIUM": 0.0,
    "HIGH": 0.0011,
    "CRITICAL": 0.9989
  },
  "model_version": "1.1.0",
  "model_confidence": 0.9989,
  "status": "valid_with_warnings",
  "validation_warnings": [
    "Out-of-range numeric value for 'migration_time_years': 4 is above observed training maximum 3.949770411700182."
  ],
  "validation_errors": []
}
```

### 3. Python API Inference
```python
from src.predict import predict_quantum_risk

asset = {
    "algorithm": "RSA-2048",
    "algorithm_family": "asymmetric",
    "crypto_role": "key_establishment",
    "key_or_hash_size_bits": 2048,
    "quantum_attack_type": "Shor",
    "quantum_vulnerable": True,
    "classical_security_bits_est": 112,
    "nist_security_category": "Category 1",
    "deprecated_or_disallowed": False,
    "protocol": "TLS",
    "crypto_library": "OpenSSL",
    "deployment_environment": "cloud",
    "environment_context": "financial",
    "implementation_age_years": 4.0,
    "key_age_days": 240,
    "key_rotation_interval_days": 365,
    "certificate_remaining_days": 120,
    "data_sensitivity": 5,
    "business_criticality": 5,
    "data_lifetime_years": 15,
    "migration_time_years": 3.5,
    "migration_complexity": 5,
    "crypto_agility": 2,
    "dependency_count": 18,
    "downstream_system_count": 9,
    "vendor_support_score": 2,
    "hardware_dependency": True,
    "internet_exposed": True,
    "external_facing": True,
    "HNDL_exposure": True,
    "data_at_rest": False,
    "key_reuse_detected": False,
    "inventory_confidence": 5,
    "compliance_criticality": 5,
    "quantum_attack_scenario": "CRQC capable of breaking RSA",
    "estimated_attack_time_log10_hours": 4.0,
    "quantum_estimate_confidence": 0.7
}

result = predict_quantum_risk(asset)
print(result)
```

---

## 🔁 How to Retrain the Model

To execute the complete, reproducible machine learning lifecycle from data audit through validation tests:
```bash
python train_all.py
```

Or execute individual pipeline stages sequentially:
```bash
# Stage 1: Inspect and audit raw dataset
python src/data_audit.py

# Stage 2: Preprocess & generate stratified splits (70/15/15)
python src/preprocess.py

# Stage 3: Train baseline benchmark models
python src/train_baseline.py

# Stage 4: Train and compare candidate models (RF, XGBoost, CatBoost)
python src/train_models.py

# Stage 5: Tune best candidate model with Bayesian optimization
python src/tune_model.py --n-trials 20

# Stage 6: Run unbiased evaluation on untouched test set
python src/evaluate.py

# Stage 7: Run stress & robustness testing across subgroups
python src/stress_test.py

# Stage 8: Generate TreeSHAP feature attributions and visual explanations
python src/explain.py

# Stage 9: Package final release artifact
python src/export_model.py

# Stage 10: Run automated test suite
pytest -v
```

---

## 📊 Performance Benchmarks

### Untouched Test Set ($N=15,000$)
*Evaluation: Synthetic dataset evaluation*

- **Accuracy**: **94.19%**
- **Macro F1**: **0.9299**
- **Weighted F1**: **0.9419**
- **Macro ROC-AUC**: **0.9960**
- **Macro PR-AUC**: **0.9837**
- **CRITICAL Tier Precision / Recall**: **89.98% / 88.75%**
- **Zero Severe Non-Adjacent Errors**: $0\%$ error across `LOW` $\leftrightarrow$ `CRITICAL`.
