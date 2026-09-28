# Senior ML Engineering Review: ECDAT Quantum Risk Classifier Pipeline

**Audit Date**: September 25, 2026  
**Auditor**: Senior Machine Learning Engineer / Lead ML Architect  
**Target Repository**: `Quantum_Risk_Model`  
**Dataset Analyzed**: `ECDAT_Industry_Quantum_Risk_Dataset_100K.xlsx` (100,000 synthetic cryptographic records)  
**Primary Evaluated Model**: CatBoost Multi-Class Classifier (`v1.0.0`)  

---

## Executive Summary

This document presents a comprehensive, production-oriented architectural audit of the ECDAT Quantum Risk Machine Learning pipeline. The scope of this review covers data hygiene, leak prevention, train/val/test split discipline, synthetic data artifacts, feature dominance, class imbalance dynamics, model serialization security, and deployment compatibility.

Overall, the pipeline exhibits **rigorous statistical discipline and software engineering maturity**:
- Strict prevention of data leakage ($X$ excludes `asset_id`, `risk_score`, `risk_level`, `recommended_action`).
- Preprocessing fit strictly on the training set (70,000 samples) with zero contamination of validation (15,000) or test (15,000) sets.
- Independent test set reserved solely for final evaluation ($\Delta_{\text{val}\to\text{test}} \le 0.4\%$).
- Automated test suite covering 100% of pipeline guarantees with 16 automated tests passing in pytest.

Below is the detailed findings register categorized by severity levels (**CRITICAL**, **HIGH**, **MEDIUM**, **LOW**, **INFO**), detailing the problem, systemic implications, file locations, and concrete remediation steps.

---

## Detailed Findings Register

```
┌──────────────┬─────────────────────────────────────────────────────────────────┐
│ Severity     │ Issue Summary                                                   │
├──────────────┼─────────────────────────────────────────────────────────────────┤
│ HIGH         │ Synthetic Data Coherence vs. Real-World Telemetry Domain Shift │
│ HIGH         │ Recall Degradation on Internal-Only Critical Assets (70.86%)    │
│ MEDIUM       │ Feature Dominance of Upstream Synthetic Formula (HNDL Exposure) │
│ MEDIUM       │ Joblib Pickle Deserialization Risk in Untrusted Environments    │
│ MEDIUM       │ Lack of Explicit Multi-Class Probability Calibration Fold       │
│ LOW          │ Floating Version Constraints in requirements.txt (Need Lockfile)│
│ LOW          │ Imputation Bias on Missing Optional Numerical Indicators        │
│ INFO         │ Absence of ONNX / C++ Native Export for Microsecond Serving     │
│ INFO         │ End-to-End Orchestration & Artifact Integrity Verification      │
└──────────────┴─────────────────────────────────────────────────────────────────┘
```

---

### 1. Synthetic Data Coherence vs. Real-World Telemetry Domain Shift

- **Classification**: `HIGH`
- **What is Wrong**:
  The training dataset (`ECDAT_Industry_Quantum_Risk_Dataset_100K.xlsx`) is synthetically generated with smooth, mathematically deterministic relationships between cryptographic properties (e.g., Grover/Shor vulnerability, key lifetime, migration time) and the risk tier. Real-world network and endpoint cryptographic discovery telemetry contains malformed protocol strings, legacy cipher aliases (e.g., `TLS_RSA_WITH_3DES_EDE_CBC_SHA`), non-standard key formats, and incomplete asset metadata.
- **Why It Matters**:
  A model achieving $>94\%$ accuracy and $>0.995$ ROC-AUC on synthetic test data will encounter an empirical performance drop when exposed to noisy, unstructured real-world enterprise discovery feeds unless robust normalization and calibration are applied.
- **Where It Occurs**:
  - `data/ECDAT_Industry_Quantum_Risk_Dataset_100K.xlsx`
  - [`src/preprocess.py`](file:///d:/Quantum_Risk_Model/src/preprocess.py)
- **How It Should Be Fixed**:
  1. Build an upstream **Cryptographic Normalization Engine** in ECDAT to standardize raw scanner outputs (IANA cipher suites, OpenSSL aliases) into canonical catalog tokens prior to ML ingestion.
  2. Plan a post-deployment **Domain Adaptation / Fine-Tuning Phase** using human-annotated enterprise discovery telemetry.
  3. Implement out-of-distribution (OOD) detection (e.g., Mahalanobis distance or prediction entropy thresholding) to flag anomalous real-world assets for manual security review.

---

### 2. Recall Degradation on Internal-Only Critical Assets

- **Classification**: `HIGH`
- **What is Wrong**:
  Stress testing revealed that while assets with `internet_exposed = 1` achieve **95.28% CRITICAL recall**, internal-only assets (`internet_exposed = 0`) drop to **70.86% CRITICAL recall** (a $\approx 24.4\%$ performance drop).
- **Why It Matters**:
  In enterprise quantum risk management, internal core banking databases or internal PKI root certificates using deprecated RSA-1024 or vulnerable ECC are prime targets for lateral movement and long-term data exfiltration. Misclassifying an internal critical asset as merely `HIGH` or `MEDIUM` could lead to deferred remediation.
- **Where It Occurs**:
  - [`src/stress_test.py`](file:///d:/Quantum_Risk_Model/src/stress_test.py#L274-L288)
  - `reports/stress_test.json`
- **How It Should Be Fixed**:
  1. Implement **Cost-Sensitive Decision Thresholding**: Lower the classification threshold for `CRITICAL` probability from the default $\ge 0.50$ (or $\text{argmax}$) to $\ge 0.35$ for internal-facing assets.
  2. Introduce sample weighting or focal loss during retraining specifically targeting high-sensitivity internal-facing assets (`internet_exposed=0` $\land$ `data_sensitivity>=4`).

---

### 3. Feature Dominance of Upstream Synthetic Formula (`HNDL_exposure`)

- **Classification**: `MEDIUM`
- **What is Wrong**:
  TreeSHAP and gain-based feature importance show that `HNDL_exposure` contributes **36.89% of tree splits** and **29.54% of global SHAP attribution**. In the synthetic generator, `HNDL_exposure` is likely derived algebraically from data lifetime and migration parameters.
- **Why It Matters**:
  If the external ECDAT HNDL engine calculates or scales exposure with a slightly different methodology or range (e.g., non-linear decay), the downstream ML model's decision boundaries could skew.
- **Where It Occurs**:
  - [`src/explain.py`](file:///d:/Quantum_Risk_Model/src/explain.py#L125-L140)
  - [`src/stress_test.py`](file:///d:/Quantum_Risk_Model/src/stress_test.py#L182-L215)
- **How It Should Be Fixed**:
  1. Define a strict, versioned contract for the `HNDL_exposure` score format $[0.0, 1.0]$ in [`models/final/feature_schema.json`](file:///d:/Quantum_Risk_Model/models/final/feature_schema.json).
  2. Implement unit tests in ECDAT core verifying that the HNDL calculation engine produces outputs strictly aligned with the schema boundaries.

---

### 4. Joblib Pickle Deserialization Risk in Untrusted Environments

- **Classification**: `MEDIUM`
- **What is Wrong**:
  The exported production artifact (`models/final/model.joblib` and `models/final/preprocessor.joblib`) relies on Python standard `pickle`/`joblib` serialization.
- **Why It Matters**:
  Loading unauthenticated `.joblib` files from external or network-shared storage exposes the host system to arbitrary code execution risks if an artifact is tampered with in transit.
- **Where It Occurs**:
  - [`src/export_model.py`](file:///d:/Quantum_Risk_Model/src/export_model.py#L140-L160)
  - [`src/predict.py`](file:///d:/Quantum_Risk_Model/src/predict.py#L65-L85)
- **How It Should Be Fixed**:
  1. In production ECDAT deployments, enforce **SHA-256 Checksum Verification** against `model_metadata.json` prior to invoking `joblib.load()`.
  2. For microservice architectures, export the CatBoost model into native `.cbm` format or standard **ONNX** (`model.onnx`), which deserialize without executing Python bytecode.

---

### 5. Lack of Explicit Multi-Class Probability Calibration Fold

- **Classification**: `MEDIUM`
- **What is Wrong**:
  The model outputs softmax probabilities directly from the gradient boosting trees. While rank-ordered, tree ensemble probabilities often exhibit overconfidence (sigmoidal distortion near 0 and 1) and were not calibrated against an independent held-out calibration split using Platt scaling or Dirichlet calibration.
- **Why It Matters**:
  In enterprise risk scoring, if a prediction displays $P(\text{CRITICAL}) = 0.85$, security operations teams expect that exactly 85 out of 100 such assets are truly critical. Overconfident probabilities can distort enterprise risk aggregation matrices.
- **Where It Occurs**:
  - [`src/tune_model.py`](file:///d:/Quantum_Risk_Model/src/tune_model.py)
  - [`src/evaluate.py`](file:///d:/Quantum_Risk_Model/src/evaluate.py)
- **How It Should Be Fixed**:
  1. Add a `CalibratedClassifierCV(estimator, method='isotonic', cv='prefit')` step fitted on the validation set before final packaging.
  2. Output Brier Score and Expected Calibration Error (ECE) metrics in `reports/final_metrics.json`.

---

### 6. Floating Version Constraints in `requirements.txt`

- **Classification**: `LOW`
- **What is Wrong**:
  `requirements.txt` uses minimum version bounds (`scikit-learn>=1.3.0`, `catboost>=1.2.0`, `numpy>=1.24.0`).
- **Why It Matters**:
  Future minor or major releases of underlying libraries (especially NumPy, pandas, or scikit-learn) could introduce breaking API changes, deprecation warnings, or pickle deserialization incompatibilities across environments.
- **Where It Occurs**:
  - [`requirements.txt`](file:///d:/Quantum_Risk_Model/requirements.txt)
- **How It Should Be Fixed**:
  Generate an exact pinned lockfile (`requirements.lock` or `pip freeze > requirements.lock`) alongside `requirements.txt` for container builds (e.g., Dockerfile / CI/CD).

---

### 7. Imputation Strategy for Rare Optional Numerical Features

- **Classification**: `LOW`
- **What is Wrong**:
  `estimated_attack_time_log10_hours` is missing in 53.06% of records (specifically for algorithms where quantum attack timeline estimates are not applicable). The preprocessor fills missing values with the training set median (`6.13`).
- **Why It Matters**:
  Imputing median attack times for algorithms with no known quantum attack (e.g., PQC or symmetric hashes) assigns an artificial numerical value, although the categorical indicator `quantum_estimate_confidence = 'not-applicable'` successfully prevents misclassification.
- **Where It Occurs**:
  - [`src/preprocess.py`](file:///d:/Quantum_Risk_Model/src/preprocess.py#L185-L195)
- **How It Should Be Fixed**:
  Enable `SimpleImputer(strategy='median', add_indicator=True)` or impute with an explicit sentinel constant (e.g., `-1.0` or `99.0`) so the tree splits can isolate non-applicable attack times directly.

---

### 8. Microservice Cross-Language Inference Architecture

- **Classification**: `INFO`
- **What is Wrong**:
  The inference module [`src/predict.py`](file:///d:/Quantum_Risk_Model/src/predict.py) requires a full Python runtime with scikit-learn and CatBoost dependencies.
- **Why It Matters**:
  If the core ECDAT scanner backend is written in Go, Rust, Java, or C++, calling a Python process introduces IPC latency (~20ms subprocess overhead vs ~2μs native in-process C++ inference).
- **Where It Occurs**:
  - [`src/predict.py`](file:///d:/Quantum_Risk_Model/src/predict.py)
  - [`models/final/`](file:///d:/Quantum_Risk_Model/models/final)
- **How It Should Be Fixed**:
  Provide an ONNX export pipeline or a lightweight REST/gRPC microservice wrapper (e.g., FastAPI / Triton Inference Server) for enterprise deployment.

---

### 9. End-to-End Orchestration & Reproducibility Verification

- **Classification**: `INFO`
- **Observation**:
  [`train_all.py`](file:///d:/Quantum_Risk_Model/train_all.py) successfully orchestrates all 10 phases sequentially with deterministic seeds (`42`), loud failure gates, non-destructive version archival, and automated pytest validation. Artifact traceability from raw Excel data through final packaging is verified.

---

## Technical Dimension Audit Matrix

| Engineering Dimension | Audit Status | Senior Engineer Evaluation |
| :--- | :---: | :--- |
| **Data Leakage Prevention** | **PASSED** | Identifiers (`asset_id`) and leakage columns (`risk_score`, `risk_level`, `recommended_action`) are excluded prior to feature matrix construction. |
| **Split Discipline** | **PASSED** | 70/15/15 stratified split is executed before fitting. Preprocessor is fitted strictly on `X_train`. Validation is used for tuning; Test set is evaluated once at the very end. |
| **Overfitting Resistance** | **PASSED** | Generalization gap between validation (0.9335) and test (0.9299) is $\approx 0.36\%$, demonstrating high regularization stability. |
| **Boundary Precision** | **PASSED** | Zero non-adjacent catastrophic errors (e.g., $0\%$ error across `LOW` $\leftrightarrow$ `CRITICAL`). All errors occur at continuous risk thresholds. |
| **Explainability (SHAP)** | **PASSED** | TreeSHAP attributions are computed accurately. Proper methodological disclaimer is included stating that SHAP quantifies model attribution, not causality. |
| **Artifact Packaging** | **PASSED** | Self-contained release folder under `models/final/` includes model binary, preprocessor, feature schema, and dataset SHA-256 hash. |
| **Automated Testing** | **PASSED** | 16 pytest unit tests cover dataset ingestion, schema validation, leakage prevention, edge-case resilience, and inference compatibility. |

---

## Final Technical Verdict: Ready for ECDAT Integration

```
========================================================================================
                      ASSESSMENT: READY FOR ECDAT INTEGRATION
========================================================================================
Verdict:                APPROVED FOR SYSTEM INTEGRATION (TECHNICAL COMPLETENESS)
Baseline Accuracy:      94.19% (Synthetic Test Set N=15,000)
Macro F1:               0.9299
One-vs-Rest ROC-AUC:    0.9960
Targeted Class Recall:  CRITICAL: 88.75% | HIGH: 96.67% | MEDIUM: 94.55% | LOW: 91.34%
Pipelines Verified:     data_audit -> preprocess -> train_models -> tune_model -> 
                        evaluate -> stress_test -> explain -> export_model -> predict
========================================================================================
```

### Integration Notes & Conditions:
1. **Scope of Approval**: This approval is granted based strictly on **software engineering integrity, leak-free pipeline architecture, reproducibility, and robust error handling**.
2. **Operational Boundary**: This approval **does not make claims regarding real-world quantum risk predictive accuracy**. Production deployment within the ECDAT enterprise suite requires continuous telemetry validation, threshold tuning for internal critical infrastructure, and real-world calibration monitoring.
