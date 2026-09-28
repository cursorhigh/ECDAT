"""
Automated Pytest Suite for Model Artifacts and Pipeline Compatibility
Covers Requirements 6, 12
"""

import json
from pathlib import Path
import pytest
import joblib
import numpy as np
import pandas as pd

FINAL_DIR = Path("models/final")
CANDIDATES_DIR = Path("models/candidates")


def test_6_model_artifact_loads_successfully():
    """Requirement 6: Test that the final model artifact loads successfully and supports inference methods."""
    model_path = FINAL_DIR / "model.joblib"
    assert model_path.exists(), f"Final model binary missing at: {model_path.resolve()}"
    model = joblib.load(model_path)
    assert hasattr(model, "predict"), "Model artifact missing 'predict' method"
    assert hasattr(model, "predict_proba"), "Model artifact missing 'predict_proba' method"


def test_12_final_model_and_preprocessing_pipeline_remain_compatible():
    """Requirement 12: Test that final model and preprocessing pipeline remain fully compatible."""
    preprocessor = joblib.load(FINAL_DIR / "preprocessor.joblib")
    model = joblib.load(FINAL_DIR / "model.joblib")

    # Load release schema
    with open(FINAL_DIR / "feature_schema.json", "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Construct mock valid sample
    synthetic_sample = pd.DataFrame([{
        "algorithm": "RSA-2048",
        "algorithm_family": "asymmetric",
        "crypto_role": "encryption",
        "key_or_hash_size_bits": 2048,
        "quantum_attack_type": "Shor",
        "quantum_vulnerable": 1,
        "classical_security_bits_est": 112,
        "nist_security_category": 0,
        "deprecated_or_disallowed": 0,
        "protocol": "TLS1.2",
        "crypto_library": "OpenSSL",
        "deployment_environment": "cloud",
        "environment_context": "internet_service",
        "implementation_age_years": 4.0,
        "key_age_days": 365,
        "key_rotation_interval_days": 365,
        "certificate_remaining_days": 90,
        "data_sensitivity": 4,
        "business_criticality": 4,
        "data_lifetime_years": 8.0,
        "migration_time_years": 2.0,
        "migration_complexity": 3,
        "crypto_agility": 3,
        "internet_exposed": 1,
        "external_facing": 1,
        "dependency_count": 10,
        "downstream_system_count": 4,
        "HNDL_exposure": 0.5,
        "data_at_rest": 0,
        "key_reuse_detected": 0,
        "hardware_dependency": 0,
        "vendor_support_score": 4,
        "inventory_confidence": 4,
        "compliance_criticality": 4,
        "quantum_attack_scenario": "notional_future",
        "estimated_attack_time_log10_hours": 6.0,
        "quantum_estimate_confidence": "scenario-dependent",
    }])

    # Preprocessor output dimension must match model input expectation
    X_trans = preprocessor.transform(synthetic_sample)
    assert X_trans.shape == (1, 151)

    preds = model.predict(X_trans)
    probs = model.predict_proba(X_trans)

    assert len(preds) == 1
    assert probs.shape == (1, 4)
