"""
Automated Pytest Suite for ECDAT Preprocessing Pipeline
Covers Requirements 1, 2, 3, 4, 5
"""

import json
from pathlib import Path
import pytest
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer

DATA_DIR = Path("data/processed")
MODEL_DIR = Path("models/preprocessor")
EXCEL_PATH = Path("data/ECDAT_Industry_Quantum_Risk_Dataset_100K.xlsx")


@pytest.fixture
def synthetic_valid_sample_df():
    """Independent synthetic valid DataFrame with all 37 input features."""
    return pd.DataFrame([{
        "algorithm": "AES-256",
        "algorithm_family": "symmetric",
        "crypto_role": "encryption",
        "key_or_hash_size_bits": 256,
        "quantum_attack_type": "Grover",
        "quantum_vulnerable": 0,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "deprecated_or_disallowed": 0,
        "protocol": "TLS1.3",
        "crypto_library": "OpenSSL",
        "deployment_environment": "cloud",
        "environment_context": "financial",
        "implementation_age_years": 2.5,
        "key_age_days": 180,
        "key_rotation_interval_days": 90,
        "certificate_remaining_days": 200,
        "data_sensitivity": 4,
        "business_criticality": 4,
        "data_lifetime_years": 5.0,
        "migration_time_years": 1.2,
        "migration_complexity": 2,
        "crypto_agility": 4,
        "internet_exposed": 1,
        "external_facing": 1,
        "dependency_count": 5,
        "downstream_system_count": 3,
        "HNDL_exposure": 0.1,
        "data_at_rest": 0,
        "key_reuse_detected": 0,
        "hardware_dependency": 0,
        "vendor_support_score": 5,
        "inventory_confidence": 5,
        "compliance_criticality": 4,
        "quantum_attack_scenario": "generic_quantum_effect",
        "estimated_attack_time_log10_hours": 8.5,
        "quantum_estimate_confidence": "not-applicable",
    }])


def test_1_dataset_loads_correctly():
    """Requirement 1: Test that dataset workbook exists and loads correctly."""
    assert EXCEL_PATH.exists(), f"Dataset workbook missing at: {EXCEL_PATH.resolve()}"
    df_sample = pd.read_excel(EXCEL_PATH, sheet_name="training_data", nrows=10)
    assert len(df_sample) == 10
    assert len(df_sample.columns) >= 38


def test_2_expected_target_column_exists():
    """Requirement 2: Test that expected target column 'risk_level' exists with valid classes."""
    df_sample = pd.read_excel(EXCEL_PATH, sheet_name="training_data", nrows=50)
    assert "risk_level" in df_sample.columns
    allowed_classes = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    observed_classes = set(df_sample["risk_level"].dropna().unique())
    assert observed_classes.issubset(allowed_classes)


def test_3_leakage_columns_are_excluded():
    """Requirement 3: Test that potential leakage columns and identifiers are strictly excluded."""
    forbidden = ["asset_id", "risk_score", "risk_level", "recommended_action"]
    with open(MODEL_DIR / "metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    raw_features = meta["raw_features"]["all"]
    transformed_features = meta["transformed_feature_names"]

    for col in forbidden:
        assert col not in raw_features, f"Forbidden column '{col}' found in raw features list"
        for name in transformed_features:
            assert col not in name, f"Forbidden column '{col}' leaked into transformed features: '{name}'"


def test_4_preprocessing_pipeline_can_transform_valid_data(synthetic_valid_sample_df):
    """Requirement 4: Test that the preprocessing pipeline can transform valid raw data."""
    preprocessor = joblib.load(MODEL_DIR / "preprocessor.joblib")
    assert isinstance(preprocessor, ColumnTransformer)

    transformed = preprocessor.transform(synthetic_valid_sample_df)
    assert transformed.shape == (1, 151)
    assert not np.isnan(transformed).any()


def test_5_preprocessing_rejects_invalid_schema_appropriately():
    """Requirement 5: Test that preprocessing pipeline rejects invalid schema appropriately."""
    preprocessor = joblib.load(MODEL_DIR / "preprocessor.joblib")
    df_corrupted = pd.DataFrame([{"invalid_random_column_abc": 123}])

    with pytest.raises(Exception):
        preprocessor.transform(df_corrupted)
