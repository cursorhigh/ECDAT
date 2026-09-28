"""
Automated Pytest Suite for Production Prediction Module & Schema Validation Architecture

Covers all 14 Phase 12 validation and inference guarantees:
1. Valid RSA-2048 input
2. Invalid datatype for nist_security_category
3. Invalid datatype for HNDL_exposure
4. Invalid datatype for quantum_estimate_confidence
5. Unknown protocol (warning, model executes)
6. Unknown quantum attack scenario (warning, model executes)
7. migration_time_years below valid range (error, model blocked)
8. migration_time_years above training range (warning, model executes)
9. Missing required feature (error, model blocked)
10. Extra unexpected feature (warning, model executes)
11. Validation errors strictly prevent model prediction (risk_level=None, probabilities=None)
12. Warnings allow model prediction (status=valid_with_warnings, risk_level populated)
13. Known categorical & canonicalized values work correctly (e.g. "Category 1" -> 1, true -> 1.0, "CRQC capable of breaking RSA" -> notional_future)
14. Model and preprocessor versions match
"""

import json
from pathlib import Path
import pytest
import numpy as np
from src.predict import predict_quantum_risk, validate_input_record, canonicalize_and_validate_record, get_model_artifacts


@pytest.fixture
def mock_representative_sample():
    """Independent synthetic representative sample for testing inference."""
    return {
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
        "implementation_age_years": 5.2,
        "key_age_days": 450,
        "key_rotation_interval_days": 365,
        "certificate_remaining_days": 120,
        "data_sensitivity": 4,
        "business_criticality": 5,
        "data_lifetime_years": 10.0,
        "migration_time_years": 2.5,
        "migration_complexity": 4,
        "crypto_agility": 2,
        "internet_exposed": 1,
        "external_facing": 1,
        "dependency_count": 15,
        "downstream_system_count": 6,
        "HNDL_exposure": 0.65,
        "data_at_rest": 0,
        "key_reuse_detected": 1,
        "hardware_dependency": 0,
        "vendor_support_score": 4,
        "inventory_confidence": 4,
        "compliance_criticality": 5,
        "quantum_attack_scenario": "notional_future",
        "estimated_attack_time_log10_hours": 5.8,
        "quantum_estimate_confidence": "scenario-dependent",
    }


def test_1_valid_rsa_2048_input(mock_representative_sample):
    """Test 1: Valid RSA-2048 input produces valid status, predicted risk tier and probability distribution."""
    result = predict_quantum_risk(mock_representative_sample)
    assert isinstance(result, dict)
    assert result["status"] in ["valid", "valid_with_warnings"]
    assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert "model_version" in result
    assert "model_confidence" in result and 0.0 <= result["model_confidence"] <= 1.0

    probs = result["probabilities"]
    assert set(probs.keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    for p in probs.values():
        assert 0.0 <= p <= 1.0
    assert pytest.approx(sum(probs.values()), abs=1e-3) == 1.0


def test_2_invalid_datatype_for_nist_security_category(mock_representative_sample):
    """Test 2: Invalid datatype for nist_security_category (e.g. unparseable string or list) returns error and blocks prediction."""
    invalid_sample = mock_representative_sample.copy()
    invalid_sample["nist_security_category"] = "INVALID_NON_NUMERIC_CATEGORY"

    result = predict_quantum_risk(invalid_sample)
    assert result["status"] == "validation_error"
    assert result["risk_level"] is None
    assert result["probabilities"] is None
    assert result["model_confidence"] is None
    assert "validation_errors" in result
    assert any("nist_security_category" in err for err in result["validation_errors"])


def test_3_invalid_datatype_for_hndl_exposure(mock_representative_sample):
    """Test 3: Invalid datatype/domain for HNDL_exposure (e.g. out-of-range float or unparseable string) returns error and blocks prediction."""
    invalid_sample = mock_representative_sample.copy()
    invalid_sample["HNDL_exposure"] = 999.0  # Invalid domain: > 1.0

    result = predict_quantum_risk(invalid_sample)
    assert result["status"] == "validation_error"
    assert result["risk_level"] is None
    assert result["probabilities"] is None
    assert result["model_confidence"] is None
    assert any("HNDL_exposure" in err for err in result["validation_errors"])


def test_4_invalid_datatype_for_quantum_estimate_confidence(mock_representative_sample):
    """Test 4: Invalid datatype for quantum_estimate_confidence (e.g. list/dict) returns error and blocks prediction."""
    invalid_sample = mock_representative_sample.copy()
    invalid_sample["quantum_estimate_confidence"] = ["invalid", "list"]

    result = predict_quantum_risk(invalid_sample)
    assert result["status"] == "validation_error"
    assert result["risk_level"] is None
    assert result["probabilities"] is None
    assert result["model_confidence"] is None
    assert any("quantum_estimate_confidence" in err for err in result["validation_errors"])


def test_5_unknown_protocol_warning(mock_representative_sample):
    """Test 5: Unknown protocol generates warning and model successfully executes with safe out-of-vocabulary handling."""
    modified = mock_representative_sample.copy()
    modified["protocol"] = "FUTURE_QUANTUM_MESH_v99"

    result = predict_quantum_risk(modified)
    assert result["status"] == "valid_with_warnings"
    assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert result["probabilities"] is not None
    assert any("FUTURE_QUANTUM_MESH_v99" in w and "protocol" in w for w in result["validation_warnings"])


def test_6_unknown_quantum_attack_scenario_warning(mock_representative_sample):
    """Test 6: Unknown quantum attack scenario generates warning and model successfully executes with safe OOV handling."""
    modified = mock_representative_sample.copy()
    modified["quantum_attack_scenario"] = "hypothetical_alien_computation"

    result = predict_quantum_risk(modified)
    assert result["status"] == "valid_with_warnings"
    assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert result["probabilities"] is not None
    assert any("hypothetical_alien_computation" in w and "quantum_attack_scenario" in w for w in result["validation_warnings"])


def test_7_migration_time_years_below_valid_range(mock_representative_sample):
    """Test 7: migration_time_years below 0.0 (negative time) generates validation error and blocks prediction."""
    invalid_sample = mock_representative_sample.copy()
    invalid_sample["migration_time_years"] = -2.5

    result = predict_quantum_risk(invalid_sample)
    assert result["status"] == "validation_error"
    assert result["risk_level"] is None
    assert result["probabilities"] is None
    assert any("migration_time_years" in err and "negative" in err for err in result["validation_errors"])


def test_8_migration_time_years_above_training_range(mock_representative_sample):
    """Test 8: migration_time_years above observed training maximum (~3.95) generates OOD warning and allows prediction."""
    sample = mock_representative_sample.copy()
    sample["migration_time_years"] = 4.5  # Valid positive time > 3.95

    result = predict_quantum_risk(sample)
    assert result["status"] == "valid_with_warnings"
    assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert result["probabilities"] is not None
    assert any("migration_time_years" in w and "above observed training maximum" in w for w in result["validation_warnings"])


def test_9_missing_required_feature(mock_representative_sample):
    """Test 9: Missing required feature generates validation error and blocks model execution."""
    incomplete_sample = mock_representative_sample.copy()
    del incomplete_sample["algorithm"]

    result = predict_quantum_risk(incomplete_sample)
    assert result["status"] == "validation_error"
    assert result["risk_level"] is None
    assert result["probabilities"] is None
    assert any("Missing required feature 'algorithm'" in err for err in result["validation_errors"])


def test_10_extra_unexpected_feature(mock_representative_sample):
    """Test 10: Extra unexpected feature generates warning, is ignored during inference, and prediction succeeds."""
    sample = mock_representative_sample.copy()
    sample["unrecognized_custom_field_xyz"] = "some_value"

    result = predict_quantum_risk(sample)
    assert result["status"] == "valid_with_warnings"
    assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert any("unrecognized_custom_field_xyz" in w for w in result["validation_warnings"])


def test_11_validation_errors_prevent_model_prediction(mock_representative_sample):
    """Test 11: Validation errors strictly prevent the ML model from running."""
    corrupted_sample = {
        "algorithm": 12345,  # Wrong type for categorical
        "data_sensitivity": 10,  # Out of domain [1, 5]
    }

    result = predict_quantum_risk(corrupted_sample)
    assert result["status"] == "validation_error"
    assert result["risk_level"] is None
    assert result["probabilities"] is None
    assert result["model_confidence"] is None
    assert len(result["validation_errors"]) >= 2


def test_12_warnings_allow_model_prediction(mock_representative_sample):
    """Test 12: Inputs with warnings (e.g. OOD migration time or unknown protocol) successfully execute ML prediction."""
    sample_with_warn = mock_representative_sample.copy()
    sample_with_warn["migration_time_years"] = 4.0

    result = predict_quantum_risk(sample_with_warn)
    assert result["status"] == "valid_with_warnings"
    assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert result["probabilities"] is not None
    assert result["model_confidence"] is not None
    assert len(result["validation_warnings"]) > 0
    assert len(result["validation_errors"]) == 0


def test_13_known_categorical_and_canonicalized_values_work_correctly():
    """Test 13: Canonicalization correctly maps strings like 'Category 1' -> 1, boolean true -> 1.0, 'TLS' -> 'TLS1.2', and domain threat scenarios."""
    user_input_sample = {
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
        "migration_time_years": 3.5,  # within training max
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
        "quantum_estimate_confidence": 0.7,
    }

    result = predict_quantum_risk(user_input_sample)
    assert result["status"] == "valid"
    assert result["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(result["validation_errors"]) == 0
    assert len(result["validation_warnings"]) == 0


def test_14_model_and_preprocessor_versions_match():
    """Test 14: Exported model metadata version matches inference engine metadata."""
    model, preprocessor, metadata, schema = get_model_artifacts()
    assert "model_version" in metadata
    assert metadata["model_version"] == "1.1.0"
    assert schema["schema_version"] == "1.1.0"
