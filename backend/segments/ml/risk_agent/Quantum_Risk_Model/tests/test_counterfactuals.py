"""
Automated Counterfactual and Monotonicity Test Suite for ECDAT Quantum Risk Model

Verifies:
1. Schema validation passes for all counterfactual scenarios with 0 errors and 0 warnings.
2. Predictions succeed and return valid risk levels in {LOW, MEDIUM, HIGH, CRITICAL}.
3. Probabilities sum approximately to 1.0.
4. Directional and behavioral expectations:
   - AES-256 (symmetric) should not have higher risk or higher P(CRITICAL) than RSA-2048 under identical context.
   - Low-context RSA should exhibit lower predicted risk / lower P(CRITICAL) than Baseline RSA.
   - Extreme RSA should exhibit equal or higher risk / P(CRITICAL) than Baseline RSA.
"""

import json
from pathlib import Path
import pytest
from src.predict import predict_quantum_risk, validate_input_record


@pytest.fixture(scope="module")
def schema():
    schema_path = Path("models/final/feature_schema.json")
    assert schema_path.exists(), "Feature schema missing at models/final/feature_schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def baseline_rsa():
    with open("examples/test_rsa_2048.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def aes_256_counterfactual():
    with open("examples/test_aes_256_counterfactual.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def low_context_rsa():
    with open("examples/test_rsa_2048_low_context_counterfactual.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def extreme_rsa():
    with open("examples/test_rsa_2048_extreme.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_1_counterfactual_schema_validation(
    schema, baseline_rsa, aes_256_counterfactual, low_context_rsa, extreme_rsa
):
    """Verify that all 4 counterfactual test cases pass strict schema validation with 0 errors and 0 warnings."""
    cases = [
        ("Baseline RSA-2048", baseline_rsa),
        ("AES-256 Counterfactual", aes_256_counterfactual),
        ("Low-Context RSA", low_context_rsa),
        ("Extreme RSA", extreme_rsa),
    ]

    for name, data in cases:
        is_valid, errors, warnings = validate_input_record(data, schema)
        assert is_valid is True, f"{name} failed schema validation with errors: {errors}"
        assert len(errors) == 0, f"{name} produced schema validation errors: {errors}"
        assert len(warnings) == 0, f"{name} produced schema validation warnings: {warnings}"


def test_2_counterfactual_inference_validity(
    baseline_rsa, aes_256_counterfactual, low_context_rsa, extreme_rsa
):
    """Verify that predictions succeed, probabilities sum to 1, and classes are valid."""
    cases = [
        ("Baseline RSA-2048", baseline_rsa),
        ("AES-256 Counterfactual", aes_256_counterfactual),
        ("Low-Context RSA", low_context_rsa),
        ("Extreme RSA", extreme_rsa),
    ]

    valid_classes = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    for name, data in cases:
        res = predict_quantum_risk(data)
        assert res["status"] in ["valid", "valid_with_warnings", "success"], f"{name} status was {res.get('status')}"
        assert res["risk_level"] in valid_classes, f"{name} risk level {res.get('risk_level')} not in {valid_classes}"
        assert "model_version" in res
        assert 0.0 <= res["model_confidence"] <= 1.0

        probs = res["probabilities"]
        assert set(probs.keys()) == valid_classes
        for c, p in probs.items():
            assert 0.0 <= p <= 1.0
        assert pytest.approx(sum(probs.values()), abs=1e-3) == 1.0


def test_3_directional_behavior_aes_vs_rsa(baseline_rsa, aes_256_counterfactual):
    """
    Directional Test:
    AES-256 (symmetric Grover-only primitive) should not have higher risk
    or higher P(CRITICAL) than Shor-vulnerable RSA-2048 under identical context.
    """
    res_rsa = predict_quantum_risk(baseline_rsa)
    res_aes = predict_quantum_risk(aes_256_counterfactual)

    p_crit_rsa = res_rsa["probabilities"]["CRITICAL"]
    p_crit_aes = res_aes["probabilities"]["CRITICAL"]

    # AES-256 P(CRITICAL) should be less than or equal to RSA-2048 P(CRITICAL)
    assert p_crit_aes <= p_crit_rsa, (
        f"Behavioral Violation: AES-256 P(CRITICAL)={p_crit_aes:.4f} is higher than RSA-2048 P(CRITICAL)={p_crit_rsa:.4f}"
    )

    # AES-256 should have higher lower-tier probability mass (LOW + MEDIUM) than RSA-2048
    lower_tier_rsa = res_rsa["probabilities"]["LOW"] + res_rsa["probabilities"]["MEDIUM"]
    lower_tier_aes = res_aes["probabilities"]["LOW"] + res_aes["probabilities"]["MEDIUM"]
    assert lower_tier_aes >= lower_tier_rsa, (
        f"Expected AES-256 to have >= lower-tier probability than RSA-2048 ({lower_tier_aes:.4f} vs {lower_tier_rsa:.4f})"
    )


def test_4_directional_behavior_low_context_rsa(baseline_rsa, low_context_rsa):
    """
    Directional Test:
    Reducing business/exposure risk for RSA-2048 should significantly reduce predicted risk.
    """
    res_base = predict_quantum_risk(baseline_rsa)
    res_low = predict_quantum_risk(low_context_rsa)

    p_crit_base = res_base["probabilities"]["CRITICAL"]
    p_crit_low = res_low["probabilities"]["CRITICAL"]

    # Low context P(CRITICAL) must be lower than baseline P(CRITICAL)
    assert p_crit_low < p_crit_base, (
        f"Behavioral Violation: Low-context RSA P(CRITICAL)={p_crit_low:.4f} is not lower than baseline {p_crit_base:.4f}"
    )

    # Ordinal risk level of low-context should be lower than baseline (CRITICAL -> MEDIUM/LOW/HIGH)
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    assert rank[res_low["risk_level"]] < rank[res_base["risk_level"]], (
        f"Expected low-context risk level {res_low['risk_level']} to be strictly lower than baseline {res_base['risk_level']}"
    )


def test_5_directional_behavior_extreme_rsa(baseline_rsa, extreme_rsa):
    """
    Directional Test:
    Extreme high-risk context should maintain or increase risk relative to Baseline RSA.
    """
    res_base = predict_quantum_risk(baseline_rsa)
    res_ext = predict_quantum_risk(extreme_rsa)

    p_crit_base = res_base["probabilities"]["CRITICAL"]
    p_crit_ext = res_ext["probabilities"]["CRITICAL"]

    # Extreme RSA P(CRITICAL) should be at least as high as baseline
    assert p_crit_ext >= p_crit_base - 1e-4, (
        f"Behavioral Violation: Extreme RSA P(CRITICAL)={p_crit_ext:.4f} decreased relative to baseline {p_crit_base:.4f}"
    )
    assert res_ext["risk_level"] == "CRITICAL"
