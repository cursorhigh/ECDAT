"""
Final Combined Result Demonstration Script (demo_final_report.py)

Demonstrates the end-to-end unification of:
1. CycloneDX CBOM Asset Catalog
2. 37-Feature CatBoost Quantum Risk Model
3. HNDL Timeline Engine
4. Mosca Inequality Solver (X + Y > Z)
5. Google Gemini AI / Deterministic Report Synthesis with Source Attributions
"""

import sys
import os
import json

backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from segments.ml.final_combined_result import (
    CombinedRiskSynthesizer,
    format_final_terminal_report,
)


def run_demo():
    print("\n" + "=" * 70)
    print("ECDAT FINAL COMBINED POST-QUANTUM RISK SYNTHESIS DEMONSTRATION")
    print("=" * 70 + "\n")

    cbom_document = {
        "crypto_assets": [
            {
                "asset_id": "asset-rsa-2048-001",
                "algorithm": "RSA-2048",
                "family": "rsa",
                "crypto_role": "key_exchange",
                "parameters": {"key_size": 2048},
            },
            {
                "asset_id": "asset-ecdsa-p256-002",
                "algorithm": "ECDSA",
                "family": "ecc",
                "crypto_role": "signature",
                "parameters": {"curve": "P-256"},
            },
            {
                "asset_id": "asset-aes-256-gcm-003",
                "algorithm": "AES-256-GCM",
                "family": "aes",
                "crypto_role": "encryption",
                "parameters": {"key_size": 256, "mode": "GCM"},
            },
            {
                "asset_id": "asset-mlkem-768-004",
                "algorithm": "ML-KEM-768",
                "family": "pqc",
                "crypto_role": "key_exchange",
                "parameters": {"claim": "NIST FIPS 203"},
            },
        ]
    }

    ml_results = {
        "asset-rsa-2048-001": {
            "prediction": "CRITICAL",
            "confidence": 0.948,
            "probabilities": {"CRITICAL": 0.948, "HIGH": 0.04, "MEDIUM": 0.01, "LOW": 0.002},
            "top_contributing_features": ["quantum_vulnerable", "key_size_2048", "asymmetric_key_exchange"],
        },
        "asset-ecdsa-p256-002": {
            "prediction": "HIGH",
            "confidence": 0.892,
            "probabilities": {"CRITICAL": 0.05, "HIGH": 0.892, "MEDIUM": 0.05, "LOW": 0.008},
            "top_contributing_features": ["quantum_vulnerable", "curve_p256", "digital_signature"],
        },
        "asset-aes-256-gcm-003": {
            "prediction": "LOW",
            "confidence": 0.965,
            "probabilities": {"CRITICAL": 0.0, "HIGH": 0.01, "MEDIUM": 0.025, "LOW": 0.965},
            "top_contributing_features": ["quantum_vulnerable=False", "key_size_256", "symmetric_gcm"],
        },
        "asset-mlkem-768-004": {
            "prediction": "LOW",
            "confidence": 0.995,
            "probabilities": {"CRITICAL": 0.0, "HIGH": 0.0, "MEDIUM": 0.005, "LOW": 0.995},
            "top_contributing_features": ["nist_pqc_standardized", "lattice_based_kem"],
        },
    }

    hndl_results = {
        "asset-rsa-2048-001": {
            "hndl": {
                "hndl_exposure_score": 0.88,
                "is_exposed": True,
                "future_decryption_risk": "CRITICAL",
                "threat_vectors": {"harvestability_score": 0.92},
                "timeline": {"exposure_factor": 1.0, "data_expiry_year": 2035},
            }
        },
        "asset-ecdsa-p256-002": {
            "hndl": {
                "hndl_exposure_score": 0.12,
                "is_exposed": False,
                "future_decryption_risk": "LOW",
                "threat_vectors": {"harvestability_score": 0.15},
                "timeline": {"exposure_factor": 0.8},
            }
        },
        "asset-aes-256-gcm-003": {
            "hndl": {
                "hndl_exposure_score": 0.04,
                "is_exposed": False,
                "future_decryption_risk": "NEGLIGIBLE",
                "threat_vectors": {"harvestability_score": 0.05},
                "timeline": {"exposure_factor": 0.8},
            }
        },
        "asset-mlkem-768-004": {
            "hndl": {
                "hndl_exposure_score": 0.00,
                "is_exposed": False,
                "future_decryption_risk": "NEGLIGIBLE",
                "threat_vectors": {"harvestability_score": 0.00},
                "timeline": {"exposure_factor": 0.0},
            }
        },
    }

    mosca_results = {
        "asset-rsa-2048-001": {
            "mosca": {
                "inequality_satisfied": True,
                "urgency_tier": "CRITICAL",
                "migration_posture": "URGENT_DEFICIT",
                "mosca_risk_index": 0.96,
                "variables": {"X_migration_time_years": 4.5, "Y_data_lifetime_years": 8.0, "Z_time_to_crqc_years": 7.0},
                "timeline": {"mosca_deficit_years": 5.5, "must_start_by_year": 2028, "is_overdue_to_start": False},
            }
        },
        "asset-ecdsa-p256-002": {
            "mosca": {
                "inequality_satisfied": True,
                "urgency_tier": "HIGH",
                "migration_posture": "DEFICIT",
                "mosca_risk_index": 0.68,
                "variables": {"X_migration_time_years": 3.0, "Y_data_lifetime_years": 5.0, "Z_time_to_crqc_years": 7.0},
                "timeline": {"mosca_deficit_years": 1.0, "must_start_by_year": 2030, "is_overdue_to_start": False},
            }
        },
        "asset-aes-256-gcm-003": {
            "mosca": {
                "inequality_satisfied": False,
                "urgency_tier": "LOW",
                "migration_posture": "SAFE_BUFFER",
                "mosca_risk_index": 0.05,
                "variables": {"X_migration_time_years": 1.5, "Y_data_lifetime_years": 2.0, "Z_time_to_crqc_years": 7.0},
                "timeline": {"mosca_deficit_years": -3.5, "must_start_by_year": 2033, "is_overdue_to_start": False},
            }
        },
        "asset-mlkem-768-004": {
            "mosca": {
                "inequality_satisfied": False,
                "urgency_tier": "NEGLIGIBLE",
                "migration_posture": "QUANTUM_RESILIENT",
                "mosca_risk_index": 0.00,
                "variables": {"X_migration_time_years": 0.5, "Y_data_lifetime_years": 10.0, "Z_time_to_crqc_years": 7.0},
                "timeline": {"mosca_deficit_years": -6.5, "must_start_by_year": 2033, "is_overdue_to_start": False},
            }
        },
    }

    # Synthesize with Gemini (or fallback if API key not set)
    synthesizer = CombinedRiskSynthesizer()
    report = synthesizer.synthesize_portfolio(
        cbom_document=cbom_document,
        ml_results_map=ml_results,
        hndl_results_map=hndl_results,
        mosca_results_map=mosca_results,
    )

    print(format_final_terminal_report(report))


if __name__ == "__main__":
    run_demo()
