"""
Test Suite for Final Combined Result Synthesis Module (test_final_combined_result.py)

Tests the unification of CatBoost ML Quantum Risk Model, HNDL Timeline Engine,
and Mosca Inequality Agent into a grounded executive report with source attributions.
"""

import unittest
from typing import Dict, Any

from segments.ml.final_combined_result import (
    CombinedRiskSynthesizer,
    DeterministicFallbackProvider,
    SynthesisValidator,
    format_final_terminal_report,
)


class TestFinalCombinedResult(unittest.TestCase):
    """Unit tests for the Final Combined Result synthesis pipeline."""

    def setUp(self):
        # Force fallback provider for deterministic, offline testing
        self.synthesizer = CombinedRiskSynthesizer(force_fallback=True)

    def test_single_asset_synthesis_rsa_critical(self):
        """Test synthesizing an RSA-2048 asset with high ML risk, high HNDL, and Mosca deficit."""
        cbom_asset = {
            "asset_id": "crypto-rsa-001",
            "algorithm": "RSA-2048",
            "family": "rsa",
            "crypto_role": "key_exchange",
            "parameters": {"key_size": 2048},
        }

        ml_risk_result = {
            "prediction": "CRITICAL",
            "confidence": 0.945,
            "probabilities": {"CRITICAL": 0.945, "HIGH": 0.04, "MEDIUM": 0.01, "LOW": 0.005},
            "top_contributing_features": ["quantum_vulnerable", "key_size", "forward_secrecy"],
        }

        hndl_result = {
            "hndl": {
                "hndl_exposure_score": 0.88,
                "is_exposed": True,
                "future_decryption_risk": "CRITICAL",
                "threat_vectors": {"harvestability_score": 0.92},
                "timeline": {"exposure_factor": 1.0, "data_expiry_year": 2035},
            }
        }

        mosca_result = {
            "mosca": {
                "inequality_satisfied": True,
                "urgency_tier": "CRITICAL",
                "migration_posture": "URGENT_DEFICIT",
                "mosca_risk_index": 0.95,
                "variables": {"X_migration_time_years": 4.5, "Y_data_lifetime_years": 8.0, "Z_time_to_crqc_years": 7.0},
                "timeline": {"mosca_deficit_years": 5.5, "must_start_by_year": 2028, "is_overdue_to_start": False},
            }
        }

        report = self.synthesizer.synthesize_asset(
            cbom_asset=cbom_asset,
            ml_risk_result=ml_risk_result,
            hndl_result=hndl_result,
            mosca_result=mosca_result,
        )

        self.assertEqual(report["asset_id"], "crypto-rsa-001")
        self.assertEqual(report["algorithm"], "RSA-2048")
        self.assertEqual(report["overall_quantum_risk_tier"], "CRITICAL")
        self.assertGreaterEqual(report["unified_risk_score"], 80.0)
        self.assertIn(report["urgency_tier"], ["CRITICAL", "IMMEDIATE"])

        # Check explicit citations / attributions
        attributions = report["attributions"]
        self.assertGreaterEqual(len(attributions), 3)
        pillars = {attr["pillar"] for attr in attributions}
        self.assertIn("ML_RISK", pillars)
        self.assertIn("HNDL_ENGINE", pillars)
        self.assertIn("MOSCA_THEOREM", pillars)

        # Check narrative contains references
        narrative = report["executive_narrative"]
        self.assertIn("[ML Risk Model]", narrative)
        self.assertIn("[HNDL Engine]", narrative)
        self.assertIn("[Mosca Theorem]", narrative)

        # Check recommendation
        self.assertIn("ML-KEM-768", report["recommended_action"])

    def test_single_asset_synthesis_pqc_resilient(self):
        """Test synthesizing a post-quantum ML-KEM-768 asset with zero quantum risk."""
        cbom_asset = {
            "asset_id": "crypto-pqc-002",
            "algorithm": "ML-KEM-768",
            "family": "pqc",
            "crypto_role": "key_exchange",
            "parameters": {"claim": "NIST FIPS 203"},
        }

        ml_risk_result = {
            "prediction": "LOW",
            "confidence": 0.98,
            "probabilities": {"CRITICAL": 0.0, "HIGH": 0.01, "MEDIUM": 0.02, "LOW": 0.97},
            "top_contributing_features": ["quantum_vulnerable", "nist_standardized"],
        }

        hndl_result = {
            "hndl": {
                "hndl_exposure_score": 0.0,
                "is_exposed": False,
                "future_decryption_risk": "NEGLIGIBLE",
                "threat_vectors": {"harvestability_score": 0.0},
                "timeline": {"exposure_factor": 0.0},
            }
        }

        mosca_result = {
            "mosca": {
                "inequality_satisfied": False,
                "urgency_tier": "NEGLIGIBLE",
                "migration_posture": "QUANTUM_RESILIENT",
                "mosca_risk_index": 0.0,
                "variables": {"X_migration_time_years": 0.5, "Y_data_lifetime_years": 10.0, "Z_time_to_crqc_years": 7.0},
                "timeline": {"mosca_deficit_years": -6.5, "must_start_by_year": 2033, "is_overdue_to_start": False},
            }
        }

        report = self.synthesizer.synthesize_asset(
            cbom_asset=cbom_asset,
            ml_risk_result=ml_risk_result,
            hndl_result=hndl_result,
            mosca_result=mosca_result,
        )

        self.assertEqual(report["overall_quantum_risk_tier"], "LOW")
        self.assertLessEqual(report["unified_risk_score"], 15.0)
        self.assertIn(report["urgency_tier"], ["LOW", "NEGLIGIBLE"])

    def test_portfolio_synthesis_multi_asset(self):
        """Test full CBOM document portfolio synthesis combining multiple assets."""
        cbom_doc = {
            "crypto_assets": [
                {
                    "asset_id": "asset-rsa-01",
                    "algorithm": "RSA-2048",
                    "family": "rsa",
                    "crypto_role": "key_exchange",
                },
                {
                    "asset_id": "asset-ecdsa-02",
                    "algorithm": "ECDSA",
                    "family": "ecc",
                    "crypto_role": "signature",
                },
                {
                    "asset_id": "asset-aes-03",
                    "algorithm": "AES-256-GCM",
                    "family": "aes",
                    "crypto_role": "encryption",
                },
                {
                    "asset_id": "asset-pqc-04",
                    "algorithm": "ML-KEM-768",
                    "family": "pqc",
                    "crypto_role": "key_exchange",
                },
            ]
        }

        ml_map = {
            "asset-rsa-01": {"prediction": "CRITICAL", "confidence": 0.95},
            "asset-ecdsa-02": {"prediction": "HIGH", "confidence": 0.88},
            "asset-aes-03": {"prediction": "LOW", "confidence": 0.92},
            "asset-pqc-04": {"prediction": "LOW", "confidence": 0.99},
        }

        hndl_map = {
            "asset-rsa-01": {"hndl": {"hndl_exposure_score": 0.85, "is_exposed": True, "future_decryption_risk": "CRITICAL"}},
            "asset-ecdsa-02": {"hndl": {"hndl_exposure_score": 0.10, "is_exposed": False, "future_decryption_risk": "LOW"}},
            "asset-aes-03": {"hndl": {"hndl_exposure_score": 0.05, "is_exposed": False, "future_decryption_risk": "NEGLIGIBLE"}},
            "asset-pqc-04": {"hndl": {"hndl_exposure_score": 0.00, "is_exposed": False, "future_decryption_risk": "NEGLIGIBLE"}},
        }

        mosca_map = {
            "asset-rsa-01": {
                "mosca": {
                    "inequality_satisfied": True,
                    "urgency_tier": "CRITICAL",
                    "mosca_risk_index": 0.90,
                    "timeline": {"mosca_deficit_years": 4.0, "must_start_by_year": 2028, "is_overdue_to_start": False},
                }
            },
            "asset-ecdsa-02": {
                "mosca": {
                    "inequality_satisfied": True,
                    "urgency_tier": "HIGH",
                    "mosca_risk_index": 0.65,
                    "timeline": {"mosca_deficit_years": 1.5, "must_start_by_year": 2029, "is_overdue_to_start": False},
                }
            },
            "asset-aes-03": {
                "mosca": {
                    "inequality_satisfied": False,
                    "urgency_tier": "LOW",
                    "mosca_risk_index": 0.05,
                    "timeline": {"mosca_deficit_years": -3.0, "must_start_by_year": 2033, "is_overdue_to_start": False},
                }
            },
            "asset-pqc-04": {
                "mosca": {
                    "inequality_satisfied": False,
                    "urgency_tier": "NEGLIGIBLE",
                    "mosca_risk_index": 0.00,
                    "timeline": {"mosca_deficit_years": -6.0, "must_start_by_year": 2033, "is_overdue_to_start": False},
                }
            },
        }

        final_report = self.synthesizer.synthesize_portfolio(
            cbom_document=cbom_doc,
            ml_results_map=ml_map,
            hndl_results_map=hndl_map,
            mosca_results_map=mosca_map,
        )

        # Validate schema
        is_valid, errs = SynthesisValidator.validate_final_report(final_report)
        self.assertTrue(is_valid, f"Validation errors: {errs}")

        stats = final_report["portfolio_stats"]
        self.assertEqual(stats["total_assets"], 4)
        self.assertEqual(stats["critical_risk_count"], 1)
        self.assertEqual(stats["high_risk_count"], 1)
        self.assertEqual(stats["hndl_exposed_count"], 1)
        self.assertEqual(stats["mosca_deficit_count"], 2)
        self.assertEqual(stats["earliest_migration_deadline_year"], 2028)

        # Verify executive summary & findings
        self.assertIn("CRITICAL", final_report["executive_summary"])
        self.assertGreaterEqual(len(final_report["key_findings"]), 2)
        self.assertEqual(len(final_report["asset_reports"]), 4)

    def test_terminal_report_formatter(self):
        """Test formatting the final report into terminal text."""
        final_report = {
            "report_title": "ECDAT Enterprise Post-Quantum Cryptographic Risk Report",
            "generated_at": "2026-09-27T12:00:00Z",
            "generation_provider": "Deterministic Fallback Engine",
            "portfolio_stats": {
                "total_assets": 1,
                "critical_risk_count": 1,
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
                "negligible_risk_count": 0,
                "hndl_exposed_count": 1,
                "mosca_deficit_count": 1,
                "overdue_migration_count": 0,
                "average_risk_score": 88.5,
                "highest_risk_score": 88.5,
                "earliest_migration_deadline_year": 2028,
            },
            "executive_summary": "High risk detected in core cryptographic layer.",
            "key_findings": ["RSA-2048 is critically vulnerable to Shor's algorithm."],
            "asset_reports": [
                {
                    "asset_id": "test-rsa-01",
                    "algorithm": "RSA-2048",
                    "overall_quantum_risk_tier": "CRITICAL",
                    "unified_risk_score": 88.5,
                    "urgency_tier": "CRITICAL",
                    "primary_risk_driver": "Mosca Deficit & Lack of Forward Secrecy",
                    "recommended_action": "Migrate to ML-KEM-768",
                    "ml_summary": {"risk_tier": "CRITICAL", "confidence": 0.95},
                    "hndl_summary": {"hndl_exposure_score": 0.85, "future_decryption_risk": "CRITICAL"},
                    "mosca_summary": {"deficit_years": 5.0, "must_start_by_year": 2028},
                }
            ],
        }

        output = format_final_terminal_report(final_report)
        self.assertIn("ECDAT FINAL POST-QUANTUM CRYPTOGRAPHIC RISK SYNTHESIS REPORT", output)
        self.assertIn("PORTFOLIO RISK SUMMARY", output)
        self.assertIn("test-rsa-01", output)
        self.assertIn("RSA-2048", output)
        self.assertIn("Score: 88.5/100", output)
        self.assertIn("Migrate to ML-KEM-768", output)


if __name__ == "__main__":
    unittest.main()
