"""
End-to-End ECDAT Pipeline Test Suite (test_ecdat_pipeline.py)

Validates the full sequential workflow:
Discovery Findings -> CycloneDX 1.6 CBOM -> HNDL Engine -> Mosca Agent ->
CatBoost ML Risk Model -> Final Combined Result Synthesis
"""

import unittest
from segments.ml import ECDATPipeline, run_ecdat_pipeline
from segments.ml.final_combined_result import format_final_terminal_report


class TestECDATPipeline(unittest.TestCase):
    """End-to-end integration tests for the full ECDAT Post-Quantum Cryptographic pipeline."""

    def setUp(self):
        self.pipeline = ECDATPipeline(force_fallback_llm=True)

    def test_full_sequential_pipeline_execution(self):
        # 1. Raw Discovery Input Findings (Simulating discovery scrapers)
        discovery_input = {
            "findings": [
                {
                    "detected": "RSA-2048 key exchange in TLS",
                    "code": "Cipher.getInstance('RSA/ECB/OAEPWithSHA-256AndMGF1Padding')",
                    "location": "src/security/KeyManager.java",
                },
                {
                    "detected": "ECDSA P-256 token signing",
                    "code": "Signature.getInstance('SHA256withECDSA')",
                    "location": "src/auth/JWTHandler.java",
                },
                {
                    "detected": "AES-256-GCM database column encryption",
                    "code": "Cipher.getInstance('AES/GCM/NoPadding')",
                    "location": "src/db/CryptoStorage.java",
                },
                {
                    "detected": "ML-KEM-768 quantum safe key encapsulation",
                    "code": "MLKEMGenerator.generateKey(768)",
                    "location": "src/pqc/PostQuantumChannel.java",
                },
            ]
        }

        # 2. User Operational / System Context (Simulating user input from UI / settings)
        operational_context = {
            "data_lifetime_years": 8.0,
            "data_sensitivity": 4,          # High sensitivity
            "business_criticality": 4,      # High criticality
            "migration_complexity": 3,      # Moderate complexity
            "crypto_agility": 2,            # Low agility
            "hardware_dependency": False,
            "quantum_horizon_year": 2033,
            "assessment_year": 2026,
        }

        # 3. Execute Pipeline
        report = self.pipeline.execute(discovery_input, operational_context)

        # 4. Assert Pipeline Completion and Structure
        self.assertIn("portfolio_stats", report)
        self.assertIn("executive_summary", report)
        self.assertIn("key_findings", report)
        self.assertIn("asset_reports", report)
        self.assertIn("cbom_document", report)
        self.assertIn("intermediate_stages", report)

        stats = report["portfolio_stats"]
        self.assertEqual(stats["total_assets"], 4)
        self.assertGreaterEqual(stats["critical_risk_count"] + stats["high_risk_count"], 1)

        # 5. Verify Intermediates: HNDL -> Mosca -> ML
        stages = report["intermediate_stages"]
        self.assertIn("hndl_assessments", stages)
        self.assertIn("mosca_assessments", stages)
        self.assertIn("ml_risk_assessments", stages)

        # 6. Verify Per-Asset Grounding & Attributions
        asset_reports = report["asset_reports"]
        self.assertEqual(len(asset_reports), 4)

        rsa_report = next((a for a in asset_reports if "RSA" in a["algorithm"]), None)
        self.assertIsNotNone(rsa_report)
        self.assertIn(rsa_report["overall_quantum_risk_tier"], ["CRITICAL", "HIGH"])
        self.assertGreaterEqual(rsa_report["unified_risk_score"], 35.0)

        # Verify pillar attributions in RSA report
        attributions = rsa_report.get("attributions", [])
        pillars = {attr["pillar"] for attr in attributions}
        self.assertIn("ML_RISK", pillars)
        self.assertIn("HNDL_ENGINE", pillars)
        self.assertIn("MOSCA_THEOREM", pillars)

        pqc_report = next((a for a in asset_reports if "ML-KEM" in a["algorithm"]), None)
        self.assertIsNotNone(pqc_report)
        self.assertIn(pqc_report["overall_quantum_risk_tier"], ["LOW", "NEGLIGIBLE"])
        self.assertLessEqual(pqc_report["unified_risk_score"], 20.0)

        # 7. Verify Terminal Display Formatter
        terminal_output = format_final_terminal_report(report)
        self.assertIn("ECDAT FINAL POST-QUANTUM CRYPTOGRAPHIC RISK SYNTHESIS REPORT", terminal_output)
        self.assertIn("RSA", terminal_output)
        self.assertIn("ML-KEM", terminal_output)


if __name__ == "__main__":
    unittest.main()
