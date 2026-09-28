"""
Comprehensive Deterministic Test Suite for HNDL Agent (test_hndl_engine.py)

Validates:
1. Exact mathematical score calculations against independent manual formulas.
2. Cryptographic susceptibility across asymmetric (RSA, ECDH, ECDSA), symmetric (AES-256, AES-128, 3DES), and PQC (ML-KEM).
3. Harvestability weighting, PFS status (present, lack, unknown), and network exposure.
4. Timeline models (expiry, exposure window, non-exposed vs exposed cases).
5. Configurable quantum-horizon scenario assumptions (2029, 2033, 2035).
6. Input validation (rejection of negative lifetimes, invalid sensitivity/criticality).
7. Full CBOM document batch scoring and application-level posture aggregation.
8. Explainability consistency and scenario assumption provenance.
"""

import unittest
from segments.ml.hndl import (
    HNDLAgent,
    HNDLTimelineEngine,
    HNDLValidator,
    HNDLExplainabilityBuilder,
    format_hndl_terminal_report,
)
from segments.ml.cbom import CBOMAgent


class TestHNDLEngine(unittest.TestCase):

    def setUp(self):
        self.agent = HNDLAgent()
        self.engine = HNDLTimelineEngine()
        self.validator = HNDLValidator()
        self.cbom_agent = CBOMAgent()

    # -------------------------------------------------------------------------
    # 1. Mathematical Accuracy Tests (Engine vs Independent Formula)
    # -------------------------------------------------------------------------
    def test_independent_math_calculation_rsa(self):
        """
        Manually calculate:
        - Algorithm: RSA-2048 (Key establishment / encryption) -> S_crypto = 1.0
        - Network: internet_exposed=True (0.35), external_facing=False (0.0), transit=True (0.25), lack_of_pfs=True (0.15) -> S_harvest = 0.75
        - Timeline: assess=2026, lifetime=10.0, horizon=2033 -> expiry=2036, window=3.0 -> timeline_factor = 3.0 / 10.0 = 0.30
        - Impact: sensitivity=4, criticality=4 -> M_impact = (4*0.6 + 4*0.4) / 5.0 = 4.0 / 5.0 = 0.80
        - Expected HNDL score = 1.0 * 0.75 * 0.30 * 0.80 = 0.1800
        """
        s_crypto, qv = self.engine.calculate_crypto_susceptibility("RSA-2048", family="asymmetric", crypto_role="encryption")
        self.assertEqual(s_crypto, 1.0)
        self.assertTrue(qv)

        s_harvest, tier, pfs = self.engine.calculate_harvestability_score(
            internet_exposed=True,
            external_facing=False,
            data_in_transit=True,
            lack_of_pfs=True,
        )
        self.assertAlmostEqual(s_harvest, 0.75, places=4)
        self.assertEqual(pfs, "LACK_OF_PFS")

        timeline = self.engine.calculate_timeline_metrics(
            assessment_year=2026,
            data_lifetime_years=10.0,
            quantum_horizon_year=2033,
        )
        self.assertAlmostEqual(timeline["timeline_factor"], 0.30, places=4)
        self.assertAlmostEqual(timeline["exposure_window_years"], 3.0, places=4)
        self.assertTrue(timeline["compromised_while_sensitive"])

        m_impact = self.engine.calculate_impact_multiplier(data_sensitivity=4, business_criticality=4)
        self.assertAlmostEqual(m_impact, 0.80, places=4)

        expected_score = 1.0 * 0.75 * 0.30 * 0.80
        actual_score = self.engine.calculate_composite_hndl_score(
            s_crypto=s_crypto,
            s_harvest=s_harvest,
            timeline_factor=timeline["timeline_factor"],
            m_impact=m_impact,
        )
        self.assertAlmostEqual(actual_score, expected_score, places=4)
        self.assertEqual(actual_score, 0.1800)

    # -------------------------------------------------------------------------
    # 2. Cryptographic Susceptibility Classification Tests
    # -------------------------------------------------------------------------
    def test_susceptibility_pqc(self):
        # ML-KEM-768 is post-quantum -> S_crypto = 0.0
        s_crypto, qv = self.engine.calculate_crypto_susceptibility("ML-KEM-768", family="pqc")
        self.assertEqual(s_crypto, 0.0)
        self.assertFalse(qv)

        s_crypto_dsa, qv_dsa = self.engine.calculate_crypto_susceptibility("ML-DSA-65", family="pqc")
        self.assertEqual(s_crypto_dsa, 0.0)
        self.assertFalse(qv_dsa)

    def test_susceptibility_symmetric(self):
        # AES-256 (NIST Cat 5, quantum-resistant) -> S_crypto = 0.05
        s_crypto_256, qv_256 = self.engine.calculate_crypto_susceptibility("AES-256", family="symmetric", key_size=256)
        self.assertEqual(s_crypto_256, 0.05)
        self.assertFalse(qv_256)

        # AES-128 (Grover reduced to ~64-bit) -> S_crypto = 0.35
        s_crypto_128, qv_128 = self.engine.calculate_crypto_susceptibility("AES-128", family="symmetric", key_size=128)
        self.assertEqual(s_crypto_128, 0.35)

        # 3DES (Deprecated / weak) -> S_crypto = 0.80
        s_crypto_3des, qv_3des = self.engine.calculate_crypto_susceptibility("3DES-112", family="symmetric")
        self.assertEqual(s_crypto_3des, 0.80)
        self.assertTrue(qv_3des)

    def test_susceptibility_asymmetric(self):
        # ECDH-P256 (Shor key establishment) -> S_crypto = 1.0
        s_crypto_ecdh, qv_ecdh = self.engine.calculate_crypto_susceptibility("ECDH-P256", family="asymmetric", crypto_role="key_establishment")
        self.assertEqual(s_crypto_ecdh, 1.0)
        self.assertTrue(qv_ecdh)

        # X25519 -> S_crypto = 1.0
        s_crypto_x25519, qv_x = self.engine.calculate_crypto_susceptibility("X25519", family="asymmetric", crypto_role="key_establishment")
        self.assertEqual(s_crypto_x25519, 1.0)

        # ECDSA-P256 (Signature) -> S_crypto = 0.30
        s_crypto_ecdsa, qv_ecdsa = self.engine.calculate_crypto_susceptibility("ECDSA-P256", family="asymmetric", crypto_role="signature")
        self.assertEqual(s_crypto_ecdsa, 0.30)

    # -------------------------------------------------------------------------
    # 3. Timeline Model & Scenario Tests
    # -------------------------------------------------------------------------
    def test_timeline_short_lived_data_expires_before_crqc(self):
        # Data lifetime = 2 years (2026 -> 2028), Horizon = 2033 -> Exposure Window = 0
        timeline = self.engine.calculate_timeline_metrics(
            assessment_year=2026,
            data_lifetime_years=2.0,
            quantum_horizon_year=2033,
        )
        self.assertEqual(timeline["data_expiry_year"], 2028.0)
        self.assertEqual(timeline["exposure_window_years"], 0.0)
        self.assertFalse(timeline["compromised_while_sensitive"])
        self.assertEqual(timeline["timeline_factor"], 0.0)

    def test_timeline_long_lived_data_exceeds_crqc(self):
        # Data lifetime = 15 years (2026 -> 2041), Horizon = 2033 -> Exposure Window = 8 years
        timeline = self.engine.calculate_timeline_metrics(
            assessment_year=2026,
            data_lifetime_years=15.0,
            quantum_horizon_year=2033,
        )
        self.assertEqual(timeline["data_expiry_year"], 2041.0)
        self.assertEqual(timeline["exposure_window_years"], 8.0)
        self.assertTrue(timeline["compromised_while_sensitive"])
        self.assertAlmostEqual(timeline["timeline_factor"], 8.0 / 15.0, places=4)

    def test_quantum_horizon_scenario_variations(self):
        # Test aggressive 2029 scenario vs conservative 2035 scenario
        t_2029 = self.engine.calculate_timeline_metrics(assessment_year=2026, data_lifetime_years=6.0, quantum_horizon_year=2029)
        self.assertEqual(t_2029["exposure_window_years"], 3.0)  # 2032 - 2029 = 3

        t_2035 = self.engine.calculate_timeline_metrics(assessment_year=2026, data_lifetime_years=6.0, quantum_horizon_year=2035)
        self.assertEqual(t_2035["exposure_window_years"], 0.0)  # 2032 <= 2035

    # -------------------------------------------------------------------------
    # 4. Harvestability & PFS Tests
    # -------------------------------------------------------------------------
    def test_harvestability_with_and_without_pfs(self):
        s_no_pfs, _, pfs_no = self.engine.calculate_harvestability_score(internet_exposed=True, data_in_transit=True, lack_of_pfs=True)
        s_with_pfs, _, pfs_yes = self.engine.calculate_harvestability_score(internet_exposed=True, data_in_transit=True, lack_of_pfs=False)
        self.assertGreater(s_no_pfs, s_with_pfs)
        self.assertEqual(pfs_no, "LACK_OF_PFS")
        self.assertEqual(pfs_yes, "PFS_PRESENT")

    def test_harvestability_unknown_pfs_handling(self):
        s_unknown, _, pfs_unk = self.engine.calculate_harvestability_score(internet_exposed=True, lack_of_pfs="UNKNOWN")
        self.assertEqual(pfs_unk, "UNKNOWN")
        self.assertGreater(s_unknown, 0.35)

    def test_harvestability_bounds(self):
        # All flags enabled must remain bounded <= 1.0
        s_max, _, _ = self.engine.calculate_harvestability_score(
            internet_exposed=True,
            external_facing=True,
            data_in_transit=True,
            storage_untrusted=True,
            lack_of_pfs=True,
        )
        self.assertLessEqual(s_max, 1.0)
        self.assertGreaterEqual(s_max, 0.0)

    # -------------------------------------------------------------------------
    # 5. Asset-Level Analysis & Agent Output Contract Tests
    # -------------------------------------------------------------------------
    def test_analyze_rsa_asset(self):
        asset = {
            "asset_id": "F001",
            "algorithm": "RSA-2048",
            "family": "asymmetric",
            "crypto_role": "key_establishment",
            "parameters": {"key_size": 2048},
            "location": {"file": "src/auth/rsa.py", "line": 42},
        }
        ctx = {
            "data_sensitivity": 5,
            "business_criticality": 5,
            "data_lifetime_years": 12.0,
            "internet_exposed": True,
            "external_facing": True,
            "lack_of_pfs": True,
            "quantum_horizon_year": 2033,
        }
        rep = self.agent.analyze(asset, ctx)

        self.assertEqual(rep["asset_id"], "F001")
        self.assertEqual(rep["algorithm"], "RSA-2048")
        hndl = rep["hndl"]
        self.assertTrue(hndl["applicable"])
        self.assertIn(hndl["urgency_tier"], ["CRITICAL", "HIGH"])
        self.assertTrue(hndl["quantum_vulnerable"])
        self.assertGreater(hndl["hndl_exposure_score"], 0.0)
        self.assertLessEqual(hndl["hndl_exposure_score"], 1.0)

        # Verify timeline & assumptions
        timeline = hndl["timeline"]
        self.assertEqual(timeline["projected_crqc_year"], 2033)
        self.assertEqual(timeline["exposure_window_years"], 5.0)
        self.assertEqual(hndl["assumptions"]["quantum_horizon_type"], "SCENARIO_ASSUMPTION")
        self.assertEqual(hndl["assumptions"]["quantum_horizon_source"], "USER_OVERRIDE")

        # Verify explainability string exists and matches calculation
        self.assertIn("RSA-2048", hndl["reason"])
        self.assertIn("2033", hndl["reason"])

    def test_analyze_pqc_asset_not_exposed(self):
        asset = {
            "asset_id": "F_PQC",
            "algorithm": "ML-KEM-768",
            "family": "pqc",
            "parameters": {"key_size": 768},
            "location": {"file": "src/pqc/kem.py", "line": 15},
        }
        ctx = {
            "data_sensitivity": 5,
            "data_lifetime_years": 20.0,
            "internet_exposed": True,
        }
        rep = self.agent.analyze(asset, ctx)
        hndl = rep["hndl"]
        self.assertFalse(hndl["applicable"])
        self.assertEqual(hndl["hndl_exposure_score"], 0.0)
        self.assertEqual(hndl["urgency_tier"], "NEGLIGIBLE")
        self.assertFalse(hndl["quantum_vulnerable"])

    # -------------------------------------------------------------------------
    # 6. Batch CBOM Document Assessment & Posture Summary
    # -------------------------------------------------------------------------
    def test_batch_cbom_assessment(self):
        raw_cbom = {
            "format": "ECDAT-CBOM",
            "crypto_assets": [
                {
                    "asset_id": "A1",
                    "algorithm": "RSA-2048",
                    "family": "asymmetric",
                    "crypto_role": "key_establishment",
                    "parameters": {"key_size": 2048},
                    "location": {"file": "auth.py", "line": 10},
                },
                {
                    "asset_id": "A2",
                    "algorithm": "AES-256",
                    "family": "symmetric",
                    "parameters": {"key_size": 256},
                    "location": {"file": "db.py", "line": 20},
                },
                {
                    "asset_id": "A3",
                    "algorithm": "ML-KEM-768",
                    "family": "pqc",
                    "location": {"file": "kem.py", "line": 30},
                },
            ],
        }
        ctx = {
            "data_sensitivity": 4,
            "business_criticality": 4,
            "data_lifetime_years": 10.0,
            "internet_exposed": True,
        }
        summary = self.agent.assess_cbom(raw_cbom, ctx)

        self.assertEqual(summary["total_assessed_assets"], 3)
        self.assertGreaterEqual(summary["applicable_assets_count"], 1)
        self.assertIn(summary["overall_hndl_posture"], ["CRITICAL", "HIGH", "MEDIUM"])
        self.assertEqual(len(summary["asset_assessments"]), 3)
        self.assertIn("by_urgency_tier", summary)

    # -------------------------------------------------------------------------
    # 7. Input Validation & Error Handling Tests
    # -------------------------------------------------------------------------
    def test_validation_rejects_negative_lifetime(self):
        asset = {"asset_id": "A1", "algorithm": "RSA-2048"}
        ctx = {"data_lifetime_years": -5.0}
        with self.assertRaises(ValueError):
            self.agent.analyze(asset, ctx)

    def test_validation_rejects_invalid_sensitivity(self):
        asset = {"asset_id": "A1", "algorithm": "RSA-2048"}
        ctx = {"data_sensitivity": 10}  # Must be 1-5
        with self.assertRaises(ValueError):
            self.agent.analyze(asset, ctx)

    def test_format_terminal_report(self):
        asset = {"asset_id": "A1", "algorithm": "RSA-2048"}
        rep = self.agent.analyze(asset, {"data_lifetime_years": 10.0})
        report_text = format_hndl_terminal_report(asset, hndl_result=rep)
        self.assertIn("HNDL — HARVEST NOW, DECRYPT LATER ASSESSMENT", report_text)
        self.assertIn("Asset ID:               A1", report_text)
        self.assertIn("Algorithm:              RSA-2048", report_text)


if __name__ == "__main__":
    unittest.main()
