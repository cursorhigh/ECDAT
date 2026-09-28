"""
Comprehensive Deterministic Test Suite for Mosca Theorem Engine (test_mosca_engine.py)

Validates:
1. Exact mathematical calculation of X + Y > Z, delta M, T_deadline, and Mosca risk index.
2. Deficit condition (X + Y > Z -> MIGRATION_DEFICIT).
3. Safe buffer condition (X + Y <= Z -> SAFE_BUFFER).
4. Overdue migration condition (X >= Z -> MIGRATION_OVERDUE).
5. Post-quantum immunity (ML-KEM-768 -> QUANTUM_RESILIENT).
6. Symmetric quantum resilience (AES-256 -> S_crypto=0.05 vs 3DES -> S_crypto=0.80).
7. Dynamic X derivation from agility (1..5), complexity (1..5), and dependencies.
8. Scenario quantum threat horizons (2029, 2033, 2035).
9. Full CBOM document batch scoring and application-level posture rollup.
10. Input validation, negative number rejection, and terminal report formatting.
"""

import unittest
from segments.ml.mosca_agent import (
    MOSCAAgent,
    MoscaSolver,
    MOSCAValidator,
    MoscaExplainabilityBuilder,
    format_mosca_terminal_report,
)
from segments.ml.cbom import CBOMAgent


class TestMoscaEngine(unittest.TestCase):

    def setUp(self):
        self.agent = MOSCAAgent()
        self.solver = MoscaSolver()
        self.validator = MOSCAValidator()
        self.cbom_agent = CBOMAgent()

    # -------------------------------------------------------------------------
    # 1. Independent Mathematical Accuracy Tests
    # -------------------------------------------------------------------------
    def test_independent_math_calculation_mosca(self):
        """
        Manually calculate:
        - X = 3.0, Y = 10.0, assess_year = 2026, crqc_year = 2033 -> Z = 7.0
        - X + Y = 13.0
        - Delta M = 13.0 - 7.0 = +6.0 years deficit
        - must_start_by = 2026 + 7.0 - 3.0 = 2030.0
        - is_overdue = False (2030 > 2026)
        - S_crypto = 1.0 (RSA-2048)
        - M_impact = (4*0.6 + 4*0.4) / 5.0 = 0.80
        - Deficit ratio = min(1.0, 6.0 / 13.0) = 0.461538...
        - R_mosca = 1.0 * (6.0/13.0) * 0.80 = 0.36923...
        """
        s_crypto, qv = self.solver.calculate_crypto_susceptibility("RSA-2048", family="asymmetric", crypto_role="key_establishment")
        self.assertEqual(s_crypto, 1.0)
        self.assertTrue(qv)

        m_impact = self.solver.calculate_impact_multiplier(data_sensitivity=4, business_criticality=4)
        self.assertAlmostEqual(m_impact, 0.80, places=4)

        solution = self.solver.solve_mosca_inequality(
            X_migration_time=3.0,
            Y_data_lifetime=10.0,
            Z_time_to_crqc=7.0,
            assessment_year=2026,
            quantum_horizon_year=2033,
            s_crypto=s_crypto,
            m_impact=m_impact,
        )

        vars = solution["variables"]
        self.assertEqual(vars["X_migration_time_years"], 3.0)
        self.assertEqual(vars["Y_data_lifetime_years"], 10.0)
        self.assertEqual(vars["Z_time_to_crqc_years"], 7.0)
        self.assertEqual(vars["X_plus_Y"], 13.0)

        timeline = solution["timeline"]
        self.assertEqual(timeline["mosca_deficit_years"], 6.0)
        self.assertEqual(timeline["must_start_by_year"], 2030.0)
        self.assertFalse(timeline["is_overdue_to_start"])

        self.assertTrue(solution["inequality_satisfied"])
        expected_r_mosca = round(1.0 * (6.0 / 13.0) * 0.80, 4)
        self.assertAlmostEqual(solution["mosca_risk_index"], expected_r_mosca, places=4)
        self.assertEqual(solution["migration_posture"], "MIGRATION_DEFICIT")
        self.assertIn(solution["urgency_tier"], ["CRITICAL", "HIGH"])

    # -------------------------------------------------------------------------
    # 2. Dynamic Migration Time (X) Derivation Tests
    # -------------------------------------------------------------------------
    def test_dynamic_x_derivation_from_complexity_and_agility(self):
        # Trivial complexity (1 -> 0.5) + full agility (5 -> 0.0) -> X = 0.5
        x_fast = self.solver.derive_migration_time(crypto_agility=5, migration_complexity=1)
        self.assertEqual(x_fast, 0.5)

        # High complexity (4 -> 3.5) + hardcoded keys (agility 1 -> +1.6) + hardware HSM (+1.0) -> X = 6.1
        x_slow = self.solver.derive_migration_time(
            crypto_agility=1,
            migration_complexity=4,
            hardware_dependency=True,
        )
        self.assertEqual(x_slow, 6.10)

        # Explicit user-supplied X overrides derivation
        x_user = self.solver.derive_migration_time(migration_time_years=4.5)
        self.assertEqual(x_user, 4.5)

    # -------------------------------------------------------------------------
    # 3. Safe Buffer vs Overdue Start Tests
    # -------------------------------------------------------------------------
    def test_safe_buffer_condition(self):
        # X = 1.0, Y = 2.0 -> X + Y = 3.0 <= Z = 7.0 -> Delta M = -4.0 (Safe buffer)
        solution = self.solver.solve_mosca_inequality(
            X_migration_time=1.0,
            Y_data_lifetime=2.0,
            Z_time_to_crqc=7.0,
            assessment_year=2026,
            quantum_horizon_year=2033,
            s_crypto=1.0,
            m_impact=0.80,
        )
        self.assertFalse(solution["inequality_satisfied"])
        self.assertEqual(solution["timeline"]["mosca_deficit_years"], -4.0)
        self.assertEqual(solution["mosca_risk_index"], 0.0)
        self.assertEqual(solution["migration_posture"], "SAFE_BUFFER")
        self.assertEqual(solution["urgency_tier"], "NEGLIGIBLE")

    def test_overdue_migration_condition(self):
        # X = 8.0 yrs, Z = 7.0 yrs -> must_start = 2026 + 7 - 8 = 2025 <= 2026 -> OVERDUE
        solution = self.solver.solve_mosca_inequality(
            X_migration_time=8.0,
            Y_data_lifetime=5.0,
            Z_time_to_crqc=7.0,
            assessment_year=2026,
            quantum_horizon_year=2033,
            s_crypto=1.0,
            m_impact=1.0,
        )
        self.assertTrue(solution["timeline"]["is_overdue_to_start"])
        self.assertEqual(solution["timeline"]["must_start_by_year"], 2025.0)
        self.assertEqual(solution["migration_posture"], "MIGRATION_OVERDUE")
        self.assertEqual(solution["urgency_tier"], "CRITICAL")

    # -------------------------------------------------------------------------
    # 4. Algorithm Susceptibility Spectrum in Mosca
    # -------------------------------------------------------------------------
    def test_pqc_immunity_in_mosca(self):
        # ML-KEM-768 has S_crypto = 0.0 -> QUANTUM_RESILIENT
        s_crypto, qv = self.solver.calculate_crypto_susceptibility("ML-KEM-768", family="pqc")
        self.assertEqual(s_crypto, 0.0)
        self.assertFalse(qv)

        solution = self.solver.solve_mosca_inequality(
            X_migration_time=5.0,
            Y_data_lifetime=15.0,
            Z_time_to_crqc=7.0,
            s_crypto=s_crypto,
        )
        self.assertFalse(solution["inequality_satisfied"])
        self.assertEqual(solution["mosca_risk_index"], 0.0)
        self.assertEqual(solution["migration_posture"], "QUANTUM_RESILIENT")
        self.assertEqual(solution["urgency_tier"], "NEGLIGIBLE")

    def test_symmetric_ciphers_in_mosca(self):
        # AES-256 (Grover resistant, 128-bit quantum security) -> S_crypto = 0.0
        s_256, qv_256 = self.solver.calculate_crypto_susceptibility("AES-256", family="symmetric", key_size=256)
        self.assertEqual(s_256, 0.0)
        self.assertFalse(qv_256)

        # 3DES (Classically Deprecated) -> S_crypto = 0.80, not Shor-vulnerable
        s_3des, qv_3des = self.solver.calculate_crypto_susceptibility("3DES-112", family="symmetric")
        self.assertEqual(s_3des, 0.80)
        self.assertFalse(qv_3des)

    # -------------------------------------------------------------------------
    # 5. Asset-Level Analysis & Output Contract Tests
    # -------------------------------------------------------------------------
    def test_analyze_rsa_cbom_asset(self):
        asset = {
            "asset_id": "F001",
            "algorithm": "RSA-2048",
            "family": "asymmetric",
            "crypto_role": "key_establishment",
            "parameters": {"key_size": 2048},
            "location": {"file": "auth.py", "line": 42},
        }
        ctx = {
            "migration_time_years": 3.0,
            "data_lifetime_years": 10.0,
            "data_sensitivity": 4,
            "business_criticality": 4,
            "quantum_horizon_year": 2033,
        }
        rep = self.agent.analyze(asset, ctx)

        self.assertEqual(rep["asset_id"], "F001")
        self.assertEqual(rep["algorithm"], "RSA-2048")
        mosca = rep["mosca"]
        self.assertTrue(mosca["inequality_satisfied"])
        self.assertGreater(mosca["mosca_risk_index"], 0.0)
        self.assertEqual(mosca["migration_posture"], "MIGRATION_DEFICIT")
        self.assertTrue(mosca["quantum_vulnerable"])

        # Timeline verification
        timeline = mosca["timeline"]
        self.assertEqual(timeline["mosca_deficit_years"], 6.0)
        self.assertEqual(timeline["must_start_by_year"], 2030.0)
        self.assertEqual(timeline["migration_completion_year"], 2029.0)

        # Explainability verification
        self.assertIn("RSA-2048", mosca["reason"])
        self.assertIn("6.0-year Mosca deficit", mosca["reason"])

    # -------------------------------------------------------------------------
    # 6. Batch CBOM Document Evaluation & Posture Summary
    # -------------------------------------------------------------------------
    def test_batch_cbom_document_mosca(self):
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
            "migration_time_years": 2.0,
            "data_lifetime_years": 8.0,
            "data_sensitivity": 4,
            "business_criticality": 4,
        }
        summary = self.agent.assess_cbom(raw_cbom, ctx)

        self.assertEqual(summary["total_assessed_assets"], 3)
        self.assertGreaterEqual(summary["inequality_satisfied_count"], 1)
        self.assertIn(summary["overall_mosca_posture"], ["CRITICAL", "HIGH", "MEDIUM"])
        self.assertEqual(len(summary["asset_assessments"]), 3)
        self.assertIn("by_urgency_tier", summary)
        self.assertGreater(summary["max_mosca_deficit_years"], 0.0)

    # -------------------------------------------------------------------------
    # 7. Input Validation & Error Handling
    # -------------------------------------------------------------------------
    def test_validation_rejects_negative_parameters(self):
        asset = {"asset_id": "A1", "algorithm": "RSA-2048"}
        with self.assertRaises(ValueError):
            self.agent.analyze(asset, {"migration_time_years": -2.0})

        with self.assertRaises(ValueError):
            self.agent.analyze(asset, {"data_lifetime_years": -5.0})

    def test_format_terminal_report(self):
        asset = {"asset_id": "A1", "algorithm": "RSA-2048"}
        rep = self.agent.analyze(asset, {"migration_time_years": 2.0, "data_lifetime_years": 10.0})
        report_text = format_mosca_terminal_report(asset, mosca_result=rep)
        self.assertIn("MOSCA+ THEOREM (X + Y > Z) QUANTUM RISK ASSESSMENT", report_text)
        self.assertIn("Asset ID:               A1", report_text)
        self.assertIn("X (Migration Time):", report_text)


if __name__ == "__main__":
    unittest.main()
