"""
ECDAT Post-ML Synthesis & PQC Audit Test Suite
Verifies all critical test cases specified in the PQC Risk Pipeline Audit.
"""

import pytest
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from segments.ml.cbom.crypto_catalog import classify_pqc_status
from segments.ml.final_combined_result.synthesizer import CombinedRiskSynthesizer
from segments.ml.mosca_agent.solver import MoscaSolver


class TestPQCPipelineAudit:
    @classmethod
    def setup_class(cls):
        cls.synthesizer = CombinedRiskSynthesizer(force_fallback=True)

    def test_1_rsa_2048(self):
        """TEST 1: RSA-2048 -> CLASSICAL_VULNERABLE, Migration required = True, Target = ML-KEM"""
        pqc_status = classify_pqc_status("RSA", {"primitive_family": "asymmetric_encryption", "security_strength_bits": 112}, {"key_size": 2048})
        assert pqc_status == "CLASSICAL_VULNERABLE"

        asset = {
            "asset_id": "DISC-001",
            "algorithm": "RSA-2048",
            "family": "asymmetric_encryption",
            "purpose": "key_establishment",
            "crypto_role": "key_establishment",
            "data_sensitivity": "HIGH",
            "parameters": {"key_size": 2048}
        }
        hndl = {"hndl_exposure_score": 0.85, "future_decryption_risk": "CRITICAL", "applicable": True}
        mosca = {
            "is_applicable": True,
            "deficit_years": 4.5,
            "must_start_by_year": 2028.5,
            "migration_time_x": 3.0,
            "security_lifetime_y": 10.0,
            "crqc_timeline_z": 8.5,
            "inequality_satisfied": True,
            "urgency_tier": "HIGH",
            "migration_posture": "ACTIVE_TIMELINE_DEFICIT"
        }
        ml = {
            "prediction": "HIGH",
            "confidence": 0.94,
            "probabilities": {"LOW": 0.02, "MEDIUM": 0.04, "HIGH": 0.94}
        }

        report = self.synthesizer.synthesize_asset(asset, ml, hndl, mosca)
        assert report["pqc_status"] == "CLASSICAL_VULNERABLE"
        assert report["migration_required"] is True
        assert report["final_risk_class"] in ("HIGH", "CRITICAL")
        assert "ML-KEM" in report["recommended_action"] or "FIPS 203" in report["recommended_action"]

    def test_2_aes_256_gcm(self):
        """TEST 2: AES-256-GCM -> SYMMETRIC_QUANTUM_RESILIENT, ML LOW, No automatic HIGH, No PQ migration"""
        pqc_status = classify_pqc_status("AES-GCM", {"primitive_family": "symmetric_encryption", "security_strength_bits": 256}, {"key_size": 256})
        assert pqc_status == "SYMMETRIC_QUANTUM_RESILIENT"

        asset = {
            "asset_id": "DISC-003",
            "algorithm": "AES-256-GCM",
            "family": "symmetric_encryption",
            "purpose": "data_at_rest_encryption",
            "crypto_role": "data_at_rest_encryption",
            "data_sensitivity": "CRITICAL",
            "parameters": {"key_size": 256}
        }
        hndl = {"hndl_exposure_score": 0.0, "future_decryption_risk": "LOW", "applicable": False}
        mosca = {
            "is_applicable": False,
            "deficit_years": 0.0,
            "must_start_by_year": None,
            "migration_time_x": 1.0,
            "security_lifetime_y": 15.0,
            "crqc_timeline_z": 8.5,
            "inequality_satisfied": False,
            "urgency_tier": "LOW",
            "migration_posture": "QUANTUM_RESILIENT"
        }
        ml = {
            "prediction": "LOW",
            "confidence": 0.913,
            "probabilities": {"LOW": 0.913, "MEDIUM": 0.06, "HIGH": 0.027}
        }

        report = self.synthesizer.synthesize_asset(asset, ml, hndl, mosca)
        assert report["pqc_status"] == "SYMMETRIC_QUANTUM_RESILIENT"
        assert report["final_risk_class"] == "LOW"
        assert report["migration_required"] is False
        assert "FIPS 203" not in report["recommended_action"]
        assert "Retain" in report["recommended_action"] or "Maintain" in report["recommended_action"]

    def test_3_3des_cbc(self):
        """TEST 3: 3DES-CBC -> Deprecated policy detected, Final risk shows policy override/reason"""
        pqc_status = classify_pqc_status("3DES-CBC", {"primitive_family": "symmetric_encryption", "is_deprecated": True}, {"key_size": 168})
        assert pqc_status == "LEGACY_DEPRECATED"

        asset = {
            "asset_id": "DISC-004",
            "algorithm": "3DES-CBC",
            "family": "symmetric_encryption",
            "purpose": "session_encryption",
            "crypto_role": "session_encryption",
            "data_sensitivity": "MEDIUM",
            "parameters": {"key_size": 168}
        }
        hndl = {"hndl_exposure_score": 0.1, "future_decryption_risk": "LOW", "applicable": True}
        mosca = {
            "is_applicable": True,
            "deficit_years": 0.0,
            "must_start_by_year": None,
            "migration_time_x": 2.0,
            "security_lifetime_y": 3.0,
            "crqc_timeline_z": 8.5,
            "inequality_satisfied": False,
            "urgency_tier": "LOW",
            "migration_posture": "SAFE_BUFFER"
        }
        ml = {
            "prediction": "LOW",
            "confidence": 0.815,
            "probabilities": {"LOW": 0.815, "MEDIUM": 0.15, "HIGH": 0.035}
        }

        report = self.synthesizer.synthesize_asset(asset, ml, hndl, mosca)
        assert report["policy_status"] in ("DEPRECATED_ALGORITHM", "DEPRECATED_DISALLOWED")
        assert report["final_risk_class"] in ("HIGH", "CRITICAL")
        assert len(report["policy_overrides"]) > 0
        assert "3DES" in report["policy_overrides"][0]
        # Should recommend modern symmetric replacement (AES-256-GCM / ChaCha20), NOT FIPS 203 PQC KEM
        assert "AES-256-GCM" in report["recommended_action"] or "symmetric" in report["recommended_action"].lower()
        assert "FIPS 203" not in report["recommended_action"]

    def test_4_ml_kem_768(self):
        """TEST 4: ML-KEM-768 -> PQC_NATIVE, Migration required = False, Mosca = N/A, Precise FIPS 203 mapping"""
        pqc_status = classify_pqc_status("ML-KEM-768", {"primitive_family": "post_quantum_kem", "nist_status": "FIPS_203_STANDARD"}, {"claimed_nist_level": 3})
        assert pqc_status == "PQC_NATIVE"

        asset = {
            "asset_id": "DISC-005",
            "algorithm": "ML-KEM-768",
            "family": "post_quantum_kem",
            "purpose": "key_exchange",
            "crypto_role": "key_exchange",
            "data_sensitivity": "HIGH",
            "parameters": {"claimed_nist_level": 3}
        }
        hndl = {"hndl_exposure_score": 0.0, "future_decryption_risk": "LOW", "applicable": False}
        mosca = {
            "is_applicable": False,
            "deficit_years": 0.0,
            "must_start_by_year": None,
            "migration_time_x": 0.5,
            "security_lifetime_y": 10.0,
            "crqc_timeline_z": 8.5,
            "inequality_satisfied": False,
            "urgency_tier": "LOW",
            "migration_posture": "QUANTUM_RESILIENT"
        }
        ml = {
            "prediction": "LOW",
            "confidence": 0.98,
            "probabilities": {"LOW": 0.98, "MEDIUM": 0.01, "HIGH": 0.01}
        }

        report = self.synthesizer.synthesize_asset(asset, ml, hndl, mosca)
        assert report["pqc_status"] == "PQC_NATIVE"
        assert report["migration_required"] is False
        assert report["final_risk_class"] == "LOW"
        assert "replace with approved fips 203" not in report["recommended_action"].lower()
        assert "FIPS 203" in report["recommended_action"]
        assert "203/204/205" not in report["recommended_action"]

    def test_5_hybrid_x25519_ml_kem_768(self):
        """TEST 5: X25519+ML-KEM-768 -> HYBRID_PQC, Not treated as pure X25519, No generic replace"""
        pqc_status = classify_pqc_status("X25519+ML-KEM-768", {"primitive_family": "hybrid_kem", "nist_status": "HYBRID_DRAFT"}, {})
        assert pqc_status == "HYBRID_PQC"

        asset = {
            "asset_id": "DISC-010",
            "algorithm": "X25519+ML-KEM-768",
            "family": "hybrid_kem",
            "purpose": "tls_key_exchange",
            "crypto_role": "key_exchange",
            "data_sensitivity": "HIGH",
            "parameters": {"classical": "X25519", "pqc": "ML-KEM-768"}
        }
        hndl = {"hndl_exposure_score": 0.0, "future_decryption_risk": "LOW", "applicable": False}
        mosca = {
            "is_applicable": False,
            "deficit_years": 0.0,
            "must_start_by_year": None,
            "migration_time_x": 0.5,
            "security_lifetime_y": 10.0,
            "crqc_timeline_z": 8.5,
            "inequality_satisfied": False,
            "urgency_tier": "LOW",
            "migration_posture": "QUANTUM_RESILIENT"
        }
        ml = {
            "prediction": "LOW",
            "confidence": 0.92,
            "probabilities": {"LOW": 0.92, "MEDIUM": 0.05, "HIGH": 0.03}
        }

        report = self.synthesizer.synthesize_asset(asset, ml, hndl, mosca)
        assert report["pqc_status"] == "HYBRID_PQC"
        assert report["migration_required"] is False
        assert "replace vulnerable primitives" not in report["recommended_action"].lower()

    def test_6_asset_specific_mosca_values(self):
        """TEST 6: Two assets with different X/Y/Z values produce different deficits/deadlines"""
        # Asset A: Fast migration (X=1.0), short retention (Y=2.0), Z=8.5 -> Total 3.0 <= 8.5 (Margin 5.5, Deficit -5.5)
        res_a = MoscaSolver.solve_mosca_inequality(X_migration_time=1.0, Y_data_lifetime=2.0, Z_time_to_crqc=8.5, s_crypto=1.0)
        # Asset B: Long migration (X=4.0), long retention (Y=15.0), Z=8.5 -> Total 19.0 > 8.5 (Deficit 10.5)
        res_b = MoscaSolver.solve_mosca_inequality(X_migration_time=4.0, Y_data_lifetime=15.0, Z_time_to_crqc=8.5, s_crypto=1.0)

        assert res_a["timeline"]["mosca_deficit_years"] != res_b["timeline"]["mosca_deficit_years"]
        assert res_a["timeline"]["must_start_by_year"] != res_b["timeline"]["must_start_by_year"]
        assert res_a["migration_posture"] == "SAFE_BUFFER"
        assert res_b["migration_posture"] == "MIGRATION_DEFICIT"
        assert res_a["timeline"]["mosca_deficit_years"] == -5.5
        assert res_b["timeline"]["mosca_deficit_years"] == 10.5

    def test_7_portfolio_valid_deadlines_aggregation(self):
        """TEST 7: Portfolio containing valid individual deadlines derives minimum valid deadline"""
        cbom_doc = {
            "crypto_assets": [
                {
                    "asset_id": "A1",
                    "algorithm": "RSA-2048",
                    "family": "asymmetric_encryption",
                    "crypto_role": "key_exchange",
                    "parameters": {"key_size": 2048}
                },
                {
                    "asset_id": "A2",
                    "algorithm": "ECDSA P-256",
                    "family": "digital_signature",
                    "crypto_role": "digital_signature",
                    "parameters": {"curve": "P-256"}
                },
                {
                    "asset_id": "A3",
                    "algorithm": "AES-256-GCM",
                    "family": "symmetric_encryption",
                    "crypto_role": "data_at_rest_encryption",
                    "parameters": {"key_size": 256}
                }
            ]
        }
        ml_map = {
            "A1": {"prediction": "HIGH", "confidence": 0.90},
            "A2": {"prediction": "HIGH", "confidence": 0.85},
            "A3": {"prediction": "LOW", "confidence": 0.95}
        }
        hndl_map = {
            "A1": {"hndl_exposure_score": 0.8, "future_decryption_risk": "HIGH", "applicable": True},
            "A2": {"hndl_exposure_score": 0.0, "future_decryption_risk": "LOW", "applicable": False},
            "A3": {"hndl_exposure_score": 0.0, "future_decryption_risk": "LOW", "applicable": False}
        }
        mosca_map = {
            "A1": {"inequality_satisfied": True, "timeline": {"mosca_deficit_years": 3.5, "must_start_by_year": 2031.5, "is_overdue_to_start": False}},
            "A2": {"inequality_satisfied": True, "timeline": {"mosca_deficit_years": 5.0, "must_start_by_year": 2028.0, "is_overdue_to_start": False}},
            "A3": {"inequality_satisfied": False, "timeline": {"mosca_deficit_years": 0.0, "must_start_by_year": None, "is_overdue_to_start": False}}
        }

        portfolio_report = self.synthesizer.synthesize_portfolio(cbom_doc, ml_map, hndl_map, mosca_map)
        assert portfolio_report["portfolio_stats"]["earliest_migration_deadline_year"] == 2028.0

    def test_8_portfolio_no_valid_deadlines(self):
        """TEST 8: Portfolio with no valid deadlines returns None/N/A without generating 'deadline of None' text"""
        cbom_doc = {
            "crypto_assets": [
                {
                    "asset_id": "A1",
                    "algorithm": "ML-KEM-768",
                    "family": "post_quantum_kem",
                    "crypto_role": "key_exchange",
                    "parameters": {"claimed_nist_level": 3}
                }
            ]
        }
        ml_map = {"A1": {"prediction": "LOW", "confidence": 0.98}}
        hndl_map = {"A1": {"hndl_exposure_score": 0.0, "future_decryption_risk": "LOW", "applicable": False}}
        mosca_map = {"A1": {"inequality_satisfied": False, "timeline": {"mosca_deficit_years": 0.0, "must_start_by_year": None, "is_overdue_to_start": False}}}

        portfolio_report = self.synthesizer.synthesize_portfolio(cbom_doc, ml_map, hndl_map, mosca_map)
        assert portfolio_report["portfolio_stats"]["earliest_migration_deadline_year"] is None
        exec_summary = portfolio_report.get("executive_summary", "")
        assert "deadline of None" not in exec_summary

    def test_9_rsa_ambiguous_purpose_classification(self):
        """TEST 9: RSA-3072 with ambiguous purpose 'authentication' requests usage classification before replacement"""
        asset = {
            "asset_id": "DISC-006",
            "algorithm": "RSA-3072",
            "family": "asymmetric",
            "purpose": "authentication",
            "crypto_role": "authentication",
            "data_sensitivity": "HIGH",
            "parameters": {"key_size": 3072}
        }
        hndl = {"hndl_exposure_score": 0.03, "future_decryption_risk": "MEDIUM", "applicable": True}
        mosca = {
            "is_applicable": True,
            "deficit_years": 1.2,
            "must_start_by_year": 2029.8,
            "inequality_satisfied": True,
            "urgency_tier": "HIGH",
            "migration_posture": "ACTIVE_TIMELINE_DEFICIT"
        }
        ml = {"prediction": "HIGH", "confidence": 0.847}

        report = self.synthesizer.synthesize_asset(asset, ml, hndl, mosca)
        assert report["pqc_status"] == "CLASSICAL_VULNERABLE"
        assert report["migration_required"] is True
        # Must not blindly recommend ML-DSA
        assert "Determine whether the RSA-3072 usage provides" in report["recommended_action"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
