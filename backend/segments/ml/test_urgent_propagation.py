"""Comprehensive Regression Suite for Authoritative Risk & Urgency Classification.

Tests the deterministic escalation rules across:
- Test 1: URGENT (RSA-1024 + Mosca Deficit + Public Endpoint + HNDL HIGH -> URGENT / Wave 1)
- Test 2: HIGH (RSA-2048 + Mosca Deficit + Internal / No Public -> HIGH / Wave 2)
- Test 3: URGENT through HNDL (RSA-2048 + Mosca Deficit + HNDL HIGH -> URGENT / Wave 1)
- Test 4: Classical Critical (DES + Exploitability 95 -> URGENT / Wave 1)
- Test 5: Digital Signature (ECDSA P-256 + Y=0 + HNDL N/A -> HIGH / Wave 2)
- Test 6: Safe Symmetric (AES-256-GCM -> LOW / Wave 3)
- Test 7: Metadata preservation in payload builder & CBOM agent
- Test 8: HNDL assessability with explicit context
"""

import os
import unittest
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from segments.ml.risk_classifier import classify_canonical_asset
from segments.ml.hndl.validator import HNDLValidator
from segments.ml.hndl.hndl_agent import HNDLAgent
from segments.ml.cbom.cbom_agent import CBOMAgent


class TestUrgentPropagation(unittest.TestCase):

    def test_01_urgent_rsa_mosca_public_endpoint(self):
        """Test 1: RSA-1024 with Mosca Deficit and Public Endpoint -> URGENT / Wave 1."""
        ctx = {
            "algorithm": "RSA-1024",
            "family": "rsa",
            "key_size": 1024,
            "role": "key_exchange",
            "migration_time_years": 2.0,
            "data_shelf_life_years": 7.0,
            "quantum_horizon_years": 7.0,
            "public_endpoint": True,
            "hndl_exposure": "HIGH",
        }
        res = classify_canonical_asset(ctx)
        self.assertEqual(res["priority"], "URGENT")
        self.assertEqual(res["risk_tier"], "URGENT")
        self.assertEqual(res["remediation_wave"], 1)
        self.assertTrue(res["quantum_vulnerable"])
        self.assertGreater(res["mosca_deficit"], 0.0)
        self.assertTrue(res["is_public"])

    def test_02_high_rsa_mosca_internal_no_public(self):
        """Test 2: RSA-2048 with Mosca Deficit but Internal (no public exposure) -> HIGH / Wave 2."""
        ctx = {
            "algorithm": "RSA-2048",
            "family": "rsa",
            "key_size": 2048,
            "role": "key_exchange",
            "migration_time_years": 2.5,
            "data_shelf_life_years": 5.0,
            "quantum_horizon_years": 7.0,
            "public_endpoint": False,
            "internet_facing": False,
            "network_exposure": "internal",
            "hndl_exposure": "LOW",
        }
        res = classify_canonical_asset(ctx)
        self.assertEqual(res["priority"], "HIGH")
        self.assertEqual(res["risk_tier"], "HIGH")
        self.assertEqual(res["remediation_wave"], 2)

    def test_03_urgent_rsa_through_hndl(self):
        """Test 3: RSA-2048 with Mosca Deficit + HNDL HIGH -> URGENT / Wave 1."""
        ctx = {
            "algorithm": "RSA-2048",
            "family": "rsa",
            "key_size": 2048,
            "role": "key_exchange",
            "migration_time_years": 2.5,
            "data_shelf_life_years": 5.0,
            "quantum_horizon_years": 7.0,
            "public_endpoint": False,
            "hndl_exposure": "HIGH",
        }
        res = classify_canonical_asset(ctx)
        self.assertEqual(res["priority"], "URGENT")
        self.assertEqual(res["risk_tier"], "URGENT")
        self.assertEqual(res["remediation_wave"], 1)

    def test_04_classical_critical_des(self):
        """Test 4: Single DES with high exploitability -> URGENT / Wave 1."""
        ctx = {
            "algorithm": "DES",
            "family": "des",
            "key_size": 56,
            "role": "data_encryption",
            "exploitability_score": 95,
        }
        res = classify_canonical_asset(ctx)
        self.assertEqual(res["priority"], "URGENT")
        self.assertEqual(res["risk_tier"], "URGENT")
        self.assertEqual(res["remediation_wave"], 1)
        self.assertEqual(res["classical_security"], "WEAK")

    def test_05_digital_signature_ecdsa(self):
        """Test 5: ECDSA P-256 Digital Signature (Y=0, HNDL N/A) -> HIGH / Wave 2."""
        ctx = {
            "algorithm": "ECDSA",
            "family": "ecc",
            "key_size": 256,
            "role": "digital_signature",
            "migration_time_years": 1.5,
            "data_shelf_life_years": 0.0,
            "quantum_horizon_years": 7.0,
            "hndl_exposure": "NOT_APPLICABLE",
        }
        res = classify_canonical_asset(ctx)
        self.assertEqual(res["priority"], "HIGH")
        self.assertEqual(res["risk_tier"], "HIGH")
        self.assertEqual(res["remediation_wave"], 2)
        self.assertTrue(res["quantum_vulnerable"])

    def test_06_safe_symmetric_aes256(self):
        """Test 6: AES-256-GCM -> LOW / Wave 3."""
        ctx = {
            "algorithm": "AES-256-GCM",
            "family": "aes",
            "key_size": 256,
            "role": "authenticated_encryption",
        }
        res = classify_canonical_asset(ctx)
        self.assertEqual(res["priority"], "LOW")
        self.assertEqual(res["risk_tier"], "LOW")
        self.assertEqual(res["remediation_wave"], 3)
        self.assertFalse(res["quantum_vulnerable"])

    def test_07_cbom_preserves_operational_metadata(self):
        """Test 7: CBOMAgent preserves operational context and threat metadata in asset dict."""
        agent = CBOMAgent()
        input_data = {
            "findings": [
                {
                    "id": "FIND-001",
                    "algorithm": "RSA-1024",
                    "family": "rsa",
                    "parameters": {"key_size": 1024},
                    "public_endpoint": True,
                    "internet_facing": True,
                    "hndl_exposure": "HIGH",
                    "data_shelf_life_years": 7.0,
                    "migration_time_years": 2.0,
                }
            ]
        }
        cbom_doc = agent.process(input_data)
        assets = cbom_doc.get("crypto_assets", [])
        self.assertEqual(len(assets), 1)
        a = assets[0]
        self.assertTrue(a.get("public_endpoint"))
        self.assertTrue(a.get("internet_facing"))
        self.assertEqual(a.get("hndl_exposure"), "HIGH")
        self.assertEqual(a.get("data_shelf_life_years"), 7.0)

    def test_08_hndl_validator_with_explicit_context(self):
        """Test 8: HNDL validator recognizes explicit HNDL rating and operational fields on cbom_asset."""
        validator = HNDLValidator()
        cbom_asset = {
            "name": "RSA-1024",
            "algorithm": "RSA-1024",
            "family": "rsa",
            "hndl_exposure": "HIGH",
        }
        is_assessable, msg = validator.check_hndl_assessability(cbom_asset, {})
        self.assertTrue(is_assessable)
        self.assertIn("Explicit HNDL exposure", msg)

    def test_09_canonical_ledger_regression_acceptance_criteria(self):
        """Test 9: Authoritative regression assertion for full canonical ledger consistency.

        Asserts:
        rsa_1024.priority == 'URGENT'
        rsa_1024.remediation_wave == 1
        rsa_1024.hndl_exposure == 'HIGH'
        rsa_1024.mosca_deficit > 0
        rsa_1024.public_exposure is True
        """
        from segments.reporting.reports.report_builder import _build_canonical_classification_ledger, expected_wave

        dummy_data = {
            "assets": [
                {
                    "id": 101,
                    "name": "RSA-1024 Gateway",
                    "algorithm": "RSA-1024",
                    "family": "rsa",
                    "key_size": 1024,
                    "location": "src/public_tls.py",
                },
                {
                    "id": 102,
                    "name": "ECDSA Token Signer",
                    "algorithm": "ECDSA",
                    "family": "ecc",
                    "key_size": 256,
                    "location": "src/auth.py",
                },
                {
                    "id": 103,
                    "name": "SHA-256 Digest",
                    "algorithm": "SHA-256",
                    "family": "hash",
                    "location": "src/hash.py",
                },
            ],
            "runs": [
                {
                    "stats": {"assets": 3},
                    "threat_context": {"crqc_year_z": 2033, "years_until_crqc": 7.0},
                }
            ],
            "mitigation": {},
        }

        # Mock objects for DB resolution
        class DummyNorm:
            def __init__(self, ev):
                self.evidence = ev

        class DummyAsset:
            def __init__(self, algo, fam, ks, ev, env=""):
                self.pk = 101
                self.name = algo
                self.algorithm = algo
                self.family = fam
                self.key_size = ks
                self.curve = ""
                self.location = "src/public_tls.py"
                self.source_path = "src/public_tls.py"
                self.environment = env
                self.normalized_findings = [DummyNorm(ev)]
                self.occurrences = []

        records = _build_canonical_classification_ledger(dummy_data)
        self.assertEqual(len(records), 3)

        # Locate RSA-1024
        rsa_1024 = next(r for r in records if "RSA" in r["algorithm"])
        ecdsa = next(r for r in records if "ECDSA" in r["algorithm"])
        sha_256 = next(r for r in records if "SHA" in r["algorithm"])

        # RSA-1024 criteria
        self.assertEqual(rsa_1024["priority"], "URGENT")
        self.assertEqual(rsa_1024["risk_tier"], "URGENT")
        self.assertEqual(rsa_1024["remediation_wave"], 1)
        self.assertEqual(rsa_1024["hndl_exposure"], "HIGH")
        self.assertEqual(rsa_1024["hndl_status"], "APPLICABLE")
        self.assertGreater(rsa_1024["mosca_deficit"], 0)
        self.assertTrue(rsa_1024["public_exposure"])

        # ECDSA criteria
        self.assertEqual(ecdsa["priority"], "HIGH")
        self.assertEqual(ecdsa["risk_tier"], "HIGH")
        self.assertEqual(ecdsa["remediation_wave"], 2)
        self.assertEqual(ecdsa["hndl_status"], "NOT_APPLICABLE")
        self.assertEqual(ecdsa["mosca_status"], "SAFE")

        # SHA-256 criteria
        self.assertEqual(sha_256["priority"], "LOW")
        self.assertEqual(sha_256["risk_tier"], "LOW")
        self.assertEqual(sha_256["remediation_wave"], 3)

        # Verify dynamic wave sequencing invariant
        for r in records:
            self.assertEqual(r["remediation_wave"], expected_wave(r))


if __name__ == "__main__":
    unittest.main()

