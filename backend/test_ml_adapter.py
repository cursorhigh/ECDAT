"""
Integration & Unit Test Suite for CBOM to ML Feature Adapter (test_ml_adapter.py)

Validates:
1. Extraction of the exact 37 canonical features from CBOM assets & CycloneDX components.
2. Compliance with feature_schema.json schema constraints and datatypes.
3. Execution of CatBoost multi-class inference via predict_quantum_risk.
4. Accurate risk tier classification (e.g., RSA-2048 / ECDSA -> CRITICAL/HIGH risk, AES-256 / ML-KEM -> LOW risk).
5. Batch document scoring with global quantum posture calculation.
6. RiskClassificationAgent interface methods.
"""

import os
import sys
import unittest
from pathlib import Path

from segments.ml.cbom import CBOMAgent, MLFeatureAdapter
from segments.ml.risk_agent import RiskClassificationAgent
from segments.ml.risk_agent.Quantum_Risk_Model.src.predict import (
    predict_quantum_risk,
    canonicalize_and_validate_record,
    get_model_artifacts,
)


class TestMLFeatureAdapter(unittest.TestCase):

    def setUp(self):
        self.agent = CBOMAgent()
        self.adapter = MLFeatureAdapter()
        self.risk_agent = RiskClassificationAgent()
        _, _, _, self.schema = get_model_artifacts()

    # -------------------------------------------------------------------------
    # 1. 37-Feature Extraction & Schema Validation Tests
    # -------------------------------------------------------------------------
    def test_rsa_asset_37_features(self):
        finding = {
            "id": "F001",
            "file": "src/auth/rsa.py",
            "line": 42,
            "detected": "RSA",
            "code": "rsa.generate_private_key(key_size=2048)",
        }
        cbom = self.agent.process({"findings": [finding]})
        asset = cbom["crypto_assets"][0]

        ctx = {
            "deployment_environment": "cloud",
            "data_sensitivity": 4,
            "data_lifetime_years": 10.0,
            "business_criticality": 4,
            "HNDL_exposure": 0.85,
        }

        features = self.adapter.cbom_asset_to_ml_features(asset, ctx)

        # 1. Check feature count
        self.assertEqual(len(features), 37)

        # 2. Check key cryptographic values
        self.assertEqual(features["algorithm"], "RSA-2048")
        self.assertEqual(features["algorithm_family"], "asymmetric")
        self.assertEqual(features["crypto_role"], "signature")
        self.assertEqual(features["key_or_hash_size_bits"], 2048)
        self.assertEqual(features["quantum_vulnerable"], 1)
        self.assertEqual(features["quantum_attack_type"], "Shor")
        self.assertEqual(features["nist_security_category"], 0)
        self.assertEqual(features["HNDL_exposure"], 0.85)

        # 3. Validate against model's canonical schema validator
        is_valid, record, errors, warnings = canonicalize_and_validate_record(features, self.schema)
        self.assertTrue(is_valid, f"Schema validation failed: {errors}")

    def test_aes_asset_37_features(self):
        finding = {
            "id": "F002",
            "file": "src/crypto/aes.py",
            "line": 15,
            "detected": "AES-256-GCM",
            "code": "Cipher(algorithms.AES(key), modes.GCM(nonce))",
        }
        cbom = self.agent.process({"findings": [finding]})
        asset = cbom["crypto_assets"][0]

        features = self.adapter.cbom_asset_to_ml_features(asset)
        self.assertEqual(features["algorithm"], "AES-256")
        self.assertEqual(features["algorithm_family"], "symmetric")
        self.assertEqual(features["quantum_vulnerable"], 0)
        self.assertEqual(features["quantum_attack_type"], "Grover")
        self.assertEqual(features["nist_security_category"], 5)

        is_valid, _, errors, _ = canonicalize_and_validate_record(features, self.schema)
        self.assertTrue(is_valid, f"Schema validation failed: {errors}")

    def test_pqc_mlkem_asset_37_features(self):
        finding = {
            "id": "F003",
            "file": "src/pqc/kem.py",
            "line": 88,
            "detected": "ML-KEM-768",
            "code": "kem.encapsulate()",
        }
        cbom = self.agent.process({"findings": [finding]})
        asset = cbom["crypto_assets"][0]

        features = self.adapter.cbom_asset_to_ml_features(asset)
        self.assertEqual(features["algorithm"], "ML-KEM-768")
        self.assertEqual(features["algorithm_family"], "pqc")
        self.assertEqual(features["quantum_vulnerable"], 0)
        self.assertEqual(features["nist_security_category"], 3)

        is_valid, _, errors, _ = canonicalize_and_validate_record(features, self.schema)
        self.assertTrue(is_valid, f"Schema validation failed: {errors}")

    # -------------------------------------------------------------------------
    # 2. ML Model Inference & Prediction Tests
    # -------------------------------------------------------------------------
    def test_predict_single_asset_risk(self):
        finding = {
            "id": "F001",
            "file": "src/auth/rsa.py",
            "line": 42,
            "detected": "RSA",
            "code": "rsa.generate_private_key(key_size=2048)",
        }
        cbom = self.agent.process({"findings": [finding]})
        asset = cbom["crypto_assets"][0]

        ctx = {
            "data_sensitivity": 5,
            "data_lifetime_years": 15.0,
            "business_criticality": 5,
            "HNDL_exposure": 0.9,
            "internet_exposed": 1,
        }

        pred = self.risk_agent.assess_asset_risk(asset, ctx)
        self.assertIn(pred["status"], ["valid", "valid_with_warnings"])
        self.assertIn(pred["risk_level"], ["HIGH", "CRITICAL"])
        conf = pred.get("model_confidence") or pred.get("confidence", 0.0)
        self.assertGreater(conf, 0.5)
        self.assertIn("probabilities", pred)
        self.assertIn("CRITICAL", pred["probabilities"])

    def test_predict_quantum_safe_asset_risk(self):
        finding = {
            "id": "F_PQC",
            "file": "src/pqc/kem.py",
            "line": 10,
            "detected": "ML-KEM-1024",
            "code": "kem.generate_key()",
        }
        cbom = self.agent.process({"findings": [finding]})
        asset = cbom["crypto_assets"][0]

        pred = self.risk_agent.assess_asset_risk(asset)
        self.assertIn(pred["status"], ["valid", "valid_with_warnings"])
        self.assertIn(pred["risk_level"], ["LOW", "MEDIUM"])

    # -------------------------------------------------------------------------
    # 3. Full CBOM Document Scoring & Batch Inference Tests
    # -------------------------------------------------------------------------
    def test_full_cbom_document_scoring(self):
        payload = {
            "repository": {"name": "enterprise-banking-core", "url": "https://github.com/bank/core"},
            "findings": [
                {
                    "id": "F1",
                    "file": "src/auth/jwt.py",
                    "line": 30,
                    "detected": "RSA-2048",
                    "code": "rsa.generate_private_key(key_size=2048)",
                },
                {
                    "id": "F2",
                    "file": "src/crypto/db_enc.py",
                    "line": 55,
                    "detected": "AES-256-GCM",
                    "code": "Cipher(algorithms.AES(key), modes.GCM(nonce))",
                },
                {
                    "id": "F3",
                    "file": "src/auth/ecdsa.py",
                    "line": 99,
                    "detected": "ECDSA",
                    "code": "ec.generate_private_key(ec.SECP256R1())",
                },
            ],
        }
        cbom_doc = self.agent.process(payload)

        system_context = {
            "deployment_environment": "cloud",
            "data_sensitivity": 4,
            "data_lifetime_years": 8.0,
            "business_criticality": 4,
            "HNDL_exposure": 0.8,
        }

        enriched_cbom = self.risk_agent.assess_cbom(cbom_doc, system_context)

        # 1. Verify each asset received quantum risk annotation
        for asset in enriched_cbom["crypto_assets"]:
            self.assertIn("quantum_risk", asset)
            qr = asset["quantum_risk"]
            self.assertIn(qr["risk_level"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            self.assertIn(qr["status"], ["valid", "valid_with_warnings"])
            self.assertGreater(qr["confidence"], 0.0)

        # 2. Verify overall summary calculation
        self.assertIn("quantum_risk_summary", enriched_cbom)
        summary = enriched_cbom["quantum_risk_summary"]
        self.assertEqual(summary["total_assessed_assets"], 3)
        self.assertIn(summary["overall_posture"], ["HIGH", "CRITICAL"])
        self.assertEqual(sum(summary["by_tier"].values()), 3)

    # -------------------------------------------------------------------------
    # 4. CycloneDX 1.6 Component Ingestion
    # -------------------------------------------------------------------------
    def test_cyclonedx_component_ingestion(self):
        payload = {
            "repository": {"name": "auth-service"},
            "findings": [
                {
                    "id": "CDX1",
                    "file": "auth.py",
                    "line": 10,
                    "detected": "RSA-4096",
                    "code": "rsa.generate_key(4096)",
                }
            ]
        }
        cbom_doc = self.agent.process(payload)
        cdx_bom = cbom_doc["cyclonedx_bom"]

        # Convert CycloneDX component to ML features
        cdx_comp = cdx_bom["components"][0]
        features = self.adapter.cbom_asset_to_ml_features(cdx_comp)
        self.assertEqual(features["algorithm"], "RSA-4096")
        self.assertEqual(features["key_or_hash_size_bits"], 4096)
        self.assertEqual(features["quantum_vulnerable"], 1)

        is_valid, _, errors, _ = canonicalize_and_validate_record(features, self.schema)
        self.assertTrue(is_valid, f"Schema validation failed: {errors}")


if __name__ == "__main__":
    unittest.main()
