"""
Comprehensive Unit Test Suite for MOSCA+ Cryptographic Assessment Agent

Verifies all 7 mandatory test scenarios:
1. RSA 2048 -> PUBLIC_KEY, quantum_vulnerable = True
2. AES-256 -> SYMMETRIC, quantum_vulnerable = False (not treated as RSA)
3. SHA-256 -> HASH, security margin evaluation
4. ECDSA -> PUBLIC_KEY, quantum_vulnerable = True
5. UNKNOWN -> Conservative handling, no crash
6. Missing Key Size -> Robust execution without crashing
7. Gemini API Unavailable -> Fallback activation without false claims
"""

import sys
import os
import unittest
from typing import Dict, Any

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from segments.ml.mosca_agent import (
    MOSCAAgent,
    CryptoRuleEngine,
    FallbackMOSCAProvider,
    get_mosca_provider,
)


class TestMOSCAAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = get_mosca_provider()
        cls.agent = MOSCAAgent(llm_provider=cls.provider, verbose=False)
        cls.rule_engine = CryptoRuleEngine()

    def test_01_rsa_2048(self):
        asset = {
            "asset_id": "crypto-rsa-001",
            "algorithm": {"family": "RSA", "name": "RSA"},
            "parameters": {"key_size": 2048},
            "purpose": ["key_establishment"],
        }
        res = self.agent.analyze(asset)
        self.assertEqual(res["asset_id"], "crypto-rsa-001")
        assessment = res["mosca_assessment"]
        self.assertEqual(assessment["algorithm_category"], "PUBLIC_KEY")
        self.assertTrue(assessment["quantum_vulnerable"])
        self.assertIn(assessment["migration_priority"], ("HIGH", "URGENT"))

    def test_02_aes_256(self):
        asset = {
            "asset_id": "crypto-aes-001",
            "algorithm": {"family": "AES", "name": "AES-256-GCM"},
            "parameters": {"key_size": 256, "mode": "GCM"},
            "purpose": ["encryption"],
        }
        res = self.agent.analyze(asset)
        assessment = res["mosca_assessment"]
        self.assertEqual(assessment["algorithm_category"], "SYMMETRIC")
        self.assertFalse(assessment["quantum_vulnerable"])

    def test_03_sha_256(self):
        asset = {
            "asset_id": "crypto-sha-001",
            "algorithm": {"family": "SHA", "name": "SHA-256"},
            "parameters": {},
            "purpose": ["hashing"],
        }
        res = self.agent.analyze(asset)
        assessment = res["mosca_assessment"]
        self.assertEqual(assessment["algorithm_category"], "HASH")
        self.assertFalse(assessment["quantum_vulnerable"])
        self.assertIn(assessment["overall_risk"], ("LOW", "MEDIUM"))

    def test_04_ecdsa(self):
        asset = {
            "asset_id": "crypto-ecdsa-001",
            "algorithm": {"family": "ECDSA", "name": "ECDSA P-256"},
            "parameters": {"curve": "P-256"},
            "purpose": ["signing"],
        }
        res = self.agent.analyze(asset)
        assessment = res["mosca_assessment"]
        self.assertEqual(assessment["algorithm_category"], "PUBLIC_KEY")
        self.assertTrue(assessment["quantum_vulnerable"])

    def test_05_unknown_custom_crypto(self):
        asset = {
            "asset_id": "crypto-custom-001",
            "algorithm": {"family": "UNKNOWN", "name": "CustomCryptoRef"},
            "parameters": {},
            "purpose": ["encryption"],
        }
        res = self.agent.analyze(asset)
        assessment = res["mosca_assessment"]
        self.assertEqual(assessment["algorithm_category"], "UNKNOWN")
        self.assertIsNone(assessment.get("quantum_vulnerable"))

    def test_06_missing_key_size(self):
        asset = {
            "asset_id": "crypto-rsa-missing-key",
            "algorithm": {"family": "RSA", "name": "RSA"},
            "parameters": {},  # key_size intentionally omitted
            "purpose": ["encryption"],
        }
        res = self.agent.analyze(asset)
        self.assertEqual(res["asset_id"], "crypto-rsa-missing-key")
        assessment = res["mosca_assessment"]
        self.assertEqual(assessment["algorithm_category"], "PUBLIC_KEY")
        self.assertTrue(assessment["quantum_vulnerable"])

    def test_07_gemini_api_unavailable_fallback(self):
        fallback_agent = MOSCAAgent(llm_provider=FallbackMOSCAProvider(), verbose=False)
        asset = {
            "asset_id": "crypto-rsa-fallback",
            "algorithm": {"family": "RSA", "name": "RSA"},
            "parameters": {"key_size": 2048},
        }
        res = fallback_agent.analyze(asset)
        assessment = res["mosca_assessment"]
        self.assertEqual(assessment["algorithm_category"], "PUBLIC_KEY")
        self.assertTrue(assessment["quantum_vulnerable"])
        self.assertIn("reason", assessment)


if __name__ == "__main__":
    unittest.main()
