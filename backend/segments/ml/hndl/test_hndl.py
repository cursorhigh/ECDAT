"""
Comprehensive Unit Test Suite & Terminal Demonstration for HNDL Module

Verifies all 5 mandatory HNDL threat assessment scenarios:
1. High HNDL Risk (RSA-2048, CRITICAL sensitivity, 20-year lifetime, internet exposed & collectable).
2. Low Harvestability (Quantum-vulnerable RSA, but unexposed/uncollectable).
3. Short-Lived Data (RSA, LOW sensitivity, 1-year lifetime).
4. Symmetric Cryptography (AES-256-GCM).
5. Unknown Algorithm (CustomCrypto -> quantum_vulnerable: null).
"""

import sys
import os
import unittest
from typing import Dict, Any

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from segments.ml.hndl import HNDLAgent, FallbackHNDLProvider, get_hndl_provider, format_hndl_terminal_report


class TestHNDLRiskModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = get_hndl_provider()
        cls.agent = HNDLAgent(provider=cls.provider)

    def test_01_high_hndl_risk(self):
        cbom_asset = {
            "asset_id": "crypto-rsa-001",
            "algorithm": {"family": "RSA", "name": "RSA"},
            "parameters": {"key_size": 2048},
            "purpose": ["key_establishment"],
        }
        risk_context = {
            "data_context": {"sensitivity": "CRITICAL", "data_lifetime_years": 20},
            "network_context": {"internet_exposed": True, "collectable": True},
        }

        res = self.agent.analyze(cbom_asset, risk_context)

        self.assertEqual(res["asset_id"], "crypto-rsa-001")
        hndl = res["hndl"]
        self.assertTrue(hndl["applicable"])
        self.assertEqual(hndl["harvestability"], "HIGH")
        self.assertEqual(hndl["future_decryption_risk"], "HIGH")
        self.assertEqual(hndl["data_lifetime_years"], 20)
        self.assertTrue(hndl["quantum_vulnerable"])
        self.assertTrue(len(hndl["reason"]) > 10)

    def test_02_low_harvestability(self):
        cbom_asset = {
            "asset_id": "crypto-rsa-002",
            "algorithm": {"family": "RSA", "name": "RSA-4096"},
            "parameters": {"key_size": 4096},
            "purpose": ["key_establishment"],
        }
        risk_context = {
            "data_context": {"sensitivity": "CRITICAL", "data_lifetime_years": 20},
            "network_context": {"internet_exposed": False, "collectable": False},
        }

        res = self.agent.analyze(cbom_asset, risk_context)

        hndl = res["hndl"]
        self.assertEqual(hndl["harvestability"], "LOW")
        self.assertIn(hndl["future_decryption_risk"], ("LOW", "MEDIUM"))

    def test_03_short_lived_data(self):
        cbom_asset = {
            "asset_id": "crypto-rsa-003",
            "algorithm": {"family": "RSA", "name": "RSA-2048"},
            "parameters": {"key_size": 2048},
            "purpose": ["encryption"],
        }
        risk_context = {
            "data_context": {"sensitivity": "LOW", "data_lifetime_years": 1},
            "network_context": {"internet_exposed": True, "collectable": True},
        }

        res = self.agent.analyze(cbom_asset, risk_context)

        hndl = res["hndl"]
        self.assertEqual(hndl["data_lifetime_years"], 1)
        self.assertEqual(hndl["future_decryption_risk"], "LOW")

    def test_04_symmetric_cryptography(self):
        cbom_asset = {
            "asset_id": "crypto-aes-001",
            "algorithm": {"family": "AES", "name": "AES-256-GCM"},
            "parameters": {"key_size": 256, "mode": "GCM"},
            "purpose": ["encryption"],
        }
        risk_context = {
            "data_context": {"sensitivity": "CRITICAL", "data_lifetime_years": 20},
            "network_context": {"internet_exposed": True, "collectable": True},
        }

        res = self.agent.analyze(cbom_asset, risk_context)

        hndl = res["hndl"]
        self.assertFalse(hndl["quantum_vulnerable"])
        self.assertEqual(hndl["future_decryption_risk"], "LOW")

    def test_05_unknown_algorithm(self):
        cbom_asset = {
            "asset_id": "crypto-custom-001",
            "algorithm": {"family": "UNKNOWN", "name": "CustomCrypto"},
            "parameters": {},
            "purpose": ["encryption"],
        }
        risk_context = {
            "data_context": {"sensitivity": "MEDIUM", "data_lifetime_years": 10},
            "network_context": {"internet_exposed": True, "collectable": True},
        }

        res = self.agent.analyze(cbom_asset, risk_context)

        hndl = res["hndl"]
        self.assertIsNone(hndl["quantum_vulnerable"])
        self.assertEqual(hndl["future_decryption_risk"], "NOT_ASSESSABLE")

    def test_06_missing_data_lifetime_not_assessable(self):
        cbom_asset = {
            "asset_id": "crypto-rsa-006",
            "algorithm": {"family": "RSA", "name": "RSA-2048"},
            "purpose": ["encryption"],
        }
        # Missing data_lifetime_years
        risk_context = {
            "data_context": {"sensitivity": "HIGH"},
            "network_context": {"internet_exposed": True},
        }
        res = self.agent.analyze(cbom_asset, risk_context)
        hndl = res["hndl"]
        self.assertFalse(hndl["applicable"])
        self.assertEqual(hndl["future_decryption_risk"], "NOT_ASSESSABLE")
        self.assertEqual(hndl["evidence_status"], "NOT_ASSESSABLE")

    def test_07_unlabelled_data_types_not_assessable(self):
        cbom_asset = {
            "asset_id": "crypto-rsa-007",
            "algorithm": {"family": "RSA", "name": "RSA-2048"},
            "purpose": ["encryption"],
        }
        # Data types: none labelled, no sensitivity provided
        risk_context = {
            "data_context": {"data_lifetime_years": 8.0, "data_types": ["none labelled"]},
            "network_context": {"internet_exposed": False, "exposure": "internal"},
        }
        res = self.agent.analyze(cbom_asset, risk_context)
        hndl = res["hndl"]
        self.assertFalse(hndl["applicable"])
        self.assertEqual(hndl["future_decryption_risk"], "NOT_ASSESSABLE")
        self.assertEqual(hndl["evidence_status"], "NOT_ASSESSABLE")

    def test_08_missing_network_exposure_not_assessable(self):
        cbom_asset = {
            "asset_id": "crypto-rsa-008",
            "algorithm": {"family": "RSA", "name": "RSA-2048"},
            "purpose": ["encryption"],
        }
        # Missing network exposure
        risk_context = {
            "data_context": {"sensitivity": "HIGH", "data_lifetime_years": 8.0},
        }
        res = self.agent.analyze(cbom_asset, risk_context)
        hndl = res["hndl"]
        self.assertFalse(hndl["applicable"])
        self.assertEqual(hndl["future_decryption_risk"], "NOT_ASSESSABLE")
        self.assertEqual(hndl["evidence_status"], "NOT_ASSESSABLE")


def run_terminal_demonstration():
    """Runs a terminal report for Test Case 1."""
    agent = HNDLAgent()
    cbom_asset = {
        "asset_id": "crypto-rsa-001",
        "algorithm": {"family": "RSA", "name": "RSA"},
        "parameters": {"key_size": 2048},
        "purpose": ["key_establishment"],
    }
    risk_context = {
        "data_context": {"sensitivity": "CRITICAL", "data_lifetime_years": 20},
        "network_context": {"internet_exposed": True, "collectable": True},
    }

    result = agent.analyze(cbom_asset, risk_context)
    report = format_hndl_terminal_report(cbom_asset, risk_context, result)
    print("\n" + report + "\n")


if __name__ == "__main__":
    run_terminal_demonstration()
    unittest.main()
