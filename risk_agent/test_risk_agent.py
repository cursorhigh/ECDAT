"""
Test Suite & Integration Tests for Risk Classification Agent

Verifies:
1. Test Case 1: Online Banking System (CRITICAL sensitivity, 20yr lifetime, internet exposed & collectable).
2. Test Case 2: Internal Document Portal (Internal system, unexposed, uncollectable).
3. Test Case 3: Public Information Portal (LOW sensitivity, internet exposed).
4. Test Case 4: Full End-to-End Pipeline Integration (RAW SYSTEM CONTEXT -> RISK AGENT -> HNDL AGENT -> FINAL HNDL ASSESSMENT).
"""

import sys
import os
import unittest
import json
from typing import Dict, Any

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from risk_agent import RiskClassificationAgent, get_risk_provider
from hndl import HNDLAgent, format_hndl_terminal_report


class TestRiskClassificationAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = get_risk_provider()
        cls.agent = RiskClassificationAgent(provider=cls.provider)

    def test_01_online_banking_system(self):
        raw_context = {
            "application": {
                "name": "Online Banking System",
                "type": "web_application",
                "description": "Public online banking platform for accounts and financial transactions."
            },
            "data": {
                "types": ["financial_records", "personal_information"],
                "description": "Customer banking data and transactions."
            },
            "network": {
                "internet_facing": True,
                "external_users": True,
                "publicly_accessible": True
            },
            "business_context": {
                "data_retention_years": 20
            }
        }

        risk_context = self.agent.analyze(raw_context)

        data_ctx = risk_context["data_context"]
        net_ctx = risk_context["network_context"]

        self.assertEqual(data_ctx["sensitivity"], "CRITICAL")
        self.assertEqual(data_ctx["data_lifetime_years"], 20)
        self.assertTrue(net_ctx["internet_exposed"])
        self.assertTrue(net_ctx["collectable"])

    def test_02_internal_document_system(self):
        raw_context = {
            "application": {
                "name": "Internal Document Portal",
                "type": "internal_system"
            },
            "data": {
                "types": ["internal_documents"]
            },
            "network": {
                "internal_only": True,
                "internet_facing": False
            }
        }

        risk_context = self.agent.analyze(raw_context)

        net_ctx = risk_context["network_context"]
        self.assertFalse(net_ctx["internet_exposed"])
        self.assertFalse(net_ctx["collectable"])

    def test_03_public_information_system(self):
        raw_context = {
            "application": {
                "name": "Public Information Portal",
                "type": "web_application"
            },
            "data": {
                "types": ["public_information"]
            },
            "network": {
                "internet_facing": True
            }
        }

        risk_context = self.agent.analyze(raw_context)

        data_ctx = risk_context["data_context"]
        net_ctx = risk_context["network_context"]

        self.assertEqual(data_ctx["sensitivity"], "LOW")
        self.assertTrue(net_ctx["internet_exposed"])

    def test_04_full_pipeline_integration_with_hndl(self):
        # 1. Raw System Context
        raw_context = {
            "application": {
                "name": "Enterprise Core Banking API",
                "type": "financial_system",
                "description": "Core banking API processing customer financial transfers."
            },
            "data": {
                "types": ["financial_records", "banking_information", "transaction_history"],
                "description": "High-value financial ledger records."
            },
            "network": {
                "publicly_accessible": True,
                "internet_facing": True,
                "external_users": True
            },
            "business_context": {
                "data_retention_years": 20,
                "long_term_value": True
            }
        }

        # 2. Input 1: CBOM Cryptographic Asset
        cbom_asset = {
            "asset_id": "crypto-rsa-001",
            "algorithm": {
                "family": "RSA",
                "name": "RSA"
            },
            "parameters": {
                "key_size": 2048
            },
            "purpose": [
                "key_establishment"
            ]
        }

        # Step A: Risk Agent transforms raw_context -> structured risk_context (Input 2)
        structured_risk_context = self.agent.analyze(raw_context)

        # Step B: HNDL Agent receives Input 1 (CBOM Asset) + Input 2 (Structured Risk Context)
        hndl_agent = HNDLAgent()
        hndl_result = hndl_agent.analyze(cbom_asset=cbom_asset, risk_context=structured_risk_context)

        # Assert pipeline success
        self.assertEqual(hndl_result["asset_id"], "crypto-rsa-001")
        hndl_body = hndl_result["hndl"]
        self.assertTrue(hndl_body["applicable"])
        self.assertEqual(hndl_body["harvestability"], "HIGH")
        self.assertEqual(hndl_body["future_decryption_risk"], "HIGH")
        self.assertEqual(hndl_body["data_lifetime_years"], 20)
        self.assertTrue(hndl_body["quantum_vulnerable"])


def run_terminal_pipeline_demonstration():
    """Runs a complete end-to-end pipeline demonstration: RAW CONTEXT -> RISK AGENT -> HNDL AGENT."""
    print("\n" + "=" * 65)
    print("END-TO-END ECDAT PIPELINE: RISK CLASSIFICATION AGENT -> HNDL AGENT")
    print("=" * 65 + "\n")

    raw_context = {
        "application": {
            "name": "Online Banking System",
            "type": "web_application",
            "description": "A public banking platform allowing customers to manage accounts and perform financial transactions."
        },
        "data": {
            "types": ["financial_records", "personal_information", "transaction_history"],
            "description": "Customer financial and transaction information."
        },
        "network": {
            "publicly_accessible": True,
            "internet_facing": True,
            "external_users": True
        },
        "business_context": {
            "data_retention_years": 20,
            "long_term_value": True
        }
    }

    cbom_asset = {
        "asset_id": "crypto-rsa-001",
        "algorithm": {
            "family": "RSA",
            "name": "RSA"
        },
        "parameters": {
            "key_size": 2048
        },
        "purpose": [
            "key_establishment"
        ]
    }

    # Step 1: Risk Agent
    risk_agent = RiskClassificationAgent()
    structured_risk_context = risk_agent.analyze(raw_context)

    print("[STEP 1] RISK CLASSIFICATION AGENT OUTPUT (INPUT 2 FOR HNDL):")
    print(json.dumps(structured_risk_context, indent=2))
    print("-" * 65 + "\n")

    # Step 2: HNDL Agent
    hndl_agent = HNDLAgent()
    hndl_result = hndl_agent.analyze(cbom_asset=cbom_asset, risk_context=structured_risk_context)

    print("[STEP 2] HNDL AGENT FINAL THREAT ASSESSMENT:")
    print(format_hndl_terminal_report(cbom_asset, structured_risk_context, hndl_result))
    print("\n" + "=" * 65 + "\n")


if __name__ == "__main__":
    run_terminal_pipeline_demonstration()
    unittest.main()
