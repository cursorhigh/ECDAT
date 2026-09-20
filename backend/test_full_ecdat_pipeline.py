"""
Full ECDAT End-to-End Master Pipeline Integration Test Script

Demonstrates and executes the complete 4-stage pipeline across 10 cryptographic assets:
STAGE 1: CBOM Generation (Deterministic + Gemini AI explainability)
STAGE 2: Risk Classification Agent (Raw context -> Structured Risk Context)
STAGE 3: HNDL Threat Assessment Agent (Input 1 CBOM Asset + Input 2 Risk Context)
STAGE 4: MOSCA+ Cryptographic Security & Migration Engine (Deterministic + Post-Quantum AI)

Outputs a consolidated ECDAT Executive Master Summary Table.
"""

import sys
import os
import json
import unittest

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from segments.ml.cbom import CBOMAgent, format_cbom_explanation
from segments.ml.risk_agent import RiskClassificationAgent
from segments.ml.hndl import HNDLAgent, format_hndl_terminal_report
from segments.ml.mosca_agent import MOSCAAgent


# 10 Representative Cryptographic Discovery Findings
SAMPLE_RAW_FINDINGS_PAYLOAD = {
    "repository": {
        "name": "enterprise-banking-core",
        "url": "https://github.com/myorg/enterprise-banking-core",
    },
    "findings": [
        {
            "id": "T001",
            "file": "src/auth/rsa_vault.py",
            "line": 42,
            "detected": "RSA",
            "code": "rsa.generate_private_key(key_size=2048)",
        },
        {
            "id": "T002",
            "file": "src/crypto/cipher.py",
            "line": 88,
            "detected": "AES-GCM",
            "code": "Cipher(algorithms.AES(key), modes.GCM(nonce))",
        },
        {
            "id": "T003",
            "file": "src/hash/digest.py",
            "line": 15,
            "detected": "SHA-256",
            "code": "hashlib.sha256(data).hexdigest()",
        },
        {
            "id": "T004",
            "file": "src/pki/ecdsa_signer.py",
            "line": 102,
            "detected": "ECDSA",
            "code": "ec.generate_private_key(ec.SECP256R1())",
        },
        {
            "id": "T005",
            "file": "src/legacy/custom_suite.py",
            "line": 55,
            "detected": "CustomCryptoRef",
            "code": "legacyCryptoEngine.initialize(CRYPTO_SUITE_XYZ)",
        },
        {
            "id": "T006",
            "file": "src/legacy/triple_des.py",
            "line": 34,
            "detected": "3DES",
            "code": "Cipher(algorithms.TripleDES(key), modes.CBC(iv))",
        },
        {
            "id": "T007",
            "file": "src/key_exchange/ecdh_handler.py",
            "line": 77,
            "detected": "ECDH",
            "code": "peer_public_key.exchange(ec.ECDH(), private_key)",
        },
        {
            "id": "T008",
            "file": "src/audit/integrity_checker.py",
            "line": 21,
            "detected": "SHA-512",
            "code": "hashlib.sha512(audit_log).digest()",
        },
        {
            "id": "T009",
            "file": "src/ca/root_cert_gen.py",
            "line": 19,
            "detected": "RSA",
            "code": "rsa.generate_private_key(key_size=4096)",
        },
        {
            "id": "T010",
            "file": "src/java/security/jca_cipher.java",
            "line": 140,
            "detected": "UNKNOWN",
            "code": 'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")',
        },
    ],
}


# Raw System Context (Input for Risk Classification Agent)
SAMPLE_RAW_SYSTEM_CONTEXT = {
    "application": {
        "name": "Enterprise Core Banking System",
        "type": "web_application",
        "description": "A public online banking platform used by enterprise customers to manage accounts and execute financial transactions."
    },
    "data": {
        "types": ["financial_records", "personal_information", "transaction_history", "authentication_credentials"],
        "description": "Customer banking, ledger records, and authentication credentials."
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


def run_full_ecdat_pipeline():
    print("\n" + "=" * 70)
    print("      ECDAT END-TO-END MASTER PIPELINE INTEGRATION DEMONSTRATION")
    print("=" * 70 + "\n")

    # Instantiate Agents
    cbom_agent = CBOMAgent()
    risk_agent = RiskClassificationAgent()
    hndl_agent = HNDLAgent()
    mosca_agent = MOSCAAgent(verbose=False)

    # -------------------------------------------------------------------------
    # STAGE 1: CBOM GENERATION
    # -------------------------------------------------------------------------
    print("=" * 70)
    print("STAGE 1: CBOM (CRYPTOGRAPHY BILL OF MATERIALS) GENERATION")
    print("=" * 70)
    cbom_document = cbom_agent.generate_cbom(
        SAMPLE_RAW_FINDINGS_PAYLOAD, output_filepath="full_pipeline_cbom_output.json"
    )
    crypto_assets = cbom_document.get("crypto_assets", [])

    print(f"\n[+] CBOM Created Successfully: {len(crypto_assets)} cryptographic assets extracted.")
    print("Saved CBOM file to: full_pipeline_cbom_output.json\n")

    print("Sample CBOM Asset Explainability (First 3 Assets):")
    print("-" * 70)
    for asset in crypto_assets[:3]:
        print(format_cbom_explanation(asset))
        print("-" * 70)
    print()

    # -------------------------------------------------------------------------
    # STAGE 2: RISK CLASSIFICATION AGENT
    # -------------------------------------------------------------------------
    print("=" * 70)
    print("STAGE 2: RISK CLASSIFICATION AGENT (RAW CONTEXT -> RISK CONTEXT)")
    print("=" * 70)
    structured_risk_context = risk_agent.analyze(SAMPLE_RAW_SYSTEM_CONTEXT)
    print("\n[+] Structured Risk Context Created (Input 2 for HNDL Agent):")
    print(json.dumps(structured_risk_context, indent=2))
    print()

    # -------------------------------------------------------------------------
    # STAGE 3: HNDL (HARVEST NOW, DECRYPT LATER) THREAT ASSESSMENT
    # -------------------------------------------------------------------------
    print("=" * 70)
    print("STAGE 3: HNDL (HARVEST NOW, DECRYPT LATER) THREAT ASSESSMENT")
    print("=" * 70)

    hndl_results = []
    for asset in crypto_assets:
        # Pass CBOM Asset (Input 1) + Risk Context (Input 2) to HNDL Agent
        res = hndl_agent.analyze(cbom_asset=asset, risk_context=structured_risk_context)
        hndl_results.append(res)

    print(f"\n[+] HNDL Analysis Complete for all {len(hndl_results)} assets.")
    print("\nSample HNDL Terminal Report (Asset T001):")
    print("-" * 70)
    print(format_hndl_terminal_report(crypto_assets[0], structured_risk_context, hndl_results[0]))
    print()

    # -------------------------------------------------------------------------
    # STAGE 4: MOSCA+ CRYPTOGRAPHIC SECURITY & MIGRATION ENGINE
    # -------------------------------------------------------------------------
    print("=" * 70)
    print("STAGE 4: MOSCA+ CRYPTOGRAPHIC SECURITY & MIGRATION ENGINE")
    print("=" * 70)

    mosca_results = []
    for asset in crypto_assets:
        res = mosca_agent.analyze(asset)
        mosca_results.append(res)

    print(f"\n[+] MOSCA+ Analysis Complete for all {len(mosca_results)} assets.\n")

    # -------------------------------------------------------------------------
    # STAGE 5: CONSOLIDATED ECDAT EXECUTIVE MASTER SUMMARY REPORT
    # -------------------------------------------------------------------------
    print("=" * 70)
    print("             ECDAT EXECUTIVE CONSOLIDATED MASTER REPORT")
    print("=" * 70 + "\n")

    print(f"{'Asset ID':<10} | {'Algorithm':<15} | {'Category':<12} | {'HNDL Risk':<10} | {'MOSCA Risk':<10} | {'Priority':<10}")
    print("-" * 78)

    for idx, asset in enumerate(crypto_assets):
        aid = asset.get("asset_id", f"T{idx+1:03d}")
        algo = str(asset.get("algorithm") or "Unknown")[:15]
        h_body = hndl_results[idx].get("hndl", {})
        h_risk = str(h_body.get("future_decryption_risk") or "N/A")

        m_body = mosca_results[idx].get("mosca_assessment", {})
        cat = str(m_body.get("algorithm_category") or "UNKNOWN")[:12]
        m_risk = str(m_body.get("overall_risk") or "N/A")
        prio = str(m_body.get("migration_priority") or "N/A")

        print(f"{aid:<10} | {algo:<15} | {cat:<12} | {h_risk:<10} | {m_risk:<10} | {prio:<10}")

    print("-" * 78 + "\n")
    print("[+] All 4 Pipeline Stages Executed Successfully!")
    print("=" * 70 + "\n")


class TestFullECDATPipeline(unittest.TestCase):
    def test_full_pipeline_execution(self):
        cbom_agent = CBOMAgent()
        risk_agent = RiskClassificationAgent()
        hndl_agent = HNDLAgent()
        mosca_agent = MOSCAAgent(verbose=False)

        # 1. CBOM
        cbom = cbom_agent.process(SAMPLE_RAW_FINDINGS_PAYLOAD)
        assets = cbom["crypto_assets"]
        self.assertEqual(len(assets), 10)

        # 2. Risk Agent
        risk_ctx = risk_agent.analyze(SAMPLE_RAW_SYSTEM_CONTEXT)
        self.assertEqual(risk_ctx["data_context"]["sensitivity"], "CRITICAL")
        self.assertEqual(risk_ctx["data_context"]["data_lifetime_years"], 20)

        # 3. HNDL & MOSCA
        for asset in assets:
            h_res = hndl_agent.analyze(cbom_asset=asset, risk_context=risk_ctx)
            self.assertIn("hndl", h_res)
            self.assertEqual(h_res["asset_id"], asset["asset_id"])

            m_res = mosca_agent.analyze(asset)
            self.assertIn("mosca_assessment", m_res)
            self.assertEqual(m_res["asset_id"], asset["asset_id"])


if __name__ == "__main__":
    run_full_ecdat_pipeline()
    unittest.main()
