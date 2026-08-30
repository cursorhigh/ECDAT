"""
MOSCA+ Agentic Cryptographic Assessment Demonstration Script

Executes multi-asset MOSCA+ analysis across RSA, AES-GCM, SHA-256, ECDSA, and Custom Crypto
demonstrating deterministic cryptographic rule matching, Google Gemini AI contextual evaluation,
and hackathon explainability logging.
"""

import sys
import os
import json

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mosca_agent import MOSCAAgent

DEMO_ASSETS = [
    {
        "asset_id": "crypto-rsa-001",
        "algorithm": {"family": "RSA", "name": "RSA-2048"},
        "parameters": {"key_size": 2048},
        "purpose": ["key_establishment"],
    },
    {
        "asset_id": "crypto-aes-001",
        "algorithm": {"family": "AES", "name": "AES-256-GCM"},
        "parameters": {"key_size": 256, "mode": "GCM"},
        "purpose": ["encryption"],
    },
    {
        "asset_id": "crypto-sha-001",
        "algorithm": {"family": "SHA", "name": "SHA-256"},
        "parameters": {},
        "purpose": ["hashing"],
    },
    {
        "asset_id": "crypto-ecdsa-001",
        "algorithm": {"family": "ECDSA", "name": "ECDSA P-256"},
        "parameters": {"curve": "P-256"},
        "purpose": ["signing"],
    },
    {
        "asset_id": "crypto-custom-001",
        "algorithm": {"family": "UNKNOWN", "name": "CustomCryptoRef"},
        "parameters": {},
        "purpose": ["encryption"],
    },
]


def run_mosca_demonstration():
    print("\n" + "=" * 50)
    print("ECDAT MOSCA+ AGENTIC ASSESSMENT DEMONSTRATION")
    print("=" * 50 + "\n")

    agent = MOSCAAgent(verbose=True)
    summary_results = []

    for asset in DEMO_ASSETS:
        result = agent.analyze(asset)
        assessment = result.get("mosca_assessment", {})
        algo_name = asset["algorithm"]["name"]
        overall_risk = assessment.get("overall_risk", "UNKNOWN")
        summary_results.append((algo_name, overall_risk))

    print("\n" + "=" * 50)
    print("ECDAT MOSCA+ ASSESSMENT SUMMARY")
    print("=" * 50 + "\n")
    print(f"Total Assets Processed: {len(DEMO_ASSETS)}")
    print("Deterministic Analysis: COMPLETE")
    print("AI Contextual Analysis: COMPLETE\n")
    print("Results Summary:")

    for algo_name, overall_risk in summary_results:
        print(f"  * {algo_name:<20} -> {overall_risk}")

    print("\n" + "=" * 50 + "\n")


if __name__ == "__main__":
    run_mosca_demonstration()
