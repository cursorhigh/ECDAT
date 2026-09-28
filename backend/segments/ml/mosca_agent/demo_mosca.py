"""
MOSCA+ Theorem (X + Y > Z) Demonstration Script

Executes multi-asset MOSCA+ analysis across RSA-2048, ECC P-256, AES-256-GCM, 3DES,
and Post-Quantum ML-KEM-768 demonstrating deterministic mathematical solving,
timeline deficits, migration start deadlines, and urgency classification.
"""

import sys
import os
import json

# Ensure backend root is in python path
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from segments.ml.mosca_agent import MOSCAAgent, format_mosca_terminal_report

DEMO_ASSETS = [
    {
        "asset_id": "crypto-rsa-2048-001",
        "algorithm": "RSA-2048",
        "family": "rsa",
        "crypto_role": "key_exchange",
        "parameters": {"key_size": 2048},
        "operational_context": {
            "migration_complexity": 4,  # High complexity -> derived X ~ 3.5+ yrs
            "crypto_agility": 2,        # Low agility
            "data_lifetime_years": 8.0, # Long shelf life Y
            "data_sensitivity": 4,      # High sensitivity
            "business_criticality": 4,
        },
    },
    {
        "asset_id": "crypto-ecdsa-p256-002",
        "algorithm": "ECDSA",
        "family": "ecc",
        "crypto_role": "signature",
        "parameters": {"curve": "P-256"},
        "operational_context": {
            "migration_complexity": 3,
            "crypto_agility": 3,
            "data_lifetime_years": 3.0,
            "data_sensitivity": 3,
            "business_criticality": 3,
        },
    },
    {
        "asset_id": "crypto-aes-256-gcm-003",
        "algorithm": "AES-256-GCM",
        "family": "aes",
        "crypto_role": "encryption",
        "parameters": {"key_size": 256, "mode": "GCM"},
        "operational_context": {
            "migration_complexity": 2,
            "crypto_agility": 4,
            "data_lifetime_years": 10.0,
            "data_sensitivity": 5,
            "business_criticality": 5,
        },
    },
    {
        "asset_id": "crypto-3des-cbc-004",
        "algorithm": "3DES-CBC",
        "family": "des",
        "crypto_role": "encryption",
        "parameters": {"key_size": 168, "mode": "CBC"},
        "operational_context": {
            "migration_complexity": 5,
            "crypto_agility": 1,
            "data_lifetime_years": 5.0,
            "data_sensitivity": 4,
            "business_criticality": 4,
        },
    },
    {
        "asset_id": "crypto-mlkem-768-005",
        "algorithm": "ML-KEM-768",
        "family": "pqc",
        "crypto_role": "key_exchange",
        "parameters": {"claim": "NIST FIPS 203 (ML-KEM)"},
        "operational_context": {
            "migration_complexity": 1,
            "crypto_agility": 5,
            "data_lifetime_years": 15.0,
            "data_sensitivity": 5,
            "business_criticality": 5,
        },
    },
]


def run_mosca_demonstration():
    print("\n" + "=" * 65)
    print("ECDAT MOSCA+ THEOREM (X + Y > Z) AGENTIC DEMONSTRATION")
    print("=" * 65 + "\n")

    agent = MOSCAAgent(default_quantum_horizon_year=2033, default_assessment_year=2026)

    for asset in DEMO_ASSETS:
        ctx = asset.get("operational_context", {})
        result = agent.analyze(cbom_asset=asset, operational_context=ctx)
        print(format_mosca_terminal_report(cbom_asset=asset, mosca_result=result))
        print("\n")


if __name__ == "__main__":
    run_mosca_demonstration()

