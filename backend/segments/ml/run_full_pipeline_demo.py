"""
ECDAT End-to-End Post-Quantum Risk Analysis Demonstration (run_full_pipeline_demo.py)

Demonstrates the complete sequential post-quantum cryptographic risk analysis:
1. Scraped Repository Findings -> CycloneDX 1.6 CBOM Agent (Starting Point)
2. CBOM Assets + Operational Context -> HNDL Timeline Engine (Feature #28 HNDL_exposure)
3. CBOM Assets + Operational Context -> Mosca Inequality Agent (X + Y > Z Solver)
4. CBOM Assets + Context + HNDL_exposure -> CatBoost 37-Feature Quantum Risk Model
5. Aggregated Pillar Results -> Final Combined Result Synthesizer (Google Gemini AI / Fallback)

Usage:
    python segments/ml/run_full_pipeline_demo.py
    python segments/ml/run_full_pipeline_demo.py --export output_report.json
"""

import sys
import os
import json
import argparse

# Ensure backend root is in python path
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from segments.ml.pipeline import ECDATPipeline
from segments.ml.final_combined_result import format_final_terminal_report


# =====================================================================
# 1. Realistic Sample Scraped Repository Findings (Discovery Output)
# =====================================================================
SAMPLE_SCRAPED_FINDINGS = {
  "repository": {
    "name": "enterprise-banking-core",
    "url": "https://github.com/enterprise/banking-core",
    "branch": "main"
  },
  "findings": [
    {
      "id": "DISC-001",
      "file": "src/security/TlsKeyManager.java",
      "line": 42,
      "detected": "RSA-2048",
      "code": "Cipher.getInstance('RSA/ECB/OAEPWithSHA-256AndMGF1Padding')",
      "purpose": "key_establishment",
      "confidence": 0.98
    },
    {
      "id": "DISC-002",
      "file": "src/auth/JwtTokenSigner.java",
      "line": 105,
      "detected": "ECDSA",
      "code": "Signature.getInstance('SHA256withECDSA')",
      "parameters": {
        "curve": "P-256"
      },
      "purpose": "signing",
      "confidence": 0.95
    },
    {
      "id": "DISC-003",
      "file": "src/db/CustomerVaultStorage.java",
      "line": 88,
      "detected": "AES-256-GCM",
      "code": "Cipher.getInstance('AES/GCM/NoPadding')",
      "parameters": {
        "key_size": 256,
        "mode": "GCM"
      },
      "purpose": "encryption",
      "confidence": 0.99
    },
    {
      "id": "DISC-004",
      "file": "src/legacy/LegacyCardStorage.java",
      "line": 12,
      "detected": "3'DES-CBC",
      "code": "Cipher.getInstance('DESede/CBC/PKCS5Padding')",
      "parameters": {
        "key_size": 168,
        "mode": "CBC"
      },
      "purpose": "encryption",
      "confidence": 0.92
    },
    {
      "id": "DISC-005",
      "file": "src/pqc/QuantumSafeChannel.java",
      "line": 34,
      "detected": "ML-KEM-768",
      "code": "MLKEMGenerator.generateSecretKey(768)",
      "parameters": {
        "claim": "NIST FIPS 203"
      },
      "purpose": "key_establishment",
      "confidence": 0.99
    },
    {
      "id": "DISC-006",
      "file": "src/ssh/SshHostKeyManager.java",
      "line": 57,
      "detected": "RSA-3072",
      "code": "KeyPairGenerator.getInstance('RSA')",
      "parameters": {
        "key_size": 3072
      },
      "purpose": "authentication",
      "confidence": 0.97
    },
    {
      "id": "DISC-007",
      "file": "src/firmware/FirmwareSigner.java",
      "line": 76,
      "detected": "RSA-4096",
      "code": "Signature.getInstance('SHA512withRSA')",
      "parameters": {
        "key_size": 4096,
        "hash": "SHA-512"
      },
      "purpose": "signing",
      "confidence": 0.96
    },
    {
      "id": "DISC-008",
      "file": "src/mobile/DeviceAuthenticator.java",
      "line": 119,
      "detected": "Ed25519",
      "code": "Signature.getInstance('Ed25519')",
      "parameters": {
        "key_size": 256
      },
      "purpose": "signing",
      "confidence": 0.98
    },
    {
      "id": "DISC-009",
      "file": "src/backup/BackupEncryptionService.java",
      "line": 63,
      "detected": "AES-128-GCM",
      "code": "Cipher.getInstance('AES/GCM/NoPadding')",
      "parameters": {
        "key_size": 128,
        "mode": "GCM"
      },
      "purpose": "encryption",
      "confidence": 0.99
    },
    {
      "id": "DISC-010",
      "file": "src/tls/HybridKeyExchange.java",
      "line": 91,
      "detected": "X25519+ML-KEM-768",
      "code": "HybridKeyExchange.of(X25519, MLKEM768)",
      "parameters": {
        "classical": "X25519",
        "pqc": "ML-KEM-768",
        "mode": "hybrid",
        "standard": "NIST FIPS 203"
      },
      "purpose": "key_establishment",
      "confidence": 0.97
    }
  ]
}

# =====================================================================
# 2. User Operational & Environmental System Context
# =====================================================================
USER_OPERATIONAL_CONTEXT = {
    "data_lifetime_years": 8.0,         # Data must remain confidential for 8 years (Y)
    "data_sensitivity": 4,              # High sensitivity (customer financial PII)
    "business_criticality": 4,          # High criticality core banking services
    "migration_complexity": 3,          # Moderate software refactoring complexity
    "crypto_agility": 2,                # Low agility (hardcoded configurations)
    "hardware_dependency": False,       # Pure software implementation
    "quantum_horizon_year": 2033,       # Projected CRQC arrival horizon (Z = 2033 - 2026 = 7.0 yrs)
    "assessment_year": 2026,            # Current baseline assessment year
}


def main():
    parser = argparse.ArgumentParser(description="Run full ECDAT ML Post-Quantum Risk Analysis Pipeline")
    parser.add_argument("--export", type=str, help="Export final report JSON to the specified file path")
    parser.add_argument("--force-fallback", action="store_true", help="Force deterministic fallback instead of Gemini API")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("      ECDAT END-TO-END POST-QUANTUM RISK ANALYSIS PIPELINE")
    print("=" * 70)
    print("Initializing 5-stage sequential analysis...")
    print("• Stage 1: CycloneDX 1.6 CBOM Extraction & NIST Catalog Mapping")
    print("• Stage 2: HNDL Engine (Harvestability & Timeline Exposure)")
    print("• Stage 3: Mosca Theorem Agent (X + Y > Z Inequality Solving)")
    print("• Stage 4: CatBoost 37-Feature Quantum Risk Classifier")
    print("• Stage 5: Google Gemini AI Report Synthesis with Grounded Attributions\n")

    pipeline = ECDATPipeline(force_fallback_llm=args.force_fallback)

    print(f"Processing {len(SAMPLE_SCRAPED_FINDINGS['findings'])} scraped discovery findings...")
    final_report = pipeline.execute(
        discovery_input=SAMPLE_SCRAPED_FINDINGS,
        operational_context=USER_OPERATIONAL_CONTEXT,
    )

    # Print human-readable executive terminal display
    terminal_report = format_final_terminal_report(final_report)
    print(terminal_report)

    # Export JSON if requested
    export_path = args.export or "ecdat_final_risk_report.json"
    try:
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=2)
        print(f"\n[+] Full structured report exported to: {os.path.abspath(export_path)}")
    except Exception as e:
        print(f"\n[-] Failed to export JSON: {e}")

    print("\n[+] ECDAT Post-Quantum Pipeline execution completed successfully.\n")


if __name__ == "__main__":
    main()
