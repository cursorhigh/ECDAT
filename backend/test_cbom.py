"""
Standalone Integration & Unit Test Suite for CBOM Module

Tests the complete CBOM processing pipeline independently of the Discovery module.
Processes mock discovery findings, runs deterministic rule extraction, AI provider abstraction,
validates quality, builds the final CBOM document, prints it to stdout, and exports to a JSON file.
"""

import os
import json
import unittest
from segments.ml.cbom import (
    CBOMAgent,
    CBOMBuilder,
    CBOMValidator,
    DeterministicExtractor,
    BaseLLMProvider,
    FallbackLLMProvider,
    GeminiLLMProvider,
    clean_and_validate_llm_json,
    CBOM_EXTRACTION_SYSTEM_PROMPT,
)

# Mock Discovery Findings payload simulating Discovery module output
MOCK_DISCOVERY_FINDINGS = {
    "repository": {
        "name": "enterprise-auth-service",
        "url": "https://github.com/example/enterprise-auth-service",
    },
    "findings": [
        {
            "id": "F001",
            "file": "src/auth/rsa_provider.py",
            "line": 24,
            "detected": "RSA",
            "code": "rsa.generate_private_key(key_size=2048, public_exponent=65537)",
        },
        {
            "id": "F002",
            "file": "src/crypto/aes_cipher.py",
            "line": 58,
            "detected": "AES-GCM",
            "code": "Cipher(algorithms.AES(key), modes.GCM(nonce))",
        },
        {
            "id": "F003",
            "file": "src/utils/hash_util.py",
            "line": 12,
            "detected": "SHA-256",
            "code": "hashlib.sha256(data).hexdigest()",
        },
        {
            "id": "F004",
            "file": "src/auth/ecdsa_signer.py",
            "line": 89,
            "detected": "ECDSA",
            "code": "ec.generate_private_key(ec.SECP256R1())",
        },
        {
            "id": "F005",
            "file": "src/network/tls_client.py",
            "line": 105,
            "detected": "OpenSSL TLS",
            "code": "ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)",
        },
        {
            "id": "F006",
            "file": "src/legacy/unknown_handler.py",
            "line": None,
            "detected": "CustomCryptoRef",
            "code": None,
        },
    ],
}


class MockLLMProvider(BaseLLMProvider):
    def __init__(self):
        self.call_count = 0

    def extract_metadata(self, finding, deterministic_results):
        self.call_count += 1
        if finding.get("id") == "F001":
            return clean_and_validate_llm_json(
                json.dumps(
                    {
                        "asset_type": "algorithm",
                        "algorithm": "RSA",
                        "family": "asymmetric",
                        "parameters": {"key_size": 2048},
                        "purpose": "digital_signature",
                        "implementation": "cryptography.hazmat.primitives.asymmetric.rsa",
                        "confidence": 0.95,
                    }
                )
            )
        return clean_and_validate_llm_json("")


class TestCBOMIntegration(unittest.TestCase):
    def setUp(self):
        self.agent = CBOMAgent(llm_provider=FallbackLLMProvider())
        self.builder = CBOMBuilder()
        self.validator = CBOMValidator()
        self.extractor = DeterministicExtractor()

    def test_full_cbom_integration_pipeline(self):
        output_file = "cbom_output.json"
        cbom_doc = self.agent.generate_cbom(
            MOCK_DISCOVERY_FINDINGS, output_filepath=output_file
        )

        # 1. Verify Document Envelope
        self.assertEqual(cbom_doc["format"], "ECDAT-CBOM")
        self.assertEqual(cbom_doc["version"], "1.0")
        self.assertIn("generated_at", cbom_doc)

        # 2. Verify Repository Metadata
        self.assertEqual(
            cbom_doc["repository"]["name"], "enterprise-auth-service"
        )

        # 3. Verify Summary Statistics
        summary = cbom_doc["summary"]
        self.assertEqual(summary["total_assets"], 6)
        self.assertEqual(summary["confirmed_assets"], 5)
        self.assertEqual(summary["partial_assets"], 1)

        # 4. Verify Individual Asset Extraction & Validation
        assets = cbom_doc["crypto_assets"]

        # RSA 2048
        rsa = assets[0]
        self.assertEqual(rsa["asset_id"], "F001")
        self.assertEqual(rsa["algorithm"], "RSA")
        self.assertEqual(rsa["family"], "asymmetric")
        self.assertEqual(rsa["parameters"]["key_size"], 2048)
        self.assertEqual(rsa["validation_status"], "confirmed")

        # AES-GCM
        aes = assets[1]
        self.assertEqual(aes["asset_id"], "F002")
        self.assertEqual(aes["algorithm"], "AES-GCM")
        self.assertEqual(aes["family"], "symmetric")
        self.assertEqual(aes["parameters"]["mode"], "GCM")
        self.assertEqual(aes["validation_status"], "confirmed")

        # SHA-256
        sha = assets[2]
        self.assertEqual(sha["asset_id"], "F003")
        self.assertEqual(sha["algorithm"], "SHA-256")
        self.assertEqual(sha["family"], "hash")
        self.assertEqual(sha["validation_status"], "confirmed")

        # ECDSA / ECC
        ecdsa = assets[3]
        self.assertEqual(ecdsa["asset_id"], "F004")
        self.assertEqual(ecdsa["algorithm"], "ECDSA")
        self.assertEqual(ecdsa["family"], "asymmetric")
        self.assertEqual(ecdsa["parameters"]["curve"], "SECP256R1")
        self.assertEqual(ecdsa["validation_status"], "confirmed")

        # OpenSSL / TLS
        tls = assets[4]
        self.assertEqual(tls["asset_id"], "F005")
        self.assertEqual(tls["algorithm"], "OpenSSL TLS")
        self.assertEqual(tls["family"], "protocol")
        self.assertEqual(tls["validation_status"], "confirmed")

        # 5. Verify File Export
        self.assertTrue(os.path.exists(output_file))

    def test_validator_and_ai_mock_pipeline(self):
        mock_provider = MockLLMProvider()
        agent = CBOMAgent(llm_provider=mock_provider)
        cbom_doc = agent.process(MOCK_DISCOVERY_FINDINGS)

        is_valid, errors = self.validator.validate(cbom_doc)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)


def run_integration_and_print():
    agent = CBOMAgent(llm_provider=FallbackLLMProvider())
    output_filename = "cbom_output.json"

    # Step 1-5: Process, validate, build, and save CBOM
    cbom_result = agent.generate_cbom(
        MOCK_DISCOVERY_FINDINGS, output_filepath=output_filename
    )

    print("\n" + "=" * 65)
    print("STANDALONE CBOM INTEGRATION TEST OUTPUT:")
    print("=" * 65)
    print(json.dumps(cbom_result, indent=2))
    print("=" * 65)
    print(f"--> Saved CBOM JSON file to: {os.path.abspath(output_filename)}\n")


if __name__ == "__main__":
    run_integration_and_print()
    unittest.main()
