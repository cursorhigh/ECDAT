"""
Comprehensive Test Suite for CycloneDX 1.6 CBOM Module (test_cbom_cyclonedx.py)

Validates:
1. Canonical algorithm catalog lookups (RSA, AES, SHA, ECC/ECDSA, PQC ML-KEM/ML-DSA, TLS)
2. Deterministic parameter extraction (key sizes, modes, padding, curves, protocols, libraries)
3. CycloneDX 1.6 schema compliance and structure
4. Cryptographic sanity and validator quality gates (valid, partial, needs_review, invalid)
5. Evidence provenance and explainability attribution
6. AI fallback invocation for ambiguous cases
7. End-to-end CBOM generation and export
"""

import json
import unittest
from pathlib import Path
from segments.ml.cbom import (
    CBOMAgent,
    CBOMBuilder,
    CBOMValidator,
    DeterministicExtractor,
    lookup_crypto_algorithm,
    canonicalize_algorithm_name,
    is_quantum_vulnerable,
    get_nist_quantum_level,
    get_classical_security_level,
    format_cbom_explanation,
    BaseLLMProvider,
    clean_and_validate_llm_json,
)


class MockDisambiguationLLM(BaseLLMProvider):
    """Mock LLM provider to test AI fallback path."""
    def __init__(self):
        self.call_count = 0

    def extract_metadata(self, finding, deterministic_results):
        self.call_count += 1
        return clean_and_validate_llm_json(
            json.dumps({
                "asset_type": "algorithm",
                "algorithm": "ChaCha20-Poly1305",
                "family": "symmetric",
                "purpose": "authenticated_encryption",
                "confidence": 0.88,
            })
        )


class TestCycloneDXCBOM(unittest.TestCase):

    def setUp(self):
        self.agent = CBOMAgent()
        self.builder = CBOMBuilder()
        self.validator = CBOMValidator()
        self.extractor = DeterministicExtractor()

    # -------------------------------------------------------------------------
    # 1. Crypto Catalog & Properties Tests
    # -------------------------------------------------------------------------
    def test_crypto_catalog_rsa(self):
        entry_2048 = lookup_crypto_algorithm("RSA", key_size=2048)
        self.assertIsNotNone(entry_2048)
        self.assertEqual(entry_2048["canonical_name"], "RSA-2048")
        self.assertEqual(entry_2048["family"], "asymmetric")
        self.assertEqual(entry_2048["classical_security_bits_est"], 112)
        self.assertEqual(entry_2048["nist_security_category"], 0)
        self.assertTrue(entry_2048["quantum_vulnerable"])
        self.assertEqual(entry_2048["quantum_attack_type"], "Shor")

        entry_4096 = lookup_crypto_algorithm("RSA-4096")
        self.assertEqual(entry_4096["canonical_name"], "RSA-4096")
        self.assertEqual(entry_4096["classical_security_bits_est"], 152)

    def test_crypto_catalog_aes(self):
        entry_gcm = lookup_crypto_algorithm("AES-256", mode="GCM")
        self.assertIsNotNone(entry_gcm)
        self.assertEqual(entry_gcm["canonical_name"], "AES-256")
        self.assertEqual(entry_gcm["family"], "symmetric")
        self.assertEqual(entry_gcm["nist_security_category"], 5)
        self.assertFalse(entry_gcm["quantum_vulnerable"])
        self.assertEqual(entry_gcm["quantum_attack_type"], "Grover")

    def test_crypto_catalog_ecc_ecdsa(self):
        entry_p256 = lookup_crypto_algorithm("ECDSA", curve="secp256r1")
        self.assertIsNotNone(entry_p256)
        self.assertEqual(entry_p256["canonical_name"], "ECDSA-P256")
        self.assertTrue(entry_p256["quantum_vulnerable"])
        self.assertEqual(entry_p256["quantum_attack_type"], "Shor")

        entry_ed25519 = lookup_crypto_algorithm("Ed25519")
        self.assertIsNotNone(entry_ed25519)
        self.assertEqual(entry_ed25519["canonical_name"], "Ed25519")
        self.assertTrue(entry_ed25519["quantum_vulnerable"])

    def test_crypto_catalog_pqc(self):
        entry_kem = lookup_crypto_algorithm("ML-KEM-768")
        self.assertIsNotNone(entry_kem)
        self.assertEqual(entry_kem["family"], "pqc")
        self.assertEqual(entry_kem["nist_security_category"], 3)
        self.assertFalse(entry_kem["quantum_vulnerable"])

        entry_dsa = lookup_crypto_algorithm("ML-DSA-65")
        self.assertIsNotNone(entry_dsa)
        self.assertEqual(entry_dsa["family"], "pqc")
        self.assertFalse(entry_dsa["quantum_vulnerable"])

    def test_deprecated_algorithms(self):
        for weak in ["DES", "3DES-112", "MD5", "SHA-1", "RSA-1024", "RC4"]:
            entry = lookup_crypto_algorithm(weak)
            self.assertIsNotNone(entry, f"Expected catalog entry for {weak}")
            self.assertTrue(entry["deprecated_or_disallowed"], f"{weak} should be deprecated")

    # -------------------------------------------------------------------------
    # 2. Deterministic Extractor Tests
    # -------------------------------------------------------------------------
    def test_extractor_rsa_oaep(self):
        finding = {
            "id": "F_RSA",
            "file": "auth/rsa.py",
            "line": 42,
            "detected": "RSA",
            "code": "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048); padding.OAEP()",
        }
        res = self.extractor.extract(finding)
        self.assertEqual(res["algorithm"], "RSA-2048")
        self.assertEqual(res["family"], "asymmetric")
        self.assertEqual(res["key_size"], 2048)
        self.assertEqual(res["padding"], "OAEP")
        self.assertTrue(res["quantum_vulnerable"])
        self.assertEqual(res["detection_method"], "deterministic")

    def test_extractor_aes_gcm(self):
        finding = {
            "id": "F_AES",
            "file": "crypto/cipher.py",
            "line": 10,
            "detected": "AES",
            "code": "cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))",
        }
        res = self.extractor.extract(finding)
        self.assertEqual(res["family"], "symmetric")
        self.assertEqual(res["mode"], "GCM")
        self.assertEqual(res["key_size"], 256)
        self.assertFalse(res["quantum_vulnerable"])

    def test_extractor_sha256(self):
        finding = {
            "id": "F_SHA",
            "file": "utils/hashing.py",
            "line": 15,
            "detected": "SHA-256",
            "code": "digest = hashlib.sha256(payload).hexdigest()",
        }
        res = self.extractor.extract(finding)
        self.assertEqual(res["algorithm"], "SHA-256")
        self.assertEqual(res["family"], "hash")
        self.assertEqual(res["nist_quantum_level"], 2)

    def test_extractor_pqc_mlkem(self):
        finding = {
            "id": "F_PQC",
            "file": "pqc/kem.py",
            "line": 33,
            "detected": "ML-KEM-768",
            "code": "kem_client = oqs.KeyEncapsulation('Kyber768')",
        }
        res = self.extractor.extract(finding)
        self.assertEqual(res["algorithm"], "ML-KEM-768")
        self.assertEqual(res["family"], "pqc")
        self.assertFalse(res["quantum_vulnerable"])

    def test_extractor_tls_protocol(self):
        finding = {
            "id": "F_TLS",
            "file": "net/ssl_client.py",
            "line": 100,
            "detected": "OpenSSL TLS",
            "code": "context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)",
        }
        res = self.extractor.extract(finding)
        self.assertEqual(res["family"], "protocol")
        self.assertEqual(res["protocol"], "TLS 1.2")

    # -------------------------------------------------------------------------
    # 3. CycloneDX 1.6 BOM Structure & Generation Tests
    # -------------------------------------------------------------------------
    def test_cyclonedx_1_6_generation(self):
        payload = {
            "repository": {"name": "enterprise-auth", "url": "https://github.com/org/auth"},
            "findings": [
                {
                    "id": "F1",
                    "file": "src/auth.py",
                    "line": 12,
                    "detected": "RSA-2048",
                    "code": "rsa.generate_private_key(key_size=2048)",
                },
                {
                    "id": "F2",
                    "file": "src/cipher.py",
                    "line": 50,
                    "detected": "AES-256-GCM",
                    "code": "Cipher(algorithms.AES(key), modes.GCM(nonce))",
                },
            ],
        }
        cbom_doc = self.agent.process(payload)
        self.assertEqual(cbom_doc["format"], "ECDAT-CBOM")
        self.assertEqual(cbom_doc["summary"]["total_assets"], 2)

        cdx = cbom_doc["cyclonedx_bom"]
        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertEqual(cdx["specVersion"], "1.6")
        self.assertTrue(cdx["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(len(cdx["components"]), 2)

        comp1 = cdx["components"][0]
        self.assertEqual(comp1["type"], "cryptographic-asset")
        self.assertEqual(comp1["name"], "RSA-2048")
        self.assertEqual(comp1["cryptoProperties"]["assetType"], "algorithm")
        self.assertEqual(comp1["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"], "2048")
        self.assertEqual(comp1["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"], 112)
        self.assertEqual(comp1["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"], 0)
        self.assertEqual(comp1["evidence"]["occurrences"][0]["location"], "src/auth.py")
        self.assertEqual(comp1["evidence"]["occurrences"][0]["line"], 12)

        # Validate CycloneDX structure
        is_valid, errors = self.validator.validate_cyclonedx_bom(cdx)
        self.assertTrue(is_valid, f"CycloneDX validation errors: {errors}")

    # -------------------------------------------------------------------------
    # 4. Validation Gate & Quality Sanity Tests
    # -------------------------------------------------------------------------
    def test_validator_confirmed_asset(self):
        asset = {
            "asset_id": "A1",
            "asset_type": "algorithm",
            "algorithm": "AES-256",
            "family": "symmetric",
            "parameters": {"key_size": 256, "mode": "GCM"},
            "location": {"file": "cipher.py", "line": 10},
            "evidence": "AES.new(key, AES.MODE_GCM)",
            "confidence": 0.95,
        }
        validated = self.validator.validate_asset(asset)
        self.assertEqual(validated["validation_status"], "confirmed")

    def test_validator_invalid_key_size_flagged(self):
        asset = {
            "asset_id": "A2",
            "asset_type": "algorithm",
            "algorithm": "AES-512",
            "family": "symmetric",
            "parameters": {"key_size": 512, "mode": "GCM"},
            "location": {"file": "bad.py", "line": 5},
            "evidence": "AES.new(512)",
            "confidence": 0.5,
        }
        validated = self.validator.validate_asset(asset)
        self.assertEqual(validated["validation_status"], "needs_review")
        self.assertTrue(any("Invalid AES key size" in iss for iss in validated["validation_issues"]))

    def test_validator_incompatible_mode_on_rsa(self):
        asset = {
            "asset_id": "A3",
            "asset_type": "algorithm",
            "algorithm": "RSA-2048",
            "family": "asymmetric",
            "parameters": {"key_size": 2048, "mode": "GCM"},
            "location": {"file": "rsa.py", "line": 8},
            "evidence": "rsa_with_gcm()",
            "confidence": 0.6,
        }
        validated = self.validator.validate_asset(asset)
        self.assertEqual(validated["validation_status"], "needs_review")
        self.assertTrue(any("Cipher mode GCM is not applicable to asymmetric RSA" in iss for iss in validated["validation_issues"]))

    def test_validator_missing_location_marked_invalid(self):
        asset = {
            "asset_id": "A4",
            "asset_type": "algorithm",
            "algorithm": "RSA-2048",
            "family": "asymmetric",
            "location": {},
            "evidence": None,
        }
        validated = self.validator.validate_asset(asset)
        self.assertEqual(validated["validation_status"], "invalid")

    # -------------------------------------------------------------------------
    # 5. AI Fallback Provenance & Explainability Tests
    # -------------------------------------------------------------------------
    def test_ai_fallback_provenance(self):
        mock_llm = MockDisambiguationLLM()
        agent = CBOMAgent(llm_provider=mock_llm)

        finding = {
            "id": "F_AMBIGUOUS",
            "file": "src/opaque_crypto.py",
            "line": 99,
            "detected": "UNKNOWN CRYPTOGRAPHIC ASSET",
            "code": "custom_crypt_wrapper(algo_ref, payload)",
        }
        cbom = agent.process({"findings": [finding]})
        self.assertEqual(mock_llm.call_count, 1)

        asset = cbom["crypto_assets"][0]
        self.assertEqual(asset["explainability"]["detection_method"], "llm")
        self.assertTrue(asset["explainability"]["ai_used"])

    def test_format_cbom_explanation(self):
        finding = {
            "id": "F_EXP",
            "file": "src/auth.py",
            "line": 20,
            "detected": "RSA",
            "code": "rsa.generate_private_key(key_size=2048)",
        }
        cbom = self.agent.process({"findings": [finding]})
        explanation_str = format_cbom_explanation(cbom["crypto_assets"][0])
        self.assertIn("[F_EXP]", explanation_str)
        self.assertIn("Detection Method: DETERMINISTIC", explanation_str)
        self.assertIn("AI Used: NO", explanation_str)
        self.assertIn("rsa.generate_private_key", explanation_str)


if __name__ == "__main__":
    unittest.main()
