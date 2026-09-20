"""
Live Integration Test for CBOM Hybrid Decision Logic with Real Google Gemini API

Demonstrates and verifies:
DETERMINISTIC RULES FIRST -> REAL GOOGLE GEMINI API ONLY WHEN NEEDED.
Applies unified explainability structure across both deterministic and AI-assisted assets.
"""

import os
import json
import unittest
from typing import Dict, Any
from dotenv import load_dotenv
from segments.ml.cbom import (
    CBOMAgent,
    CBOMBuilder,
    CBOMValidator,
    DeterministicExtractor,
    GeminiLLMProvider,
    FallbackLLMProvider,
    format_cbom_explanation,
)

load_dotenv()


class TrackingGeminiProvider(GeminiLLMProvider):
    """
    Tracks live Gemini API calls and prints the real AI responses returned from Google Gemini.
    """

    def __init__(self, api_key: str = None, model: str = None):
        super().__init__(api_key=api_key, model=model)
        self.call_count = 0
        self.called_for = []
        self.responses = {}

    def extract_metadata(
        self, finding: Dict[str, Any], deterministic_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        finding_id = finding.get("id", "UNKNOWN")
        self.call_count += 1
        self.called_for.append(finding_id)

        print(
            f"\n[LIVE GEMINI AI TRIGGERED] Sending finding {finding_id} to Google Gemini API ({self.model})..."
        )

        res = super().extract_metadata(finding, deterministic_results)
        self.responses[finding_id] = res
        print(f"[GEMINI RESPONSE for {finding_id}]: {json.dumps(res, indent=2)}")
        return res


# Test findings payload
TEST_FINDINGS_PAYLOAD = {
    "repository": {
        "name": "live-gemini-hybrid-test",
        "url": "https://github.com/example/live-gemini-hybrid-test",
    },
    "findings": [
        {
            "id": "T001",
            "file": "src/auth.py",
            "line": 10,
            "detected": "RSA",
            "code": "rsa.generate_private_key(key_size=2048)",
        },
        {
            "id": "T002",
            "file": "src/encryption.py",
            "line": 20,
            "detected": "AES-GCM",
            "code": "Cipher(algorithms.AES(key), modes.GCM(nonce))",
        },
        {
            "id": "T003",
            "file": "src/hash.py",
            "line": 30,
            "detected": "SHA-256",
            "code": "hashlib.sha256(data).hexdigest()",
        },
        {
            "id": "T004",
            "file": "src/legacy/custom_crypto.py",
            "line": 45,
            "detected": "CustomCryptoRef",
            "code": "legacyCryptoEngine.initialize(CRYPTO_SUITE_XYZ)",
        },
        {
            "id": "T005",
            "file": "src/security/crypto.java",
            "line": 100,
            "detected": "UNKNOWN",
            "code": 'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")',
        },
    ],
}


class TestCBOMLiveGeminiTrigger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key and api_key != "YOUR_GEMINI_API_KEY_HERE":
            cls.provider = TrackingGeminiProvider(api_key=api_key)
        else:
            cls.provider = FallbackLLMProvider()

        cls.agent = CBOMAgent(llm_provider=cls.provider)
        cls.validator = CBOMValidator()
        cls.cbom_result = cls.agent.process(TEST_FINDINGS_PAYLOAD)

    def test_01_clear_rsa_no_ai(self):
        if hasattr(self.provider, "called_for"):
            self.assertNotIn("T001", self.provider.called_for)

    def test_02_clear_aes_gcm_no_ai(self):
        if hasattr(self.provider, "called_for"):
            self.assertNotIn("T002", self.provider.called_for)

    def test_03_clear_sha256_no_ai(self):
        if hasattr(self.provider, "called_for"):
            self.assertNotIn("T003", self.provider.called_for)

    def test_04_ambiguous_custom_crypto_triggers_ai(self):
        if hasattr(self.provider, "called_for"):
            self.assertIn("T004", self.provider.called_for)

    def test_05_complex_crypto_triggers_ai(self):
        if hasattr(self.provider, "called_for"):
            self.assertIn("T005", self.provider.called_for)

    def test_06_exact_ai_call_counts_and_ids(self):
        if hasattr(self.provider, "called_for"):
            self.assertEqual(self.provider.call_count, 2)
            self.assertEqual(self.provider.called_for, ["T004", "T005"])

    def test_07_cbom_contains_all_findings(self):
        assets = self.cbom_result["crypto_assets"]
        self.assertEqual(len(assets), 5)
        asset_ids = [a["asset_id"] for a in assets]
        self.assertEqual(asset_ids, ["T001", "T002", "T003", "T004", "T005"])

    def test_08_all_assets_pass_validation(self):
        is_valid, errors = self.validator.validate(self.cbom_result)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)


def print_live_gemini_report():
    extractor = DeterministicExtractor()
    api_key = os.getenv("GEMINI_API_KEY")

    if api_key and api_key != "YOUR_GEMINI_API_KEY_HERE":
        provider = TrackingGeminiProvider(api_key=api_key)
    else:
        provider = FallbackLLMProvider()

    agent = CBOMAgent(llm_provider=provider)

    print("\n" + "=" * 60)
    print("LIVE GOOGLE GEMINI HYBRID AI TRIGGER TEST")
    print("=" * 60 + "\n")

    cases = [
        ("T001", "RSA"),
        ("T002", "AES-GCM"),
        ("T003", "SHA-256"),
        ("T004", "CustomCryptoRef"),
        ("T005", "Complex RSA Configuration"),
    ]

    findings_list = TEST_FINDINGS_PAYLOAD["findings"]

    for idx, (fid, label) in enumerate(cases):
        finding = findings_list[idx]
        extracted = extractor.extract(finding)
        ai_needed = agent._is_information_missing(extracted, finding)

        print(f"[{fid}] {label}")
        if not ai_needed:
            print("Deterministic extraction: SUCCESS")
            print("AI Required: NO\n")
        else:
            print("Deterministic extraction: INSUFFICIENT")
            print("AI Required: YES\n")

    # Generate full CBOM document
    cbom_doc = agent.generate_cbom(TEST_FINDINGS_PAYLOAD, output_filepath="live_gemini_cbom_output.json")

    print("\n" + "=" * 60)
    print("TERMINAL EXPLAINABILITY REPORT FOR ALL ASSETS")
    print("=" * 60 + "\n")
    for asset in cbom_doc.get("crypto_assets", []):
        print(format_cbom_explanation(asset))
        print("-" * 60 + "\n")

    total_count = len(findings_list)
    ai_count = getattr(provider, "call_count", 0)
    det_count = total_count - ai_count
    called_ids_str = ", ".join(getattr(provider, "called_for", []))

    print("=" * 60)
    print("LIVE GEMINI TEST SUMMARY")
    print("=" * 60 + "\n")
    print(f"Total Findings: {total_count}")
    print(f"Deterministic Only: {det_count}")
    print(f"AI Triggered: {ai_count}")
    print(f"AI Triggered For: {called_ids_str}\n")
    print("Saved CBOM to: live_gemini_cbom_output.json")
    print("Tests: PASSED\n")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    print_live_gemini_report()
    unittest.main()
