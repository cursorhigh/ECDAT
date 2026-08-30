"""
Live AI Explainability Demonstration Script for ECDAT CBOM

Demonstrates real Google Gemini AI execution when deterministic extraction is insufficient.
Extracts cryptographic metadata and generates field-level evidence & explainability provenance.
"""

import os
import json
from dotenv import load_dotenv
from cbom import (
    CBOMAgent,
    GeminiLLMProvider,
    format_cbom_explanation,
)

load_dotenv()

# Ambiguous finding where deterministic extraction is insufficient, triggering Gemini AI
AMBIGUOUS_FINDING_PAYLOAD = {
    "repository": {
        "name": "enterprise-custom-crypto-service",
        "url": "https://github.com/example/enterprise-custom-crypto-service",
    },
    "findings": [
        {
            "id": "AI_DEMO_001",
            "file": "src/security/legacy_cipher.java",
            "line": 142,
            "detected": "UNKNOWN CRYPTOGRAPHIC ASSET",
            "code": 'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));',
        },
        {
            "id": "AI_DEMO_002",
            "file": "src/auth/token_verifier.go",
            "line": 88,
            "detected": "CustomSignatureSuite",
            "code": 'signer, err := ecdsa.SignASN1(rand.Reader, privateKey, hashedSHA384[:])',
        }
    ],
}


def run_ai_demonstration():
    api_key = os.getenv("GEMINI_API_KEY")
    print(f"Loaded GEMINI_API_KEY: {api_key[:10]}..." if api_key else "NO GEMINI_API_KEY FOUND!")

    print("\n" + "=" * 60)
    print("STARTING AI-ASSISTED CBOM EXPLAINABILITY DEMONSTRATION")
    print("=" * 60)

    # Instantiate CBOMAgent with explicit Gemini LLM Provider
    gemini_provider = GeminiLLMProvider(api_key=api_key)
    agent = CBOMAgent(llm_provider=gemini_provider)

    # Process finding payload through CBOM agent pipeline
    print("\n--> Processing findings through CBOM Agent pipeline...")
    cbom_doc = agent.process(AMBIGUOUS_FINDING_PAYLOAD)

    print("\n" + "=" * 60)
    print("GENERATED CBOM DOCUMENT (JSON OUTPUT)")
    print("=" * 60)
    print(json.dumps(cbom_doc, indent=2))

    print("\n" + "=" * 60)
    print("HUMAN-READABLE CBOM EXPLANATIONS FOR AI-EXTRACTED ASSETS")
    print("=" * 60)
    for asset in cbom_doc.get("crypto_assets", []):
        print(format_cbom_explanation(asset))
        print("-" * 60)


if __name__ == "__main__":
    run_ai_demonstration()
