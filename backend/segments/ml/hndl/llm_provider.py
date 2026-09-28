"""
HNDL Module LLM Provider Architecture

Defines Abstract Provider interface, Google Gemini API implementation with model cascade fallback,
JSON cleaning/normalization, and deterministic Fallback LLM Provider for offline testing.
"""

import os
import re
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from .prompts import build_hndl_prompt

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)


def clean_and_validate_hndl_json(
    raw_text: str, fallback_asset_id: str, fallback_lifetime: int
) -> Dict[str, Any]:
    """
    Cleans raw LLM response text by stripping Markdown code fences (```json ... ```)
    and parses JSON into a normalized HNDL assessment dictionary.
    """
    default_schema = {
        "asset_id": fallback_asset_id,
        "hndl": {
            "applicable": False,
            "harvestability": "LOW",
            "future_decryption_risk": "LOW",
            "data_lifetime_years": fallback_lifetime,
            "quantum_vulnerable": None,
            "reason": "Analysis payload fallback due to missing or invalid LLM response.",
        },
    }

    if not raw_text or not isinstance(raw_text, str):
        return default_schema

    # Strip markdown code blocks
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()

    try:
        data = json.loads(cleaned)
        if not isinstance(data, dict):
            return default_schema
    except Exception as e:
        logger.debug(f"Malformed HNDL JSON response: {type(e).__name__}. Returning default schema.")
        return default_schema

    # Ensure asset_id exists and matches
    if not data.get("asset_id"):
        data["asset_id"] = fallback_asset_id

    hndl = data.get("hndl")
    if not isinstance(hndl, dict):
        data["hndl"] = default_schema["hndl"]
    else:
        hndl["data_lifetime_years"] = fallback_lifetime

    return data


class HNDLLLMProvider(ABC):
    """
    Abstract Base Class for HNDL Risk Assessment LLM Providers.
    """

    @abstractmethod
    def analyze_hndl(
        self, cbom_asset: Dict[str, Any], risk_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyzes a CBOM asset and Risk Context to produce a structured HNDL threat assessment.

        :param cbom_asset: Input 1 dictionary.
        :param risk_context: Input 2 dictionary.
        :return: Structured HNDL response dictionary.
        """
        pass


class FallbackHNDLProvider(HNDLLLMProvider):
    """
    Fallback HNDL Provider used for offline development, testing, or missing API keys.
    Evaluates HNDL threats deterministically using rule heuristics.
    """

    def analyze_hndl(
        self, cbom_asset: Dict[str, Any], risk_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        asset_id = str(cbom_asset.get("asset_id") or "unknown-asset")

        # Extract algorithm details safely
        algo_obj = cbom_asset.get("algorithm") or {}
        if isinstance(algo_obj, dict):
            family = str(algo_obj.get("family") or "").upper()
            name = str(algo_obj.get("name") or "").upper()
        else:
            family = str(algo_obj).upper()
            name = str(algo_obj).upper()

        purpose_list = cbom_asset.get("purpose", [])
        if isinstance(purpose_list, str):
            purpose_list = [purpose_list]

        # Extract risk context details safely
        data_ctx = risk_context.get("data_context") or {}
        sensitivity = str(data_ctx.get("sensitivity") or "MEDIUM").upper()
        lifetime = int(data_ctx.get("data_lifetime_years") or 0)

        net_ctx = risk_context.get("network_context") or {}
        exposed = bool(net_ctx.get("internet_exposed", False))
        collectable = bool(net_ctx.get("collectable", False))

        # 1. Quantum Vulnerability Evaluation
        if any(f in family or f in name for f in ["RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH"]):
            quantum_vulnerable = True
        elif any(f in family or f in name for f in ["AES", "SHA", "3DES", "HMAC"]):
            quantum_vulnerable = False
        else:
            quantum_vulnerable = None

        # 2. Harvestability Evaluation
        if exposed and collectable:
            harvestability = "HIGH"
        elif collectable or exposed:
            harvestability = "MEDIUM"
        else:
            harvestability = "LOW"

        # 3. Applicability & Future Risk Evaluation
        if quantum_vulnerable is True and harvestability in ("HIGH", "MEDIUM") and lifetime >= 5:
            applicable = True
            future_risk = "HIGH" if sensitivity in ("HIGH", "CRITICAL") else "MEDIUM"
            reason = (
                f"Long-lived {sensitivity.lower()} data ({lifetime} years) protected by quantum-vulnerable "
                f"{family or name} cryptography is collectable in the current network context, creating a significant "
                "Harvest Now, Decrypt Later threat."
            )
        elif quantum_vulnerable is True and harvestability == "LOW":
            applicable = False
            future_risk = "LOW"
            reason = (
                f"Data is protected by quantum-vulnerable {family or name}, but network context indicates "
                "data is not realistically collectable, mitigating HNDL harvestability."
            )
        elif quantum_vulnerable is True and lifetime <= 2:
            applicable = False
            future_risk = "LOW"
            reason = (
                f"Data protected by {family or name} has a short lifespan ({lifetime} year(s)), making future decryption "
                "after a CRQC emerges irrelevant."
            )
        elif quantum_vulnerable is False:
            applicable = False
            future_risk = "LOW"
            reason = (
                f"{family or name} is a symmetric algorithm or hash function that is not vulnerable to classic "
                "CRQC public-key break (Shor's algorithm), so traditional HNDL decryption risk does not apply."
            )
        else:
            applicable = False
            future_risk = "LOW"
            reason = (
                f"Insufficient cryptographic metadata for {name or family} to confirm quantum vulnerability with certainty."
            )

        return {
            "asset_id": asset_id,
            "hndl": {
                "applicable": applicable,
                "harvestability": harvestability,
                "future_decryption_risk": future_risk,
                "data_lifetime_years": lifetime,
                "quantum_vulnerable": quantum_vulnerable,
                "reason": reason,
            },
        }


class GeminiHNDLProvider(HNDLLLMProvider):
    """
    Google Gemini LLM Provider implementation for AI-assisted HNDL Threat Assessment.
    Supports model cascade fallback and clean JSON extraction.
    """

    DEFAULT_MODELS = [
        "gemini-3.5-flash-lite",
        "gemini-3.1-flash-lite",
        "gemini-3.6-flash",
    ]

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY_HNDL") or os.getenv("GEMINI_API_KEY")
        user_model = model or os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

        candidate_list = [user_model] + [m for m in self.DEFAULT_MODELS if m != user_model]
        self.candidate_models = []
        for m in candidate_list:
            if m not in self.candidate_models:
                self.candidate_models.append(m)

    def analyze_hndl(
        self, cbom_asset: Dict[str, Any], risk_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        asset_id = str(cbom_asset.get("asset_id") or "unknown-asset")
        data_ctx = risk_context.get("data_context") or {}
        lifetime = int(data_ctx.get("data_lifetime_years") or 0)

        if not self.api_key or self.api_key == "YOUR_GEMINI_API_KEY_HERE":
            logger.warning("GEMINI_API_KEY missing or placeholder. Falling back to FallbackHNDLProvider.")
            return FallbackHNDLProvider().analyze_hndl(cbom_asset, risk_context)

        prompt_text = build_hndl_prompt(cbom_asset, risk_context)

        for model_name in self.candidate_models:
            try:
                raw_text = None
                try:
                    from google import genai
                    from google.genai import types

                    client = genai.Client(api_key=self.api_key)
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt_text,
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            temperature=0.0,
                        ),
                    )
                    raw_text = response.text
                except ImportError:
                    import google.generativeai as genai

                    genai.configure(api_key=self.api_key)
                    model_instance = genai.GenerativeModel(model_name)
                    response = model_instance.generate_content(
                        prompt_text,
                        generation_config={
                            "response_mime_type": "application/json",
                            "temperature": 0.0,
                        },
                    )
                    raw_text = response.text

                if raw_text:
                    return clean_and_validate_hndl_json(raw_text, asset_id, lifetime)
            except Exception as e:
                err_msg = str(e)
                if any(k in err_msg for k in ("429", "RESOURCE_EXHAUSTED", "404", "503", "NOT_FOUND")):
                    logger.debug(f"Gemini HNDL API '{model_name}' hit rate limit: {e}. Retrying fallback...")
                    import time
                    time.sleep(1.0)
                    continue
                else:
                    logger.debug(f"Gemini HNDL API failed for '{model_name}': {e}")
                    continue

        return FallbackHNDLProvider().analyze_hndl(cbom_asset, risk_context)


def get_hndl_provider(provider_type: Optional[str] = None) -> HNDLLLMProvider:
    """
    Factory function to instantiate configured HNDL Provider.
    """
    api_key = os.getenv("GEMINI_API_KEY_HNDL") or os.getenv("GEMINI_API_KEY")
    if provider_type == "gemini" or (api_key and api_key != "YOUR_GEMINI_API_KEY_HERE"):
        return GeminiHNDLProvider()
    return FallbackHNDLProvider()
