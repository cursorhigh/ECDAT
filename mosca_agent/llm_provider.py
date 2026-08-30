"""
MOSCA+ LLM Provider Architecture

Defines Abstract Provider interface, Google Gemini API implementation with model cascade fallback,
JSON cleaning/normalization, and deterministic Fallback LLM Provider for offline testing.
"""

import os
import re
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from .prompts import build_mosca_prompt

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)


def clean_and_validate_mosca_json(
    raw_text: str, fallback_asset_id: str, det_findings: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Cleans raw LLM response text by stripping Markdown code fences (```json ... ```)
    and parses JSON into a normalized MOSCA+ assessment dictionary.
    """
    default_schema = {
        "asset_id": fallback_asset_id,
        "mosca_assessment": {
            "algorithm_category": det_findings.get("algorithm_category", "UNKNOWN"),
            "classical_security": det_findings.get("classical_baseline", "UNKNOWN"),
            "quantum_vulnerable": det_findings.get("known_quantum_vulnerable"),
            "quantum_migration_risk": "HIGH" if det_findings.get("known_quantum_vulnerable") else "LOW",
            "overall_risk": "HIGH" if det_findings.get("known_quantum_vulnerable") else "MEDIUM",
            "migration_priority": "URGENT" if det_findings.get("known_quantum_vulnerable") else "LOW",
            "recommended_action": "Review cryptographic implementation and migration path.",
            "reason": "Assessment completed via deterministic cryptographic rule fallback.",
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
        logger.debug(f"Malformed MOSCA JSON response: {type(e).__name__}. Returning fallback schema.")
        return default_schema

    if not data.get("asset_id"):
        data["asset_id"] = fallback_asset_id

    assessment = data.get("mosca_assessment")
    if not isinstance(assessment, dict):
        data["mosca_assessment"] = default_schema["mosca_assessment"]

    return data


class MOSCALLMProvider(ABC):
    """
    Abstract Base Class for MOSCA+ LLM Providers.
    """

    @abstractmethod
    def assess(
        self, cbom_asset: Dict[str, Any], deterministic_findings: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Assesses cryptographic security and post-quantum migration risk.

        :param cbom_asset: Input CBOM cryptographic asset.
        :param deterministic_findings: Deterministic findings from CryptoRuleEngine.
        :return: Structured MOSCA+ assessment response dictionary.
        """
        pass


class FallbackMOSCAProvider(MOSCALLMProvider):
    """
    Fallback MOSCA Provider used for offline development, testing, or missing API keys.
    Generates conservative MOSCA+ assessments using deterministic findings.
    """

    def assess(
        self, cbom_asset: Dict[str, Any], deterministic_findings: Dict[str, Any]
    ) -> Dict[str, Any]:
        asset_id = str(cbom_asset.get("asset_id") or "unknown-asset")
        category = deterministic_findings.get("algorithm_category", "UNKNOWN")
        qv = deterministic_findings.get("known_quantum_vulnerable")
        baseline = deterministic_findings.get("classical_baseline", "UNKNOWN")

        algo_obj = cbom_asset.get("algorithm") or {}
        algo_name = str(algo_obj.get("name") if isinstance(algo_obj, dict) else algo_obj).upper()

        if category == "PUBLIC_KEY":
            classical_sec = "HIGH" if baseline in ("ACCEPTABLE", "STRONG") else ("LOW" if baseline == "LEGACY_WEAK" else "MEDIUM")
            quantum_risk = "HIGH"
            overall_risk = "HIGH" if classical_sec == "HIGH" else "CRITICAL"
            priority = "URGENT"
            action = "Prioritize a structured migration plan toward appropriate post-quantum cryptographic mechanisms."
            reason = f"The asset uses {algo_name}, a public-key algorithm vulnerable to Shor's algorithm on a future CRQC."
        elif category == "SYMMETRIC":
            classical_sec = "HIGH" if baseline in ("ACCEPTABLE", "STRONG") else "LOW"
            quantum_risk = "LOW"
            overall_risk = "MEDIUM" if "128" in algo_name else "LOW"
            priority = "LOW"
            action = f"Maintain current {algo_name} deployment with appropriate key management."
            reason = f"{algo_name} provides strong classical security and a high quantum search resilience margin."
        elif category == "HASH":
            classical_sec = "HIGH" if baseline in ("ACCEPTABLE", "STRONG") else "LOW"
            quantum_risk = "LOW"
            overall_risk = "LOW"
            priority = "LOW"
            action = f"Maintain {algo_name} for message digest integrity."
            reason = f"{algo_name} maintains a robust security margin against Grover-style quantum pre-image attacks."
        else:
            classical_sec = "UNKNOWN"
            quantum_risk = "HIGH"
            overall_risk = "HIGH"
            priority = "HIGH"
            action = "Review custom/unknown cipher implementation for standards compliance."
            reason = "Custom or unknown cryptographic reference prevents deterministic certainty; cautious review recommended."

        return {
            "asset_id": asset_id,
            "mosca_assessment": {
                "algorithm_category": category,
                "classical_security": classical_sec,
                "quantum_vulnerable": qv,
                "quantum_migration_risk": quantum_risk,
                "overall_risk": overall_risk,
                "migration_priority": priority,
                "recommended_action": action,
                "reason": reason,
            },
        }


class GeminiMOSCAProvider(MOSCALLMProvider):
    """
    Google Gemini LLM Provider implementation for AI-assisted MOSCA+ Assessment.
    Supports model cascade fallback and clean JSON extraction.
    """

    DEFAULT_MODELS = [
        "gemini-3.6-flash",
        "gemini-3.1-flash-lite",
        "gemini-2.5-flash",
    ]

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY_MOSCA") or os.getenv("GEMINI_API_KEY")
        user_model = model or os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

        candidate_list = [user_model] + [m for m in self.DEFAULT_MODELS if m != user_model]
        self.candidate_models = []
        for m in candidate_list:
            if m not in self.candidate_models:
                self.candidate_models.append(m)

    def assess(
        self, cbom_asset: Dict[str, Any], deterministic_findings: Dict[str, Any]
    ) -> Dict[str, Any]:
        asset_id = str(cbom_asset.get("asset_id") or "unknown-asset")

        if not self.api_key or self.api_key == "YOUR_GEMINI_API_KEY_HERE":
            logger.warning("GEMINI_API_KEY missing or placeholder. Falling back to FallbackMOSCAProvider.")
            return FallbackMOSCAProvider().assess(cbom_asset, deterministic_findings)

        prompt_text = build_mosca_prompt(cbom_asset, deterministic_findings)

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
                    return clean_and_validate_mosca_json(raw_text, asset_id, deterministic_findings)
            except Exception as e:
                err_msg = str(e)
                if any(k in err_msg for k in ("429", "RESOURCE_EXHAUSTED", "404", "503", "NOT_FOUND")):
                    logger.debug(f"Gemini MOSCA API '{model_name}' hit rate limit: {e}. Retrying fallback...")
                    import time
                    time.sleep(1.0)
                    continue
                else:
                    logger.debug(f"Gemini MOSCA API failed for '{model_name}': {e}")
                    continue

        return FallbackMOSCAProvider().assess(cbom_asset, deterministic_findings)


def get_mosca_provider(provider_type: Optional[str] = None) -> MOSCALLMProvider:
    """
    Factory function to instantiate configured MOSCA LLM Provider.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if provider_type == "gemini" or (api_key and api_key != "YOUR_GEMINI_API_KEY_HERE"):
        return GeminiMOSCAProvider()
    return FallbackMOSCAProvider()
