"""
Risk LLM Provider Architecture

Defines Abstract Provider interface, Google Gemini API implementation with model cascade fallback,
JSON cleaning/normalization, and deterministic Fallback LLM Provider for offline testing.
"""

import os
import re
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from .prompts import build_risk_prompt

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)


def clean_and_validate_risk_json(raw_text: str) -> Dict[str, Any]:
    """
    Cleans raw LLM response text by stripping Markdown code fences (```json ... ```)
    and parses JSON into a normalized Risk Context dictionary.
    """
    default_schema = {
        "data_context": {
            "sensitivity": "MEDIUM",
            "data_lifetime_years": 5,
        },
        "network_context": {
            "internet_exposed": False,
            "collectable": False,
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
        logger.debug(f"Malformed Risk JSON response: {type(e).__name__}. Returning default schema.")
        return default_schema

    # Validate inner dictionaries
    data_ctx = data.get("data_context")
    if not isinstance(data_ctx, dict):
        data["data_context"] = default_schema["data_context"]
    else:
        if "sensitivity" not in data_ctx:
            data_ctx["sensitivity"] = "MEDIUM"
        if "data_lifetime_years" not in data_ctx:
            data_ctx["data_lifetime_years"] = 5

    net_ctx = data.get("network_context")
    if not isinstance(net_ctx, dict):
        data["network_context"] = default_schema["network_context"]
    else:
        if "internet_exposed" not in net_ctx:
            net_ctx["internet_exposed"] = False
        if "collectable" not in net_ctx:
            net_ctx["collectable"] = False

    return data


class RiskLLMProvider(ABC):
    """
    Abstract Base Class for Risk Classification Agent LLM Providers.
    """

    @abstractmethod
    def analyze_risk_context(self, raw_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes raw system context to produce a structured Risk Context dictionary.

        :param raw_context: Input raw system context dictionary.
        :return: Structured Risk Context dictionary.
        """
        pass


class FallbackRiskProvider(RiskLLMProvider):
    """
    Fallback Risk Provider used for offline development, testing, or missing API keys.
    Deterministically maps raw application, data, network, and business context to Risk Context JSON.
    """

    def analyze_risk_context(self, raw_context: Dict[str, Any]) -> Dict[str, Any]:
        app = raw_context.get("application") or {}
        data_info = raw_context.get("data") or {}
        net_info = raw_context.get("network") or {}
        biz_info = raw_context.get("business_context") or {}

        # 1. Sensitivity Classification
        data_types = data_info.get("types", [])
        if isinstance(data_types, str):
            data_types = [data_types]
        data_types_lower = [str(t).lower() for t in data_types]
        desc = (str(data_info.get("description") or "") + " " + str(app.get("description") or "")).lower()

        critical_keywords = [
            "financial_records", "banking_information", "transaction_history",
            "authentication_credentials", "passwords", "private_keys",
            "cryptographic_keys", "government_secrets", "banking", "financial"
        ]
        high_keywords = [
            "personal_information", "customer_records", "confidential_business_data",
            "intellectual_property", "healthcare_records", "medical_information", "pii"
        ]

        if any(k in t for t in data_types_lower for k in critical_keywords) or any(k in desc for k in ["banking", "financial", "transaction", "credential"]):
            sensitivity = "CRITICAL"
        elif any(k in t for t in data_types_lower for k in high_keywords) or any(k in desc for k in ["personal", "medical", "patient", "confidential"]):
            sensitivity = "HIGH"
        elif any(k in t for t in data_types_lower for k in ["public_information"]) or "public" in desc:
            sensitivity = "LOW"
        else:
            sensitivity = "MEDIUM"

        # 2. Lifetime Classification (Priority Rule 1: explicit retention)
        explicit_retention = biz_info.get("data_retention_years")
        if explicit_retention is not None and isinstance(explicit_retention, (int, float)):
            lifetime = int(explicit_retention)
        else:
            # Priority Rule 2: Estimate based on data context
            if sensitivity == "CRITICAL":
                lifetime = 20
            elif sensitivity == "HIGH":
                lifetime = 10
            elif sensitivity == "MEDIUM":
                lifetime = 5
            else:
                lifetime = 1

        # 3. Internet Exposure Classification
        exposed = bool(
            net_info.get("internet_facing")
            or net_info.get("publicly_accessible")
            or net_info.get("external_users")
            or app.get("type") in ["web_application", "cloud_service", "public_api"]
        )
        if net_info.get("internal_only") or net_info.get("private_network") or app.get("type") == "internal_system":
            if not net_info.get("internet_facing") and not net_info.get("publicly_accessible"):
                exposed = False

        # 4. Collectability Classification
        if exposed and not net_info.get("internal_only"):
            collectable = True
        elif net_info.get("internal_only") or not exposed:
            collectable = False
        else:
            collectable = exposed

        return {
            "data_context": {
                "sensitivity": sensitivity,
                "data_lifetime_years": lifetime,
            },
            "network_context": {
                "internet_exposed": exposed,
                "collectable": collectable,
            },
        }


class GeminiRiskProvider(RiskLLMProvider):
    """
    Google Gemini LLM Provider implementation for AI-assisted Risk Classification.
    Supports model cascade fallback and clean JSON extraction.
    """

    DEFAULT_MODELS = [
        "gemini-3.6-flash",
        "gemini-3.1-flash-lite",
        "gemini-2.5-flash",
    ]

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY_RISK") or os.getenv("GEMINI_API_KEY")
        user_model = model or os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

        candidate_list = [user_model] + [m for m in self.DEFAULT_MODELS if m != user_model]
        self.candidate_models = []
        for m in candidate_list:
            if m not in self.candidate_models:
                self.candidate_models.append(m)

    def analyze_risk_context(self, raw_context: Dict[str, Any]) -> Dict[str, Any]:
        if not self.api_key or self.api_key == "YOUR_GEMINI_API_KEY_HERE":
            logger.warning("GEMINI_API_KEY missing or placeholder. Falling back to FallbackRiskProvider.")
            return FallbackRiskProvider().analyze_risk_context(raw_context)

        prompt_text = build_risk_prompt(raw_context)

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
                    return clean_and_validate_risk_json(raw_text)
            except Exception as e:
                err_msg = str(e)
                if any(k in err_msg for k in ("429", "RESOURCE_EXHAUSTED", "404", "503", "NOT_FOUND")):
                    logger.debug(f"Gemini Risk API '{model_name}' hit rate limit: {e}. Retrying fallback...")
                    import time
                    time.sleep(1.0)
                    continue
                else:
                    logger.debug(f"Gemini Risk API failed for '{model_name}': {e}")
                    continue

        return FallbackRiskProvider().analyze_risk_context(raw_context)


def get_risk_provider(provider_type: Optional[str] = None) -> RiskLLMProvider:
    """
    Factory function to instantiate configured Risk LLM Provider.
    """
    api_key = os.getenv("GEMINI_API_KEY_RISK") or os.getenv("GEMINI_API_KEY")
    if provider_type == "gemini" or (api_key and api_key != "YOUR_GEMINI_API_KEY_HERE"):
        return GeminiRiskProvider()
    return FallbackRiskProvider()
