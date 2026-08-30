"""
AI Provider Abstraction Layer for CBOM Module

Defines strict LLM prompt instructions, response validation, and concrete implementations
(Fallback/Mock, Gemini, OpenAI) for AI-assisted cryptographic analysis with field-level explainability.
"""

import os
import json
import re
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

CBOM_EXTRACTION_SYSTEM_PROMPT = """
You are a precise cryptographic analysis engine for enterprise CBOM (Cryptography Bill of Materials) generation.
Your task is to analyze a single cryptographic discovery finding and its source code evidence.

Respond ONLY with a valid JSON object matching this schema exactly:
{
  "asset_type": null,
  "algorithm": null,
  "family": null,
  "parameters": {},
  "purpose": null,
  "implementation": null,
  "confidence": 0.0,
  "explainability": {
    "summary": null,
    "field_evidence": [],
    "confidence_reason": null
  }
}

Each item in "field_evidence" MUST strictly follow this structure:
{
  "field": "algorithm | parameters.key_size | parameters.mode | family | purpose | implementation",
  "value": "Extracted field value",
  "source": "provided_source_code | finding | deterministic_result",
  "snippet": "Exact relevant snippet from evidence",
  "evidence_type": "explicit | pattern_match | inferred_from_provided_evidence",
  "explanation": "Short evidence-based explanation"
}

STRICT RULES:
1. Extract ONLY information directly supported by the provided finding and code evidence.
2. For each extracted value, provide concise evidence showing what supports the value.
3. Evidence snippets MUST come ONLY from the supplied source code, finding, or deterministic extraction results.
4. Do NOT invent or fabricate evidence. If no evidence exists, do NOT claim evidence.
5. Do NOT expose hidden reasoning, chain-of-thought, or internal model thoughts.
6. Provide ONLY short evidence-based explanations.
7. If a CBOM field cannot be supported by evidence, set it to null.
8. Clearly distinguish between:
   - explicit evidence (explicit API calls, constants)
   - pattern matches (regex/rule matches)
   - inference from supplied evidence (e.g. key exchange implies key_establishment purpose)
9. The confidence_reason must explain why the confidence score is high, medium, or low based on available evidence.
10. Parameters object MUST contain only parameters explicitly visible or strongly identifiable from evidence (e.g., key_size, mode, curve, hash).
11. Do NOT perform quantum risk analysis or calculate Mosca's inequality.
12. Return JSON only. Do not wrap in markdown or add explanations outside the JSON object.
"""


def clean_and_validate_llm_json(raw_text: str) -> Dict[str, Any]:
    """
    Cleans raw LLM response text (stripping markdown codeblock tags if present)
    and validates JSON output structure against expected types including explainability.
    Robust against malformed JSON or invalid data types.
    """
    default_schema: Dict[str, Any] = {
        "asset_type": None,
        "algorithm": None,
        "family": None,
        "parameters": {},
        "purpose": None,
        "implementation": None,
        "confidence": 0.0,
        "explainability": {
            "summary": None,
            "field_evidence": [],
            "confidence_reason": None,
        },
    }

    if not raw_text or not isinstance(raw_text, str):
        return default_schema

    # Clean markdown fences if present
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()

    try:
        data = json.loads(cleaned)
        if not isinstance(data, dict):
            return default_schema
    except Exception as e:
        logger.warning(
            f"Malformed LLM JSON response: {type(e).__name__}. Returning safe fallback schema."
        )
        return default_schema

    # Validate individual fields and coerce types safely
    asset_type = data.get("asset_type") if isinstance(data.get("asset_type"), str) else None
    algorithm = data.get("algorithm") if isinstance(data.get("algorithm"), str) else None
    family = data.get("family") if isinstance(data.get("family"), str) else None

    parameters = data.get("parameters")
    if not isinstance(parameters, dict):
        parameters = {}

    purpose = data.get("purpose") if isinstance(data.get("purpose"), str) else None
    implementation = (
        data.get("implementation") if isinstance(data.get("implementation"), str) else None
    )

    confidence = data.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else 0.0
        confidence = max(0.0, min(1.0, confidence))
    except (ValueError, TypeError):
        confidence = 0.0

    # Validate explainability structure safely
    raw_exp = data.get("explainability")
    if not isinstance(raw_exp, dict):
        raw_exp = {}

    summary = raw_exp.get("summary") if isinstance(raw_exp.get("summary"), str) else None
    confidence_reason = (
        raw_exp.get("confidence_reason")
        if isinstance(raw_exp.get("confidence_reason"), str)
        else None
    )

    raw_evidence_list = raw_exp.get("field_evidence")
    if not isinstance(raw_evidence_list, list):
        raw_evidence_list = []

    validated_evidence: List[Dict[str, Any]] = []
    valid_sources = {"provided_source_code", "source_code", "deterministic_result", "finding"}
    valid_types = {"explicit", "pattern_match", "inferred_from_provided_evidence", "insufficient"}

    for item in raw_evidence_list:
        if not isinstance(item, dict):
            continue
        field_name = str(item.get("field") or "").strip()
        if not field_name:
            continue

        src = str(item.get("source") or "provided_source_code").strip()
        if src not in valid_sources:
            src = "provided_source_code"

        etype = str(item.get("evidence_type") or "explicit").strip()
        if etype not in valid_types:
            etype = "inferred_from_provided_evidence"

        validated_evidence.append({
            "field": field_name,
            "value": item.get("value"),
            "source": src,
            "snippet": str(item.get("snippet") or "").strip(),
            "evidence_type": etype,
            "explanation": str(item.get("explanation") or "").strip(),
        })

    return {
        "asset_type": asset_type,
        "algorithm": algorithm,
        "family": family,
        "parameters": parameters,
        "purpose": purpose,
        "implementation": implementation,
        "confidence": confidence,
        "explainability": {
            "summary": summary,
            "field_evidence": validated_evidence,
            "confidence_reason": confidence_reason,
        },
    }


class BaseLLMProvider(ABC):
    """
    Abstract Base Class for LLM Providers used by CBOMAgent.
    """

    @abstractmethod
    def extract_metadata(
        self, finding: Dict[str, Any], deterministic_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Uses LLM reasoning to extract supported cryptographic metadata from finding code evidence.

        :param finding: Raw discovery finding dictionary.
        :param deterministic_results: Output from DeterministicExtractor.
        :return: Dict containing validated extracted fields matching CBOM schema with explainability.
        """
        pass


class FallbackLLMProvider(BaseLLMProvider):
    """
    Fallback LLM Provider used when no API keys are set.
    Performs safe non-LLM passthrough, returning safe default schema.
    """

    def extract_metadata(
        self, finding: Dict[str, Any], deterministic_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        return clean_and_validate_llm_json("")


class GeminiLLMProvider(BaseLLMProvider):
    """
    Google Gemini LLM Provider implementation for AI-assisted cryptographic analysis.
    Supports official google-genai SDK with automatic model fallback on rate limits or invalid model names.
    """

    DEFAULT_MODELS = [
        "gemini-3.6-flash",
        "gemini-3.1-flash-lite",
    ]

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        user_model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

        # Build candidate models list maintaining preference order
        candidate_list = [user_model] + [m for m in self.DEFAULT_MODELS if m != user_model]
        self.candidate_models = []
        for m in candidate_list:
            if m not in self.candidate_models:
                self.candidate_models.append(m)
        self.model = self.candidate_models[0]

    def extract_metadata(
        self, finding: Dict[str, Any], deterministic_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        if not self.api_key:
            logger.warning("GEMINI_API_KEY is missing. Skipping AI metadata extraction.")
            return clean_and_validate_llm_json("")

        user_content = f"""
Input Discovery Finding:
Detected: {finding.get('detected')}
Code Evidence: {finding.get('code')}

Deterministically identified properties:
{json.dumps(deterministic_results)}
"""

        for model_name in self.candidate_models:
            try:
                raw_text = None
                # Try google-genai (official SDK)
                try:
                    from google import genai
                    from google.genai import types

                    client = genai.Client(api_key=self.api_key)
                    response = client.models.generate_content(
                        model=model_name,
                        contents=f"{CBOM_EXTRACTION_SYSTEM_PROMPT}\n\n{user_content}",
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            temperature=0.0,
                        ),
                    )
                    raw_text = response.text
                except ImportError:

                    import google.generativeai as genai

                    genai.configure(api_key=self.api_key)
                    model_instance = genai.GenerativeModel(
                        model_name,
                        system_instruction=CBOM_EXTRACTION_SYSTEM_PROMPT,
                    )
                    response = model_instance.generate_content(
                        user_content,
                        generation_config={
                            "response_mime_type": "application/json",
                            "temperature": 0.0,
                        },
                    )
                    raw_text = response.text

                if raw_text:
                    return clean_and_validate_llm_json(raw_text)
            except Exception as e:
                err_msg = str(e)
                if any(k in err_msg for k in ("429", "RESOURCE_EXHAUSTED", "404", "503", "NOT_FOUND")):
                    logger.debug(f"Gemini API model '{model_name}' hit rate limit/error: {e}. Retrying fallback...")
                    import time
                    time.sleep(1.0)
                    continue
                else:
                    logger.debug(f"Gemini API execution failed for '{model_name}': {e}")
                    continue

        return clean_and_validate_llm_json("")


class OpenAILLMProvider(BaseLLMProvider):
    """
    OpenAI LLM Provider implementation.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def extract_metadata(
        self, finding: Dict[str, Any], deterministic_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        if not self.api_key:
            logger.warning("OPENAI_API_KEY is missing. Skipping AI metadata extraction.")
            return clean_and_validate_llm_json("")

        user_content = f"""
Input Discovery Finding:
Detected: {finding.get('detected')}
Code Evidence: {finding.get('code')}

Deterministically identified properties:
{json.dumps(deterministic_results)}
"""

        try:
            import openai

            client = openai.OpenAI(api_key=self.api_key)

            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": CBOM_EXTRACTION_SYSTEM_PROMPT,
                    },
                    {"role": "user", "content": user_content},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,
            )

            raw_content = response.choices[0].message.content
            return clean_and_validate_llm_json(raw_content or "")
        except Exception as e:
            logger.error(f"OpenAI API execution failed safely: {type(e).__name__}")
            return clean_and_validate_llm_json("")


def get_llm_provider(provider_type: Optional[str] = None) -> BaseLLMProvider:
    """
    Factory function to instantiate configured LLM provider based on environment variables or explicit provider choice.
    """
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    if provider_type == "gemini" or os.getenv("GEMINI_API_KEY"):
        return GeminiLLMProvider()
    elif provider_type == "openai" or os.getenv("OPENAI_API_KEY"):
        return OpenAILLMProvider()

    return FallbackLLMProvider()
