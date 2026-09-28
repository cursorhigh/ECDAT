"""LLM provider for the mitigation narrator.

Mirrors the MOSCA provider pattern: Gemini with model cascade fallback and
strict JSON cleaning. The narrator NEVER makes risk decisions - it only
polishes prose, so a failure here degrades gracefully to deterministic text.
"""

import json
import os
import re
from typing import Any, Dict, Optional

from .prompts import build_mitigation_prompt

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def clean_narrative_json(
    raw_text: Optional[str], deterministic_doc: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """Parse the model's narrative JSON; return None on any malformed output."""
    if not raw_text or not isinstance(raw_text, str):
        return None
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    try:
        data = json.loads(cleaned)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    out = {}
    for key in ("executive_summary", "quantum_risk_narrative"):
        if isinstance(data.get(key), str) and data[key].strip():
            out[key] = data[key].strip()
    if isinstance(data.get("strategic_recommendations"), list):
        filtered = [
            item
            for item in data["strategic_recommendations"]
            if isinstance(item, dict) and isinstance(item.get("title"), str)
        ][:4]
        if filtered:
            out["strategic_recommendations"] = filtered
    if isinstance(data.get("code_replacements"), list):
        expected = {
            str(row.get("asset_id") or row.get("id")): (row.get("migration_impact") or {}).get("replacement")
            for row in (deterministic_doc or {}).get("rows", [])
            if row.get("source_context")
        }
        replacements = []
        for item in data["code_replacements"]:
            if not isinstance(item, dict):
                continue
            asset_id = str(item.get("asset_id") or "")
            required = ("file", "language", "replacement_algorithm", "vulnerable_code", "replacement_code", "explanation")
            if not asset_id or asset_id not in expected or any(not isinstance(item.get(key), str) or not item[key].strip() for key in required):
                continue
            if item["replacement_algorithm"] != expected[asset_id]:
                continue
            replacements.append({key: item[key].strip() for key in ("asset_id", *required)})
        if replacements:
            out["code_replacements"] = replacements[:20]
    return out or None


class MitigationProvider:
    """Provider interface: enhance narrative fields or return None."""

    def enhance(self, deterministic_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return None


class FallbackMitigationProvider(MitigationProvider):
    pass


class GeminiMitigationProvider(MitigationProvider):
    DEFAULT_MODELS = [
        "gemini-3.5-flash-lite",
        "gemini-3.1-flash-lite",
        "gemini-3.6-flash",
    ]

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY_MITIGATION") or os.getenv("GEMINI_API_KEY")
        user_model = model or os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
        candidate_list = [user_model] + [m for m in self.DEFAULT_MODELS if m != user_model]
        self.candidate_models = []
        for m in candidate_list:
            if m not in self.candidate_models:
                self.candidate_models.append(m)

    def enhance(self, deterministic_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.api_key or self.api_key == "YOUR_GEMINI_API_KEY_HERE":
            return None
        prompt_text = build_mitigation_prompt(deterministic_doc)
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
                    parsed = clean_narrative_json(raw_text, deterministic_doc)
                    if parsed:
                        parsed["model_used"] = model_name
                        return parsed
            except Exception:
                import time

                time.sleep(1.0)
                continue
        return None


def get_mitigation_provider() -> MitigationProvider:
    api_key = os.getenv("GEMINI_API_KEY_MITIGATION") or os.getenv("GEMINI_API_KEY")
    if api_key and api_key != "YOUR_GEMINI_API_KEY_HERE":
        return GeminiMitigationProvider()
    return FallbackMitigationProvider()