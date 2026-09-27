"""
CBOM (Cryptography Bill of Materials) Module

This module takes pre-discovered cryptographic findings (JSON) from the Discovery module,
processes and structures them into Cryptographic Assets using deterministic extraction and AI assistance,
and outputs a validated CBOM JSON structure with field-level explainability provenance.
"""

from .builder import CBOMBuilder
from .cyclonedx import to_cyclonedx, to_cyclonedx_xml
from .export import CBOMUnavailable, build_export
from .validator import CBOMValidator
from .cbom_agent import CBOMAgent, format_cbom_explanation
from .extractor import DeterministicExtractor
from .ai_provider import (
    BaseLLMProvider,
    FallbackLLMProvider,
    GeminiLLMProvider,
    OpenAILLMProvider,
    get_llm_provider,
    clean_and_validate_llm_json,
    CBOM_EXTRACTION_SYSTEM_PROMPT,
)

__all__ = [
    "CBOMBuilder",
    "CBOMValidator",
    "CBOMAgent",
    "to_cyclonedx",
    "to_cyclonedx_xml",
    "build_export",
    "CBOMUnavailable",
    "format_cbom_explanation",
    "DeterministicExtractor",
    "BaseLLMProvider",
    "FallbackLLMProvider",
    "GeminiLLMProvider",
    "OpenAILLMProvider",
    "get_llm_provider",
    "clean_and_validate_llm_json",
    "CBOM_EXTRACTION_SYSTEM_PROMPT",
]
