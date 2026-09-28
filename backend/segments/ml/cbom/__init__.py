"""
CBOM (Cryptography Bill of Materials) Module

Transforms discovery findings into standards-compliant CycloneDX 1.6 and ECDAT
CBOM structures with deterministic cryptographic catalog enrichment and explainability provenance.
"""

from .builder import CBOMBuilder
from .cyclonedx import to_cyclonedx, to_cyclonedx_xml
from .export import CBOMUnavailable, build_export
from .validator import CBOMValidator
from .cbom_agent import CBOMAgent, format_cbom_explanation
from .extractor import DeterministicExtractor
from .ml_adapter import MLFeatureAdapter
from .crypto_catalog import (
    lookup_crypto_algorithm,
    canonicalize_algorithm_name,
    is_quantum_vulnerable,
    get_nist_quantum_level,
    get_classical_security_level,
    CRYPTO_CATALOG,
)
from .cyclonedx_schema import (
    CycloneDX16CBOM,
    CryptoComponent,
    CryptoProperties,
    AlgorithmProperties,
    ProtocolProperties,
    CertificateProperties,
    Evidence,
    Occurrence,
)
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
    "MLFeatureAdapter",
    "format_cbom_explanation",
    "DeterministicExtractor",
    "lookup_crypto_algorithm",
    "canonicalize_algorithm_name",
    "is_quantum_vulnerable",
    "get_nist_quantum_level",
    "get_classical_security_level",
    "CRYPTO_CATALOG",
    "CycloneDX16CBOM",
    "CryptoComponent",
    "CryptoProperties",
    "AlgorithmProperties",
    "ProtocolProperties",
    "CertificateProperties",
    "Evidence",
    "Occurrence",
    "BaseLLMProvider",
    "FallbackLLMProvider",
    "GeminiLLMProvider",
    "OpenAILLMProvider",
    "get_llm_provider",
    "clean_and_validate_llm_json",
    "CBOM_EXTRACTION_SYSTEM_PROMPT",
]
