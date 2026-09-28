"""
MOSCA+ Agent Module

Implements Michele Mosca's Theorem of Quantum Risk (X + Y > Z) as a deterministic
mathematical and migration timeline solver for CBOM cryptographic assets.
"""

from .mosca_agent import MOSCAAgent, format_mosca_terminal_report
from .solver import MoscaSolver
from .crypto_rules import CryptoRuleEngine
from .validator import MOSCAValidator
from .explainability import MoscaExplainabilityBuilder
from .llm_provider import FallbackMOSCAProvider, get_mosca_provider
from .models import (
    MoscaVariables,
    MoscaTimelineMetrics,
    MoscaThreatVectors,
    MoscaScenarioAssumptions,
    MoscaAssessment,
    MoscaAssetReport,
    MoscaDocumentSummary,
)

__all__ = [
    "MOSCAAgent",
    "format_mosca_terminal_report",
    "MoscaSolver",
    "CryptoRuleEngine",
    "MOSCAValidator",
    "MoscaExplainabilityBuilder",
    "FallbackMOSCAProvider",
    "get_mosca_provider",
    "MoscaVariables",
    "MoscaTimelineMetrics",
    "MoscaThreatVectors",
    "MoscaScenarioAssumptions",
    "MoscaAssessment",
    "MoscaAssetReport",
    "MoscaDocumentSummary",
]
