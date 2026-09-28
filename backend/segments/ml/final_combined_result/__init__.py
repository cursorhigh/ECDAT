"""
Final Combined Result Package (ML Risk + HNDL + Mosca + Gemini Report Synthesis)
"""

from .models import (
    AssetInputBundle,
    AssetSynthesisReport,
    FinalExecutiveReport,
    PortfolioSummaryStats,
    AttributionEvidence,
)
from .gemini_provider import (
    GeminiReportProvider,
    DeterministicFallbackProvider,
    BaseReportProvider,
)
from .validator import SynthesisValidator
from .synthesizer import (
    CombinedRiskSynthesizer,
    format_final_terminal_report,
)

__all__ = [
    "AssetInputBundle",
    "AssetSynthesisReport",
    "FinalExecutiveReport",
    "PortfolioSummaryStats",
    "AttributionEvidence",
    "GeminiReportProvider",
    "DeterministicFallbackProvider",
    "BaseReportProvider",
    "SynthesisValidator",
    "CombinedRiskSynthesizer",
    "format_final_terminal_report",
]
