"""
Risk Classification Agent Orchestrator

Primary agent class for analyzing raw application, data, network, and business context
and converting it into standardized structured Risk Context JSON for downstream HNDL analysis.
"""

from typing import Dict, Any, Optional
from .llm_provider import RiskLLMProvider, get_risk_provider
from .validator import RiskAgentValidator


class RiskClassificationAgent:
    """
    AI-driven Risk Classification Agent for ECDAT platform.
    Converts raw system context into structured Risk Context (data_context + network_context).
    """

    def __init__(self, provider: Optional[RiskLLMProvider] = None):
        self.provider = provider or get_risk_provider()
        self.validator = RiskAgentValidator()

    def analyze(self, raw_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes Risk Classification pipeline:
        Validate Input -> LLM Analysis -> Validate Output -> Return Structured Risk Context.

        :param raw_context: Raw system, application, data, network, and business context dictionary.
        :return: Structured Risk Context dictionary containing 'data_context' and 'network_context'.
        """
        # 1. Input Validation
        is_input_valid, input_errors = self.validator.validate_input(raw_context)
        if not is_input_valid:
            raise ValueError(f"Risk Classification Agent Input Validation Failed: {'; '.join(input_errors)}")

        # 2. Execute Analysis via Provider
        risk_result = self.provider.analyze_risk_context(raw_context)

        # 3. Output Schema Validation
        is_output_valid, output_errors = self.validator.validate_output(risk_result)
        if not is_output_valid:
            raise ValueError(f"Risk Classification Agent Output Validation Failed: {'; '.join(output_errors)}")

        return risk_result
