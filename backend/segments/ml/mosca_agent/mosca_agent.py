"""
MOSCA+ Agent Orchestrator

Primary agent class for assessing cryptographic security, classical posture,
quantum vulnerability, and post-quantum migration priority of CBOM cryptographic assets.
"""

import logging
from typing import Dict, Any, Optional
from .crypto_rules import CryptoRuleEngine
from .llm_provider import MOSCALLMProvider, get_mosca_provider
from .validator import MOSCAValidator
from .exceptions import MOSCAInputValidationError, MOSCAOutputValidationError

logger = logging.getLogger(__name__)


class MOSCAAgent:
    """
    MOSCA+ Cryptographic Security and Migration Risk Assessment Agent.
    Combines deterministic cryptographic rule analysis with Gemini AI contextual evaluation.
    """

    def __init__(
        self,
        llm_provider: Optional[MOSCALLMProvider] = None,
        rule_engine: Optional[CryptoRuleEngine] = None,
        verbose: bool = True,
    ):
        self.llm_provider = llm_provider or get_mosca_provider()
        self.rule_engine = rule_engine or CryptoRuleEngine()
        self.validator = MOSCAValidator()
        self.verbose = verbose

    def analyze(self, cbom_asset: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes MOSCA+ assessment workflow:
        Validate Input -> Deterministic Rule Engine -> Log Explainability -> LLM Assessment -> Validate Output.

        :param cbom_asset: Input CBOM cryptographic asset dictionary.
        :return: Structured MOSCA+ Assessment Dictionary.
        """
        # 1. Input Validation
        is_input_valid, input_errors = self.validator.validate_input(cbom_asset)
        if not is_input_valid:
            raise MOSCAInputValidationError(f"MOSCA+ Input Validation Failed: {'; '.join(input_errors)}")

        asset_id = str(cbom_asset.get("asset_id"))

        # Extract algorithm & parameter info for logging
        algo_obj = cbom_asset.get("algorithm") or {}
        algo_name = str(algo_obj.get("name") if isinstance(algo_obj, dict) else algo_obj)
        params = cbom_asset.get("parameters") or {}
        key_size = params.get("key_size") if isinstance(params, dict) else "N/A"
        purpose = cbom_asset.get("purpose") or "N/A"

        # 2. Run Deterministic CryptoRuleEngine
        deterministic_findings = self.rule_engine.analyze(cbom_asset)

        # 3. Print Explainability Logging
        if self.verbose:
            self._log_explainability(
                asset_id=asset_id,
                algo_name=algo_name,
                key_size=key_size,
                purpose=purpose,
                deterministic_findings=deterministic_findings,
            )

        # 4. Send CBOM asset + deterministic findings to LLM Provider
        if self.verbose:
            print("[3] AI CONTEXTUAL ANALYSIS")
            print("Sending deterministic findings and CBOM asset to Gemini...\n")

        result = self.llm_provider.assess(cbom_asset, deterministic_findings)

        if self.verbose:
            print("AI assessment received successfully.\n")

        # 5. Validate Output Schema
        is_output_valid, output_errors = self.validator.validate(result, expected_asset_id=asset_id)
        if not is_output_valid:
            raise MOSCAOutputValidationError(f"MOSCA+ Output Validation Failed: {'; '.join(output_errors)}")

        # 6. Log Final Results
        assessment = result.get("mosca_assessment") or {}
        if self.verbose:
            print("[4] FINAL MOSCA+ RESULT")
            print(f"Classical Security: {assessment.get('classical_security')}")
            print(f"Quantum Migration Risk: {assessment.get('quantum_migration_risk')}")
            print(f"Overall Risk: {assessment.get('overall_risk')}")
            print(f"Migration Priority: {assessment.get('migration_priority')}")
            print("=" * 40 + "\n")

        return result

    def _log_explainability(
        self,
        asset_id: str,
        algo_name: str,
        key_size: Any,
        purpose: Any,
        deterministic_findings: Dict[str, Any],
    ) -> None:
        """Prints explainability logging headers for hackathon demonstration."""
        print("\n" + "=" * 40)
        print("MOSCA+ CRYPTOGRAPHIC ASSESSMENT")
        print("=" * 40)
        print(f"Asset ID: {asset_id}\n")
        print("[1] CBOM INPUT RECEIVED")
        print(f"Algorithm: {algo_name}")
        print(f"Key Size: {key_size}")
        print(f"Purpose: {purpose}\n")
        print("[2] DETERMINISTIC ANALYSIS")
        print(f"Algorithm Category: {deterministic_findings.get('algorithm_category')}")
        qv = deterministic_findings.get("known_quantum_vulnerable")
        qv_str = "TRUE" if qv is True else ("FALSE" if qv is False else "UNKNOWN")
        print(f"Known Quantum Vulnerable: {qv_str}")
        print(f"Quantum Threat Type: {deterministic_findings.get('quantum_attack')}")
        print(f"Deterministic Confidence: {deterministic_findings.get('confidence')}\n")
