"""
HNDL Agent Component

Primary orchestrator for the Harvest Now, Decrypt Later (HNDL) Risk Assessment Module.
Integrates input validation, LLM provider invocation, output schema validation,
and terminal report formatting without modifying source code or original CBOM assets.
"""

from typing import Dict, Any, Optional
from .llm_provider import HNDLLLMProvider, get_hndl_provider
from .validator import HNDLValidator


def format_hndl_terminal_report(
    cbom_asset: Dict[str, Any], risk_context: Dict[str, Any], hndl_result: Dict[str, Any]
) -> str:
    """
    Formats a clean, human-readable terminal demonstration report for an HNDL assessment.

    :param cbom_asset: Input 1 dictionary.
    :param risk_context: Input 2 dictionary.
    :param hndl_result: HNDL assessment dictionary.
    :return: Formatted text block string.
    """
    asset_id = hndl_result.get("asset_id") or cbom_asset.get("asset_id") or "N/A"

    algo_obj = cbom_asset.get("algorithm") or {}
    if isinstance(algo_obj, dict):
        algo_name = algo_obj.get("name") or algo_obj.get("family") or "N/A"
    else:
        algo_name = str(algo_obj)

    data_ctx = risk_context.get("data_context") or {}
    sensitivity = str(data_ctx.get("sensitivity") or "N/A").upper()
    lifetime = data_ctx.get("data_lifetime_years", "N/A")

    net_ctx = risk_context.get("network_context") or {}
    exposed_str = "YES" if net_ctx.get("internet_exposed") else "NO"
    collectable_str = "YES" if net_ctx.get("collectable") else "NO"

    hndl_body = hndl_result.get("hndl") or {}
    applicable_str = "YES" if hndl_body.get("applicable") else "NO"
    harvestability = str(hndl_body.get("harvestability") or "LOW").upper()

    qv = hndl_body.get("quantum_vulnerable")
    if qv is True:
        qv_str = "YES"
    elif qv is False:
        qv_str = "NO"
    else:
        qv_str = "UNKNOWN / NULL"

    future_risk = str(hndl_body.get("future_decryption_risk") or "LOW").upper()
    reason = str(hndl_body.get("reason") or "N/A").strip()

    report = f"""============================================================
HNDL — HARVEST NOW, DECRYPT LATER ASSESSMENT
============================================================

Asset ID:
{asset_id}

Algorithm:
{algo_name}

Data Sensitivity:
{sensitivity}

Data Lifetime:
{lifetime} years

Internet Exposed:
{exposed_str}

Collectable:
{collectable_str}

------------------------------------------------------------

HNDL Applicable:
{applicable_str}

Harvestability:
{harvestability}

Quantum Vulnerable:
{qv_str}

Future Decryption Risk:
{future_risk}

Reason:
{reason}

============================================================"""
    return report


class HNDLAgent:
    """
    HNDL Agent for analyzing Harvest Now, Decrypt Later threats on cryptographic assets.
    """

    def __init__(self, provider: Optional[HNDLLLMProvider] = None):
        self.provider = provider or get_hndl_provider()
        self.validator = HNDLValidator()

    def analyze(
        self, cbom_asset: Dict[str, Any], risk_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Executes HNDL threat assessment workflow:
        Input Validation -> Provider Execution -> Output Validation -> Assessment Return.

        :param cbom_asset: Input 1 dictionary (CBOM Cryptographic Asset).
        :param risk_context: Input 2 dictionary (Data & Network Context).
        :return: Validated HNDL Assessment Dictionary.
        """
        # 1. Input Validation
        is_input_valid, input_errors = self.validator.validate_inputs(cbom_asset, risk_context)
        if not is_input_valid:
            raise ValueError(f"HNDL Input Validation Failed: {'; '.join(input_errors)}")

        # 2. Execute Analysis via Provider
        hndl_result = self.provider.analyze_hndl(cbom_asset, risk_context)

        # 3. Output Schema & Asset ID Validation
        asset_id = str(cbom_asset.get("asset_id"))
        lifetime = int(risk_context["data_context"]["data_lifetime_years"])

        is_output_valid, output_errors = self.validator.validate_output(
            hndl_result, expected_asset_id=asset_id, expected_lifetime=lifetime
        )
        if not is_output_valid:
            raise ValueError(f"HNDL Output Validation Failed: {'; '.join(output_errors)}")

        return hndl_result
