"""
End-to-End ECDAT Quantum Risk Pipeline Orchestrator (pipeline.py)

Orchestrates the complete sequential flow:
1. Discovery Findings -> CycloneDX 1.6 CBOM Agent (Starting Point)
2. CBOM Assets + User Operational Context -> HNDL Timeline Engine (Feature #28 HNDL_exposure)
3. CBOM Assets + User Operational Context -> Mosca Inequality Agent (X + Y > Z Solver)
4. CBOM Assets + Context + HNDL_exposure -> 37-Feature CatBoost Quantum Risk Model
5. Aggregated Pillar Results -> Final Combined Result Synthesizer (Google Gemini AI / Fallback)
"""

from typing import Dict, Any, List, Optional, Union
import logging

from segments.ml.cbom import CBOMAgent
from segments.ml.cbom.ml_adapter import MLFeatureAdapter
from segments.ml.hndl import HNDLAgent
from segments.ml.mosca_agent import MOSCAAgent
from segments.ml.final_combined_result import CombinedRiskSynthesizer, format_final_terminal_report

logger = logging.getLogger(__name__)


class ECDATPipeline:
    """
    Unified Pipeline Orchestrator executing the complete post-quantum cryptographic risk workflow.
    """

    def __init__(
        self,
        gemini_api_key: Optional[str] = None,
        gemini_model: Optional[str] = None,
        force_fallback_llm: bool = False,
        default_quantum_horizon_year: int = 2033,
        default_assessment_year: int = 2026,
    ):
        self.cbom_agent = CBOMAgent()
        self.hndl_agent = HNDLAgent(
            default_quantum_horizon_year=default_quantum_horizon_year,
            default_assessment_year=default_assessment_year,
        )
        self.mosca_agent = MOSCAAgent(
            default_quantum_horizon_year=default_quantum_horizon_year,
            default_assessment_year=default_assessment_year,
        )
        self.ml_adapter = MLFeatureAdapter()
        self.synthesizer = CombinedRiskSynthesizer(
            gemini_api_key=gemini_api_key,
            gemini_model=gemini_model,
            force_fallback=force_fallback_llm,
        )

    def execute(
        self,
        discovery_input: Union[Dict[str, Any], List[Dict[str, Any]]],
        operational_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes the full ECDAT pipeline sequentially.

        :param discovery_input: Discovery findings dictionary or list of raw findings.
        :param operational_context: User-provided system/operational parameters (lifetime, sensitivity, complexity, agility).
        :return: Complete final risk report dictionary including CBOM, HNDL, Mosca, ML, and Executive Synthesis.
        """
        ctx = operational_context.copy() if isinstance(operational_context, dict) else {}

        # -------------------------------------------------------------
        # STAGE 1: CBOM Agent (Starting Point)
        # -------------------------------------------------------------
        if isinstance(discovery_input, dict) and ("crypto_assets" in discovery_input or "components" in discovery_input):
            cbom_document = discovery_input
        else:
            payload = discovery_input if isinstance(discovery_input, dict) else {"findings": discovery_input}
            cbom_document = self.cbom_agent.process(payload)

        assets = cbom_document.get("crypto_assets") or cbom_document.get("components") or []
        if not isinstance(assets, list):
            assets = []

        hndl_results_map: Dict[str, Any] = {}
        mosca_results_map: Dict[str, Any] = {}
        ml_results_map: Dict[str, Any] = {}

        # -------------------------------------------------------------
        # STAGES 2-4: Per-Asset Assessment (HNDL -> Mosca -> ML Model)
        # -------------------------------------------------------------
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            aid = str(asset.get("asset_id") or asset.get("id") or asset.get("name") or "UNKNOWN")

            # Stage 2: HNDL Engine
            h_res = self.hndl_agent.analyze(cbom_asset=asset, operational_context=ctx)
            hndl_results_map[aid] = h_res
            hndl_exposure = float(h_res.get("hndl", {}).get("hndl_exposure_score", 0.0))

            # Stage 3: Mosca Theorem Agent (X + Y > Z)
            m_res = self.mosca_agent.analyze(cbom_asset=asset, operational_context=ctx)
            mosca_results_map[aid] = m_res

            # Stage 4: CatBoost ML Risk Model with HNDL Exposure Feature
            asset_ctx = ctx.copy()
            asset_ctx["HNDL_exposure"] = hndl_exposure
            ml_res = self.ml_adapter.predict_single_asset(cbom_asset=asset, system_context=asset_ctx)
            ml_results_map[aid] = ml_res

        # -------------------------------------------------------------
        # STAGE 5: Final Combined Result Synthesis (Google Gemini AI)
        # -------------------------------------------------------------
        final_report = self.synthesizer.synthesize_portfolio(
            cbom_document=cbom_document,
            ml_results_map=ml_results_map,
            hndl_results_map=hndl_results_map,
            mosca_results_map=mosca_results_map,
            operational_context=ctx,
        )

        # Attach intermediate artifacts for auditability and downstream mitigation
        final_report["cbom_document"] = cbom_document
        final_report["intermediate_stages"] = {
            "hndl_assessments": hndl_results_map,
            "mosca_assessments": mosca_results_map,
            "ml_risk_assessments": ml_results_map,
        }

        return final_report


def run_ecdat_pipeline(
    discovery_input: Union[Dict[str, Any], List[Dict[str, Any]]],
    operational_context: Optional[Dict[str, Any]] = None,
    gemini_api_key: Optional[str] = None,
    force_fallback_llm: bool = False,
) -> Dict[str, Any]:
    """
    Convenience function to execute the complete ECDAT Post-Quantum Cryptographic Pipeline.
    """
    pipeline = ECDATPipeline(
        gemini_api_key=gemini_api_key,
        force_fallback_llm=force_fallback_llm,
    )
    return pipeline.execute(discovery_input, operational_context)
