"""
Combined Result Synthesizer Orchestrator (synthesizer.py)

Orchestrates the unification of:
- 37-feature CatBoost Quantum Risk Model results (Risk Tier, Confidence, SHAP)
- HNDL Timeline Engine results (Exposure Score, Harvestability, Long-lived Data Risk)
- Mosca Theorem Agent results (X + Y > Z Deficit, Must-Start Deadline, Urgency)

Produces the final grounded Post-Quantum Cryptographic Risk Report with explicit
source attributions using Google Gemini AI or deterministic fallback.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union

from .models import AssetSynthesisReport, FinalExecutiveReport, PortfolioSummaryStats, AttributionEvidence
from .gemini_provider import GeminiReportProvider, DeterministicFallbackProvider, BaseReportProvider
from .validator import SynthesisValidator


class CombinedRiskSynthesizer:
    """
    Main orchestrator for synthesizing the Final Post-Quantum Risk Report from ML, HNDL, and Mosca pillars.
    """

    def __init__(
        self,
        gemini_api_key: Optional[str] = None,
        gemini_model: Optional[str] = None,
        force_fallback: bool = False,
    ):
        if force_fallback:
            self.provider: BaseReportProvider = DeterministicFallbackProvider()
        else:
            self.provider = GeminiReportProvider(api_key=gemini_api_key, model=gemini_model)
        self.validator = SynthesisValidator()

    def synthesize_asset(
        self,
        cbom_asset: Dict[str, Any],
        ml_risk_result: Optional[Dict[str, Any]] = None,
        hndl_result: Optional[Dict[str, Any]] = None,
        mosca_result: Optional[Dict[str, Any]] = None,
        operational_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Synthesizes the final quantum risk assessment for a single cryptographic asset.
        """
        asset_id = str(cbom_asset.get("asset_id") or cbom_asset.get("id") or cbom_asset.get("name") or "UNKNOWN")
        algo_name = str(cbom_asset.get("algorithm") or cbom_asset.get("name") or "UNKNOWN")
        family = str(cbom_asset.get("family") or "").lower()
        role = str(cbom_asset.get("crypto_role") or cbom_asset.get("purpose") or "").lower()
        params = cbom_asset.get("parameters", {}) if isinstance(cbom_asset.get("parameters"), dict) else {}

        asset_bundle = {
            "asset_id": asset_id,
            "algorithm": algo_name,
            "family": family,
            "crypto_role": role,
            "parameters": params,
            "operational_context": operational_context or {},
        }

        # 1. Normalize ML Summary
        ml_res = ml_risk_result or {}
        ml_prediction = ml_res.get("prediction") or ml_res.get("risk_tier") or "MEDIUM"
        ml_conf = ml_res.get("confidence") or ml_res.get("model_confidence") or 0.85
        ml_probs = ml_res.get("probabilities") or ml_res.get("class_probabilities") or {}
        ml_top_feats = ml_res.get("top_contributing_features") or ml_res.get("shap_features") or [
            "quantum_vulnerable", "key_size", "crypto_role"
        ]

        ml_summary = {
            "risk_tier": str(ml_prediction).upper(),
            "confidence": float(ml_conf),
            "probabilities": ml_probs,
            "top_contributing_features": ml_top_feats,
        }

        # 2. Normalize HNDL Summary
        h_res = hndl_result or {}
        h_body = h_res.get("hndl") or h_res
        h_timeline = h_body.get("timeline") or {}
        h_threats = h_body.get("threat_vectors") or {}

        hndl_score_val = float(h_body.get("hndl_exposure_score", 0.0))
        is_exp = bool(h_body.get("is_exposed", False) or h_body.get("applicable", False) or hndl_score_val >= 0.30)

        hndl_summary = {
            "hndl_exposure_score": hndl_score_val,
            "harvestability_score": float(h_threats.get("harvestability_score", 0.0)),
            "future_decryption_risk": str(h_body.get("future_decryption_risk", "NEGLIGIBLE")).upper(),
            "is_exposed": is_exp,
            "applicable": bool(h_body.get("applicable", False)),
            "exposure_factor": float(h_timeline.get("exposure_factor", 0.0)),
            "data_expiry_year": h_timeline.get("data_expiry_year", "N/A"),
        }

        # 3. Normalize Mosca Summary
        m_res = mosca_result or {}
        m_body = m_res.get("mosca") or m_res.get("mosca_assessment") or m_res
        m_vars = m_body.get("variables") or {}
        m_timeline = m_body.get("timeline") or {}

        mosca_summary = {
            "inequality_satisfied": bool(m_body.get("inequality_satisfied", False)),
            "deficit_years": float(m_timeline.get("mosca_deficit_years", 0.0)),
            "must_start_by_year": m_timeline.get("must_start_by_year", 2028),
            "is_overdue_to_start": bool(m_timeline.get("is_overdue_to_start", False)),
            "urgency_tier": str(m_body.get("urgency_tier", "LOW")).upper(),
            "migration_posture": str(m_body.get("migration_posture", "SAFE_BUFFER")).upper(),
            "mosca_risk_index": float(m_body.get("mosca_risk_index", 0.0)),
            "variables": {
                "X_migration_time": float(m_vars.get("X_migration_time_years", 0.0)),
                "Y_data_lifetime": float(m_vars.get("Y_data_lifetime_years", 0.0)),
                "Z_time_to_crqc": float(m_vars.get("Z_time_to_crqc_years", 0.0)),
            },
        }

        # 4. Generate Synthesized Report via Provider (Gemini / Fallback)
        report_data = self.provider.synthesize_asset_report(
            asset_bundle=asset_bundle,
            ml_summary=ml_summary,
            hndl_summary=hndl_summary,
            mosca_summary=mosca_summary,
        )

        # Attach raw pillar summaries to output
        report_data["ml_summary"] = ml_summary
        report_data["hndl_summary"] = hndl_summary
        report_data["mosca_summary"] = mosca_summary

        # Validate structure
        is_valid, errs = self.validator.validate_asset_synthesis_report(report_data)
        if not is_valid:
            # Re-fallback if LLM generated invalid output
            report_data = DeterministicFallbackProvider().synthesize_asset_report(
                asset_bundle, ml_summary, hndl_summary, mosca_summary
            )
            report_data["ml_summary"] = ml_summary
            report_data["hndl_summary"] = hndl_summary
            report_data["mosca_summary"] = mosca_summary

        return report_data

    def synthesize_portfolio(
        self,
        cbom_document: Dict[str, Any],
        ml_results_map: Optional[Dict[str, Any]] = None,
        hndl_results_map: Optional[Dict[str, Any]] = None,
        mosca_results_map: Optional[Dict[str, Any]] = None,
        operational_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Synthesizes the global application-level Post-Quantum Risk Report across all CBOM assets.
        """
        assets = cbom_document.get("crypto_assets") or cbom_document.get("components") or []
        if not isinstance(assets, list):
            assets = []

        ml_map = ml_results_map or {}
        hndl_map = hndl_results_map or {}
        mosca_map = mosca_results_map or {}

        asset_reports: List[Dict[str, Any]] = []
        tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NEGLIGIBLE": 0}
        hndl_exposed_count = 0
        mosca_deficit_count = 0
        overdue_count = 0
        total_score = 0.0
        max_score = 0.0
        earliest_deadline: Optional[int] = None

        for asset in assets:
            if not isinstance(asset, dict):
                continue
            aid = str(asset.get("asset_id") or asset.get("id") or asset.get("name") or "")
            
            ml_res = ml_map.get(aid)
            h_res = hndl_map.get(aid)
            m_res = mosca_map.get(aid)

            rep = self.synthesize_asset(
                cbom_asset=asset,
                ml_risk_result=ml_res,
                hndl_result=h_res,
                mosca_result=m_res,
                operational_context=operational_context,
            )
            asset_reports.append(rep)

            # Aggregate stats
            tier = rep.get("final_risk_class") or rep.get("overall_quantum_risk_tier", "MEDIUM")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

            score = float(rep.get("unified_risk_score", 0.0))
            total_score += score
            if score > max_score:
                max_score = score

            if rep.get("hndl_summary", {}).get("is_exposed"):
                hndl_exposed_count += 1

            m_sum = rep.get("mosca_summary", {})
            deficit_val = float(m_sum.get("deficit_years", 0.0))
            if deficit_val > 0.0 and rep.get("migration_required"):
                mosca_deficit_count += 1
            if m_sum.get("is_overdue_to_start") and rep.get("migration_required"):
                overdue_count += 1

            # Minimum valid deadline from assets requiring migration
            deadline = rep.get("migration_deadline")
            if deadline is not None and rep.get("migration_required"):
                try:
                    num_deadline = float(deadline)
                    if earliest_deadline is None or num_deadline < earliest_deadline:
                        earliest_deadline = round(num_deadline, 1)
                except (ValueError, TypeError):
                    pass

        total_assets = len(asset_reports)
        avg_score = round(total_score / max(1, total_assets), 2)

        portfolio_stats = {
            "total_assets": total_assets,
            "critical_risk_count": tier_counts.get("CRITICAL", 0),
            "high_risk_count": tier_counts.get("HIGH", 0),
            "medium_risk_count": tier_counts.get("MEDIUM", 0),
            "low_risk_count": tier_counts.get("LOW", 0),
            "negligible_risk_count": tier_counts.get("NEGLIGIBLE", 0),
            "hndl_exposed_count": hndl_exposed_count,
            "mosca_deficit_count": mosca_deficit_count,
            "overdue_migration_count": overdue_count,
            "average_risk_score": avg_score,
            "highest_risk_score": max_score,
            "earliest_migration_deadline_year": earliest_deadline,
        }

        # Executive narrative synthesis
        exec_data = self.provider.synthesize_portfolio_report(portfolio_stats, asset_reports)

        provider_name = (
            "Google Gemini AI"
            if isinstance(self.provider, GeminiReportProvider) and self.provider.api_key
            else "Deterministic Fallback Engine"
        )

        final_report = {
            "report_title": exec_data.get("report_title", "ECDAT Enterprise Post-Quantum Cryptographic Risk Report"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generation_provider": provider_name,
            "portfolio_stats": portfolio_stats,
            "executive_summary": exec_data.get("executive_summary", ""),
            "key_findings": exec_data.get("key_findings", []),
            "source_attribution_summary": exec_data.get("source_attribution_summary", {}),
            "asset_reports": asset_reports,
        }

        return final_report


def format_final_terminal_report(final_report: Dict[str, Any]) -> str:
    """
    Formats the synthesized Final Post-Quantum Report into a clean, human-readable terminal display.
    """
    stats = final_report.get("portfolio_stats", {})
    exec_summary = final_report.get("executive_summary", "")
    key_findings = final_report.get("key_findings", [])
    assets = final_report.get("asset_reports", [])
    provider = final_report.get("generation_provider", "N/A")
    gen_time = final_report.get("generated_at", "N/A")

    deadline_val = stats.get("earliest_migration_deadline_year")
    deadline_str = f"{deadline_val}" if deadline_val is not None else "Not applicable / Safe buffer"

    lines = [
        "=" * 70,
        "   ECDAT FINAL POST-QUANTUM CRYPTOGRAPHIC RISK SYNTHESIS REPORT",
        "=" * 70,
        f"Generated At:       {gen_time}",
        f"Synthesis Engine:   {provider}",
        "",
        "PORTFOLIO RISK SUMMARY:",
        f"• Total Cryptographic Assets:   {stats.get('total_assets', 0)}",
        f"• Critical Risk Assets:         {stats.get('critical_risk_count', 0)}",
        f"• High Risk Assets:             {stats.get('high_risk_count', 0)}",
        f"• Medium Risk Assets:           {stats.get('medium_risk_count', 0)}",
        f"• Low / Negligible Risk Assets: {stats.get('low_risk_count', 0)} / {stats.get('negligible_risk_count', 0)}",
        f"• HNDL Intercept-Exposed:       {stats.get('hndl_exposed_count', 0)}",
        f"• Mosca Timeline Deficit Assets:{stats.get('mosca_deficit_count', 0)} (Overdue: {stats.get('overdue_migration_count', 0)})",
        f"• Earliest Migration Deadline:  {deadline_str}",
        f"• Average Unified Risk Score:   {stats.get('average_risk_score', 0.0):.1f} / 100.0 (Max: {stats.get('highest_risk_score', 0.0):.1f})",
        "",
        "EXECUTIVE BRIEFING:",
        exec_summary,
        "",
        "KEY FINDINGS & ATTRIBUTIONS:",
    ]

    for finding in key_findings:
        lines.append(f"  * {finding}")

    lines.append("")
    lines.append("INDIVIDUAL ASSET ASSESSMENTS:")
    lines.append("-" * 70)

    for asset in assets:
        aid = asset.get("asset_id", "N/A")
        algo = asset.get("algorithm", "N/A")
        pqc = asset.get("pqc_status", "N/A")
        tier = asset.get("final_risk_class") or asset.get("overall_quantum_risk_tier", "N/A")
        base_class = asset.get("base_risk_class", tier)
        score = asset.get("unified_risk_score", 0.0)
        urgency = asset.get("urgency_tier", "N/A")
        driver = asset.get("primary_risk_driver", "N/A")
        action = asset.get("recommended_action", "N/A")
        policy_overrides = asset.get("policy_overrides", [])
        mig_req = "YES" if asset.get("migration_required") else "NO"
        deadline_asset = asset.get("migration_deadline")
        deadline_display = f"Must start by: {deadline_asset}" if deadline_asset is not None else "N/A (Quantum-Safe / Retained)"

        ml_pred = asset.get("ml_prediction") or asset.get("ml_summary", {}).get("risk_tier", "N/A")
        ml_conf = asset.get("ml_confidence_pct") or (float(asset.get("ml_summary", {}).get("confidence", 0)) * 100.0)
        hndl_s = asset.get("hndl_summary", {})
        mosca_s = asset.get("mosca_summary", {})
        deficit_val = float(mosca_s.get("deficit_years", 0.0))

        if pqc in ("PQC_NATIVE", "HYBRID_PQC", "SYMMETRIC_QUANTUM_RESILIENT") or not asset.get("migration_required"):
            mosca_metric_str = f"ΔM: N/A ({deadline_display})"
        elif deficit_val > 0.0:
            mosca_metric_str = f"Timeline Deficit: +{deficit_val:.1f}y ({deadline_display})"
        elif deficit_val < 0.0:
            mosca_metric_str = f"Timeline Margin: {abs(deficit_val):.1f}y (ΔM = {deficit_val:+.1f}y) ({deadline_display})"
        else:
            mosca_metric_str = f"ΔM: 0.0y (Exact Boundary) ({deadline_display})"

        score_details = f"{tier} (Score: {score:.1f}/100, Base: {base_class}, Urgency: {urgency})"
        lines.extend([
            f"Asset ID: {aid} | Algorithm: {algo}",
            f"• PQC Classification: {pqc} (Migration Required: {mig_req})",
            f"• Unified Risk:       {score_details}",
        ])
        if policy_overrides:
            lines.append(f"• Policy Overrides:   {policy_overrides[0]}")
        lines.extend([
            f"• Primary Driver:     {driver}",
            f"• Pillar Metrics:",
            f"  - [ML Risk Model]:  {ml_pred} (Confidence: {ml_conf:.1f}%)",
            f"  - [HNDL Engine]:    Exposure Score: {hndl_s.get('hndl_exposure_score', 0.0):.2f} ({hndl_s.get('future_decryption_risk')})",
            f"  - [Mosca Theorem]:  {mosca_metric_str}",
            f"• Action Required:    {action}",
            "-" * 70,
        ])

    return "\n".join(lines)
