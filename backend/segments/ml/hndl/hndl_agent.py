"""
HNDL Agent Orchestrator (hndl_agent.py)

Orchestrates Harvest Now, Decrypt Later (HNDL) risk evaluations for individual CBOM assets
and full CBOM documents using deterministic mathematical calculations and configurable scenario assumptions.
"""

from typing import Dict, Any, List, Optional, Union
from .timeline_engine import HNDLTimelineEngine
from .validator import HNDLValidator
from .explainability import HNDLExplainabilityBuilder


def format_hndl_terminal_report(
    cbom_asset: Dict[str, Any], risk_context: Optional[Dict[str, Any]] = None, hndl_result: Optional[Dict[str, Any]] = None
) -> str:
    """
    Formats a human-readable terminal demonstration report for an HNDL assessment.
    """
    res = hndl_result or {}
    asset_id = res.get("asset_id") or cbom_asset.get("asset_id") or cbom_asset.get("id") or "N/A"
    algo_name = res.get("algorithm") or cbom_asset.get("algorithm") or cbom_asset.get("name") or "N/A"

    hndl_body = res.get("hndl") or {}
    timeline = hndl_body.get("timeline") or {}
    threats = hndl_body.get("threat_vectors") or {}
    assumptions = hndl_body.get("assumptions") or {}

    applicable_str = "YES" if hndl_body.get("applicable") else "NO"
    score_str = f"{hndl_body.get('hndl_exposure_score', 0.0):.4f}"
    urgency = str(hndl_body.get("urgency_tier", "NEGLIGIBLE")).upper()
    harvestability = str(hndl_body.get("harvestability", "LOW")).upper()
    future_risk = str(hndl_body.get("future_decryption_risk", "NEGLIGIBLE")).upper()

    lifetime = timeline.get("data_lifetime_years", 0.0)
    expiry = timeline.get("data_expiry_year", "N/A")
    horizon = assumptions.get("quantum_horizon_year", 2033)
    window = timeline.get("exposure_window_years", 0.0)

    s_crypto = threats.get("crypto_susceptibility", 0.0)
    s_harvest = threats.get("harvestability_score", 0.0)
    m_impact = threats.get("impact_multiplier", 0.0)
    pfs_status = threats.get("pfs_status", "UNKNOWN")

    reason = hndl_body.get("reason", "N/A")
    mitigation = hndl_body.get("mitigation_priority", "N/A")

    report = f"""============================================================
HNDL — HARVEST NOW, DECRYPT LATER ASSESSMENT
============================================================

Asset ID:               {asset_id}
Algorithm:              {algo_name}
HNDL Applicable:        {applicable_str}
HNDL Exposure Score:    {score_str} (Urgency: {urgency})

Timeline Scenario:
• Assessment Year:      {timeline.get('assessment_year', 2026)}
• Data Lifetime:        {lifetime} years (Confidentiality Expires: {expiry})
• Quantum Horizon:      {horizon} ({assumptions.get('quantum_horizon_type', 'SCENARIO_ASSUMPTION')} - {assumptions.get('quantum_horizon_source', 'CONFIGURATION')})
• Exposure Window:      {window} years (Compromised While Sensitive: {'YES' if timeline.get('compromised_while_sensitive') else 'NO'})

Threat Vectors:
• Crypto Susceptibility: {s_crypto:.2f}
• Harvestability:        {s_harvest:.2f} ({harvestability})
• PFS Status:            {pfs_status}
• Impact Multiplier:     {m_impact:.2f}

Assessment Findings:
• Future Decrypt Risk:   {future_risk}
• Reason:                {reason}
• Action Plan:           {mitigation}

============================================================"""
    return report.strip()


class HNDLAgent:
    """
    Agent for deterministic Harvest Now, Decrypt Later threat assessments.
    """

    DEFAULT_QUANTUM_HORIZON_YEAR = 2033
    DEFAULT_ASSESSMENT_YEAR = 2026

    def __init__(
        self,
        default_quantum_horizon_year: int = DEFAULT_QUANTUM_HORIZON_YEAR,
        default_assessment_year: int = DEFAULT_ASSESSMENT_YEAR,
        provider: Optional[Any] = None,
        **kwargs,
    ):
        self.default_quantum_horizon_year = default_quantum_horizon_year
        self.default_assessment_year = default_assessment_year
        self.provider = provider
        self.engine = HNDLTimelineEngine()
        self.validator = HNDLValidator()

    def analyze(
        self,
        cbom_asset: Dict[str, Any],
        risk_context: Optional[Dict[str, Any]] = None,
        operational_context: Optional[Dict[str, Any]] = None,
        quantum_horizon_year: Optional[int] = None,
        assessment_year: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates a single CBOM asset against operational risk context and deterministic HNDL rules.

        :param cbom_asset: CBOM Cryptographic Asset dictionary.
        :param risk_context: Operational system and data context dictionary.
        :param operational_context: Alias for risk_context.
        :param quantum_horizon_year: Optional override for quantum threat arrival scenario.
        :param assessment_year: Optional override for current assessment year.
        :return: Validated HNDL asset assessment dictionary.
        """
        ctx = operational_context if operational_context is not None else (risk_context if isinstance(risk_context, dict) else {})

        # 1. Input Validation
        is_valid, errs = self.validator.validate_inputs(cbom_asset, ctx)
        if not is_valid:
            raise ValueError(f"HNDL input validation failed: {errs}")

        # 2. Extract and Normalize Asset & Context Attributes
        asset_id = str(cbom_asset.get("asset_id") or cbom_asset.get("id") or cbom_asset.get("name") or "UNKNOWN")
        algo_data = cbom_asset.get("algorithm")
        family = str(cbom_asset.get("family") or "").lower()
        if isinstance(algo_data, dict):
            algo_name = str(algo_data.get("name") or algo_data.get("algorithm") or cbom_asset.get("name") or "Unknown-Algorithm")
            if not family:
                family = str(algo_data.get("family") or "").lower()
        else:
            algo_name = str(algo_data or cbom_asset.get("name") or "Unknown-Algorithm")

        crypto_role = str(cbom_asset.get("crypto_role") or cbom_asset.get("purpose") or "").lower()
        
        params = cbom_asset.get("parameters", {}) if isinstance(cbom_asset.get("parameters"), dict) else {}
        key_size = params.get("key_size") or cbom_asset.get("key_size")
        curve = params.get("curve") or cbom_asset.get("curve")
        protocol = str(cbom_asset.get("protocol") or ctx.get("protocol") or "")

        # Extract context attributes (supporting flat and nested legacy contexts)
        data_ctx = ctx.get("data_context") if isinstance(ctx.get("data_context"), dict) else {}
        net_ctx = ctx.get("network_context") if isinstance(ctx.get("network_context"), dict) else {}

        lifetime_val = ctx.get("data_lifetime_years", data_ctx.get("data_lifetime_years", 5.0))
        data_lifetime = float(lifetime_val) if lifetime_val is not None else 5.0

        raw_sensitivity = ctx.get("data_sensitivity", data_ctx.get("sensitivity", 3))
        if isinstance(raw_sensitivity, str):
            sens_upper = raw_sensitivity.upper()
            data_sensitivity = self.validator.SENSITIVITY_MAP.get(sens_upper, 3) if not sens_upper.isdigit() else int(sens_upper)
        else:
            data_sensitivity = int(raw_sensitivity) if raw_sensitivity is not None else 3

        business_crit = int(ctx.get("business_criticality", 3))

        internet_exp = bool(ctx.get("internet_exposed", net_ctx.get("internet_exposed", False)))
        external_fac = bool(ctx.get("external_facing", False))
        is_collectable = net_ctx.get("collectable", True)
        data_at_rest = bool(ctx.get("data_at_rest", not is_collectable if not internet_exp else False))
        data_in_transit = bool(ctx.get("data_in_transit", is_collectable and not data_at_rest))
        lack_of_pfs = ctx.get("lack_of_pfs", "UNKNOWN")

        # Scenario Parameter Resolution
        if quantum_horizon_year is not None:
            horizon_year = int(quantum_horizon_year)
            horizon_source = "USER_OVERRIDE"
        elif ctx.get("quantum_horizon_year") is not None:
            horizon_year = int(ctx["quantum_horizon_year"])
            horizon_source = "USER_OVERRIDE"
        else:
            horizon_year = self.default_quantum_horizon_year
            horizon_source = "CONFIGURATION"

        assess_year = int(assessment_year or ctx.get("assessment_year") or self.default_assessment_year)

        assumptions = {
            "quantum_horizon_year": horizon_year,
            "quantum_horizon_type": "SCENARIO_ASSUMPTION",
            "quantum_horizon_source": horizon_source,
            "assessment_year": assess_year,
        }

        # Strict Input Assessability Check (HNDL Input Validation Boundary)
        is_assessable, unassessable_reason = self.validator.check_hndl_assessability(cbom_asset, ctx)
        if not is_assessable or (family == "unknown" or "CUSTOM" in algo_name.upper() or "UNKNOWN" in algo_name.upper()):
            reason = f"HNDL exposure is NOT_ASSESSABLE for '{algo_name}' because: {unassessable_reason}."
            timeline_metrics = {
                "assessment_year": assess_year,
                "data_lifetime_years": None,
                "data_expiry_year": "NOT_ASSESSABLE",
                "quantum_horizon_year": horizon_year,
                "exposure_window_years": 0.0,
                "compromised_while_sensitive": False,
                "timeline_factor": 0.0,
            }
            return {
                "asset_id": asset_id,
                "algorithm": algo_name,
                "hndl": {
                    "applicable": False,
                    "evidence_status": "NOT_ASSESSABLE",
                    "hndl_exposure_score": 0.0,
                    "urgency_tier": "NOT_ASSESSABLE",
                    "harvestability": "NOT_ASSESSABLE",
                    "quantum_vulnerable": None,
                    "future_decryption_risk": "NOT_ASSESSABLE",
                    "data_lifetime_years": None,
                    "timeline": timeline_metrics,
                    "threat_vectors": {
                        "crypto_susceptibility": 0.0,
                        "harvestability_score": 0.0,
                        "impact_multiplier": 0.0,
                        "pfs_status": "NOT_ASSESSABLE",
                    },
                    "assumptions": assumptions,
                    "reason": reason,
                    "mitigation_priority": "NOT_ASSESSABLE",
                },
            }

        # 3. Deterministic Engine Computations
        # Vector A: Crypto Susceptibility
        s_crypto, qv = self.engine.calculate_crypto_susceptibility(
            algorithm_name=algo_name,
            family=family,
            crypto_role=crypto_role,
            key_size=key_size,
            curve=curve,
        )

        # Vector B: Harvestability
        s_harvest, harvest_tier, pfs_status = self.engine.calculate_harvestability_score(
            internet_exposed=internet_exp,
            external_facing=external_fac,
            data_in_transit=data_in_transit,
            data_at_rest=data_at_rest,
            lack_of_pfs=lack_of_pfs,
            protocol=protocol,
        )

        # Vector C: Timeline
        timeline_metrics = self.engine.calculate_timeline_metrics(
            assessment_year=assess_year,
            data_lifetime_years=data_lifetime,
            quantum_horizon_year=horizon_year,
        )

        # Vector D: Impact Multiplier
        m_impact = self.engine.calculate_impact_multiplier(
            data_sensitivity=data_sensitivity,
            business_criticality=business_crit,
        )

        # Composite HNDL Score
        timeline_factor = timeline_metrics["timeline_factor"]
        hndl_score = self.engine.calculate_composite_hndl_score(
            s_crypto=s_crypto,
            s_harvest=s_harvest,
            timeline_factor=timeline_factor,
            m_impact=m_impact,
        )

        # Applicability, Urgency & Risk Tiers
        applicable, urgency_tier, future_risk = self.engine.determine_applicability_and_urgency(
            hndl_score=hndl_score,
            s_crypto=s_crypto,
            s_harvest=s_harvest,
            timeline_metrics=timeline_metrics,
            data_sensitivity=data_sensitivity,
        )

        # Mitigation Priority
        mitigation_priority = self.engine.determine_mitigation_priority(
            urgency_tier=urgency_tier,
            algorithm_name=algo_name,
            crypto_role=crypto_role,
        )

        # 4. Deterministic Explainability Rationale
        reason = HNDLExplainabilityBuilder.build_explanation(
            algorithm_name=algo_name,
            crypto_role=crypto_role,
            s_crypto=s_crypto,
            s_harvest=s_harvest,
            timeline_metrics=timeline_metrics,
            m_impact=m_impact,
            hndl_score=hndl_score,
            applicable=applicable,
            assumptions=assumptions,
            pfs_status=pfs_status,
        )

        # Evidence Quality and Context Completeness Evaluation
        has_operational_context = True
        evidence_status = "ASSESSED"
        qv_val = qv
        if not applicable or s_harvest == 0.0 or harvest_tier == "LOW":
            future_risk_val = "LOW" if (s_crypto > 0.0 and qv_val) else "NEGLIGIBLE"
        elif future_risk == "CRITICAL" and data_sensitivity >= 4:
            future_risk_val = "HIGH"
        elif future_risk == "NEGLIGIBLE" and s_crypto > 0.0:
            future_risk_val = "LOW"
        else:
            future_risk_val = future_risk

        qv_val = None if (family == "unknown" or "CUSTOM" in algo_name.upper() or "UNKNOWN" in algo_name.upper()) else qv

        assessment_result = {
            "asset_id": asset_id,
            "algorithm": algo_name,
            "hndl": {
                "applicable": applicable,
                "evidence_status": evidence_status,
                "hndl_exposure_score": hndl_score if evidence_status == "ASSESSED" else 0.0,
                "urgency_tier": urgency_tier,
                "harvestability": harvest_tier if has_operational_context else "UNKNOWN",
                "quantum_vulnerable": qv_val,
                "future_decryption_risk": future_risk_val,
                "data_lifetime_years": data_lifetime if has_operational_context else None,
                "timeline": timeline_metrics,
                "threat_vectors": {
                    "crypto_susceptibility": s_crypto,
                    "harvestability_score": s_harvest,
                    "impact_multiplier": m_impact,
                    "pfs_status": pfs_status,
                },
                "assumptions": assumptions,
                "reason": reason,
                "mitigation_priority": mitigation_priority,
            },
        }

        # 5. Output Validation
        out_valid, out_errs = self.validator.validate_output(assessment_result, expected_asset_id=asset_id)
        if not out_valid:
            raise ValueError(f"Generated HNDL output failed schema validation: {out_errs}")

        return assessment_result

    def assess_cbom(
        self,
        cbom_doc: Dict[str, Any],
        risk_context: Optional[Dict[str, Any]] = None,
        quantum_horizon_year: Optional[int] = None,
        assessment_year: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Assesses an entire CBOM document (ECDAT or CycloneDX 1.6) and produces per-asset
        HNDL assessments and an aggregated application-level posture summary.

        :param cbom_doc: Input CBOM document dictionary.
        :param risk_context: Operational system and data context dictionary.
        :param quantum_horizon_year: Optional scenario quantum threat arrival year.
        :param assessment_year: Optional baseline assessment year.
        :return: Aggregated HNDL summary dictionary including per-asset assessments.
        """
        assets = cbom_doc.get("crypto_assets")
        if not assets and "components" in cbom_doc:
            assets = cbom_doc.get("components", [])

        if not isinstance(assets, list):
            assets = []

        asset_reports: List[Dict[str, Any]] = []
        tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NEGLIGIBLE": 0}
        applicable_count = 0
        max_score = 0.0

        for asset in assets:
            if not isinstance(asset, dict):
                continue
            rep = self.analyze(
                cbom_asset=asset,
                risk_context=risk_context,
                quantum_horizon_year=quantum_horizon_year,
                assessment_year=assessment_year,
            )
            asset_reports.append(rep)

            hndl_data = rep.get("hndl", {})
            tier = hndl_data.get("urgency_tier", "NEGLIGIBLE")
            if tier in tier_counts:
                tier_counts[tier] += 1
            if hndl_data.get("applicable"):
                applicable_count += 1
            score = hndl_data.get("hndl_exposure_score", 0.0)
            if score > max_score:
                max_score = score

        # Determine overall posture
        if tier_counts["CRITICAL"] > 0:
            overall_posture = "CRITICAL"
        elif tier_counts["HIGH"] > 0:
            overall_posture = "HIGH"
        elif tier_counts["MEDIUM"] > 0:
            overall_posture = "MEDIUM"
        elif tier_counts["LOW"] > 0:
            overall_posture = "LOW"
        else:
            overall_posture = "NEGLIGIBLE"

        horizon = quantum_horizon_year or (risk_context or {}).get("quantum_horizon_year") or self.default_quantum_horizon_year
        source = "USER_OVERRIDE" if (quantum_horizon_year or (risk_context or {}).get("quantum_horizon_year")) else "CONFIGURATION"
        assess_yr = assessment_year or (risk_context or {}).get("assessment_year") or self.default_assessment_year

        summary = {
            "assessment_year": assess_yr,
            "total_assessed_assets": len(asset_reports),
            "applicable_assets_count": applicable_count,
            "overall_hndl_posture": overall_posture,
            "max_hndl_exposure_score": round(max_score, 4),
            "by_urgency_tier": tier_counts,
            "assumptions": {
                "quantum_horizon_year": horizon,
                "quantum_horizon_type": "SCENARIO_ASSUMPTION",
                "quantum_horizon_source": source,
                "assessment_year": assess_yr,
            },
            "asset_assessments": asset_reports,
        }

        # Also write back into cbom_doc for pipeline compatibility
        cbom_doc["hndl_summary"] = summary

        return summary
