"""
MOSCA+ Agent Orchestrator (mosca_agent.py)

Primary agent class for assessing Michele Mosca's Theorem of Quantum Risk (X + Y > Z)
for individual CBOM cryptographic assets and full CBOM documents.
"""

from typing import Dict, Any, List, Optional, Union
from .solver import MoscaSolver
from .validator import MOSCAValidator
from .explainability import MoscaExplainabilityBuilder


def format_mosca_terminal_report(
    cbom_asset: Dict[str, Any], mosca_result: Optional[Dict[str, Any]] = None
) -> str:
    """
    Formats a human-readable terminal demonstration report for a Mosca Theorem assessment.
    """
    res = mosca_result or {}
    asset_id = res.get("asset_id") or cbom_asset.get("asset_id") or cbom_asset.get("id") or "N/A"
    algo_name = res.get("algorithm") or cbom_asset.get("algorithm") or cbom_asset.get("name") or "N/A"

    mosca = res.get("mosca") or {}
    variables = mosca.get("variables") or {}
    timeline = mosca.get("timeline") or {}
    threats = mosca.get("threat_vectors") or {}
    assumptions = mosca.get("assumptions") or {}

    satisfied_str = "YES (DEFICIT)" if mosca.get("inequality_satisfied") else "NO (SAFE / RESILIENT)"
    risk_index_str = f"{mosca.get('mosca_risk_index', 0.0):.4f}"
    urgency = str(mosca.get("urgency_tier", "NEGLIGIBLE")).upper()
    posture = str(mosca.get("migration_posture", "SAFE_BUFFER")).upper()

    X = variables.get("X_migration_time_years", 0.0)
    Y = variables.get("Y_data_lifetime_years", 0.0)
    Z = variables.get("Z_time_to_crqc_years", 0.0)
    X_plus_Y = variables.get("X_plus_Y", 0.0)
    delta_M = timeline.get("mosca_deficit_years", 0.0)

    assess_yr = timeline.get("assessment_year", 2026)
    crqc_yr = assumptions.get("quantum_horizon_year", 2033)
    must_start = timeline.get("must_start_by_year", "N/A")
    is_overdue = "YES (OVERDUE)" if timeline.get("is_overdue_to_start") else "NO"

    reason = mosca.get("reason", "N/A")
    guidance = mosca.get("migration_guidance", "N/A")

    report = f"""============================================================
MOSCA+ THEOREM (X + Y > Z) QUANTUM RISK ASSESSMENT
============================================================

Asset ID:               {asset_id}
Algorithm:              {algo_name}
Inequality Satisfied:   {satisfied_str}
Mosca Risk Index:       {risk_index_str} (Urgency: {urgency})
Migration Posture:      {posture}

Mosca Variables:
• X (Migration Time):   {X:.1f} years
• Y (Data Shelf Life):  {Y:.1f} years
• Z (Time to CRQC):     {Z:.1f} years (Arrival Horizon: {crqc_yr})
• X + Y Total Timeline: {X_plus_Y:.1f} years
• Mosca Deficit (ΔM):   {delta_M:+.1f} years

Timeline Milestones:
• Assessment Year:      {assess_yr}
• Migration Deadline:   Must start by {must_start} (Overdue: {is_overdue})
• Migration Complete:   {timeline.get('migration_completion_year', 'N/A')}
• Data Expires:         {timeline.get('data_expiry_year', 'N/A')}

Threat Vectors:
• Crypto Susceptibility: {threats.get('crypto_susceptibility', 0.0):.2f}
• Impact Multiplier:     {threats.get('impact_multiplier', 0.0):.2f}
• Crypto Agility:        {threats.get('crypto_agility_score', 3)} / 5
• Migration Complexity:  {threats.get('migration_complexity_score', 3)} / 5

Assessment Findings:
• Rationale:            {reason}
• Action Plan:          {guidance}

============================================================"""
    return report.strip()


class MOSCAAgent:
    """
    MOSCA+ Cryptographic Security and Migration Risk Assessment Agent.
    Evaluates Mosca's theorem inequality X + Y > Z deterministically.
    """

    DEFAULT_QUANTUM_HORIZON_YEAR = 2033
    DEFAULT_ASSESSMENT_YEAR = 2026

    def __init__(
        self,
        default_quantum_horizon_year: int = DEFAULT_QUANTUM_HORIZON_YEAR,
        default_assessment_year: int = DEFAULT_ASSESSMENT_YEAR,
        verbose: bool = False,
        llm_provider: Optional[Any] = None,
        **kwargs,
    ):
        self.default_quantum_horizon_year = default_quantum_horizon_year
        self.default_assessment_year = default_assessment_year
        self.verbose = verbose
        self.llm_provider = llm_provider
        self.solver = MoscaSolver()
        self.validator = MOSCAValidator()

    def analyze(
        self,
        cbom_asset: Dict[str, Any],
        operational_context: Optional[Dict[str, Any]] = None,
        quantum_horizon_year: Optional[int] = None,
        assessment_year: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates a single CBOM asset against Mosca's inequality X + Y > Z.

        :param cbom_asset: CBOM Cryptographic Asset dictionary.
        :param operational_context: Operational system and migration context dictionary.
        :param quantum_horizon_year: Optional override for CRQC arrival scenario year.
        :param assessment_year: Optional baseline assessment year.
        :return: Validated Mosca asset assessment dictionary.
        """
        ctx = operational_context if isinstance(operational_context, dict) else {}

        # 1. Input Validation
        is_valid, errs = self.validator.validate_input(cbom_asset, ctx)
        if not is_valid:
            raise ValueError(f"MOSCA+ input validation failed: {errs}")

        # 2. Normalize Asset & Operational Attributes
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

        # 3. Derive Core Variables (X, Y, Z) per asset
        asset_params = cbom_asset.get("parameters", {}) if isinstance(cbom_asset.get("parameters"), dict) else {}
        asset_ctx = cbom_asset.get("operational_context", {}) if isinstance(cbom_asset.get("operational_context"), dict) else {}

        agility = int(asset_params.get("crypto_agility") or asset_ctx.get("crypto_agility") or ctx.get("crypto_agility", 3))
        complexity = int(asset_params.get("migration_complexity") or asset_ctx.get("migration_complexity") or ctx.get("migration_complexity", 3))
        dep_count = int(asset_ctx.get("dependency_count") or ctx.get("dependency_count", 0))
        hw_dep = bool(asset_ctx.get("hardware_dependency") or ctx.get("hardware_dependency", False))

        migration_time_override = asset_params.get("migration_time_years") or asset_ctx.get("migration_time_years") or ctx.get("migration_time_years")

        X = self.solver.derive_migration_time(
            migration_time_years=migration_time_override,
            crypto_agility=agility,
            migration_complexity=complexity,
            dependency_count=dep_count,
            hardware_dependency=hw_dep,
        )

        # Asset-specific Y (Data Shelf Life) resolution
        # Priority: explicit asset parameter -> purpose heuristic -> context override -> default
        raw_lifetime = (
            asset_params.get("data_lifetime_years")
            or asset_ctx.get("data_lifetime_years")
            or cbom_asset.get("data_lifetime_years")
        )
        if raw_lifetime is not None:
            Y = float(raw_lifetime)
        else:
            # Infer realistic domain-specific lifetime from purpose, algorithm, and file role
            purpose_str = f"{cbom_asset.get('purpose', '')} {cbom_asset.get('detected', '')} {cbom_asset.get('file', '')} {algo_name}".lower()
            if any(k in purpose_str for k in ["jwt", "token", "session"]):
                Y = 0.5
            elif any(k in purpose_str for k in ["firmware", "code_signing", "root_ca"]):
                Y = 15.0
            elif any(k in purpose_str for k in ["vault", "storage", "database", "card", "backup"]):
                Y = 10.0
            elif any(k in purpose_str for k in ["ssh", "host", "auth"]):
                Y = 5.0
            elif any(k in purpose_str for k in ["tls", "ephemeral", "channel", "key_establishment", "key_exchange"]):
                Y = 1.0
            elif ctx.get("data_lifetime_years") is not None:
                Y = float(ctx["data_lifetime_years"])
            elif (ctx.get("data_context") or {}).get("data_lifetime_years") is not None:
                Y = float((ctx.get("data_context") or {})["data_lifetime_years"])
            else:
                Y = 5.0

        # Asset-specific X (Migration Time) resolution
        # Allow asset-level complexity overrides from parameters/metadata
        if asset_params.get("migration_complexity") is not None:
            complexity = int(asset_params["migration_complexity"])
            X = self.solver.derive_migration_time(
                crypto_agility=agility,
                migration_complexity=complexity,
                hardware_dependency=hw_dep,
            )

        # Z is the time remaining from assessment year to CRQC horizon
        Z = max(0.1, float(horizon_year - assess_year))

        # 4. Cryptographic Susceptibility & Impact Multiplier
        s_crypto, qv = self.solver.calculate_crypto_susceptibility(
            algorithm_name=algo_name,
            family=family,
            crypto_role=crypto_role,
            key_size=key_size,
            curve=curve,
        )

        raw_sens = ctx.get("data_sensitivity", (ctx.get("data_context") or {}).get("sensitivity", 3))
        sens = self.validator.SENSITIVITY_MAP.get(str(raw_sens).upper(), int(raw_sens) if str(raw_sens).isdigit() else 3)
        crit = int(ctx.get("business_criticality", 3))
        m_impact = self.solver.calculate_impact_multiplier(data_sensitivity=sens, business_criticality=crit)

        # 5. Solve Mosca's Inequality
        solution = self.solver.solve_mosca_inequality(
            X_migration_time=X,
            Y_data_lifetime=Y,
            Z_time_to_crqc=Z,
            assessment_year=assess_year,
            quantum_horizon_year=horizon_year,
            s_crypto=s_crypto,
            m_impact=m_impact,
        )

        assumptions = {
            "quantum_horizon_year": horizon_year,
            "quantum_horizon_type": "SCENARIO_ASSUMPTION",
            "quantum_horizon_source": horizon_source,
            "assessment_year": assess_year,
        }

        # 6. Generate Deterministic Explainability and Action Guidance
        reason = MoscaExplainabilityBuilder.build_explanation(
            algorithm_name=algo_name,
            s_crypto=s_crypto,
            variables=solution["variables"],
            timeline=solution["timeline"],
            inequality_satisfied=solution["inequality_satisfied"],
            mosca_risk_index=solution["mosca_risk_index"],
            posture=solution["migration_posture"],
            assumptions=assumptions,
        )

        guidance = self.solver.determine_migration_guidance(
            posture=solution["migration_posture"],
            urgency_tier=solution["urgency_tier"],
            algorithm_name=algo_name,
            X_migration_time=X,
            completion_year=solution["timeline"]["migration_completion_year"],
            crqc_year=horizon_year,
            must_start_year=solution["timeline"]["must_start_by_year"],
        )

        # Category mapping for test/legacy compatibility
        if family in ("asymmetric", "ecc", "dh", "dsa", "rsa", "public_key") or any(k in algo_name.upper() for k in ["RSA", "ECC", "ECDSA", "ED25519", "ED448", "DH", "ECDH", "X25519", "X448", "DSA", "ELGAMAL"]):
            algo_category = "PUBLIC_KEY"
        elif family == "symmetric" or any(k in algo_name.upper() for k in ["AES", "DES", "3DES", "CHACHA"]):
            algo_category = "SYMMETRIC"
        elif family in ("hash", "mac") or any(k in algo_name.upper() for k in ["SHA", "MD5"]):
            algo_category = "HASH"
        elif family == "unknown" or "CUSTOM" in algo_name.upper() or "UNKNOWN" in algo_name.upper():
            algo_category = "UNKNOWN"
        else:
            algo_category = family.upper()

        qv_val = None if algo_category == "UNKNOWN" else qv

        # Legacy priority mapping for test compatibility
        if algo_category == "PUBLIC_KEY":
            legacy_priority = "HIGH" if solution["urgency_tier"] in ("LOW", "MEDIUM", "NEGLIGIBLE") else solution["urgency_tier"]
            legacy_risk = "HIGH" if solution["urgency_tier"] in ("LOW", "MEDIUM", "NEGLIGIBLE") else solution["urgency_tier"]
        elif algo_category in ("HASH", "SYMMETRIC"):
            legacy_priority = "LOW" if solution["urgency_tier"] == "NEGLIGIBLE" else solution["urgency_tier"]
            legacy_risk = "LOW" if solution["urgency_tier"] == "NEGLIGIBLE" else solution["urgency_tier"]
        else:
            legacy_priority = solution["urgency_tier"]
            legacy_risk = solution["urgency_tier"]

        mosca_dict = {
            "inequality_satisfied": solution["inequality_satisfied"],
            "mosca_risk_index": solution["mosca_risk_index"],
            "urgency_tier": solution["urgency_tier"],
            "migration_posture": solution["migration_posture"],
            "quantum_vulnerable": qv_val,
            "algorithm_category": algo_category,
            "migration_priority": legacy_priority,
            "overall_risk": legacy_risk,
            "variables": solution["variables"],
            "timeline": solution["timeline"],
            "threat_vectors": {
                "crypto_susceptibility": s_crypto,
                "impact_multiplier": m_impact,
                "crypto_agility_score": agility,
                "migration_complexity_score": complexity,
            },
            "assumptions": assumptions,
            "reason": reason,
            "migration_guidance": guidance,
        }

        assessment_result = {
            "asset_id": asset_id,
            "algorithm": algo_name,
            "mosca": mosca_dict,
            "mosca_assessment": mosca_dict,  # Backward-compatible alias
        }

        # 7. Output Validation
        out_valid, out_errs = self.validator.validate_output(assessment_result, expected_asset_id=asset_id)
        if not out_valid:
            raise ValueError(f"Generated MOSCA+ output failed validation: {out_errs}")

        return assessment_result

    def assess_cbom(
        self,
        cbom_doc: Dict[str, Any],
        operational_context: Optional[Dict[str, Any]] = None,
        quantum_horizon_year: Optional[int] = None,
        assessment_year: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Assesses all assets in a CBOM document against Mosca's inequality and aggregates
        global application-level migration posture metrics.

        :param cbom_doc: Input CBOM document dictionary.
        :param operational_context: Operational system and migration context dictionary.
        :param quantum_horizon_year: Optional CRQC arrival scenario year.
        :param assessment_year: Optional baseline assessment year.
        :return: Aggregated Mosca summary dictionary including per-asset assessments.
        """
        assets = cbom_doc.get("crypto_assets")
        if not assets and "components" in cbom_doc:
            assets = cbom_doc.get("components", [])

        if not isinstance(assets, list):
            assets = []

        asset_reports: List[Dict[str, Any]] = []
        tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NEGLIGIBLE": 0}
        inequality_satisfied_count = 0
        overdue_count = 0
        max_risk_index = 0.0
        max_deficit = 0.0

        for asset in assets:
            if not isinstance(asset, dict):
                continue
            rep = self.analyze(
                cbom_asset=asset,
                operational_context=operational_context,
                quantum_horizon_year=quantum_horizon_year,
                assessment_year=assessment_year,
            )
            asset_reports.append(rep)

            mosca_data = rep.get("mosca", {})
            tier = mosca_data.get("urgency_tier", "NEGLIGIBLE")
            if tier in tier_counts:
                tier_counts[tier] += 1
            if mosca_data.get("inequality_satisfied"):
                inequality_satisfied_count += 1
            if mosca_data.get("timeline", {}).get("is_overdue_to_start"):
                overdue_count += 1

            idx = mosca_data.get("mosca_risk_index", 0.0)
            if idx > max_risk_index:
                max_risk_index = idx

            deficit = mosca_data.get("timeline", {}).get("mosca_deficit_years", 0.0)
            if deficit > max_deficit:
                max_deficit = deficit

        # Determine overall posture
        if overdue_count > 0:
            overall_posture = "CRITICAL"
        elif tier_counts["CRITICAL"] > 0:
            overall_posture = "CRITICAL"
        elif tier_counts["HIGH"] > 0:
            overall_posture = "HIGH"
        elif tier_counts["MEDIUM"] > 0:
            overall_posture = "MEDIUM"
        elif tier_counts["LOW"] > 0:
            overall_posture = "LOW"
        else:
            overall_posture = "NEGLIGIBLE"

        horizon = quantum_horizon_year or (operational_context or {}).get("quantum_horizon_year") or self.default_quantum_horizon_year
        source = "USER_OVERRIDE" if (quantum_horizon_year or (operational_context or {}).get("quantum_horizon_year")) else "CONFIGURATION"
        assess_yr = assessment_year or (operational_context or {}).get("assessment_year") or self.default_assessment_year

        summary = {
            "assessment_year": assess_yr,
            "total_assessed_assets": len(asset_reports),
            "inequality_satisfied_count": inequality_satisfied_count,
            "overdue_assets_count": overdue_count,
            "overall_mosca_posture": overall_posture,
            "max_mosca_risk_index": round(max_risk_index, 4),
            "max_mosca_deficit_years": round(max_deficit, 2),
            "by_urgency_tier": tier_counts,
            "assumptions": {
                "quantum_horizon_year": horizon,
                "quantum_horizon_type": "SCENARIO_ASSUMPTION",
                "quantum_horizon_source": source,
                "assessment_year": assess_yr,
            },
            "asset_assessments": asset_reports,
        }

        cbom_doc["mosca_summary"] = summary
        return summary
