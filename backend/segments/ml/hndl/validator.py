"""
HNDL Input and Output Validator (validator.py)

Validates CBOM assets, operational risk contexts, numerical ranges, and generated
HNDL assessment structures without modifying raw data.
"""

from typing import Dict, Any, Tuple, List, Optional


class HNDLValidator:
    """
    Validates inputs and outputs for HNDL risk assessment pipeline.
    """

    ALLOWED_URGENCY_TIERS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INSUFFICIENT_CONTEXT", "NOT_ASSESSABLE", "UNKNOWN"}
    ALLOWED_HARVEST_TIERS = {"HIGH", "MEDIUM", "LOW", "UNKNOWN", "NOT_ASSESSABLE"}
    SENSITIVITY_MAP = {"LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

    def validate_inputs(
        self, cbom_asset: Dict[str, Any], risk_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validates input CBOM asset and risk context dictionaries.

        :param cbom_asset: Input CBOM Cryptographic Asset dictionary.
        :param risk_context: Input operational context dictionary.
        :return: Tuple (is_valid: bool, list_of_error_messages)
        """
        errors: List[str] = []

        if not isinstance(cbom_asset, dict):
            return False, ["CBOM asset must be a dictionary."]

        ctx = risk_context if isinstance(risk_context, dict) else {}

        # 1. Validate CBOM Asset Required Fields
        asset_id = cbom_asset.get("asset_id") or cbom_asset.get("id") or cbom_asset.get("name")
        if not asset_id or not isinstance(asset_id, str):
            errors.append("CBOM asset missing required identifier (asset_id or id).")

        algorithm = cbom_asset.get("algorithm") or cbom_asset.get("name")
        if not algorithm:
            errors.append("CBOM asset missing required field 'algorithm'.")

        # 2. Validate Risk Context Fields (Supports both nested and flat structures)
        # Data Lifetime Validation
        lifetime = ctx.get("data_lifetime_years")
        if lifetime is None and "data_context" in ctx and isinstance(ctx["data_context"], dict):
            lifetime = ctx["data_context"].get("data_lifetime_years")

        if lifetime is not None:
            try:
                val = float(lifetime)
                if val < 0.0:
                    errors.append("Invalid data_lifetime_years: cannot be negative.")
            except (ValueError, TypeError):
                errors.append(f"Invalid data_lifetime_years '{lifetime}': must be numeric.")

        # Data Sensitivity Validation
        sensitivity = ctx.get("data_sensitivity")
        if sensitivity is None and "data_context" in ctx and isinstance(ctx["data_context"], dict):
            sensitivity = ctx["data_context"].get("sensitivity")

        if sensitivity is not None:
            if isinstance(sensitivity, str):
                s_upper = sensitivity.upper()
                if s_upper not in self.SENSITIVITY_MAP and not s_upper.isdigit():
                    errors.append(f"Invalid data_sensitivity '{sensitivity}'. Allowed: 1-5 or LOW, MEDIUM, HIGH, CRITICAL.")
                elif s_upper.isdigit():
                    int_val = int(s_upper)
                    if int_val < 1 or int_val > 5:
                        errors.append(f"Invalid data_sensitivity {int_val}: must be between 1 and 5.")
            elif isinstance(sensitivity, (int, float)):
                int_val = int(sensitivity)
                if int_val < 1 or int_val > 5:
                    errors.append(f"Invalid data_sensitivity {int_val}: must be between 1 and 5.")
            else:
                errors.append("Invalid data_sensitivity: wrong datatype.")

        # Business Criticality Validation
        criticality = ctx.get("business_criticality")
        if criticality is not None:
            try:
                int_val = int(criticality)
                if int_val < 1 or int_val > 5:
                    errors.append(f"Invalid business_criticality {int_val}: must be between 1 and 5.")
            except (ValueError, TypeError):
                errors.append(f"Invalid business_criticality '{criticality}': must be integer in [1, 5].")

        # Quantum Horizon Scenario Validation
        horizon = ctx.get("quantum_horizon_year")
        if horizon is not None:
            try:
                h_val = int(horizon)
                if h_val < 2020 or h_val > 2100:
                    errors.append(f"Invalid quantum_horizon_year {h_val}: expected realistic scenario year [2020, 2100].")
            except (ValueError, TypeError):
                errors.append(f"Invalid quantum_horizon_year '{horizon}': must be integer.")

        return len(errors) == 0, errors

    def check_hndl_assessability(
        self, cbom_asset: Dict[str, Any], risk_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Check if all required HNDL operational context inputs are present and explicitly labelled.
        Inspects both explicit cbom_asset metadata and risk_context.
        """
        ca = cbom_asset if isinstance(cbom_asset, dict) else {}
        ctx = risk_context if isinstance(risk_context, dict) else {}
        missing = []

        # If cbom_asset explicitly carries a verified HNDL rating (e.g. HIGH/CRITICAL), it is assessable
        explicit_hndl = ca.get("hndl_exposure") or ca.get("hndl_risk") or ctx.get("hndl_exposure")
        if explicit_hndl and str(explicit_hndl).upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return True, f"Explicit HNDL exposure provided: {explicit_hndl}"

        # 1. Data Shelf-Life / Lifetime
        data_ctx = ctx.get("data_context") if isinstance(ctx.get("data_context"), dict) else {}
        lifetime = (
            ca.get("data_lifetime_years")
            or ca.get("data_shelf_life_years")
            or ctx.get("data_lifetime_years")
            or ctx.get("data_shelf_life_years")
            or data_ctx.get("data_lifetime_years")
        )
        if lifetime is None:
            missing.append("data shelf-life (missing)")

        # 2. Data Sensitivity / Data Types
        sensitivity = (
            ca.get("data_sensitivity")
            or ca.get("data_classification")
            or ctx.get("data_sensitivity")
            or data_ctx.get("sensitivity")
            or data_ctx.get("data_sensitivity")
        )
        data_types = ca.get("data_types") or ctx.get("data_types") or data_ctx.get("data_types")
        if isinstance(data_types, list):
            data_types = [t for t in data_types if t and str(t).lower() not in ("none labelled", "none", "unknown", "unlabelled")]
        
        if sensitivity is None and not data_types:
            missing.append("data sensitivity/type (unlabelled or missing)")

        # 3. Network Exposure
        net_ctx = ctx.get("network_context") if isinstance(ctx.get("network_context"), dict) else {}
        exposure = (
            ca.get("network_exposure")
            or ca.get("exposure")
            or ctx.get("network_exposure")
            or net_ctx.get("exposure")
            or ctx.get("exposure")
        )
        internet_exp = (
            ca.get("internet_facing")
            or ca.get("public_endpoint")
            or ctx.get("internet_exposed")
            or ctx.get("internet_facing")
            or net_ctx.get("internet_exposed")
        )
        if exposure is None and internet_exp is None:
            missing.append("network exposure (missing)")

        # 4. Explicit assessability flag from ThreatContext
        if ctx.get("hndl_assessable") is False and not explicit_hndl:
            if not missing:
                missing.append("insufficient operational threat context")

        if missing:
            return False, f"Required HNDL inputs missing or unlabelled: {', '.join(missing)}"
        return True, "All required HNDL inputs present and valid."

    def validate_output(
        self,
        hndl_json: Dict[str, Any],
        expected_asset_id: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Validates generated HNDL assessment dictionary.

        :param hndl_json: Generated HNDL assessment dictionary.
        :param expected_asset_id: Expected asset ID to verify consistency.
        :return: Tuple (is_valid: bool, list_of_error_messages)
        """
        errors: List[str] = []

        if not isinstance(hndl_json, dict):
            return False, ["HNDL output must be a JSON object (dictionary)."]

        asset_id = hndl_json.get("asset_id")
        if not asset_id:
            errors.append("HNDL output missing required field 'asset_id'.")
        elif expected_asset_id and asset_id != expected_asset_id:
            errors.append(f"HNDL output asset_id '{asset_id}' does not match expected '{expected_asset_id}'.")

        hndl = hndl_json.get("hndl")
        if not isinstance(hndl, dict):
            return False, ["HNDL output missing required dictionary 'hndl'."]

        # Check required fields
        if "applicable" not in hndl or not isinstance(hndl["applicable"], bool):
            errors.append("HNDL body missing required boolean 'applicable'.")

        score = hndl.get("hndl_exposure_score")
        if score is None or not isinstance(score, (int, float)) or score < 0.0 or score > 1.0:
            errors.append(f"Invalid hndl_exposure_score: {score} (must be float between 0.0 and 1.0).")

        urgency = hndl.get("urgency_tier")
        if urgency not in self.ALLOWED_URGENCY_TIERS:
            errors.append(f"Invalid urgency_tier '{urgency}'. Allowed: {self.ALLOWED_URGENCY_TIERS}.")

        timeline = hndl.get("timeline")
        if not isinstance(timeline, dict) or "exposure_window_years" not in timeline:
            errors.append("Missing or invalid timeline object in HNDL assessment.")

        threats = hndl.get("threat_vectors")
        if not isinstance(threats, dict) or "crypto_susceptibility" not in threats:
            errors.append("Missing or invalid threat_vectors object in HNDL assessment.")

        assumptions = hndl.get("assumptions")
        if not isinstance(assumptions, dict) or "quantum_horizon_year" not in assumptions:
            errors.append("Missing or invalid assumptions metadata in HNDL assessment.")

        return len(errors) == 0, errors


def validate_hndl_inputs(cbom_asset: Dict[str, Any], risk_context: Dict[str, Any]) -> Tuple[bool, List[str]]:
    return HNDLValidator().validate_inputs(cbom_asset, risk_context)


def validate_hndl_output(hndl_json: Dict[str, Any], expected_asset_id: str, expected_lifetime: Optional[int] = None) -> Tuple[bool, List[str]]:
    return HNDLValidator().validate_output(hndl_json, expected_asset_id)
