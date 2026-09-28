"""
MOSCA+ Input and Output Validator (validator.py)

Validates CBOM assets, operational context parameters, numerical bounds, and generated
Mosca Theorem assessment output schemas without mutating raw data.
"""

from typing import Dict, Any, Tuple, List, Optional


class MOSCAValidator:
    """
    Validates inputs and outputs for the Mosca Theorem risk assessment pipeline.
    """

    ALLOWED_URGENCY_TIERS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"}
    ALLOWED_POSTURES = {"MIGRATION_DEFICIT", "MIGRATION_OVERDUE", "SAFE_BUFFER", "QUANTUM_RESILIENT"}
    SENSITIVITY_MAP = {"LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

    def validate_input(
        self, cbom_asset: Dict[str, Any], operational_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validates input CBOM asset and operational context parameters.

        :param cbom_asset: Input CBOM Cryptographic Asset dictionary.
        :param operational_context: Operational system and migration context dictionary.
        :return: Tuple (is_valid: bool, list_of_error_messages)
        """
        errors: List[str] = []

        if not isinstance(cbom_asset, dict):
            return False, ["CBOM asset must be a dictionary."]

        ctx = operational_context if isinstance(operational_context, dict) else {}

        # 1. Validate CBOM Asset Required Fields
        asset_id = cbom_asset.get("asset_id") or cbom_asset.get("id") or cbom_asset.get("name")
        if not asset_id or not isinstance(asset_id, str):
            errors.append("CBOM asset missing required identifier (asset_id or id).")

        algorithm = cbom_asset.get("algorithm") or cbom_asset.get("name")
        if not algorithm:
            errors.append("CBOM asset missing required field 'algorithm'.")

        # 2. Validate Operational Parameters
        # Migration Time (X) Validation
        mig_time = ctx.get("migration_time_years")
        if mig_time is not None:
            try:
                val = float(mig_time)
                if val < 0.0:
                    errors.append("Invalid migration_time_years: cannot be negative.")
            except (ValueError, TypeError):
                errors.append(f"Invalid migration_time_years '{mig_time}': must be numeric.")

        # Data Lifetime (Y) Validation
        lifetime = ctx.get("data_lifetime_years")
        if lifetime is not None:
            try:
                val = float(lifetime)
                if val < 0.0:
                    errors.append("Invalid data_lifetime_years: cannot be negative.")
            except (ValueError, TypeError):
                errors.append(f"Invalid data_lifetime_years '{lifetime}': must be numeric.")

        # Agility & Complexity Validation
        for param, name in [("crypto_agility", "crypto_agility"), ("migration_complexity", "migration_complexity")]:
            if param in ctx and ctx[param] is not None:
                try:
                    int_val = int(ctx[param])
                    if int_val < 1 or int_val > 5:
                        errors.append(f"Invalid {name} {int_val}: must be between 1 and 5.")
                except (ValueError, TypeError):
                    errors.append(f"Invalid {name} '{ctx[param]}': must be integer in [1, 5].")

        # Sensitivity & Criticality Validation
        for param, name in [("data_sensitivity", "data_sensitivity"), ("business_criticality", "business_criticality")]:
            if param in ctx and ctx[param] is not None:
                val = ctx[param]
                if isinstance(val, str) and val.upper() in self.SENSITIVITY_MAP:
                    pass
                else:
                    try:
                        int_val = int(val)
                        if int_val < 1 or int_val > 5:
                            errors.append(f"Invalid {name} {int_val}: must be between 1 and 5.")
                    except (ValueError, TypeError):
                        errors.append(f"Invalid {name} '{val}': must be integer in [1, 5].")

        # Quantum Horizon Validation
        horizon = ctx.get("quantum_horizon_year")
        if horizon is not None:
            try:
                h_val = int(horizon)
                if h_val < 2020 or h_val > 2100:
                    errors.append(f"Invalid quantum_horizon_year {h_val}: expected scenario year [2020, 2100].")
            except (ValueError, TypeError):
                errors.append(f"Invalid quantum_horizon_year '{horizon}': must be integer.")

        return len(errors) == 0, errors

    def validate_output(
        self,
        mosca_json: Dict[str, Any],
        expected_asset_id: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Validates generated Mosca assessment dictionary.

        :param mosca_json: Generated Mosca assessment dictionary.
        :param expected_asset_id: Expected asset ID to verify consistency.
        :return: Tuple (is_valid: bool, list_of_error_messages)
        """
        errors: List[str] = []

        if not isinstance(mosca_json, dict):
            return False, ["Mosca output must be a JSON object (dictionary)."]

        asset_id = mosca_json.get("asset_id")
        if not asset_id:
            errors.append("Mosca output missing required field 'asset_id'.")
        elif expected_asset_id and asset_id != expected_asset_id:
            errors.append(f"Mosca output asset_id '{asset_id}' does not match expected '{expected_asset_id}'.")

        mosca = mosca_json.get("mosca")
        if not isinstance(mosca, dict):
            return False, ["Mosca output missing required dictionary 'mosca'."]

        # Check required fields
        if "inequality_satisfied" not in mosca or not isinstance(mosca["inequality_satisfied"], bool):
            errors.append("Mosca body missing required boolean 'inequality_satisfied'.")

        risk_index = mosca.get("mosca_risk_index")
        if risk_index is None or not isinstance(risk_index, (int, float)) or risk_index < 0.0 or risk_index > 1.0:
            errors.append(f"Invalid mosca_risk_index: {risk_index} (must be float between 0.0 and 1.0).")

        urgency = mosca.get("urgency_tier")
        if urgency not in self.ALLOWED_URGENCY_TIERS:
            errors.append(f"Invalid urgency_tier '{urgency}'. Allowed: {self.ALLOWED_URGENCY_TIERS}.")

        posture = mosca.get("migration_posture")
        if posture not in self.ALLOWED_POSTURES:
            errors.append(f"Invalid migration_posture '{posture}'. Allowed: {self.ALLOWED_POSTURES}.")

        variables = mosca.get("variables")
        if not isinstance(variables, dict) or "X_plus_Y" not in variables:
            errors.append("Missing or invalid variables object in Mosca assessment.")

        timeline = mosca.get("timeline")
        if not isinstance(timeline, dict) or "mosca_deficit_years" not in timeline:
            errors.append("Missing or invalid timeline object in Mosca assessment.")

        assumptions = mosca.get("assumptions")
        if not isinstance(assumptions, dict) or "quantum_horizon_year" not in assumptions:
            errors.append("Missing or invalid assumptions metadata in Mosca assessment.")

        return len(errors) == 0, errors

    def validate(self, mosca_json: Dict[str, Any], expected_asset_id: Optional[str] = None) -> Tuple[bool, List[str]]:
        """Alias for validate_output."""
        return self.validate_output(mosca_json, expected_asset_id)
