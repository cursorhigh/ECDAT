"""
HNDL Module Input & Output Validator

Provides structural and semantic validation for CBOM assets, risk contexts,
and generated HNDL threat assessment JSON outputs.
"""

from typing import Dict, Any, Tuple, List, Optional


class HNDLValidator:
    """
    Validates inputs and outputs for HNDL risk assessment pipeline.
    """

    ALLOWED_SENSITIVITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    ALLOWED_RISK_LEVELS = {"HIGH", "MEDIUM", "LOW"}

    def validate_inputs(
        self, cbom_asset: Dict[str, Any], risk_context: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """
        Validates input CBOM asset and risk context dictionaries.

        :param cbom_asset: Input 1 dictionary.
        :param risk_context: Input 2 dictionary.
        :return: Tuple (is_valid: bool, list_of_error_messages)
        """
        errors: List[str] = []

        if not isinstance(cbom_asset, dict):
            return False, ["CBOM asset must be a dictionary."]

        if not isinstance(risk_context, dict):
            return False, ["Risk context must be a dictionary."]

        # 1. Validate CBOM Asset Required Fields
        asset_id = cbom_asset.get("asset_id")
        if not asset_id or not isinstance(asset_id, str):
            errors.append("CBOM asset missing required string field 'asset_id'.")

        algorithm = cbom_asset.get("algorithm")
        if not algorithm:
            errors.append("CBOM asset missing required field 'algorithm'.")
        elif isinstance(algorithm, dict):
            if not algorithm.get("family") and not algorithm.get("name"):
                errors.append("CBOM asset algorithm object must contain 'family' or 'name'.")

        # 2. Validate Risk Context Required Fields
        data_ctx = risk_context.get("data_context")
        if not isinstance(data_ctx, dict):
            errors.append("Risk context missing required dictionary field 'data_context'.")
        else:
            sensitivity = str(data_ctx.get("sensitivity") or "").upper()
            if sensitivity not in self.ALLOWED_SENSITIVITY:
                errors.append(
                    f"Invalid data sensitivity '{sensitivity}'. Allowed: {self.ALLOWED_SENSITIVITY}."
                )

            lifetime = data_ctx.get("data_lifetime_years")
            if lifetime is None or not isinstance(lifetime, (int, float)) or lifetime < 0:
                errors.append("Invalid data_lifetime_years. Must be a non-negative integer.")

        network_ctx = risk_context.get("network_context")
        if not isinstance(network_ctx, dict):
            errors.append("Risk context missing required dictionary field 'network_context'.")
        else:
            if "internet_exposed" not in network_ctx or not isinstance(network_ctx["internet_exposed"], bool):
                errors.append("Network context missing required boolean field 'internet_exposed'.")

            if "collectable" not in network_ctx or not isinstance(network_ctx["collectable"], bool):
                errors.append("Network context missing required boolean field 'collectable'.")

        return len(errors) == 0, errors

    def validate_output(
        self,
        hndl_json: Dict[str, Any],
        expected_asset_id: str,
        expected_lifetime: int,
    ) -> Tuple[bool, List[str]]:
        """
        Validates generated HNDL assessment JSON schema, fields, types, and asset_id consistency.

        :param hndl_json: Generated HNDL assessment dictionary.
        :param expected_asset_id: Original CBOM asset_id to enforce exact match.
        :param expected_lifetime: Original data_lifetime_years to enforce exact match.
        :return: Tuple (is_valid: bool, list_of_error_messages)
        """
        errors: List[str] = []

        if not isinstance(hndl_json, dict):
            return False, ["HNDL output must be a JSON object (dictionary)."]

        # Validate asset_id match
        asset_id = hndl_json.get("asset_id")
        if not asset_id:
            errors.append("HNDL output missing required field 'asset_id'.")
        elif asset_id != expected_asset_id:
            errors.append(
                f"HNDL output asset_id '{asset_id}' does not match original asset_id '{expected_asset_id}'."
            )

        # Validate hndl block
        hndl_body = hndl_json.get("hndl")
        if not isinstance(hndl_body, dict):
            errors.append("HNDL output missing required dictionary field 'hndl'.")
            return False, errors

        # Field: applicable
        if "applicable" not in hndl_body or not isinstance(hndl_body["applicable"], bool):
            errors.append("Field 'hndl.applicable' must be a boolean.")

        # Field: harvestability
        harvestability = str(hndl_body.get("harvestability") or "").upper()
        if harvestability not in self.ALLOWED_RISK_LEVELS:
            errors.append(
                f"Field 'hndl.harvestability' must be one of {self.ALLOWED_RISK_LEVELS}. Got '{harvestability}'."
            )

        # Field: future_decryption_risk
        risk = str(hndl_body.get("future_decryption_risk") or "").upper()
        if risk not in self.ALLOWED_RISK_LEVELS:
            errors.append(
                f"Field 'hndl.future_decryption_risk' must be one of {self.ALLOWED_RISK_LEVELS}. Got '{risk}'."
            )

        # Field: data_lifetime_years
        lifetime = hndl_body.get("data_lifetime_years")
        if lifetime is None or not isinstance(lifetime, (int, float)):
            errors.append("Field 'hndl.data_lifetime_years' must be an integer.")
        elif int(lifetime) != int(expected_lifetime):
            errors.append(
                f"Field 'hndl.data_lifetime_years' ({lifetime}) does not match input context ({expected_lifetime})."
            )

        # Field: quantum_vulnerable
        qv = hndl_body.get("quantum_vulnerable")
        if qv is not None and not isinstance(qv, bool):
            errors.append("Field 'hndl.quantum_vulnerable' must be boolean or null.")

        # Field: reason
        reason = hndl_body.get("reason")
        if not reason or not isinstance(reason, str) or not reason.strip():
            errors.append("Field 'hndl.reason' must be a non-empty string.")

        return len(errors) == 0, errors


def validate_hndl_inputs(
    cbom_asset: Dict[str, Any], risk_context: Dict[str, Any]
) -> Tuple[bool, List[str]]:
    """Helper wrapper for input validation."""
    return HNDLValidator().validate_inputs(cbom_asset, risk_context)


def validate_hndl_output(
    hndl_json: Dict[str, Any], expected_asset_id: str, expected_lifetime: int
) -> Tuple[bool, List[str]]:
    """Helper wrapper for output validation."""
    return HNDLValidator().validate_output(hndl_json, expected_asset_id, expected_lifetime)
